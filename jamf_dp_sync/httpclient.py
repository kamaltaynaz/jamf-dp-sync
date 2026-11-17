"""Small urllib wrapper (stdlib only).

Redirects are followed by hand (DECISIONS B7):
  * the method is kept (urllib would turn HEAD into GET and download a multi-GB body);
  * `Authorization` is dropped as soon as the host changes (spec section 6, github_tag rule 5);
  * an https -> http downgrade is refused.
Non-2xx responses are returned, not raised; network failures raise NetworkError.
"""
import http.client
import os
import shutil
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from jamf_dp_sync import __version__
from jamf_dp_sync.errors import SyncError

REDIRECT_CODES = (301, 302, 303, 307, 308)
USER_AGENT = "jamf-dp-sync/%s" % __version__


LOOPBACK = ("127.0.0.1", "localhost", "::1")


def credential_url_problem(url, what):
    """None if `url` may carry credentials: https, or http to a loopback host (the local test
    stubs). Otherwise a fixed message naming `what`; it never quotes the URL."""
    try:
        parts = urllib.parse.urlsplit(url or "")
        host = (parts.hostname or "").lower()
        parts.port  # raises ValueError on a bad port
    except ValueError:
        return "%s could not be parsed" % what
    if not host:
        return "%s has no host" % what
    if parts.username or parts.password:
        return "%s must not contain a user name or password" % what
    if parts.scheme == "https" or (parts.scheme == "http" and host in LOOPBACK):
        return None
    return "%s must use https" % what


class NetworkError(SyncError):
    step = "network"


class Response(object):
    def __init__(self, status, headers, url, body=None, history=None):
        self.status = status
        self.headers = headers  # dict, lower-case keys
        self.url = url
        self.body = body
        self.history = history or []

    def header(self, name, default=None):
        return self.headers.get(name.lower(), default)

    def json(self):
        import json
        try:
            return json.loads((self.body or b"").decode("utf-8"))
        except ValueError as e:
            raise SyncError("response from %s is not JSON: %s" % (_host(self.url), e))

    def __repr__(self):
        return "Response(%d, %s)" % (self.status, self.url)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _host(url):
    return urllib.parse.urlsplit(url).hostname or ""


def _headers_dict(msg):
    return dict((k.lower(), v) for k, v in msg.items())


URL_MAP_ENV = "JDS_TEST_URL_MAP"


def _url_map():
    """Test-only (spec 11.3: env, never config): "https://api.github.com=http://127.0.0.1:8001/gh,...".

    Rewrites the URL actually opened; redirect, auth-stripping and https checks all see the logical
    (public) URL, so the agent's behaviour is unchanged apart from where bytes come from.
    """
    pairs = []
    for item in os.environ.get(URL_MAP_ENV, "").split(","):
        if "=" in item:
            src, dst = item.split("=", 1)
            pairs.append((src.strip().rstrip("/"), dst.strip().rstrip("/")))
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return pairs


class HttpClient(object):
    def __init__(self, timeout=30, user_agent=USER_AGENT, max_redirects=10, ssl_context=None):
        self.url_map = _url_map()
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_redirects = max_redirects
        handlers = [_NoRedirect()]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        self._opener = urllib.request.build_opener(*handlers)

    def _rewrite(self, url):
        for src, dst in self.url_map:
            if url == src or url.startswith(src + "/") or url.startswith(src + "?"):
                return dst + url[len(src):]
        return url

    def _open(self, method, url, headers, data, timeout):
        req = urllib.request.Request(self._rewrite(url), data=data, method=method)
        req.add_header("User-Agent", self.user_agent)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            return self._opener.open(req, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as e:
            return e  # has .code, .headers, .read()
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise NetworkError("%s %s: %s" % (method, _host(url), reason))

    def _follow(self, method, url, headers, data, follow, timeout):
        """Open `url`, following redirects per the module rules. Returns (open response, status,
        headers dict, final url, history); the caller must close the response."""
        headers = dict(headers or {})
        history = []
        start_host = _host(url)
        for _ in range(self.max_redirects + 1):
            resp = self._open(method, url, headers, data, timeout)
            status = getattr(resp, "status", None) or resp.code
            hdrs = _headers_dict(resp.headers)
            if not (follow and status in REDIRECT_CODES and "location" in hdrs):
                return resp, status, hdrs, url, history
            resp.close()
            new = urllib.parse.urljoin(url, hdrs["location"])
            if urllib.parse.urlsplit(url).scheme == "https" and urllib.parse.urlsplit(new).scheme != "https":
                raise NetworkError("refusing redirect from https to %s" % urllib.parse.urlsplit(new).scheme)
            history.append((status, url))
            if _host(new) != start_host:
                headers = dict((k, v) for k, v in headers.items() if k.lower() != "authorization")
            if status == 303 and method != "HEAD":
                method, data = "GET", None
            url = new
        raise NetworkError("too many redirects from %s" % start_host)

    def request(self, method, url, headers=None, data=None, follow=True, timeout=None):
        """Return a Response with the body read (None for HEAD)."""
        resp, status, hdrs, final, history = self._follow(method, url, headers, data, follow, timeout)
        try:
            body = resp.read() if method != "HEAD" else None
        except (socket.timeout, ssl.SSLError, ConnectionError, OSError) as e:
            raise NetworkError("%s %s: reading response failed: %s" % (method, _host(final), e))
        finally:
            resp.close()
        return Response(status, hdrs, final, body, history)

    def get(self, url, headers=None, **kw):
        return self.request("GET", url, headers=headers, **kw)

    def head(self, url, headers=None, **kw):
        return self.request("HEAD", url, headers=headers, **kw)

    def download(self, url, dest, headers=None, timeout=None):
        """Stream a GET to `dest`. Returns the Response (body None). Non-2xx (including 304 for a
        conditional GET) leaves `dest` untouched.

        Never pass an Authorization header for a release asset download (section 6 rule 5).
        """
        resp, status, hdrs, final, history = self._follow("GET", url, headers, None, True, timeout)
        try:
            if 200 <= status < 300:
                with open(dest, "wb") as f:
                    shutil.copyfileobj(resp, f, 1024 * 1024)
                expected = hdrs.get("content-length")
                got = os.path.getsize(dest)
                if expected is not None and expected.isdigit() and int(expected) != got:
                    raise NetworkError("download from %s stopped early: %d of %s bytes (review #2)"
                                       % (_host(final), got, expected))
        except NetworkError:
            try:
                os.unlink(dest)
            except OSError:
                pass
            raise
        except (socket.timeout, ssl.SSLError, ConnectionError, OSError, http.client.HTTPException) as e:
            try:
                os.unlink(dest)  # never leave a partial download behind
            except OSError:
                pass
            raise NetworkError("download from %s failed: %s" % (_host(final), e))
        finally:
            resp.close()
        return Response(status, hdrs, final, None, history)
