# jamf-dp-sync: development targets. The agent itself needs no build step.
PYTHON ?= python3

.PHONY: help test test-unit test-int leak-check
help:
	@echo "make test-unit    # unit tests (stdlib unittest, no network)"
	@echo "make test-int     # integration tests against local Jamf Pro, webhook and upstream stubs"
	@echo "make test         # both"
	@echo "make leak-check   # fail if anything in the repo looks like a real secret"

test: test-unit test-int

test-unit:
	$(PYTHON) -m unittest discover -s tests/unit -t . -v

test-int:
	$(PYTHON) -m unittest discover -s tests/integration -t . -v

leak-check:
	$(PYTHON) scripts/leak_check.py
