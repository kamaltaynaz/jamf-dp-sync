#!/usr/bin/env python3
"""Entry point called from cron (spec section 9)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jamf_dp_sync.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
