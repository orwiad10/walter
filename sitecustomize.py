"""Project-level Python startup customizations.

When pytest starts on Windows, third-party setuptools plugins can be auto-loaded
before command-line or ini-level plugin suppression is applied. Some globally
installed plugins (e.g. pytest-ansible) import POSIX-only modules such as
``fcntl`` and crash test startup.

To keep local Windows test runs working, disable external pytest plugin
autoloading only on Windows. Builtin pytest plugins remain available.
"""

from __future__ import annotations

import os
import sys


if os.name == "nt" and any("pytest" in arg.lower() for arg in sys.argv):
    os.environ.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
