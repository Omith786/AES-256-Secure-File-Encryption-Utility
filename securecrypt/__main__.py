"""Allow ``python -m securecrypt``."""

import sys

from .cli import main

sys.exit(main())
