"""Single source of the app version. Bump VERSION (and add a CHANGELOG entry) for every release."""
from pathlib import Path

try:
    __version__ = (Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()) or "0.0.0"
except OSError:  # pragma: no cover - VERSION missing from a copied install
    __version__ = "0.0.0"


APP_NAME = "Qlik Server Event Manager"   # shown in the header and browser tab; change here to rename the app
