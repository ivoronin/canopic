"""canopic: password-derived asymmetric encryption to a self-extracting archive."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("canopic")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"
