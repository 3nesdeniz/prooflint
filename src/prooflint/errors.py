"""Expected, user-facing Prooflint errors."""


class ProoflintError(Exception):
    """Base class for errors that should not produce a traceback."""


class ParseError(ProoflintError):
    """A finding could not be parsed safely."""


class PathSafetyError(ProoflintError):
    """A path would escape or bypass the configured evidence root."""


class ManifestError(ProoflintError):
    """A manifest is malformed or cannot be generated."""
