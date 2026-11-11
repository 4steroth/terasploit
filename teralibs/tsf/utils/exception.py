class TeraxException(Exception):
    """Base class for all Terax errors."""

    def __init__(self, message: str):
        super().__init__(message)


class PythonExploitationLibraryException(Exception):
    """PEX Library Base exception class for all errors."""

    def __init__(self, message: str):
        super().__init__(message)


class TsfBaseException(Exception):
    """TSF Base exception class for all errors."""

    def __init__(self, message: str):
        super().__init__(message)


class TerasploitException(Exception):
    """Base exception for all Terasploit Framework errors."""

    def __init__(self, message: str):
        super().__init__(message)


class TerasploitShellError(Exception):
    """Raised when a general failure in terasploit shell occurs."""


class WorkerThreadError(TerasploitException):
    """Raised when an error occurs during the main worker thread's execution."""


class DatastoreAccessError(TerasploitException):
    """Raised when a general failure when accessing the datastore occured."""


class ModuleInspectionError(TerasploitException):
    """Raised when a module cannot be inspected or its metadata is missing."""


class ModuleInitializationError(TerasploitException):
    """Raised when a module fails to initialize."""


class ShellExecError(TerasploitException):
    """Raised when shell command execution fails."""


class ExploitCleanupError(TerasploitException):
    """Raised when an error occurs during exploit cleanup."""


class ValidationError(TerasploitException):
    """Raised when validation fails."""


class UrlParseError(TerasploitException):
    """Raised when a URL cannot be parsed."""


class EncoderError(TsfBaseException):
    """Raised when error occured in encoder's methods."""


class ExploitError(TsfBaseException):
    """Raised when error occured in exploit's methods."""


class NopError(TsfBaseException):
    """Raised when error occured in nop's methods."""


class TeraxGenerationError(TeraxException):
    """Raised when payload generation fails."""


class PythonExploitationLibraryError(PythonExploitationLibraryException):
    """Serves as a catch-all safety net for PEX library errors."""


class GraphMLError(PythonExploitationLibraryError):
    """Base error class for all GraphML parsing exceptions."""


class ParserError(GraphMLError):
    """Raised when structural or hierarchical XML parsing issues occur."""


class HttpClientError(PythonExploitationLibraryError):
    """Transport-level failure."""
