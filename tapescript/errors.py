class ScriptExecutionError(BaseException):
    """Error raised when an error is encountered during script execution."""
    ...

class SyntaxError(BaseException):
    """Error raised by parser when syntax error encountered."""
    ...


def vert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises ValueError with the
        given message if the condition check fails.
    """
    if condition:
        return
    raise ValueError(message)

def tert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises TypeError with the
        given message if the condition check fails.
    """
    if condition:
        return
    raise TypeError(message)

def sert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises ScriptExecutionError
        with the given message if the condition check fails.
    """
    if condition:
        return
    raise ScriptExecutionError(message)

def yert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises SyntaxError with the
        given message if the condition check fails.
    """
    if condition:
        return
    raise SyntaxError(message)
