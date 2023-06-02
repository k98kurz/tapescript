class ScriptExecutionError(BaseException):
    ...

class SyntaxError(BaseException):
    ...


def vert(condition: bool, message: str = '') -> None:
    if condition:
        return
    raise ValueError(message)

def tert(condition: bool, message: str = '') -> None:
    if condition:
        return
    raise TypeError(message)

def sert(condition: bool, message: str = '') -> None:
    if condition:
        return
    raise ScriptExecutionError(message)

def yert(condition: bool, message: str = '') -> None:
    if condition:
        return
    raise SyntaxError(message)
