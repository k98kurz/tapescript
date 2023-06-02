def vert(condition: bool, message: str = '') -> None:
    if condition:
        return
    raise ValueError(message)

def tert(condition: bool, message: str = '') -> None:
    if condition:
        return
    raise TypeError(message)
