from typing import Protocol, runtime_checkable


@runtime_checkable
class TapeProtocol(Protocol):
    def read(self, size: int, move_pointer: bool = True) -> bytes:
        """Read symbols from the data."""
        ...

    def has_terminated(self) -> bool:
        """Return whether or not the tape has terminated."""
        ...
