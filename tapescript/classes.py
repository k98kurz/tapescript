from __future__ import annotations
from dataclasses import dataclass, field
from .errors import sert


@dataclass
class Tape:
    """Class for reading the byte code of the script."""
    data: bytes
    pointer: int = field(default=0)
    callstack_limit: int = field(default=64)
    callstack_count: int = field(default=0)
    definitions: dict = field(default_factory=dict)
    flags: dict[str|int, int|bool] = field(default_factory=dict)
    contracts: dict[bytes, object] = field(default_factory=dict)

    def read(self, size: int, move_pointer: bool = True) -> bytes:
        """Read symbols from the data."""
        sert(self.pointer + size <= len(self.data),
            'cannot read that many bytes')
        data = self.data[self.pointer:self.pointer+size]

        if move_pointer:
            self.move_pointer(size)

        return data

    def move_pointer(self, n: int) -> int:
        """Move the pointer the given number of places."""
        sert(self.pointer + n <= len(self.data), 'cannot move pointer that far')
        self.pointer += n
        return self.pointer

    def reset_pointer(self) -> None:
        """Reset the pointer to 0."""
        self.pointer = 0

    def reset(self) -> None:
        """Reset the pointer to 0 and the definitions to {}."""
        self.pointer = 0
        self.definitions = {}

    def has_terminated(self) -> bool:
        """Return whether or not the tape has terminated."""
        return self.pointer >= len(self.data)

    def remaining(self) -> int:
        """Return the remaining number of symbols left in the tape."""
        return len(self.data) - self.pointer
