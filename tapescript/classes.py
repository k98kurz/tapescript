from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from typing import Callable
from .errors import sert, tert


@dataclass
class Tape:
    """Class for reading the byte code of the script."""
    data: bytes
    pointer: int = field(default=0)
    callstack_limit: int = field(default=128)
    callstack_count: int = field(default=0)
    definitions: dict[bytes, Tape] = field(default_factory=dict)
    flags: dict[str|int, int|bool] = field(default_factory=dict)
    contracts: dict[bytes, object] = field(default_factory=dict)
    plugins: dict[str, list[Callable]] = field(default_factory=dict)

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


class Stack:
    """Class to implement a Stack of bytes items."""
    deque: deque[bytes]
    max_items: int
    max_item_size: int

    def __init__(self, max_items: int = 1024, max_item_size: int = 1024) -> None:
        """Initialize an empty Stack."""
        self.max_items = max_items
        self.max_item_size = max_item_size
        self.deque = deque(maxlen=self.max_items)

    def get(self) -> bytes:
        """Get the top item of the Stack. Raises IndexError if the deque
            is empty.
        """
        return self.deque.pop()

    def put(self, item: bytes) -> None:
        """Put an item onto the Stack. Raises ScriptExecutionError if
            the item is too large or if the Stack is full; raises
            TypeError if the item is not bytes.
        """
        tert(type(item) is bytes, 'Stack item must be bytes')
        sert(len(item) <= self.max_item_size, 'Stack item size too large')
        sert(len(self.deque) < self.max_items, 'cannot put onto full Stack')
        self.deque.append(item)

    def size(self) -> int:
        """Return the number of bytes currently stored on the Stack."""
        return sum([len(item) for item in self.deque])

    def __len__(self) -> int:
        """Return the current number of items in the Stack."""
        return len(self.deque)

    def list(self) -> list:
        """Returns a list containing the Stack items."""
        return list(self.deque)

    def empty(self) -> bool:
        """Return True if there are no items on the Stack. Otherwise,
            return False.
        """
        return len(self) == 0

    def peek(self, index: int = 0) -> bytes:
        """Returns the item of the stack at the given index without
            removing it.
        """
        index = len(self) - index - 1
        return self.deque[index]

