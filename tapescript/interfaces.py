from typing import Protocol, runtime_checkable


@runtime_checkable
class TapeProtocol(Protocol):
    def read(self, size: int, move_pointer: bool = True) -> bytes:
        """Read symbols from the data."""
        ...

    def has_terminated(self) -> bool:
        """Return whether or not the tape has terminated."""
        ...


@runtime_checkable
class CanCheckTransfer(Protocol):
    def verify_txn_proof(proof: bytes) -> bool:
        """Checks a transaction proof. Returns True if it is valid and
            False otherwise.
        """
        ...

    def verify_transfer(proof: bytes, source: bytes, destination: bytes) -> bool:
        """Checks a transfer. Returns True if the proof proves that
            there was a transfer from source to destination.
        """
        ...

    def verify_txn_constraint(proof: bytes, constraint: bytes) -> bool:
        """Checks whether a txn proof abides by a constraint. Returns
            True if it did and False otherwise.
        """
        ...

    def calc_txn_aggregates(proofs: list[bytes], scope: bytes = None) -> dict:
        """Calculates the aggregate amounts moved to sources and
            destinations, using negative numbers for net reductions and
            returns a dict mapping address to integer amount. If the
            optional scope argument is supplied, it will calculate only
            the aggregate for that address.
        """
        ...


@runtime_checkable
class CanBeInvoked(Protocol):
    def abi(self, args: list[bytes]) -> list[bytes]|None:
        """Allow the contract to be called by OP_INVOKE. ABI=Application
            Binary Interface. Takes a list of bytes as args and returns
            either a list of bytes or None.
        """
        ...
