from .functions import (
    clamp_scalar,
    token_bytes,
    aggregate_points,
    bytes_are_same,
)
from hashlib import sha256
import nacl.bindings


class AMHL:
    """Singleton exposing all the AMHL helper functions. Messy
        conventions taken directly from the Anonymous Multi-Hop Lock
        paper.
    """
    @staticmethod
    def sample(seed: bytes, i: int) -> bytes:
        """Take 1 sample from the domain of the homomorphic one-way function."""
        return clamp_scalar(sha256(seed + i.to_bytes(8, 'big')).digest())

    @staticmethod
    def samples(n: int, seed: bytes = None) -> tuple[bytes]:
        """Take n samples from the domain of the homomorphic one-way function."""
        seed = seed if seed else token_bytes(32)
        return tuple(AMHL.sample(seed, i) for i in range(n))

    @staticmethod
    def oneway(scalar: bytes) -> bytes:
        """Run the homomorphic one-way function on the input scalar."""
        return nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)

    @staticmethod
    def setup(n_users: int, seed: bytes = None) -> tuple[tuple[bytes], tuple[bytes]]:
        """Setup the lock inputs. Returns two tuples: one containing the
            scalars (keys) and one containing the points (locks).
        """
        y = AMHL.samples(n_users, seed)
        Y = [AMHL.oneway(y[0])]
        for i, y_i in enumerate(y):
            if i > 0:
                Y.append(aggregate_points((Y[i-1], AMHL.oneway(y_i))))
        return (y, tuple(Y))

    @staticmethod
    def scalar_sum(*scalars: tuple[bytes]) -> bytes:
        """Compute the sum of the scalars."""
        sum = scalars[0]
        for i in range(1, len(scalars)):
            sum = nacl.bindings.crypto_core_ed25519_scalar_add(sum, scalars[i])
        return sum

    @staticmethod
    def setup_for(s: tuple[tuple[bytes], tuple[bytes]], i: int) -> tuple[bytes]:
        """Generate the setup for a particular user given the setup s
            and the user index i. Returns a tuple with a scalar for i=0;
            left tweak point, right tweak point, and partial tweak
            scalar for i<len(s[0]); or tuple of (left tweak point, 0, 0)
            and the sum of all partial tweak scalars as as key to unlock
            the final hop in the chain.
        """
        if i == 0:
            return (s[0][0],)

        if i == len(s[0]):
            return ((s[1][i-1], 0, 0), AMHL.scalar_sum(*s[0]))

        return (s[1][i-1], s[1][i], s[0][i])

    @staticmethod
    def check_setup(s: tuple[bytes], i: int, n: int) -> bool:
        """Verifies the setup for the ith of n users is valid."""
        if i == 0:
            return len(s) == 1 and isinstance(s[0], bytes)

        if i == n:
            return len(s) == 2 and type(s[0]) is tuple and len(s[0]) == 3 and \
                type(s[0][0]) is bytes and type(s[1]) is bytes

        Y_i = aggregate_points((s[0], AMHL.oneway(s[2])))
        return bytes_are_same(Y_i, s[1])

    @staticmethod
    def lock(s: tuple) -> tuple[bytes, bool]:
        """Create the lock from the setup for a specific hop."""
        return (s[1], False)

    @staticmethod
    def release(k: bytes, y: bytes) -> bytes:
        """Release a left lock given a key from a released intermediate lock."""
        return nacl.bindings.crypto_core_ed25519_scalar_sub(k, y)

    @staticmethod
    def verify_lock_key(l: bytes, k: bytes) -> bool:
        """Verify that a key opens a lock."""
        return bytes_are_same(l, AMHL.oneway(k))
