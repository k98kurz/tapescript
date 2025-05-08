from __future__ import annotations
from context import functions, tools
from dataclasses import dataclass, field
from hashlib import sha256
from time import time
import struct


'''Simple UTXO-based accounting system without concern for consensus or
    persistent data storage.
'''


def serialize(things: list[bytes]) -> bytes:
    result = b''
    for thing in things:
        result = result + struct.pack(f'!H{len(thing)}s', len(thing), thing)
    return result

def deserialize(data: bytes) -> list[bytes]:
    remainder = data
    things = []
    while len(remainder):
        length, remainder = struct.unpack(f'!H{len(data)-2}s', data)
        things.append(remainder[:length])
        remainder = remainder[length:]
    return things


@dataclass
class UTXO:
    lock: tools.Script = field(default_factory=lambda: tools.Script.from_src('true'))
    amount: int = field(default=0)
    spent: bool = field(default=False)
    txn: Txn|None = field(default=None)

    def pack(self) -> bytes:
        return struct.pack(
            f'!{len(self.lock.bytes)}sH?',
            self.lock.bytes,
            self.amount,
            self.spent
        )

    @classmethod
    def unpack(cls, data: bytes) -> UTXO:
        lock, amount, spent = struct.unpack(f'!{len(data)-3}sH?', data)
        return cls(lock=tools.Script.from_bytes(lock),amount=amount,spent=spent)

@dataclass
class Entry:
    inputs: list[UTXO] = field(default_factory=list)
    outputs: list[UTXO] = field(default_factory=list)
    witnesses: list[tools.Script] = field(default_factory=list)

    def pack_inputs(self) -> bytes:
        return serialize([i.pack() for i in self.inputs])

    def pack_outputs(self) -> bytes:
        return serialize([o.pack() for o in self.outputs])

    def pack_witnesses(self) -> bytes:
        return serialize([w.pack() for w in self.witnesses])

    def pack(self) -> bytes:
        inputs = self.pack_inputs()
        outputs = self.pack_outputs()
        witnesses = self.pack_witnesses()
        return struct.pack(
            f'!III{len(inputs)}s{len(outputs)}s{len(witnesses)}s',
            len(inputs),
            len(outputs),
            len(witnesses),
            inputs,
            outputs,
            witnesses,
        )

    def pack_without_witnesses(self) -> bytes:
        inputs = self.pack_inputs()
        outputs = self.pack_outputs()
        return struct.pack(
            f'!II{len(inputs)}s{len(outputs)}s',
            len(inputs),
            len(outputs),
            inputs,
            outputs,
        )

    def id(self) -> bytes:
        return sha256(self.pack_without_witnesses()).digest()

    @classmethod
    def unpack(cls, data: bytes) -> Entry:
        ilen, olen, wlen, data = struct.unpack(f'!III{len(data)-12}s', data)
        idata, odata, wdata = struct.unpack(f'!{ilen}s{olen}s{wlen}s', data)
        inputs = deserialize(idata)
        outputs = deserialize(odata)
        witnesses = deserialize(wdata)
        return cls(inputs=inputs, outputs=outputs, witnesses=witnesses)

@dataclass
class Txn:
    sequence: int = field()
    timestamp: int = field(default_factory=lambda: int(time()))
    entries: list[Entry] = field(default_factory=list)

    def pack(self) -> bytes:
        entries = serialize([e.pack() for e in self.entries])
        return struct.pack(
            f'!HI{len(entries)}s',
            self.sequence,
            self.timestamp,
            entries,
        )

    def entries_root(self) -> bytes:
        """Get the root hash for all entries."""
        return sha256(b''.join(sorted([e.id() for e in self.entries]))).digest()

    def id(self) -> bytes:
        return sha256(struct.pack(
            f'!ii32s',
            self.sequence,
            self.timestamp,
            self.entries_root(),
        )).digest()

    @classmethod
    def unpack(cls, data: bytes) -> Txn:
        sequence, timestamp, edata = struct.unpack(f'!HI{len(data)-6}s', data)
        entries = deserialize(edata)
        return cls(sequence=sequence, timestamp=timestamp, entries=entries)

    def get_cache_values(self) -> dict:
        return {
            entry.id(): {
                'sigfield1': serialize([
                    n.pack() for n in entry.inputs
                ]),
                'sigfield2': serialize([
                    o.pack() for o in entry.outputs
                ]),
                'sigfield3': functions.uint_to_bytes(self.sequence),
                'sigfield4': functions.uint_to_bytes(self.timestamp),
            }
            for entry in self.entries
        }


def validate_txn(txn: Txn) -> bool:
    cache_values = txn.get_cache_values()
    for entry in txn.entries:
        input_ts = max([
            i.txn.timestamp if i.txn else 0
            for i in entry.inputs
        ])
        for i in range(len(entry.inputs)):
            input = entry.inputs[i]
            witness = entry.witnesses[i]
            if not functions.run_auth_scripts(
                [witness, input.lock],
                {
                    **cache_values[entry.id()],
                    'input_ts': input_ts,
                }
            ):
                return False
        input_sum = sum([i.amount for i in entry.inputs])
        output_sum = sum([o.amount for o in entry.outputs])
        if output_sum > input_sum:
            return False
    return True
