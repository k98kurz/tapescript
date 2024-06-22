from __future__ import annotations
from context import functions, tools
from dataclasses import dataclass, field
from hashlib import sha256
from time import time
import struct


'''Simple UTXO-based accounting system without concern for consensus or
    persistent data storage.
'''


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
        inputs = b''
        for i in self.inputs:
            i = i.pack()
            inputs = inputs + struct.pack(f'!h{len(i)}s', i)
        return inputs

    def pack_outputs(self) -> bytes:
        outputs = b''
        for o in self.outputs:
            o = o.pack()
            outputs = outputs + struct.pack(f'!h{len(o)}s', o)
        return outputs

    def pack_witnesses(self) -> bytes:
        witnesses = b''
        for w in self.witnesses:
            witnesses += struct.pack(f'!h{len(w.bytes)}s', w.bytes)
        return witnesses

    def pack(self) -> bytes:
        inputs = self.pack_inputs()
        outputs = self.pack_outputs()
        witnesses = self.pack_witnesses()
        return struct.pack(
            f'!HHH{len(inputs)}s{len(outputs)}s{len(witnesses)}s',
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
            f'!HH{len(inputs)}s{len(outputs)}s',
            len(inputs),
            len(outputs),
            inputs,
            outputs,
        )

    def id(self) -> bytes:
        return sha256(self.pack_without_witnesses()).digest()

    @classmethod
    def unpack(cls, data: bytes) -> Entry:
        ilen, olen, wlen, data = struct.unpack(f'!HHH{len(data)-6}s', data)
        idata, odata, wdata = struct.unpack(f'!{ilen}s{olen}s{wlen}s', data)
        inputs = []
        while len(idata):
            ilen, idata = struct.unpack(f'!H{len(idata)-2}s', idata)
            inputs.append(UTXO.unpack(idata[:ilen]))
            idata = idata[ilen:]
        outputs = []
        while len(odata):
            olen, odata = struct.unpack(f'!H{len(odata)-2}s', odata)
            outputs.append(UTXO.unpack(odata[:olen]))
            odata = odata[olen:]
        witnesses = []
        while len(wdata):
            wlen, wdata = struct.unpack(f'!H{len(wdata)-2}s', wdata)
            witnesses.append(tools.Script.from_bytes(wdata[:wlen]))
            wdata = wdata[wlen:]
        return cls(inputs=inputs, outputs=outputs, witnesses=witnesses)

@dataclass
class Txn:
    sequence: int = field()
    timestamp: int = field(default_factory=lambda: int(time()))
    entries: list[Entry] = field(default_factory=list)

    def pack(self) -> bytes:
        entries = b''
        for e in self.entries:
            e = e.pack()
            entries += struct.pack(f'!h{len(e)}s', len(e), e)
        return struct.pack(
            f'!hi{len(entries)}s',
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
        sequence, timestamp, edata = struct.unpack(f'!hi{len(data)-6}s', data)
        entries = []
        while len(edata):
            elen, edata = struct.unpack(f'!h{len(edata)}s', edata)
            entries.append(Entry.unpack(edata[:elen]))
            edata = edata[elen:]
        return cls(sequence=sequence, timestamp=timestamp, entries=entries)


def validate_txn(txn: Txn) -> bool:
    for entry in txn.entries:
        input_ts = max([
            i.txn.timestamp if i.txn else 0
            for i in entry.inputs
        ])
        for i in range(len(entry.inputs)):
            input = entry.inputs[i]
            witness = entry.witnesses[i]
            if not functions.run_auth_script(
                witness + input.lock,
                {
                    'sigfield1': b''.join([
                        n.pack() for n in entry.inputs
                    ]),
                    'sigfield2': b''.join([
                        o.pack() for o in entry.outputs
                    ]),
                    'sigfield3': functions.uint_to_bytes(txn.sequence),
                    'sigfield4': functions.uint_to_bytes(txn.timestamp),
                    'time': int(time()),
                    'input_ts': input_ts,
                }
            ):
                return False
        input_sum = sum([i.amount for i in entry.inputs])
        output_sum = sum([o.amount for o in entry.outputs])
        if output_sum > input_sum:
            return False
    return True
