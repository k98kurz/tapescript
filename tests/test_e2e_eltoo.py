from __future__ import annotations
from context import functions, tools
from dataclasses import dataclass, field
from hashlib import sha256
from nacl.signing import SigningKey, VerifyKey
from time import time
import struct
import unittest


'''Example implementation of the eltoo protocol. The primary deviation
    from Example 6 from script_examples.md is that UTXOs are simply
    serialized rather than referenced via txn_id and index in the
    witness data creation and verification -- as written, Example 6
    requires looking up the UTXO data before creating or verifying any
    witness data. I did not want to implement an entire blockchain for
    this test and was interested only in the eltoo mechanism itself.

    The Eltoo proposed OP_CHECKSEQUENCEVERIFY is simulated by putting
    the state integer into sigfield3 and comparing in the locking script
    with OP_LESS OP_VERIFY. For channel updates, inputs are encoded in
    sigfield1 and excluded from signature checks using sigflag of 0x01.
    For channel closures (i.e. time lock branch), a sigflag of 0x00 is
    used to require signature commitment to the whole transaction.
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


def eltoo_setup_lock(pubkeyA: bytes, pubkeyB: bytes) -> tools.Script:
    return tools.Script.from_src(f'''
        PUSH x{bytes(pubkeyA).hex()}
        PUSH x{bytes(pubkeyB).hex()}
        CHECK_MULTISIG x00 d2 d2
    ''')

def eltoo_update_lock(pubkeyA: bytes, pubkeyB: bytes, state: int) -> tools.Script:
    return tools.Script.from_src(f'''
        if {"{"}
            val s"sigfield4"
            # 2 second delay is all I'm willing to wait in a test #
            val s"input_ts" push d2 add_ints d2
            less verify
            val s"time"
            val s"sigfield4"
            leq verify
            push x{bytes(pubkeyA).hex()}
            push x{bytes(pubkeyB).hex()}
            check_multisig x00 d2 d2
        {"}"} else {"{"}
            val s"sigfield3"
            push d{state}
            less verify
            push x{bytes(pubkeyA).hex()}
            push x{bytes(pubkeyB).hex()}
            check_multisig x01 d2 d2
        {"}"}
    ''')

def eltoo_witness(
        prvkeyA: SigningKey, prvkeyB: SigningKey, message: bytes,
        sigflag: str = '') -> tools.Script:
    sigA = prvkeyA.sign(message).signature
    sigB = prvkeyB.sign(message).signature
    return tools.Script.from_src(f'''
        push x{sigB.hex()}{sigflag}
        push x{sigA.hex()}{sigflag}
    ''')

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


class TestEltoo(unittest.TestCase):
    prvkeyA: SigningKey
    prvkeyB: SigningKey
    pubkeyA: VerifyKey
    pubkeyB: VerifyKey

    def setUp(self) -> None:
        self.prvkeyA = SigningKey(b'yellow submarine is extra yellow')
        self.pubkeyA = self.prvkeyA.verify_key
        self.prvkeyB = SigningKey(b'submarine such yellow extra very')
        self.pubkeyB = self.prvkeyB.verify_key
        return super().setUp()

    def test_auto_validate(self):
        genesis_utxo = UTXO(amount=10)
        genesis_entry = Entry([], [genesis_utxo])
        genesis_txn = Txn(0, entries=[genesis_entry])
        genesis_utxo.txn = genesis_txn

        burn_utxo = UTXO(tools.Script.from_src('false'), amount=10)
        burn_entry = Entry([genesis_utxo], [burn_utxo], [tools.Script('', b'')])
        burn_txn = Txn(1, entries=[burn_entry])
        assert validate_txn(burn_txn)

    def test_single_sig(self):
        genesis_utxo = UTXO(tools.Script.from_src(f'''
            push x{bytes(self.pubkeyA).hex()}
            check_sig x00
        '''), 100)
        spend_utxo = UTXO(amount=5)
        ts = int(time())
        sig = self.prvkeyA.sign(
            genesis_utxo.pack() + spend_utxo.pack() +
            b'\x01' + functions.int_to_bytes(ts)
        ).signature
        spend_entry = Entry([genesis_utxo], [spend_utxo], [
            tools.Script.from_src(f'push x{sig.hex()}')
        ])
        spend_txn = Txn(1, ts, [spend_entry])
        assert validate_txn(spend_txn)

    def test_eltoo_e2e(self):
        """A proof-of-concept eltoo implementation."""
        op_false, op_true = tools.Script.from_src('false'), tools.Script.from_src('true')
        settle_A_lock = tools.Script.from_src(f'''
            push x{bytes(self.pubkeyA).hex()}
            check_sig x00
        ''')
        settle_B_lock = tools.Script.from_src(f'''
            push x{bytes(self.pubkeyB).hex()}
            check_sig x00
        ''')
        setup_lock = eltoo_setup_lock(self.pubkeyA, self.pubkeyB)
        setup_utxo = UTXO(setup_lock, 100)
        state = 0

        # initial floating trigger txn created before broadcasting setup
        trigger_lock = eltoo_update_lock(self.pubkeyA, self.pubkeyB, state)
        trigger_utxo = UTXO(trigger_lock, 100)
        # trigger 10 seconds into past
        trigger_ts = int(time())-10
        trigger_txn = Txn(state, trigger_ts, [Entry(
            [setup_utxo],
            [trigger_utxo],
            [eltoo_witness(
                self.prvkeyA,
                self.prvkeyB,
                setup_utxo.pack() +
                trigger_utxo.pack() +
                functions.int_to_bytes(state) +
                functions.int_to_bytes(trigger_ts)
            )]
        )])
        trigger_utxo.txn = trigger_txn
        assert validate_txn(trigger_txn)

        # initial floating settlement txn
        state += 1
        settlement_ts_1 = int(time())-7
        sA_utxo1 = UTXO(settle_A_lock, 50)
        sB_utxo1 = UTXO(settle_B_lock, 50)
        settlement_txn_1 = Txn(state, settlement_ts_1, [Entry(
            [trigger_utxo],
            [sA_utxo1, sB_utxo1],
            [eltoo_witness(
                self.prvkeyA,
                self.prvkeyB,
                trigger_utxo.pack() +
                sA_utxo1.pack() + sB_utxo1.pack() +
                functions.int_to_bytes(state) +
                functions.int_to_bytes(settlement_ts_1)
            ) + op_true]
        )])
        sA_utxo1.txn = settlement_txn_1
        sB_utxo1.txn = settlement_txn_1
        assert validate_txn(settlement_txn_1)

        # floating update txn
        update_ts1 = int(time())-5
        update_lock1 = eltoo_update_lock(self.pubkeyA, self.pubkeyB, state)
        update_utxo1 = UTXO(update_lock1, 100)
        update_txn1 = Txn(state, update_ts1, [Entry(
            [trigger_utxo],
            [update_utxo1],
            [eltoo_witness(
                self.prvkeyA,
                self.prvkeyB,
                update_utxo1.pack() +
                functions.int_to_bytes(state) +
                functions.int_to_bytes(update_ts1),
                '01'
            ) + op_false]
        )])
        update_utxo1.txn = update_txn1
        assert validate_txn(update_txn1)

        # updated floating settlement txn
        settlement_ts_2 = int(time())
        sA_utxo2 = UTXO(settle_A_lock, 60)
        sB_utxo2 = UTXO(settle_B_lock, 40)
        settlement_txn_2 = Txn(state, settlement_ts_2, [Entry(
            [update_utxo1],
            [sA_utxo2, sB_utxo2],
            [eltoo_witness(
                self.prvkeyA,
                self.prvkeyB,
                update_utxo1.pack() +
                sA_utxo2.pack() + sB_utxo2.pack() +
                functions.int_to_bytes(state) +
                functions.int_to_bytes(settlement_ts_2)
            ) + op_true]
        )])
        sA_utxo2.txn = settlement_txn_2
        sB_utxo2.txn = settlement_txn_2
        assert validate_txn(settlement_txn_2)

        # prove that an old settlement txn witness cannot spend the later update txn
        invalid_settlement_txn_1 = Txn(state, settlement_ts_1, [Entry(
            [update_utxo1],
            [sA_utxo1, sB_utxo1],
            settlement_txn_1.entries[0].witnesses
        )])
        assert not validate_txn(invalid_settlement_txn_1)

        # floating update txn 2
        state += 1
        update_ts2 = int(time())
        update_lock2 = eltoo_update_lock(self.pubkeyA, self.pubkeyB, state)
        update_utxo2 = UTXO(update_lock2, 100)
        update_txn2 = Txn(state, update_ts2, [Entry(
            [trigger_utxo],
            [update_utxo2],
            [eltoo_witness(
                self.prvkeyA,
                self.prvkeyB,
                update_utxo2.pack() +
                functions.int_to_bytes(state) +
                functions.int_to_bytes(update_ts2),
                '01'
            ) + op_false]
        )])
        update_utxo2.txn = update_txn2
        assert validate_txn(update_txn2)

        # prove the witness can be rebound to spend the first update
        update_txn2 = Txn(state, update_ts2, [Entry(
            [update_utxo1],
            [update_utxo2],
            update_txn2.entries[0].witnesses
        )])
        assert validate_txn(update_txn2)

        # prove that the witness from the first update cannot spend the second
        invalid_update_txn2 = Txn(state+1, update_ts1, [Entry(
            [update_utxo2],
            [update_utxo1],
            update_txn1.entries[0].witnesses
        )])
        assert not validate_txn(invalid_update_txn2)
        # even with a state number that matches the update2 state
        invalid_update_txn2.sequence -= 1
        assert not validate_txn(invalid_update_txn2)
        # even with a state number that matches the update1 state
        invalid_update_txn2.sequence -= 1
        assert not validate_txn(invalid_update_txn2)


if __name__ == '__main__':
    unittest.main()
