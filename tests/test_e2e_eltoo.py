from utxos import UTXO, Entry, Txn, validate_txn, serialize, deserialize
from context import functions, tools
from nacl.signing import SigningKey, VerifyKey
from time import time
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
            val s"timestamp"
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
            serialize([genesis_utxo.pack()]) + serialize([spend_utxo.pack()]) +
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
                serialize([setup_utxo.pack()]) +
                serialize([trigger_utxo.pack()]) +
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
                serialize([trigger_utxo.pack()]) +
                serialize([sA_utxo1.pack(), sB_utxo1.pack()]) +
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
                serialize([update_utxo1.pack()]) +
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
                serialize([update_utxo1.pack()]) +
                serialize([sA_utxo2.pack(), sB_utxo2.pack()]) +
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
                serialize([update_utxo2.pack()]) +
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
