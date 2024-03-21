from context import classes
from context import errors
from context import functions
from context import parsing
from context import tools
from nacl.signing import SigningKey, VerifyKey
from queue import LifoQueue
from secrets import token_bytes
from time import time
import nacl.bindings
import unittest


class TestTools(unittest.TestCase):
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

    @classmethod
    def setUpClass(cls) -> None:
        cls.original_opcodes = {**functions.opcodes}
        cls.original_opcodes_inverse = {**functions.opcodes_inverse}
        cls.original_nopcodes = {**functions.nopcodes}
        cls.original_nopcodes_inverse = {**functions.nopcodes_inverse}
        return super().setUpClass()

    def tearDown(self) -> None:
        # some extreme monkeypatching
        ops = [op for op in functions.opcodes]
        for op in ops:
            if op not in self.original_opcodes:
                del functions.opcodes[op]

        ops = [op for op in functions.opcodes_inverse]
        for op in ops:
            if op not in self.original_opcodes_inverse:
                del functions.opcodes_inverse[op]

        nops = [nop for nop in self.original_nopcodes]
        for nop in nops:
            if nop not in functions.nopcodes:
                functions.nopcodes[nop] = self.original_nopcodes[nop]

        nops = [nop for nop in self.original_nopcodes_inverse]
        for nop in nops:
            if nop not in functions.nopcodes_inverse:
                functions.nopcodes_inverse[nop] = self.original_nopcodes_inverse[nop]

        opnames = [name for name in parsing.additional_opcodes]
        for opname in opnames:
            del parsing.additional_opcodes[opname]

        return super().tearDown()

    def test_create_merklized_script_returns_tuple_of_str_and_list(self):
        result = tools.create_merklized_script(['OP_PUSH d123'])
        assert type(result) is tuple
        assert len(result) == 2

        # locking script
        assert type(result[0]) is str
        parts = result[0].split()
        assert len(parts) == 2
        assert parts[0] == 'OP_MERKLEVAL'
        assert parts[1][0] == 'x'
        assert len(parts[1]) == 65

        # unlocking scripts
        assert type(result[1]) is list
        assert len(result[1]) == 2 # given branch + filler
        for unlocking_script in result[1]:
            assert type(unlocking_script) is str

    def test_create_merklized_script_1_branch_e2e(self):
        result = tools.create_merklized_script(['OP_PUSH d123'])
        locking_script = parsing.compile_script(result[0])
        unlocking_script = parsing.compile_script(result[1][0])

        tape, queue, cache = functions.run_script(unlocking_script + locking_script)
        assert tape.has_terminated()
        assert not queue.empty()
        assert int.from_bytes(queue.get(False), 'big') == 123
        assert queue.empty()

    def test_create_merklized_script_2_branches_e2e(self):
        result = tools.create_merklized_script(['OP_PUSH d123', 'OP_PUSH x0123'])
        locking_script = parsing.compile_script(result[0])
        unlocking_scripts = [parsing.compile_script(s) for s in result[1]]
        assert len(unlocking_scripts) == 2

        tape, queue, cache = functions.run_script(unlocking_scripts[0] + locking_script)
        assert tape.has_terminated()
        assert not queue.empty()
        assert int.from_bytes(queue.get(False), 'big') == 123
        assert queue.empty()

        tape, queue, cache = functions.run_script(unlocking_scripts[1] + locking_script)
        assert tape.has_terminated()
        assert not queue.empty()
        assert queue.get(False) == b'\x01\x23'
        assert queue.empty()

    def test_create_merklized_script_3_branches_e2e(self):
        result = tools.create_merklized_script([
            'OP_PUSH d123', 'OP_PUSH x0123', 'OP_PUSH s"hello world"'
        ])
        locking_script = parsing.compile_script(result[0])
        unlocking_scripts = [parsing.compile_script(s) for s in result[1]]
        assert len(unlocking_scripts) == 3

        tape, queue, cache = functions.run_script(unlocking_scripts[0] + locking_script)
        assert tape.has_terminated()
        assert not queue.empty()
        assert int.from_bytes(queue.get(False), 'big') == 123
        assert queue.empty()

        tape, queue, cache = functions.run_script(unlocking_scripts[1] + locking_script)
        assert tape.has_terminated()
        assert not queue.empty()
        assert queue.get(False) == b'\x01\x23'
        assert queue.empty()

        tape, queue, cache = functions.run_script(unlocking_scripts[2] + locking_script)
        assert tape.has_terminated()
        assert not queue.empty()
        assert str(queue.get(False), 'utf-8') == 'hello world'
        assert queue.empty()

    def test_create_merklized_script_20_branches_e2e(self):
        scripts = [f'OP_PUSH d{i}' for i in range(20)]
        result = tools.create_merklized_script(scripts)
        locking_script = parsing.compile_script(result[0])
        unlocking_scripts = [parsing.compile_script(s) for s in result[1]]
        assert len(unlocking_scripts) == 20

        for i in range(20):
            tape, queue, cache = functions.run_script(unlocking_scripts[i] + locking_script)
            assert tape.has_terminated()
            assert not queue.empty()
            assert int.from_bytes(queue.get(False), 'big') == i
            assert queue.empty()

    def test_add_soft_fork_e2e(self):
        locking_script_old_src = 'NOP255 d3 OP_TRUE'
        locking_script_new_src = 'OP_CHECK_ALL_EQUAL_VERIFY d3 OP_TRUE'
        good_unlocking_script_src = 'OP_PUSH x0123 OP_PUSH x0123 OP_PUSH x0123'
        bad_unlocking_script_src = 'OP_PUSH x0123 OP_PUSH x0123 OP_PUSH x3210'

        def OP_CHECK_ALL_EQUAL_VERIFY(tape: classes.Tape, queue: LifoQueue, cache: dict) -> None:
            """Replacement for NOP255: read the next bytes as uint count, take
                that many items from queue, run checks, and raise an error if
                any checks fail.
            """
            count = tape.read(1)[0]
            items = []
            for i in range(count):
                items.append(queue.get(False))

            compare = items.pop()
            while len(items):
                if items.pop() != compare:
                    raise errors.ScriptExecutionError('not all the same')

        locking_script_old = parsing.compile_script(locking_script_old_src)
        good_unlocking_script = parsing.compile_script(good_unlocking_script_src)
        bad_unlocking_script = parsing.compile_script(bad_unlocking_script_src)

        # before soft fork activation
        assert functions.run_auth_script(good_unlocking_script + locking_script_old)
        assert functions.run_auth_script(bad_unlocking_script + locking_script_old)

        # soft fork activation
        tools.add_soft_fork(255, 'OP_CHECK_ALL_EQUAL_VERIFY', OP_CHECK_ALL_EQUAL_VERIFY)

        # after soft fork activation
        locking_script_new = parsing.compile_script(locking_script_new_src)
        assert locking_script_new == locking_script_old
        assert functions.run_auth_script(good_unlocking_script + locking_script_new)
        assert not functions.run_auth_script(bad_unlocking_script + locking_script_new)

    def test_add_soft_fork_merklized_script_e2e(self):
        locking_script_old_src = 'NOP255 d3 OP_TRUE'
        locking_script_new_src = 'OP_CHECK_ALL_EQUAL_VERIFY d3 OP_TRUE'
        good_unlocking_script_src = 'OP_PUSH x0123 OP_PUSH x0123 OP_PUSH x0123'
        bad_unlocking_script_src = 'OP_PUSH x0123 OP_PUSH x0123 OP_PUSH x3210'

        def OP_CHECK_ALL_EQUAL_VERIFY(tape: classes.Tape, queue: LifoQueue, cache: dict) -> None:
            """Replacement for NOP255: read the next bytes as uint count, take
                that many items from queue, run checks, and raise an error if
                any checks fail.
            """
            count = tape.read(1)[0]
            items = []
            for i in range(count):
                items.append(queue.get(False))

            compare = items.pop()
            while len(items):
                if items.pop() != compare:
                    raise errors.ScriptExecutionError('not all the same')

        locking_script_old = parsing.compile_script(locking_script_old_src)

        # before soft fork activation
        good_scripts = [good_unlocking_script_src for i in range(20)]
        bad_scripts = [bad_unlocking_script_src for i in range(20)]

        result = tools.create_merklized_script(good_scripts)
        good_locking_script = parsing.compile_script(result[0])
        good_unlocking_scripts = [parsing.compile_script(s) for s in result[1]]

        result = tools.create_merklized_script(bad_scripts)
        bad_locking_script = parsing.compile_script(result[0])
        bad_unlocking_scripts = [parsing.compile_script(s) for s in result[1]]

        for i in range(20):
            branch = good_unlocking_scripts[i] + good_locking_script + locking_script_old
            assert functions.run_auth_script(branch)
            branch = bad_unlocking_scripts[i] + bad_locking_script + locking_script_old
            assert functions.run_auth_script(branch)

        # soft fork activation
        tools.add_soft_fork(255, 'OP_CHECK_ALL_EQUAL_VERIFY', OP_CHECK_ALL_EQUAL_VERIFY)

        # after soft fork activation
        locking_script_new = parsing.compile_script(locking_script_new_src)
        assert locking_script_new == locking_script_old

        good_scripts = [good_unlocking_script_src for i in range(20)]
        bad_scripts = [bad_unlocking_script_src for i in range(20)]

        result = tools.create_merklized_script(good_scripts)
        good_locking_script = parsing.compile_script(result[0])
        good_unlocking_scripts = [parsing.compile_script(s) for s in result[1]]

        result = tools.create_merklized_script(bad_scripts)
        bad_locking_script = parsing.compile_script(result[0])
        bad_unlocking_scripts = [parsing.compile_script(s) for s in result[1]]

        for i in range(20):
            branch = good_unlocking_scripts[i] + good_locking_script + locking_script_old
            assert functions.run_auth_script(branch)
            branch = bad_unlocking_scripts[i] + bad_locking_script + locking_script_old
            assert not functions.run_auth_script(branch)

    def test_make_adapter_locks_prv_and_make_adapter_witness_e2e(self):
        # setup lock and decrypt scripts
        tweak = token_bytes(32)
        scripts = tools.make_adapter_locks_prv(bytes(self.pubkeyA), tweak)
        assert type(scripts) in (list, tuple) and len(scripts) == 3
        script1_src, script2_src, script3_src = scripts
        verify_adapter_lock = parsing.compile_script(script1_src)
        decrypt_adapter_script = parsing.compile_script(script2_src)
        check_sig_lock = parsing.compile_script(script3_src)
        # make_adapter_locks_prv calls make_adapter_locks_pub under the hood,
        # so this counts as testing both

        # setup adapter witness
        sigfields = {
            'sigfield1': b'hello world',
            'sigfield2': b'pay Bob 2 btc pls',
        }
        tweak_point = functions.derive_point_from_scalar(
            functions.clamp_scalar(tweak)
        )
        witness_src = tools.make_adapter_witness(
            bytes(self.prvkeyA),
            tweak_point,
            sigfields
        )
        witness = tools.compile_script(witness_src)

        # run witness script
        _, queue, _ = functions.run_script(witness, sigfields)
        assert queue.qsize() == 2
        R = queue.get(False)
        sa = queue.get(False)
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(R)
        assert len(sa) == 32

        # verify adapter witness with adapter verification script
        assert functions.run_auth_script(
            witness + verify_adapter_lock,
            sigfields
        )

        # decrypt signature from witness
        _, queue, _ = functions.run_script(
            witness + decrypt_adapter_script,
            sigfields
        )
        assert queue.qsize() == 2
        RT = queue.get(False)
        s = queue.get(False)

        # check the signature with the check_sig auth script
        assert functions.run_auth_script(
            parsing.compile_script(f'push x{(RT+s).hex()}') + check_sig_lock,
            sigfields
        )

        # decrypt and check sig in one shot
        assert functions.run_auth_script(
            witness + decrypt_adapter_script + parsing.compile_script('concat') +
            check_sig_lock,
            sigfields
        )

    def test_make_adapter_lock_prv_and_make_adapter_witness_e2e(self):
        # setup lock and decrypt scripts
        tweak = token_bytes(32)
        script = tools.make_adapter_lock_prv(bytes(self.pubkeyA), tweak)
        lock = parsing.compile_script(script)
        # make_adapter_lock_prv calls make_adapter_lock_pub under the hood,
        # so this counts as testing both

        # setup adapter witness
        sigfields = {
            'sigfield1': b'hello world',
            'sigfield2': b'pay Bob 2 btc pls',
        }
        tweak_point = functions.derive_point_from_scalar(
            functions.clamp_scalar(tweak)
        )
        witness_src = tools.make_adapter_witness(
            bytes(self.prvkeyA),
            tweak_point,
            {**sigfields}
        )
        witness = tools.compile_script(f'push x{tweak.hex()} {witness_src}')

        # run witness script
        _, queue, _ = functions.run_script(witness, {**sigfields})
        assert queue.qsize() == 3
        R = queue.get(False)
        sa = queue.get(False)
        t = queue.get(False)
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(R)
        assert len(sa) == 32
        assert t == tweak

        # run combined auth script
        assert functions.run_auth_script(
            witness + lock,
            {**sigfields}
        )

    def test_make_single_sig_lock_and_make_single_sig_witness_e2e(self):
        # make lock
        sigfields = {'sigfield1': b'hello world'}
        lock_src = tools.make_single_sig_lock(bytes(self.pubkeyA))
        lock = parsing.compile_script(lock_src)

        # make witness
        unlock_src = tools.make_single_sig_witness(bytes(self.prvkeyA), {**sigfields})
        unlock = parsing.compile_script(unlock_src)

        # run e2e
        assert functions.run_auth_script(unlock + lock, {**sigfields})

    def test_make_multi_sig_lock_and_make_single_sig_witness_e2e(self):
        # make lock
        sigfields = {'sigfield1': b'hello world'}
        lock_src = tools.make_multisig_lock(
            [bytes(self.pubkeyA), bytes(self.pubkeyB)], 2)
        lock = parsing.compile_script(lock_src)

        # make witness
        unlock_src1 = tools.make_single_sig_witness(bytes(self.prvkeyA), {**sigfields})
        unlock_src2 = tools.make_single_sig_witness(bytes(self.prvkeyB), {**sigfields})
        unlock = parsing.compile_script(unlock_src1) + parsing.compile_script(unlock_src2)

        # run e2e
        assert functions.run_auth_script(unlock + lock, {**sigfields})

    def test_make_delegate_key_lock_e2e(self):
        lock_src = tools.make_delegate_key_lock(bytes(self.pubkeyA))
        lock = parsing.compile_script(lock_src)

        begin_ts = int(time()) - 120
        end_ts = int(time()) + 120
        cert_sig = tools.make_delegate_key_cert_sig(
            bytes(self.prvkeyA), bytes(self.pubkeyB), begin_ts, end_ts
        )
        assert type(cert_sig) is bytes
        assert len(cert_sig) == 64

        cache = {'sigfield1': b'hello world'}

        unlock_src = tools.make_delegate_key_unlock(
            bytes(self.prvkeyB), bytes(self.pubkeyB), begin_ts, end_ts,
            cert_sig, cache
        )
        unlock = parsing.compile_script(unlock_src)

        # run e2e
        assert functions.run_auth_script(unlock + lock, cache)

    def test_mke_htlc_sha256_lock_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        lock_src = tools.make_htlc_sha256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            preimage=preimage,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout
        )
        lock = parsing.compile_script(lock_src)

        hash_unlock_src = tools.make_htlc_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        hash_unlock = parsing.compile_script(hash_unlock_src)
        refund_unlock_src = tools.make_htlc_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )
        refund_unlock = parsing.compile_script(refund_unlock_src)

        # test that the refund will not work yet
        assert not functions.run_auth_script(refund_unlock + lock, sigfields)

        # test that the main path works
        assert functions.run_auth_script(hash_unlock + lock, sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_script(
            refund_unlock + lock,
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_mke_htlc_sha256_lock_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        lock_src = tools.make_htlc_shake256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            preimage=preimage,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout
        )
        lock = parsing.compile_script(lock_src)

        hash_unlock_src = tools.make_htlc_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        hash_unlock = parsing.compile_script(hash_unlock_src)
        refund_unlock_src = tools.make_htlc_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )
        refund_unlock = parsing.compile_script(refund_unlock_src)

        # test that the refund will not work yet
        assert not functions.run_auth_script(refund_unlock + lock, sigfields)

        # test that the main path works
        assert functions.run_auth_script(hash_unlock + lock, sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_script(
            refund_unlock + lock,
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )


if __name__ == '__main__':
    unittest.main()
