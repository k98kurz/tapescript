from context import classes, errors, functions, parsing, tools
from hashlib import sha256, shake_256
from nacl.signing import SigningKey, VerifyKey
from random import randint
from time import time
import nacl.bindings
import unittest

try:
    from secrets import token_bytes
except ImportError:
    from os import urandom
    def token_bytes(count: int) -> bytes:
        return urandom(count)


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
        self.prvkeyC = SigningKey(b'extra yellow is yellow submarine')
        self.pubkeyC = self.prvkeyC.verify_key
        self.prvkeyD = SigningKey(b'very submarine such yellow wow..')
        self.pubkeyD = self.prvkeyD.verify_key
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

    def test_Script_class_e2e(self):
        src1, src2 = '', ''
        code1, code2 = b'', b''
        decompiled1, decompiled2 = '', ''

        # get test vectors
        with open('tests/vectors/4.src', 'r') as f:
            src1 = f.read()
        with open('tests/vectors/4_decompiled.src', 'r') as f:
            decompiled1 = f.read()
        with open('tests/vectors/4.hex', 'r') as f:
            code1 = bytes.fromhex(''.join(f.read().split()))
        with open('tests/vectors/5.src', 'r') as f:
            src2 = f.read()
        with open('tests/vectors/5_decompiled.src', 'r') as f:
            decompiled2 = f.read()
        with open('tests/vectors/5.hex', 'r') as f:
            code2 = bytes.fromhex(''.join(f.read().split()))

        # create scripts from src vectors
        script1 = tools.Script.from_src(src1)
        script2 = tools.Script.from_src(src2)

        # test compilation was correct
        assert script1.bytes == code1
        assert script2.bytes == code2

        # test addition
        script3 = script1 + script2
        assert script1.src in script3.src
        assert script2.src in script3.src
        assert script3.bytes == script1.bytes + script2.bytes

        # create scripts from bytes vectors
        script1 = tools.Script.from_bytes(code1)
        script2 = tools.Script.from_bytes(code2)

        # test decompilation was correct
        assert script1.src == decompiled1, f'{script1.src=}\n\n{decompiled1=}'
        assert script2.src == decompiled2, f'{script2.src=}\n\n{decompiled2=}'

    def test_merklized_script_tree_classes_e2e(self):
        tree = tools.ScriptNode(
            tools.ScriptNode(
                tools.ScriptLeaf.from_src(f'sha256 push x{sha256(b"secret").digest().hex()} equal'),
                tools.ScriptLeaf.from_src('true'),
            ),
            tools.ScriptNode(
                tools.ScriptLeaf.from_src('push s"hello world"'),
                tools.ScriptLeaf.from_src('true'),
            )
        )

        unlock = tree.right.right.unlocking_script()
        assert type(unlock) is tools.Script

        lock = tree.locking_script()
        assert type(lock) is tools.Script
        assert functions.run_auth_scripts([unlock.bytes, lock.bytes])

        unlock = tree.left.left.unlocking_script()
        assert type(unlock) is tools.Script

        lock = tree.locking_script()
        assert type(lock) is tools.Script
        assert functions.run_auth_scripts(
            [tools.Script.from_src('push s"secret"'), unlock, lock]
        )

        packed = tree.pack()
        unpacked = tools.ScriptNode.unpack(packed)
        assert unpacked.locking_script().bytes == lock.bytes
        assert unpacked.right.right.commitment() == tree.right.right.commitment()

    def test_make_merklized_script_prioritized_returns_tuple_of_Script_and_list_of_Scripts(self):
        result = tools.make_merklized_script_prioritized(['OP_PUSH d123'])
        assert type(result) is tuple
        assert len(result) == 2

        # locking script
        assert type(result[0]) is tools.Script
        parts = result[0].src.split()
        assert len(parts) == 2
        assert parts[0] == 'OP_MERKLEVAL'
        assert parts[1][0] == 'x'
        assert len(parts[1]) == 65

        # unlocking scripts
        assert type(result[1]) is list
        assert len(result[1]) == 2 # given branch + filler
        for unlocking_script in result[1]:
            assert type(unlocking_script) is tools.Script

    def test_make_merklized_script_prioritized_1_branch_e2e(self):
        lock, unlocks = tools.make_merklized_script_prioritized(['OP_PUSH d123'])
        locking_script = lock.bytes
        unlocking_script = unlocks[0].bytes

        tape, stack, cache = functions.run_script(unlocking_script + locking_script)
        assert tape.has_terminated()
        assert not stack.empty()
        item = stack.get()
        assert int.from_bytes(item, 'big') == 123, item.hex()
        assert stack.empty()

    def test_make_merklized_script_prioritized_2_branches_e2e(self):
        lock, unlocks = tools.make_merklized_script_prioritized(['OP_PUSH d123', 'OP_PUSH x0123'])
        locking_script = lock.bytes
        unlocking_scripts = [s.bytes for s in unlocks]
        assert len(unlocking_scripts) == 2

        tape, stack, cache = functions.run_script(unlocking_scripts[0] + locking_script)
        assert tape.has_terminated()
        assert not stack.empty()
        assert int.from_bytes(stack.get(), 'big') == 123
        assert stack.empty()

        tape, stack, cache = functions.run_script(unlocking_scripts[1] + locking_script)
        assert tape.has_terminated()
        assert not stack.empty()
        assert stack.get() == b'\x01\x23'
        assert stack.empty()

    def test_make_merklized_script_prioritized_3_branches_e2e(self):
        lock, unlocks = tools.make_merklized_script_prioritized([
            'OP_PUSH d123', 'OP_PUSH x0123', 'OP_PUSH s"hello world"'
        ])
        locking_script = lock.bytes
        unlocking_scripts = [s.bytes for s in unlocks]
        assert len(unlocking_scripts) == 3

        tape, stack, cache = functions.run_script(unlocking_scripts[0] + locking_script)
        assert tape.has_terminated()
        assert not stack.empty()
        assert int.from_bytes(stack.get(), 'big') == 123
        assert stack.empty()

        tape, stack, cache = functions.run_script(unlocking_scripts[1] + locking_script)
        assert tape.has_terminated()
        assert not stack.empty()
        assert stack.get() == b'\x01\x23'
        assert stack.empty()

        tape, stack, cache = functions.run_script(unlocking_scripts[2] + locking_script)
        assert tape.has_terminated()
        assert not stack.empty()
        assert str(stack.get(), 'utf-8') == 'hello world'
        assert stack.empty()

    def test_make_merklized_script_prioritized_20_branches_e2e(self):
        scripts = [f'OP_PUSH d{i}' for i in range(20)]
        lock, unlocks = tools.make_merklized_script_prioritized(scripts)
        locking_script = lock.bytes
        unlocking_scripts = [s.bytes for s in unlocks]
        assert len(unlocking_scripts) == 20

        for i in range(20):
            tape, stack, cache = functions.run_script(unlocking_scripts[i] + locking_script)
            assert tape.has_terminated()
            assert not stack.empty()
            assert int.from_bytes(stack.get(), 'big') == i
            assert stack.empty()

    def test_make_script_tree_balanced_4_leaves_e2e(self):
        scripts = [f'push d{i} pop0 true' for i in range(4)]
        tree = tools.make_script_tree_balanced(scripts)
        assert type(tree.left) is tools.ScriptNode
        assert type(tree.left.left) is tools.ScriptLeaf
        assert type(tree.left.right) is tools.ScriptLeaf
        assert type(tree.right) is tools.ScriptNode
        assert type(tree.right.left) is tools.ScriptLeaf
        assert type(tree.right.right) is tools.ScriptLeaf

    def test_make_script_tree_balanced_7_leaves_e2e(self):
        scripts = [f'push d{i} pop0 true' for i in range(7)]
        tree = tools.make_script_tree_balanced(scripts)
        lock = tree.locking_script()

        # prove structure is perfectly balanced as all things should be
        assert type(tree.left) is tools.ScriptNode
        assert type(tree.left.left) is tools.ScriptNode
        assert type(tree.left.left.left) is tools.ScriptLeaf
        assert type(tree.left.left.right) is tools.ScriptLeaf
        assert type(tree.left.right) is tools.ScriptNode
        assert type(tree.left.right.left) is tools.ScriptLeaf
        assert type(tree.left.right.right) is tools.ScriptLeaf
        assert type(tree.right) is tools.ScriptNode
        assert type(tree.right.left) is tools.ScriptNode
        assert type(tree.right.left.left) is tools.ScriptLeaf
        assert type(tree.right.left.right) is tools.ScriptLeaf
        assert type(tree.right.right) is tools.ScriptNode
        assert type(tree.right.right.left) is tools.ScriptLeaf
        assert type(tree.right.right.right) is tools.ScriptLeaf

        # prove a good leaf validates
        unlock = tree.left.left.left.unlocking_script()
        assert functions.run_auth_scripts([unlock, lock])

        # prove the filler leaf does not validate
        unlock = tree.right.right.right.unlocking_script()
        assert not functions.run_auth_scripts([unlock, lock])
        # even if we inject an OP_TRUE
        hax = tools.Script.from_src('true')
        assert not functions.run_auth_scripts([hax, unlock, lock])
        assert not functions.run_auth_scripts([unlock, hax, lock])
        assert not functions.run_auth_scripts([unlock, lock, hax])

    def test_make_merklized_script_balanced_4_leaves_e2e(self):
        scripts = [f'push d{i} pop0 true' for i in range(4)]
        lock, unlocks = tools.make_merklized_script_balanced(scripts)
        assert len(unlocks) == 4, len(unlocks)
        assert lock.src.split()[0] == 'OP_MERKLEVAL'

        for unlock in unlocks:
            assert functions.run_auth_scripts([unlock, lock])

    def test_make_merklized_script_balanced_7_leaves_e2e(self):
        scripts = [f'push d{i} pop0 true' for i in range(7)]
        lock, unlocks = tools.make_merklized_script_balanced(scripts)
        assert len(unlocks) == 7, len(unlocks)
        assert lock.src.split()[0] == 'OP_MERKLEVAL'

        for unlock in unlocks:
            assert functions.run_auth_scripts([unlock, lock])

    def test_add_soft_fork_e2e(self):
        locking_script_old_src = 'NOP255 d3 OP_TRUE'
        locking_script_new_src = 'OP_CHECK_ALL_EQUAL_VERIFY d3 OP_TRUE'
        good_unlocking_script_src = 'OP_PUSH x0123 OP_PUSH x0123 OP_PUSH x0123'
        bad_unlocking_script_src = 'OP_PUSH x0123 OP_PUSH x0123 OP_PUSH x3210'

        def OP_CHECK_ALL_EQUAL_VERIFY(tape: classes.Tape, stack: classes.Stack, cache: dict) -> None:
            """Replacement for NOP255: read the next bytes as uint count, take
                that many items from stack, run checks, and raise an error if
                any checks fail.
            """
            count = tape.read(1)[0]
            items = []
            for i in range(count):
                items.append(stack.get())

            compare = items.pop()
            while len(items):
                if items.pop() != compare:
                    raise errors.ScriptExecutionError('not all the same')

        locking_script_old = parsing.compile_script(locking_script_old_src)
        good_unlocking_script = parsing.compile_script(good_unlocking_script_src)
        bad_unlocking_script = parsing.compile_script(bad_unlocking_script_src)

        # before soft fork activation
        assert functions.run_auth_scripts([good_unlocking_script, locking_script_old])
        assert functions.run_auth_scripts([bad_unlocking_script, locking_script_old])

        # soft fork activation
        tools.add_soft_fork(255, 'OP_CHECK_ALL_EQUAL_VERIFY', OP_CHECK_ALL_EQUAL_VERIFY)

        # after soft fork activation
        locking_script_new = parsing.compile_script(locking_script_new_src)
        assert locking_script_new == locking_script_old
        assert functions.run_auth_scripts([good_unlocking_script, locking_script_new])
        assert not functions.run_auth_scripts([bad_unlocking_script, locking_script_new])

    def test_add_soft_fork_merklized_script_e2e(self):
        locking_script_old_src = 'NOP255 d3 OP_TRUE'
        locking_script_new_src = 'OP_CHECK_ALL_EQUAL_VERIFY d3 OP_TRUE'
        good_unlocking_script_src = 'OP_PUSH x0123 OP_PUSH x0123 OP_PUSH x0123'
        bad_unlocking_script_src = 'OP_PUSH x0123 OP_PUSH x0123 OP_PUSH x3210'

        def OP_CHECK_ALL_EQUAL_VERIFY(tape: classes.Tape, stack: classes.Stack, cache: dict) -> None:
            """Replacement for NOP255: read the next bytes as uint count, take
                that many items from stack, run checks, and raise an error if
                any checks fail.
            """
            count = tape.read(1)[0]
            items = []
            for i in range(count):
                items.append(stack.get())

            compare = items.pop()
            while len(items):
                if items.pop() != compare:
                    raise errors.ScriptExecutionError('not all the same')

        locking_script_old = parsing.compile_script(locking_script_old_src)

        # before soft fork activation
        good_scripts = [good_unlocking_script_src for i in range(20)]
        bad_scripts = [bad_unlocking_script_src for i in range(20)]

        result = tools.make_merklized_script_prioritized(good_scripts)
        good_locking_script = result[0].bytes
        good_unlocking_scripts = [s.bytes for s in result[1]]

        result = tools.make_merklized_script_prioritized(bad_scripts)
        bad_locking_script = result[0].bytes
        bad_unlocking_scripts = [s.bytes for s in result[1]]

        for i in range(20):
            branch = good_unlocking_scripts[i] + good_locking_script + locking_script_old
            assert functions.run_auth_scripts([branch])
            branch = bad_unlocking_scripts[i] + bad_locking_script + locking_script_old
            assert functions.run_auth_scripts([branch])

        # soft fork activation
        tools.add_soft_fork(255, 'OP_CHECK_ALL_EQUAL_VERIFY', OP_CHECK_ALL_EQUAL_VERIFY)

        # after soft fork activation
        locking_script_new = parsing.compile_script(locking_script_new_src)
        assert locking_script_new == locking_script_old

        good_scripts = [good_unlocking_script_src for i in range(20)]
        bad_scripts = [bad_unlocking_script_src for i in range(20)]

        result = tools.make_merklized_script_prioritized(good_scripts)
        good_locking_script = result[0].bytes
        good_unlocking_scripts = [s.bytes for s in result[1]]

        result = tools.make_merklized_script_prioritized(bad_scripts)
        bad_locking_script = result[0].bytes
        bad_unlocking_scripts = [s.bytes for s in result[1]]

        for i in range(20):
            branch = good_unlocking_scripts[i] + good_locking_script + locking_script_old
            assert functions.run_auth_scripts([branch])
            branch = bad_unlocking_scripts[i] + bad_locking_script + locking_script_old
            assert not functions.run_auth_scripts([branch])

    def test_make_scripthash_lock_and_make_scripthash_witness_e2e(self):
        committed_script = tools.Script.from_src('true')
        lock = tools.make_scripthash_lock(committed_script)
        assert isinstance(lock, functions.ScriptProtocol)
        witness = tools.make_scripthash_witness(committed_script)
        assert isinstance(witness, functions.ScriptProtocol)
        assert functions.run_auth_scripts([witness, lock])

    def test_make_adapter_locks_prv_and_make_adapter_witness_e2e(self):
        # setup lock and decrypt scripts
        tweak = token_bytes(32)
        scripts = tools.make_adapter_locks_prv(bytes(self.pubkeyA), tweak)
        assert type(scripts) is tuple and len(scripts) == 3
        script1, script2, script3 = scripts
        verify_adapter_lock = script1.bytes
        decrypt_adapter_script = script2.bytes
        check_sig_lock = script3.bytes
        # make_adapter_locks_prv calls make_adapter_locks_pub and
        # make_adapter_decrypt under the hood, so this counts as testing both

        # setup adapter witness
        sigfields = {
            'sigfield1': b'hello world',
            'sigfield2': b'pay Bob 2 btc pls',
        }
        tweak_point = functions.derive_point_from_scalar(
            functions.clamp_scalar(tweak)
        )
        witness = tools.make_adapter_witness(
            bytes(self.prvkeyA),
            tweak_point,
            sigfields
        ).bytes

        # run witness script
        _, stack, _ = functions.run_script(witness, sigfields)
        assert len(stack) == 2
        R = stack.get()
        sa = stack.get()
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(R)
        assert len(sa) == 32

        # verify adapter witness with adapter verification script
        assert functions.run_auth_scripts(
            [witness, verify_adapter_lock],
            sigfields
        )

        # decrypt signature from witness
        _, stack, _ = functions.run_script(
            witness + decrypt_adapter_script,
            sigfields
        )
        assert len(stack) == 2
        s = stack.get()
        RT = stack.get()

        # decrypt method 2
        assert tools.decrypt_adapter(witness, tweak) == RT + s

        # check the signature with the check_sig auth script
        assert functions.run_auth_scripts(
            [parsing.compile_script(f'push x{(RT+s).hex()}'), check_sig_lock],
            sigfields
        )

        # decrypt and check sig in one shot
        assert functions.run_auth_scripts([
                witness, decrypt_adapter_script,
                parsing.compile_script('concat'),
                check_sig_lock
            ], sigfields
        )

    def test_make_adapter_lock_prv_and_make_adapter_witness_e2e(self):
        # setup lock and decrypt scripts
        tweak = token_bytes(32)
        script = tools.make_adapter_lock_prv(bytes(self.pubkeyA), tweak)
        lock = script.bytes
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
        _, stack, _ = functions.run_script(witness, {**sigfields})
        assert len(stack) == 3
        R = stack.get()
        sa = stack.get()
        t = stack.get()
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(R)
        assert len(sa) == 32
        assert t == tweak

        # run combined auth script
        assert functions.run_auth_scripts(
            [witness, lock],
            {**sigfields}
        )

    def test_double_tweak_adapters_e2e(self):
        t1 = functions.clamp_scalar(token_bytes(32))
        t2 = functions.clamp_scalar(token_bytes(32))
        T1 = functions.derive_point_from_scalar(t1)
        T2 = functions.derive_point_from_scalar(t2)
        tt = functions.aggregate_scalars([t1, t2])
        TT = functions.aggregate_points([T1, T2])
        assert TT == functions.derive_point_from_scalar(tt)

        scripts1 = tools.make_adapter_locks_pub(bytes(self.pubkeyA), TT)
        scripts2 = tools.make_adapter_locks_pub(bytes(self.pubkeyB), TT)

        verify_adapter_1 = scripts1[0].bytes
        verify_signature_1 = scripts1[1].bytes
        verify_adapter_2 = scripts2[0].bytes
        verify_signature_2 = scripts2[1].bytes

        sigfields = {'sigfield1': b'we both get what we want'}
        adapter_witness1 = tools.make_adapter_witness(bytes(self.prvkeyA), TT, sigfields).bytes
        adapter_witness2 = tools.make_adapter_witness(bytes(self.prvkeyB), TT, sigfields).bytes

        # verify adapters
        assert functions.run_auth_scripts([adapter_witness1, verify_adapter_1], sigfields)
        assert functions.run_auth_scripts([adapter_witness2, verify_adapter_2], sigfields)

        # decrypt signatures
        sig1 = tools.decrypt_adapter(adapter_witness1, tt)
        sig2 = tools.decrypt_adapter(adapter_witness2, tt)

        # verify signatures
        assert functions.run_auth_scripts(
            [parsing.compile_script(f'push x{sig1.hex()}'), verify_signature_1],
            sigfields
        )
        assert functions.run_auth_scripts(
            [parsing.compile_script(f'push x{sig2.hex()}'), verify_signature_2],
            sigfields
        )

    def test_make_single_sig_lock_and_make_single_sig_witness_e2e(self):
        # make lock
        sigfields = {'sigfield1': b'hello world'}
        lock = tools.make_single_sig_lock(bytes(self.pubkeyA)).bytes

        # make witness
        unlock = tools.make_single_sig_witness(bytes(self.prvkeyA), {**sigfields}).bytes

        # run e2e
        assert functions.run_auth_scripts([unlock, lock], {**sigfields})

    def test_make_single_sig_lock2_and_make_single_sig_witness2_e2e(self):
        # make lock
        sigfields = {'sigfield1': b'hello world'}
        lock = tools.make_single_sig_lock2(bytes(self.pubkeyA))

        # make witness
        unlock = tools.make_single_sig_witness2(bytes(self.prvkeyA), {**sigfields})

        # run e2e
        assert functions.run_auth_scripts([unlock.bytes, lock.bytes], {**sigfields})

    def test_make_multi_sig_lock_and_make_single_sig_witness_e2e(self):
        # make lock
        sigfields = {'sigfield1': b'hello world'}
        lock = tools.make_multisig_lock(
            [bytes(self.pubkeyA), bytes(self.pubkeyB)], 2, 'f0'
        )

        # make witness
        unlock1 = tools.make_single_sig_witness(bytes(self.prvkeyA), {**sigfields}, 'f0')
        unlock2 = tools.make_single_sig_witness(bytes(self.prvkeyB), {**sigfields}, 'f0')
        unlock = unlock1.bytes + unlock2.bytes

        # run e2e
        assert functions.run_auth_scripts([unlock, lock.bytes], {**sigfields})

    def test_make_delegate_key_lock_e2e(self):
        lock = tools.make_delegate_key_lock(bytes(self.pubkeyA))

        begin_ts = int(time()) - 120
        end_ts = int(time()) + 120
        cert = tools.make_delegate_key_cert(
            bytes(self.prvkeyA), bytes(self.pubkeyB), begin_ts, end_ts
        )
        assert type(cert) is bytes
        assert len(cert) == 105, len(cert)

        cache = {'sigfield1': b'hello world'}

        unlock = tools.make_delegate_key_witness(
            bytes(self.prvkeyB), cert, cache
        )
        assert len(lock.bytes) == 98, len(lock.bytes)
        assert len(unlock.bytes) == 173, len(unlock.bytes)

        # run e2e
        assert functions.run_auth_scripts([unlock, lock], cache), (unlock + lock).src

    def test_make_delegate_key_chain_lock_e2e(self):
        lock = tools.make_delegate_key_chain_lock(bytes(self.pubkeyA))

        begin_ts = int(time()) - 120
        end_ts = int(time()) + 120
        cert1 = tools.make_delegate_key_cert(
            bytes(self.prvkeyA), bytes(self.pubkeyB), begin_ts, end_ts
        )
        assert type(cert1) is bytes
        assert len(cert1) == 105, len(cert1)

        cache = {'sigfield1': b'hello world'}

        unlock = tools.make_delegate_key_chain_witness(
            bytes(self.prvkeyB), [cert1], cache
        )
        assert len(lock.bytes) == 128, len(lock.bytes)
        assert len(unlock.bytes) == 174, (len(unlock.bytes), unlock.src)

        # run e2e 1 cert
        assert functions.run_auth_scripts([unlock, lock], cache), (unlock+lock).src

        cert2 = tools.make_delegate_key_cert(
            bytes(self.prvkeyB), bytes(self.pubkeyC), begin_ts, end_ts
        )
        assert type(cert2) is bytes
        assert len(cert2) == 105, len(cert2)

        unlock = tools.make_delegate_key_chain_witness(
            bytes(self.prvkeyC), [cert2, cert1], cache
        )
        assert len(unlock.bytes) == 282, (len(unlock.bytes), unlock.src)

        # run e2e 2 certs chained
        assert functions.run_auth_scripts([unlock.bytes, lock.bytes], cache)

    def test_make_graftroot_lock_e2e(self):
        sigfields = {'sigfield1': b'hello world'}
        lock = tools.make_graftroot_lock(bytes(self.pubkeyA))
        assert len(lock.bytes) == 58, len(lock.bytes)

        unlock = tools.make_graftroot_witness_keyspend(bytes(self.prvkeyA), sigfields)
        assert len(unlock.bytes) == 67, len(unlock.bytes)

        # run e2e
        assert functions.run_auth_scripts([unlock, lock], sigfields), \
            (unlock + lock).src

        script = tools.Script.from_src('true')
        surrogate = tools.make_scripthash_lock(script)
        unlock1 = tools.make_scripthash_witness(script)
        unlock2 = tools.make_graftroot_witness_surrogate(bytes(self.prvkeyA), surrogate)
        assert len(unlock2.bytes) == len(surrogate.bytes) + 69, \
            (len(unlock2.bytes), len(surrogate.bytes))

        # run e2e
        assert functions.run_auth_scripts([unlock1, unlock2, lock], sigfields)

        # additional length check
        surrogate = tools.Script.from_src('true')
        unlock2 = tools.make_graftroot_witness_surrogate(bytes(self.prvkeyA), surrogate)
        assert len(unlock2.bytes) == len(surrogate.bytes) + 68, \
            (len(unlock2.bytes), len(surrogate.bytes))

    def test_make_htlc_sha256_lock_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        lock = tools.make_htlc_sha256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            preimage=preimage,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout
        )

        hash_unlock = tools.make_htlc_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        refund_unlock = tools.make_htlc_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([hash_unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_htlc_sha256_lock_with_digest_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        lock = tools.make_htlc_sha256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            digest=sha256(preimage).digest(),
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout
        )

        hash_unlock = tools.make_htlc_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        refund_unlock = tools.make_htlc_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([hash_unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_htlc_shake256_lock_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        hash_size = randint(16, 40)
        lock = tools.make_htlc_shake256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            preimage=preimage,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout,
            hash_size=hash_size
        )

        hash_unlock = tools.make_htlc_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        refund_unlock = tools.make_htlc_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([hash_unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_htlc_shake256_lock_with_digest_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        hash_size = randint(16, 40)
        digest = shake_256(preimage).digest(hash_size)
        lock = tools.make_htlc_shake256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            digest=digest,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout,
            hash_size=hash_size
        )

        hash_unlock = tools.make_htlc_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        refund_unlock = tools.make_htlc_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([hash_unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_htlc2_sha256_lock_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        lock = tools.make_htlc2_sha256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            preimage=preimage,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout
        )

        hash_unlock = tools.make_htlc2_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        refund_unlock = tools.make_htlc2_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([hash_unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_htlc2_sha256_lock_with_digest_e2e(self):
        preimage = token_bytes(16)
        digest = sha256(preimage).digest()
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        lock = tools.make_htlc2_sha256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            digest=digest,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout
        )

        hash_unlock = tools.make_htlc2_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        refund_unlock = tools.make_htlc2_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([hash_unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_htlc2_shake256_lock_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        hash_size = randint(16, 40)
        lock = tools.make_htlc2_shake256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            preimage=preimage,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout,
            hash_size=hash_size
        )

        hash_unlock = tools.make_htlc2_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        refund_unlock = tools.make_htlc2_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([hash_unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_htlc2_shake256_lock_with_digest_e2e(self):
        preimage = token_bytes(16)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        hash_size = randint(16, 40)
        digest = shake_256(preimage).digest(hash_size)
        lock = tools.make_htlc2_shake256_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            digest=digest,
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout,
            hash_size=hash_size
        )

        hash_unlock = tools.make_htlc2_witness(
            prvkey=bytes(self.prvkeyB),
            preimage=preimage,
            sigfields=sigfields
        )
        refund_unlock = tools.make_htlc2_witness(
            bytes(self.prvkeyA), b'refund', sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([hash_unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_ptlc_lock_e2e(self):
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        lock = tools.make_ptlc_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            refund_pubkey=bytes(self.pubkeyA),
            timeout=timeout
        )

        unlock = tools.make_ptlc_witness(
            prvkey=bytes(self.prvkeyB),
            sigfields=sigfields
        )
        refund_unlock = tools.make_ptlc_refund_witness(
            bytes(self.prvkeyA), sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_ptlc_lock_with_tweak_e2e(self):
        tweak_scalar = functions.clamp_scalar(token_bytes(32), True)
        tweak_point = functions.derive_point_from_scalar(tweak_scalar)
        sigfields = {'sigfield1': b'hello world'}
        # NB: ts_threshold is 60, preventing timestamps >60s into future from verifying
        timeout = 30
        lock = tools.make_ptlc_lock(
            receiver_pubkey=bytes(self.pubkeyB),
            refund_pubkey=bytes(self.pubkeyA),
            tweak_point=tweak_point,
            timeout=timeout,
        )

        unlock = tools.make_ptlc_witness(
            prvkey=bytes(self.prvkeyB),
            sigfields=sigfields,
            tweak_scalar=tweak_scalar,
        )
        refund_unlock = tools.make_ptlc_refund_witness(
            bytes(self.prvkeyA), sigfields
        )

        # test that the refund will not work yet
        assert not functions.run_auth_scripts([refund_unlock.bytes, lock.bytes], sigfields)

        # test that the main path works
        assert functions.run_auth_scripts([unlock.bytes, lock.bytes], sigfields)

        # test that the refund will work if the timestamp is past the timeout
        assert functions.run_auth_scripts(
            [refund_unlock.bytes, lock.bytes],
            {**sigfields, 'timestamp': int(time()) + timeout + 1}
        )

    def test_make_taproot_lock_and_witnesses_e2e(self):
        sigfields = {'sigfield1': b'hello ', 'sigfield2': b'world'}
        script = tools.Script.from_src('true')
        x = functions.derive_key_from_seed(bytes(self.prvkeyA))
        X = bytes(self.pubkeyA)
        t = functions.clamp_scalar(sha256(X + script.commitment()).digest())
        T = functions.derive_point_from_scalar(t)
        root = functions.aggregate_points((X, T))
        sig = functions.sign_with_scalar(
            functions.aggregate_scalars([x, t]),
            b'hello world'
        )

        lock = tools.make_taproot_lock(X, script, sigflags='01')
        assert lock.src == f'push x{root.hex()} tr x01', lock.src
        assert len(lock.bytes) == 36, len(lock.bytes)

        unlock1 = tools.make_taproot_witness_keyspend(
            bytes(self.prvkeyA),
            sigfields,
            script
        )
        assert unlock1.src == f'push x{sig.hex()}', \
            f'\nexpected push x{sig.hex()}\nobserved {unlock1.src}'
        assert len(unlock1.bytes) == 66, len(unlock1.bytes)

        unlock2 = tools.make_taproot_witness_scriptspend(X, script)
        assert unlock2.src == f'push x{script.bytes.hex()} push x{X.hex()}'
        assert len(unlock2.bytes) == 35 + len(script.bytes), \
            (len(unlock2.bytes), len(script.bytes))

        assert functions.run_auth_scripts([unlock1, lock], sigfields)
        assert functions.run_auth_scripts([unlock2, lock], sigfields)

        sig = functions.sign_with_scalar(
            functions.aggregate_scalars((x, t)),
            b'world'
        )

        unlock1 = tools.make_taproot_witness_keyspend(
            bytes(self.prvkeyA),
            sigfields,
            script,
            sigflags='01'
        )
        assert unlock1.src == f'push x{sig.hex()}01', \
            f'\nexpected push x{sig.hex()}01\nobserved {unlock1.src}'
        assert functions.run_auth_scripts([unlock1, lock], sigfields)

    def test_make_nonnative_taproot_lock_e2e(self):
        sigfields = {'sigfield1': b'hello ', 'sigfield2': b'world'}
        script = tools.Script.from_src('true')

        lock = tools.make_nonnative_taproot_lock(bytes(self.pubkeyA), script)
        assert len(lock.bytes) == 72, (lock.src, len(lock.bytes))

        unlock1 = tools.make_taproot_witness_keyspend(
            bytes(self.prvkeyA),
            sigfields,
            script
        )

        unlock2 = tools.make_taproot_witness_scriptspend(bytes(self.pubkeyA), script)

        assert functions.run_auth_scripts([unlock1, lock], sigfields)
        assert functions.run_auth_scripts([unlock2, lock], sigfields), \
            (unlock2 + lock).src

        unlock1 = tools.make_taproot_witness_keyspend(
            bytes(self.prvkeyA),
            sigfields,
            script
        )
        assert functions.run_auth_scripts([unlock1, lock], sigfields)

    def test_make_graftap_lock_and_witnesses_e2e(self):
        sigfields = {'sigfield1': b'hello world'}
        lock = tools.make_graftap_lock(bytes(self.pubkeyA))
        assert len(lock.bytes) == 36, len(lock.bytes)

        unlock = tools.make_graftap_witness_keyspend(bytes(self.prvkeyA), sigfields)
        assert len(unlock.bytes) == 66, len(unlock.bytes)

        # run e2e
        assert functions.run_auth_scripts([unlock, lock], sigfields)

        script = tools.Script.from_src('true')
        surrogate = tools.make_scripthash_lock(script)
        unlock1 = tools.make_scripthash_witness(script)
        unlock2 = tools.make_graftap_witness_scriptspend(
            bytes(self.prvkeyA), surrogate
        )
        assert len(unlock2.bytes) == len(surrogate.bytes) + 145, \
            (len(unlock2.bytes), len(surrogate.bytes))

        # run e2e
        assert functions.run_auth_scripts([unlock1, unlock2, lock], sigfields), \
            (unlock1 + unlock2 + lock).src

        # another length check
        script = tools.Script.from_src('true')
        unlock2 = tools.make_graftap_witness_scriptspend(
            bytes(self.prvkeyA), surrogate
        )
        assert len(unlock2.bytes) == len(surrogate.bytes) + 145, \
            (len(unlock2.bytes), len(surrogate.bytes))

    def test_AMHL_primitive(self):
        """Test for setup, locking, and release of an Anonymous Multi-
            Hop Lock using the homomorphic one-way ability of ed25519.
        """
        # first run the initial setup for 5 payers (4 intermediate)
        n = 5
        s = tools.AMHL.setup(n)

        # validate setups for each user
        for i in range(len(s[0])):
            assert tools.AMHL.check_setup(tools.AMHL.setup_for(s, i), i, n)

        # validate releasing of locks from right to left
        s_n = tools.AMHL.setup_for(s, n)
        k = s_n[1]

        for i in range(n-1, 1, -1):
            s_i = tools.AMHL.setup_for(s, i)
            r = tools.AMHL.release(k, s_i[2])
            assert tools.AMHL.verify_lock_key(tools.AMHL.setup_for(s, i-1)[1], r)
            k = r

    def test_setup_amhl_adapter_locks(self):
        pubkeys = [
            bytes(self.pubkeyA),
            bytes(self.pubkeyB),
            bytes(self.pubkeyC),
        ]
        prvkeys = [
            bytes(self.prvkeyA),
            bytes(self.prvkeyB),
            bytes(self.prvkeyC),
        ]
        amhl = tools.setup_amhl(b'123', pubkeys)
        assert type(amhl) is dict
        for pk in pubkeys:
            assert pk in amhl
        assert 'key' in amhl
        sigfields = [
            {'sigfield1': b'pay Bob 1.2'},
            {'sigfield1': b'pay Carla 1.1'},
            {'sigfield1': b'pay Dave 1.0'},
        ]

        adapter_witnesses = [
            tools.make_adapter_witness(prvkeys[i], amhl[pubkeys[i]][2], sigfields[i])
            for i in range(len(prvkeys))
        ]

        # validate adapter witnesses
        for i in range(len(adapter_witnesses)):
            assert functions.run_auth_scripts(
                [adapter_witnesses[i].bytes, amhl[pubkeys[i]][0].bytes],
                sigfields[i]
            )

        Alice = {
            'outbound_txn': {
                'sigfields': sigfields[0],
                'adapter_lock': amhl[pubkeys[0]][0],
                'adapter_witness': adapter_witnesses[0].bytes,
                'locking_script': amhl[pubkeys[0]][1].bytes,
            },
            'tweak_point': amhl[pubkeys[0]][2],
            'scalar': amhl[pubkeys[0]][3],
        }

        Bob = {
            'outbound_txn': {
                'sigfields': sigfields[1],
                'adapter_lock': amhl[pubkeys[1]][0],
                'adapter_witness': adapter_witnesses[1].bytes,
                'locking_script': amhl[pubkeys[1]][1].bytes,
            },
            'inbound_txn': Alice['outbound_txn'],
            'tweak_point': amhl[pubkeys[1]][2],
            'scalar': amhl[pubkeys[1]][3],
        }

        Carla = {
            'outbound_txn': {
                'sigfields': sigfields[2],
                'adapter_lock': amhl[pubkeys[2]][0],
                'adapter_witness': adapter_witnesses[2].bytes,
                'locking_script': amhl[pubkeys[2]][1].bytes,
            },
            'inbound_txn': Bob['outbound_txn'],
            'tweak_point': amhl[pubkeys[2]][2],
            'scalar': amhl[pubkeys[2]][3],
        }

        Dave = {
            'inbound_txn': Carla['outbound_txn'],
            'scalar': amhl['key'],
        }

        # unlock from right to left; decrypt last hop first
        # after a payment route has been set up, the payer sends the scalar to
        # the final recipient to begin the process; the decrypted signature is
        # sent back to the previous hop correspondent C to clear, thus hop C
        # will be able to unlock the payment from B
        sigC = tools.decrypt_adapter(Dave['inbound_txn']['adapter_witness'], Dave['scalar'])
        Dave['inbound_txn']['witness'] = parsing.compile_script(f'push x{sigC.hex()}')
        assert functions.run_auth_scripts(
            [Dave['inbound_txn']['witness'], Dave['inbound_txn']['locking_script']],
            Dave['inbound_txn']['sigfields']
        )

        # release previous hop; done by correspondent C to get payment from B
        r = tools.release_left_amhl_lock(
            Carla['outbound_txn']['adapter_witness'], sigC, Carla['scalar']
        )
        sigB = tools.decrypt_adapter(Carla['inbound_txn']['adapter_witness'], r)
        Carla['inbound_txn']['witness'] = parsing.compile_script(f'push x{sigB.hex()}')
        assert functions.run_auth_scripts(
            [Carla['inbound_txn']['witness'], Carla['inbound_txn']['locking_script']],
            Carla['inbound_txn']['sigfields']
        )

        # release previous hop again; done by correspondent B to get payment from A
        r = tools.release_left_amhl_lock(
            Bob['outbound_txn']['adapter_witness'], sigB, Bob['scalar']
        )
        sigA = tools.decrypt_adapter(Bob['inbound_txn']['adapter_witness'], r)
        Bob['inbound_txn']['witness'] = parsing.compile_script(f'push x{sigA.hex()}')
        assert functions.run_auth_scripts(
            [Bob['inbound_txn']['witness'], Bob['inbound_txn']['locking_script']],
            Bob['inbound_txn']['sigfields']
        )

    def test_setup_amhl_adapter_ptlcs(self):
        pubkeys = [
            bytes(self.pubkeyA),
            bytes(self.pubkeyB),
            bytes(self.pubkeyC),
        ]
        prvkeys = [
            bytes(self.prvkeyA),
            bytes(self.prvkeyB),
            bytes(self.prvkeyC),
        ]
        refund_pubkeys = {
            pk: pk for pk in pubkeys
        }
        amhl = tools.setup_amhl(b'123', pubkeys, refund_pubkeys=refund_pubkeys, timeout=10)
        assert type(amhl) is dict
        for pk in pubkeys:
            assert pk in amhl
        assert 'key' in amhl
        sigfields = [
            {'sigfield1': b'pay Bob 1.2'},
            {'sigfield1': b'pay Carla 1.1'},
            {'sigfield1': b'pay Dave 1.0'},
        ]
        refund_sigfields = [
            {'sigfield1': b'Alice takes back her 1.2 after timeout'},
            {'sigfield1': b'Bob takes back his 1.1 after timeout'},
            {'sigfield1': b'Carla takes back her 1.0 after timeout'},
        ]

        adapter_witnesses = [
            tools.make_adapter_witness(prvkeys[i], amhl[pubkeys[i]][2], sigfields[i])
            for i in range(len(prvkeys))
        ]

        # validate adapter witnesses
        for i in range(len(adapter_witnesses)):
            assert functions.run_auth_scripts(
                [adapter_witnesses[i].bytes, amhl[pubkeys[i]][0].bytes],
                sigfields[i]
            )

        Alice = {
            'outbound_txn': {
                'sigfields': sigfields[0],
                'adapter_lock': amhl[pubkeys[0]][0],
                'adapter_witness': adapter_witnesses[0].bytes,
                'locking_script': amhl[pubkeys[0]][1].bytes,
            },
            'prvkey': prvkeys[0],
            'pubkey': pubkeys[0],
            'tweak_point': amhl[pubkeys[0]][2],
            'scalar': amhl[pubkeys[0]][3],
        }

        Bob = {
            'outbound_txn': {
                'sigfields': sigfields[1],
                'adapter_lock': amhl[pubkeys[1]][0],
                'adapter_witness': adapter_witnesses[1].bytes,
                'locking_script': amhl[pubkeys[1]][1].bytes,
            },
            'prvkey': prvkeys[1],
            'pubkey': pubkeys[1],
            'inbound_txn': Alice['outbound_txn'],
            'tweak_point': amhl[pubkeys[1]][2],
            'scalar': amhl[pubkeys[1]][3],
        }

        Carla = {
            'outbound_txn': {
                'sigfields': sigfields[2],
                'adapter_lock': amhl[pubkeys[2]][0],
                'adapter_witness': adapter_witnesses[2].bytes,
                'locking_script': amhl[pubkeys[2]][1].bytes,
            },
            'prvkey': prvkeys[2],
            'pubkey': pubkeys[2],
            'inbound_txn': Bob['outbound_txn'],
            'tweak_point': amhl[pubkeys[2]][2],
            'scalar': amhl[pubkeys[2]][3],
        }

        Dave = {
            'inbound_txn': Carla['outbound_txn'],
            'scalar': amhl['key'],
        }

        # unlock from right to left; decrypt last hop first
        # after a payment route has been set up, the payer sends the scalar to
        # the final recipient to begin the process; the decrypted signature is
        # sent back to the previous hop correspondent C to clear, thus hop C
        # will be able to unlock the payment from B
        sigC = tools.decrypt_adapter(Dave['inbound_txn']['adapter_witness'], Dave['scalar'])
        Dave['inbound_txn']['witness'] = parsing.compile_script(f'push x{sigC.hex()} true')
        assert functions.run_auth_scripts(
            [Dave['inbound_txn']['witness'], Dave['inbound_txn']['locking_script']],
            Dave['inbound_txn']['sigfields']
        )

        # release previous hop; done by correspondent C to get payment from B
        r = tools.release_left_amhl_lock(
            Carla['outbound_txn']['adapter_witness'], sigC, Carla['scalar']
        )
        sigB = tools.decrypt_adapter(Carla['inbound_txn']['adapter_witness'], r)
        Carla['inbound_txn']['witness'] = parsing.compile_script(f'push x{sigB.hex()} true')
        assert functions.run_auth_scripts(
            [Carla['inbound_txn']['witness'], Carla['inbound_txn']['locking_script']],
            Carla['inbound_txn']['sigfields']
        )

        # release previous hop again; done by correspondent B to get payment from A
        r = tools.release_left_amhl_lock(
            Bob['outbound_txn']['adapter_witness'], sigB, Bob['scalar']
        )
        sigA = tools.decrypt_adapter(Bob['inbound_txn']['adapter_witness'], r)
        Bob['inbound_txn']['witness'] = parsing.compile_script(f'push x{sigA.hex()} true')
        assert functions.run_auth_scripts(
            [Bob['inbound_txn']['witness'], Bob['inbound_txn']['locking_script']],
            Bob['inbound_txn']['sigfields']
        )

        # go into the future to prove a refund txn works
        refund_witness = tools.make_ptlc_refund_witness(
            Alice['prvkey'], refund_sigfields[0]
        )
        assert functions.run_auth_scripts(
            [refund_witness.bytes, Alice['outbound_txn']['locking_script']],
            {**refund_sigfields[0], 'timestamp': int(time())+11}
        )


if __name__ == '__main__':
    unittest.main()
