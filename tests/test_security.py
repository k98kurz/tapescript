from context import classes, errors, functions, tools
import nacl.bindings
import unittest

try:
    from secrets import token_bytes
except ImportError:
    from os import urandom
    def token_bytes(count: int) -> bytes:
        return urandom(count)


class TestSecurityAssumptions(unittest.TestCase):
    tape: classes.Tape
    stack: classes.Stack
    cache: dict
    original_opcodes: dict
    original_nopcodes: dict
    original_opcodes_inverse: dict
    original_nopcodes_inverse: dict
    original_contract_interfaces: dict

    def setUp(self) -> None:
        self.tape = classes.Tape(b'')
        self.stack = classes.Stack()
        self.cache = {}
        self.original_opcodes = {**functions.opcodes}
        self.original_opcodes_inverse = {**functions.opcodes_inverse}
        self.original_nopcodes = {**functions.nopcodes}
        self.original_nopcodes_inverse = {**functions.nopcodes_inverse}
        self.original_contract_interfaces = {**functions._contract_interfaces}
        return super().setUp()

    def tearDown(self) -> None:
        functions.opcodes = self.original_opcodes
        functions.opcodes_inverse = self.original_opcodes_inverse
        functions.nopcodes = self.original_nopcodes
        functions.nopcodes_inverse = self.original_nopcodes_inverse
        functions._contracts = {}
        functions._contract_interfaces = self.original_contract_interfaces

    # cryptographic proofs
    def test_ed25519_maths_meet_homomorphic_one_way_condition(self):
        """Test if Ed25519 meets the homomorphic one way condition."""
        x1 = functions.clamp_scalar(token_bytes(32))
        x2 = functions.clamp_scalar(token_bytes(32))
        y1 = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(x1) # G^x1
        y2 = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(x2) # G^x2

        # test
        y3_1 = nacl.bindings.crypto_core_ed25519_add(y1, y2) # G^x1 * G^x2
        x3 = nacl.bindings.crypto_core_ed25519_scalar_add(x1, x2) # x1 + x2
        y3_2 = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(x3) # G^(x1+x2)
        assert y3_1 == y3_2 # G^x1 * G^x2 = G^(x1+x2) where * denotes group operator

    def test_taproot_not_vulnerable_to_ed25519_point_subtraction(self):
        seed = token_bytes(32)
        prvkey = functions.derive_key_from_seed(seed)
        pubkey = functions.derive_point_from_scalar(prvkey)
        intended_script = tools.make_single_sig_lock(pubkey)
        taproot_lock = tools.make_taproot_lock(pubkey, intended_script)
        sigfields = {'sigfield1': b'hello world'}
        taproot_unlock_keyspend = tools.make_taproot_witness_keyspend(seed, sigfields, intended_script)
        taproot_unlock_scriptspend = tools.make_single_sig_witness(seed, sigfields) + \
            tools.make_taproot_witness_scriptspend(pubkey, intended_script)

        # prove normal functioning
        assert functions.run_auth_script(taproot_unlock_keyspend + taproot_lock, sigfields)
        assert functions.run_auth_script(taproot_unlock_scriptspend + taproot_lock, sigfields)

        # derive point from malicious script
        malicious_script = tools.Script.from_src('true')
        root = taproot_lock.bytes[-32:]
        script_scalar = functions.clamp_scalar(malicious_script.commitment())
        script_point = functions.derive_point_from_scalar(script_scalar)

        # subtract point
        script_point_inverse = nacl.bindings.crypto_core_ed25519_sub(root, script_point)
        malicious_unlock = tools.make_taproot_witness_scriptspend(script_point_inverse, malicious_script)
        assert not functions.run_auth_script(malicious_unlock + taproot_lock)

    # problem cases to avoid
    def test_prove_all_mirror_trees_validate_each_other(self):
        tree = tools.ScriptNode(
            tools.ScriptNode(
                tools.ScriptLeaf.from_src('push s"hello world"'),
                tools.ScriptLeaf.from_src('true'),
            ),
            tools.ScriptNode(
                tools.ScriptLeaf.from_src('push s"hello world"'),
                tools.ScriptLeaf.from_src('true'),
            )
        )
        lock = tree.locking_script()

        # prove that a different symmetrical tree will validate for the same root
        tree2 = tools.ScriptNode(
            tools.ScriptLeaf.from_src('push s"I hacked it" pop0 true'),
            tools.ScriptLeaf.from_src('push s"I hacked it" pop0 true'),
        )
        unlock = tree2.right.unlocking_script()
        assert functions.run_auth_script(unlock.bytes + lock.bytes)

        # prove that an asymmetrical tree will not validate for the same root
        tree3 = tools.ScriptNode(
            tools.ScriptLeaf.from_src('push s"some script" pop0 true'),
            tools.ScriptLeaf.from_src('push s"different innit" pop0 true'),
        )
        unlock = tree3.right.unlocking_script()
        assert not functions.run_auth_script(unlock.bytes + lock.bytes)

        # prove that any arbitrary symmetrical tree will validate for the same root
        for i in range(100):
            t = token_bytes(i+1)
            tree2 = tools.ScriptNode(
                tools.ScriptLeaf.from_src(f'push x{t.hex()} pop0 true'),
                tools.ScriptLeaf.from_src(f'push x{t.hex()} pop0 true'),
            )
            unlock = tree2.right.unlocking_script()
            assert functions.run_auth_script(unlock.bytes + lock.bytes)

    # patched DoS attack vectors
    def test_memory_exhaustion_DoS_attacks_result_in_ScriptExecutionError(self):
        script1 = tools.Script.from_bytes(b''.join([b'\x01' for _ in range(1025)]))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.run_script(script1)
        assert 'full Stack' in str(e.exception)

        script2 = tools.Script.from_src('true loop { dup concat }')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.run_script(script2)
        assert 'item size too large' in str(e.exception)

    def test_OP_LOOP_and_recursive_OP_CALL_raises_callstack_limit_error(self):
        script = tools.Script.from_src('def 0 { loop { call d0 } } true call d0')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.run_script(script)
        assert 'limit exceeded' in str(e.exception)

    def test_infinite_recursion_results_in_callstack_limit_exceeded_error(self):
        script1 = tools.Script.from_src('def 0 { call d0 } call d0')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.run_script(script1)
        assert 'limit exceeded' in str(e.exception)

        script1 = tools.Script.from_src('true loop { }')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.run_script(script1)
        assert 'limit exceeded' in str(e.exception), e.exception

    def test_CPU_exhaustion_attack(self):
        script = tools.Script.from_src(
            """
            def 0 {
                push d1
                add_ints d2
                if ( dup push d120 equal ) {
                    pop0
                    return
                }
                call d0
            }
            true
            loop {
                push d1
                call d0
            }
        """)
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.run_script(script)
        assert "limit exceeded" in str(e.exception)


if __name__ == '__main__':
    unittest.main()
