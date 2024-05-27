from context import classes, errors, functions, interfaces, tools
from secrets import token_bytes
import nacl.bindings
import unittest


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
