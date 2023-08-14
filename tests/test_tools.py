from context import classes
from context import errors
from context import functions
from context import parsing
from context import tools
from queue import LifoQueue
import unittest


class TestTools(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
