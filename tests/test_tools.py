from context import functions
from context import parsing
from context import tools
import unittest


class TestTools(unittest.TestCase):
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
        assert int.from_bytes(queue.get(False)) == 123
        assert queue.empty()

    def test_create_merklized_script_2_branches_e2e(self):
        result = tools.create_merklized_script(['OP_PUSH d123', 'OP_PUSH x0123'])
        locking_script = parsing.compile_script(result[0])
        unlocking_scripts = [parsing.compile_script(s) for s in result[1]]
        assert len(unlocking_scripts) == 2

        tape, queue, cache = functions.run_script(unlocking_scripts[0] + locking_script)
        assert tape.has_terminated()
        assert not queue.empty()
        assert int.from_bytes(queue.get(False)) == 123
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
        assert int.from_bytes(queue.get(False)) == 123
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
            assert int.from_bytes(queue.get(False)) == i
            assert queue.empty()


if __name__ == '__main__':
    unittest.main()
