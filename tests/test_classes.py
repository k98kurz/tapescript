from context import classes, errors, interfaces
import unittest


class TestTape(unittest.TestCase):
    def test_Tape_implements_TapeProtocol(self):
        assert isinstance(classes.Tape, interfaces.TapeProtocol)

    def test_Tape_initializes_without_error(self):
        assert hasattr(classes, 'Tape')
        assert type(classes.Tape) is type
        tape = classes.Tape(b'some data')
        assert type(tape) is classes.Tape

    def test_Tape_read_returns_bytes(self):
        tape = classes.Tape(b'some data')
        read = tape.read(4)
        assert type(read) is bytes
        assert read == b'some'

    def test_Tape_raises_error_if_remaining_tape_too_short(self):
        tape = classes.Tape(b'some data')

        with self.assertRaises(errors.ScriptExecutionError) as e:
            tape.read(20)

        assert tape.read(9) == b'some data'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            tape.read(1)

    def test_Tape_has_terminated_returns_correct_bool(self):
        tape = classes.Tape(b'some data')
        assert type(tape.has_terminated()) is bool
        assert tape.has_terminated() is False

        tape.read(9)
        assert type(tape.has_terminated()) is bool
        assert tape.has_terminated() is True

    def test_Tape_instance_has_dict_flags_property(self):
        tape = classes.Tape(b'some data')
        assert hasattr(tape, 'flags')
        assert isinstance(tape.flags, dict)

    def test_Tape_instance_has_dict_definitions_property(self):
        tape = classes.Tape(b'some data')
        assert hasattr(tape, 'definitions')
        assert isinstance(tape.definitions, dict)

    def test_Tape_instance_has_int_pointer_property(self):
        tape = classes.Tape(b'some data')
        assert hasattr(tape, 'pointer')
        assert isinstance(tape.pointer, int)

    def test_Tape_instance_has_dict_contracts_property(self):
        tape = classes.Tape(b'some data')
        assert hasattr(tape, 'contracts')
        assert isinstance(tape.contracts, dict)


if __name__ == '__main__':
    unittest.main()
