from .classes import Tape
from .errors import ScriptExecutionError
from .functions import (
    run_script,
    run_tape,
    run_auth_script,
    add_opcode
)
from .parsing import (
    compile_script,
    decompile_script,
    add_opcode_parsing_handlers
)