from .errors import tert, vert
from .parsing import compile_script
from hashlib import sha256
from .functions import (
    opcodes_inverse,
    nopcodes_inverse,
    run_script,
    run_tape,
    run_auth_script,
    add_opcode
)


def _combine_two(branch_a: str, branch_b: str) -> list[str]:
    """Takes two script branches, hashes them, and returns a root script
        using OP_MERKLEVAL and two unlocking scripts that execute the
        supplied branches after the locking script executes.
    """
    compiled_a = compile_script(branch_a)
    compiled_b = compile_script(branch_b)
    hash_a = sha256(compiled_a).digest()
    hash_b = sha256(compiled_b).digest()
    root = sha256(hash_a + hash_b).digest()

    root_script = f'OP_MERKLEVAL x{root.hex()}\n'
    script_a = f'OP_PUSH x{hash_b.hex()}\nOP_PUSH x{compiled_a.hex()}\nOP_TRUE\n'
    script_b = f'OP_PUSH x{hash_a.hex()}\nOP_PUSH x{compiled_b.hex()}\nOP_FALSE\n'

    return [root_script, script_a, script_b]

def _format_scripts(levels: list) -> tuple[str, list[str]]:
    """Turns a list of script levels into a top-level locking script and
        the unlocking scripts for each branch.
    """
    locking_script = levels[0][0]
    branches = [levels[0][1]]
    partial = levels[0][2]

    for i in range(1, len(levels)):
        branches.append(levels[i][1] + partial)
        partial = levels[i][2] + partial

    branches.append(partial)

    return (locking_script, branches)

def create_merklized_script(branches: list[str], levels: list = None) -> tuple[str, list[str]]:
    """Produces a Merklized, branching script structure with a branch on
        the left at every level. Returns a tuple of root script and list
        of branch execution scripts.
    """
    tert(type(branches) in (list, tuple), 'branches must be list or tuple or str')
    for branch in branches:
        tert(type(branch) is str, 'branches must be list or tuple or str')
        vert(len(branch) > 0, 'branches must not be empty')
    vert(len(branches) >= 1, 'must be at least 1 branch')

    if len(branches) == 1:
        branches.append('OP_FALSE') # filler branch
    levels = [] if not levels else levels

    # combine final 2 branches
    scripts = _combine_two(branches[-2], branches[-1])
    levels.append(scripts)
    remaining_branches = [*branches[:-2], scripts[0]]

    if len(remaining_branches) == 1:
        levels.reverse()
        return _format_scripts(levels)

    return create_merklized_script(remaining_branches, levels)

def _format_docstring(docstring: str) -> str:
    """Takes a docstring, tokenizes it, and returns a str formatted to
        72 chars or fewer per line without splitting tokens.
    """
    def make_line(tokens: list[str]) -> tuple[str, list[str]]:
        line = ''
        while len(tokens) and len(line) + len(tokens[0]) <= 72:
            line += tokens[0] + ' '
            tokens = tokens[1:]
        return (line[:-1], tokens)

    tokens = docstring.split()
    lines = []

    while len(tokens):
        line, tokens = make_line(tokens)
        lines.append(line)

    return '\n'.join(lines)

def generate_docs() -> list[str]:
    data = {}

    for opname in opcodes_inverse:
        number = opcodes_inverse[opname][0]
        doc = opcodes_inverse[opname][1].__doc__
        data[number] = (opname, doc)

    for nopname in nopcodes_inverse:
        number = nopcodes_inverse[nopname][0]
        doc = nopcodes_inverse[nopname][1].__doc__
        data[number] = (nopname, doc)

    paragraphs = ['# OPs\n']

    for number in data:
        line = f'\n## {data[number][0]} - {number} - x{number.to_bytes(1).hex().upper()}\n\n'
        docstring = _format_docstring(data[number][1])
        paragraphs.append(line + docstring + '\n')

    paragraphs.append('\n\n# Other functions')
    docstring = _format_docstring(run_script.__doc__)
    paragraphs.append('\n\n## run_script\n\n' + docstring)
    docstring = _format_docstring(run_tape.__doc__)
    paragraphs.append('\n\n## run_tape\n\n' + docstring)
    docstring = _format_docstring(run_auth_script.__doc__)
    paragraphs.append('\n\n## run_auth_script\n\n' + docstring)
    docstring = _format_docstring(add_opcode.__doc__)
    paragraphs.append('\n\n## add_opcode\n\n' + docstring)

    return paragraphs
