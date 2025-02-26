from context import classes, errors, functions, parsing, tools
from queue import LifoQueue

# with open('tests/vectors/temp.src', 'r') as f:
    # data = f.read()

# data = """push s'abc123EFG'"""

# compiled = parsing.compile_script(data)
# print(' '.join([compiled[i:i+1].hex() for i in range(len(compiled))]))

# tape, queue, cache = functions.run_script(compiled)
# print(tape)
# print(queue.queue)
# print(cache)

tools.repl()