## 0.4.0 (next)

- Changed `OP_CHECK_TRANSFER` to pull the `count` parameter from the queue.
- Added `OP_LESS` (alias `LESS`): pulls value1 then value2 from the queue and
puts `value1<value2` onto the queue.
- Added `OP_LESS_OR_EQUAL` (aliases `LESS_OR_EQUAL`, `OP_LEQ`, and `LEQ`): pulls
value1 then value 2 from the queue and puts `value1<=value2` onto the queue.
- Added `OP_GET_VALUE s"key"` (aliases `GET_VALUE`, `OP_VAL`, and `VAL`): puts
the read-only cache values at the string key onto the queue.
- Added example txn protocol using a sequence number (held in a sigfield) and
sequence number constraint. Included an e2e test implementing eltoo protocol.

## 0.3.1

- Expanded the variable syntax to include directly pulling items from the queue.

## 0.3.0

- Added a macro and variable system to the compiler.

## 0.2.8

- Added OP code aliases.
- Improved compiler and fixed some edge cases.
  - Extended comment support to within control flow blocks.
  - Fixed string value parsing.
  - Refactored compiler logic.

## 0.2.7

- Improved compiler error reporting.

## 0.2.6

- Improved `OP_EVAL` and other subtape execution OPs.
- Bug fixes.

## 0.2.5

- Bug fixes.

## 0.2.4

- Compiler improvement: handle `OP_TRY_EXCEPT` within `OP_IF` and `OP_IF_ELSE`.

## 0.2.3

- Bug fixes.

## 0.2.0

- Replaced `NOP61` with `OP_TRY_EXCEPT`. Constitutes a hard fork, but nobody is
using this yet, so no harm done.
- Reduced maximum subtape size from 16MB to 64KB, saving a byte in encoded size
arguments for `OP_IF`, `OP_IF_ELSE`, `OP_DEF`, and `OP_TRY_EXCEPT`.
