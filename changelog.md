## 0.2.0

- Replaced `NOP61` with `OP_TRY_EXCEPT`. Constitutes a hard fork, but nobody is
using this yet, so no harm done.
- Reduced maximum subtape size from 16MB to 64KB, saving a byte in encoded size
arguments for `OP_IF`, `OP_IF_ELSE`, `OP_DEF`, and `OP_TRY_EXCEPT`.
