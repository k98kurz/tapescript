# Notes

## Flags

The virtual machine includes a flag system for configuring some ops. The
following flags are standard:

- ts_threshold: int amount of slack allowable in timestamp comparisons (default 60)
- epoch_threshold: int amount of slack allowable in epoch comparisons (default 60)
- 0: when True (default True), `OP_INVOKE` sets cache key b'IR' to return value
- 1: when True (default True), relevant ops set cache key b'x' (private key)
- 2: when True (default True), relevant ops set cache key b'X' (public key)
- 3: when True (default True), relevant ops set cache key b'r' (nonce scalar)
- 4: when True (default True), relevant ops set cache key b'R' (nonce point)
- 5: when True (default True), relevant ops set cache key b't' (tweak scalar)
- 6: when True (default True), relevant ops set cache key b'T' (tweak point)
- 7: when True (default True), relevant ops set cache key b'RT' (nonce point * tweak point)
- 8: when True (default True), relevant ops set cache key b'sa' (signature adapter)
- 9: when True (default True), relevant ops set cache key b's' (signature)

These values can be changed by updating the `functions.flags` dict. Additional
flags can be defined with similar syntax.

```python
functions.flags['ts_threshold'] = 120
functions.flags[69] = 420
```

Integer flags 0-255 can be set or unset by `OP_SET_FLAG` and `OP_UNSET_FLAG`.
Flag keys must have type int or str, and flag values must have type int or bool.

The script running functions, `run_tape`, `run_script`, and `run_auth_script`
set all flags with keys contained in `functions.flags_to_set` before running the
script; other flags must be enabled with `OP_SET_FLAG`.

At this time, the CLI does not support setting custom flags.
