# Tapescript

Simple script system loosely inspired by Bitcoin script but also hopefully more
useful for other applications. The idea is to programmatically ensure access
controls in a distributed system.

## Status

- [x] OPs
- [x] Interpreter functions and classes
- [x] Byte-code compiler
- [ ] Decompiler
- [x] Unit tests
- [ ] E2e tests
- [ ] Taproot test vector
- [ ] Decent docs
- [ ] Package published

## Usage

### Installation

```bash
pip install tapescript
```

### Write, compile, decompile

@todo

### Run a script

@todo

### Signature checking

Notes for the `OP_CHECK_SIG` and `OP_CHECK_SIG_VERIFY` functions:

1. The body of the message to be used in checking the signature is comprised of
the `sigfield[1-8]` cache items.
2. Each signature can have an additional (33rd) byte attached which encodes up
to 8 bit flags. Each bit flag encoded will exclude the associated `sigfield{n}`
cache item from the message body during signature checks.
3. These function calls take a 1 byte param from the tap that encodes the
allowable flags. If a signature is passed to a signature checker that uses a
disallowed sigflag, a `ScriptExecutionError` will be raised.

### Timestamp and epoch checking

@todo ensure implementation semantics are correct, then write some documentation
explaining it

### Testing

First, clone the repo, set up the virtualenv, and install requirements.

```bash
git clone ...
python -m venv venv/
source venv/bin/activate
pip install -r requirements.txt
```

For windows, replace `source venv/bin/activate` with `source venv/Scripts/activate`.

Then run the test suite with the following:

```bash
python test/test_classes.py
```

## ISC License

Copyleft (c) 2023 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

Exceptions: this permission is not granted to Alphabet/Google, Amazon,
Apple, Microsoft, Netflix, Meta/Facebook, Twitter, or Disney; nor is
permission granted to any company that contracts to supply weapons or
logistics to any national military; nor is permission granted to any
national government or governmental agency; nor is permission granted to
any employees, associates, or affiliates of these designated entities.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
