from __future__ import annotations
from context import functions, parsing, classes, tools
from hashlib import sha256
from nacl.signing import SigningKey
import unittest




def hash_sigfields(tape: classes.Tape, stack: classes.Stack, cache: dict) -> None:
    """When called for the first time, backup the original sigfields to
        a new cache location, then transform the sigfields not excluded.
        When called subsequently, replace the sigfields with the backup
        values, then transform the sigfields not excluded.
    """
    sig_flags = cache.get(b'sigext', [b'\x00'])[0]
    sig_flags = int.from_bytes(sig_flags, 'big')
    sig_flag1 = sig_flags & 0b00000001
    sig_flag2 = sig_flags & 0b00000010
    sig_flag3 = sig_flags & 0b00000100
    sig_flag4 = sig_flags & 0b00001000
    sig_flag5 = sig_flags & 0b00010000
    sig_flag6 = sig_flags & 0b00100000
    sig_flag7 = sig_flags & 0b01000000
    sig_flag8 = sig_flags & 0b10000000
    sig_flags = {
        1: sig_flag1,
        2: sig_flag2,
        3: sig_flag3,
        4: sig_flag4,
        5: sig_flag5,
        6: sig_flag6,
        7: sig_flag7,
        8: sig_flag8,
    }

    # backup sigfields on first call
    if 'sigfield_backup' not in cache:
        cache['sigfield_backup'] = {
            1: cache['sigfield1'],
            2: cache['sigfield2'],
            3: cache['sigfield3'],
            4: cache['sigfield4'],
            5: cache['sigfield5'],
            6: cache['sigfield6'],
            7: cache['sigfield7'],
            8: cache['sigfield8'],
        }

    # restore backed-up sigfields
    cache['sigfield1'] = cache['sigfield_backup'][1]
    cache['sigfield2'] = cache['sigfield_backup'][2]
    cache['sigfield3'] = cache['sigfield_backup'][3]
    cache['sigfield4'] = cache['sigfield_backup'][4]
    cache['sigfield5'] = cache['sigfield_backup'][5]
    cache['sigfield6'] = cache['sigfield_backup'][6]
    cache['sigfield7'] = cache['sigfield_backup'][7]
    cache['sigfield8'] = cache['sigfield_backup'][8]

    # transform fields indicated
    for n, flag in sig_flags.items():
        if flag:
            cache[f'sigfield{n}'] = sha256(cache[f'sigfield{n}']).digest()


class TestPlugins(unittest.TestCase):
    original_plugins: dict

    def setUp(self) -> None:
        self.original_plugins = { **functions._plugins }
        functions._plugins['test'] = []
        for k, v in self.original_plugins.items():
            self.original_plugins[k] = [*v]
        return super().setUp()

    def tearDown(self) -> None:
        functions._plugins = { **self.original_plugins }
        for k, v in functions._plugins.items():
            functions._plugins[k] = [*v]
        return super().tearDown()

    def test_add_plugin(self):
        len1 = len(functions._plugins['test'])
        functions.add_plugin('test', hash_sigfields)
        len2 = len(functions._plugins['test'])
        assert len2 == len1 + 1

    def test_remove_plugin(self):
        functions.add_plugin('test', hash_sigfields)
        len1 = len(functions._plugins['test'])
        functions.remove_plugin('test', hash_sigfields)
        len2 = len(functions._plugins['test'])
        assert len2 == len1 - 1

    def test_run_plugins(self):
        hashcheck = lambda tape, stack, cache: cache.update({'foo': 'bar'})
        functions.add_plugin('test', hashcheck)
        cache = {}
        assert 'foo' not in cache
        functions.run_plugins(
            'test',
            classes.Tape(b'', plugins=functions._plugins),
            classes.Stack(),
            cache
        )
        assert cache.get('foo', None) == 'bar', cache


class TestSigExt(unittest.TestCase):
    '''Example implementation of a signature extension plugin utilizing
        the b'sigext' cache location.
    '''
    prvkeyA: bytes
    prvkeyB: bytes
    pubkeyA: bytes
    pubkeyB: bytes

    def setUp(self) -> None:
        self.prvkeyA = b'yellow submarine is extra yellow'
        self.pubkeyA = bytes(SigningKey(self.prvkeyA).verify_key)
        self.prvkeyB = b'submarine such yellow extra very'
        self.pubkeyB = bytes(SigningKey(self.prvkeyB).verify_key)
        return super().setUp()

    def tearDown(self) -> None:
        functions._plugins['signature_extensions'] = []
        return super().tearDown()

    def test_add_and_remove_functions_work(self) -> None:
        assert len(functions._plugins['signature_extensions']) == 0
        functions.add_signature_extension(hash_sigfields)
        assert len(functions._plugins['signature_extensions']) == 1
        functions.remove_signature_extension(hash_sigfields)
        assert len(functions._plugins['signature_extensions']) == 0
        functions.add_signature_extension(hash_sigfields)
        assert len(functions._plugins['signature_extensions']) == 1
        functions.reset_signature_extensions()
        assert len(functions._plugins['signature_extensions']) == 0

    def test_sig_ext_e2e(self) -> None:
        sigfields = {
            'sigfield1': b'message part 1',
            'sigfield2': b'message part 2',
            'sigfield3': b'message part 3',
            'sigfield4': b'message part 4',
            'sigfield5': b'message part 5',
            'sigfield6': b'message part 6',
            'sigfield7': b'message part 7',
            'sigfield8': b'message part 8',
        }

        # locks
        siglock1 = tools.make_single_sig_lock(self.pubkeyA)
        siglock2 = tools.Script.from_src(f'@= sigext [ x02 ] {siglock1.src}')
        multilock1 = tools.make_multisig_lock([self.pubkeyA, self.pubkeyB], 2)
        multilock2 = tools.Script.from_src(f'@= sigext [ x02 ] {multilock1.src}')

        # witnesses
        sigwit1 = tools.make_single_sig_witness(self.prvkeyA, sigfields)
        functions.add_signature_extension(hash_sigfields)
        _, stack, _ = functions.run_script(
            parsing.compile_script(f'@= sigext [ x02 ] push x{self.prvkeyA.hex()} sign x00'),
            {**sigfields}
        )
        sig: bytes = stack.get()
        sigwit2 = tools.Script.from_src(f'push x{sig.hex()}')

        functions.reset_signature_extensions()
        _, stack, _ = functions.run_script(
            parsing.compile_script(f'msg x00 push x{self.prvkeyB.hex()} sign_stack'),
            {**sigfields}
        )
        sig = stack.get()
        multiwit1 = tools.Script.from_src(f'{sigwit1.src} push x{sig.hex()}')

        functions.add_signature_extension(hash_sigfields)
        _, stack, _ = functions.run_script(
            parsing.compile_script(f'@= sigext [ x02 ] push x{self.prvkeyB.hex()} sign x00'),
            {**sigfields}
        )
        sig = stack.get()
        multiwit2 = tools.Script.from_src(f'{sigwit2.src} push x{sig.hex()}')

        # auth tests using the VM-wide plugin management functions
        functions.reset_signature_extensions()
        assert functions.run_auth_script(sigwit1 + siglock1, sigfields)
        assert not functions.run_auth_script(sigwit2 + siglock2, sigfields)
        assert functions.run_auth_script(multiwit1 + multilock1, sigfields)
        assert not functions.run_auth_script(multiwit2 + multilock2, sigfields)

        functions.add_signature_extension(hash_sigfields)
        assert functions.run_auth_script(sigwit1 + siglock1, sigfields)
        assert functions.run_auth_script(sigwit2 + siglock2, sigfields)
        assert functions.run_auth_script(multiwit1 + multilock1, sigfields)
        assert functions.run_auth_script(multiwit2 + multilock2, sigfields)

        # auth tests using plugin injection
        functions.reset_signature_extensions()
        assert functions.run_auth_script(sigwit1 + siglock1, sigfields)
        assert not functions.run_auth_script(sigwit2 + siglock2, sigfields)
        assert functions.run_auth_script(multiwit1 + multilock1, sigfields)
        assert not functions.run_auth_script(multiwit2 + multilock2, sigfields)

        plugins = {'signature_extensions': [hash_sigfields]}
        assert functions.run_auth_script(sigwit1 + siglock1, sigfields, plugins=plugins)
        assert functions.run_auth_script(sigwit2 + siglock2, sigfields, plugins=plugins)
        assert functions.run_auth_script(multiwit1 + multilock1, sigfields, plugins=plugins)
        assert functions.run_auth_script(multiwit2 + multilock2, sigfields, plugins=plugins)


class TestCTExt(unittest.TestCase):
    '''Example implementation of a check_template extension plugin.'''
    def tearDown(self) -> None:
        functions._plugins['check_template'] = []
        return super().tearDown()

    def test_check_template_ext_e2e(self):
        ishelloworld = lambda tape, stack, cache: [stack.get(), stack.get()][1] == b'hello world'
        script = tools.Script.from_src('push x0102 check_template x01')
        functions.add_plugin('check_template', ishelloworld)
        assert functions.run_auth_script(script,{ 'sigfield1': b'hello world' })
        assert not functions.run_auth_script(script,{ 'sigfield1': b'hello world1' })


if __name__ == '__main__':
    unittest.main()
