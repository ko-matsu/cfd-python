from unittest import TestCase
from tests.util import load_test_list, load_json_file, get_json_file,\
    assert_equal, assert_match, assert_error
from cfd.util import CfdError
from cfd.hdwallet import HDWallet
import unicodedata


def test_mnemonic_word_list_func(obj, name, case, req, exp, error):
    try:
        if name == 'GetMnemonicWordList':
            resp = HDWallet.get_mnemonic_word_list(req['language'])
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        exp_data = get_json_file(exp['file'])
        assert_match(obj, name, case, exp_data, resp, 'wordlist')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def test_convert_mnemonic_func(obj, name, case, req, exp, error):
    try:
        if 'file' in exp:
            test_data_list = obj.mnemonic_test_data[exp['language']]
            results = []
            for test_data in test_data_list:
                if name == 'GetEntropyFromMnemonic':
                    resp = HDWallet.get_entropy(
                        test_data['mnemonic'], req['language'])
                    results.append(resp)
                elif name == 'GetMnemonicFromEntropy':
                    resp = HDWallet.get_mnemonic(
                        test_data['entropy'], req['language'])
                    results.append(resp)
                elif name == 'GetMnemonicToSeed':
                    resp = HDWallet.from_mnemonic(
                        test_data['mnemonic'], req['language'],
                        test_data['passphrase'])
                    results.append(resp.seed)
                elif name == 'GetExtPrivkeyFromSeed':
                    resp = HDWallet.from_seed(test_data['seed'])
                    results.append(resp.ext_privkey)
                else:
                    raise Exception('unknown name: ' + name)

            for index, test_data in enumerate(test_data_list):
                if name == 'GetEntropyFromMnemonic':
                    assert_match(obj, name, case, test_data['entropy'],
                                 results[index], index)
                elif name == 'GetMnemonicFromEntropy':
                    _mnemonic = ' '.join(test_data['mnemonic'])
                    _mnemonic = unicodedata.normalize('NFD', _mnemonic)
                    assert_match(obj, name, case, _mnemonic,
                                 results[index], index)
                elif name == 'GetMnemonicToSeed':
                    assert_match(obj, name, case, test_data['seed'],
                                 results[index], index)
                elif name == 'GetExtPrivkeyFromSeed':
                    assert_match(obj, name, case, test_data['xpriv'],
                                 results[index], index)

        else:
            raise Exception('unsupported route: ' + name)
        assert_error(obj, name, case, error)

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestHDWallet(TestCase):
    def setUp(self):
        self.test_list = load_json_file('hdwallet_test.json')
        self.mnemonic_test_data = get_json_file('bip39/test_vector.json')

    def test_get_mnemonic_word_list(self):
        test_name = 'GetMnemonicWordList'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_mnemonic_word_list_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])

    def test_get_entropy_from_mnemonic(self):
        test_name = 'GetEntropyFromMnemonic'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_convert_mnemonic_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])

    def test_get_mnemonic_from_entropy(self):
        test_name = 'GetMnemonicFromEntropy'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_convert_mnemonic_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])

    def test_mnemonic_to_seed(self):
        test_name = 'GetMnemonicToSeed'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_convert_mnemonic_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])

    def test_extkey_from_seed(self):
        test_name = 'GetExtPrivkeyFromSeed'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_convert_mnemonic_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])
