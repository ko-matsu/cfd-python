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
                    results.append(str(resp.ext_privkey))
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


def test_convert_bip32_func(obj, name, case, req, exp, error):
    try:
        if 'file' in exp:
            test_data_list = obj.bip32_test_data['tests']
            results = []
            for test_data in test_data_list:
                if name == 'GetExtPubkeyFromSeed':
                    resp = HDWallet.from_seed(
                        test_data['seed'], test_data['network'])
                    results.append([str(resp.ext_privkey),
                                    str(resp.ext_privkey.get_extpubkey())])
                elif name == 'DerivePrivkeyFromSeed':
                    wallet = HDWallet.from_seed(
                        test_data['seed'], test_data['network'])
                    _list = []

                    def derive(child_data, parent_path):
                        if 'children' in child_data:
                            for child in child_data['children']:
                                path = parent_path + '/' + child['index']
                                resp = wallet.get_privkey(path=path)
                                _list.append(path + ':' + resp.extkey)
                                derive(child, path)

                    derive(test_data['chain'], '')
                    results.append(_list)
                elif name == 'DerivePubkeyFromSeed':
                    wallet = HDWallet.from_seed(
                        test_data['seed'], test_data['network'])
                    _list = []

                    def derive(child_data, parent_path):
                        if 'children' in child_data:
                            for child in child_data['children']:
                                path = parent_path + '/' + child['index']
                                resp = wallet.get_pubkey(path=path)
                                _list.append(path + ':' + resp.extkey)
                                derive(child, path)

                    derive(test_data['chain'], '')
                    results.append(_list)
                else:
                    raise Exception('unknown name: ' + name)

            def gen_list(child_data, is_privkey, parent_path, key_list):
                if 'children' in child_data:
                    for child in child_data['children']:
                        path = parent_path + '/' + child['index']
                        if is_privkey:
                            key = child['extPrivkey']
                        else:
                            key = child['extPubkey']
                        key_list.append(path + ':' + key)
                        gen_list(child, is_privkey, path, key_list)
                return key_list

            for index, test_data in enumerate(test_data_list):
                if name == 'GetExtPubkeyFromSeed':
                    assert_match(obj, name, case,
                                 test_data['chain']['extPrivkey'],
                                 results[index][0], '{},pubkey'.format(index))
                    assert_match(obj, name, case,
                                 test_data['chain']['extPubkey'],
                                 results[index][1], '{},privkey'.format(index))
                elif name == 'DerivePrivkeyFromSeed':
                    _list = gen_list(test_data['chain'], True, '', [])
                    assert_match(obj, name, case, len(_list),
                                 len(results[index]), '{},num'.format(index))
                    for exp_index, exp_item in enumerate(_list):
                        assert_match(obj, name, case, exp_item,
                                     results[index][exp_index],
                                     '{},{}'.format(index, exp_index))
                elif name == 'DerivePubkeyFromSeed':
                    _list = gen_list(test_data['chain'], False, '', [])
                    assert_match(obj, name, case, len(_list),
                                 len(results[index]), '{},num'.format(index))
                    for exp_index, exp_item in enumerate(_list):
                        assert_match(obj, name, case, exp_item,
                                     results[index][exp_index],
                                     '{},{}'.format(index, exp_index))
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
        self.bip32_test_data = get_json_file('bip32/test_vector.json')

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

    def test_extpubkey_from_seed(self):
        test_name = 'GetExtPubkeyFromSeed'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_convert_bip32_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])

    def test_derive_privkey_from_seed(self):
        test_name = 'DerivePrivkeyFromSeed'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_convert_bip32_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])

    def test_derive_pubkey_from_seed(self):
        test_name = 'DerivePubkeyFromSeed'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_convert_bip32_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])
