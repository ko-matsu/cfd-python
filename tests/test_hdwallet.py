from unittest import TestCase
from tests.util import load_json_file, get_json_file,\
    exec_test, assert_equal, assert_match, assert_error
from cfd.util import CfdError, set_custom_prefix, clear_custom_prefix
from cfd.key import Privkey
from cfd.hdwallet import HDWallet, ExtPrivkey, ExtPubkey, Extkey
import json
import unicodedata


def test_mnemonic_word_list_func(obj, name, case, req, exp, error):
    try:
        if name == 'HDWallet.GetMnemonicWordList':
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
        if ('file' in exp) and ('language' in exp):
            test_data_list = obj.mnemonic_test_data[exp['language']]
            results = []
            for test_data in test_data_list:
                if name == 'HDWallet.GetEntropyFromMnemonic':
                    resp = HDWallet.get_entropy(
                        test_data['mnemonic'], req['language'])
                    results.append(resp)
                elif name == 'HDWallet.GetMnemonicFromEntropy':
                    resp = HDWallet.get_mnemonic(
                        test_data['entropy'], req['language'])
                    results.append(resp)
                elif name == 'HDWallet.GetMnemonicToSeed':
                    resp = HDWallet.from_mnemonic(
                        test_data['mnemonic'], req['language'],
                        test_data['passphrase'])
                    results.append(resp.seed)
                elif name == 'HDWallet.GetExtPrivkeyFromSeed':
                    resp = HDWallet.from_seed(test_data['seed'])
                    results.append(str(resp.ext_privkey))
                else:
                    raise Exception('unknown name: ' + name)

            for index, test_data in enumerate(test_data_list):
                if name == 'HDWallet.GetEntropyFromMnemonic':
                    assert_match(obj, name, case, test_data['entropy'],
                                 results[index], index)
                elif name == 'HDWallet.GetMnemonicFromEntropy':
                    _mnemonic = ' '.join(test_data['mnemonic'])
                    _mnemonic = unicodedata.normalize('NFD', _mnemonic)
                    assert_match(obj, name, case, _mnemonic,
                                 results[index], index)
                elif name == 'HDWallet.GetMnemonicToSeed':
                    assert_match(obj, name, case, test_data['seed'],
                                 results[index], index)
                elif name == 'HDWallet.GetExtPrivkeyFromSeed':
                    assert_match(obj, name, case, test_data['xpriv'],
                                 results[index], index)

        elif 'file' in exp:
            test_data_list = obj.bip32_test_data['tests']
            results = []
            for test_data in test_data_list:
                if name == 'HDWallet.GetExtPrivkeyFromSeed':
                    resp = HDWallet.from_seed(
                        test_data['seed'], test_data['network'])
                    results.append(str(resp.ext_privkey))

            for index, test_data in enumerate(test_data_list):
                if name == 'HDWallet.GetExtPrivkeyFromSeed':
                    assert_match(obj, name, case,
                                 test_data['chain']['extPrivkey'],
                                 results[index], index)

        else:
            if name == 'HDWallet.GetMnemonicFromEntropy':
                resp = HDWallet.get_mnemonic(req['entropy'], req['language'])
            elif name == 'HDWallet.GetMnemonicToSeed':
                strict_check = True
                if 'strict_check' in req:
                    strict_check = req['strict_check']
                resp = HDWallet.from_mnemonic(
                    req['mnemonic'], req['language'], req['passphrase'],
                    strict_check=strict_check)
            elif name == 'HDWallet.GetExtPrivkeyFromSeed':
                resp = HDWallet.from_seed(req['seed'], req['network'],
                                          req.get('bip32FormatType', 'bip32'))
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
                if name == 'Extkey.GetExtPubkey':
                    resp = HDWallet.from_seed(
                        test_data['seed'], test_data['network'])
                    results.append([str(resp.ext_privkey),
                                    str(resp.ext_privkey.get_extpubkey())])
                elif name == 'Extkey.DerivePrivkeyFromSeed':
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
                elif name == 'Extkey.DerivePubkeyFromSeed':
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
                if name == 'Extkey.GetExtPubkey':
                    assert_match(obj, name, case,
                                 test_data['chain']['extPrivkey'],
                                 results[index][0], '{},pubkey'.format(index))
                    assert_match(obj, name, case,
                                 test_data['chain']['extPubkey'],
                                 results[index][1], '{},privkey'.format(index))
                elif name == 'Extkey.DerivePrivkeyFromSeed':
                    _list = gen_list(test_data['chain'], True, '', [])
                    assert_match(obj, name, case, len(_list),
                                 len(results[index]), '{},num'.format(index))
                    for exp_index, exp_item in enumerate(_list):
                        assert_match(obj, name, case, exp_item,
                                     results[index][exp_index],
                                     '{},{}'.format(index, exp_index))
                elif name == 'Extkey.DerivePubkeyFromSeed':
                    _list = gen_list(test_data['chain'], False, '', [])
                    assert_match(obj, name, case, len(_list),
                                 len(results[index]), '{},num'.format(index))
                    for exp_index, exp_item in enumerate(_list):
                        assert_match(obj, name, case, exp_item,
                                     results[index][exp_index],
                                     '{},{}'.format(index, exp_index))
        else:
            if name == 'Extkey.GetExtPubkey':
                resp = ExtPrivkey(req['extkey'])
                resp.get_extpubkey()
            else:
                raise Exception('unsupported route: ' + name)
        assert_error(obj, name, case, error)

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def test_extkey_func(obj, name, case, req, exp, error):
    try:
        _path = ''
        number = req.get('childNumber', 0)
        if number >= 0 and req.get('hardened', False) is True:
            number |= 0x80000000

        if name in ['Extkey.CreateExtkeyFromParent',
                    'Extkey.CreateExtkeyFromParentPath']:
            if req.get('extkeyType', '') == 'extPrivkey':
                resp = ExtPrivkey(req['extkey'])
            else:
                resp = ExtPubkey(req['extkey'])
            resp = resp.derive(
                path=req.get('path', ''),
                number=number,
                number_list=req.get('childNumberArray', []))

        elif name == 'Extkey.GetExtkeyInfo':
            if 'privkey' in case:
                resp = ExtPrivkey(req['extkey'])
            else:
                resp = ExtPubkey(req['extkey'])

        elif name == 'Extkey.CreateExtkey':
            if req['extkeyType'] == 'extPrivkey':
                cls_obj = ExtPrivkey
            else:
                cls_obj = ExtPubkey

            resp = cls_obj.create(
                network=req['network'],
                fingerprint=req['parentFingerprint'],
                key=req['key'],
                chain_code=req['chainCode'],
                depth=req['depth'],
                number=number,
                format_type=req.get('bip32FormatType', 'bip32'))

        elif name == 'Extkey.GetExtkeyPathData':
            if 'privkey' in case:
                resp = ExtPrivkey(req['extkey'])
            else:
                resp = ExtPubkey(req['extkey'])
            _path, resp = resp.get_path_data(req['bip32'])

        elif name == 'Extkey.GetPrivkeyFromExtkey':
            resp = ExtPrivkey(req['extkey'])
            resp = resp.privkey
            if not req.get('isCompressed', True):
                resp = Privkey(hex=resp.hex, network=resp.network,
                               is_compressed=False)

            if req.get('wif', True):
                resp = resp.wif
            else:
                resp = resp.hex

        elif name == 'Extkey.GetPubkeyFromExtkey':
            if 'privkey' in case:
                resp = ExtPrivkey(req['extkey'])
                resp = resp.get_extpubkey()
            else:
                resp = ExtPubkey(req['extkey'])
            resp = resp.pubkey

        else:
            raise Exception('unsupported route: ' + name)

        assert_error(obj, name, case, error, resp)

        assert_equal(obj, name, case, exp, resp, 'extkey')
        if isinstance(resp, Extkey):
            assert_equal(obj, name, case, exp,
                         resp.network.as_str(), 'network')
            assert_equal(obj, name, case, exp, resp.version, 'version')
            assert_equal(obj, name, case, exp, resp.depth, 'depth')
            assert_equal(obj, name, case, exp, resp.fingerprint, 'fingerprint')
            assert_equal(obj, name, case, exp,
                         resp.child_number, 'childNumber')
            assert_equal(obj, name, case, exp, resp.chain_code, 'chainCode')
        assert_equal(obj, name, case, exp, _path, 'path')
        assert_equal(obj, name, case, exp, resp, 'pubkey')
        assert_equal(obj, name, case, exp, resp, 'privkey')

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
        exec_test(self, 'HDWallet.GetMnemonicWordList',
                  test_mnemonic_word_list_func)

    def test_get_entropy_from_mnemonic(self):
        exec_test(self, 'HDWallet.GetEntropyFromMnemonic',
                  test_convert_mnemonic_func)

    def test_get_mnemonic_from_entropy(self):
        exec_test(self, 'HDWallet.GetMnemonicFromEntropy',
                  test_convert_mnemonic_func)

    def test_mnemonic_to_seed(self):
        exec_test(self, 'HDWallet.GetMnemonicToSeed',
                  test_convert_mnemonic_func)

    def test_extkey_from_seed(self):
        exec_test(self, 'HDWallet.GetExtPrivkeyFromSeed',
                  test_convert_mnemonic_func)

    def test_extpubkey_from_seed(self):
        exec_test(self, 'Extkey.GetExtPubkey', test_convert_bip32_func)

    def test_derive_privkey_from_seed(self):
        exec_test(self, 'Extkey.DerivePrivkeyFromSeed',
                  test_convert_bip32_func)

    def test_derive_pubkey_from_seed(self):
        exec_test(self, 'Extkey.DerivePubkeyFromSeed', test_convert_bip32_func)

    def test_extkey_from_parent(self):
        exec_test(self, 'Extkey.CreateExtkeyFromParent', test_extkey_func)
        exec_test(self, 'Extkey.CreateExtkeyFromParentPath', test_extkey_func)

    def test_extkey_info(self):
        exec_test(self, 'Extkey.GetExtkeyInfo', test_extkey_func)

    def test_create_extkey(self):
        exec_test(self, 'Extkey.CreateExtkey', test_extkey_func)

    def test_extkey_path_data(self):
        exec_test(self, 'Extkey.GetExtkeyPathData', test_extkey_func)

    def test_privkey_from_extkey(self):
        exec_test(self, 'Extkey.GetPrivkeyFromExtkey', test_extkey_func)

    def test_pubkey_from_extkey(self):
        exec_test(self, 'Extkey.GetPubkeyFromExtkey', test_extkey_func)

    def test_custom_prefix(self):
        try:
            json_dict = {
                'addressJsonDatas': [
                    {
                        'nettype': 'liquidv1',
                        'p2pkh': '39',
                        'p2sh': '27',
                        'bech32': 'ex',
                        'blinded': '0c',
                        'blech32': 'lq',
                    },
                    {
                        'nettype': 'elementsregtest',
                        'p2pkh': 'eb',
                        'p2sh': '4b',
                        'bech32': 'ert',
                        'blinded': '04',
                        'blindedP2sh': '04',
                        'blech32': 'el',
                    },
                ],
                'keyJsonDatas': [
                    {
                        'IsMainnet': 'true',
                        'wif': '80',
                        'bip32xpub': '0488b21e',
                        'bip32xprv': '0488ade4',
                        'bip49ypub': '049d7cb2',
                        'bip49yprv': '049d7878',
                        'bip84zpub': '04b24746',
                        'bip84zprv': '04b2430c',
                    },
                    {
                        'IsMainnet': 'false',
                        'wif': 'ef',
                        'bip32xpub': '043587cf',
                        'bip32xprv': '04358394',
                        'bip49ypub': '044a5262',
                        'bip49yprv': '044a4e28',
                        'bip84zpub': '045f1cf6',
                        'bip84zprv': '045f18bc',
                    },
                ],
            }
            json_str = json.dumps(json_dict)
            set_custom_prefix(json_str)

            # check
            xprv = ExtPrivkey(
                'xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq')  # noqa: E501
            xpub = xprv.get_extpubkey()
            self.assertEqual(
                'xpub661MyMwAqRbcFAEb7d5FeyQpgzpW1yk1koNRtHHhuayKXL7Ls2Kg3GdMzWHSDAfpkzzxKfB9pDHeF8iWTcnovFuJ4DYPBbPBWq7oUFW31LB',  # noqa: E501
                str(xpub), 'xpub')

            clear_custom_prefix()
        except CfdError as err:
            clear_custom_prefix()
            self.assertEqual('', err.message, 'exception')
