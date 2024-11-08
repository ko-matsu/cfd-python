from unittest import TestCase
from tests.util import load_json_file, get_json_file,\
    exec_test, assert_equal, assert_match, assert_error
from cfd.util import CfdError, set_custom_prefix, clear_custom_prefix
from cfd.key import Privkey, Network
from cfd.hdwallet import HDWallet, ExtPrivkey, ExtPubkey, Extkey, ExtKeyType
import json
import time
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
                try:
                    resp = ExtPrivkey(req['extkey'])
                except CfdError:
                    resp = ExtPubkey(req['extkey'])

            resp = resp.derive(
                path=req.get('path', ''),
                number=number,
                number_list=req.get('childNumberArray', []))

            if (req.get('extkeyType', '') == 'extPubkey') and (
                    resp.extkey_type == ExtKeyType.EXT_PRIVKEY):
                resp = resp.get_extpubkey()

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
                        'wif': '40',
                        'bip32xpub': '0473e78d',
                        'bip32xprv': '0473e354',
                        'bip49ypub': '049d7cb2',
                        'bip49yprv': '049d7878',
                        'bip84zpub': '04b24746',
                        'bip84zprv': '04b2430c',
                    },
                    {
                        'IsMainnet': 'false',
                        'wif': '60',
                        'bip32xpub': '0420bd3a',
                        'bip32xprv': '0420b900',
                        'bip49ypub': '044a5262',
                        'bip49yprv': '044a4e28',
                        'bip84zpub': '045f1cf6',
                        'bip84zprv': '045f18bc',
                    },
                ],
            }
            json_str = json.dumps(json_dict)
            set_custom_prefix(json_str)

            # parse
            wprv = ExtPrivkey(
                'wprvikzVDokm6P1KtKfqXgTJv8XpWZcukZYCFsmaRemcFvKZakza93Zwuo15JHekgFrn6ZZai45KS6AitFzNGo2sTf17aiPR86dWi9Tq82Qgo1r')  # noqa: E501
            sprv = ExtPrivkey(
                'sprv8Erh3X3hFeKuoD653knTvhJHkiKLxbhym6yyMYfKJ9kPXc3AnztLtmAyv29tc6yQn95qGE6e6TmYRokeKRMdyBXuyXTihmcpwoqJJPtTyAy')  # noqa: E501
            self.assertEqual(Network.MAINNET, wprv.network, 'wprv.network')
            self.assertEqual(Network.TESTNET, sprv.network, 'sprv.network')

            # check
            seed = 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'  # noqa: E501
            hdwallet_mainnet = HDWallet.from_seed(
                seed, network=Network.MAINNET)
            hdwallet_testnet = HDWallet.from_seed(
                seed, network=Network.TESTNET)
            extprv_main = hdwallet_mainnet.ext_privkey
            extprv_test = hdwallet_testnet.ext_privkey
            self.assertEqual(
                'wprvikzVDokm6P1KtKfqXgTJv8XpWZcukZYCFsmaRemcFvKZakza93Zwuo15JHekgFrn6ZZai45KS6AitFzNGo2sTf17aiPR86dWi9Tq82Qgo1r',  # noqa: E501
                str(extprv_main), 'extprv_main')
            self.assertEqual(
                'sprv8Erh3X3hFeKuoD653knTvhJHkiKLxbhym6yyMYfKJ9kPXc3AnztLtmAyv29tc6yQn95qGE6e6TmYRokeKRMdyBXuyXTihmcpwoqJJPtTyAy',  # noqa: E501
                str(extprv_test), 'extprv_test')
            extpub_main = extprv_main.get_extpubkey()
            extpub_test = extprv_test.get_extpubkey()
            self.assertEqual(
                'wpubWgH9tQnJckSFRpnyr5rjEzmB3bmxQ9nzR21zjuYXxKb8VsQ6bjNrpu2Aph61HVbgR9UFxZuRKe5FMHkZncoGNGUF1zjL8eyQSoacUbLMX4F',  # noqa: E501
                str(extpub_main), 'extpub_main')
            self.assertEqual(
                'spub4Tr3T2ab61tD1hAY9nKUHqF2Jk9qN4Rq8Kua9w4vrVHNQQNKLYCbSZVTmHWGjUHEXBze8DprMkvK8ATi6tdKxBBjwmLdjVtuMKo4yLfkDWR',  # noqa: E501
                str(extpub_test), 'extpub_test')

            try:
                ExtPrivkey(
                    'tpubD6NzVbkrYhZ4XyJymmEgYC3uVhyj4YtPFX6yRTbW6RvfRC7Ag3sVhKSz7MNzFWW5MJ7aVBKXCAX7En296EYdpo43M4a4LaeaHuhhgHToSJF')  # noqa: E501
                self.assertTrue(True, 'invalid prefix not error')
            except CfdError as err2:
                self.assertEqual('unsupported extkey version.',
                                 err2.message, 'invalid prefix')

            clear_custom_prefix()
            time.sleep(1)  # for other test
        except CfdError as err:
            clear_custom_prefix()
            time.sleep(1)  # for other test
            self.assertEqual('', err.message, 'exception')
        finally:
            clear_custom_prefix()
            time.sleep(1)  # for other test
