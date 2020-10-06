from unittest import TestCase
from tests.util import load_test_list, load_json_file,\
    assert_equal, assert_error
from cfd.util import CfdError
from cfd.key import Privkey, Pubkey


def test_privkey_func(obj, name, case, req, exp, error):
    try:
        if name == 'Privkey':
            resp = Privkey(req['wif'], req['hex'],
                           req['network'], req['is_compressed'])
        elif name == 'Privkey.AddTweak':
            key = Privkey(hex=req['hex'])
            resp = key.add_tweak(req['tweak'])
        elif name == 'Privkey.MulTweak':
            key = Privkey(hex=req['hex'])
            resp = key.mul_tweak(req['tweak'])
        elif name == 'Privkey.Negate':
            key = Privkey(hex=req['hex'])
            resp = key.negate()
        elif name == 'Privkey.CalculateEcSignature':
            key = Privkey(hex=req['hex'])
            resp = key.calculate_ec_signature(
                req['sighash'], req['grind_r'])
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if isinstance(resp, Privkey):
            assert_equal(obj, name, case, exp, str(resp), 'privkey')
            assert_equal(obj, name, case, exp, resp.wif, 'wif')
            assert_equal(obj, name, case, exp, resp.hex, 'hex')
            assert_equal(obj, name, case, exp,
                         resp.network.as_str(), 'network')
            assert_equal(obj, name, case, exp,
                         resp.is_compressed, 'is_compressed')
            assert_equal(obj, name, case, exp,
                         str(resp.pubkey), 'pubkey')
        else:
            assert_equal(obj, name, case, exp, resp, 'signature')
            assert_equal(obj, name, case, exp, resp, 'hex')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


def test_pubkey_func(obj, name, case, req, exp, error):
    try:
        if name == 'Pubkey':
            resp = Pubkey(req['hex'])
        elif name == 'Pubkey.VerifyEcSignature':
            key = Pubkey(req['hex'])
            resp = key.verify_ec_signature(
                req['sighash'], req['signature'])
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if isinstance(resp, Pubkey):
            assert_equal(obj, name, case, exp, str(resp), 'hex')
        elif isinstance(resp, bool):
            assert_equal(obj, name, case, exp, resp, 'bool')
        else:
            assert_equal(obj, name, case, exp, resp, 'hex')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestKey(TestCase):
    def setUp(self):
        self.test_list = load_json_file('key_test.json')

    def test_privkey(self):
        test_name = 'Privkey'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_privkey_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])

    def test_pubkey(self):
        test_name = 'Pubkey'
        _dict = load_test_list(self.test_list, test_name)
        for key_name, tests in _dict.items():
            for test_data in tests:
                test_pubkey_func(
                    self, key_name,
                    test_data['case'], test_data['request'],
                    test_data['expect'], test_data['error'])
