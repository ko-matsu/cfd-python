from unittest import TestCase
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match
from cfd.util import CfdError
from cfd.hdwallet import ExtPrivkey
from cfd.address import AddressUtil
from cfd.descriptor import parse_descriptor
from cfd.script import HashType
from cfd.key import Network, SigHashType, SignParameter
from cfd.transaction import OutPoint, TxIn, TxOut, Transaction, Txid
import json


def test_transaction_func1(obj, name, case, req, exp, error):
    try:
        if 'tx' in req:
            resp = Transaction.from_hex(req['tx'])
        txins, txouts = [], []
        for input in req.get('txins', []):
            txins.append(TxIn(txid=input['txid'], vout=input['vout'],
                              sequence=input.get('sequence',
                                                 TxIn.SEQUENCE_DISABLE)))
        for output in req.get('txouts', []):
            txouts.append(TxOut(
                output['amount'], address=output.get('address', ''),
                locking_script=output.get('directLockingScript', '')))

        if name == 'Transaction.Create':
            resp = Transaction.create(req['version'], req['locktime'],
                                      txins, txouts)
        elif name == 'Transaction.Add':
            if len(txins) + len(txouts) == 1:
                for input in req.get('txins', []):
                    resp.add_txin(txid=input['txid'], vout=input['vout'],
                                  sequence=input.get('sequence',
                                                     TxIn.SEQUENCE_DISABLE))
                for output in req.get('txouts', []):
                    resp.add_txout(
                        output['amount'], address=output.get('address', ''),
                        locking_script=output.get('directLockingScript', ''))
            else:
                resp.add(txins, txouts)
        elif name == 'Transaction.UpdateTxOutAmount':
            for output in req.get('txouts', []):
                index = resp.get_txout_index(
                    address=output.get('address', ''),
                    locking_script=output.get('directLockingScript', ''))
                resp.update_txout_amount(index, output['amount'])
        elif name == 'Transaction.UpdateWitnessStack':
            # FIXME impl
            return True

        else:
            return False
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'hex')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_transaction_func2(obj, name, case, req, exp, error):
    try:
        if 'tx' in req:
            resp = Transaction.from_hex(req['tx'])
        if 'txin' in req:
            txin = req['txin']
        if name == 'Transaction.SignWithPrivkey':
            _sighashtype = SigHashType.get(
                txin.get('sighashType', 'all'),
                txin.get('sighashAnyoneCanPay', False))
            resp.sign_with_privkey(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                txin['privkey'],
                amount=txin.get('amount', 0),
                sighashtype=_sighashtype)
        elif name == 'Transaction.AddSign':
            hash_type = HashType.P2SH
            if txin.get('isWitness', True):
                hash_type = HashType.P2WSH
            for param in txin.get('signParam', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    param.get('sighashAnyoneCanPay', False))
                encode_der = False
                if param.get('type', '') == 'sign':
                    encode_der = True
                resp.add_sign(
                    OutPoint(txin['txid'], txin['vout']),
                    hash_type,
                    param['hex'],
                    clear_stack=txin.get('clearStack', False),
                    use_der_encode=param.get('derEncode', encode_der),
                    sighashtype=_sighashtype)

        elif name == 'Transaction.AddPubkeyHashSign':
            param = txin['signParam']
            _sighashtype = SigHashType.get(
                param.get('sighashType', 'all'),
                param.get('sighashAnyoneCanPay', False))
            resp.add_pubkey_hash_sign(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                pubkey=txin['pubkey'],
                signature=param['hex'],
                sighashtype=_sighashtype)

        elif name == 'Transaction.AddMultisigSign':
            signature_list = []
            script = txin.get('witnessScript', txin.get('redeemScript', ''))
            for param in txin.get('signParams', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    param.get('sighashAnyoneCanPay', False))
                sign = SignParameter(
                    param['hex'],
                    sighashtype=_sighashtype,
                    use_der_encode=param.get('derEncode', True),
                    related_pubkey=param.get('relatedPubkey', ''))
                signature_list.append(sign)

            resp.add_multisig_sign(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                redeem_script=script,
                signature_list=signature_list)

        elif name == 'Transaction.AddScriptHashSign':
            signature_list = []
            for param in txin.get('signParam', []):
                _sighashtype = SigHashType.get(
                    param.get('sighashType', 'all'),
                    param.get('sighashAnyoneCanPay', False))
                try:
                    sign = SignParameter(
                        param['hex'],
                        sighashtype=_sighashtype,
                        use_der_encode=param.get('derEncode', True))
                    signature_list.append(sign)
                except CfdError:
                    signature_list.append(param['hex'])

            resp.add_script_hash_sign(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                redeem_script=txin['redeemScript'],
                signature_list=signature_list)
            if 'multisig p2wsh' == case:
                print(str(resp))

        elif name == 'Transaction.VerifySign':
            err_list = []
            for txin in req.get('txins', []):
                hash_type = HashType.P2WPKH
                addr = txin.get('address', '')
                desc = txin.get('descriptor', '')
                if desc != '':
                    desc = parse_descriptor(desc)
                    addr = desc.data.address
                    hash_type = desc.data.hash_type
                elif addr != '':
                    addr = AddressUtil.parse(addr)
                    hash_type = addr.hash_type

                try:
                    resp.verify_sign(
                        OutPoint(txin['txid'], txin['vout']),
                        addr, hash_type, txin.get('amount', 0))
                except CfdError as err:
                    _dict = {'txid': txin['txid'], 'vout': txin['vout']}
                    _dict['reason'] = err.message
                    err_list.append(_dict)

            success = (len(err_list) == 0)
            resp = {'success': success, 'failTxins': err_list}

        elif name == 'Transaction.VerifySignature':
            resp = resp.verify_signature(
                OutPoint(txin['txid'], txin['vout']),
                signature=txin.get('signature', ''),
                hash_type=txin['hashType'],
                amount=txin.get('amount', 0),
                pubkey=txin['pubkey'],
                redeem_script=txin.get('redeemScript', ''),
                sighashtype=txin.get('sighashType', 'all'))

        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'Transaction.VerifySign':
            assert_equal(obj, name, case, exp, resp['success'], 'success')
            assert_match(obj, name, case, len(exp['failTxins']),
                         len(exp['failTxins']), 'failTxinsLen')
            for index, txin in enumerate(resp['failTxins']):
                assert_match(obj, name, case,
                             exp['failTxins'][index]['txid'],
                             txin['txid'], 'failTxins.txid')
                assert_match(obj, name, case,
                             exp['failTxins'][index]['vout'],
                             txin['vout'], 'failTxins.vout')
                assert_match(obj, name, case,
                             exp['failTxins'][index]['reason'],
                             txin['reason'], 'failTxins.reason')
        elif name == 'Transaction.VerifySignature':
            assert_equal(obj, name, case, exp, resp, 'success')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'hex')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_transaction_func3(obj, name, case, req, exp, error):
    try:
        if name == 'Transaction.Decode':
            resp = Transaction.parse_to_json(
                req.get('hex', ''), req.get('network', 'mainnet'))
        elif name == 'Transaction.CreateSighash':
            resp = Transaction.from_hex(req['tx'])
            txin = req['txin']
            key_data = txin['keyData']
            pubkey = key_data['hex'] if key_data['type'] == 'pubkey' else ''
            script = key_data['hex'] if key_data['type'] != 'pubkey' else ''
            _sighashtype = SigHashType.get(
                txin.get('sighashType', 'all'),
                txin.get('sighashAnyoneCanPay', False))
            resp = resp.get_sighash(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                amount=txin.get('amount', 0),
                pubkey=pubkey,
                redeem_script=script,
                sighashtype=_sighashtype)
        elif name == 'Transaction.GetWitnessStackNum':
            resp = Transaction.from_hex(req['tx'])
            txin = req['txin']
            index = resp.get_txin_index(txid=txin['txid'], vout=txin['vout'])
            resp = len(resp.txin_list[index].witness_stack)
        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'Transaction.Decode':
            exp_json = json.dumps(exp)
            exp_json = exp_json.replace(', ', ',')
            exp_json = exp_json.replace('} ', '}')
            exp_json = exp_json.replace('] ', ']')
            exp_json = exp_json.replace(': ', ':')

            assert_match(obj, name, case, exp_json, resp, 'json')
        elif name == 'Transaction.GetWitnessStackNum':
            assert_equal(obj, name, case, exp, resp, 'count')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'sighash')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_transaction_func(obj, name, case, req, exp, error):
    if test_transaction_func1(obj, name, case, req, exp, error):
        pass
    elif test_transaction_func2(obj, name, case, req, exp, error):
        pass
    elif test_transaction_func3(obj, name, case, req, exp, error):
        pass
    else:
        raise Exception('unknown name: ' + name)


class TestTxid(TestCase):
    def test_txid(self):
        txid = 'fe0000000000000000000000000000000000000000000000000000000000ff01'  # noqa: E501
        byte_data = b'\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe'  # noqa: E501
        list_data = [1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254]  # noqa: E501
        b_array = bytearray(list_data)
        _txid1 = Txid(txid)
        _txid2 = Txid(byte_data)
        _txid3 = Txid(list_data)
        _txid4 = Txid(b_array)
        self.assertEqual(txid, str(_txid1))
        self.assertEqual(txid, str(_txid2))
        self.assertEqual(txid, str(_txid3))
        self.assertEqual(txid, str(_txid4))
        self.assertEqual(byte_data, _txid1.as_bytes())
        self.assertEqual(list_data, _txid1.as_array())


class TestTransaction(TestCase):
    def setUp(self):
        self.test_list = load_json_file('transaction_test.json')

    def test_transaction(self):
        exec_test(self, 'Transaction', test_transaction_func)

    def test_create_raw_transaction(self):
        privkey = ExtPrivkey(
            'xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV')  # noqa: E501
        addr1 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=1).pubkey, Network.REGTEST)
        addr2 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=2).pubkey, Network.REGTEST)
        addr3 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=3).pubkey, Network.REGTEST)

        outpoint1 = OutPoint(
            '0000000000000000000000000000000000000000000000000000000000000001',
            2)
        outpoint2 = OutPoint(
            '0000000000000000000000000000000000000000000000000000000000000001',
            3)
        tx = Transaction.create(
            version=2,
            locktime=0,
            txins=[
                TxIn(outpoint=outpoint1),
                TxIn(outpoint=outpoint2),
            ],
            txouts=[
                TxOut(amount=10000, locking_script=addr1.locking_script),
                TxOut(amount=10000, locking_script=addr2.locking_script),
            ])
        tx.add_txout(amount=50000, address=addr3)
        self.assertEqual(
            "020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000",  # noqa: E501
            tx.hex)

        privkey1 = privkey.derive(number=11).privkey
        pubkey1 = privkey1.pubkey
        sighash_type = SigHashType.ALL
        sighash = tx.get_sighash(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            pubkey=pubkey1,
            amount=50000,
            sighashtype=sighash_type)
        signature = privkey1.calculate_ec_signature(sighash)
        tx.add_sign(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            sign_data=signature,
            clear_stack=True,
            use_der_encode=True,
            sighashtype=sighash_type)
        tx.add_sign(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            sign_data=pubkey1)
        self.assertEqual(
            "0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000",  # noqa: E501
            tx.hex)

        addr11 = AddressUtil.p2wpkh(pubkey1, Network.REGTEST)
        try:
            tx.verify_sign(
                outpoint=outpoint1,
                address=addr11,
                hash_type=addr11.hash_type,
                amount=50000)
        except Exception as err:
            self.assertIsNone(err)
