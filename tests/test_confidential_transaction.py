from unittest import TestCase
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match
from cfd.util import CfdError
from cfd.address import AddressUtil
from cfd.descriptor import parse_descriptor
from cfd.script import HashType
from cfd.key import SigHashType, SignParameter, Network
from cfd.transaction import OutPoint, TxIn
from cfd.confidential_transaction import ConfidentialTxOut,\
    ConfidentialTransaction, ElementsUtxoData, IssuanceKeyPair
import json


def test_ct_transaction_func1(obj, name, case, req, exp, error):
    try:
        def get_tx():
            resp = ''
            if 'tx' in req:
                resp = ConfidentialTransaction.from_hex(req['tx'])
            txins, txouts = [], []
            for input in req.get('txins', []):
                txins.append(TxIn(txid=input['txid'], vout=input['vout'],
                                  sequence=input.get('sequence',
                                                     TxIn.SEQUENCE_DISABLE)))
            for output in req.get('txouts', []):
                txouts.append(ConfidentialTxOut(
                    output['amount'], address=output.get('address', ''),
                    locking_script=output.get('directLockingScript', ''),
                    asset=output.get('asset', ''),
                    nonce=output.get('directNonce', '')))
            for output in req.get('destroyAmountTxouts', []):
                txouts.append(ConfidentialTxOut.for_destroy_amount(
                    output['amount'], asset=output.get('asset', ''),
                    nonce=output.get('directNonce', '')))
            if 'fee' in req:
                output = req['fee']
                if 'amount' in output:
                    txouts.append(ConfidentialTxOut.for_fee(
                        output['amount'], asset=output.get('asset', '')))
            return resp, txins, txouts

        if name == 'ConfidentialTransaction.Create':
            resp, txins, txouts = get_tx()
            resp = ConfidentialTransaction.create(
                req['version'], req['locktime'], txins, txouts)
        elif name == 'ConfidentialTransaction.Add':
            resp, txins, txouts = get_tx()
            if len(txins) + len(txouts) == 1:
                for input in req.get('txins', []):
                    resp.add_txin(txid=input['txid'], vout=input['vout'],
                                  sequence=input.get('sequence',
                                                     TxIn.SEQUENCE_DISABLE))
                for output in req.get('txouts', []):
                    resp.add_txout(
                        output['amount'], address=output.get('address', ''),
                        locking_script=output.get('directLockingScript', ''),
                        asset=output.get('asset', ''),
                        nonce=output.get('directNonce', ''))
                for output in req.get('destroyAmountTxouts', []):
                    resp.add_destroy_amount_txout(
                        output['amount'], output.get('asset', ''),
                        nonce=output.get('directNonce', ''))
                if ('fee' in req) and ('amount' in req['fee']):
                    output = req['fee']
                    resp.add_fee_txout(
                        output['amount'], output.get('asset', ''))
            else:
                resp.add(txins, txouts)
        elif name == 'ConfidentialTransaction.UpdateTxOutAmount':
            resp, txins, txouts = get_tx()
            for output in req.get('txouts', []):
                if 'index' in output:
                    index = output['index']
                else:
                    index = resp.get_txout_index(
                        address=output.get('address', ''),
                        locking_script=output.get('directLockingScript', ''))
                resp.update_txout_amount(index, output['amount'])
        elif name == 'ConfidentialTransaction.UpdateWitnessStack':
            resp, txins, txouts = get_tx()
            # FIXME impl
            return True

        elif name == 'ConfidentialTransaction.UpdateTxOutFeeAmount':
            # FIXME impl
            # update_txout_fee_amount
            pass
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


def test_ct_transaction_func2(obj, name, case, req, exp, error):
    try:
        def get_tx():
            resp, txin = None, None
            if 'tx' in req:
                resp = ConfidentialTransaction.from_hex(req['tx'])
            if 'txin' in req:
                txin = req['txin']
            return resp, txin

        if name == 'ConfidentialTransaction.SignWithPrivkey':
            resp, txin = get_tx()
            _sighashtype = SigHashType.get(
                txin.get('sighashType', 'all'),
                txin.get('sighashAnyoneCanPay', False))
            resp.sign_with_privkey(
                OutPoint(txin['txid'], txin['vout']),
                txin['hashType'],
                txin['privkey'],
                value=txin.get('confidentialValueCommitment',
                               txin.get('amount', 0)),
                sighashtype=_sighashtype)
        elif name == 'ConfidentialTransaction.AddSign':
            resp, txin = get_tx()
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

        elif name == 'ConfidentialTransaction.AddPubkeyHashSign':
            resp, txin = get_tx()
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

        elif name == 'ConfidentialTransaction.AddMultisigSign':
            resp, txin = get_tx()
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

        elif name == 'ConfidentialTransaction.AddScriptHashSign':
            resp, txin = get_tx()
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

        elif name == 'ConfidentialTransaction.VerifySign':
            resp, txin = get_tx()
            err_list = []
            for txin in req.get('txins', []):
                hash_type = HashType.P2WPKH
                addr = txin.get('address', '')
                desc = txin.get('descriptor', '')
                if desc != '':
                    desc = parse_descriptor(desc, network=Network.LIQUID_V1)
                    addr = desc.data.address
                    hash_type = desc.data.hash_type
                elif addr != '':
                    addr = AddressUtil.parse(addr)
                    hash_type = addr.hash_type

                try:
                    resp.verify_sign(
                        OutPoint(txin['txid'], txin['vout']),
                        addr, hash_type,
                        txin.get('confidentialValueCommitment',
                                 txin.get('amount', 0)))
                except CfdError as err:
                    _dict = {'txid': txin['txid'], 'vout': txin['vout']}
                    _dict['reason'] = err.message
                    err_list.append(_dict)

            success = (len(err_list) == 0)
            resp = {'success': success, 'failTxins': err_list}

        elif name == 'ConfidentialTransaction.VerifySignature':
            resp, txin = get_tx()
            resp = resp.verify_signature(
                OutPoint(txin['txid'], txin['vout']),
                signature=txin.get('signature', ''),
                hash_type=txin['hashType'],
                pubkey=txin['pubkey'],
                value=txin.get('confidentialValueCommitment',
                               txin.get('amount', 0)),
                redeem_script=txin.get('redeemScript', ''),
                sighashtype=txin.get('sighashType', 'all'))

        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'ConfidentialTransaction.VerifySign':
            assert_match(obj, name, case, len(exp['failTxins']),
                         len(resp['failTxins']), 'failTxinsLen')
            assert_equal(obj, name, case, exp, resp['success'], 'success')
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
        elif name == 'ConfidentialTransaction.VerifySignature':
            assert_equal(obj, name, case, exp, resp, 'success')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'hex')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_ct_transaction_func3(obj, name, case, req, exp, error):
    try:
        if name == 'ConfidentialTransaction.Decode':
            resp = ConfidentialTransaction.parse_to_json(
                req.get('hex', ''), req.get('network', 'mainnet'),
                req.get('fullDump', False))
        elif name == 'ConfidentialTransaction.CreateSighash':
            resp = ConfidentialTransaction.from_hex(req['tx'])
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
                value=txin.get('confidentialValueCommitment',
                               txin.get('amount', 0)),
                pubkey=pubkey,
                redeem_script=script,
                sighashtype=_sighashtype)
        elif name == 'ConfidentialTransaction.GetWitnessStackNum':
            resp = ConfidentialTransaction.from_hex(req['tx'])
            txin = req['txin']
            index = resp.get_txin_index(txid=txin['txid'], vout=txin['vout'])
            resp = len(resp.txin_list[index].witness_stack)
        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'ConfidentialTransaction.Decode':
            exp_json = json.dumps(exp)
            exp_json = exp_json.replace(', ', ',')
            exp_json = exp_json.replace('} ', '}')
            exp_json = exp_json.replace('] ', ']')
            exp_json = exp_json.replace(': ', ':')

            assert_match(obj, name, case, exp_json, resp, 'json')
        elif name == 'ConfidentialTransaction.GetWitnessStackNum':
            assert_equal(obj, name, case, exp, resp, 'count')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'sighash')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_ct_transaction_func4(obj, name, case, req, exp, error):
    try:
        resp = ''
        if name == 'ConfidentialTransaction.BlindingKey.Default':
            if 'lockingScript' in req:
                script = req['lockingScript']
            else:
                addr = AddressUtil.parse(req['address'])
                script = addr.locking_script
            resp = ConfidentialTransaction.get_default_blinding_key(
                req['masterBlindingKey'], script)
        elif name == 'ConfidentialTransaction.BlindingKey.Issuance':
            resp = ConfidentialTransaction.get_issuance_blinding_key(
                req['masterBlindingKey'], req['txid'], req['vout'])
        elif name == 'ConfidentialTransaction.CreateRawPegin':
            # FIXME: implement
            return True
        elif name == 'ConfidentialTransaction.CreateRawPegout':
            # FIXME: implement
            return True
        elif name == 'ConfidentialTransaction.CreateDestroyAmount':
            # FIXME: implement
            return True
        elif name == 'ConfidentialTransaction.SetIssueAsset':
            # FIXME: implement
            return True
        elif name == 'ConfidentialTransaction.Unblind':
            outputs = []
            issuance_outputs = []
            resp = ConfidentialTransaction.from_hex(req['tx'])
            for output in req.get('txouts', []):
                txout = resp.unblind_txout(
                    output['index'], output['blindingKey'])
                outputs.append({
                    'index': output['index'],
                    'asset': str(txout.asset),
                    'blindFactor': str(txout.amount_blinder),
                    'assetBlindFactor': str(txout.asset_blinder),
                    'amount': txout.value.amount
                })
            for output in req.get('issuances', []):
                index = resp.get_txin_index(txid=output['txid'],
                                            vout=output['vout'])
                issuance = resp.unblind_issuance(
                    index, output['assetBlindingKey'],
                    output.get('tokenBlindingKey', output['assetBlindingKey']))
                issuance_outputs.append({
                    'txid': output['txid'],
                    'vout': output['vout'],
                    'asset': str(issuance[0].asset),
                    'assetamount': issuance[0].value.amount,
                    'token': str(issuance[1].asset),
                    'tokenamount': issuance[1].value.amount
                })
            resp = {'outputs': outputs, 'issuanceOutputs': issuance_outputs}
        elif name == 'ConfidentialTransaction.SetReissueAsset':
            resp = ConfidentialTransaction.from_hex(req['tx'])
            issuances = []
            for issuance in req.get('issuances', []):
                utxo = ElementsUtxoData(
                    txid=issuance['txid'], vout=issuance['vout'],
                    amount=issuance['amount'],
                    asset_blinder=issuance['assetBlindingNonce'])
                asset = resp.set_raw_reissue_asset(
                    utxo, issuance['amount'], issuance['address'],
                    issuance['assetEntropy'])
                issuances.append({
                    'txid': str(issuance['txid']),
                    'vout': issuance['vout'],
                    'asset': str(asset),
                    'entropy': str(issuance['assetEntropy'])
                })
            resp = {'hex': str(resp), 'issuances': issuances}
        elif name == 'ConfidentialTransaction.Blind':
            resp = ConfidentialTransaction.from_hex(req['tx'])
            utxo_list = []
            issuance_key_map = {}
            ct_addr_list = req.get('txoutConfidentialAddresses', [])
            txout_map = {}
            for txin in req.get('txins', []):
                utxo = ElementsUtxoData(
                    txid=txin['txid'], vout=txin['vout'],
                    amount=txin['amount'], asset=txin['asset'],
                    asset_blinder=txin['assetBlindFactor'],
                    amount_blinder=txin['blindFactor'])
                utxo_list.append(utxo)
            for issuance in req.get('issuances', []):
                outpoint = OutPoint(issuance['txid'], issuance['vout'])
                issuance_key_map[str(outpoint)] = IssuanceKeyPair(
                    issuance['assetBlindingKey'], issuance['tokenBlindingKey'])
            for output in req.get('txouts', []):
                txout_map[str(output['index'])] = output['confidentialKey']
            if issuance_key_map:
                resp.blind(utxo_list,
                           issuance_key_map=issuance_key_map,
                           confidential_address_list=ct_addr_list,
                           direct_confidential_key_map=txout_map,
                           minimum_range_value=req.get('minimumRangeValue', 1),
                           exponent=req.get('exponent', 0),
                           minimum_bits=req.get('minimumBits', -1))
            else:
                resp.blind_txout(utxo_list,
                                 confidential_address_list=ct_addr_list,
                                 direct_confidential_key_map=txout_map,
                                 minimum_range_value=req.get(
                                     'minimumRangeValue', 1),
                                 exponent=req.get('exponent', 0),
                                 minimum_bits=req.get('minimumBits', -1))

            resp = {'size': resp.size, 'vsize': resp.vsize}
        else:
            return False
        assert_error(obj, name, case, error)

        if name == 'ConfidentialTransaction.Unblind':
            assert_match(obj, name, case, len(exp['outputs']),
                         len(resp['outputs']), 'outputsLen')
            exp_issuances = exp.get('issuanceOutputs', [])
            assert_match(obj, name, case, len(exp_issuances),
                         len(resp['issuanceOutputs']),
                         'issuanceOutputsLen')
            for index, output in enumerate(resp['outputs']):
                assert_match(obj, name, case,
                             exp['outputs'][index]['index'],
                             output['index'], 'outputs.index')
                assert_match(obj, name, case,
                             exp['outputs'][index]['asset'],
                             output['asset'], 'outputs.asset')
                assert_match(obj, name, case,
                             exp['outputs'][index]['blindFactor'],
                             output['blindFactor'], 'outputs.blindFactor')
                assert_match(obj, name, case,
                             exp['outputs'][index]['assetBlindFactor'],
                             output['assetBlindFactor'],
                             'outputs.assetBlindFactor')
                assert_match(obj, name, case,
                             exp['outputs'][index]['amount'],
                             output['amount'], 'outputs.amount')
            for index, output in enumerate(resp['issuanceOutputs']):
                assert_match(obj, name, case,
                             exp_issuances[index]['txid'],
                             output['txid'], 'issuanceOutputs.txid')
                assert_match(obj, name, case,
                             exp_issuances[index]['vout'],
                             output['vout'], 'issuanceOutputs.vout')
                assert_match(obj, name, case,
                             exp_issuances[index]['asset'],
                             output['asset'], 'issuanceOutputs.asset')
                assert_match(obj, name, case,
                             exp_issuances[index]['assetamount'],
                             output['assetamount'],
                             'issuanceOutputs.assetamount')
                assert_match(obj, name, case,
                             exp_issuances[index]['token'],
                             output['token'], 'issuanceOutputs.token')
                assert_match(obj, name, case,
                             exp_issuances[index]['tokenamount'],
                             output['tokenamount'],
                             'issuanceOutputs.tokenamount')
        elif name == 'ConfidentialTransaction.SetReissueAsset':
            assert_equal(obj, name, case, exp, str(resp['hex']), 'hex')
            assert_match(obj, name, case, len(exp['issuances']),
                         len(resp['issuances']), 'issuancesLen')
            for index, output in enumerate(resp['issuances']):
                assert_match(obj, name, case,
                             exp['issuances'][index]['txid'],
                             output['txid'], 'issuances.txid')
                assert_match(obj, name, case,
                             exp['issuances'][index]['vout'],
                             output['vout'], 'issuances.vout')
                assert_match(obj, name, case,
                             exp['issuances'][index]['asset'],
                             output['asset'], 'issuances.asset')
                assert_match(obj, name, case,
                             exp['issuances'][index]['entropy'],
                             output['entropy'], 'issuances.entropy')

        elif name == 'ConfidentialTransaction.Blind':
            if resp['size'] < exp['minSize']:
                obj.assertEqual(exp['minSize'], resp['size'],
                                'Fail: {}:{}:{}'.format(name, case, 'minSize'))
            elif exp['maxSize'] < resp['size']:
                obj.assertEqual(exp['maxSize'], resp['size'],
                                'Fail: {}:{}:{}'.format(name, case, 'maxSize'))
            if resp['vsize'] < exp['minVsize']:
                obj.assertEqual(exp['minVsize'], resp['vsize'],
                                'Fail: {}:{}:{}'.format(
                                    name, case, 'minVsize'))
            elif exp['maxVsize'] < resp['vsize']:
                obj.assertEqual(exp['maxVsize'], resp['vsize'],
                                'Fail: {}:{}:{}'.format(
                                    name, case, 'maxVsize'))
        else:
            assert_equal(obj, name, case, exp, str(resp), 'blindingKey')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_ct_transaction_func(obj, name, case, req, exp, error):
    if test_ct_transaction_func1(obj, name, case, req, exp, error):
        pass
    elif test_ct_transaction_func2(obj, name, case, req, exp, error):
        pass
    elif test_ct_transaction_func3(obj, name, case, req, exp, error):
        pass
    elif test_ct_transaction_func4(obj, name, case, req, exp, error):
        pass
    else:
        raise Exception('unknown name: ' + name)


def test_elements_tx_func(obj, name, case, req, exp, error):
    try:
        if name == 'Elements.CoinSelection':
            pass
        elif name == 'Elements.EstimateFee':
            pass
        elif name == 'Elements.FundTransaction':
            pass
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestConfidentialTransaction(TestCase):
    def setUp(self):
        self.test_list = load_json_file('elements_transaction_test.json')
        self.test_list += load_json_file('elements_coin_test.json')

    def test_confidential_transaction(self):
        exec_test(self, 'ConfidentialTransaction', test_ct_transaction_func)

    def test_elements_tx(self):
        exec_test(self, 'Elements', test_elements_tx_func)
