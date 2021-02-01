from unittest import TestCase
from tests.util import load_json_file,\
    exec_test, assert_equal, assert_error, assert_message, assert_match
from cfd.util import ByteData, CfdError
from cfd.address import AddressUtil
from cfd.crypto import CryptoUtil
from cfd.hdwallet import KeyData, ExtPubkey
from cfd.key import Network, Pubkey, SigHashType
from cfd.psbt import Psbt
from cfd.script import Script
from cfd.transaction import Transaction, OutPoint, TxOut, UtxoData, TxIn


def test_decode_psbt_func(obj, name, case, req, exp, error):
    try:
        if name != 'Psbt.DecodePsbt':
            raise Exception('unknown name: ' + name)

        psbt = Psbt(req['psbt'], network=req.get(
            'network', Network.MAINNET))
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(psbt.get_tx()), 'tx_hex')
        if 'version' in exp:
            _, ver, _, _ = psbt.get_global_data()
            assert_equal(obj, name, case, exp, ver, 'version')
        xpubkeys = psbt.get_global_xpub_list()
        if 'xpubs' in exp:
            assert_match(obj, name, case, len(exp['xpubs']), len(xpubkeys),
                         f'global:xpubs:num')
            for xpub_index, xpub_data in enumerate(exp.get('xpubs', [])):
                assert_match(obj, name, case, xpub_data['xpub']['base58'], str(
                    xpubkeys[xpub_index].ext_pubkey), f'global:xpubs{xpub_index}:xpub')
                assert_match(obj, name, case, xpub_data['master_fingerprint'], str(
                    xpubkeys[xpub_index].fingerprint),
                    f'global:xpubs{xpub_index}:master_fingerprint')
                assert_match(obj, name, case, xpub_data['path'], str(
                    xpubkeys[xpub_index].bip32_path),
                    f'global:xpubs{xpub_index}:path')
        if 'unknown' in exp:
            unknown_keys = psbt.get_global_unknown_keys()
            key_len = len(unknown_keys)
            if req.get('hasDetail', False):
                key_len = key_len - len(xpubkeys)
            assert_match(obj, name, case, len(exp['unknown']), key_len,
                         'global:unknown:num')
            for unknown_data in exp.get('unknown', []):
                key = unknown_data['key']
                value = psbt.get_global_record(key)
                assert_match(obj, name, case, unknown_data['value'], str(
                    value), f'global:unknown:{key}')

        in_num, out_num = psbt.get_tx_count()
        assert_match(obj, name, case, len(exp['inputs']), in_num, 'num:inputs')
        assert_match(obj, name, case, len(
            exp['outputs']), out_num, 'num:outputs')

        for index in range(in_num):
            exp_input = exp['inputs'][index]
            outpoint = psbt.get_input_outpoint(index)
            if ('witness_utxo' in exp_input) or ('non_witness_utxo_hex' in exp_input):
                utxo, locking_script, _, full_tx = psbt.get_input_utxo_data(
                    outpoint)
                if 'witness_utxo' in exp_input:
                    assert_match(obj, name, case, exp_input['witness_utxo']['amount'],
                                 utxo.amount, f'input{index}:witness_utxo:amount')
                    assert_match(obj, name, case, exp_input['witness_utxo']['scriptPubKey']['hex'],
                                 str(locking_script),
                                 f'input{index}:witness_utxo:scriptPubKey:hex')
                if 'non_witness_utxo_hex' in exp_input:
                    assert_match(obj, name, case, exp_input['non_witness_utxo_hex'], str(
                        str(full_tx)), f'input{index}:non_witness_utxo_hex')
            if 'sighash' in exp_input:
                sighash = psbt.get_input_sighash_type(outpoint)
                assert_match(obj, name, case, exp_input['sighash'].lower(), str(
                    str(sighash)), f'input{index}:sighash')
            if 'final_scriptsig' in exp_input:
                final_scriptsig = psbt.get_input_final_scriptsig(outpoint)
                assert_match(obj, name, case, exp_input['final_scriptsig']['hex'], str(
                    final_scriptsig), f'input{index}:final_scriptsig:hex')
            if 'final_scriptsig' in exp_input:
                final_scriptsig = psbt.get_input_final_scriptsig(outpoint)
                assert_match(obj, name, case, exp_input['final_scriptsig']['hex'], str(
                    final_scriptsig), f'input{index}:final_scriptsig:hex')
            if 'final_scriptwitness' in exp_input:
                witness = psbt.get_input_final_witness(outpoint)
                assert_match(obj, name, case, len(
                    exp_input['final_scriptwitness']), len(witness),
                    f'input{index}:final_scriptwitness:num')
                for wit_index, stack in enumerate(exp_input.get('final_scriptwitness', [])):
                    assert_match(obj, name, case, stack, str(
                        witness[wit_index]), f'input{index}:final_scriptwitness{wit_index}')
            if 'redeem_script' in exp_input:
                redeem_script = psbt.get_input_redeem_script(outpoint)
                assert_match(obj, name, case, exp_input['redeem_script']['hex'], str(
                    redeem_script), f'input{index}:redeem_script:hex')
            if 'witness_script' in exp_input:
                witness_script = psbt.get_input_witness_script(outpoint)
                assert_match(obj, name, case, exp_input['witness_script']['hex'], str(
                    witness_script), f'input{index}:witness_script:hex')
            if 'partial_signatures' in exp_input:
                sigs = psbt.get_input_signature_list(outpoint)
                assert_match(obj, name, case, len(
                    exp_input['partial_signatures']), len(sigs),
                    f'input{index}:partial_signatures:num')
                for sig_index, sig_data in enumerate(exp_input.get('partial_signatures', [])):
                    assert_match(obj, name, case, sig_data['pubkey'], str(
                        sigs[sig_index].related_pubkey), f'input{index}:partial_signatures{sig_index}:pubkey')
                    assert_match(obj, name, case, sig_data['signature'], str(
                        sigs[sig_index].hex),
                        f'input{index}:partial_signatures{sig_index}:signature')
            if 'bip32_derivs' in exp_input:
                pubkeys = psbt.get_input_bip32_list(outpoint)
                assert_match(obj, name, case, len(
                    exp_input['bip32_derivs']), len(pubkeys),
                    f'input{index}:bip32_derivs:num')
                for key_index, key_data in enumerate(exp_input.get('bip32_derivs', [])):
                    assert_match(obj, name, case, key_data['pubkey'], str(
                        pubkeys[key_index].pubkey), f'input{index}:bip32_derivs{key_index}:pubkey')
                    assert_match(obj, name, case, key_data['master_fingerprint'], str(
                        pubkeys[key_index].fingerprint),
                        f'input{index}:bip32_derivs{key_index}:master_fingerprint')
                    assert_match(obj, name, case, key_data['path'],
                                 pubkeys[key_index].bip32_path,
                                 f'input{index}:bip32_derivs{key_index}:path')
            if 'unknown' in exp_input:
                unknown_keys = psbt.get_input_unknown_keys(outpoint)
                assert_match(obj, name, case, len(exp_input['unknown']), len(unknown_keys),
                             f'input{index}:unknown:num')
                for unknown_data in exp_input.get('unknown', []):
                    key = unknown_data['key']
                    value = psbt.get_input_record(outpoint, key)
                    assert_match(obj, name, case, unknown_data['value'], str(
                        value), f'input{index}:unknown:{key}')

        for index in range(out_num):
            exp_output = exp['outputs'][index]
            if 'redeem_script' in exp_output:
                redeem_script = psbt.get_output_redeem_script(index)
                assert_match(obj, name, case, exp_output['redeem_script']['hex'], str(
                    redeem_script), f'output{index}:redeem_script:hex')
            if 'witness_script' in exp_output:
                witness_script = psbt.get_output_witness_script(index)
                assert_match(obj, name, case, exp_output['witness_script']['hex'], str(
                    witness_script), f'output{index}:witness_script:hex')
            if 'bip32_derivs' in exp_output:
                pubkeys = psbt.get_output_bip32_list(index)
                assert_match(obj, name, case, len(
                    exp_output['bip32_derivs']), len(pubkeys),
                    f'output{index}:bip32_derivs:num')
                for key_index, key_data in enumerate(exp_output.get('bip32_derivs', [])):
                    assert_match(obj, name, case, key_data['pubkey'], str(
                        pubkeys[key_index].pubkey), f'output{index}:bip32_derivs{key_index}:pubkey')
                    assert_match(obj, name, case, key_data['master_fingerprint'], str(
                        pubkeys[key_index].fingerprint),
                        f'output{index}:bip32_derivs{key_index}:master_fingerprint')
                    assert_match(obj, name, case, key_data['path'],
                                 pubkeys[key_index].bip32_path,
                                 f'output{index}:bip32_derivs{key_index}:path')
            if 'unknown' in exp_output:
                unknown_keys = psbt.get_output_unknown_keys(index)
                assert_match(obj, name, case, len(exp_output['unknown']), len(unknown_keys),
                             f'output{index}:unknown:num')
                for unknown_data in exp_output.get('unknown', []):
                    key = unknown_data['key']
                    value = psbt.get_output_record(index, key)
                    assert_match(obj, name, case, unknown_data['value'], str(
                        value), f'output{index}:unknown:{key}')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_verify_psbt_func(obj, name, case, req, exp, error):
    try:
        error = False if exp.get('success', True) else True
        if name == 'Psbt.VerifyPsbtSign':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            outpoints = req.get('outPointList', [])
            if outpoints:
                for txin in outpoints:
                    psbt.verify(OutPoint(txin['txid'], txin['vout']))
            else:
                psbt.verify()
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        for fail_data in exp.get('failTxins', []):
            if fail_data['reason'] in err.message:
                return True
        assert_message(obj, name, case, err.message)
    return True


def test_check_finalized_psbt_func(obj, name, case, req, exp, error):
    try:
        resp = {}
        if name == 'Psbt.IsFinalizedPsbt':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            success = True
            fail_inputs = []
            outpoints = req.get('outPointList', psbt.get_tx().txin_list)
            for txin in outpoints:
                if isinstance(txin, TxIn):
                    outpoint = txin.outpoint
                else:
                    outpoint = OutPoint(txin['txid'], txin['vout'])
                if not psbt.is_finalized_input(outpoint):
                    success = False
                    fail_inputs.append(outpoint)
            finalized_all = psbt.is_finalized()
            resp = {
                'success': success,
                'finalizedAll': finalized_all,
                'failInputs': fail_inputs,
            }
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, resp['success'], 'success')
        assert_equal(obj, name, case, exp,
                     resp['finalizedAll'], 'finalizedAll')
        exp_fail_inputs = exp.get('failInputs', [])
        assert_match(obj, name, case, len(exp_fail_inputs),
                     len(resp['failInputs']), 'failInputs')
        if len(exp_fail_inputs) == len(resp['failInputs']):
            for txin in exp_fail_inputs:
                outpoint = OutPoint(txin['txid'], txin['vout'])
                if outpoint not in resp['failInputs']:
                    assert_message(obj, name, case,
                                   f'not found in failInputs: {str(outpoint)}')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_get_utxos_psbt_func(obj, name, case, req, exp, error):
    try:
        resp = {}
        if name == 'Psbt.GetPsbtUtxos':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            resp = []
            in_count, _ = psbt.get_tx_count()
            for index in range(in_count):
                outpoint, amount, _, _, desc, _ = psbt.get_input_data_by_index(
                    index)
                resp.append(UtxoData(outpoint, amount=amount, descriptor=desc))
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        exp_utxos = exp.get('utxos', [])
        assert_match(obj, name, case, len(exp_utxos), len(resp), 'utxos')
        if len(exp_utxos) == len(resp):
            for index, exp_utxo in enumerate(exp_utxos):
                utxo: 'UtxoData' = resp[index]
                assert_equal(obj, name, case, exp_utxo,
                             str(utxo.outpoint.txid), 'txid')
                assert_equal(obj, name, case, exp_utxo,
                             utxo.outpoint.vout, 'vout')
                assert_equal(obj, name, case, exp_utxo, utxo.amount, 'amount')
                assert_equal(obj, name, case, exp_utxo,
                             str(utxo.descriptor), 'descriptor')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


def test_psbt_func(obj, name, case, req, exp, error):
    try:
        fee_amount = None
        if name == 'Psbt.CreatePsbt':
            resp = Psbt.create(req['version'], req['locktime'], network=req.get(
                'network', Network.MAINNET))
            for txin in req.get('txins', []):
                resp.add_input(OutPoint(txin['txid'], txin['vout']),
                               sequence=txin.get('sequence', 4294967295))
            for txout in req.get('txouts', []):
                resp.add_output(txout['amount'], address=txout['address'])
        elif name == 'Psbt.ConvertToPsbt':
            tx = Transaction(req['tx'])
            resp = Psbt.from_transaction(
                tx,
                permit_sig_data=req.get('permitSigData', False),
                network=req.get('network', Network.MAINNET))
        elif name == 'Psbt.JoinPsbts':
            resp = Psbt.join_psbts(req['psbts'], network=req.get(
                'network', Network.MAINNET))
        elif name == 'Psbt.CombinePsbt':
            resp = Psbt.combine_psbts(req['psbts'], network=req.get(
                'network', Network.MAINNET))
        elif name == 'Psbt.FinalizePsbtInput':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            for input in req.get('inputs', []):
                scripts = []
                outpoint = OutPoint(input['txid'], input['vout'])
                if 'final_scriptwitness' in input:
                    for stack in input['final_scriptwitness']:
                        try:
                            scripts.append(Script(stack))
                        except:
                            scripts.append(Script.from_asm([stack]))
                    psbt.set_input_finalize(outpoint, scripts)
                if 'finalScriptsig' in input:
                    if 'final_scriptwitness' in input:
                        psbt.set_input_final_scriptsig(
                            outpoint, input['finalScriptsig'])
                    else:
                        psbt.set_input_finalize(
                            outpoint, Script(input['finalScriptsig']))
                psbt.clear_input_sign_data(outpoint)
            resp = psbt
        elif name == 'Psbt.FinalizePsbt':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            psbt.finalize()
            resp = psbt
        elif name == 'Psbt.SignPsbt':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            psbt.sign(privkey=req['privkey'],
                      has_grind_r=req.get('hasGrindR', True))
            resp = psbt
        elif name == 'Psbt.AddPsbtData':
            net_type = Network.get(req.get('network', Network.MAINNET))
            psbt = Psbt(req['psbt'], network=net_type)
            for input_data in req.get('inputs', []):
                txin = input_data['txin']
                input = input_data['input']
                utxo = TxOut(0)
                if 'witnessUtxo' in input:
                    addr = ''
                    if 'address' in input['witnessUtxo']:
                        addr = AddressUtil.parse(
                            input['witnessUtxo']['address'])
                    utxo = TxOut(input['witnessUtxo']['amount'],
                                 address=addr,
                                 locking_script=input['witnessUtxo'].get('directLockingScript', ''))
                script = '' if 'redeemScript' not in input else Script(
                    input['redeemScript'])
                tx = '' if 'utxoFullTx' not in input else Transaction(
                    input['utxoFullTx'])
                outpoint = OutPoint(txin['txid'], txin['vout'])
                psbt.add_input(outpoint, utxo=utxo, redeem_script=script,
                               utxo_tx=tx, sequence=txin.get('sequence', 4294967295))
                for bip32_data in input.get('bip32Derives', []):
                    if 'descriptor' in bip32_data:
                        psbt.set_input_bip32_key(
                            outpoint, pubkey=bip32_data['descriptor'])
                    else:
                        psbt.set_input_bip32_key(
                            outpoint,
                            key_data=KeyData(Pubkey(bip32_data['pubkey']),
                                             fingerprint=ByteData(
                                bip32_data['master_fingerprint']),
                                bip32_path=bip32_data['path']))
            _, index = psbt.get_tx_count()
            for output_data in req.get('outputs', []):
                txout = output_data['txout']
                output = output_data['output']
                addr = ''
                if 'address' in txout:
                    addr = AddressUtil.parse(
                        txout['address'])
                script = '' if 'redeemScript' not in output else Script(
                    output['redeemScript'])
                psbt.add_output(txout['amount'],
                                address=addr,
                                locking_script=txout.get('directLockingScript', ''), redeem_script=script)
                for bip32_data in output.get('bip32Derives', []):
                    if 'descriptor' in bip32_data:
                        psbt.set_output_bip32_key(
                            index, pubkey=bip32_data['descriptor'])
                    else:
                        psbt.set_output_bip32_key(
                            index,
                            key_data=KeyData(
                                Pubkey(bip32_data['pubkey']), fingerprint=ByteData(
                                    bip32_data['master_fingerprint']),
                                bip32_path=bip32_data['path']))
                index += 1
            resp = psbt
        elif name == 'Psbt.SetPsbtData':
            net_type = Network.get(req.get('network', Network.MAINNET))
            psbt = Psbt(req['psbt'], network=net_type)
            for input_data in req.get('inputs', []):
                input = input_data['input']
                outpoint = psbt.get_input_outpoint(input_data.get('index', 0))
                full_tx = input.get('utxoFullTx', '')
                utxo = None
                if 'witnessUtxo' in input:
                    addr = ''
                    if 'address' in input['witnessUtxo']:
                        addr = AddressUtil.parse(
                            input['witnessUtxo']['address'])
                    utxo = TxOut(input['witnessUtxo']['amount'], addr,
                                 input['witnessUtxo'].get('directLockingScript', ''))
                if 'redeemScript' in input:
                    psbt.set_input_script(outpoint, input['redeemScript'])
                if full_tx or (utxo is not None):
                    utxo = TxOut(0) if utxo is None else utxo
                    psbt.set_input_utxo(outpoint, utxo, full_tx)
                for bip32_data in input.get('bip32Derives', []):
                    if 'descriptor' in bip32_data:
                        psbt.set_input_bip32_key(
                            outpoint, pubkey=bip32_data['descriptor'])
                    else:
                        psbt.set_input_bip32_key(
                            outpoint,
                            key_data=KeyData(Pubkey(bip32_data['pubkey']),
                                             fingerprint=ByteData(
                                bip32_data['master_fingerprint']),
                                bip32_path=bip32_data['path']))
                if 'sighash' in input:
                    psbt.set_input_sighash_type(
                        outpoint, SigHashType.get(input['sighash']))
                for sig_data in input.get('partialSignature', []):
                    psbt.set_input_signature(
                        outpoint, sig_data['pubkey'],  sig_data['signature'])
                for record in input.get('unknown', []):
                    psbt.set_input_record(
                        outpoint, record['key'], record['value'])
            for output_data in req.get('outputs', []):
                output = output_data['output']
                index = output_data.get('index', 0)
                if 'redeemScript' in output:
                    psbt.set_output_script(index, output['redeemScript'])
                for bip32_data in output.get('bip32Derives', []):
                    if 'descriptor' in bip32_data:
                        psbt.set_output_bip32_key(
                            index, pubkey=bip32_data['descriptor'])
                    else:
                        psbt.set_output_bip32_key(
                            index,
                            key_data=KeyData(
                                Pubkey(bip32_data['pubkey']), fingerprint=ByteData(
                                    bip32_data['master_fingerprint']),
                                bip32_path=bip32_data['path']))
                for record in output.get('unknown', []):
                    psbt.set_output_record(
                        index, record['key'], record['value'])
            if 'global' in req:
                global_data = req['global']
                for xpub_data in global_data.get('xpubs', []):
                    if 'descriptorXpub' in xpub_data:
                        psbt.set_global_xpub(
                            ext_pubkey=xpub_data['descriptorXpub'])
                    else:
                        psbt.set_global_xpub(
                            key_data=KeyData(
                                ExtPubkey(xpub_data['xpub']), fingerprint=ByteData(
                                    xpub_data['master_fingerprint']),
                                bip32_path=xpub_data['path']))
                for record in global_data.get('unknown', []):
                    psbt.set_global_record(record['key'], record['value'])
            resp = psbt
        elif name == 'Psbt.SetPsbtRecord':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            for record in req['records']:
                if record['type'] == 'input':
                    psbt.set_input_record(None, record['key'], record['value'],
                                          record.get('index', 0))
                elif record['type'] == 'output':
                    psbt.set_output_record(record.get(
                        'index', 0), record['key'], record['value'])
                elif record['type'] == 'global':
                    psbt.set_global_record(record['key'], record['value'])
            resp = psbt
        elif name == 'Psbt.FundPsbt':
            psbt = Psbt(req['psbt'], network=req.get(
                'network', Network.MAINNET))
            utxos = []
            desc = req['reservedDescriptor']
            fee_rate = req['feeInfo']['feeRate']
            long_term_fee_rate = req['feeInfo']['longTermFeeRate']
            knapsack_min_change = req['feeInfo']['knapsackMinChange']
            dust_fee_rate = req['feeInfo']['dustFeeRate']
            for utxo in req.get('utxos', []):
                utxos.append(UtxoData(OutPoint(utxo['txid'], utxo['vout']),
                                      amount=utxo['amount'], descriptor=utxo['descriptor']))
            fee_amount = psbt.fund(utxos, desc, fee_rate, long_term_fee_rate,
                                   dust_fee_rate, knapsack_min_change)
            resp = psbt
        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        assert_equal(obj, name, case, exp, str(resp), 'psbt')
        if isinstance(resp, Psbt) and ('hex' in exp):
            assert_equal(obj, name, case, exp, str(resp.get_bytes()), 'hex')
        if fee_amount:
            assert_equal(obj, name, case, exp, fee_amount, 'feeAmount')

    except CfdError as err:
        if not error:
            print('{}:{} req={}'.format(name, case, req))
            raise err
        assert_equal(obj, name, case, exp, err.message)
    return True


class TestPsbt(TestCase):
    def setUp(self):
        self.test_list = load_json_file('psbt_test.json')

    def test_psbt_decode(self):
        exec_test(self, 'Psbt.DecodePsbt', test_decode_psbt_func)

    def test_psbt_create(self):
        exec_test(self, 'Psbt.CreatePsbt', test_psbt_func)

    def test_psbt_convert(self):
        exec_test(self, 'Psbt.ConvertToPsbt', test_psbt_func)

    def test_psbt_join(self):
        exec_test(self, 'Psbt.JoinPsbts', test_psbt_func)

    def test_psbt_combine(self):
        exec_test(self, 'Psbt.CombinePsbt', test_psbt_func)

    def test_psbt_finalize_input(self):
        exec_test(self, 'Psbt.FinalizePsbtInput', test_psbt_func)

    def test_psbt_finalize(self):
        exec_test(self, 'Psbt.FinalizePsbt', test_psbt_func)

    def test_psbt_sign(self):
        exec_test(self, 'Psbt.SignPsbt', test_psbt_func)

    def test_psbt_verify(self):
        exec_test(self, 'Psbt.VerifyPsbtSign', test_verify_psbt_func)

    def test_psbt_add(self):
        exec_test(self, 'Psbt.AddPsbtData', test_psbt_func)

    def test_psbt_set_data(self):
        exec_test(self, 'Psbt.SetPsbtData', test_psbt_func)

    def test_psbt_set_record(self):
        exec_test(self, 'Psbt.SetPsbtRecord', test_psbt_func)

    def test_psbt_is_finalized(self):
        exec_test(self, 'Psbt.IsFinalizedPsbt', test_check_finalized_psbt_func)

    def test_psbt_get_utxos(self):
        exec_test(self, 'Psbt.GetPsbtUtxos', test_get_utxos_psbt_func)

    def test_psbt_fund(self):
        exec_test(self, 'Psbt.FundPsbt', test_psbt_func)
