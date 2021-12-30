import unittest
from helper import RpcWrapper, get_utxo
from cfd.address import AddressUtil
from cfd.key import SigHashType, Network, SchnorrPubkey, SchnorrUtil,\
    SignParameter
from cfd.block import Block
from cfd.hdwallet import HDWallet
from cfd.descriptor import parse_descriptor
from cfd.script import HashType, Script
from cfd.taproot import TapBranch, TaprootScriptTree
from cfd.transaction import Transaction, OutPoint
from cfd.confidential_address import ConfidentialAddress
from cfd.confidential_transaction import BlindFactor, ConfidentialTransaction,\
    ConfidentialTxIn, ConfidentialTxOut, ConfidentialValue, ElementsUtxoData,\
    TargetAmountData
from decimal import Decimal
import json
import logging
import time

MNEMONIC = [
    'clerk', 'zoo', 'mercy', 'board', 'grab', 'service', 'impact', 'tortoise',
    'step', 'crash', 'load', 'aerobic', 'suggest', 'rack', 'refuse', 'can',
    'solve', 'become', 'upset', 'jump', 'token', 'anchor', 'apart', 'dog']
PASSPHRASE = 'Unx3HmdQ'
NETWORK = 'elementsregtest'
MAINCHAIN_NETWORK = 'regtest'
ROOT_PATH = 'm/44h/0h/0h'
FEE_PATH = ROOT_PATH + '/1/0'
GEN_PATH = ROOT_PATH + '/1/1'
MULTISIG_CT_PATH_BASE = ROOT_PATH + '/0/100/'
BTC_AMOUNT = 100000000
BTC_AMOUNT_BIT = 8

WSH_OP_TRUE = \
    '00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260'
new_fedpeg_script = \
    '5121024241bff4d20f2e616bef2f6e5c25145c068d45a78da3ddba433b3101bbe9a37d51ae'  # noqa: E501
pak1 = \
  '02b6991705d4b343ba192c2d1b10e7b8785202f51679f26a1f2cdbe9c069f8dceb024fb0908ea9263bedb5327da23ff914ce1883f851337d71b3ca09b32701003d05'  # noqa: E501


def convert_elements_utxos(test_obj, utxo_list,
                           is_blind_only: bool = True,
                           ):
    # {'txid': 'b8e25f336229b447e02eb18cc3f1201979eaea7fd9299c167407c8b97454f849', 'vout': 0, 'address': 'ert1qyq7xhec45m75m5nvhzuh47vsj3as7tqflljjgr', 'label': 'test_fee', 'scriptPubKey': '0014203c6be715a6fd4dd26cb8b97af990947b0f2c09', 'amount': Decimal('248.99999710'), 'assetcommitment': '0a42101f526b26b4f74d26c5ce566d77d6159894a8b50214b82d2f838dd0a3a418', 'asset': '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225', 'amountcommitment': '0842192917a9b4adbd4e0d3ff7a71dc97004de57f94ef825b956e04531f6a87098', 'amountblinder': '2f79bce2b26efe065378cfb532907d77dfb426a90cf1181da597dc7ea05b303b', 'assetblinder': '0dfc94eb72987ee2781fa31b2881f132cce118b9005f3c1623224225b37c0eeb', 'confirmations': 111, 'spendable': False, 'solvable': False, 'safe': True}  # noqa8
    utxos = []
    for utxo in utxo_list:
        desc = test_obj.desc_dic[utxo['address']]
        value = Decimal(str(utxo['amount']))
        value = value * BTC_AMOUNT
        amount_commitment = utxo.get('amountcommitment', '')
        asset = utxo.get('asset', test_obj.pegged_asset)
        asset_commitment = utxo.get('assetcommitment', '')
        asset_blinder = utxo.get('assetblinder', '')
        amount_blinder = utxo.get('amountblinder', '')
        if is_blind_only and BlindFactor(amount_blinder).is_empty():
            continue
        data = ElementsUtxoData(
            txid=utxo['txid'], vout=utxo['vout'],
            amount=int(value), descriptor=desc,
            value=amount_commitment,
            asset=asset,
            asset_commitment=asset_commitment,
            asset_blinder=asset_blinder,
            amount_blinder=amount_blinder)
        utxos.append(data)
    return utxos


def search_utxos(test_obj, utxo_list, outpoint):
    for utxo in utxo_list:
        if utxo.outpoint == outpoint:
            return utxo
    test_obj.assertTrue(False, 'UTXO is empty. outpoint={}'.format(outpoint))


def generatetoaddress_dynafed(test_obj, count):
    for i in range(count):
        elm_rpc = test_obj.elmConn.get_rpc()
        # generate dynafed block
        block_data = elm_rpc.getnewblockhex(
            0,
            {
                "signblockscript": WSH_OP_TRUE,
                "max_block_witness": 500,
                "fedpegscript": new_fedpeg_script,
                "extension_space": [pak1],
            })
        elm_rpc.submitblock(block_data)


def create_bitcoin_address(test_obj):
    # fee address
    pk = str(test_obj.hdwallet.get_pubkey(path=FEE_PATH).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = FEE_PATH
    test_obj.addr_dic['fee'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set fee addr: ' + str(addr))
    path2 = FEE_PATH + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set fee ct_addr: ' + str(ct_addr))

    # gen address
    pk = str(test_obj.hdwallet.get_pubkey(path=GEN_PATH).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = FEE_PATH
    test_obj.addr_dic['gen'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set gen addr: ' + str(addr))
    path2 = GEN_PATH + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set gen ct_addr: ' + str(ct_addr))

    # wpkh main address
    path = '{}/0/0'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['main'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set main addr: ' + str(addr))
    path2 = path + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set main ct_addr: ' + str(ct_addr))

    # tr address with main
    main_spk, _ = SchnorrPubkey.from_pubkey(str(pk))
    mains_addr = AddressUtil.taproot(main_spk, network=NETWORK)
    test_obj.addr_dic['mains'] = mains_addr
    test_obj.desc_dic[str(mains_addr)] = parse_descriptor(
        'raw({})'.format(str(mains_addr.locking_script)), network=NETWORK)
    print('set mains addr: ' + str(mains_addr))
    ct_addr = ConfidentialAddress(mains_addr, sk.pubkey)
    test_obj.ct_addr_dic[str(mains_addr)] = ct_addr
    test_obj.blind_key_dic[str(mains_addr)] = sk
    print('set mains ct_addr: ' + str(ct_addr))

    # pkh address
    path = '{}/0/1'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2pkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2pkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'pkh({})'.format(str(pk)), network=NETWORK)
    print('set p2pkh addr: ' + str(addr))
    path2 = path + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2pkh ct_addr: ' + str(ct_addr))
    # wpkh address
    path = '{}/0/2'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2wpkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wpkh({})'.format(str(pk)), network=NETWORK)
    print('set p2wpkh addr: ' + str(addr))
    path2 = path + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2wpkh ct_addr: ' + str(ct_addr))
    # p2sh-p2wpkh address
    path = '{}/0/3'.format(ROOT_PATH)
    pk = str(test_obj.hdwallet.get_pubkey(path=path).pubkey)
    addr = AddressUtil.p2sh_p2wpkh(pk, network=NETWORK)
    test_obj.path_dic[str(addr)] = path
    test_obj.addr_dic['p2sh-p2wpkh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh(wpkh({}))'.format(str(pk)), network=NETWORK)
    print('set p2sh-p2wpkh addr: ' + str(addr))
    path2 = path + '/0'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2sh-p2wpkh ct_addr: ' + str(ct_addr))

    # multisig_key
    path = '{}/0/'.format(ROOT_PATH)
    path_list = [path + str(i + 1) for i in range(3)]
    pk1 = str(test_obj.hdwallet.get_pubkey(path=path_list[0]).pubkey)
    pk2 = str(test_obj.hdwallet.get_pubkey(path=path_list[1]).pubkey)
    pk3 = str(test_obj.hdwallet.get_pubkey(path=path_list[2]).pubkey)
    pk_list = [pk1, pk2, pk3]
    req_num = 2
    desc_multi = 'multi({},{},{},{})'.format(req_num, pk1, pk2, pk3)
    addr = AddressUtil.multisig(
        req_num, pk_list, HashType.P2SH, network=NETWORK)
    test_obj.path_dic[str(addr)] = path_list
    test_obj.addr_dic['p2sh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh({})'.format(desc_multi), network=NETWORK)
    print('set p2sh addr: ' + str(addr))
    path2 = MULTISIG_CT_PATH_BASE + '1'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2sh ct_addr: ' + str(ct_addr))
    addr = AddressUtil.multisig(
        req_num, pk_list, HashType.P2WSH, network=NETWORK)
    test_obj.path_dic[str(addr)] = path_list
    test_obj.addr_dic['p2wsh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'wsh({})'.format(desc_multi), network=NETWORK)
    print('set p2wsh addr: ' + str(addr))
    path2 = MULTISIG_CT_PATH_BASE + '2'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2wsh ct_addr: ' + str(ct_addr))
    addr = AddressUtil.multisig(
        req_num, pk_list, HashType.P2SH_P2WSH, network=NETWORK)
    test_obj.path_dic[str(addr)] = path_list
    test_obj.addr_dic['p2sh-p2wsh'] = addr
    test_obj.desc_dic[str(addr)] = parse_descriptor(
        'sh(wsh({}))'.format(desc_multi), network=NETWORK)
    print('set p2sh-p2wsh addr: ' + str(addr))
    path2 = MULTISIG_CT_PATH_BASE + '3'
    sk = test_obj.hdwallet.get_privkey(path=path2).privkey
    test_obj.blind_key_dic[str(addr)] = sk
    ct_addr = ConfidentialAddress(addr, sk.pubkey)
    test_obj.ct_addr_dic[str(addr)] = ct_addr
    print('set p2sh-p2wsh ct_addr: ' + str(ct_addr))

    # master blinding key
    path = '{}/0/1001'.format(ROOT_PATH)
    sk = str(test_obj.hdwallet.get_privkey(path=path).privkey)
    test_obj.master_blinding_key = sk
    print('set master blinding key: ' + sk)


def test_import_address(test_obj):
    btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()

    # get btc address from bitcoin-cli (for fee)
    btc_addr = btc_rpc.getnewaddress('', 'bech32')
    test_obj.addr_dic['btc'] = btc_addr

    # fee address
    addr = str(test_obj.addr_dic['fee'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_fee', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    # pkh address
    addr = str(test_obj.addr_dic['main'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_main', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2pkh'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_pkh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2wpkh'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_wpkh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2sh-p2wpkh'])
    elm_rpc.importaddress(
        str(test_obj.ct_addr_dic[addr]), 'test_sh_wpkh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    # multisig_key
    addr = str(test_obj.addr_dic['p2sh'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_sh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2wsh'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_wsh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    addr = str(test_obj.addr_dic['p2sh-p2wsh'])
    elm_rpc.importaddress(
        str(test_obj.ct_addr_dic[addr]), 'test_sh_wsh', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))
    # tr addr
    addr = str(test_obj.addr_dic['mains'])
    elm_rpc.importaddress(str(test_obj.ct_addr_dic[addr]), 'test_mains', False)
    elm_rpc.importblindingkey(
        str(test_obj.ct_addr_dic[addr]),
        str(test_obj.blind_key_dic[addr].hex))


def get_elements_config(test_obj):
    elm_rpc = test_obj.elmConn.get_rpc()
    # mainchain
    test_obj.sidechaininfo = elm_rpc.getsidechaininfo()
    test_obj.pegged_asset = test_obj.sidechaininfo['pegged_asset']
    test_obj.fedpegscript = test_obj.sidechaininfo['fedpegscript']
    test_obj.parent_blockhash = test_obj.sidechaininfo['parent_blockhash']
    test_obj.pegin_confirmation_depth =\
        test_obj.sidechaininfo['pegin_confirmation_depth']


def create_pegin_tx(test_obj, btc_tx: 'Transaction', pegin_address,
                    txout_proof, claim_script, is_blind: bool = True,
                    is_taproot: bool = False) -> str:
    btc_tx_obj = btc_tx
    btc_txid = btc_tx_obj.txid
    btc_txout_index = btc_tx_obj.get_txout_index(address=pegin_address)
    btc_amount = btc_tx_obj.txout_list[btc_txout_index].amount
    btc_size = len(str(btc_tx)) / 2
    txoutproof_size = len(str(txout_proof)) / 2

    # add txout
    tx = ConfidentialTransaction.create(2, 0)
    tx.add_pegin_input(outpoint=OutPoint(btc_txid, btc_txout_index),
                       amount=btc_amount,
                       asset=test_obj.pegged_asset,
                       mainchain_genesis_block_hash=test_obj.parent_blockhash,
                       claim_script=claim_script,
                       mainchain_tx=btc_tx,
                       txout_proof=txout_proof)
    fee_addr = test_obj.addr_dic['fee']
    main_addr = test_obj.addr_dic['main']
    if is_taproot:
        main_pk, _ = SchnorrPubkey.from_pubkey(str(main_addr.pubkey))
        main_addr = AddressUtil.taproot(main_pk, network=NETWORK)
    if is_blind:
        fee_addr = test_obj.ct_addr_dic[str(fee_addr)]
        main_addr = test_obj.ct_addr_dic[str(main_addr)]
    tx.add_txout(amount=1,
                 address=fee_addr,
                 asset=test_obj.pegged_asset)
    target_index = 0
    send2_amount = 1000
    if is_taproot:
        send2_amount = 1000000000
    tx.add_txout(amount=send2_amount,
                 address=main_addr,
                 asset=test_obj.pegged_asset)
    tx.add_fee_txout(amount=1, asset=test_obj.pegged_asset)

    # calc fee
    pegin_utxo = ElementsUtxoData(
        txid=btc_txid, vout=btc_txout_index,
        amount=btc_amount,
        descriptor='wpkh({})'.format('02' * 33),  # dummy
        asset=test_obj.pegged_asset,
        is_pegin=True, pegin_btc_tx_size=int(btc_size),
        pegin_txoutproof_size=int(txoutproof_size),
        claim_script=claim_script)
    utxo_list = [pegin_utxo]
    minimum_bits = 52
    calc_fee, _, _ = tx.estimate_fee(
        utxo_list, test_obj.pegged_asset, fee_rate=0.1,
        minimum_bits=minimum_bits)
    # update fee
    tx.update_txout_fee_amount(calc_fee)

    # change amount
    new_amount = btc_amount - calc_fee - send2_amount
    tx.update_txout_amount(target_index, new_amount)

    # blind
    if is_blind:
        print('before blind tx=', str(tx))
        tx.blind_txout(utxo_list, minimum_bits=minimum_bits)
    return str(tx)


def update_pegin_tx(test_obj, pegin_tx, btc_tx, pegin_address,
                    claim_script, txout_proof) -> str:
    pegin_tx2 = pegin_tx
    btc_tx_obj = Transaction.from_hex(btc_tx)
    btc_txid = btc_tx_obj.txid
    btc_txout_index = btc_tx_obj.get_txout_index(address=pegin_address)
    btc_amount = btc_tx_obj.txout_list[btc_txout_index].amount
    btc_size = len(btc_tx) / 2
    txoutproof_size = len(txout_proof) / 2

    # decode
    tx = ConfidentialTransaction.from_hex(pegin_tx)
    target_script_pubkey = ''
    target_amount = 0
    target_index = 0
    # fee_index = -1
    fee_amount = 0
    has_fee = len(tx.txout_list) == 2
    for index, txout in enumerate(tx.txout_list):
        if len(txout.locking_script.hex) > 0:
            target_script_pubkey = str(txout.locking_script)
            target_amount = txout.amount
            target_index = index
        else:
            fee_amount = txout.amount
            # fee_index = index
    # change script pubkey (string replace)
    target_script_pubkey = '16' + target_script_pubkey

    fee_addr = test_obj.addr_dic['fee']
    new_script_pubkey = '16' + str(fee_addr.locking_script)
    pegin_tx2 = pegin_tx.replace(target_script_pubkey, new_script_pubkey)
    tx = ConfidentialTransaction.from_hex(pegin_tx2)
    total_amount = target_amount + fee_amount
    utxo_amount = 0
    if has_fee:
        utxo_amount = total_amount - btc_amount

    # add txout
    tx.add_txout(amount=1,
                 address=test_obj.ct_addr_dic[str(test_obj.addr_dic['main'])],
                 asset=test_obj.pegged_asset)

    # calc fee
    pegin_utxo = ElementsUtxoData(
        txid=btc_txid, vout=btc_txout_index,
        amount=btc_amount,
        descriptor='wpkh({})'.format('02' * 33),  # dummy
        asset=test_obj.pegged_asset,
        is_pegin=True, pegin_btc_tx_size=int(btc_size),
        pegin_txoutproof_size=int(txoutproof_size),
        claim_script=claim_script)
    utxo_list = [pegin_utxo]
    if utxo_amount > 0:
        for txin in tx.txin_list:
            if txin.outpoint.txid != btc_txid:
                utxo = ElementsUtxoData(
                    outpoint=txin.outpoint, amount=utxo_amount,
                    descriptor='', asset=test_obj.pegged_asset)
                utxo_list.append(utxo)
                break
    calc_fee, _, _ = tx.estimate_fee(utxo_list, test_obj.pegged_asset)
    # update fee
    tx.update_txout_fee_amount(calc_fee)

    # change amount
    new_amount = total_amount - calc_fee - 1
    tx.update_txout_amount(target_index, new_amount)

    # blind
    fee_ct_addr = test_obj.ct_addr_dic[str(fee_addr)]
    print('before blind tx=', str(tx))
    tx.blind_txout(utxo_list,
                   confidential_address_list=[fee_ct_addr])
    return str(tx)


def test_generate_btc(test_obj):
    # generatetoaddress -> fee address
    print(test_obj.addr_dic)
    btc_rpc = test_obj.btcConn.get_rpc()

    addr = str(test_obj.addr_dic['btc'])
    btc_rpc.generatetoaddress(100, addr)
    btc_rpc.generatetoaddress(5, addr)
    time.sleep(2)
    resp = get_utxo(btc_rpc, [addr])
    print(resp)


def test_pegin(test_obj):
    btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()

    # generate pegin address
    path = '{}/0/0'.format(ROOT_PATH)
    main_ext_sk = test_obj.hdwallet.get_privkey(path=path)
    main_sk = str(main_ext_sk.privkey)
    main_pk = str(main_ext_sk.privkey.pubkey)
    main_addr = test_obj.addr_dic['main']
    pegin_address, claim_script, _ = AddressUtil.get_pegin_address(
        fedpeg_script=test_obj.fedpegscript,
        pubkey=main_pk,
        mainchain_network=Network.REGTEST,
        hash_type=HashType.P2SH_P2WSH)
    pegin_address = str(pegin_address)
    claim_script = claim_script.hex
    # pegin_addr_info = elm_rpc.getpeginaddress()
    # pegin_address = pegin_addr_info['mainchain_address']
    # claim_script = pegin_addr_info['claim_script']

    for i in range(3):
        try:
            blk_cnt = btc_rpc.getblockcount() + 1
            # send bitcoin
            utxos = get_utxo(btc_rpc, [])
            amount = 0
            for utxo in utxos:
                amount += utxo['amount']
            amount -= 1
            if amount > 100:
                amount = 100
            txid = btc_rpc.sendtoaddress(pegin_address, amount)

            # generate bitcoin 100 block
            addr = str(test_obj.addr_dic['btc'])
            btc_rpc.generatetoaddress(104, addr)
            max_blk_cnt = btc_rpc.getblockcount()
            # generatetoaddress -> gen address
            addr = str(test_obj.addr_dic['gen'])
            elm_rpc.generatetoaddress(2, addr)

            txout_proof = None
            for i in range(max_blk_cnt - blk_cnt):
                blk_hash = btc_rpc.getblockhash(blk_cnt + i)
                block_hex = btc_rpc.getblock(blk_hash, 0)
                block = Block(block_hex)
                if block.exist_txid(txid):
                    tx_data, txout_proof = block.get_tx_data(txid)
                    print(f'pegin block: {str(block)}')
                    break

            if txout_proof is None:
                raise Exception('txoutproof is empty.')

            # pegin transaction for fee address
            # tx_data = btc_rpc.gettransaction(txid)['hex']
            tx = Transaction(tx_data)
            vout = tx.get_txout_index(pegin_address)
            pegged_amount = tx.txout_list[vout].amount
            # txout_proof = btc_rpc.gettxoutproof([txid])
            # pegin_tx = elm_rpc.createrawpegin(
            #     tx_data, txout_proof, claim_script)['hex']
            # pegin_tx = update_pegin_tx(
            #     test_obj, pegin_tx, tx_data, pegin_address, txout_proof)
            pegin_tx = create_pegin_tx(test_obj, tx, pegin_address,
                                       txout_proof, claim_script)
            ct = ConfidentialTransaction(pegin_tx)
            ct.sign_with_privkey(
                OutPoint(txid, vout), HashType.P2WPKH, main_sk, pegged_amount)
            ct.verify_sign(outpoint=OutPoint(txid, vout),
                           address=main_addr,
                           hash_type=HashType.P2WPKH,
                           value=ConfidentialValue(pegged_amount))
            pegin_tx = str(ct)
            # broadcast
            print(ConfidentialTransaction.parse_to_json(
                pegin_tx, network=NETWORK))
            txid = elm_rpc.sendrawtransaction(pegin_tx)
            test_obj.tx_dic[txid] = pegin_tx
            # generatetoaddress -> gen address
            addr = str(test_obj.addr_dic['gen'])
            elm_rpc.generatetoaddress(2, addr)
            time.sleep(2)
        except Exception as err:
            print('Exception({})'.format(i))
            raise err

    # generatetoaddress -> gen address
    addr = str(test_obj.addr_dic['gen'])
    elm_rpc.generatetoaddress(100, addr)
    elm_rpc.generatetoaddress(5, addr)
    time.sleep(2)
    fee_addr = test_obj.addr_dic['fee']
    utxos = get_utxo(elm_rpc, [str(fee_addr)])
    # utxos = get_utxo(elm_rpc, [])
    print('UTXO: {}'.format(utxos))


def test_pegin_unblind_taproot(test_obj):
    btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()

    # generate pegin address
    path = '{}/0/0'.format(ROOT_PATH)
    main_ext_sk = test_obj.hdwallet.get_privkey(path=path)
    main_sk = str(main_ext_sk.privkey)
    main_pk = str(main_ext_sk.privkey.pubkey)
    main_addr = test_obj.addr_dic['main']
    pegin_address, claim_script, _ = AddressUtil.get_pegin_address(
        fedpeg_script=test_obj.fedpegscript,
        pubkey=main_pk,
        mainchain_network=Network.REGTEST,
        hash_type=HashType.P2SH_P2WSH)
    pegin_address = str(pegin_address)
    claim_script = claim_script.hex
    # pegin_addr_info = elm_rpc.getpeginaddress()
    # pegin_address = pegin_addr_info['mainchain_address']
    # claim_script = pegin_addr_info['claim_script']

    for i in range(3):
        try:
            blk_cnt = btc_rpc.getblockcount() + 1
            # send bitcoin
            utxos = get_utxo(btc_rpc, [])
            amount = 0
            for utxo in utxos:
                amount += utxo['amount']
            amount -= 1
            if amount > 100:
                amount = 100
            txid = btc_rpc.sendtoaddress(pegin_address, amount)

            # generate bitcoin 100 block
            addr = str(test_obj.addr_dic['btc'])
            btc_rpc.generatetoaddress(104, addr)
            max_blk_cnt = btc_rpc.getblockcount()
            # generatetoaddress -> gen address
            addr = str(test_obj.addr_dic['gen'])
            elm_rpc.generatetoaddress(2, addr)

            txout_proof = None
            for i in range(max_blk_cnt - blk_cnt):
                blk_hash = btc_rpc.getblockhash(blk_cnt + i)
                block_hex = btc_rpc.getblock(blk_hash, 0)
                block = Block(block_hex)
                if block.exist_txid(txid):
                    tx_data, txout_proof = block.get_tx_data(txid)
                    print(f'pegin block: {str(block)}')
                    break

            if txout_proof is None:
                raise Exception('txoutproof is empty.')

            # pegin transaction for fee address
            # tx_data = btc_rpc.gettransaction(txid)['hex']
            tx = Transaction(tx_data)
            vout = tx.get_txout_index(pegin_address)
            pegged_amount = tx.txout_list[vout].amount
            # txout_proof = btc_rpc.gettxoutproof([txid])
            # pegin_tx = elm_rpc.createrawpegin(
            #     tx_data, txout_proof, claim_script)['hex']
            # pegin_tx = update_pegin_tx(
            #     test_obj, pegin_tx, tx_data, pegin_address, txout_proof)
            pegin_tx = create_pegin_tx(test_obj, tx, pegin_address,
                                       txout_proof, claim_script,
                                       is_blind=False, is_taproot=True)
            ct = ConfidentialTransaction(pegin_tx)
            ct.sign_with_privkey(
                OutPoint(txid, vout), HashType.P2WPKH, main_sk, pegged_amount)
            ct.verify_sign(outpoint=OutPoint(txid, vout),
                           address=main_addr,
                           hash_type=HashType.P2WPKH,
                           value=ConfidentialValue(pegged_amount))
            pegin_tx = str(ct)
            # broadcast
            print(ConfidentialTransaction.parse_to_json(
                pegin_tx, network=NETWORK))
            txid = elm_rpc.sendrawtransaction(pegin_tx)
            test_obj.tx_dic[txid] = pegin_tx
            # generatetoaddress -> gen address
            addr = str(test_obj.addr_dic['gen'])
            elm_rpc.generatetoaddress(2, addr)
            time.sleep(2)
        except Exception as err:
            print('Exception({})'.format(i))
            raise err

    # generatetoaddress -> gen address
    addr = str(test_obj.addr_dic['gen'])
    elm_rpc.generatetoaddress(100, addr)
    elm_rpc.generatetoaddress(5, addr)
    time.sleep(2)
    fee_addr = test_obj.addr_dic['fee']
    utxos = get_utxo(elm_rpc, [str(fee_addr)])
    # utxos = get_utxo(elm_rpc, [])
    print('UTXO: {}'.format(utxos))


def test_elements_pkh(test_obj):
    # btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()
    # create tx (output wpkh, p2sh-segwit, pkh)
    txouts = [
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2pkh'])],
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2wpkh'])],
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2sh-p2wpkh'])],
            asset=test_obj.pegged_asset),
    ]
    tx = ConfidentialTransaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_ct_addr = test_obj.ct_addr_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=1,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx.fund_raw_transaction([], utxo_list,
                            target_list=target_list,
                            fee_asset=test_obj.pegged_asset,
                            effective_fee_rate=0.1,
                            knapsack_min_change=1)
    # blind
    blind_utxo_list = []
    for txin in tx.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, utxo_list, txin.outpoint))
    tx.blind_txout(blind_utxo_list)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             value=utxo.value,
                             sighashtype=SigHashType.ALL_PLUS_RANGEPROOF)
    print('after sign_with_privkey tx')
    print(str(tx))
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx), network=NETWORK))
    txid = elm_rpc.sendrawtransaction(str(tx))
    test_obj.tx_dic[txid] = tx
    # generate block
    elm_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # create tx (output wpkh only, input tx1-3)
    txid = tx.txid
    txin_list = []
    txin_utxo_list = []
    for index, txout in enumerate(tx.txout_list):
        if not txout.locking_script.hex:
            continue
        temp_addr = str(txout.get_address(network=NETWORK))
        if temp_addr == fee_addr:
            continue
        txin_list.append(ConfidentialTxIn(txid=txid, vout=index))
        if temp_addr not in test_obj.desc_dic:
            test_obj.assertTrue(False, 'addr not found. [{}]:[{}]'.format(
                index, temp_addr))
        desc = test_obj.desc_dic[temp_addr]
        blind_key = test_obj.blind_key_dic[temp_addr]
        unblind_data = tx.unblind_txout(index, blind_key)
        txin_utxo_list.append(ElementsUtxoData(
            txid=txid, vout=index,
            amount=unblind_data.value.amount,
            descriptor=desc,
            value=txout.value.hex,
            asset=test_obj.pegged_asset,
            asset_blinder=unblind_data.asset_blinder,
            amount_blinder=unblind_data.amount_blinder))
    txouts2 = [
        ConfidentialTxOut(
            300000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['main'])],
            asset=test_obj.pegged_asset),
    ]
    tx2 = ConfidentialTransaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=0,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list,
                             target_list=target_list,
                             fee_asset=test_obj.pegged_asset,
                             effective_fee_rate=0.1,
                             knapsack_min_change=1)
    # blind
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    blind_utxo_list = []
    for txin in tx2.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, join_utxo_list, txin.outpoint))
    tx2.blind_txout(blind_utxo_list)
    print('before sign_with_privkey')
    print(ConfidentialTransaction.parse_to_json(str(tx2), network=NETWORK))
    # add sign
    for txin in tx2.txin_list:
        utxo = search_utxos(test_obj, blind_utxo_list, txin.outpoint)
        path = test_obj.path_dic[str(utxo.descriptor.data.address)]
        sk = test_obj.hdwallet.get_privkey(path=path).privkey
        tx2.sign_with_privkey(txin.outpoint, utxo.descriptor.data.hash_type,
                              sk, value=utxo.value,
                              sighashtype=SigHashType.ALL_PLUS_RANGEPROOF)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx2), network=NETWORK))
    txid = elm_rpc.sendrawtransaction(str(tx2))
    test_obj.tx_dic[txid] = tx2
    # generate block
    elm_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)
    utxos = get_utxo(elm_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


def test_elements_multisig(test_obj):
    # btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()
    # create tx (output multisig)
    txouts = [
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2sh'])],
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2wsh'])],
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2sh-p2wsh'])],
            asset=test_obj.pegged_asset),
    ]
    tx = ConfidentialTransaction.create(2, 0, [], txouts)
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_ct_addr = test_obj.ct_addr_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=1,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx.fund_raw_transaction([], utxo_list,
                            fee_asset=test_obj.pegged_asset,
                            target_list=target_list,
                            effective_fee_rate=0.1,
                            knapsack_min_change=1)
    # blind
    blind_utxo_list = []
    for txin in tx.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, utxo_list, txin.outpoint))
    tx.blind_txout(blind_utxo_list)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             value=utxo.value,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx), network=NETWORK))
    elm_rpc.sendrawtransaction(str(tx))
    # generate block
    elm_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)

    # create tx (output wpkh only, input multisig tx1-3)
    txid = tx.txid
    txin_list = []
    txin_utxo_list = []
    for index, txout in enumerate(tx.txout_list):
        if not txout.locking_script.hex:
            continue
        temp_addr = str(txout.get_address(network=NETWORK))
        if temp_addr == fee_addr:
            continue
        txin_list.append(ConfidentialTxIn(txid=txid, vout=index))
        if temp_addr not in test_obj.desc_dic:
            test_obj.assertTrue(False, 'addr not found. [{}]:[{}]'.format(
                index, temp_addr))
        desc = test_obj.desc_dic[temp_addr]
        blind_key = test_obj.blind_key_dic[temp_addr]
        unblind_data = tx.unblind_txout(index, blind_key)
        txin_utxo_list.append(ElementsUtxoData(
            txid=txid, vout=index,
            amount=unblind_data.value.amount,
            descriptor=desc,
            value=txout.value.hex,
            asset=test_obj.pegged_asset,
            asset_blinder=unblind_data.asset_blinder,
            amount_blinder=unblind_data.amount_blinder))
    txouts2 = [
        ConfidentialTxOut(
            300000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['main'])],
            asset=test_obj.pegged_asset),
    ]
    tx2 = ConfidentialTransaction.create(2, 0, txin_list, txouts2)
    main_addr = test_obj.addr_dic['main']
    utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=0,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx2.fund_raw_transaction(txin_utxo_list, utxo_list,
                             fee_asset=test_obj.pegged_asset,
                             target_list=target_list,
                             effective_fee_rate=0.1,
                             knapsack_min_change=1)
    # blind
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    blind_utxo_list = []
    for txin in tx2.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, join_utxo_list, txin.outpoint))
    tx2.blind_txout(blind_utxo_list)

    def multisig_sign(tx_obj, utxo, path_list):
        sighash = tx_obj.get_sighash(
            outpoint=utxo.outpoint,
            hash_type=utxo.descriptor.data.hash_type,
            value=utxo.value,
            redeem_script=utxo.descriptor.data.redeem_script)
        signature_list = []
        for path in path_list:
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            sig = sk.calculate_ec_signature(sighash)
            sig.related_pubkey = sk.pubkey
            signature_list.append(sig)
            if len(signature_list) == 2:
                break
        tx_obj.add_multisig_sign(
            utxo.outpoint, utxo.descriptor.data.hash_type,
            utxo.descriptor.data.redeem_script, signature_list)

    # add sign
    join_utxo_list = []
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = utxo_list
    join_utxo_list[len(join_utxo_list):len(join_utxo_list)] = txin_utxo_list
    for index, txin in enumerate(tx2.txin_list):
        utxo = search_utxos(test_obj, join_utxo_list, txin.outpoint)
        if not utxo.descriptor.data.redeem_script:
            path = test_obj.path_dic[str(utxo.descriptor.data.address)]
            sk = test_obj.hdwallet.get_privkey(path=path).privkey
            tx2.sign_with_privkey(txin.outpoint,
                                  utxo.descriptor.data.hash_type,
                                  sk, value=utxo.value,
                                  sighashtype=SigHashType.ALL)
        else:
            path_list = test_obj.path_dic[str(utxo.descriptor.data.address)]
            multisig_sign(tx2, utxo, path_list)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx2), network=NETWORK))
    elm_rpc.sendrawtransaction(str(tx2))
    # generate block
    elm_rpc.generatetoaddress(2, fee_addr)
    time.sleep(2)
    utxos = get_utxo(elm_rpc, [str(main_addr)])
    print('UTXO: {}'.format(utxos))


def test_elements_dynafed(test_obj):
    btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()

    # generate block
    chaininfo = elm_rpc.getblockchaininfo()
    epoch_length = chaininfo['epoch_length']
    epoch_age = chaininfo['epoch_age']
    gen_num = epoch_length - epoch_age - 1
    addr = str(test_obj.addr_dic['gen'])
    elm_rpc.generatetoaddress(gen_num, addr)
    # generate dynafed block

    block_data = elm_rpc.getnewblockhex(
        0,
        {
            "signblockscript": WSH_OP_TRUE,
            "max_block_witness": 500,
            "fedpegscript": new_fedpeg_script,
            "extension_space": [pak1],
        })
    elm_rpc.submitblock(block_data)
    elm_rpc.getblockchaininfo()
    elm_rpc.getsidechaininfo()
    elm_rpc.getblock(chaininfo['bestblockhash'])
    generatetoaddress_dynafed(test_obj, epoch_length)
    time.sleep(2)
    chaininfo = elm_rpc.getblockchaininfo()
    sidechaininfo = elm_rpc.getsidechaininfo()

    # generate pegin address
    path = '{}/0/0'.format(ROOT_PATH)
    main_ext_sk = test_obj.hdwallet.get_privkey(path=path)
    main_sk = str(main_ext_sk.privkey)
    main_pk = str(main_ext_sk.privkey.pubkey)
    pegin_address, claim_script, tweaked = AddressUtil.get_pegin_address(
        fedpeg_script=new_fedpeg_script,
        pubkey=main_pk,
        mainchain_network=Network.REGTEST,
        hash_type=HashType.P2WSH)  # TODO: Dynafed mode (need p2wsh)
    pegin_address = str(pegin_address)
    claim_script = claim_script.hex
    print(f'pegin_address[{pegin_address}]')
    print(f'claim_script[{claim_script}]')
    print(f'tweaked_fedpeg_script[{tweaked}]')
    # pegin_addr_info = elm_rpc.getpeginaddress()
    # pegin_address = pegin_addr_info['mainchain_address']
    # claim_script = pegin_addr_info['claim_script']

    for i in range(3):
        try:
            blk_cnt = btc_rpc.getblockcount() + 1
            # send bitcoin
            utxos = get_utxo(btc_rpc, [])
            amount = 0
            for utxo in utxos:
                amount += utxo['amount']
            amount -= 1
            if amount > 100:
                amount = 100
            txid = btc_rpc.sendtoaddress(pegin_address, amount)

            # generate bitcoin 100 block
            addr = str(test_obj.addr_dic['btc'])
            btc_rpc.generatetoaddress(101, addr)
            max_blk_cnt = btc_rpc.getblockcount()

            txout_proof = None
            for i in range(max_blk_cnt - blk_cnt):
                blk_hash = btc_rpc.getblockhash(blk_cnt + i)
                block_hex = btc_rpc.getblock(blk_hash, 0)
                block = Block(block_hex)
                if block.exist_txid(txid):
                    tx_data, txout_proof = block.get_tx_data(txid)
                    print(f'pegin block: {str(block)}')
                    break

            if txout_proof is None:
                raise Exception('txoutproof is empty.')

            # pegin transaction for fee address
            # tx_data = btc_rpc.gettransaction(txid)['hex']
            tx = Transaction(tx_data)
            vout = tx.get_txout_index(pegin_address)
            pegged_amount = tx.txout_list[vout].amount
            # txout_proof = btc_rpc.gettxoutproof([txid])
            # pegin_tx = elm_rpc.createrawpegin(
            #     tx_data, txout_proof, claim_script)['hex']
            # pegin_tx = update_pegin_tx(
            #     test_obj, pegin_tx, tx_data, pegin_address, txout_proof)
            pegin_tx = create_pegin_tx(test_obj, tx, pegin_address,
                                       txout_proof, claim_script)
            ct = ConfidentialTransaction(pegin_tx)
            ct.sign_with_privkey(
                OutPoint(txid, vout), HashType.P2WPKH, main_sk, pegged_amount)
            pegin_tx = str(ct)
            # broadcast
            print(ConfidentialTransaction.parse_to_json(
                pegin_tx, network=NETWORK))
            txid = elm_rpc.sendrawtransaction(pegin_tx)
            test_obj.tx_dic[txid] = pegin_tx
            # generatetoaddress -> gen address
            addr = str(test_obj.addr_dic['gen'])
            # elm_rpc.generatetoaddress(2, addr)
            generatetoaddress_dynafed(test_obj, 2)
            time.sleep(2)
        except Exception as err:
            print('Exception({})'.format(i))
            raise err

    # generatetoaddress -> gen address
    addr = str(test_obj.addr_dic['gen'])
    # elm_rpc.generatetoaddress(100, addr)
    generatetoaddress_dynafed(test_obj, 100)
    # elm_rpc.generatetoaddress(5, addr)
    generatetoaddress_dynafed(test_obj, 5)
    time.sleep(2)
    fee_addr = test_obj.addr_dic['fee']
    utxos = get_utxo(elm_rpc, [str(fee_addr)])
    # utxos = get_utxo(elm_rpc, [])
    print('UTXO: {}'.format(utxos))

    # pegout
    pegout_amount = 1000000
    counter = 3
    mainchain_bip32 = 'tpubDDbMfNVnS7fmrTyv98A1bPydovdx2GhaxVAfvgPztEw3R3J2bZ7c2yy3oHx1D3ivjEH5tidRdA766QC83omWBtoUN7CBrk6vyogkTEPUb5b'  # noqa: E501
    pegout_descriptor = f'pkh({mainchain_bip32}/0/*)'
    online_key = 'cVSf1dmLm1XjafyXSXn955cyb2uabdtXxjBXx6fHMQLPQKzHCpT7'
    online_pubkey = \
        '024fb0908ea9263bedb5327da23ff914ce1883f851337d71b3ca09b32701003d05'
    whitelist = ''.join(chaininfo['extension_space'])
    txouts = [
        ConfidentialTxOut(
            100000000,
            test_obj.ct_addr_dic[str(test_obj.addr_dic['p2wsh'])],
            asset=test_obj.pegged_asset),
    ]
    tx = ConfidentialTransaction.create(2, 0, [], txouts)
    tx.add_pegout_output(
        asset=test_obj.pegged_asset,
        amount=pegout_amount,
        mainchain_network_type=Network.REGTEST,
        elements_network_type=Network.ELEMENTS_REGTEST,
        mainchain_genesis_block_hash=sidechaininfo['parent_blockhash'],
        online_pubkey=online_pubkey,
        master_online_key=online_key,
        mainchain_output_descriptor=pegout_descriptor,
        bip32_counter=counter,
        whitelist=whitelist,
    )
    # fundrawtransaction
    fee_addr = str(test_obj.addr_dic['fee'])
    fee_desc = test_obj.desc_dic[fee_addr]
    fee_ct_addr = test_obj.ct_addr_dic[fee_addr]
    fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey
    # utxos = get_utxo(elm_rpc, [fee_addr])
    utxo_list = convert_elements_utxos(test_obj, utxos)
    target_list = [TargetAmountData(
        amount=1,
        asset=test_obj.pegged_asset,
        reserved_address=fee_ct_addr)]
    tx.fund_raw_transaction([], utxo_list,
                            fee_asset=test_obj.pegged_asset,
                            target_list=target_list,
                            effective_fee_rate=0.1,
                            knapsack_min_change=1)
    # blind
    blind_utxo_list = []
    for txin in tx.txin_list:
        blind_utxo_list.append(search_utxos(
            test_obj, utxo_list, txin.outpoint))
    tx.blind_txout(blind_utxo_list)
    # add sign
    for txin in tx.txin_list:
        utxo = search_utxos(test_obj, utxo_list, txin.outpoint)
        tx.sign_with_privkey(txin.outpoint, fee_desc.data.hash_type, fee_sk,
                             value=utxo.value,
                             sighashtype=SigHashType.ALL)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx), network=NETWORK))
    elm_rpc.sendrawtransaction(str(tx))
    # generate block
    # elm_rpc.generatetoaddress(2, fee_addr)
    generatetoaddress_dynafed(test_obj, 2)
    time.sleep(2)


def search_vout(tx_hex, address) -> OutPoint:
    json_str = ConfidentialTransaction.parse_to_json(
        hex=tx_hex, network=NETWORK)
    tx = json.loads(json_str)
    for vout in tx['vout']:
        if ('scriptPubKey' in vout) and ('addresses' in vout['scriptPubKey']):
            addrs = vout['scriptPubKey']['addresses']
            if (len(addrs) == 1) and (addrs[0] == address):
                return OutPoint(tx['txid'], int(vout['n']))
    raise Exception('address not found.')


def test_elements_taproot(test_obj):
    # btc_rpc = test_obj.btcConn.get_rpc()
    elm_rpc = test_obj.elmConn.get_rpc()

    genesis_block_hash = elm_rpc.getblockhash(0)
    ConfidentialTransaction.set_default_genesis_block_hash(genesis_block_hash)

    main_addr = test_obj.addr_dic['main']
    main_pk, _ = SchnorrPubkey.from_pubkey(str(main_addr.pubkey))
    tr_addr1 = AddressUtil.taproot(main_pk, network=NETWORK)
    main_path = str(test_obj.path_dic[str(main_addr)])
    main_sk = test_obj.hdwallet.get_privkey(path=main_path).privkey

    desc1 = parse_descriptor(f'tr({str(main_pk)})', network=NETWORK)
    st1 = TapBranch.from_string(desc1.data.tree_string, network=NETWORK)
    tr_addr2 = desc1.data.address
    script2 = Script.from_asm([str(main_pk), 'OP_CHECKSIG'])
    st2 = TaprootScriptTree(script2, network=NETWORK)
    st2.internal_pubkey = main_pk
    tr_addr3 = AddressUtil.taproot(st2, network=NETWORK)
    print(str(st2))
    desc2 = parse_descriptor(
        f'tr({str(main_pk)},pk({str(main_pk)}))', network=NETWORK)
    if str(tr_addr3) != str(desc2.data.address):
        raise Exception(f'unmatch address: {tr_addr3}, {desc2.data.address}')

    # 1. unblind tx by taproot (sighash default)
    # collect pegin utxo
    utxos = get_utxo(elm_rpc, [str(tr_addr1)])
    utxo_list0 = convert_elements_utxos(test_obj, utxos, is_blind_only=False)
    txin_utxo_list = []
    txin_list = []
    total_amount = 0
    for utxo in utxo_list0:
        if not utxo.amount_blinder.is_empty():
            continue
        total_amount += utxo.amount if utxo.amount > 0 else utxo.value.amount
        txin_utxo_list.append(utxo)
        txin_list.append(ConfidentialTxIn(utxo.outpoint))
        if total_amount > 1000000000:
            break
    # fee_addr = str(test_obj.addr_dic['fee'])
    # fee_desc = test_obj.desc_dic[fee_addr]
    # fee_ct_addr = test_obj.ct_addr_dic[fee_addr]
    # fee_sk = test_obj.hdwallet.get_privkey(path=FEE_PATH).privkey

    # create tx (output wpkh only, input tx1-3)
    txout_list = [
        ConfidentialTxOut(
            total_amount-2000-400000000,
            main_addr,
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            200000000,
            tr_addr2,
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            200000000,
            tr_addr3,
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            2000,
            asset=test_obj.pegged_asset),
    ]
    tx = ConfidentialTransaction.create(2, 0, txin_list, txout_list)
    # add sign
    for utxo in txin_utxo_list:
        tx.sign_with_privkey(utxo.outpoint,
                             HashType.TAPROOT,
                             main_sk,
                             sighashtype=SigHashType.DEFAULT,
                             utxos=txin_utxo_list)
    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx), network=NETWORK))
    txid = elm_rpc.sendrawtransaction(str(tx))
    test_obj.tx_dic[txid] = tx
    # generate block
    generatetoaddress_dynafed(test_obj, 2)
    time.sleep(2)
    # utxos = get_utxo(elm_rpc, [str(main_addr)])
    # print('UTXO: {}'.format(utxos))

    # 2. unblind tx by tapscript (sighash default) => use descriptor
    txin_utxo_list2 = []
    txin_list2 = []
    txin_utxo_list2.append(ElementsUtxoData(
        outpoint=OutPoint(tx.txid, 1),
        descriptor=f'raw({desc1.data.locking_script})',
        amount=txout_list[1].amount,
        asset=txout_list[1].asset,
    ))
    txin_list2.append(ConfidentialTxIn(txin_utxo_list2[0].outpoint))

    txin_utxo_list2.append(ElementsUtxoData(
        outpoint=OutPoint(tx.txid, 2),
        descriptor=f'raw({desc2.data.locking_script})',
        amount=txout_list[2].amount,
        asset=txout_list[2].asset,
    ))
    txin_list2.append(ConfidentialTxIn(txin_utxo_list2[1].outpoint))
    total_amount = txout_list[1].amount+txout_list[2].amount
    txout_list2 = [
        ConfidentialTxOut(
            total_amount-2000,
            main_addr,
            asset=test_obj.pegged_asset),
        ConfidentialTxOut(
            2000,
            asset=test_obj.pegged_asset),
    ]
    tx2 = ConfidentialTransaction.create(2, 0, txin_list2, txout_list2)
    # add sign
    for index, utxo in enumerate(txin_utxo_list2):
        if index == 0:
            sk = st1.get_privkey(main_sk)
            tx2.sign_with_privkey(utxo.outpoint,
                                  HashType.TAPROOT,
                                  sk,
                                  sighashtype=SigHashType.DEFAULT,
                                  utxos=txin_utxo_list2)
        elif index == 1:
            print(f'{main_sk},{script2},{str(tx2)}')
            tree = TaprootScriptTree(
                Script(script2), network=Network.LIQUID_V1)
            sighash = tx2.get_sighash(
                utxo.outpoint, HashType.TAPROOT, redeem_script=script2,
                sighashtype=SigHashType.DEFAULT, utxos=txin_utxo_list2,
                tapleaf_hash=str(tree.hash))
            sig = SchnorrUtil.sign(sighash, main_sk)
            sign_param = SignParameter(sig, sighashtype=SigHashType.DEFAULT)
            _, _, _, control_block = st2.get_taproot_data()
            tx2.add_tapscript_sign(utxo.outpoint, [sign_param],
                                   script2, control_block)

    # broadcast
    print(ConfidentialTransaction.parse_to_json(str(tx2), network=NETWORK))
    txid = elm_rpc.sendrawtransaction(str(tx2))
    test_obj.tx_dic[txid] = tx2
    # generate block
    generatetoaddress_dynafed(test_obj, 2)
    time.sleep(2)

    # 3. blind tx by taproot (sighash default)
    # 4. blind tx by tapscript (sighash default) => use descriptor
    # 5. sighash ALL/Single/None
    # 6. issue/reissue, other asset


class TestElements(unittest.TestCase):
    def setUp(self):
        logging.basicConfig()
        logging.getLogger("BitcoinRPC").setLevel(logging.DEBUG)

        # FIXME get connection from config file.

        self.path_dic = {}
        self.addr_dic = {}
        self.desc_dic = {}
        self.master_blinding_key = ''
        self.ct_addr_dic = {}
        self.blind_key_dic = {}
        self.tx_dic = {}
        self.sidechaininfo = {}
        self.pegged_asset = ''
        self.fedpegscript = ''
        self.parent_blockhash = ''
        self.pegin_confirmation_depth = 0

        self.hdwallet = HDWallet.from_mnemonic(
            MNEMONIC, passphrase=PASSPHRASE, network=MAINCHAIN_NETWORK)
        create_bitcoin_address(self)
        self.btcConn = RpcWrapper(
            port=18443, rpc_user='bitcoinrpc', rpc_password='password')
        self.elmConn = RpcWrapper(
            port=18447, rpc_user='elementsrpc', rpc_password='password')
        # init command
        btc_rpc = self.btcConn.get_rpc()
        btc_rpc.settxfee(0.00001)

    def test_elements(self):
        '''
        To execute sequentially, define only one test
        and call the test function in it.
        '''
        get_elements_config(self)
        test_import_address(self)
        test_generate_btc(self)
        test_pegin(self)
        test_pegin_unblind_taproot(self)
        test_elements_pkh(self)
        test_elements_multisig(self)
        # issue on RPC
        # reissue
        # send multi asset
        # destroy amount
        test_elements_dynafed(self)
        test_elements_taproot(self)


if __name__ == "__main__":
    unittest.main()
