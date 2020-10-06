# -*- coding: utf-8 -*-
##
# @file confidential_transaction.py
# @brief elements confidential transaction function implements file.
# @note Copyright 2020 CryptoGarage
from .util import ReverseByteData, CfdError, JobHandle,\
    CfdErrorCode, to_hex_string, get_util
from .key import Network, SigHashType
from .script import HashType
from .transaction import UtxoData, OutPoint, Txid, TxIn, TxOut, _FundTxOpt
from enum import Enum


class BlindFactor(ReverseByteData):
    def __init__(self, data):
        super().__init__(data)
        if len(self.hex) != 64:
            raise CfdError(
                error_code=1, message='Error: Invalid blind factor.')


class ConfidentialNonce:
    def __init__(self, data=''):
        self.hex = to_hex_string(data)
        if len(self.hex) not in {0, 66}:
            raise CfdError(
                error_code=1, message='Error: Invalid nonce.')

    ##
    # @brief get string.
    # @return hex.
    def __repr__(self):
        return self.hex


class ConfidentialAsset:
    def __init__(self, data):
        self.hex = to_hex_string(data)
        if len(self.hex) == 64:
            self.hex = str(ReverseByteData(data))
        if len(self.hex) not in {0, 64, 66}:
            raise CfdError(
                error_code=1, message='Error: Invalid asset.')

    ##
    # @brief get string.
    # @return hex.
    def __repr__(self):
        return self.hex

    def has_blind(self):
        if (len(self.hex) == 66) and (self.hex[0] == '0') and (
                self.hex[1].lower() in {'a', 'b'}):
            return True
        return False

    def get_commitment(self, asset_blind_factor):
        if self.has_blind():
            raise CfdError(
                error_code=1, message='Error: Blind asset.')
        util = get_util()
        with util.create_handle() as handle:
            commitment = util.call_func(
                'CfdGetAssetCommitment', handle.get_handle(),
                self.hex, to_hex_string(asset_blind_factor))
            return ConfidentialAsset(commitment)


class ConfidentialValue:
    def create(cls, value, amount):
        _value_hex = to_hex_string(value)
        if isinstance(value, ConfidentialValue):
            return value
        elif len(_value_hex) != 0:
            return ConfidentialValue(to_hex_string(value))
        else:
            return ConfidentialValue(amount)

    def _byte_from_amount(cls, amount):
        util = get_util()
        with util.create_handle() as handle:
            value_hex = util.call_func(
                'CfdGetConfidentialValueHex', handle.get_handle(),
                amount, False)
            return value_hex

    def __init__(self, data):
        if isinstance(data, int):
            self.amount = data
            self.hex = self._byte_from_amount(self.amount)
        else:
            self.hex = to_hex_string(data)
            self.amount = 0
        if len(self.hex) not in {0, 18, 66}:
            raise CfdError(
                error_code=1, message='Error: Invalid value.')

    ##
    # @brief get string.
    # @return hex or amount.
    def __repr__(self):
        return self.hex

    def has_blind(self):
        return (len(self.hex) == 66)

    def get_commitment(self, asset_commitment, blind_factor):
        if self.has_blind():
            raise CfdError(
                error_code=1, message='Error: Blind value.')
        if isinstance(asset_commitment, ConfidentialAsset) and (
                asset_commitment.has_blind() is False):
            raise CfdError(
                error_code=1, message='Error: Unblind asset.')
        util = get_util()
        with util.create_handle() as handle:
            commitment = util.call_func(
                'CfdGetValueCommitment', handle.get_handle(),
                self.amount, to_hex_string(asset_commitment),
                to_hex_string(blind_factor))
            return ConfidentialAsset(commitment)


class ElementsUtxoData(UtxoData):
    def __init__(
            self, outpoint=None, txid='', vout=0,
            amount=0, descriptor='', scriptsig_template='',
            value='', asset='', is_issuance=False, is_blind_issuance=False,
            is_pegin=False, pegin_btc_tx_size=0, fedpeg_script='',
            asset_blinder='', amount_blinder=''):
        super().__init__(
            outpoint=outpoint, txid=txid, vout=vout,
            amount=amount, descriptor=descriptor,
            scriptsig_template=scriptsig_template)
        self.value = ConfidentialValue.create(value, amount)
        self.asset = asset
        self.is_issuance = is_issuance
        self.is_blind_issuance = is_blind_issuance
        self.is_pegin = is_pegin
        self.pegin_btc_tx_size = pegin_btc_tx_size
        self.fedpeg_script = fedpeg_script
        self.asset_blinder = asset_blinder
        self.amount_blinder = amount_blinder


class UnblindData:
    def __init__(self, asset, amount, asset_blinder, amount_blinder):
        self.asset = asset
        self.value = ConfidentialValue(amount)
        self.asset_blinder = BlindFactor(asset_blinder)
        self.amount_blinder = BlindFactor(amount_blinder)


class Issuance:
    def __init__(self):
        self.entropy = ''
        self.nonce = ''
        self.asset_value = ConfidentialValue(0)
        self.token_value = ConfidentialValue(0)


class IssuanceKeyPair:
    def __init__(self, asset_key='', token_key=''):
        self.asset_key = asset_key
        self.token_key = token_key


class ConfidentialTxIn(TxIn):
    def __init__(self, outpoint=None, txid='', vout=0, sequence=0xffffffff):
        super().__init__(outpoint, txid, vout, sequence)
        self.pegin_witness_stack = []


class ConfidentialTxOut(TxOut):
    def __init__(
            self, amount=0, address='', locking_script='',
            value='', asset='', nonce=''):
        super().__init__(
            amount=amount, address=address, locking_script=locking_script)
        self.value = ConfidentialValue.create(value, amount)
        self.asset = ConfidentialAsset(asset)
        self.nonce = ConfidentialNonce(nonce)
        self.surjectionproof = []
        self.rangeproof = []
        self.issuance = Issuance()


class TargetAmountData:
    def __init__(self, amount, asset, reserved_address=''):
        self.amount = amount
        self.asset = asset
        self.reserved_address = reserved_address


class ConfidentialTransaction:
    ##
    # bitcoin network value.
    NETWORK = Network.LIQUID_V1.value
    ##
    # blind minimumBits on default.
    DEFAULT_BLIND_MINIMUM_BITS = 52
    ##
    # transaction's free function name.
    FREE_FUNC_NAME = 'CfdFreeTransactionHandle'

    @classmethod
    def parse_to_json(cls, hex, network=Network.LIQUID_V1):
        mainchain_str = 'mainnet'
        network_str = 'liquidv1'
        if network != Network.LIQUID_V1:
            mainchain_str = 'regtest'
            network_str = 'elementsregtest'
        cmd = '{{"hex":"{}","network":"{}","mainchainNetwork":"{}"}}'
        request_json = cmd.format(
            hex, network_str, mainchain_str)
        util = get_util()
        with util.create_handle() as handle:
            return util.call_func(
                'CfdRequestExecuteJson', handle.get_handle(),
                'ElementsDecodeRawTransaction', request_json)

    def __init__(self, hex, enable_cache=True):
        super().__init__(hex, self.NETWORK, enable_cache)
        self.txin_list = []
        self.txout_list = []
        self._update_tx_all()

    def _get_txin(self, handle, tx_handle, index=0, outpoint=None):
        util = get_util()

        if isinstance(outpoint, OutPoint):
            index = util.call_func(
                'CfdGetTxInIndexByHandle', handle.get_handle(),
                tx_handle.get_handle(), str(outpoint.txid),
                outpoint.vout)

        txid, vout, seq, script = util.call_func(
            'CfdGetTxInByHandle', handle.get_handle(),
            tx_handle.get_handle(), index)
        txin = ConfidentialTxIn(txid=txid, vout=vout, sequence=seq)
        txin.script_sig = script

        txin.witness_stack = []
        _count = util.call_func(
            'CfdGetTxInWitnessCountByHandle', handle.get_handle(),
            tx_handle.get_handle(), 0, index)
        for i in range(_count):
            data = util.call_func(
                'CfdGetTxInWitnessByHandle', handle.get_handle(),
                tx_handle.get_handle(), 0, index, i)
            txin.witness_stack.append(data)

        entropy, nonce, asset_amount, asset_value, token_amount,\
            toke_value, _ = util.call_func(
                'CfdGetTxInIssuanceInfoByHandle',
                handle.get_handle(), tx_handle.get_handle(), index)
        txin.issuance.entropy = entropy
        txin.issuance.nonce = nonce
        txin.issuance.asset_value = ConfidentialValue.create(
            asset_value, asset_amount)
        txin.issuance.token_value = ConfidentialValue.create(
            toke_value, token_amount)

        txin.pegin_witness_stack = []
        _count = util.call_func(
            'CfdGetTxInWitnessCountByHandle', handle.get_handle(),
            tx_handle.get_handle(), 1, index)
        for i in range(_count):
            data = util.call_func(
                'CfdGetTxInWitnessByHandle', handle.get_handle(),
                tx_handle.get_handle(), 1, index, i)
            txin.pegin_witness_stack.append(data)
        return txin, index

    def _update_info(self):
        if self.enable_cache is False:
            return
        util = get_util()
        with util.create_handle() as handle:
            self.txid, self.wtxid, self.wit_hash, self.size, self.vsize,\
                self.weight, self.version, self.locktime = util.call_func(
                    'CfdGetConfidentialTxInfo', handle.get_handle(),
                    self.NETWORK, self.hex)
            self.txid = Txid(self.txid)
            self.wtxid = Txid(self.wtxid)

    def _update_txin(self, outpoint):
        if self.enable_cache is False:
            return
        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTxDataHandle', handle.get_handle(),
                self.NETWORK, self.hex)
            with JobHandle(handle, _tx_handle,
                           self.FREE_FUNC_NAME) as tx_handle:
                self.txid, self.wtxid, self.wit_hash, self.size, self.vsize,\
                    self.weight, self.version, self.locktime = util.call_func(
                        'CfdGetConfidentialTxInfoByHandle',
                        handle.get_handle(), tx_handle.get_handle())
                self.txid = Txid(self.txid)
                self.wtxid = Txid(self.wtxid)
                # update txin
                txin, index = self._get_txin(
                    handle, tx_handle, outpoint=outpoint)
                self.txin_list[index] = txin

    @classmethod
    def create(cls, version, locktime, txins, txouts):
        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTransaction', handle.get_handle(),
                cls.NETWORK, version, locktime, '')
            with JobHandle(
                    handle, _tx_handle, cls.FREE_FUNC_NAME) as tx_handle:
                for txin in txins:
                    util.call_func(
                        'CfdAddTransactionInput', handle.get_handle(),
                        tx_handle.get_handle(), str(txin.outpoint.txid),
                        txin.outpoint.vout, txin.sequence)
                for txout in txouts:
                    util.call_func(
                        'CfdAddConfidentialTxOutput', handle.get_handle(),
                        tx_handle.get_handle(), txout.amount,
                        str(txout.address),
                        str(txout.locking_script),
                        str(txout.asset), str(txout.nonce))
                hex = util.call_func(
                    'CfdFinalizeTransaction', handle.get_handle(),
                    tx_handle.get_handle())
        return ConfidentialTransaction(hex)

    def get_tx_all(self):
        def get_txin_list(handle, tx_handle):
            txin_list = []
            _count = util.call_func(
                'CfdGetTxInCountByHandle', handle.get_handle(),
                tx_handle.get_handle())
            for i in range(_count):
                txin = self._get_txin(handle, tx_handle, i)
                txin_list.append(txin)
            return txin_list

        def get_txout_list(handle, tx_handle):
            txout_list = []
            _count = util.call_func(
                'CfdGetTxOutCountByHandle', handle.get_handle(),
                tx_handle.get_handle())
            for i in range(_count):
                # CfdGetConfidentialTxOutByHandle
                asset, amount, value_commitment, nonce,\
                    script = util.call_func(
                        'CfdGetConfidentialTxOutSimpleByHandle',
                        handle.get_handle(), tx_handle.get_handle(), i)
                txout = ConfidentialTxOut(
                    amount=amount, locking_script=script,
                    asset=asset, value=value_commitment, nonce=nonce)
                txout_list.append(txout)
            return txout_list

        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTxDataHandle', handle.get_handle(),
                self.NETWORK, self.hex)
            with JobHandle(
                    handle, _tx_handle,
                    self.FREE_FUNC_NAME) as tx_handle:
                self.txid, self.wtxid, self.wit_hash, self.size, self.vsize,\
                    self.weight, self.version, self.locktime = util.call_func(
                        'CfdGetConfidentialTxInfoByHandle',
                        handle.get_handle(), tx_handle.get_handle())
                self.txid = Txid(self.txid)
                self.wtxid = Txid(self.wtxid)
                self.txin_list = get_txin_list(handle, tx_handle)
                self.txout_list = get_txout_list(handle, tx_handle)
                return self.txin_list, self.txout_list

    def add_txin(self, outpoint=None, sequence=0xffffffff, txid='', vout=0):
        txin = ConfidentialTxIn(
            outpoint=outpoint, sequence=sequence,
            txid=txid, vout=vout)
        self.update([txin], [])

    def add_txout(
            self, amount, address='', locking_script='',
            value='', asset='', nonce=''):
        txout = ConfidentialTxOut(
            amount, address, locking_script, value, asset, nonce)
        self.update([], [txout])

    def add_fee_txout(self, amount, asset):
        self.add_txout(amount, asset=asset)

    def add_destroy_amount_txout(self, amount, asset):
        self.add_txout(amount, locking_script='6a', asset=asset)

    def update(self, txins, txouts):
        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTransaction', handle.get_handle(),
                self.NETWORK, 0, 0, self.hex)
            with JobHandle(
                    handle, _tx_handle, self.FREE_FUNC_NAME) as tx_handle:
                for txin in txins:
                    util.call_func(
                        'CfdAddTransactionInput', handle.get_handle(),
                        tx_handle.get_handle(), str(txin.outpoint.txid),
                        txin.outpoint.vout, txin.sequence)
                for txout in txouts:
                    util.call_func(
                        'CfdAddConfidentialTxOutput',
                        handle.get_handle(),
                        tx_handle.get_handle(), txout.amount,
                        str(txout.address),
                        str(txout.locking_script),
                        str(txout.asset), str(txout.nonce))
                self.hex = util.call_func(
                    'CfdFinalizeTransaction', handle.get_handle(),
                    tx_handle.get_handle())
                self.txid, self.wtxid, self.wit_hash, self.size, self.vsize,\
                    self.weight, self.version, self.locktime = util.call_func(
                        'CfdGetConfidentialTxInfoByHandle',
                        handle.get_handle(), tx_handle.get_handle())
                self.txid = Txid(self.txid)
                self.wtxid = Txid(self.wtxid)
                self.txin_list += txins
                self.txout_list += txouts

    def update_txout_amount(self, index, amount):
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdUpdateTxOutAmount', handle.get_handle(),
                self.NETWORK, self.hex, index, amount)
            self._update_info()
            self.txout_list[index].amount = amount

    def update_txout_fee_amount(self, amount):
        index = self.get_txout_index()
        self.update_txout_amount(index, amount)

    def blind_txout(self, utxo_list, confidential_address_list=[],
                    direct_confidential_key_map={},
                    minimum_range_value=1, exponent=0, minimum_bits=-1):
        self.blind(utxo_list=utxo_list,
                   confidential_address_list=confidential_address_list,
                   direct_confidential_key_map=direct_confidential_key_map,
                   minimum_range_value=minimum_range_value,
                   exponent=exponent, minimum_bits=minimum_bits)

    def blind(self, utxo_list,
              issuance_key_map={},
              confidential_address_list=[],
              direct_confidential_key_map={},
              minimum_range_value=1, exponent=0, minimum_bits=-1):
        if minimum_bits == -1:
            minimum_bits = self.DEFAULT_BLIND_MINIMUM_BITS

        def set_opt(handle, tx_handle, key, i_val=0):
            util.call_func(
                'CfdSetBlindTxOption', handle.get_handle(),
                tx_handle.get_handle(), key, i_val)

        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeBlindTx', handle.get_handle())
            with JobHandle(
                    handle, _tx_handle, 'CfdFreeBlindHandle') as tx_handle:
                for txin in utxo_list:
                    asset_key, token_key = '', ''
                    if str(txin.outpoint) in issuance_key_map:
                        item = issuance_key_map[str(txin.outpoint)]
                        asset_key, token_key = item.asset_key, item.token_key
                    util.call_func(
                        'CfdAddBlindTxInData', handle.get_handle(),
                        tx_handle.get_handle(),
                        to_hex_string(txin.outpoint.txid),
                        txin.outpoint.vout, to_hex_string(txin.asset),
                        to_hex_string(txin.asset_blinder),
                        to_hex_string(txin.amount_blinder),
                        asset_key, token_key)
                for addr in confidential_address_list:
                    util.call_func(
                        'CfdAddBlindTxOutByAddress', handle.get_handle(),
                        tx_handle.get_handle(), str(addr))
                for key_index in direct_confidential_key_map.keys():
                    key = direct_confidential_key_map[key_index]
                    util.call_func(
                        'CfdAddBlindTxOutData', handle.get_handle(),
                        tx_handle.get_handle(), int(key_index),
                        to_hex_string(key))
                set_opt(handle, tx_handle,
                        _BlindOpt.MINIMUM_RANGE_VALUE, minimum_range_value)
                set_opt(handle, tx_handle, _BlindOpt.EXPONENT, exponent)
                set_opt(handle, tx_handle,
                        _BlindOpt.MINIMUM_BITS, minimum_bits)
                self.hex = util.call_func(
                    'CfdFinalizeBlindTx', handle.get_handle(),
                    tx_handle.get_handle(), self.hex)
                self._update_tx_all()

    def unblind_txout(self, index, blinding_key):
        util = get_util()
        with util.create_handle() as handle:
            asset, asset_amount, asset_blinder,\
                amount_blinder = util.call_func(
                    'CfdUnblindTxOut', handle.get_handle(),
                    self.hex, index, to_hex_string(blinding_key))
            return UnblindData(
                asset, asset_amount, asset_blinder, amount_blinder)

    def unblind_issuance(self, asset_key, token_key):
        util = get_util()
        with util.create_handle() as handle:
            asset, asset_amount, asset_blinder, amount_blinder, token,\
                token_amount, token_blinder,\
                token_amount_blinder = util.call_func(
                    'CfdUnblindIssuance', handle.get_handle(),
                    self.hex, to_hex_string(asset_key),
                    to_hex_string(token_key))
            asset_data = UnblindData(
                asset, asset_amount, asset_blinder, amount_blinder)
            token_data = UnblindData(
                token, token_amount, token_blinder, token_amount_blinder)
            return asset_data, token_data

    def set_raw_reissue_asset(self, utxo, amount, address, entropy):
        _amount = amount
        if isinstance(amount, ConfidentialValue):
            _amount = amount.amount
        util = get_util()
        with util.create_handle() as handle:
            _asset, self.hex = util.call_func(
                'CfdSetRawReissueAsset', handle.get_handle(),
                self.hex, to_hex_string(utxo.outpoint.txid),
                utxo.outpoint.vout, _amount,
                to_hex_string(utxo.asset_blinder),
                to_hex_string(entropy), str(address), '')
            return ConfidentialAsset(_asset)

    def get_sighash(self, outpoint, hash_type, value, pubkey='',
                    redeem_script='', sighashtype=SigHashType.ALL):
        _hash_type = HashType.get(hash_type)
        _pubkey = to_hex_string(pubkey)
        _script = to_hex_string(redeem_script)
        _sighashtype = SigHashType.get(sighashtype)
        _value = value
        if isinstance(value, ConfidentialValue) is False:
            _value = ConfidentialValue(value)
        util = get_util()
        with util.create_handle() as handle:
            sighash = util.call_func(
                'CfdCreateConfidentialSighash', handle.get_handle(),
                self.hex, str(outpoint.txid), outpoint.vout,
                _hash_type.value, _pubkey, _script,
                _value.amount, _value.hex, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay())
            return sighash

    def sign_with_privkey(
            self, outpoint, hash_type, privkey, value,
            sighashtype=SigHashType.ALL, grind_r=True):
        _hash_type = HashType.get(hash_type)
        _privkey = privkey
        _pubkey = _privkey.get_pubkey()
        _sighashtype = SigHashType.get(sighashtype)
        _value = value
        if isinstance(value, ConfidentialValue) is False:
            _value = ConfidentialValue(value)
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddConfidentialTxSignWithPrivkeySimple',
                handle.get_handle(), self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, str(_pubkey),
                str(_privkey), _value.amount, _value.hex,
                _sighashtype.get_type(),
                _sighashtype.anyone_can_pay(), grind_r)
            self._update_txin(outpoint)

    def verify_sign(self, outpoint, address, hash_type, value):
        _hash_type = HashType.get(hash_type)
        _value = value
        if isinstance(value, ConfidentialValue) is False:
            _value = ConfidentialValue(value)
        util = get_util()
        with util.create_handle() as handle:
            util.call_func(
                'CfdVerifyTxSign', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, str(address), _hash_type.value,
                '', _value.amount, _value.hex)

    def verify_signature(
            self, outpoint, address, hash_type, value,
            direct_locking_script=''):
        if direct_locking_script != '':
            _script = to_hex_string(direct_locking_script)
            _addr = ''
        else:
            _addr, _script = address, ''
        _hash_type = HashType.get(hash_type)
        _value = value
        if isinstance(value, ConfidentialValue) is False:
            _value = ConfidentialValue(value)
        try:
            util = get_util()
            with util.create_handle() as handle:
                util.call_func(
                    'CfdVerifySignature', handle.get_handle(),
                    self.NETWORK, self.hex, str(outpoint.txid),
                    outpoint.vout, str(_addr), _hash_type.value,
                    _script, _value.amount, _value.hex)
                return True
        except CfdError as err:
            if err.error_code == CfdErrorCode.SIGN_VERIFICATION.value:
                return False
            else:
                raise err

    @classmethod
    def select_coins(
            cls, utxo_list, tx_fee_amount, target_list,
            effective_fee_rate=0.11, long_term_fee_rate=0.11,
            dust_fee_rate=3.0, knapsack_min_change=-1, is_blind=True,
            exponent=1, minimum_bits=52):
        if (isinstance(utxo_list, list) is False) or (
                len(utxo_list) == 0):
            raise CfdError(error_code=1, message='Error: Invalid utxo_list.')
        util = get_util()

        def set_opt(handle, tx_handle, key, i_val=0, f_val=0, b_val=False):
            util.call_func(
                'CfdSetOptionCoinSelection', handle.get_handle(),
                tx_handle.get_handle(), key, i_val, f_val, b_val)

        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeCoinSelection', handle.get_handle(),
                len(utxo_list), 1, '', tx_fee_amount, effective_fee_rate,
                long_term_fee_rate, dust_fee_rate, knapsack_min_change)
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeCoinSelectionHandle') as tx_handle:
                for index, utxo in enumerate(utxo_list):
                    util.call_func(
                        'CfdAddCoinSelectionUtxoTemplate',
                        handle.get_handle(), tx_handle.get_handle(), index,
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount,
                        str(utxo.asset),
                        str(utxo.descriptor),
                        to_hex_string(utxo.scriptsig_template))
                for index, target in enumerate(target_list):
                    util.call_func(
                        'CfdAddCoinSelectionAmount',
                        handle.get_handle(), tx_handle.get_handle(), index,
                        target.amount, str(target.asset))

                set_opt(handle, tx_handle, _CoinSelectionOpt.EXPONENT,
                        i_val=exponent)
                set_opt(handle, tx_handle, _CoinSelectionOpt.MINIMUM_BITS,
                        i_val=minimum_bits)

                _utxo_fee = util.call_func(
                    'CfdFinalizeCoinSelection',
                    handle.get_handle(), tx_handle.get_handle())

                selected_utxo_list = []
                for i in range(len(utxo_list)):
                    _utxo_index = util.call_func(
                        'CfdGetSelectedCoinIndex',
                        handle.get_handle(), tx_handle.get_handle(), i)
                    if _utxo_index < 0:
                        break
                    elif _utxo_index < len(utxo_list):
                        selected_utxo_list.append(utxo_list[_utxo_index])

                total_amount_list = []
                for index, target in enumerate(target_list):
                    total_amount = util.call_func(
                        'CfdGetSelectedCoinAssetAmount',
                        handle.get_handle(), tx_handle.get_handle(), index)
                    total_amount_list[target.asset] = total_amount
                return selected_utxo_list, _utxo_fee, total_amount_list

    def estimate_fee(self, utxo_list, fee_asset, fee_rate=0.11,
                     is_blind=True, exponent=1, minimum_bits=52):
        _fee_asset = ConfidentialAsset(fee_asset)
        if (isinstance(utxo_list, list) is False) or (
                len(utxo_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid utxo_list.')
        util = get_util()

        def set_opt(handle, tx_handle, key, i_val=0, f_val=0, b_val=False):
            util.call_func(
                'CfdSetOptionEstimateFee', handle.get_handle(),
                tx_handle.get_handle(), key, i_val, f_val, b_val)

        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeEstimateFee', handle.get_handle(), True)
            with JobHandle(handle, word_handle,
                           'CfdFreeEstimateFeeHandle') as tx_handle:
                for utxo in utxo_list:
                    util.call_func(
                        'CfdAddTxInTemplateForEstimateFee',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        str(utxo.descriptor), str(utxo.asset),
                        utxo.is_issuance, utxo.is_blind_issuance,
                        utxo.is_pegin, utxo.pegin_btc_tx_size,
                        to_hex_string(utxo.fedpeg_script),
                        to_hex_string(utxo.scriptsig_template))

                set_opt(handle, tx_handle, _FeeOpt.EXPONENT, i_val=exponent)
                set_opt(handle, tx_handle, _FeeOpt.MINIMUM_BITS,
                        i_val=minimum_bits)

                _txout_fee, _utxo_fee = util.call_func(
                    'CfdFinalizeEstimateFee',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.hex, str(_fee_asset), is_blind, fee_rate)
                return (_txout_fee + _utxo_fee), _txout_fee, _utxo_fee

    def fund_raw_transaction(
            self, txin_utxo_list, utxo_list, target_list,
            effective_fee_rate=0.11,
            long_term_fee_rate=-1.0, dust_fee_rate=-1.0,
            knapsack_min_change=-1, is_blind=True,
            exponent=0, minimum_bits=52):
        util = get_util()

        def set_opt(handle, tx_handle, key, i_val=0, f_val=0, b_val=False):
            util.call_func(
                'CfdSetOptionFundRawTx', handle.get_handle(),
                tx_handle.get_handle(), key, i_val, f_val, b_val)

        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeFundRawTx', handle.get_handle(),
                self.NETWORK, 1, '')
            with JobHandle(handle, word_handle,
                           'CfdFreeFundRawTxHandle') as tx_handle:
                for utxo in txin_utxo_list:
                    util.call_func(
                        'CfdAddTxInTemplateForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, str(utxo.descriptor),
                        str(utxo.asset),
                        utxo.is_issuance, utxo.is_blind_issuance,
                        utxo.is_pegin, utxo.pegin_btc_tx_size,
                        to_hex_string(utxo.fedpeg_script),
                        to_hex_string(utxo.scriptsig_template))
                for utxo in utxo_list:
                    util.call_func(
                        'CfdAddUtxoTemplateForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, str(utxo.descriptor), str(utxo.asset),
                        to_hex_string(utxo.scriptsig_template))

                for index, target in enumerate(target_list):
                    util.call_func(
                        'CfdAddTargetAmountForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        index, target.amount, str(target.asset),
                        str(target.reserved_address))

                set_opt(handle, tx_handle, _FundTxOpt.DUST_FEE_RATE,
                        d_val=dust_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.LONG_TERM_FEE_RATE,
                        d_val=long_term_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.KNAPSACK_MIN_CHANGE,
                        i_val=dust_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.USE_BLIND,
                        b_val=is_blind)
                set_opt(handle, tx_handle, _FundTxOpt.EXPONENT,
                        i_val=exponent)
                set_opt(handle, tx_handle, _FundTxOpt.MINIMUM_BITS,
                        i_val=minimum_bits)

                _tx_fee, _append_txout_count, _new_hex = util.call_func(
                    'CfdFinalizeFundRawTx',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.hex, effective_fee_rate)

                _used_addr_list = []
                for i in range(_append_txout_count):
                    _used_addr = util.call_func(
                        'CfdGetAppendTxOutFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(), i)
                    _used_addr_list.append(_used_addr)

                self.hex = _new_hex
                self._update_tx_all()
                return _tx_fee, _used_addr_list


class _BlindOpt(Enum):
    MINIMUM_RANGE_VALUE = 1
    EXPONENT = 2
    MINIMUM_BITS = 3


class _CoinSelectionOpt(Enum):
    EXPONENT = 1
    MINIMUM_BITS = 2


class _FeeOpt(Enum):
    EXPONENT = 1
    MINIMUM_BITS = 2
