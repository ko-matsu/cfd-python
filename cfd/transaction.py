# -*- coding: utf-8 -*-
##
# @file transaction.py
# @brief hdwallet function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util, JobHandle, CfdError, to_hex_string,\
    CfdErrorCode, ReverseByteData
from .address import Address, AddressUtil
from .key import Network, SigHashType, SignParameter
from .script import HashType
from enum import Enum


class Txid(ReverseByteData):
    def __init__(self, txid):
        super().__init__(txid)
        if len(self.hex) != 64:
            raise CfdError(
                error_code=1, message='Error: Invalid txid.')


class OutPoint:
    def __init__(self, txid, vout):
        self.txid = Txid(txid)
        self.vout = vout
        if isinstance(vout, int) is False:
            raise CfdError(
                error_code=1,
                message='Error: Invalid vout type.')

    ##
    # @brief get string.
    # @return txid.
    def __repr__(self):
        return '{},{}'.format(str(self.txid), self.vout)


class UtxoData:
    def __init__(
            self, outpoint=None, txid='', vout=0,
            amount=0, descriptor='', scriptsig_template=''):
        if isinstance(outpoint, OutPoint):
            self.outpoint = outpoint
        else:
            self.outpoint = OutPoint(txid, vout)
        self.amount = amount
        self.descriptor = descriptor
        self.scriptsig_template = scriptsig_template

    ##
    # @brief get string.
    # @return hex.
    def __repr__(self):
        return str(self.outpoint)


class TxIn:
    def __init__(self, outpoint=None, txid='', vout=0, sequence=0xffffffff):
        if isinstance(outpoint, OutPoint):
            self.outpoint = outpoint
        else:
            self.outpoint = OutPoint(txid=txid, vout=vout)
        self.sequence = sequence
        self.script_sig = ''
        self.witness_stack = []

    ##
    # @brief get string.
    # @return hex.
    def __repr__(self):
        return str(self.outpoint)


class TxOut:
    def __init__(self, amount, address='', locking_script=''):
        self.amount = amount
        if address != '':
            self.address = address
            self.locking_script = ''
        else:
            self.locking_script = locking_script
            self.address = ''

    def get_address(self, network=Network.MAINNET):
        if isinstance(self.address, Address):
            return self.address
        if self.address != '':
            return AddressUtil.parse(self.address)
        return AddressUtil.from_locking_script(self.locking_script, network)

    ##
    # @brief get string.
    # @return address or script.
    def __repr__(self):
        return self.address if (self.address != '') else self.locking_script


class _TransactionBase:
    ##
    # hex
    # transaction hex string
    ##
    # network
    # transaction network type
    ##
    # enable_cache
    # use transaction cache

    def __init__(self, hex, network, enable_cache=True):
        self.hex = to_hex_string(hex)
        self.enable_cache = enable_cache
        self.network = network

    ##
    # @brief get string.
    # @return tx hex.
    def __repr__(self):
        return self.hex

    def _update_tx_all(self):
        if self.enable_cache:
            self.get_tx_all()

    def get_tx_all(self):
        pass

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
        txin = TxIn(txid=txid, vout=vout, sequence=seq)
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
        return txin, index

    def get_txin_index(self, outpoint=None, txid='', vout=0):
        txin = TxIn(outpoint=outpoint, txid=txid, vout=vout)
        util = get_util()
        with util.create_handle() as handle:
            index = util.call_func(
                'CfdGetTxInIndex', handle.get_handle(),
                self.network, self.hex, str(txin.outpoint.txid),
                txin.outpoint.vout)
            return index

    def get_txout_index(self, address='', locking_script=''):
        # get first target only.
        _script = to_hex_string(locking_script)
        util = get_util()
        with util.create_handle() as handle:
            index = util.call_func(
                'CfdGetTxOutIndex', handle.get_handle(),
                self.network, self.hex, str(address), _script)
            return index

    def add_pubkey_hash_sign(
            self, outpoint, hash_type, pubkey, signature,
            sighashtype=SigHashType.ALL):
        _hash_type = HashType.get(hash_type)
        _pubkey = to_hex_string(pubkey)
        _signature = to_hex_string(signature)
        _sighashtype = SigHashType.get(sighashtype)
        if isinstance(signature, SignParameter) and (
                _sighashtype == SigHashType.ALL):
            _sighashtype = SigHashType.get(signature.sighashtype)
        use_der_encode = (len(_signature) <= 130) is True
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddPubkeyHashSign', handle.get_handle(),
                self.network, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, _pubkey,
                _signature, use_der_encode, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay())
            self._update_txin(outpoint)

    def add_multisig_sign(
            self, outpoint, hash_type, redeem_script,
            signature_list):
        if (isinstance(signature_list, list) is False) or (
                len(signature_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid signature_list.')
        _hash_type = HashType.get(hash_type)
        _script = to_hex_string(redeem_script)
        util = get_util()
        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeMultisigSign', handle.get_handle())
            with JobHandle(handle, word_handle,
                           'CfdFreeMultisigSignHandle') as tx_handle:
                for sig in signature_list:
                    _sig = to_hex_string(sig)
                    _sighashtype = SigHashType.ALL
                    _related_pubkey = ''
                    use_der = (len(_sig) <= 130)
                    if isinstance(sig, SignParameter):
                        _sighashtype = SigHashType.get(sig.sighashtype)
                        _related_pubkey = to_hex_string(sig.related_pubkey)
                    elif use_der:
                        raise CfdError(
                            error_code=1, message='Error: Invalid signature.')

                    if use_der:
                        util.call_func(
                            'CfdAddMultisigSignDataToDer',
                            handle.get_handle(), tx_handle.get_handle(),
                            _sig, _sighashtype.get_type(),
                            _sighashtype.anyone_can_pay(), _related_pubkey)
                    else:
                        util.call_func(
                            'CfdAddMultisigSignData',
                            handle.get_handle(), tx_handle.get_handle(),
                            _sig, _related_pubkey)

                self.hex = util.call_func(
                    'CfdFinalizeMultisigSign',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.network, self.hex, str(outpoint.txid),
                    outpoint.vout, _hash_type.value, _script)
                self._update_txin(outpoint)

    def add_script_hash_sign(
            self, outpoint, hash_type, redeem_script,
            signature_list):
        if (isinstance(signature_list, list) is False) or (
                len(signature_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid signature_list.')
        _hash_type = HashType.get(hash_type)
        _script = to_hex_string(redeem_script)
        util = get_util()
        with util.create_handle() as handle:
            clear_stack = True
            for sig in signature_list:
                _sig = to_hex_string(sig)
                _sighashtype = SigHashType.ALL
                use_der_encode = False
                if isinstance(sig, SignParameter):
                    _sighashtype = SigHashType.get(sig.sighashtype)
                    use_der_encode = sig.use_der_encode

                self.hex = util.call_func(
                    'CfdAddTxSign', handle.get_handle(),
                    self.network, self.hex, str(outpoint.txid),
                    outpoint.vout, _hash_type.value, _sig,
                    use_der_encode, _sighashtype.get_type(),
                    _sighashtype.anyone_can_pay(), clear_stack)
                clear_stack = False

            self.hex = util.call_func(
                'CfdAddScriptHashSign',
                handle.get_handle(), self.network, self.hex,
                str(outpoint.txid), outpoint.vout, _hash_type.value,
                _script, False)
            self._update_txin(outpoint)

    def add_sign(
            self, outpoint, hash_type, sign_data,
            clear_stack=False, use_der_encode=False,
            sighashtype=SigHashType.ALL):
        _hash_type = HashType.get(hash_type)
        _sign_data = to_hex_string(sign_data)
        _sighashtype = SigHashType.get(sighashtype)
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddTxSign', handle.get_handle(),
                self.network, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, _sign_data,
                use_der_encode, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay(), clear_stack)
            self._update_txin(outpoint)


class Transaction(_TransactionBase):
    ##
    # bitcoin network value.
    NETWORK = Network.MAINNET.value
    ##
    # transaction's free function name.
    FREE_FUNC_NAME = 'CfdFreeTransactionHandle'

    @classmethod
    def parse_to_json(cls, hex, network=Network.MAINNET):
        network_str = 'mainnet'
        if network == Network.TESTNET:
            network_str = 'testnet'
        elif network == Network.REGTEST:
            network_str = 'regtest'
        request_json = '{{"hex":"{}","network":"{}"}}'.format(hex, network_str)
        util = get_util()
        with util.create_handle() as handle:
            return util.call_func(
                'CfdRequestExecuteJson', handle.get_handle(),
                'DecodeRawTransaction', request_json)

    def __init__(self, hex, enable_cache=True):
        super().__init__(hex, self.NETWORK, enable_cache)
        self.txin_list = []
        self.txout_list = []
        self._update_tx_all()

    def _update_info(self):
        if self.enable_cache is False:
            return
        util = get_util()
        with util.create_handle() as handle:
            self.txid, self.wtxid, self.size, self.vsize, self.weight,\
                self.version, self.locktime = util.call_func(
                    'CfdGetTxInfo', handle.get_handle(),
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
                self.txid, self.wtxid, self.size, self.vsize, self.weight,\
                    self.version, self.locktime = util.call_func(
                        'CfdGetTxInfoByHandle', handle.get_handle(),
                        tx_handle.get_handle())
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
                        'CfdAddTransactionOutput', handle.get_handle(),
                        tx_handle.get_handle(), txout.amount,
                        str(txout.address),
                        str(txout.locking_script), '')
                hex = util.call_func(
                    'CfdFinalizeTransaction', handle.get_handle(),
                    tx_handle.get_handle())
        return Transaction(hex)

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
                amount, script, _ = util.call_func(
                    'CfdGetTxOutByHandle', handle.get_handle(),
                    tx_handle.get_handle(), i)
                txout = TxOut(amount=amount, locking_script=script)
                txout_list.append(txout)
            return txout_list

        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTxDataHandle', handle.get_handle(),
                self.NETWORK, self.hex)
            with JobHandle(handle, _tx_handle,
                           self.FREE_FUNC_NAME) as tx_handle:
                self.txid, self.wtxid, self.size, self.vsize, self.weight,\
                    self.version, self.locktime = util.call_func(
                        'CfdGetTxInfoByHandle', handle.get_handle(),
                        tx_handle.get_handle())
                self.txid = Txid(self.txid)
                self.wtxid = Txid(self.wtxid)
                self.txin_list = get_txin_list(handle, tx_handle)
                self.txout_list = get_txout_list(handle, tx_handle)
                return self.txin_list, self.txout_list

    def add_txin(self, outpoint=None, sequence=0xffffffff, txid='', vout=0):
        txin = TxIn(
            outpoint=outpoint, sequence=sequence,
            txid=txid, vout=vout)
        self.update([txin], [])

    def add_txout(self, amount, address='', locking_script=''):
        txout = TxOut(amount, address, locking_script)
        self.update([], [txout])

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
                        'CfdAddTransactionOutput', handle.get_handle(),
                        tx_handle.get_handle(), txout.amount,
                        str(txout.address),
                        str(txout.locking_script), '')
                self.hex = util.call_func(
                    'CfdFinalizeTransaction', handle.get_handle(),
                    tx_handle.get_handle())
                self.txid, self.wtxid, self.size, self.vsize, self.weight,\
                    self.version, self.locktime = util.call_func(
                        'CfdGetTxInfoByHandle', handle.get_handle(),
                        tx_handle.get_handle())
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

    def get_sighash(
            self,
            outpoint,
            hash_type,
            amount=0,
            pubkey='',
            redeem_script='',
            sighashtype=SigHashType.ALL):
        _hash_type = HashType.get(hash_type)
        _pubkey = to_hex_string(pubkey)
        _script = to_hex_string(redeem_script)
        _sighashtype = SigHashType.get(sighashtype)
        util = get_util()
        with util.create_handle() as handle:
            sighash = util.call_func(
                'CfdCreateSighash', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, _pubkey,
                _script, amount, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay())
            return sighash

    def sign_with_privkey(
            self,
            outpoint,
            hash_type,
            privkey,
            amount=0,
            sighashtype=SigHashType.ALL,
            grind_r=True):
        _hash_type = HashType.get(hash_type)
        _privkey = privkey
        _pubkey = _privkey.get_pubkey()
        _sighashtype = SigHashType.get(sighashtype)
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddSignWithPrivkeySimple', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, str(_pubkey),
                str(_privkey), amount, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay(), grind_r)
            self._update_txin(outpoint)

    def verify_sign(self, outpoint, address, hash_type, amount):
        _hash_type = HashType.get(hash_type)
        util = get_util()
        with util.create_handle() as handle:
            util.call_func(
                'CfdVerifyTxSign', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, str(address), _hash_type.value,
                '', amount, '')

    def verify_signature(
            self, outpoint, address, hash_type, amount,
            direct_locking_script=''):
        if direct_locking_script != '':
            _script = to_hex_string(direct_locking_script)
            _addr = ''
        else:
            _addr = address
            _script = ''
        _hash_type = HashType.get(hash_type)
        try:
            util = get_util()
            with util.create_handle() as handle:
                util.call_func(
                    'CfdVerifySignature', handle.get_handle(),
                    self.NETWORK, self.hex, str(outpoint.txid),
                    outpoint.vout, str(_addr), _hash_type.value,
                    _script, amount, '')
                return True
        except CfdError as err:
            if err.error_code == CfdErrorCode.SIGN_VERIFICATION.value:
                return False
            else:
                raise err

    @classmethod
    def select_coins(
            cls, utxo_list, tx_fee_amount, target_amount,
            effective_fee_rate=20.0, long_term_fee_rate=20.0,
            dust_fee_rate=3.0, knapsack_min_change=-1):
        if (isinstance(utxo_list, list) is False) or (
                len(utxo_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid utxo_list.')
        util = get_util()
        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeCoinSelection', handle.get_handle(),
                len(utxo_list), 1, '', tx_fee_amount, effective_fee_rate,
                long_term_fee_rate, dust_fee_rate, knapsack_min_change)
            with JobHandle(handle, word_handle,
                           'CfdFreeCoinSelectionHandle') as tx_handle:
                for index, utxo in enumerate(utxo_list):
                    util.call_func(
                        'CfdAddCoinSelectionUtxoTemplate',
                        handle.get_handle(), tx_handle.get_handle(), index,
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, '', str(utxo.descriptor),
                        to_hex_string(utxo.scriptsig_template))
                util.call_func(
                    'CfdAddCoinSelectionAmount',
                    handle.get_handle(), tx_handle.get_handle(), 0,
                    target_amount, '')

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

                total_amount = util.call_func(
                    'CfdGetSelectedCoinAssetAmount',
                    handle.get_handle(), tx_handle.get_handle(), 0)
                return selected_utxo_list, _utxo_fee, total_amount

    def estimate_fee(self, utxo_list, fee_rate=20.0):
        if (isinstance(utxo_list, list) is False) or (
                len(utxo_list) == 0):
            raise CfdError(
                error_code=1, message='Error: Invalid utxo_list.')
        util = get_util()
        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeEstimateFee', handle.get_handle(), False)
            with JobHandle(handle, word_handle,
                           'CfdFreeEstimateFeeHandle') as tx_handle:
                for utxo in utxo_list:
                    util.call_func(
                        'CfdAddTxInTemplateForEstimateFee',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        str(utxo.descriptor), '', False, False, False,
                        0, '', to_hex_string(utxo.scriptsig_template))

                _txout_fee, _utxo_fee = util.call_func(
                    'CfdFinalizeEstimateFee',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.hex, '', False, fee_rate)
                return (_txout_fee + _utxo_fee), _txout_fee, _utxo_fee

    def fund_raw_transaction(
            self, txin_utxo_list, utxo_list, reserved_address,
            target_amount=0, effective_fee_rate=20.0,
            long_term_fee_rate=20.0, dust_fee_rate=-1.0,
            knapsack_min_change=-1):
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
                        '', False, False, False, 0, '',
                        to_hex_string(utxo.scriptsig_template))
                for utxo in utxo_list:
                    util.call_func(
                        'CfdAddUtxoTemplateForFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(),
                        str(utxo.outpoint.txid), utxo.outpoint.vout,
                        utxo.amount, str(utxo.descriptor), '',
                        to_hex_string(utxo.scriptsig_template))

                util.call_func(
                    'CfdAddTargetAmountForFundRawTx',
                    handle.get_handle(), tx_handle.get_handle(),
                    0, target_amount, '', str(reserved_address))

                set_opt(handle, tx_handle, _FundTxOpt.DUST_FEE_RATE,
                        d_val=dust_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.LONG_TERM_FEE_RATE,
                        d_val=long_term_fee_rate)
                set_opt(handle, tx_handle, _FundTxOpt.KNAPSACK_MIN_CHANGE,
                        i_val=dust_fee_rate)

                _tx_fee, _append_txout_count, _new_hex = util.call_func(
                    'CfdFinalizeFundRawTx',
                    handle.get_handle(), tx_handle.get_handle(),
                    self.hex, effective_fee_rate)

                _used_addr = ''
                if _append_txout_count > 0:
                    _used_addr = util.call_func(
                        'CfdGetAppendTxOutFundRawTx',
                        handle.get_handle(), tx_handle.get_handle(), 0)
                used_addr = None
                if _used_addr == reserved_address:
                    used_addr = reserved_address

                self.hex = _new_hex
                self._update_tx_all()
                return _tx_fee, used_addr


class _FundTxOpt(Enum):
    USE_BLIND = 1
    DUST_FEE_RATE = 2
    LONG_TERM_FEE_RATE = 3
    KNAPSACK_MIN_CHANGE = 4
    EXPONENT = 5
    MINIMUM_BITS = 6
