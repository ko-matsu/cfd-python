# -*- coding: utf-8 -*-
##
# @file transaction.py
# @brief hdwallet function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util, JobHandle, CfdError, to_hex_string
from .key import NetworkType, SigHashType, get_sighash_type, parse_sighash_type
from .script import get_hash_type

##
# mnemonic's free function name.
FREE_FUNC_NAME = 'CfdFreeTransactionHandle'


class Txid:
    def __init__(self, txid):
        # FIXME: reverse check
        if (isinstance(txid, bytes)):
            self.txid = txid.hex()
        elif (isinstance(txid, list)):
            self.txid = "".join("%02x" % b for b in txid)
        else:
            self.txid = str(txid)

    # @brief get string.
    # @return txid.
    def __repr__(self):
        return self.txid

    def as_array(self):
        pass


class OutPoint:
    def __init__(self, txid, vout):
        self.txid = Txid(txid)
        self.vout = vout
        if isinstance(vout, int) is False:
            raise CfdError(
                error_code=1,
                message='Error: Invalid vout type.')


class TxIn:
    def __init__(self, outpoint=None, sequence=0xffffffff, txid='', vout=0):
        if isinstance(outpoint, OutPoint):
            self.outpoint = outpoint
        else:
            self.outpoint = OutPoint(txid=txid, vout=vout)
        self.sequence = sequence


class TxOut:
    def __init__(self, amount, address='', locking_script=''):
        self.amount = amount
        if address != '':
            self.address = address
            self.locking_script = ''
        else:
            self.locking_script = locking_script
            self.address = ''


class Transaction:
    NETWORK = NetworkType.MAINNET.value

    def __init__(self, hex):
        self.hex = to_hex_string(hex)
        self._update_info()

    def _update_info(self):
        util = get_util()
        with util.create_handle() as handle:
            self.txid, self.wtxid, self.size, self.vsize, self.weight,\
                self.version, self.locktime = util.call_func(
                    'CfdGetTxInfo', handle.get_handle(),
                    self.NETWORK, self.hex)

    @classmethod
    def create(cls, version, locktime, txins, txouts):
        util = get_util()
        with util.create_handle() as handle:
            _tx_handle = util.call_func(
                'CfdInitializeTransaction', handle.get_handle(),
                cls.NETWORK, version, locktime, '')
            with JobHandle(handle, _tx_handle, FREE_FUNC_NAME) as tx_handle:
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

    def add_txin(self, outpoint=None, sequence=0xffffffff, txid='', vout=0):
        txin = TxIn(outpoint, sequence, txid, vout)
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
            with JobHandle(handle, _tx_handle, FREE_FUNC_NAME) as tx_handle:
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

    def get_sighash(
            self,
            outpoint,
            hash_type,
            amount=0,
            pubkey='',
            redeem_script='',
            sighashtype=SigHashType.ALL):
        _hash_type = get_hash_type(hash_type)
        _pubkey = to_hex_string(pubkey)
        _script = to_hex_string(redeem_script)
        _sighashtype1 = get_sighash_type(sighashtype)
        _sighash_type, anyone_can_pay = parse_sighash_type(_sighashtype1)
        util = get_util()
        with util.create_handle() as handle:
            sighash = util.call_func(
                'CfdCreateSighash', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, _pubkey,
                _script, amount, _sighash_type.value, anyone_can_pay)
            return sighash

    def sign_with_privkey(
            self,
            outpoint,
            hash_type,
            privkey,
            sighashtype=SigHashType.ALL,
            amount=0,
            grind_r=True):
        _hash_type = get_hash_type(hash_type)
        _privkey = privkey
        _pubkey = _privkey.get_pubkey()
        _sighashtype1 = get_sighash_type(sighashtype)
        _sighash_type, anyone_can_pay = parse_sighash_type(_sighashtype1)
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddSignWithPrivkeySimple', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, str(_pubkey),
                str(_privkey), amount, _sighash_type.value,
                anyone_can_pay, grind_r)
            self._update_info()

    def add_pubkey_hash_sign(
            self,
            outpoint,
            hash_type,
            pubkey,
            signature):
        pass

    def add_multisig_sign(
            self,
            outpoint,
            hash_type,
            redeem_script,
            signature_list):
        pass

    def add_sign(
            self,
            outpoint,
            hash_type,
            sign_data,
            clear_stack=False,
            use_der_encode=False,
            sighashtype=SigHashType.ALL):
        _hash_type = get_hash_type(hash_type)
        _sign_data = to_hex_string(sign_data)
        _sighashtype1 = get_sighash_type(sighashtype)
        _sighash_type, anyone_can_pay = parse_sighash_type(_sighashtype1)
        util = get_util()
        with util.create_handle() as handle:
            self.hex = util.call_func(
                'CfdAddTxSign', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, _hash_type.value, _sign_data,
                use_der_encode, _sighash_type.value,
                anyone_can_pay, clear_stack)
            self._update_info()

    def verify_sign(
            self,
            outpoint,
            address,
            hash_type,
            amount):
        _addr = address
        _addr.hash_type = get_hash_type(hash_type)
        util = get_util()
        with util.create_handle() as handle:
            util.call_func(
                'CfdVerifyTxSign', handle.get_handle(),
                self.NETWORK, self.hex, str(outpoint.txid),
                outpoint.vout, str(_addr), _addr.hash_type.value,
                '', amount, '')

    def verify_signature(
            self,
            outpoint,
            address,
            hash_type,
            amount):
        # FIXME: not implement
        _addr = address
        _addr.hash_type = get_hash_type(hash_type)
        try:
            util = get_util()
            with util.create_handle() as handle:
                util.call_func(
                    'CfdVerifySignature', handle.get_handle(),
                    self.NETWORK, self.hex, str(outpoint.txid),
                    outpoint.vout, str(_addr), _addr.hash_type.value,
                    '', amount, '')
                return True
        except CfdError as err:
            if err.error_code == 7:
                return False
            else:
                raise err
