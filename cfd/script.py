# -*- coding: utf-8 -*-
##
# @file script.py
# @brief bitcoin script function implements file.
# @note Copyright 2020 CryptoGarage
from .util import CfdError, to_hex_string, get_util, JobHandle
from .key import SignParameter, SigHashType
from enum import Enum


##
# @class HashType
# @brief Hash Type
class HashType(Enum):
    ##
    # HashType: p2sh
    P2SH = 1
    ##
    # HashType: p2pkh
    P2PKH = 2
    ##
    # HashType: p2wsh
    P2WSH = 3
    ##
    # HashType: p2wpkh
    P2WPKH = 4
    ##
    # HashType: p2sh-p2wsh
    P2SH_P2WSH = 5
    ##
    # HashType: p2sh-p2wpkh
    P2SH_P2WPKH = 6

    @classmethod
    def get(cls, hashtype):
        if (isinstance(hashtype, HashType)):
            return hashtype
        elif (isinstance(hashtype, int)):
            _num = int(hashtype)
            for hash_type in HashType:
                if _num == hash_type.value:
                    return hash_type
        else:
            _hash_type = str(hashtype).lower()
            for hash_type in HashType:
                if _hash_type == hash_type.name.lower():
                    return hash_type
            if _hash_type == 'p2sh-p2wsh':
                return HashType.P2SH_P2WSH
            elif _hash_type == 'p2sh-p2wpkh':
                return HashType.P2SH_P2WPKH
        raise CfdError(
            error_code=1,
            message='Error: Invalid hash type.')


class Script:
    @classmethod
    def from_asm(cls, script_items):
        _asm = script_items
        if isinstance(script_items, list):
            _asm = ' '.join(script_items)
        util = get_util()
        with util.create_handle() as handle:
            _hex = util.call_func(
                'CfdConvertScriptAsmToHex', handle.get_handle(), _asm)
            return Script(_hex)

    @classmethod
    def create_multisig_scriptsig(cls, redeem_script, sign_parameter_list):
        _script = to_hex_string(redeem_script)
        util = get_util()
        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeMultisigScriptSig', handle.get_handle())
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeMultisigScriptSigHandle') as script_handle:
                for param in sign_parameter_list:
                    if isinstance(param, SignParameter) is False:
                        raise CfdError(
                            error_code=1,
                            message='Error: Invalid sign_parameter_list item.')
                    if len(param.hex) > 130:    # der encoded
                        util.call_func(
                            'CfdAddMultisigScriptSigData',
                            handle.get_handle(), script_handle.get_handle(),
                            param.hex, param.related_pubkey)
                    else:
                        _sighashtype = SigHashType.get(param.sighashtype)
                        util.call_func(
                            'CfdAddMultisigScriptSigDataToDer',
                            handle.get_handle(), script_handle.get_handle(),
                            param.hex, _sighashtype.get_type(),
                            _sighashtype.anyone_can_pay(),
                            param.related_pubkey)
                scriptsig = util.call_func(
                    'CfdFinalizeMultisigScriptSig',
                    handle.get_handle(), script_handle.get_handle(),
                    _script)
                return Script(scriptsig)

    def __init__(self, script):
        self.hex = to_hex_string(script)
        self.asm = Script._parse(self.hex)

    # @brief get string.
    # @return address.
    def __repr__(self):
        return self.hex

    @classmethod
    def _parse(cls, script):
        util = get_util()
        script_list = []
        with util.create_handle() as handle:
            word_handle, max_index = util.call_func(
                'CfdParseScript', handle.get_handle(), script)
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeScriptItemHandle') as script_handle:
                for i in range(max_index):
                    item = util.call_func(
                        'CfdGetScriptItem',
                        handle.get_handle(), script_handle.get_handle(), i)
                    script_list.append(item)
        return ' '.join(script_list)
