# -*- coding: utf-8 -*-
##
# @file script.py
# @brief bitcoin script function implements file.
# @note Copyright 2020 CryptoGarage
from .util import CfdError, to_hex_string
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


def get_hash_type(hashtype):
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
    def __init__(self, script):
        self.hex = to_hex_string(script)
        self.asm = ''

    # @brief get string.
    # @return address.
    def __repr__(self):
        return self.hex
