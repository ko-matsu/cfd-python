# -*- coding: utf-8 -*-
##
# @file key.py
# @brief key function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util, CfdError, to_hex_string
from enum import Enum

##
# mnemonic's free function name.
FREE_FUNC_NAME = 'CfdFreeMnemonicWordList'


##
# @class NetworkType
# @brief Network Type
class NetworkType(Enum):
    ##
    # Network: Bitcoin Mainnet
    MAINNET = 0
    ##
    # Network: Bitcoin Testnet
    TESTNET = 1
    ##
    # Network: Bitcoin Regtest
    REGTEST = 2
    ##
    # Network: Liquid LiquidV1
    LIQUID_V1 = 10
    ##
    # Network: Liquid ElementsRegtest
    ELEMENTS_REGTEST = 11
    ##
    # Network: Liquid custom chain
    CUSTOM_CHAIN = 12


def get_network_type(network):
    if (isinstance(network, NetworkType)):
        return network
    elif (isinstance(network, int)):
        _num = int(network)
        for net in NetworkType:
            if _num == net.value:
                return net
    else:
        _network = str(network).lower()
        for net in NetworkType:
            if _network == net.name.lower():
                return net
        if _network == 'liquidv1':
            return NetworkType.LIQUID_V1
        elif _network in {'elementsregtest', 'liquidregtest'}:
            return NetworkType.ELEMENTS_REGTEST
    raise CfdError(
        error_code=1,
        message='Error: Invalid network type.')


##
# @class SigHashType
# @brief Signature hash type
class SigHashType(Enum):
    ##
    # SigHashType: all
    ALL = 1
    ##
    # SigHashType: none
    NONE = 2
    ##
    # SigHashType: single
    SINGLE = 3
    ##
    # SigHashType: all+anyoneCanPay
    ALL_PLUS_ANYONE_CAN_PAY = 0x81
    ##
    # SigHashType: none+anyoneCanPay
    NONE_PLUS_ANYONE_CAN_PAY = 0x82
    ##
    # SigHashType: single+anyoneCanPay
    SINGLE_PLUS_ANYONE_CAN_PAY = 0x83


def get_sighash_type(sighashtype, anyoneCanPay=False):
    if (isinstance(sighashtype, SigHashType)):
        if anyoneCanPay is True:
            return get_sighash_type(sighashtype.value | 0x80)
        else:
            return sighashtype
    elif (isinstance(sighashtype, int)):
        _num = int(sighashtype)
        if anyoneCanPay is True:
            _num |= 0x80
        for hash_type in SigHashType:
            if _num == hash_type.value:
                return hash_type
    else:
        _hash_type = str(sighashtype).lower()
        if (anyoneCanPay is True) and (
                _hash_type.find('_plus_anyone_can_pay') == -1):
            _hash_type += '_plus_anyone_can_pay'
        for hash_type in SigHashType:
            if _hash_type == hash_type.name.lower():
                return hash_type
    raise CfdError(
        error_code=1,
        message='Error: Invalid sighash type.')


def parse_sighash_type(sighashtype):
    obj = get_sighash_type(sighashtype)
    anyone_can_pay = False
    if obj.value >= 0x80:
        obj = get_sighash_type(obj.value & 0x0f)
        anyone_can_pay = True
    return obj, anyone_can_pay


##
# @class Privkey
# @brief privkey class.
class Privkey:
    ##
    # @var hex
    # privkey hex
    ##
    # @var wif
    # wallet import format
    ##
    # @var network
    # network type.
    ##
    # @var is_compressed
    # pubkey compressed flag

    ##
    # @brief constructor.
    # @param[in] wif            wif
    # @param[in] hex            hex
    # @param[in] network        network
    # @param[in] is_compressed  is_compressed
    def __init__(
            self,
            wif='',
            hex='',
            network=NetworkType.MAINNET,
            is_compressed=True):
        self.hex = to_hex_string(hex)
        self.wif = wif
        self.network = get_network_type(network)
        self.is_compressed = is_compressed
        util = get_util()
        with util.create_handle() as handle:
            if len(wif) == 0:
                self.wif_first = False
                self.wif = util.call_func(
                    'CfdGetPrivkeyWif', handle.get_handle(),
                    self.hex, self.network.value, is_compressed)
            else:
                self.wif_first = True
                self.hex, self.network, \
                    self.is_compressed = util.call_func(
                        'CfdParsePrivkeyWif', handle.get_handle(),
                        self.wif)
                self.network = get_network_type(self.network)
            self.pubkey = util.call_func(
                'CfdGetPubkeyFromPrivkey', handle.get_handle(),
                self.hex, '', self.is_compressed)

    ##
    # @brief get string.
    # @return pubkey hex.
    def __repr__(self):
        return self.wif if (self.wif_first) else self.hex

    def add_tweak(self, tweak):
        # FIXME
        return self.hex

    def mul_tweak(self, tweak):
        # FIXME
        return self.hex

    def negate(self):
        # FIXME
        return self.hex

    def calculate_ec_signature(self, sighash, grind_r=True):
        util = get_util()
        with util.create_handle() as handle:
            signature = util.call_func(
                'CfdCalculateEcSignature', handle.get_handle(),
                sighash, self.hex, '', self.network.value, grind_r)
        return signature


##
# @class Pubkey
# @brief pubkey class.
class Pubkey:
    ##
    # @var hex
    # pubkey hex

    ##
    # @brief constructor.
    # @param[in] pubkey     pubkey
    def __init__(self, pubkey):
        self.hex = to_hex_string(pubkey)
        util = get_util()
        with util.create_handle() as handle:
            util.call_func(
                'CfdCompressPubkey', handle.get_handle(), self.hex)

    ##
    # @brief get string.
    # @return pubkey hex.
    def __repr__(self):
        return self.hex

    def compress(self, tweak):
        util = get_util()
        with util.create_handle() as handle:
            _pubkey = util.call_func(
                'CfdCompressPubkey', handle.get_handle(), self.hex)
        return Pubkey(_pubkey)

    def uncompress(self, tweak):
        util = get_util()
        with util.create_handle() as handle:
            _pubkey = util.call_func(
                'CfdUncompressPubkey', handle.get_handle(), self.hex)
        return Pubkey(_pubkey)

    def add_tweak(self, tweak):
        # FIXME
        return self.hex

    def mul_tweak(self, tweak):
        # FIXME
        return self.hex

    def negate(self):
        # FIXME
        return self.hex


class SignParameter:
    def __init__(self, data):
        self.hex = to_hex_string(data)
