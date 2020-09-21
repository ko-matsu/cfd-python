# -*- coding: utf-8 -*-
##
# @file address.py
# @brief address function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util
from enum import Enum


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


##
# @brief create address for p2pkh.
# @param[in] pubkey      public key
# @retval addr              address
# @retval locking_script    locking script
def create_p2pkh_address(pubkey):
    util = get_util()
    # handle = util.create_handle()
    addr, locking_script = '', ''
    with util.create_handle() as handle:
        if isinstance(pubkey, str):
            addr, locking_script, segwit_locking_script = util.call_func(
                'CfdCreateAddress',
                handle.get_handle(), HashType.P2PKH.value, pubkey,
                '', NetworkType.MAINNET.value)
    return addr, locking_script
