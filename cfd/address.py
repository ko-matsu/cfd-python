from .util import get_util
from enum import Enum


class NetworkType(Enum):
    MAINNET = 0
    TESTNET = 1
    REGTEST = 2
    LIQUID_V1 = 10
    ELEMENTS_REGTEST = 11
    CUSTOM_CHAIN = 12


class HashType(Enum):
    P2SH = 1
    P2PKH = 2
    P2WSH = 3
    P2WPKH = 4
    P2SH_P2WSH = 5
    P2SH_P2WPKH = 6


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
