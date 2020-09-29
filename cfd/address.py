# -*- coding: utf-8 -*-
##
# @file address.py
# @brief address function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util
from .key import NetworkType, get_network_type, Pubkey
from .script import HashType, get_hash_type, Script


class Address:
    def __init__(
            self,
            address,
            locking_script,
            hash_type=HashType.P2SH,
            network=NetworkType.MAINNET,
            pubkey='',
            redeem_script='',
            p2sh_wrapped_script=''):
        self.address = address
        self.locking_script = locking_script
        self.pubkey = pubkey
        self.redeem_script = redeem_script
        self.p2sh_wrapped_script = p2sh_wrapped_script
        self.hash_type = hash_type
        self.network = network

    ##
    # @brief get string.
    # @return address.
    def __repr__(self):
        return self.address


class AddressUtil:
    @classmethod
    def p2wpkh(cls, pubkey, network=NetworkType.MAINNET):
        return cls.from_pubkey_hash(
            pubkey, HashType.P2WPKH, network)

    @classmethod
    def from_pubkey_hash(
            cls,
            pubkey,
            hash_type,
            network=NetworkType.MAINNET):
        _pubkey = str(pubkey)
        _hash_type = get_hash_type(hash_type)
        _network = get_network_type(network)
        util = get_util()
        with util.create_handle() as handle:
            addr, locking_script, segwit_locking_script = util.call_func(
                'CfdCreateAddress',
                handle.get_handle(), _hash_type.value, _pubkey,
                '', _network.value)
            return Address(
                addr,
                locking_script,
                hash_type=_hash_type,
                network=_network,
                pubkey=Pubkey(_pubkey),
                p2sh_wrapped_script=segwit_locking_script)

    @classmethod
    def from_script_hash(
            cls,
            redeem_script,
            hash_type,
            network=NetworkType.MAINNET):
        _script = str(redeem_script)
        _hash_type = get_hash_type(hash_type)
        _network = get_network_type(network)
        util = get_util()
        with util.create_handle() as handle:
            addr, locking_script, segwit_locking_script = util.call_func(
                'CfdCreateAddress',
                handle.get_handle(), _hash_type.value, '',
                _script, _network.value)
            return Address(
                addr,
                locking_script,
                hash_type=_hash_type,
                network=_network,
                redeem_script=Script(_script),
                p2sh_wrapped_script=segwit_locking_script)


##
# @brief create address for p2pkh.
# @param[in] pubkey      public key
# @retval addr              address
# @retval locking_script    locking script
def create_p2pkh_address(pubkey):
    addr = AddressUtil.from_pubkey_hash(
        pubkey,
        hash_type='p2pkh')
    return str(addr), addr.locking_script
