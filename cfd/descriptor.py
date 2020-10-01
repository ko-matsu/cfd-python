# -*- coding: utf-8 -*-
##
# @file descriptor.py
# @brief hdwallet function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util, JobHandle, CfdError
from .address import AddressUtil
from .key import Network
from .script import HashType
from enum import Enum


class DescriptorScriptType(Enum):
    NULL = 0
    SH = 1
    WSH = 2
    PK = 3
    PKH = 4
    WPKH = 5
    COMBO = 6
    MULTI = 7
    SORTED_MULTI = 8
    ADDR = 9
    RAW = 10

    @classmethod
    def get(cls, desc_type):
        if (isinstance(desc_type, DescriptorScriptType)):
            return desc_type
        elif (isinstance(desc_type, int)):
            _num = int(desc_type)
            for type_data in DescriptorScriptType:
                if _num == type_data.value:
                    return type_data
        else:
            _type = str(desc_type).lower()
            for type_data in DescriptorScriptType:
                if _type == type_data.name.lower():
                    return type_data
        raise CfdError(
            error_code=1,
            message='Error: Invalid type.')


class DescriptorKeyType(Enum):
    NULL = 0
    PUBLIC = 1
    BIP32 = 2
    BIP32_PRIV = 3

    @classmethod
    def get(cls, desc_type):
        if (isinstance(desc_type, DescriptorKeyType)):
            return desc_type
        elif (isinstance(desc_type, int)):
            _num = int(desc_type)
            for type_data in DescriptorKeyType:
                if _num == type_data.value:
                    return type_data
        else:
            _type = str(desc_type).lower()
            for type_data in DescriptorKeyType:
                if _type == type_data.name.lower():
                    return type_data
        raise CfdError(
            error_code=1,
            message='Error: Invalid type.')


class DescriptorKeyData:
    def __init__(
            self,
            key_type=DescriptorKeyType.NULL,
            pubkey='',
            ext_pubkey='',
            ext_privkey=''):
        self.key_type = DescriptorKeyType.get(key_type)
        self.pubkey = pubkey
        self.ext_pubkey = ext_pubkey
        self.ext_privkey = ext_privkey


class DescriptorScriptData:
    def __init__(
            self, script_type, depth, hash_type, address,
            redeem_script='',
            key_data=None,
            key_list=[],
            multisig_require_num=0):
        self.script_type = script_type
        self.depth = depth
        self.hash_type = hash_type
        self.address = address
        self.redeem_script = redeem_script
        self.key_data = key_data
        self.key_list = key_list
        self.multisig_require_num = multisig_require_num


class Descriptor:
    def __init__(self, descriptor, network=Network.MAINNET, path=''):
        self.network = Network.get(network)
        self.path = str(path)
        self.descriptor = self._verify(str(descriptor))
        self.script_list = self._parse()
        self.data = self._analyze()

    def _verify(self, descriptor):
        util = get_util()
        with util.create_handle() as handle:
            return util.call_func(
                'CfdGetDescriptorChecksum', handle.get_handle(),
                self.network.value, descriptor)

    def _parse(self):
        util = get_util()
        with util.create_handle() as handle:
            word_handle, max_index = util.call_func(
                'CfdParseDescriptor', handle.get_handle(),
                self.descriptor, self.network.value)
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeDescriptorHandle') as desc_handle:

                def get_key(index):
                    return util.call_func(
                        'CfdGetDescriptorMultisigKey',
                        handle.get_handle(), desc_handle.get_handle(),
                        index)

                script_list = []
                for i in range(max_index + 1):
                    max_index, depth, script_type, locking_script,\
                        address, hash_type, redeem_script, key_type,\
                        pubkey, ext_pubkey, ext_privkey, is_multisig,\
                        max_key_num, req_sig_num = util.call_func(
                            'CfdGetDescriptorData',
                            handle.get_handle(), desc_handle.get_handle(), i)
                    _script_type = DescriptorScriptType.get(script_type)
                    data = DescriptorScriptData(
                        _script_type,
                        depth,
                        HashType.get(hash_type),
                        address)
                    if _script_type in {
                            DescriptorScriptType.COMBO,
                            DescriptorScriptType.PK,
                            DescriptorScriptType.PKH,
                            DescriptorScriptType.WPKH}:
                        data.key_data = DescriptorKeyData(
                            key_type, pubkey, ext_pubkey, ext_privkey)
                        data.address = AddressUtil.parse(address, hash_type)
                    elif _script_type in {
                            DescriptorScriptType.SH,
                            DescriptorScriptType.WSH,
                            DescriptorScriptType.MULTI,
                            DescriptorScriptType.SORTED_MULTI}:
                        data.address = AddressUtil.parse(address, hash_type)
                        if is_multisig is False:
                            data.redeem_script = redeem_script
                        else:
                            key_list = []
                            for i in range(max_key_num):
                                key_info = DescriptorKeyData(*get_key(i))
                                key_list.append(key_info)
                            data.key_list = key_list
                            data.multisig_require_num = req_sig_num
                    elif _script_type == DescriptorScriptType.RAW:
                        pass
                    elif _script_type == DescriptorScriptType.ADDR:
                        data.address = AddressUtil.parse(address, hash_type)

                    script_list.append(data)
                    if _script_type == DescriptorScriptType.COMBO:
                        # TODO: combo data is top only.
                        break
                return script_list

    def _analyze(self):
        if (self.script_list[0].hash_type in {
                HashType.P2WSH, HashType.P2SH}) and (
                len(self.script_list) > 1) and (
                self.script_list[1].hash_type == HashType.P2PKH):
            data = DescriptorScriptData(
                self.script_list[0].script_type,
                self.script_list[0].depth,
                self.script_list[0].hash_type,
                self.script_list[0].address,
                self.script_list[0].redeem_script,
                self.script_list[1].key_data)
            return data

        if (self.script_list[0].hash_type == HashType.P2SH_P2WSH) and (
                len(self.script_list) > 2) and (
                self.script_list[2].hash_type == HashType.P2PKH):
            data = DescriptorScriptData(
                self.script_list[0].script_type,
                self.script_list[0].depth,
                self.script_list[0].hash_type,
                self.script_list[0].address,
                self.script_list[1].redeem_script,
                self.script_list[2].key_data)
            return data
        if len(self.script_list) == 1:
            return self.script_list[0]

        if self.script_list[0].hash_type == HashType.P2SH_P2WSH:
            if self.script_list[1].multisig_require_num > 0:
                multisig_require_num = self.script_list[1].multisig_require_num
                data = DescriptorScriptData(
                    self.script_list[0].script_type,
                    self.script_list[0].depth,
                    self.script_list[0].hash_type,
                    self.script_list[0].address,
                    self.script_list[1].redeem_script,
                    key_list=self.script_list[1].key_list,
                    multisig_require_num=multisig_require_num)
                return data
            else:
                data = DescriptorScriptData(
                    self.script_list[0].script_type,
                    self.script_list[0].depth,
                    self.script_list[0].hash_type,
                    self.script_list[0].address,
                    self.script_list[1].redeem_script)
                return data
        elif self.script_list[0].hash_type == HashType.P2SH_P2WPKH:
            data = DescriptorScriptData(
                self.script_list[0].script_type,
                self.script_list[0].depth,
                self.script_list[0].hash_type,
                self.script_list[0].address,
                key_data=self.script_list[1].key_data)
            return data
        return self.script_list[0]

    ##
    # @brief get string.
    # @return descriptor.
    def __repr__(self):
        return self.descriptor


##
# @brief parse descriptor.
# @param[in] descriptor     descriptor
# @param[in] network        network
# @param[in] path           bip32 path
# @retval Descriptor        descriptor object
def parse_descriptor(descriptor, network=Network.MAINNET, path=''):
    return Descriptor(descriptor, network=network, path=path)
