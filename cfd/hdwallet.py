# -*- coding: utf-8 -*-
##
# @file hdwallet.py
# @brief hdwallet function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util, JobHandle, to_hex_string
from .key import NetworkType, Privkey, Pubkey
from enum import Enum

##
# mnemonic's free function name.
FREE_FUNC_NAME = 'CfdFreeMnemonicWordList'


##
# xpriv mainnet version
XPRIV_MAINNET_VERSION = '0488ade4'
##
# xpriv testnet version
XPRIV_TESTNET_VERSION = '04358394'
##
# xpub mainnet version
XPUB_MAINNET_VERSION = '0488b21e'
##
# xpub testnet version
XPUB_TESTNET_VERSION = '043587cf'


class ExtKeyType(Enum):
    EXT_PRIVKEY = 0
    EXT_PUBKEY = 1


class Extkey(object):
    def __init__(self):
        self.util = get_util()
        self.version, self.fingerprint, self.chain_code, self.depth, \
            self.child_number = ('', '', '', 0, 0)
        self.extkey = ''
        self.network = NetworkType.TESTNET

    def _get_information(self, extkey):
        with self.util.create_handle() as handle:
            result = self.util.call_func(
                'CfdGetExtkeyInformation', handle.get_handle(), extkey)
            self.version, self.fingerprint, self.chain_code, self.depth, \
                self.child_number = result
            self.extkey = extkey
            self.network = NetworkType.TESTNET
            if self.version in {XPRIV_MAINNET_VERSION, XPUB_MAINNET_VERSION}:
                self.network = NetworkType.MAINNET

    def _convert_path(self, path='', number=0, number_list=[]):
        if path != '':
            return path, []
        if isinstance(number_list, list) and (
                len(number_list) > 0) and (isinstance(number_list[0], int)):
            return '', number_list
        return '', [number]


class ExtPrivkey(Extkey):
    @classmethod
    def from_seed(cls, seed, network=NetworkType.MAINNET):
        _seed = to_hex_string(seed)
        util = get_util()
        with util.create_handle() as handle:
            _extkey = util.call_func(
                'CfdCreateExtkeyFromSeed', handle.get_handle(),
                _seed, network.value)
        return _extkey

    def __init__(self, extkey):
        super().__init__()
        self._get_information(extkey)
        with self.util.create_handle() as handle:
            _hex, wif = self.util.call_func(
                'CfdGetPrivkeyFromExtkey', handle.get_handle(),
                self.extkey, self.network.value)
            self.privkey = Privkey(wif=wif)

    # @brief get string.
    # @return extkey.
    def __repr__(self):
        return self.extkey

    def derive(self, path='', number=0, number_list=[]):
        _path, _list = self._convert_path(path, number, number_list)
        with self.util.create_handle() as handle:
            if _path == '':
                _extkey = self.extkey
                for child in _list:
                    _extkey = self.util.call_func(
                        'CfdCreateExtkeyFromParent',
                        handle.get_handle(), _extkey, child, False,
                        self.network.value,
                        ExtKeyType.EXT_PRIVKEY.value)
            else:
                _extkey = self.util.call_func(
                    'CfdCreateExtkeyFromParentPath', handle.get_handle(),
                    self.extkey, _path, self.network.value,
                    ExtKeyType.EXT_PRIVKEY.value)
        return ExtPrivkey(_extkey)

    def derive_pubkey(self, path='', number=0, number_list=[]):
        return self.derive(
            path=path,
            number=number,
            number_list=number_list).get_extpubkey()

    def get_extpubkey(self):
        with self.util.create_handle() as handle:
            ext_pubkey = self.util.call_func(
                'CfdCreateExtPubkey', handle.get_handle(),
                self.extkey, self.network.value)
            return ExtPubkey(ext_pubkey)


class ExtPubkey(Extkey):
    def __init__(self, extkey):
        super().__init__()
        self._get_information(extkey)
        with self.util.create_handle() as handle:
            hex = self.util.call_func(
                'CfdGetPubkeyFromExtkey', handle.get_handle(),
                self.extkey, self.network.value)
            self.pubkey = Pubkey(hex)

    # @brief get string.
    # @return extkey.
    def __repr__(self):
        return self.extkey

    def derive(self, path='', number=0, number_list=[]):
        _path, _list = self._convert_path(path, number, number_list)
        with self.util.create_handle() as handle:
            if _path == '':
                _extkey = self.extkey
                for child in number_list:
                    _extkey = self.util.call_func(
                        'CfdCreateExtkeyFromParent',
                        handle.get_handle(),
                        _extkey, child, False,
                        self.network.value,
                        ExtKeyType.EXT_PUBKEY.value)
            else:
                _extkey = self.util.call_func(
                    'CfdCreateExtkeyFromParentPath', handle.get_handle(),
                    self.extkey, _path, self.network.value,
                    ExtKeyType.EXT_PUBKEY.value)
        return ExtPubkey(_extkey)


class HDWallet:
    def __init__(self, seed='', mnemonic='', passphrase=''):
        if mnemonic != '':
            pass
        self.seed = seed
        # parse

    @classmethod
    ##
    # @brief get mnemonic word list.
    # @param[in] lang       language
    # @retval word_list     mnemonic word list
    def get_mnemonic_word_list(cls, lang):
        util = get_util()
        word_list = []
        with util.create_handle() as handle:
            word_handle, max_index = util.call_func(
                'CfdInitializeMnemonicWordList', handle.get_handle(), lang)
            with JobHandle(
                    handle,
                    word_handle,
                    FREE_FUNC_NAME) as mnemonic_handle:
                for i in range(max_index):
                    word = util.call_func(
                        'CfdGetMnemonicWord',
                        handle.get_handle(), mnemonic_handle.get_handle(), i)
                    word_list.append(word)
        return word_list

    def get_privkey(self, path='', number=0, number_list=[]):
        pass

    def get_pubkey(self, path='', number=0, number_list=[]):
        pass


##
# @brief get mnemonic word list.
# @param[in] lang       language
# @retval word_list     mnemonic word list
def get_mnemonic_word_list(lang):
    util = get_util()
    word_list = []
    with util.create_handle() as handle:
        word_handle, max_index = util.call_func(
            'CfdInitializeMnemonicWordList', handle.get_handle(), lang)
        with JobHandle(
                handle,
                word_handle,
                FREE_FUNC_NAME) as mnemonic_handle:
            for i in range(max_index):
                word = util.call_func(
                    'CfdGetMnemonicWord',
                    handle.get_handle(), mnemonic_handle.get_handle(), i)
                word_list.append(word)
    return word_list
