# -*- coding: utf-8 -*-
##
# @file hdwallet.py
# @brief hdwallet function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util, JobHandle, to_hex_string, CfdError
from .key import Network, Privkey, Pubkey
from enum import Enum
import unicodedata


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
        self.network = Network.TESTNET

    def _get_information(self, extkey):
        with self.util.create_handle() as handle:
            result = self.util.call_func(
                'CfdGetExtkeyInformation', handle.get_handle(), extkey)
            self.version, self.fingerprint, self.chain_code, self.depth, \
                self.child_number = result
            self.extkey = extkey
            self.network = Network.TESTNET
            if self.version in {XPRIV_MAINNET_VERSION, XPUB_MAINNET_VERSION}:
                self.network = Network.MAINNET

    def _convert_path(self, path='', number=0, number_list=[]):
        if path != '':
            return path, []
        if isinstance(number_list, list) and (
                len(number_list) > 0) and (isinstance(number_list[0], int)):
            return '', number_list
        return '', [number]

    def _get_path_data(self, bip32_path, key_type):
        with self.util.create_handle() as handle:
            return self.util.call_func(
                'CfdGetParentExtkeyPathData', handle.get_handle(),
                self.extkey, bip32_path, key_type.value)

    @classmethod
    def _create(
            cls, key_type, network, fingerprint, key, chain_code,
            depth, number, parent_key=''):
        _network = Network.get_mainchain(network)
        _fingerprint = ''
        if parent_key == '':
            _fingerprint = fingerprint
        _network = Network.get_mainchain(network)
        util = get_util()
        with util.create_handle() as handle:
            _extkey = util.call_func(
                'CfdCreateExtkey', handle.get_handle(),
                _network.value, key_type.value, parent_key,
                _fingerprint, key, chain_code, depth, number)
        return _extkey


class ExtPrivkey(Extkey):
    @classmethod
    def from_seed(cls, seed, network=Network.MAINNET):
        _seed = to_hex_string(seed)
        _network = Network.get_mainchain(network)
        util = get_util()
        with util.create_handle() as handle:
            _extkey = util.call_func(
                'CfdCreateExtkeyFromSeed', handle.get_handle(),
                _seed, _network.value, ExtKeyType.EXT_PRIVKEY.value)
        return ExtPrivkey(_extkey)

    @classmethod
    def create(
            cls, network, fingerprint, key, chain_code,
            depth, number, parent_key=''):
        _extkey = cls._create(
            cls, ExtKeyType.EXT_PRIVKEY, network, fingerprint, key,
            chain_code, depth, number, parent_key)
        return ExtPrivkey(_extkey)

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

    def get_path_data(self, bip32_path, key_type):
        path_data, child_key = self._get_path_data(
            bip32_path, key_type)
        if key_type == ExtKeyType.EXT_PRIVKEY:
            return path_data, ExtPrivkey(child_key)
        else:
            return path_data, ExtPubkey(child_key)


class ExtPubkey(Extkey):
    @classmethod
    def create(
            cls, network, fingerprint, key, chain_code,
            depth, number, parent_key=''):
        _extkey = cls._create(
            cls, ExtKeyType.EXT_PUBKEY, network, fingerprint, key,
            chain_code, depth, number, parent_key)
        return ExtPubkey(_extkey)

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

    def get_path_data(self, bip32_path):
        path_data, child_key = self._get_path_data(
            bip32_path, ExtKeyType.EXT_PUBKEY)
        return path_data, ExtPubkey(child_key)


class MnemonicLanguage(Enum):
    EN = 'en'
    ES = 'es'
    FR = 'fr'
    IT = 'it'
    JP = 'jp'
    ZH_CN = 'zhs'
    ZH_TW = 'zht'

    @classmethod
    def get(cls, language):
        if (isinstance(language, MnemonicLanguage)):
            return language
        else:
            _type = str(language).lower()
            for lang_data in MnemonicLanguage:
                if _type == lang_data.value:
                    return lang_data
            _type = str(language).upper()
            for lang_data in MnemonicLanguage:
                if _type == lang_data.name:
                    return lang_data
            if _type == 'ZHCN':
                return MnemonicLanguage.ZH_CN
            if _type == 'ZHTW':
                return MnemonicLanguage.ZH_TW
        raise CfdError(
            error_code=1,
            message='Error: Invalid lang.')


class HDWallet:
    @classmethod
    ##
    # @brief get mnemonic word list.
    # @param[in] language   language
    # @retval word_list     mnemonic word list
    def get_mnemonic_word_list(cls, language):
        util = get_util()
        _lang = MnemonicLanguage.get(language).value
        word_list = []
        with util.create_handle() as handle:
            word_handle, max_index = util.call_func(
                'CfdInitializeMnemonicWordList', handle.get_handle(), _lang)
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeMnemonicWordList') as mnemonic_handle:
                for i in range(max_index):
                    word = util.call_func(
                        'CfdGetMnemonicWord',
                        handle.get_handle(), mnemonic_handle.get_handle(), i)
                    word_list.append(word)
        return word_list

    @classmethod
    def get_mnemonic(cls, entropy, language):
        _entropy = to_hex_string(entropy)
        _lang = MnemonicLanguage.get(language).value
        util = get_util()
        with util.create_handle() as handle:
            mnemonic = util.call_func(
                'CfdConvertEntropyToMnemonic',
                handle.get_handle(), _entropy, _lang)
            return mnemonic

    @classmethod
    def get_entropy(cls, mnemonic, language, strict_check=True):
        _mnemonic = cls._convert_mnemonic(mnemonic)
        _lang = MnemonicLanguage.get(language).value
        _mnemonic = unicodedata.normalize('NFKD', _mnemonic)
        util = get_util()
        with util.create_handle() as handle:
            _, entropy = util.call_func(
                'CfdConvertMnemonicToSeed', handle.get_handle(),
                _mnemonic, '', strict_check, _lang, False)
            return entropy

    @classmethod
    def from_seed(cls, seed, network=Network.MAINNET):
        return HDWallet(seed=seed, network=network)

    @classmethod
    def from_mnemonic(
            cls, mnemonic, language='en', passphrase='',
            network=Network.MAINNET, strict_check=True):
        return HDWallet(
            mnemonic=mnemonic, language=language,
            passphrase=passphrase, network=network, strict_check=strict_check)

    def __init__(
            self, seed='', mnemonic='', language='en', passphrase='',
            network=Network.MAINNET, strict_check=True):
        self.seed = to_hex_string(seed)
        self.network = Network.get_mainchain(network)
        _mnemonic = self._convert_mnemonic(mnemonic)
        _lang = MnemonicLanguage.get(language).value
        _mnemonic = unicodedata.normalize('NFKD', _mnemonic)
        _passphrase = unicodedata.normalize('NFKD', passphrase)
        if _mnemonic != '':
            util = get_util()
            with util.create_handle() as handle:
                self.seed, _ = util.call_func(
                    'CfdConvertMnemonicToSeed',
                    handle.get_handle(), _mnemonic, _passphrase,
                    strict_check, _lang, False)
        self.ext_privkey = ExtPrivkey.from_seed(self.seed, self.network)

    def get_privkey(self, path='', number=0, number_list=[]):
        return self.ext_privkey.derive(path, number, number_list)

    def get_pubkey(self, path='', number=0, number_list=[]):
        return self.ext_privkey.derive_pubkey(path, number, number_list)

    @classmethod
    def _convert_mnemonic(cls, mnemonic):
        _words = ' '.join(mnemonic) if isinstance(mnemonic, list) else mnemonic
        return _words.replace('　', ' ') if isinstance(_words, str) else _words
