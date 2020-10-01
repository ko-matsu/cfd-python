# -*- coding: utf-8 -*-
##
# @file key.py
# @brief key function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util, CfdError, to_hex_string, CfdErrorCode, JobHandle
from enum import Enum


##
# @class Network
# @brief Network Type
class Network(Enum):
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
    # @brief get string.
    # @return name.
    def __repr__(self):
        return self.name.lower().replace('_', '')

    ##
    # @brief get string.
    # @return name.
    def as_str(self):
        return self.name.lower().replace('_', '')

    @classmethod
    def get(cls, network):
        if (isinstance(network, Network)):
            return network
        elif (isinstance(network, int)):
            _num = int(network)
            for net in Network:
                if _num == net.value:
                    return net
        else:
            _network = str(network).lower()
            for net in Network:
                if _network == net.name.lower():
                    return net
            if _network == 'liquidv1':
                return Network.LIQUID_V1
            elif _network in {'elementsregtest', 'liquidregtest'}:
                return Network.ELEMENTS_REGTEST
        raise CfdError(
            error_code=1,
            message='Error: Invalid network type.')

    @classmethod
    def get_mainchain(cls, network):
        _network = cls.get(network)
        if _network == Network.LIQUID_V1:
            _network = Network.MAINNET
        elif _network in {Network.ELEMENTS_REGTEST, Network.CUSTOM_CHAIN}:
            _network = Network.TESTNET
        return _network


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

    ##
    # @brief get string.
    # @return name.
    def __repr__(self):
        return self.name.lower().replace('_', '')

    ##
    # @brief get string.
    # @return name.
    def as_str(self):
        return self.name.lower().replace('_', '')

    def get_type(self):
        return self.value & 0x0f

    def anyone_can_pay(self):
        return self.value >= 0x80

    @classmethod
    def get(cls, sighashtype, anyoneCanPay=False):
        if (isinstance(sighashtype, SigHashType)):
            if anyoneCanPay is True:
                return cls.get(sighashtype.value | 0x80)
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
    # @brief generate key pair.
    # @param[in] is_compressed  pubkey compressed
    # @param[in] network        network type
    @classmethod
    def generate(cls, is_compressed=True, network=Network.MAINNET):
        _network = Network.get_mainchain(network)
        util = get_util()
        with util.create_handle() as handle:
            pubkey, privkey, wif = util.call_func(
                'CfdGetPrivkeyWif', handle.get_handle(),
                is_compressed, _network.value)
            return Privkey(wif=wif), Pubkey(pubkey)

    ##
    # @brief constructor.
    # @param[in] wif            wif
    # @param[in] hex            hex
    # @param[in] network        network
    # @param[in] is_compressed  pubkey compressed
    def __init__(
            self,
            wif='',
            hex='',
            network=Network.MAINNET,
            is_compressed=True):
        self.hex = to_hex_string(hex)
        self.wif = wif
        self.network = Network.get_mainchain(network)
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
                self.network = Network.get_mainchain(self.network)
            self.pubkey = util.call_func(
                'CfdGetPubkeyFromPrivkey', handle.get_handle(),
                self.hex, '', self.is_compressed)

    ##
    # @brief get string.
    # @return pubkey hex.
    def __repr__(self):
        return self.wif if (self.wif_first) else self.hex

    def add_tweak(self, tweak):
        _tweak = to_hex_string(tweak)
        util = get_util()
        with util.create_handle() as handle:
            _key = util.call_func(
                'CfdPrivkeyTweakAdd', handle.get_handle(),
                self.hex, _tweak)
            return Privkey(
                hex=_key, network=self.network,
                is_compressed=self.is_compressed)

    def mul_tweak(self, tweak):
        _tweak = to_hex_string(tweak)
        util = get_util()
        with util.create_handle() as handle:
            _key = util.call_func(
                'CfdPrivkeyTweakMul', handle.get_handle(),
                self.hex, _tweak)
            return Privkey(
                hex=_key, network=self.network,
                is_compressed=self.is_compressed)

    def negate(self):
        util = get_util()
        with util.create_handle() as handle:
            _key = util.call_func(
                'CfdNegatePrivkey', handle.get_handle(), self.hex)
            return Privkey(
                hex=_key, network=self.network,
                is_compressed=self.is_compressed)

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
    # @var _hex
    # pubkey hex

    @classmethod
    def combine(cls, pubkey_list):
        if (isinstance(pubkey_list, list) is False) or (
                len(pubkey_list) == 0):
            raise CfdError(
                error_code=1,
                message='Error: Invalid pubkey list.')
        util = get_util()
        with util.create_handle() as handle:
            word_handle = util.call_func(
                'CfdInitializeCombinePubkey', handle.get_handle())
            with JobHandle(
                    handle,
                    word_handle,
                    'CfdFreeCombinePubkeyHandle') as key_handle:
                for pubkey in pubkey_list:
                    util.call_func(
                        'CfdAddCombinePubkey',
                        handle.get_handle(), key_handle.get_handle(),
                        to_hex_string(pubkey))

                _key = util.call_func(
                    'CfdFinalizeCombinePubkey',
                    handle.get_handle(), key_handle.get_handle())
                return Pubkey(_key)

    ##
    # @brief constructor.
    # @param[in] pubkey     pubkey
    def __init__(self, pubkey):
        self._hex = to_hex_string(pubkey)
        # validate
        util = get_util()
        with util.create_handle() as handle:
            util.call_func(
                'CfdCompressPubkey', handle.get_handle(), self._hex)

    ##
    # @brief get string.
    # @return pubkey hex.
    def __repr__(self):
        return self._hex

    def compress(self):
        util = get_util()
        with util.create_handle() as handle:
            _pubkey = util.call_func(
                'CfdCompressPubkey', handle.get_handle(), self._hex)
        return Pubkey(_pubkey)

    def uncompress(self):
        util = get_util()
        with util.create_handle() as handle:
            _pubkey = util.call_func(
                'CfdUncompressPubkey', handle.get_handle(), self._hex)
        return Pubkey(_pubkey)

    def add_tweak(self, tweak):
        _tweak = to_hex_string(tweak)
        util = get_util()
        with util.create_handle() as handle:
            _pubkey = util.call_func(
                'CfdPubkeyTweakAdd', handle.get_handle(),
                self._hex, _tweak)
            return Pubkey(_pubkey)

    def mul_tweak(self, tweak):
        _tweak = to_hex_string(tweak)
        util = get_util()
        with util.create_handle() as handle:
            _pubkey = util.call_func(
                'CfdPubkeyTweakMul', handle.get_handle(),
                self._hex, _tweak)
            return Pubkey(_pubkey)

    def negate(self):
        util = get_util()
        with util.create_handle() as handle:
            _pubkey = util.call_func(
                'CfdNegatePubkey', handle.get_handle(), self._hex)
            return Pubkey(_pubkey)

    def verify_ec_signature(self, sighash, signature):
        try:
            util = get_util()
            with util.create_handle() as handle:
                util.call_func(
                    'CfdVerifyEcSignature', handle.get_handle(),
                    sighash, self._hex, signature)
            return True
        except CfdError as err:
            if err.error_code == CfdErrorCode.SIGN_VERIFICATION.value:
                return False
            else:
                raise err


class SignParameter:
    def __init__(self, data, related_pubkey='', sighashtype=SigHashType.ALL):
        self.hex = to_hex_string(data)
        self.related_pubkey = related_pubkey
        self.sighashtype = SigHashType.get(sighashtype)
        self.use_der_encode = False

    ##
    # @brief get string.
    # @return sing data hex.
    def __repr__(self):
        return self.hex

    def set_der_encode(self):
        self.use_der_encode = True

    @classmethod
    def encode_by_der(cls, signature, sighashtype=SigHashType.ALL):
        _signature = to_hex_string(signature)
        _sighashtype = SigHashType.get(sighashtype)
        util = get_util()
        with util.create_handle() as handle:
            der_signature = util.call_func(
                'CfdEncodeSignatureByDer', handle.get_handle(),
                _signature, _sighashtype.get_type(),
                _sighashtype.anyone_can_pay())
        return SignParameter(der_signature, '', _sighashtype)

    @classmethod
    def decode_from_der(cls, signature):
        der_signature = to_hex_string(signature)
        util = get_util()
        with util.create_handle() as handle:
            _signature, sighashtype, anyone_can_pay = util.call_func(
                'CfdDecodeSignatureFromDer', handle.get_handle(),
                der_signature)
            _sighashtype = SigHashType.get(sighashtype, anyone_can_pay)
        return SignParameter(_signature, '', _sighashtype)

    @classmethod
    def normalize(cls, signature):
        _signature = to_hex_string(signature)
        _sighashtype = SigHashType.ALL
        if isinstance(signature, SignParameter):
            _sighashtype = signature.sighashtype
        util = get_util()
        with util.create_handle() as handle:
            normalize_sig = util.call_func(
                'CfdNormalizeSignature', handle.get_handle(), _signature)
        return SignParameter(normalize_sig, '', _sighashtype)


class EcdsaAdaptor:
    @classmethod
    def sign(cls, message, secret_key, adaptor):
        _msg = to_hex_string(message)
        _sk = to_hex_string(secret_key)
        _adaptor = to_hex_string(adaptor)
        util = get_util()
        with util.create_handle() as handle:
            signature, proof = util.call_func(
                'CfdSignEcdsaAdaptor', handle.get_handle(),
                _msg, _sk, _adaptor)
        return signature, proof

    @classmethod
    def adapt(cls, adaptor_signature, adaptor_secret):
        _sig = to_hex_string(adaptor_signature)
        _sk = to_hex_string(adaptor_secret)
        util = get_util()
        with util.create_handle() as handle:
            signature = util.call_func(
                'CfdAdaptEcdsaAdaptor', handle.get_handle(), _sig, _sk)
        return signature

    @classmethod
    def extract_secret(cls, adaptor_signature, signature, adaptor):
        _adaptor_signature = to_hex_string(adaptor_signature)
        _signature = to_hex_string(signature)
        _adaptor = to_hex_string(adaptor)
        util = get_util()
        with util.create_handle() as handle:
            adaptor_secret = util.call_func(
                'CfdExtractEcdsaAdaptorSecret', handle.get_handle(),
                _adaptor_signature, _signature, _adaptor)
        return adaptor_secret

    @classmethod
    def verify(cls, adaptor_signature, proof, adaptor, message, pubkey):
        _adaptor_signature = to_hex_string(adaptor_signature)
        _proof = to_hex_string(proof)
        _adaptor = to_hex_string(adaptor)
        _msg = to_hex_string(message)
        _pk = to_hex_string(pubkey)
        util = get_util()
        with util.create_handle() as handle:
            try:
                util.call_func(
                    'CfdVerifyEcdsaAdaptor', handle.get_handle(),
                    _adaptor_signature, _proof, _adaptor, _msg, _pk)
            except CfdError as err:
                if err.error_code == CfdErrorCode.SIGN_VERIFICATION.value:
                    return False
                else:
                    raise err


class SchnorrPubkey:
    def from_privkey(cls, privkey):
        if isinstance(privkey, Privkey):
            _privkey = privkey.hex
        else:
            _privkey = to_hex_string(privkey)
        util = get_util()
        with util.create_handle() as handle:
            pubkey = util.call_func(
                'CfdGetSchnorrPubkeyFromPrivkey', handle.get_handle(),
                _privkey)
            return SchnorrPubkey(pubkey)

    def __init__(self, data):
        self.hex = to_hex_string(data)
        if len(self.hex) != 64:
            raise CfdError(
                error_code=1, message='Error: Invalid schnorr pubkey.')

    ##
    # @brief get string.
    # @return pubkey hex.
    def __repr__(self):
        return self.hex


class SchnorrSignature:
    def __init__(self, signature):
        self.signature = to_hex_string(signature)
        util = get_util()
        with util.create_handle() as handle:
            self.nonce, self.key = util.call_func(
                'CfdSplitSchnorrSignature', handle.get_handle(),
                self.signature)

    ##
    # @brief get string.
    # @return signature hex.
    def __repr__(self):
        return self.signature


class SchnorrUtil:
    @classmethod
    def sign(cls, message, secret_key, aux_rand='', nonce=''):
        _msg = to_hex_string(message)
        _sk = to_hex_string(secret_key)
        _rand = to_hex_string(aux_rand)
        _nonce = to_hex_string(nonce)
        util = get_util()
        with util.create_handle() as handle:
            if _nonce != '':
                signature = util.call_func(
                    'CfdSignSchnorrWithNonce', handle.get_handle(),
                    _msg, _sk, _nonce)
            else:
                signature = util.call_func(
                    'CfdSignSchnorr', handle.get_handle(), _msg, _sk, _rand)
        return SchnorrSignature(signature)

    @classmethod
    def compute_sig_point(cls, message, nonce, pubkey):
        _msg = to_hex_string(message)
        _nonce = to_hex_string(nonce)
        _pubkey = to_hex_string(pubkey)
        util = get_util()
        with util.create_handle() as handle:
            sig_point = util.call_func(
                'CfdComputeSchnorrSigPoint', handle.get_handle(),
                _msg, _nonce, _pubkey)
        return sig_point

    @classmethod
    def verify(cls, signature, message, pubkey):
        _signature = to_hex_string(signature)
        _msg = to_hex_string(message)
        _pk = to_hex_string(pubkey)
        util = get_util()
        with util.create_handle() as handle:
            try:
                util.call_func(
                    'CfdVerifySchnorr', handle.get_handle(),
                    _signature, _msg, _pk)
                return True
            except CfdError as err:
                if err.error_code == CfdErrorCode.SIGN_VERIFICATION.value:
                    return False
                else:
                    raise err
