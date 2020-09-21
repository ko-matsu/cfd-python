# -*- coding: utf-8 -*-
##
# @file hdwallet.py
# @brief hdwallet function implements file.
# @note Copyright 2020 CryptoGarage
from .util import get_util, JobHandle

##
# mnemonic's free function name.
FREE_FUNC_NAME = 'CfdFreeMnemonicWordList'


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
