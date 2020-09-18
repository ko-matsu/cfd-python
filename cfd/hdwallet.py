from .util import get_util, JobHandle

FREE_FUNC_NAME = 'CfdFreeMnemonicWordList'


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
