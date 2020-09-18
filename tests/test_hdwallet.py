from unittest import TestCase
from cfd.hdwallet import get_mnemonic_word_list


class TestHDWallet(TestCase):
    def test_get_mnemonic_word_list(self):
        word_list = get_mnemonic_word_list('jp')
        self.assertEqual(word_list[0], 'あいこくしん')
        self.assertEqual(len(word_list), 2048)
