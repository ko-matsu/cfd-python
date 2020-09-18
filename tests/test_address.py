from unittest import TestCase
from cfd.address import create_p2pkh_address

PUBKEY = '027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af'


class TestAddress(TestCase):
    def test_create_p2pkh_address(self):
        addr, locking_script = create_p2pkh_address(PUBKEY)
        self.assertEqual(addr, '1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn')
        self.assertEqual(
            locking_script,
            '76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac')
