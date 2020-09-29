from unittest import TestCase
from cfd.hdwallet import ExtPrivkey
from cfd.address import AddressUtil
from cfd.script import HashType
from cfd.key import NetworkType, SigHashType
from cfd.transaction import OutPoint, TxIn, TxOut, Transaction


class TestTransaction(TestCase):
    def test_create_raw_transaction(self):
        privkey = ExtPrivkey(
            'xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV')  # noqa: E501
        addr1 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=1).pubkey, NetworkType.REGTEST)
        addr2 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=2).pubkey, NetworkType.REGTEST)
        addr3 = AddressUtil.p2wpkh(
            privkey.derive_pubkey(number=3).pubkey, NetworkType.REGTEST)

        outpoint1 = OutPoint(
            '0000000000000000000000000000000000000000000000000000000000000001',
            2)
        outpoint2 = OutPoint(
            '0000000000000000000000000000000000000000000000000000000000000001',
            3)
        tx = Transaction.create(
            version=2,
            locktime=0,
            txins=[
                TxIn(outpoint=outpoint1),
                TxIn(outpoint=outpoint2),
            ],
            txouts=[
                TxOut(amount=10000, locking_script=addr1.locking_script),
                TxOut(amount=10000, locking_script=addr2.locking_script),
            ])
        tx.add_txout(amount=50000, address=addr3)
        self.assertEqual(
            "020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000",  # noqa: E501
            tx.hex)

        privkey1 = privkey.derive(number=11).privkey
        pubkey1 = privkey1.pubkey
        sighash_type = SigHashType.ALL
        sighash = tx.get_sighash(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            pubkey=pubkey1,
            amount=50000,
            sighashtype=sighash_type)
        signature = privkey1.calculate_ec_signature(sighash)
        tx.add_sign(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            sign_data=signature,
            clear_stack=True,
            use_der_encode=True,
            sighashtype=sighash_type)
        tx.add_sign(
            outpoint=outpoint1,
            hash_type=HashType.P2WPKH,
            sign_data=pubkey1)
        self.assertEqual(
            "0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000",  # noqa: E501
            tx.hex)

        addr11 = AddressUtil.p2wpkh(pubkey1, NetworkType.REGTEST)
        try:
            tx.verify_sign(
                outpoint=outpoint1,
                address=addr11,
                hash_type=addr11.hash_type,
                amount=50000)
        except Exception as err:
            self.assertIsNone(err)

        # type1
        # hdwallet
        # key
        # address
        # transaction

        # type2
        # descriptor
        # script
        # transaction
