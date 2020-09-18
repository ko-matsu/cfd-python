from cfd.address import create_p2pkh_address


PUBKEY = '027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af'


if __name__ == '__main__':
    addr, locking_script = create_p2pkh_address(PUBKEY)
    if addr != '1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn':
        print('invalid address: ' + addr)
    else:
        print('address: ' + addr)
    if locking_script != '76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac':
        print('invalid script: ' + locking_script)
    else:
        print('locking script: ' + locking_script)
