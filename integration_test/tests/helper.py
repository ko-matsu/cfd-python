from bitcoinrpc.authproxy import AuthServiceProxy
import time


LISTUNSPENT_MAX = 9999999


class RpcWrapper:
    def __init__(self, host='127.0.0.1', port=8432,
                 rpc_user='', rpc_password='', wallet_name=''):
        if wallet_name != '':
            self.rpc_connection = AuthServiceProxy('http://{}:{}@{}:{}/wallet/{}'.format(
                rpc_user, rpc_password, host, port, wallet_name))
        else:
            self.rpc_connection = AuthServiceProxy('http://{}:{}@{}:{}'.format(
                rpc_user, rpc_password, host, port))

    def command(self, command, *args):
        return self.rpc_connection.command(args)

    def get_rpc(self):
        return self.rpc_connection


def get_utxo(conn, address_list=[]):
    return conn.listunspent(0, LISTUNSPENT_MAX, address_list)


def long_sleep(btc_rpc, sleep_time):
    count = int(sleep_time/10)
    last_sleep = int(sleep_time % 10)
    for i in range(count):
        btc_rpc.ping()
        time.sleep(10)

    if last_sleep >= 1:
        time.sleep(last_sleep)
    return
