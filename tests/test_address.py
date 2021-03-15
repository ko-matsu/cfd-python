from unittest import TestCase
from tests.util import load_json_file, exec_test,\
    assert_equal, assert_error, assert_match
from cfd.address import AddressUtil
from cfd.key import Network, SchnorrPubkey, Privkey
from cfd.script import HashType, Script
from cfd.taproot import TapBranch, TaprootScriptTree
from cfd.util import CfdError, ByteData


def test_address_func(obj, name, case, req, exp, error):
    try:
        resp = None
        _network = req.get('network', 'mainnet')
        if req.get('isElements', False) and (
                _network.lower() == Network.REGTEST.as_str()):
            _network = Network.ELEMENTS_REGTEST

        if name == 'Address.Create':
            _hash_type = HashType.get(req['hashType'])
            if _hash_type == HashType.P2PKH:
                resp = AddressUtil.p2pkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2WPKH:
                resp = AddressUtil.p2wpkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH_P2WPKH:
                resp = AddressUtil.p2sh_p2wpkh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH:
                resp = AddressUtil.p2sh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2WSH:
                resp = AddressUtil.p2wsh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.P2SH_P2WSH:
                resp = AddressUtil.p2sh_p2wsh(
                    req['keyData']['hex'], network=_network)
            elif _hash_type == HashType.TAPROOT:
                resp = AddressUtil.taproot(
                    req['keyData']['hex'], network=_network)
        elif name == 'Address.GetInfo':
            resp = AddressUtil.parse(req['address'])
        elif name == 'Address.MultisigAddresses':
            resp = AddressUtil.get_multisig_address_list(
                req['redeemScript'], req['hashType'], network=_network)
        elif name == 'Address.CreateMultisig':
            resp = AddressUtil.multisig(
                req['nrequired'],
                req['keys'], req['hashType'], network=_network)

        elif name == 'Address.FromLockingScript':
            resp = AddressUtil.from_locking_script(
                req['lockingScript'], network=_network)

        elif name == 'Address.GetTapScriptTreeInfo':
            resp = {}
            nodes = []
            for node in req['tree'][1:]:
                if 'tapscript' in node:
                    nodes.append(Script(node['tapscript']))
                elif 'treeString' in node:
                    nodes.append(TapBranch(tree_str=node['treeString']))
                else:
                    nodes.append(ByteData(node['branchHash']))
            pk = None if 'internalPubkey' not in req else SchnorrPubkey(
                req['internalPubkey'])
            if 'tapscript' in req['tree'][0]:
                tree = TaprootScriptTree.create(
                    Script(req['tree'][0]['tapscript']), nodes, pk)
                if 'internalPubkey' not in req:
                    tapleaf_hash = tree.get_root_hash()
                    resp = {
                        'tapLeafHash': tapleaf_hash,
                        'tapscript': tree.tapscript,
                    }
                else:
                    tap_data = tree.get_taproot_data()
                    addr = AddressUtil.taproot(tree, network=_network)
                    resp = {
                        'tapLeafHash': tap_data[1],
                        'tapscript': tap_data[2],
                        'tweakedPubkey': tap_data[0],
                        'controlBlock': tap_data[3],
                        'address': addr.address,
                        'lockingScript': addr.locking_script,
                    }
                if 'internalPrivkey' in req:
                    tweak_privkey = tree.get_privkey(
                        Privkey(hex=req['internalPrivkey']))
                    resp['tweakedPrivkey'] = tweak_privkey
                nodes = []
                for node in tree.branches:
                    if isinstance(node, TapBranch):
                        nodes.append(node.get_current_hash())
                    else:
                        nodes.append(str(node))
                resp['nodes'] = nodes
            elif 'treeString' in node:
                tree = TapBranch(tree_str=node['treeString'])
            else:
                tree = TapBranch(ByteData(node['branchHash']))
            resp['topBranchHash'] = tree.get_current_hash()
            resp['treeString'] = tree.as_str()

        elif name == 'Address.GetTapScriptTreeInfoByControlBlock':
            tree = TaprootScriptTree.from_control_block(
                ByteData(req['controlBlock']),
                Script(req['tapscript']))
            tap_data = tree.get_taproot_data()
            addr = AddressUtil.taproot(tree, network=_network)
            resp = {
                'tapLeafHash': tap_data[1],
                'tweakedPubkey': tap_data[0],
                'controlBlock': tap_data[3],
                'tapscript': tap_data[2],
                'address': addr.address,
                'lockingScript': addr.locking_script,
            }
            resp['topBranchHash'] = tree.get_current_hash()
            resp['treeString'] = tree.as_str()
            nodes = []
            for node in tree.branches:
                if isinstance(node, TapBranch):
                    nodes.append(node.get_current_hash())
                else:
                    nodes.append(str(node))
            resp['nodes'] = nodes
            if 'internalPrivkey' in req:
                tweak_privkey = tree.get_privkey(
                    Privkey(hex=req['internalPrivkey']))
                resp['tweakedPrivkey'] = tweak_privkey

        elif name == 'Address.GetTapScriptTreeFromString':
            resp = {}
            if 'tapscript' in req:
                nodes = [ByteData(node) for node in req.get('nodes', [])]
                pk = None if 'internalPubkey' not in req else SchnorrPubkey(
                    req['internalPubkey'])
                tree = TaprootScriptTree.from_string(
                    req['treeString'], Script(req['tapscript']), nodes, pk)
                if pk is not None:
                    tap_data = tree.get_taproot_data()
                    addr = AddressUtil.taproot(tree, network=_network)
                    resp = {
                        'tweakedPubkey': tap_data[0],
                        'controlBlock': tap_data[3],
                        'address': addr.address,
                        'lockingScript': addr.locking_script,
                    }
                if 'internalPrivkey' in req:
                    tweak_privkey = tree.get_privkey(
                        Privkey(hex=req['internalPrivkey']))
                    resp['tweakedPrivkey'] = tweak_privkey
                resp['tapLeafHash'] = tree.get_root_hash()
                resp['tapscript'] = tree.tapscript
                nodes = []
                for node in tree.branches:
                    if isinstance(node, TapBranch):
                        nodes.append(node.get_current_hash())
                    else:
                        nodes.append(str(node))
                resp['nodes'] = nodes
            else:
                tree = TapBranch(tree_str=req['treeString'])
            resp['topBranchHash'] = tree.get_current_hash()
            resp['treeString'] = tree.as_str()

        else:
            raise Exception('unknown name: ' + name)
        assert_error(obj, name, case, error)

        if isinstance(resp, dict):
            for key, val in resp.items():
                if isinstance(val, list):
                    assert_match(obj, name, case, len(exp[key]),
                                 len(val), f'{key}:Len')
                    for index, list_val in enumerate(val):
                        assert_match(obj, name, case, str(exp[key][index]),
                                     str(list_val), f'{key}:{index}')
                else:
                    assert_equal(obj, name, case, exp, val, key)
        elif isinstance(resp, list):
            assert_match(obj, name, case, len(exp['addresses']),
                         len(resp), 'addressLen')
            if 'pubkeys' in exp:
                assert_match(obj, name, case, len(exp['pubkeys']),
                             len(resp), 'pubkeyLen')
            for index, addr in enumerate(resp):
                assert_match(obj, name, case, exp['addresses'][index],
                             str(addr), 'address')
                assert_match(obj, name, case, exp['pubkeys'][index],
                             str(addr.pubkey), 'pubkey')
        else:
            assert_equal(obj, name, case, exp, str(resp), 'address')
            if name == 'Address.CreateMultisig':
                if ('redeemScript' in exp) and ('witnessScript' in exp):
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'witnessScript')
                    assert_equal(obj, name, case, exp,
                                 resp.p2sh_wrapped_script, 'redeemScript')
                elif 'witnessScript' in exp:
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'witnessScript')
                else:
                    assert_equal(obj, name, case, exp,
                                 resp.redeem_script, 'redeemScript')

            elif name == 'Address.Create':
                assert_equal(obj, name, case, exp,
                             resp.p2sh_wrapped_script, 'redeemScript')

            if resp.network == Network.ELEMENTS_REGTEST:
                assert_match(obj, name, case,
                             Network.ELEMENTS_REGTEST.as_str(),
                             resp.network.as_str(), 'network')
            else:
                assert_equal(obj, name, case, exp,
                             resp.network.as_str(), 'network')

            assert_equal(obj, name, case, exp,
                         resp.locking_script, 'lockingScript')
            assert_equal(obj, name, case, exp,
                         resp.hash_type.as_str(), 'hashType')
            assert_equal(obj, name, case, exp,
                         resp.witness_version, 'witnessVersion')

    except CfdError as err:
        if not error:
            raise err
        assert_equal(obj, name, case, exp, err.message)


class TestAddress(TestCase):
    def setUp(self):
        self.test_list = load_json_file('address_test.json')

    def test_address(self):
        exec_test(self, 'Address', test_address_func)
