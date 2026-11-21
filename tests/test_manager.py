"""Regression tests for real generation, routing and ownership behavior."""
import copy
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest

try:
    m = importlib.import_module('headless_vpn.manager')
except ModuleNotFoundError:
    m = None

NODE = {'protocol': 'vless', 'settings': {'vnext': [{'address': 'example.com', 'port': 443, 'users': [{'id': '11111111-1111-4111-8111-111111111111', 'encryption': 'none'}]}]}, 'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'serverName': 'example.com'}}}
TEMPLATE = {'inbounds': [{'type': 'tun', 'auto_route': True, 'address': ['172.18.0.1/30']}], 'outbounds': [{'type': 'socks', 'tag': 'proxy', 'server': '127.0.0.1', 'server_port': 10808}, {'type': 'direct', 'tag': 'direct'}], 'dns': {'servers': [{'tag': 'dns-proxy', 'address': '198.18.0.2', 'detour': 'proxy'}]}, 'route': {'auto_detect_interface': True, 'final': 'proxy', 'rules': []}}

class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(m, 'headless_vpn.manager not implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_physical_interface_ignores_happ_and_tun_defaults(self):
        routes = [{'dst':'default','dev':'happ-xray','metric':1}, {'dst':'default','dev':'tun0'}, {'dst':'default','gateway':'192.168.0.1','dev':'enp9s0','metric':100}]
        self.assertEqual(m.choose_interface(routes, lambda dev: dev == 'enp9s0'), 'enp9s0')
        with self.assertRaises(ValueError): m.choose_interface(routes[:2], lambda dev: False)

    def test_canonical_id_excludes_tag_and_local_interface(self):
        other = copy.deepcopy(NODE); other['tag'] = 'untrusted'; other['streamSettings']['sockopt'] = {'interface':'happ-xray'}
        self.assertEqual(m.node_id(other), m.node_id(NODE))
        other['settings']['vnext'][0]['port'] = 8443
        self.assertNotEqual(m.node_id(other), m.node_id(NODE))

    def test_collect_nodes_deduplicates_without_dropping_manual_ownership(self):
        catalog = m.empty_catalog()
        catalog['manual'][m.node_id(NODE)] = NODE
        catalog['subscriptions']['first'] = {'url':'https://example.com/secret','nodes':[NODE]}
        self.assertEqual(len(m.collect_nodes(catalog)),1)
        del catalog['subscriptions']['first']
        self.assertEqual(len(m.collect_nodes(catalog)),1)

    def test_xray_all_nodes_observed_even_single_and_no_direct_fallback(self):
        config = m.xray_config([NODE], 'enp9s0')
        self.assertEqual(config['inbounds'][0]['listen'],'127.0.0.1')
        self.assertNotIn('freedom', [o['protocol'] for o in config['outbounds']])
        balance = config['routing']['balancers'][0]
        self.assertEqual(balance['fallbackTag'], 'block')
        self.assertEqual(balance['strategy']['type'],'leastPing')
        self.assertEqual(config['observatory']['probeInterval'],'15s')
        self.assertEqual(config['outbounds'][0]['streamSettings']['sockopt']['interface'],'enp9s0')
        self.assertEqual(config['routing']['rules'][-1]['balancerTag'],'auto')

    def test_sing_dns_is_not_old_happ_fake_address(self):
        config = m.sing_config(TEMPLATE, 'enp9s0')
        self.assertEqual(config['outbounds'][0]['server_port'],10818)
        self.assertEqual(config['dns']['servers'][0]['address'],'https://1.1.1.1/dns-query')
        self.assertEqual(config['dns']['servers'][0]['detour'],'proxy')
        self.assertEqual(config['route']['default_interface'],'enp9s0')
        self.assertNotEqual(config['inbounds'][0]['address'],['172.18.0.1/30'])
        self.assertEqual(TEMPLATE['outbounds'][0]['server_port'],10808)

    def store(self, validator=None):
        return m.Store(self.root/'private', TEMPLATE, 'enp9s0', validator=validator or (lambda x,s: None))

    def catalog(self):
        c=m.empty_catalog();c['manual'][m.node_id(NODE)]=copy.deepcopy(NODE);return c

    def test_generation_commit_private_and_atomic(self):
        store=self.store(); c=self.catalog(); generation=store.commit(c)
        self.assertEqual(store.load(),c)
        self.assertTrue((store.root/'current').is_symlink())
        self.assertEqual((store.root/'current').resolve(),generation)
        self.assertEqual(store.root.stat().st_mode & 0o777,0o700)
        for p in generation.iterdir(): self.assertEqual(p.stat().st_mode & 0o777,0o600)

    def test_validation_failure_keeps_last_generation(self):
        store=self.store();old=store.commit(self.catalog())
        def reject(x,s): raise ValueError('invalid candidate')
        store.validator=reject
        changed=self.catalog();changed['subscriptions']['one']={'url':'https://example.com/token','nodes':[NODE]}
        with self.assertRaises(ValueError):store.commit(changed)
        self.assertEqual((store.root/'current').resolve(),old)
        self.assertEqual(store.load(),self.catalog())

    def test_directory_sync_failure_retains_readable_previous_generation(self):
        import stat
        from unittest.mock import patch
        store = self.store(); old = store.commit(self.catalog())
        changed = self.catalog()
        changed['subscriptions']['added'] = {'url': 'https://example.com/token', 'nodes': [NODE]}
        real_sync = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('simulated directory fsync failure')
            return real_sync(fd)
        with patch.object(m.os, 'fsync', side_effect=fail_directory):
            with self.assertRaises(OSError): store.commit(changed)
        self.assertEqual(store.current(), old)
        self.assertEqual(store.load(), self.catalog())

    def test_empty_configuration_rejected_before_publish(self):
        store=self.store();old=store.commit(self.catalog())
        with self.assertRaises(ValueError):store.commit(m.empty_catalog())
        self.assertEqual((store.root/'current').resolve(),old)

    def test_refresh_failed_fetch_keeps_old_subscription(self):
        c=m.empty_catalog();c['subscriptions']['one']={'url':'https://example.com/private','nodes':[NODE]}
        def fail(url):raise ValueError('upstream unavailable')
        fresh,errors=m.refreshed_catalog(c, fail, lambda b:[NODE], lambda nodes: True)
        self.assertEqual(fresh,c);self.assertEqual(errors,['one'])

    def test_refresh_unreachable_nodes_keeps_old_subscription(self):
        c=m.empty_catalog();c['subscriptions']['one']={'url':'https://example.com/private','nodes':[NODE]}
        replacement=copy.deepcopy(NODE);replacement['settings']['vnext'][0]['port']=8443
        fresh,errors=m.refreshed_catalog(c, lambda u:b'data', lambda b:[replacement], lambda nodes:False)
        self.assertEqual(fresh,c);self.assertEqual(errors,['one'])

    def test_refresh_replaces_source_not_unrelated_manual(self):
        c=self.catalog();c['subscriptions']['one']={'url':'https://example.com/private','nodes':[NODE]}
        replacement=copy.deepcopy(NODE);replacement['settings']['vnext'][0]['port']=8443
        fresh,errors=m.refreshed_catalog(c,lambda u:b'data',lambda b:[replacement],lambda nodes:True)
        self.assertEqual(errors,[]);self.assertEqual(len(m.collect_nodes(fresh)),2)
        self.assertEqual(c['subscriptions']['one']['nodes'],[NODE])

    def test_url_validation_rejects_insecure_or_credentials(self):
        for url in ['http://example.com/token','file:///etc/passwd','https://u:p@example.com/s','https://example.com/\nsecret']:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):m.validate_url(url)
        self.assertEqual(m.validate_url('https://example.com/token'),'https://example.com/token')

if __name__ == '__main__': unittest.main()
