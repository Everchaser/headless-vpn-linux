import unittest
from headless_vpn import cli, manager as m

URI = b'vless://11111111-1111-4111-8111-111111111111@vpn.example:443'

class HwidTests(unittest.TestCase):
    def test_opt_in_and_mixed_refresh(self):
        args = cli.parser().parse_args(['subscription','add','test','--url-stdin','--device-name','Home server'])
        self.assertEqual(args.device_name,'Home server')
        source = {'url':'https://fixture.example/token', 'device_name':'Home server','nodes':[]}
        calls = []
        def fetch(url, *, device_name):
            calls.append(device_name)
            return b'hysteria2://ignored@example.org:443\n'+URI
        from headless_vpn.subscription import parse_subscription
        fresh, errors = m.refreshed_catalog({'subscriptions':{'fixture':source}},fetch,parse_subscription,lambda nodes: bool(nodes))
        self.assertEqual(errors,[])
        self.assertEqual(calls,['Home server'])
        self.assertEqual(fresh['subscriptions']['fixture']['nodes'][0]['settings']['vnext'][0]['address'],'vpn.example')
        self.assertEqual(source['nodes'],[])
