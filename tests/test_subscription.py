"""Synthetic fixtures only; no subscription fetches or live networking."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
from urllib.parse import urlencode
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'headless_vpn' / 'subscription.py'
UUID = '11111111-1111-4111-8111-111111111111'
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
URI = f'vless://{UUID}@example.com:443'


def api():
    # A missing implementation is an assertion failure in the initial RED run.
    assert SOURCE.is_file(), 'subscription parser is not implemented'
    spec = importlib.util.spec_from_file_location('subscription_under_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def outbound():
    return {'protocol': 'vless', 'settings': {'vnext': [{'address': 'example.com', 'port': 443,
            'users': [{'id': UUID, 'encryption': 'none'}]}]},
            'streamSettings': {'network': 'tcp', 'security': 'none'}}


class SubscriptionTests(unittest.TestCase):
    def test_plain_vless_has_no_imported_tag(self):
        self.assertEqual(api().parse_subscription((URI + '#private-label').encode()), [outbound()])

    def test_plain_and_base64_lists_preserve_order(self):
        data = (URI + '\n\n' + URI.replace('example.com', 'second.example') + '\n').encode()
        expected = [outbound(), outbound()]
        expected[1]['settings']['vnext'][0]['address'] = 'second.example'
        for encoded in (data, base64.b64encode(data), base64.urlsafe_b64encode(data).rstrip(b'=')):
            with self.subTest(encoding=encoded[:4]):
                self.assertEqual(api().parse_subscription(encoded), expected)

    def test_invalid_payload_and_endpoint_are_redacted(self):
        mod = api()
        bad = [b'', b'  ', b'<html>private-secret</html>', b'\xff', b'A' * (4 * 1024 * 1024 + 1),
               b'not-a-subscription', base64.b64encode(b'<html>private-secret</html>'),
               (URI + '?type=tcp&type=ws').encode(), (URI + '?private-secret=x').encode(),
               URI.replace(':443', ':0').encode(), URI.replace(':443', ':65536').encode(),
               URI.replace(':443', ':secret-port').encode(), URI.replace(':443', '').encode(),
               URI.replace(UUID, 'private-secret').encode(), URI.replace('vless:', 'vmess:').encode(),
               (URI + '/unmapped-path').encode(), (URI + '?type=%ZZ').encode(),
               URI.replace('@', ':password@').encode(), URI.replace('example.com', '').encode()]
        for payload in bad:
            with self.subTest(case=bad.index(payload)):
                with self.assertRaises(mod.SubscriptionError) as caught:
                    mod.parse_subscription(payload)
                self.assertNotIn('private-secret', str(caught.exception))
                self.assertNotIn(UUID, str(caught.exception))
                self.assertNotIn('vless://', str(caught.exception))

    def test_reality_uri_preserves_credentials_and_aliases(self):
        for key in ('pbk', 'publicKey', 'password'):
            with self.subTest(alias=key):
                value = api().parse_subscription((URI + f'?type=raw&security=reality&{key}={KEY}'
                    '&fp=chrome&sni=cover.example&sid=ab12&spx=%2Fscan&flow=xtls-rprx-vision'
                    '&encryption=none').encode())[0]
                self.assertEqual(value['streamSettings'], {'network': 'tcp', 'security': 'reality',
                    'realitySettings': {'publicKey': KEY, 'fingerprint': 'chrome',
                    'serverName': 'cover.example', 'shortId': 'ab12', 'spiderX': '/scan'}})
                self.assertEqual(value['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')

    def test_reality_hybrid_support_hint_maps_to_native_xray_behavior(self):
        for transport in ('tcp', 'xhttp'):
            query = {'type': transport, 'security': 'reality', 'pbk': KEY,
                     'fp': 'chrome', 'sni': 'cover.example', 'support-x25519mlkem768': 'true'}
            parsed = api().parse_subscription((URI + '?' + urlencode(query)).encode())[0]
            self.assertEqual(parsed['streamSettings']['realitySettings'],
                             {'publicKey': KEY, 'fingerprint': 'chrome', 'serverName': 'cover.example'})
            self.assertEqual(parsed['streamSettings']['network'], transport)

    def test_hybrid_hint_rejects_disabling_malformed_or_non_reality(self):
        mod = api()
        cases = [('reality', 'false'), ('reality', '1'), ('reality', ''),
                 ('reality', 'anything'), ('tls', 'true'), ('none', 'true')]
        for security, flag in cases:
            query = {'type': 'tcp', 'security': security, 'support-x25519mlkem768': flag}
            if security == 'reality': query['pbk'] = KEY
            with self.subTest(security=security, flag=flag), self.assertRaises(mod.SubscriptionError):
                mod.parse_subscription((URI + '?' + urlencode(query)).encode())

    def test_ws_grpc_xhttp_tls_uri_mapping(self):
        cases = [('ws', 'path=%2Fsocket&host=cdn.example', 'wsSettings',
                  {'path': '/socket', 'host': 'cdn.example'}),
                 ('grpc', 'serviceName=svc&authority=cdn.example&mode=multi', 'grpcSettings',
                  {'serviceName': 'svc', 'authority': 'cdn.example', 'multiMode': True}),
                 ('xhttp', 'path=%2Fx&host=cdn.example&mode=stream-up', 'xhttpSettings',
                  {'path': '/x', 'host': 'cdn.example', 'mode': 'stream-up'})]
        for network, query, settings, expected in cases:
            with self.subTest(network=network):
                result = api().parse_subscription((URI + '?type=' + network + '&security=tls&'
                    'sni=cover.example&fp=firefox&alpn=h2%2Chttp%2F1.1&' + query).encode())[0]
                stream = result['streamSettings']
                self.assertEqual(stream[settings], expected)
                self.assertEqual(stream['tlsSettings'], {'serverName': 'cover.example',
                    'fingerprint': 'firefox', 'alpn': ['h2', 'http/1.1']})

    def test_transport_security_options_fail_closed(self):
        mod = api()
        queries = ['type=kcp', 'security=xtls', 'type=tcp&headerType=http', 'type=tcp&host=x',
                   'security=none&sni=x', 'security=tls&allowInsecure=1',
                   'security=reality&pbk=bad', 'security=reality&pbk=' + KEY + '&sid=abc',
                   'security=reality&pbk=' + KEY + '&fp=bad',
                   'security=reality&pbk=' + KEY + '&password=' + KEY,
                   'type=ws&security=reality&pbk=' + KEY,
                   'type=grpc&mode=bad', 'type=xhttp&mode=bad',
                   'type=ws&flow=xtls-rprx-vision', 'flow=bogus', 'encryption=auto',
                   'security=reality&pbk=' + KEY + '&spx=relative', 'type=ws&path=%0D%0AX-Evil:x']
        for query in queries:
            with self.subTest(case=queries.index(query)):
                with self.assertRaises(mod.SubscriptionError):
                    mod.parse_subscription((URI + '?' + query).encode())

    def test_json_outbound_config_and_list_strip_untrusted_config(self):
        node = outbound()
        node['tag'] = 'untrusted-tag'
        node['streamSettings']['sockopt'] = {'interface': 'untrusted-tun'}
        config = {'inbounds': [{'listen': '0.0.0.0', 'port': 80}],
                  'routing': {'domainStrategy': 'AsIs'}, 'log': {'access': '/untrusted'},
                  'outbounds': [node, {'protocol': 'freedom', 'tag': 'direct'},
                                {'protocol': 'blackhole', 'tag': 'block'},
                                {'protocol': 'dns', 'tag': 'dns-out'}]}
        for document in (node, config, [node], [config], {'outbounds': [node]}):
            with self.subTest(kind=type(document).__name__):
                self.assertEqual(api().parse_subscription(json.dumps(document).encode()), [outbound()])

    def test_json_settings_are_validated_not_copied_blindly(self):
        mod = api()
        edits = [('protocol', 'vmess'), ('mux', {'enabled': False}), ('proxySettings', {'tag': 'other'}),
                 ('sendThrough', '127.0.0.1'), ('streamSettings.sockopt', {'dialerProxy': 'other'}),
                 ('streamSettings.sockopt', {'mark': 1}), ('streamSettings.security', 'xtls'),
                 ('streamSettings.tlsSettings', {'certificates': [{'certificateFile': '/secret'}]}),
                 ('streamSettings', None), ('settings', []), ('settings.vnext', []),
                 ('settings.vnext.0.address', 'https://private-secret'),
                 ('settings.vnext.0.port', True), ('settings.vnext.0.port', '443'),
                 ('settings.vnext.0.port', 65536), ('settings.vnext.0.users.0.id', 'invalid-id'),
                 ('settings.vnext.0.users.0.encryption', 'auto'),
                 ('settings.vnext.0.users.0.reverse', {'tag': 'r'}),
                 ('settings.vnext.0.users.0.flow', 'xtls-rprx-vision')]
        for path, value in edits:
            node = outbound()
            target = node
            parts = path.split('.')
            for part in parts[:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            target[parts[-1]] = value
            with self.subTest(path=path):
                with self.assertRaises(mod.SubscriptionError):
                    mod.parse_subscription(json.dumps(node).encode())
        for document in ([], {}, {'outbounds': []}, {'outbounds': [{'protocol': 'vmess'}]},
                         {'protocol': 'freedom'}, [outbound(), {'protocol': 'freedom'}]):
            with self.subTest(document_type=type(document).__name__):
                with self.assertRaises(mod.SubscriptionError):
                    mod.parse_subscription(json.dumps(document).encode())
        with self.assertRaises(mod.SubscriptionError):
            mod.parse_subscription(b'{"outbounds":[],"outbounds":[]}')

    def test_reality_structured_text_values_fail_with_safe_parser_error(self):
        mod = api()
        for field in ('spiderX', 'serverName', 'shortId', 'fingerprint'):
            node = outbound()
            node['streamSettings'] = {'network': 'tcp', 'security': 'reality',
                'realitySettings': {'publicKey': KEY, field: []}}
            with self.subTest(field=field), self.assertRaises(mod.SubscriptionError):
                mod.parse_subscription(json.dumps(node).encode())

    def test_json_reality_password_and_flat_vless_settings(self):
        node = outbound()
        node['settings'] = {'address': 'example.com', 'port': 443, 'id': UUID,
                            'encryption': 'none', 'flow': 'xtls-rprx-vision'}
        node['streamSettings'] = {'network': 'raw', 'security': 'reality',
                                 'realitySettings': {'password': KEY, 'fingerprint': 'chrome',
                                                     'shortId': '', 'spiderX': '/'},
                                 'rawSettings': {'header': {'type': 'none'}}}
        result = api().parse_subscription(json.dumps(node).encode())[0]
        self.assertEqual(result['streamSettings']['realitySettings'], node['streamSettings']['realitySettings'])
        self.assertEqual(result['streamSettings']['network'], 'tcp')
        self.assertEqual(result['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')

    def test_xhttp_extra_known_safe_settings_are_preserved(self):
        extra = {'xPaddingBytes': '100-1000', 'noGRPCHeader': True, 'noSSEHeader': False,
                 'scMaxEachPostBytes': 1000000, 'scMinPostsIntervalMs': '10-50',
                 'scMaxBufferedPosts': 30, 'scStreamUpServerSecs': '20-80',
                 'headers': {'User-Agent': 'Synthetic-Test'},
                 'xmux': {'maxConcurrency': '16-32', 'cMaxReuseTimes': 0,
                          'hMaxRequestTimes': '600-900', 'hMaxReusableSecs': '1800-3000',
                          'hKeepAlivePeriod': 0}}
        for security in ('tls', 'reality'):
            query = {'type': 'xhttp', 'security': security, 'mode': 'auto', 'path': '/x',
                     'sni': 'cover.example', 'fp': 'chrome', 'extra': json.dumps(extra)}
            if security == 'reality':
                query['pbk'] = KEY
            node = api().parse_subscription((URI + '?' + urlencode(query)).encode())[0]
            self.assertEqual(node['streamSettings']['xhttpSettings']['extra'], extra)
            self.assertEqual(api().parse_subscription(json.dumps(node).encode()), [node])

    def test_xhttp_extra_redundant_mode_is_preserved(self):
        # Provider emits mode both at top level and inside extra.
        for mode in ('auto', 'packet-up', 'stream-up', 'stream-one'):
            query = urlencode({'type': 'xhttp', 'mode': mode,
                               'extra': json.dumps({'mode': mode})})
            node = api().parse_subscription((URI + '?' + query).encode())[0]
            self.assertEqual(node['streamSettings']['xhttpSettings'],
                             {'mode': mode, 'extra': {'mode': mode}})
            self.assertEqual(api().parse_subscription(json.dumps(node).encode()), [node])

    def test_xhttp_extra_invalid_or_conflicting_mode_rejected(self):
        mod = api()
        for mode in ('bogus', 'stream-one', True, [], None):
            query = urlencode({'type': 'xhttp', 'mode': 'auto',
                               'extra': json.dumps({'mode': mode})})
            with self.subTest(mode=mode), self.assertRaises(mod.SubscriptionError):
                mod.parse_subscription((URI + '?' + query).encode())

    def test_xhttp_extra_rejects_nested_dialers_and_unknown_semantics(self):
        mod = api()
        bad = [{'downloadSettings': {'sockopt': {'dialerProxy': 'x'}}}, {'unknown': True},
               {'extra': {}}, {'mux': {}}, {'host': 'overridden'}, {'path': '/overridden'},
               {'noGRPCHeader': 'true'}, {'xPaddingBytes': '0-10'},
               {'xPaddingBytes': 2147483648}, {'scMaxBufferedPosts': -1},
               {'headers': {'Host': 'other.example'}}, {'headers': {'X-Test': 'bad\r\n'}},
               {'xmux': {'maxConnections': 2, 'maxConcurrency': 2}},
               {'xmux': {'dialerProxy': 'bad'}}, {'xmux': {'maxConnections': -1}},
               {'sessionIDTable': 'A'}, [], 'invalid', None]
        for extra in bad:
            with self.subTest(case=bad.index(extra)):
                query = urlencode({'type': 'xhttp', 'extra': json.dumps(extra)})
                with self.assertRaises(mod.SubscriptionError):
                    mod.parse_subscription((URI + '?' + query).encode())
        query = urlencode({'type': 'xhttp', 'extra': '{"noGRPCHeader":true,"noGRPCHeader":false}'})
        with self.assertRaises(mod.SubscriptionError):
            mod.parse_subscription((URI + '?' + query).encode())


if __name__ == '__main__':
    unittest.main()
