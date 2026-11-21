import base64
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from headless_vpn import provider as p

URI = b'vless://11111111-1111-4111-8111-111111111111@vpn.example:443'
ALT = b'hysteria2://ignored@example.org:443'
BOM = b'\xef\xbb\xbf'

class SubscriptionReviewRegression(unittest.TestCase):
    def test_curl_globbing_disabled_for_device_bound_requests(self):
        url = 'https://sub.example/{1,2}'
        def run(cmd, **kwargs):
            self.assertIn('--globoff', cmd)
            self.assertNotIn('--location', cmd)
            return subprocess.CompletedProcess(cmd, 0, URI + p.STATUS_MARK + b'200', b'')
        with patch.object(Path,'read_text',return_value='a'*32), patch.object(p.subprocess,'run',run):
            self.assertEqual(p.download(url,user_agent='test',device_name='Lab'),URI)

    def test_mixed_list_cannot_embed_nested_subscription_to_bypass_limits(self):
        # With a small cap, one encoded group and another URI exceed it even
        # though the outer list has fewer lines than the cap.
        mixed = b'\n'.join((ALT, base64.b64encode(b'\n'.join([URI]*3)), URI))
        with patch.object(p, 'MAX_NODES',3):
            with self.assertRaises(ValueError):
                p.parse_device_payload(mixed)

    def test_bom_and_scheme_case_do_not_hide_working_vless(self):
        mix = ALT + b'\n' + URI
        for payload in (BOM + mix, BOM + base64.b64encode(mix), ALT.replace(b'hysteria2',b'HYSTERIA2') + b'\n' + URI):
            with self.subTest(payload_shape=len(payload)):
                nodes = p.parse_device_payload(payload)
                self.assertEqual([x['settings']['vnext'][0]['address'] for x in nodes], ['vpn.example'])
