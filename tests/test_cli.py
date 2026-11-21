import importlib
import io
import unittest
from contextlib import redirect_stdout, redirect_stderr
try:
    c=importlib.import_module('headless_vpn.cli')
except ModuleNotFoundError: c=None

class CliTests(unittest.TestCase):
    def setUp(self):self.assertIsNotNone(c,'CLI not implemented')
    def test_subscription_names_reject_paths_and_control_characters(self):
        for value in ['../x','two words','a\nb','', 'x'*49]:
            with self.assertRaises(ValueError):c.subscription_name(value)
        self.assertEqual(c.subscription_name('birds'),'birds')
    def test_help_available_without_state_or_services(self):
        out=io.StringIO()
        with redirect_stdout(out),self.assertRaises(SystemExit) as raised:c.main(['--help'])
        self.assertEqual(raised.exception.code,0)
        self.assertIn('subscription',out.getvalue())
    def test_oversized_file_is_rejected_before_truncated_prefix_can_publish(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from test_manager import NODE, TEMPLATE
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root/'oversized.json'; template = root/'template.json'
            valid = json.dumps(NODE).encode()
            source.write_bytes(valid + b' ' * (c.m.MAX_PAYLOAD + 1 - len(valid)) + b'invalid trailing content')
            template.write_text(json.dumps(TEMPLATE))
            with patch.object(c.m, 'default_interface', return_value='test0'), patch.object(c, 'ready', return_value=True), patch.object(c.m.Store, 'commit') as commit:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    result = c.main(['--state', str(root/'state'), '--template', str(template), 'add', str(source)])
            self.assertEqual(result, 1)
            commit.assert_not_called()

    def test_add_uses_url_stdin_not_required_in_process_arguments(self):
        args=c.parser().parse_args(['subscription','add','birds','--url-stdin'])
        self.assertTrue(args.url_stdin)
        self.assertEqual(args.name,'birds')

if __name__=='__main__':unittest.main()
