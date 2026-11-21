import importlib
import tempfile
from pathlib import Path
import unittest
try:
    r=importlib.import_module('headless_vpn.runner')
except ModuleNotFoundError:r=None

class RunnerTests(unittest.TestCase):
    def setUp(self):self.assertIsNotNone(r,'generation runner not implemented')
    def test_bootstrap_dns_bypasses_tun_only_for_internal_node_resolution(self):
        from copy import deepcopy
        from headless_vpn.manager import xray_config
        from test_manager import NODE
        original = xray_config([NODE], 'eth42')
        saved = deepcopy(original)
        from headless_vpn import bootstrap
        runtime = bootstrap.configure(original, 10553)
        proxy, deny = runtime['outbounds']
        self.assertEqual(proxy['settings'], original['outbounds'][0]['settings'])
        self.assertEqual(proxy['streamSettings']['sockopt']['domainStrategy'], 'ForceIPv4')
        self.assertNotIn('targetStrategy', proxy)
        self.assertEqual(runtime['dns']['servers'], ['tcp+local://127.0.0.1:10553'])
        self.assertEqual(runtime['dns']['queryStrategy'], 'UseIPv4')
        self.assertEqual(runtime['routing'], original['routing'])
        self.assertEqual(runtime['routing']['balancers'][0]['fallbackTag'], deny['tag'])
        self.assertEqual(original, saved)

    def test_failed_dns_interface_never_connects_even_to_reachable_socket(self):
        import socket
        from headless_vpn import bootstrap
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(.1)
            with self.assertRaises(OSError):
                bootstrap.device_connection('no-such-vpnif', listener.getsockname())
            with self.assertRaises(TimeoutError):
                listener.accept()

    def test_resolver_forwards_only_registered_peer_a_question_without_extra_data(self):
        import socket
        from unittest.mock import patch
        from headless_vpn import bootstrap
        from headless_vpn.manager import xray_config
        from test_manager import NODE

        def exchange(server, name, kind):
            header = bytes.fromhex('031401000001000000000001')
            labels = b''.join(bytes([len(label)]) + label for label in name.split(b'.')) + b'\0'
            payload = header + labels + bytes((0, kind, 0, 1)) + b'not part of the question'
            with socket.create_connection(server.server_address, timeout=2) as conn:
                conn.sendall(len(payload).to_bytes(2, 'big') + payload)
                length = int.from_bytes(conn.recv(2), 'big')
                return payload, conn.recv(length)

        clean_reply = bytes.fromhex('031481800001000000000000')
        with bootstrap.resolver('eth42') as server:
            server.configure(xray_config([NODE], 'eth42'))
            with patch.object(bootstrap, 'doh_query', return_value=clean_reply) as query:
                self.assertEqual(exchange(server, b'not-a-peer.test', 1)[1], b'')
                self.assertEqual(exchange(server, b'example.com', 28)[1], b'')
                query.assert_not_called()
                raw, reply = exchange(server, b'example.com', 1)
                self.assertEqual(reply, clean_reply)
                self.assertEqual(query.call_args.args[:2], ('eth42', raw[:10] + b'\0\0' + raw[12:29]))

    def controller(self, health):
        events=[]
        control=r.Controller(lambda gen:events.append(('validate',gen)),lambda gen:events.append(('start',gen)) or {'gen':gen},lambda proc:events.append(('stop',proc['gen'])),lambda proc:health[proc['gen']],lambda gen:events.append(('rollback',gen)))
        return control,events
    def test_unchanged_generation_does_not_restart_connections(self):
        control,events=self.controller({'a':True})
        self.assertTrue(control.apply('a'));self.assertTrue(control.apply('a'))
        self.assertEqual(events,[('validate','a'),('start','a')])
    def test_failed_candidate_restores_old_process(self):
        control,events=self.controller({'a':True,'b':False})
        control.apply('a');self.assertFalse(control.apply('b'))
        self.assertEqual(control.generation,'a')
        self.assertEqual(events[-3:],[('stop','b'),('rollback','a'),('start','a')])
    def test_invalid_candidate_does_not_stop_working_process(self):
        control,events=self.controller({'a':True})
        control.apply('a')
        def invalid(gen):raise ValueError('invalid config')
        control.validate=invalid
        with self.assertRaises(ValueError):control.apply('b')
        self.assertEqual(control.process,{'gen':'a'})
        self.assertNotIn(('stop','a'),events)
    def test_successful_refresh_stops_old_before_new_same_port(self):
        control,events=self.controller({'a':True,'b':True})
        control.apply('a');self.assertTrue(control.apply('b'))
        self.assertEqual(events[-3:],[('validate','b'),('stop','a'),('start','b')])
        self.assertEqual(control.generation,'b')
    def test_failed_initial_start_has_no_running_process(self):
        control,events=self.controller({'a':False})
        self.assertFalse(control.apply('a'))
        self.assertIsNone(control.process);self.assertIsNone(control.generation)
    def test_rollback_rechecks_health_and_stops_unhealthy_previous(self):
        health = {'a': True, 'b': False}
        control, events = self.controller(health)
        control.apply('a')
        health['a'] = False
        self.assertFalse(control.apply('b'))
        self.assertIsNone(control.process)
        self.assertEqual(events[-1], ('stop', 'a'))

    def test_startup_rejects_generation_different_from_live_tun_snapshot(self):
        import json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); candidate = root / 'candidate'; candidate.mkdir()
            (candidate / 'sing-box.json').write_text(json.dumps({'route': 'new'}))
            snapshot = root / 'snapshot.json'
            snapshot.write_text(json.dumps({'route': 'old'}))
            self.assertTrue(hasattr(r, 'validate_generation'), 'startup baseline validation missing')
            with patch.object(r.m, 'validate_cores'), self.assertRaises(ValueError):
                r.validate_generation(candidate, tun_snapshot=snapshot)
            (candidate / 'sing-box.json').write_text(json.dumps({'route': 'old'}))
            with patch.object(r.m, 'validate_cores'):
                r.validate_generation(candidate, tun_snapshot=snapshot)

    def test_child_recovery_does_not_wait_for_refresh_lock_or_change_pending_pointer(self):
        import json
        from unittest.mock import patch
        from headless_vpn import manager as m
        from test_manager import TEMPLATE, NODE
        with tempfile.TemporaryDirectory() as folder:
            store = m.Store(Path(folder)/'state', TEMPLATE, 'test0', validator=lambda *_: None)
            catalog = m.empty_catalog(); catalog['manual'][m.node_id(NODE)] = NODE
            first = store.commit(catalog)
            second = store.commit(catalog)
            class Child:
                def __init__(self, dead=False): self.dead = dead
                def poll(self): return 1 if self.dead else None
            starts = []
            control = r.Controller(lambda _: None,
                lambda gen: starts.append(gen) or Child(), lambda _: None,
                lambda _: True, store.point_to)
            control.generation = first; control.process = Child(dead=True)
            self.assertTrue(hasattr(r, 'tick'), 'nonblocking supervisor cycle missing')
            with store.locked():
                # flock uses separate open descriptions, even in one process.
                r.tick(control, store)
            self.assertEqual(starts, [first])
            self.assertIsNone(control.process.poll())
            self.assertEqual(store.current(), second)
            self.assertEqual(control.generation, first)

    def test_spawn_error_restores_old_process(self):
        control,events=self.controller({'a':True})
        control.apply('a'); original=control.start
        def start(gen):
            if gen=='b':raise OSError('spawn failed')
            return original(gen)
        control.start=start
        self.assertFalse(control.apply('b'))
        self.assertEqual(control.process,{'gen':'a'})

if __name__=='__main__':unittest.main()
