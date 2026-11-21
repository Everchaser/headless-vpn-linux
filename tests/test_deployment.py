"""Deployment tests use synthetic units/process metadata, never live service writes."""
import configparser
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
HELPER = PROJECT / 'systemd/deployment.py'


def load_helper():
    if not HELPER.exists():
        return None
    spec = importlib.util.spec_from_file_location('deployment', HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.d = load_helper()
        self.assertIsNotNone(self.d, 'guarded deployment helper not implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def upstream(self, **changes):
        result = {'ActiveState': 'active', 'User': 'headless-vpn',
                  'MainPID': '123', 'DropInPaths': '',
                  'WorkingDirectory': str(self.d.PROJECT),
                  'FragmentPath': '/etc/systemd/system/headless-vpn-xray.service'}
        result.update(changes)
        return result

    def test_ipv6_default_refuses_ipv4_only_profile(self):
        with patch.object(self.d.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'default via fe80::1 dev eth0\n')):
            with self.assertRaises(ValueError):
                self.d.require_ipv4_host()

    def test_boot_guard_distinguishes_missing_happ_from_enabled_happ(self):
        cases = [({'LoadState': 'not-found', 'UnitFileState': ''}, True),
                 ({'LoadState': 'loaded', 'UnitFileState': 'disabled'}, True),
                 ({'LoadState': 'masked', 'UnitFileState': 'masked'}, True),
                 ({'LoadState': 'loaded', 'UnitFileState': 'enabled'}, False),
                 ({'LoadState': 'loaded', 'UnitFileState': ''}, False)]
        for props, allowed in cases:
            with self.subTest(props=props), patch.object(self.d, 'properties', return_value=props):
                if allowed:
                    self.d.require_happ_disabled()
                else:
                    with self.assertRaises(ValueError):
                        self.d.require_happ_disabled()

    def test_refresh_refuses_inactive_legacy_and_overridden_upstream(self):
        cases = [self.upstream(ActiveState='inactive'), self.upstream(User='root'),
                 self.upstream(DropInPaths='/etc/systemd/system/override.conf'),
                 self.upstream(WorkingDirectory='/etc/headless-vpn'),
                 self.upstream(MainPID='0')]
        for properties in cases:
            with self.subTest(properties=properties), self.assertRaises(ValueError):
                self.d.require_upstream(properties, self.d.RUNNER_ARGV)
        with self.assertRaises(ValueError):
            self.d.require_upstream(self.upstream(), ['/opt/headless-vpn/bin/xray', 'run', '-c', 'legacy.json'])
        self.d.require_upstream(self.upstream(), self.d.RUNNER_ARGV)

    def test_refresh_checks_before_cli_and_never_starts_upstream(self):
        with patch.object(self.d, 'require_active_v2', side_effect=ValueError('inactive')):
            with patch.object(self.d.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    self.d.refresh()
                run.assert_not_called()
        with patch.object(self.d, 'require_active_v2'), patch.object(self.d, 'check_tun_baseline'):
            with patch.object(self.d.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                self.assertEqual(self.d.refresh(), 0)
                self.assertEqual(run.call_args.args[0], self.d.REFRESH_ARGV)
                self.assertNotIn('systemctl', run.call_args.args[0])

    def state(self, name='gen-one', config=None):
        state = self.root / 'state'
        gen = state / 'generations' / name
        gen.mkdir(parents=True)
        (state / '.lock').touch(mode=0o600)
        (gen / 'sing-box.json').write_text(json.dumps(config or {'route': {'final': 'proxy'}}))
        pointer = state / 'current'
        pointer.unlink(missing_ok=True)
        pointer.symlink_to(gen)
        return state

    def test_tun_snapshot_does_not_follow_current_pointer(self):
        state = self.state()
        runtime = self.root / 'run'
        runtime.mkdir()
        self.d.snapshot_tun(state, runtime)
        self.state('gen-two', {'route': {'final': 'block'}})
        self.assertEqual(json.loads((runtime / 'sing-box.json').read_text()), {'route': {'final': 'proxy'}})
        self.assertEqual((runtime / 'sing-box.json').stat().st_mode & 0o777, 0o640)
        with self.assertRaises(ValueError):
            self.d.check_tun_baseline(state, runtime)

    def test_automatic_restart_reuses_approved_snapshot_not_pending_generation(self):
        state = self.state()
        runtime = self.root/'run'; runtime.mkdir()
        self.d.snapshot_tun(state, runtime)
        approved = (runtime/'sing-box.json').read_bytes()
        self.state('pending', {'route': {'final': 'block'}})
        self.d.snapshot_tun(state, runtime)
        self.assertEqual((runtime/'sing-box.json').read_bytes(), approved)
        with self.assertRaises(ValueError): self.d.check_tun_baseline(state, runtime)
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(PROJECT/'systemd/headless-vpn.service')
        self.assertEqual(cfg['Service'].get('RuntimeDirectoryPreserve'), 'restart')

    def test_existing_snapshot_restart_does_not_wait_for_refresh_lock(self):
        import fcntl
        state = self.state(); runtime = self.root/'run'; runtime.mkdir()
        self.d.snapshot_tun(state, runtime)
        code = ('import importlib.util,sys; from pathlib import Path; '
                's=importlib.util.spec_from_file_location("d",sys.argv[1]); '
                'd=importlib.util.module_from_spec(s); s.loader.exec_module(d); '
                'd.snapshot_tun(Path(sys.argv[2]),Path(sys.argv[3]))')
        with (state/'.lock').open('r') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                result = subprocess.run(['/usr/bin/python3', '-c', code, str(HELPER), str(state), str(runtime)],
                                        capture_output=True, timeout=2)
            except subprocess.TimeoutExpired:
                self.fail('TUN restart blocked by refresh despite existing approved snapshot')
        self.assertEqual(result.returncode, 0)

    def test_snapshot_rejects_escaping_generation(self):
        state = self.root / 'state'; state.mkdir()
        (state / '.lock').touch(mode=0o600)
        (state / 'current').symlink_to(self.root)
        with self.assertRaises(ValueError):
            self.d.snapshot_tun(state, self.root)

    def test_preflight_refuses_happ_tun_or_running_headless(self):
        for active, interfaces in [({'happd.service'}, []), (set(), ['happ-xray']),
                                   ({'headless-vpn.service'}, []), ({'headless-vpn-xray.service'}, []),
                                   ({'headless-vpn-refresh.timer'}, []), ({'headless-vpn-refresh.service'}, [])]:
            with self.subTest(active=active, interfaces=interfaces), self.assertRaises(ValueError):
                self.d.check_conflicts(active, interfaces)
        self.d.check_conflicts(set(), ['eth0', 'lo'])

    def test_rollback_restores_files_without_starting_legacy_or_happ(self):
        units = self.root / 'units'; units.mkdir()
        backup = self.root / 'backup'; backup.mkdir()
        for name in self.d.UNITS:
            (units / name).write_text('v2')
        (backup / 'headless-vpn.service').write_text('legacy tun')
        (backup / 'headless-vpn-xray.service').write_text('legacy upstream')
        with patch.object(self.d, 'properties', return_value={'ActiveState': 'inactive', 'UnitFileState': 'disabled'}), patch.object(self.d, 'systemctl') as ctl:
            self.d.restore(backup, units)
        self.assertEqual((units / 'headless-vpn.service').read_text(), 'legacy tun')
        self.assertFalse((units / 'headless-vpn-refresh.timer').exists())
        calls = [call.args for call in ctl.call_args_list]
        self.assertTrue(any('stop' in call for call in calls))
        self.assertTrue(any('disable' in call for call in calls))
        self.assertFalse(any('start' in call or 'enable' in call or 'restart' in call for call in calls))

    def test_activation_requires_root_and_explicit_consent(self):
        for uid, args in [(0, ['activate']), (1000, ['activate', '--activate']),
                          (0, ['rollback']), (0, ['activate', '--activate', 'extra'])]:
            with self.subTest(uid=uid, args=args), patch.object(self.d.os, 'geteuid', return_value=uid), contextlib.redirect_stderr(io.StringIO()):
                with patch.object(self.d, 'activate') as activate, patch.object(self.d, 'restore') as restore:
                    self.assertEqual(self.d.main(args), 1)
                    activate.assert_not_called(); restore.assert_not_called()

    def test_activation_failure_restores_original_definitions_and_leaves_disabled(self):
        units = self.root / 'units'; units.mkdir()
        backup = self.root / 'rollback'
        (units / 'headless-vpn.service').write_text('legacy tun')
        (units / 'headless-vpn-xray.service').write_text('legacy xray')
        def ctl(*args, **kwargs):
            if args == ('start', 'headless-vpn.service'):
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(self.d, 'UNIT_DIR', units), patch.object(self.d, 'BACKUP', backup), patch.object(self.d, 'PROJECT', PROJECT):
            with patch.object(self.d, 'preflight'), patch.object(self.d, 'properties', return_value={'ActiveState': 'inactive'}):
                with patch.object(self.d, 'systemctl', side_effect=ctl):
                    with self.assertRaises(subprocess.CalledProcessError):
                        self.d.activate()
        self.assertEqual((units / 'headless-vpn.service').read_text(), 'legacy tun')
        self.assertEqual((units / 'headless-vpn-xray.service').read_text(), 'legacy xray')
        self.assertFalse((units / 'headless-vpn-refresh.timer').exists())
        self.assertTrue((backup / 'complete').exists())

    def test_snapshot_preserves_lock_ownership_and_requires_existing_lock(self):
        state = self.state()
        (state / '.lock').unlink(missing_ok=True)
        runtime = self.root / 'run'; runtime.mkdir()
        with self.assertRaises(FileNotFoundError):
            self.d.snapshot_tun(state, runtime)
        self.assertFalse((state / '.lock').exists())

    def test_rollback_stops_before_restore_and_refuses_a_still_running_tun(self):
        units = self.root / 'units'; units.mkdir()
        backup = self.root / 'backup'; backup.mkdir()
        (units / 'headless-vpn.service').write_text('v2')
        (backup / 'headless-vpn.service').write_text('legacy')
        with patch.object(self.d, 'systemctl'), patch.object(self.d, 'properties', return_value={'ActiveState': 'active'}):
            with self.assertRaises(ValueError):
                self.d.restore(backup, units)
        self.assertEqual((units / 'headless-vpn.service').read_text(), 'v2')

    def test_runner_start_refuses_tun_baseline_mismatch(self):
        with patch.object(self.d, 'properties', return_value={'ActiveState': 'active'}):
            with patch.object(self.d, 'check_tun_baseline', side_effect=ValueError('changed')):
                with self.assertRaises(ValueError):
                    self.d.check_runner_start()

    def test_units_do_not_pull_upstream_from_refresh(self):
        def unit(name):
            cfg = configparser.ConfigParser(interpolation=None, strict=False)
            self.assertTrue(cfg.read(PROJECT / 'systemd' / name))
            return cfg
        refresh = unit('headless-vpn-refresh.service')
        self.assertEqual(refresh['Service']['User'], 'headless-vpn')
        self.assertEqual(refresh['Service']['Type'], 'oneshot')
        self.assertIn('headless-vpn-xray.service', refresh['Unit']['Requisite'])
        for key in ('Requires', 'Wants', 'BindsTo'):
            self.assertNotIn('headless-vpn-xray.service', refresh['Unit'].get(key, ''))
        self.assertEqual(refresh['Service']['ExecStart'].split()[-1], 'refresh')
        timer = unit('headless-vpn-refresh.timer')
        # Calendar retries even if a Requisite failure prevented activation.
        self.assertEqual(timer['Timer'].get('OnCalendar'), 'hourly')
        upstream = unit('headless-vpn-xray.service')
        self.assertEqual(upstream['Service']['User'], 'headless-vpn')
        self.assertEqual(upstream['Service']['ExecStart'].split(), self.d.RUNNER_ARGV)
        tun = unit('headless-vpn.service')
        self.assertEqual(tun['Service']['User'], 'root')
        self.assertIn('/run/headless-vpn-v2/sing-box.json', tun['Service']['ExecStart'])
        self.assertIn('happd.service', tun['Unit']['Conflicts'])

    def test_shell_and_systemd_syntax(self):
        installer = PROJECT / 'install-headless-vpn-v2.sh'
        self.assertTrue(installer.exists(), 'installer missing')
        subprocess.run(['bash', '-n', str(installer)], check=True, capture_output=True)
        files = [str(PROJECT / 'systemd' / name) for name in self.d.UNITS]
        # The required core is deliberately not bundled; substitute a real
        # executable only for parsing units before /opt installation.
        with tempfile.TemporaryDirectory() as folder:
            for file in files:
                unit = Path(file)
                (Path(folder) / unit.name).write_text(unit.read_text().replace('/opt/headless-vpn/bin/sing-box', '/usr/bin/true'))
            result = subprocess.run(['systemd-analyze', 'verify', *[str(Path(folder)/Path(f).name) for f in files]], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
