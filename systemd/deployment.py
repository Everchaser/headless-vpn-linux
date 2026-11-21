#!/usr/bin/python
"""Deployment guards. Refresh is unprivileged; activate/rollback require explicit root consent."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

PROJECT = Path('/opt/headless-vpn')
STATE = Path('/var/lib/headless-vpn/state')
RUNTIME = Path('/run/headless-vpn-v2')
UNIT_DIR = Path('/etc/systemd/system')
BACKUP = Path('/var/lib/headless-vpn-v2/rollback')
UNITS = ('headless-vpn.service', 'headless-vpn-xray.service',
         'headless-vpn-refresh.service', 'headless-vpn-refresh.timer')
RUNNER_ARGV = ['/usr/bin/python3', '-m', 'headless_vpn.runner', '--state', str(STATE)]
CLI_ARGV = ['/usr/bin/python3', '-m', 'headless_vpn.cli', '--state', str(STATE)]
REFRESH_ARGV = CLI_ARGV + ['--template', str(RUNTIME / 'sing-box.json'), 'subscription', 'refresh']


def systemctl(*args, check=True):
    return subprocess.run(['/usr/bin/systemctl', *args], capture_output=True,
                          text=True, check=check, timeout=120)


def properties(unit):
    result = systemctl('show', unit, '--property=LoadState,ActiveState,User,MainPID,DropInPaths,WorkingDirectory,FragmentPath,UnitFileState')
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def require_upstream(props, argv):
    if (props.get('ActiveState') != 'active' or props.get('User') != 'headless-vpn'
            or props.get('WorkingDirectory') != str(PROJECT)
            or props.get('FragmentPath') != str(UNIT_DIR / 'headless-vpn-xray.service')
            or props.get('DropInPaths') or not props.get('MainPID', '').isdigit()
            or int(props['MainPID']) <= 0 or argv != RUNNER_ARGV):
        raise ValueError('Refresh requires the active, unmodified v2 runner')


def require_active_v2():
    props = properties('headless-vpn-xray.service')
    pid = props.get('MainPID', '0')
    if not pid.isdigit() or int(pid) <= 0:
        raise ValueError('No active upstream')
    argv = Path('/proc', pid, 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    require_upstream(props, argv)
    if (UNIT_DIR / 'headless-vpn-xray.service').read_bytes() != (PROJECT / 'systemd/headless-vpn-xray.service').read_bytes():
        raise ValueError('Installed upstream differs from reviewed v2 unit')
    tun = properties('headless-vpn.service')
    if tun.get('ActiveState') != 'active' or tun.get('DropInPaths'):
        raise ValueError('Refresh requires active v2 TUN')
    if (UNIT_DIR / 'headless-vpn.service').read_bytes() != (PROJECT / 'systemd/headless-vpn.service').read_bytes():
        raise ValueError('Legacy TUN is not eligible for refresh')


def generation(state):
    pointer = state / 'current'
    if not pointer.is_symlink():
        raise ValueError('Missing generation')
    current = pointer.resolve(strict=True)
    if current.parent != (state / 'generations').resolve():
        raise ValueError('Invalid generation pointer')
    return current


def snapshot_tun(state=STATE, runtime=RUNTIME, *, trusted=None):
    # A shared lock serializes against the manager/runner exclusive publication lock.
    # RuntimeDirectory is root:headless-vpn 0750; root is its only writer.
    target = runtime / 'sing-box.json'
    if target.exists():
        # Reuse approved root-owned baseline, even while refresh owns the lock.
        # RuntimeDirectoryPreserve=restart keeps it through automatic restarts.
        json.loads(target.read_bytes())
        return
    with (state / '.lock').open('r') as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        data = (generation(state) / 'sing-box.json').read_bytes()
        proposed = json.loads(data)
        if trusted is not None:
            if proposed != trusted:
                raise ValueError('Unprivileged generation differs from root-owned TUN template')
            data = json.dumps(trusted).encode() + b'\n'
        temporary = runtime / 'sing-box.json.new'
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)


def check_tun_baseline(state=STATE, runtime=RUNTIME):
    frozen = json.loads((runtime / 'sing-box.json').read_text())
    current = json.loads((generation(state) / 'sing-box.json').read_text())
    if current != frozen:
        raise ValueError('TUN changes require a separately approved complete restart')


def check_runner_start():
    # On runner auto-restart, do not accept a new baseline underneath a live TUN.
    if properties('headless-vpn.service').get('ActiveState') == 'active':
        check_tun_baseline()


def refresh():
    require_active_v2()
    check_tun_baseline()
    # NO systemctl start/try-restart: only the running runner applies/rolls back Xray.
    return subprocess.run(REFRESH_ARGV, cwd=PROJECT, check=False).returncode


def wait_upstream():
    deadline = time.monotonic() + 55
    command = ['/usr/bin/curl', '-q', '--noproxy', '', '--proxy', 'socks5h://127.0.0.1:10818',
               '--silent', '--show-error', '--connect-timeout', '3', '--max-time', '6',
               '--output', '/dev/null', '--write-out', '%{http_code}',
               'https://www.gstatic.com/generate_204']
    while time.monotonic() < deadline:
        if properties('headless-vpn-xray.service').get('ActiveState') != 'active':
            raise ValueError('Upstream stopped')
        result = subprocess.run(command, capture_output=True, text=True, timeout=8)
        if result.returncode == 0 and result.stdout.strip() == '204':
            return
        time.sleep(1)
    raise ValueError('Upstream has no verified egress')


def check_conflicts(active, interfaces):
    if set(active) & {'happd.service', *UNITS}:
        raise ValueError('Stop the existing VPN explicitly before activation')
    if any(name == 'tun0' or name.startswith('happ') for name in interfaces):
        raise ValueError('Existing TUN interface prevents activation')


def require_ipv4_host():
    result = subprocess.run(['ip', '-6', 'route', 'show', 'table', 'main', 'default'],
                            capture_output=True, check=True, timeout=5)
    if result.stdout.strip():
        raise ValueError('This profile does not guard an IPv6 default route')


def require_happ_disabled():
    happ = properties('happd.service')
    if happ.get('LoadState') != 'not-found' and happ.get('UnitFileState') not in ('disabled', 'masked'):
        raise ValueError('Disable Happ boot activation explicitly before cutover')


def preflight():
    active = {name for name in (*UNITS, 'happd.service')
              if properties(name).get('ActiveState') not in ('inactive', 'failed')}
    check_conflicts(active, [p.name for p in Path('/sys/class/net').iterdir()])
    require_happ_disabled()
    for name in UNITS:
        info = properties(name)
        if info.get('DropInPaths') or (UNIT_DIR / name).is_symlink():
            raise ValueError('Unit overrides/masks require manual review')
    if BACKUP.exists():
        raise ValueError('Previous rollback backup exists; review/archive it first')
    if not Path('/dev/net/tun').is_char_device():
        raise ValueError('Linux TUN is not available')
    require_ipv4_host()
    if PROJECT.resolve() != Path(__file__).resolve().parents[1]:
        raise ValueError('Deployment must use the reviewed fixed project path')
    subprocess.run(['/usr/bin/systemd-analyze', 'verify', *[str(PROJECT / 'systemd' / n) for n in UNITS]],
                   capture_output=True, check=True, timeout=30)
    runuser = shutil.which('runuser', path='/usr/sbin:/usr/bin:/sbin:/bin')
    if not runuser:
        raise ValueError('runuser is required')
    for action in ('check', 'probe'):
        result = subprocess.run([runuser, '-u', 'headless-vpn', '--', *CLI_ARGV, action],
                                cwd=PROJECT, capture_output=True, timeout=600)
        if result.returncode:
            raise ValueError('Preflight core validation/probe failed')


def restore(backup=None, unit_dir=None):
    backup = BACKUP if backup is None else backup
    unit_dir = UNIT_DIR if unit_dir is None else unit_dir
    # Safety-first rollback: restore definitions, NOT old boot enablement or legacy traffic.
    # Starting old units can resurrect the obsolete manual node; only the operator returns to Happ.
    systemctl('stop', 'headless-vpn-refresh.timer', 'headless-vpn-refresh.service',
              'headless-vpn.service', 'headless-vpn-xray.service', check=False)
    # Partial installs may not yet have all four units. Verify stopped state,
    # rather than treating a missing unit's nonzero stop result as unsafe.
    for name in UNITS:
        if properties(name).get('ActiveState') not in ('inactive', 'failed'):
            raise ValueError('Rollback refused: headless unit is still running')
    systemctl('disable', *UNITS, check=False)
    for name in UNITS:
        if properties(name).get('UnitFileState', '') in ('enabled', 'enabled-runtime', 'linked', 'linked-runtime'):
            raise ValueError('Rollback refused: headless boot activation remains enabled')
    for name in UNITS:
        target = unit_dir / name
        target.unlink(missing_ok=True)
        original = backup / name
        if original.exists():
            shutil.copy2(original, target)
    systemctl('daemon-reload')


def activate():
    preflight()
    BACKUP.mkdir(parents=True, mode=0o700)
    BACKUP.parent.chmod(0o700)
    manifest = {name: properties(name).get('UnitFileState', 'unknown') for name in UNITS}
    for name in UNITS:
        original = UNIT_DIR / name
        if original.exists():
            shutil.copy2(original, BACKUP / name)
    (BACKUP / 'previous-enable-state.json').write_text(json.dumps(manifest, indent=2))
    (BACKUP / 'complete').touch(mode=0o600)
    try:
        for name in UNITS:
            target = UNIT_DIR / name
            shutil.copyfile(PROJECT / 'systemd' / name, target)
            target.chmod(0o644)
        systemctl('daemon-reload')
        systemctl('start', 'headless-vpn.service')
        require_active_v2()
        wait_upstream()
        check_tun_baseline()
        systemctl('enable', 'headless-vpn.service', 'headless-vpn-refresh.timer')
        systemctl('start', 'headless-vpn-refresh.timer')
        for name in ('headless-vpn.service', 'headless-vpn-xray.service', 'headless-vpn-refresh.timer'):
            if properties(name).get('ActiveState') != 'active':
                raise ValueError('Activation verification failed')
    except BaseException:
        restore()
        raise
    print('v2 services activated. Cold-boot and host-TUN egress verification still required.')


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if args and args[0] in ('activate', 'rollback'):
            if args != [args[0], '--activate'] or os.geteuid() != 0:
                raise ValueError('Explicit --activate and root are required')
            os.umask(0o077)
            signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
            if args[0] == 'activate':
                activate()
            else:
                if not (BACKUP / 'complete').is_file():
                    raise ValueError('No complete rollback backup')
                restore()
                print('Unit definitions restored; headless remains stopped/disabled. Start Happ manually if approved.')
            return 0
        if args == ['refresh']:
            return refresh()
        if args == ['snapshot-tun']:
            require_ipv4_host()
            wait_upstream()
            # The state owner can edit generations, but cannot supply arbitrary root config.
            sys.path.insert(0, str(PROJECT))
            from headless_vpn import manager
            template = json.loads((PROJECT / 'templates/tun.json').read_text())
            snapshot_tun(trusted=manager.sing_config(template, manager.default_interface()))
            return 0
        if args == ['check-runner-start']:
            check_runner_start()
            return 0
        raise ValueError('Invalid deployment action')
    except (ValueError, OSError, subprocess.SubprocessError, KeyboardInterrupt):
        print('Deployment action refused or failed; details suppressed. Review service state/rollback before retrying.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
