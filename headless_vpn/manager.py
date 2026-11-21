"""Private generations and loopback-only Xray probes. Never changes services/routes."""
import contextlib
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from . import bootstrap
from .subscription import MAX_PAYLOAD_BYTES

XRAY = os.getenv('HEADLESS_XRAY', '/opt/headless-vpn/bin/xray')
SING = os.getenv('HEADLESS_SING', '/opt/headless-vpn/bin/sing-box')
PROBE_URL = 'https://www.gstatic.com/generate_204'
MAX_PAYLOAD = MAX_PAYLOAD_BYTES


def private_json(path, value):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())


def canonical_node(node):
    result = copy.deepcopy(node)
    result.pop('tag', None)
    stream = result.get('streamSettings', {})
    sock = stream.get('sockopt', {})
    sock.pop('interface', None)
    if not sock: stream.pop('sockopt', None)
    return result


def node_id(node):
    encoded = json.dumps(canonical_node(node), sort_keys=True, separators=(',', ':')).encode()
    return 'node-' + hashlib.sha256(encoded).hexdigest()[:16]


def choose_interface(routes, is_physical):
    candidates = [r for r in routes if r.get('dst') == 'default' and r.get('gateway') and is_physical(r.get('dev', ''))]
    if not candidates: raise ValueError('No physical default interface; refusing to use a VPN interface')
    return min(candidates, key=lambda r: r.get('metric', 0))['dev']


def default_interface():
    result = subprocess.run(['ip', '-j', '-4', 'route', 'show', 'table', 'main'], capture_output=True, text=True, check=True, timeout=5)
    return choose_interface(json.loads(result.stdout), lambda dev: (Path('/sys/class/net') / dev / 'device').exists())


def empty_catalog():
    return {'version': 2, 'manual': {}, 'subscriptions': {}}


def collect_nodes(catalog):
    all_nodes = list(catalog['manual'].values())
    for source in catalog['subscriptions'].values(): all_nodes.extend(source['nodes'])
    return list({node_id(n): canonical_node(n) for n in all_nodes}.values())


def xray_config(nodes, interface, port=10818, probe_interval='15s', probe_url=PROBE_URL):
    if not nodes: raise ValueError('Cannot publish zero VPN nodes')
    outbounds = []
    for node in nodes:
        item = canonical_node(node); item['tag'] = node_id(item)
        item.setdefault('streamSettings', {}).setdefault('sockopt', {})['interface'] = interface
        outbounds.append(item)
    return {
        'log': {'loglevel': 'warning'},
        'inbounds': [{'tag': 'socks', 'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}],
        'outbounds': outbounds + [{'tag': 'block', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'AsIs', 'balancers': [{'tag': 'auto', 'selector': ['node-'], 'fallbackTag': 'block', 'strategy': {'type': 'leastPing'}}], 'rules': [{'type': 'field', 'network': 'tcp,udp', 'balancerTag': 'auto'}]},
        'observatory': {'subjectSelector': ['node-'], 'probeUrl': probe_url, 'probeInterval': probe_interval, 'enableConcurrency': True},
    }


def sing_config(template, interface):
    config = copy.deepcopy(template)
    proxies = [o for o in config.get('outbounds', []) if o.get('tag') == 'proxy' and o.get('type') == 'socks' and o.get('server') == '127.0.0.1']
    tuns = [i for i in config.get('inbounds', []) if i.get('type') == 'tun' and i.get('auto_route')]
    if len(proxies) != 1 or len(tuns) != 1: raise ValueError('Expected one loopback SOCKS bridge and one automatic TUN')
    proxies[0]['server_port'] = 10818
    tuns[0]['interface_name'] = 'tun0'
    tuns[0]['address'] = ['198.18.0.1/30']
    config['dns'] = {'servers': [{'tag': 'dns-proxy', 'address': 'https://1.1.1.1/dns-query', 'detour': 'proxy'}]}
    config.setdefault('route', {})['default_interface'] = interface
    config['route']['auto_detect_interface'] = False
    config['route']['final'] = 'proxy'
    config['log'] = {'level': 'warn', 'timestamp': True}
    return config


def validate_cores(xray_path, sing_path):
    for command in ([XRAY, '-test', '-c', str(xray_path)], [SING, 'check', '-c', str(sing_path)]):
        result = subprocess.run(command, capture_output=True, timeout=25)
        if result.returncode: raise ValueError(Path(command[0]).name + ' rejected candidate (details suppressed: may contain secrets)')


def validate_effective_cores(xray_path, sing_path):
    with tempfile.TemporaryDirectory(prefix='headless-vpn-check-') as folder:
        effective = Path(folder) / 'xray.json'
        private_json(effective, bootstrap.configure(json.loads(xray_path.read_text()), free_port()))
        validate_cores(effective, sing_path)


class Store:
    def __init__(self, root, template, interface, validator=validate_cores):
        self.root = Path(root)
        self.template = template
        self.interface = interface
        self.validator = validator

    @contextlib.contextmanager
    def locked(self, *, blocking=True):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700); self.root.chmod(0o700)
        fd = os.open(self.root / '.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
            fcntl.flock(fd, flags)
            yield
        finally: os.close(fd)

    def current(self):
        pointer = self.root / 'current'
        if not pointer.is_symlink(): return None
        target = pointer.resolve(strict=True)
        if target.parent != (self.root / 'generations').resolve(): raise ValueError('Invalid generation pointer')
        return target

    def load(self):
        current = self.current()
        return json.loads((current / 'catalog.json').read_text()) if current else empty_catalog()

    def point_to(self, generation):
        generation = Path(generation).resolve(strict=True)
        if generation.parent != (self.root / 'generations').resolve(): raise ValueError('Invalid rollback generation')
        temp = self.root / ('.current-' + uuid.uuid4().hex)
        pointer = self.root / 'current'
        previous = os.readlink(pointer) if pointer.is_symlink() else None
        replaced = False
        try:
            temp.symlink_to(Path('generations') / generation.name)
            os.replace(temp, pointer)
            replaced = True
            fd = os.open(self.root, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        except OSError:
            if replaced:
                # A failed durability check is not permission to remove a live target.
                # Restore the previous pointer; if rollback also fails, commit's
                # cleanup preserves whichever generation is still referenced.
                if previous is None:
                    pointer.unlink()
                else:
                    temp.symlink_to(previous)
                    os.replace(temp, pointer)
            raise
        finally: temp.unlink(missing_ok=True)

    def commit(self, catalog):
        nodes = collect_nodes(catalog)
        xray = xray_config(nodes, self.interface)
        sing = sing_config(self.template, self.interface)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700); self.root.chmod(0o700)
        generations = self.root / 'generations'; generations.mkdir(mode=0o700, exist_ok=True)
        generation = Path(tempfile.mkdtemp(prefix='gen-', dir=generations))
        published = False
        try:
            for name, value in [('catalog.json', catalog), ('xray.json', xray), ('sing-box.json', sing)]: private_json(generation / name, value)
            self.validator(generation / 'xray.json', generation / 'sing-box.json')
            self.point_to(generation); published = True
            return generation
        finally:
            if not published and (self.root / 'current').resolve() != generation:
                shutil.rmtree(generation)


def validate_url(url):
    if any(ord(c) < 32 or ord(c) == 127 for c in url): raise ValueError('Invalid subscription URL')
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError: raise ValueError('Invalid subscription URL') from None
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or (port is not None and not 1 <= port <= 65535):
        raise ValueError('Subscription must be an HTTPS URL without userinfo or fragment')
    return url


def fetch_subscription(url, interface, *, device_name=None):
    from .provider import download
    return download(validate_url(url), user_agent='headless-vpn/2.0', interface=interface, device_name=device_name)


def fetch_source(source, fetcher, parser):
    name = source.get('device_name')
    if name is None:
        return parser(fetcher(source['url']))
    from .provider import parse_device_payload
    return parse_device_payload(fetcher(source['url'], device_name=name))

def refreshed_catalog(catalog, fetcher, parser, checker):
    fresh = copy.deepcopy(catalog); errors = []
    for name, source in fresh['subscriptions'].items():
        try:
            nodes = fetch_source(source, fetcher, parser)
            if not nodes or not checker(nodes): raise ValueError('No reachable candidate')
            source['nodes'] = nodes
        except (ValueError, OSError, subprocess.SubprocessError): errors.append(name)
    return fresh, errors


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]


@contextlib.contextmanager
def running_xray(config):
    """Only a loopback SOCKS process, owned and reaped here; never a TUN."""
    if any(i.get('listen') != '127.0.0.1' or i.get('protocol') != 'socks' for i in config.get('inbounds', [])):
        raise ValueError('Probe may only create loopback SOCKS listeners')
    with tempfile.TemporaryDirectory(prefix='headless-vpn-probe-') as folder:
        path = Path(folder) / 'xray.json'; private_json(path, config)
        check = subprocess.run([XRAY, '-test', '-c', str(path)], capture_output=True, timeout=20)
        if check.returncode: raise ValueError('Probe configuration rejected by Xray')
        process = subprocess.Popen([XRAY, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None: raise ValueError('Probe Xray exited before ready')
                try:
                    with socket.create_connection(('127.0.0.1', config['inbounds'][0]['port']), timeout=.2): break
                except OSError: time.sleep(.05)
            else: raise ValueError('Probe listener did not become ready')
            yield process
        finally:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)


def http_probe(port, url=PROBE_URL, timeout=10):
    result = subprocess.run(['curl', '-q', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{port}', '--silent', '--show-error', '--connect-timeout', '5', '--max-time', str(timeout), '--output', '/dev/null', '--write-out', '%{http_code}', url], capture_output=True, text=True, timeout=timeout+2)
    return result.returncode == 0 and result.stdout.strip() == '204'


def probe_nodes(nodes, interface):
    results = []
    with bootstrap.resolver(interface) as dns:
        for node in nodes:
            started = time.monotonic(); ok = False
            try:
                config = xray_config([node], interface, port=free_port())
                config.pop('observatory'); config.pop('routing')
                with running_xray(dns.configure(config)):
                    ok = http_probe(config['inbounds'][0]['port'])
            except (ValueError, OSError, subprocess.SubprocessError): pass
            results.append({'id': node_id(node), 'ok': ok, 'elapsed_ms': round((time.monotonic()-started)*1000)})
    return results
