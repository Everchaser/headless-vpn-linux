"""Provider-authorized, host-bound HTTPS subscription downloads."""
import base64
import hmac
import ipaddress
import json
from pathlib import Path
import re
import subprocess

from .subscription import MAX_NODES, MAX_PAYLOAD_BYTES, parse_subscription

STATUS_MARK = b'\nDCL_HTTP_STATUS '


def valid_device_name(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}', name):
        raise ValueError('Invalid subscription device name')
    return name


def download(url, *, user_agent, interface=None, device_name=None):
    cmd = ['curl','-q','--globoff','--config','-','--noproxy','*','--proto','=https','--proto-redir','=https',
           '--connect-timeout','8','--max-time','30','--max-filesize',str(MAX_PAYLOAD_BYTES),
           '--fail','--silent','--show-error','--user-agent',user_agent]
    if interface is not None:
        cmd += ['--interface', interface]
    lines = ['url = ' + json.dumps(url)]
    if device_name is None:
        cmd += ['--location','--max-redirs','3']
    else:
        valid_device_name(device_name)
        machine_id = Path('/etc/machine-id').read_text(encoding='ascii').strip()
        if not re.fullmatch(r'[a-f0-9]{32}', machine_id) or machine_id == '0'*32:
            raise ValueError('Missing valid machine identity')
        hwid = hmac.digest(bytes.fromhex(machine_id), b'dcl-vpn/provider-device-id/v1', 'sha256').hex()
        lines += ['header = ' + json.dumps(h) for h in ('x-hwid: '+hwid,'x-device-os: Linux','x-device-model: '+device_name)]
        # Do not forward identifying headers through redirects.
        cmd += ['--dump-header','/dev/stderr','--write-out',STATUS_MARK.decode()+'%{http_code}']
    result = subprocess.run(cmd,input=('\n'.join(lines)+'\n').encode(),capture_output=True,timeout=35)
    body = result.stdout
    if device_name is not None:
        body, marker, code = body.rpartition(STATUS_MARK)
        if re.search(rb'(?im)^x-hwid-(?:not-supported|max-devices-reached|limit):[ \t]*(?:true|1)[ \t]*\r?$', result.stderr):
            raise ValueError('Provider refused device authorization or device limit reached')
        if not marker or code != b'200':
            raise ValueError('Device-bound subscription requires HTTP 200 without redirects')
    if result.returncode or not body or len(body) > MAX_PAYLOAD_BYTES:
        raise ValueError('Subscription download failed; old nodes retained')
    return body


def parse_device_payload(body):
    try:
        nodes = parse_subscription(body)
    except ValueError:
        if not body or len(body) > MAX_PAYLOAD_BYTES:
            raise ValueError('Invalid device-bound subscription') from None
        try:
            raw = body.decode('utf-8-sig').strip()
            if '://' not in raw and not raw.startswith(('{', '[', '<')):
                raw = ''.join(raw.split())
                raw = base64.b64decode(raw + '='*(-len(raw)%4), altchars=b'-_', validate=True).decode('utf-8-sig')
        except (ValueError, UnicodeError):
            raise ValueError('Invalid device-bound subscription') from None
        lines = [x.strip() for x in raw.splitlines() if x.strip()]
        if not 0 < len(lines) <= MAX_NODES:
            raise ValueError('Invalid device-bound node count') from None
        uris = []
        for line in lines:
            scheme, sep, _ = line.partition('://')
            if not sep or scheme.lower() not in ('vless', 'hysteria2', 'hy2'):
                raise ValueError('Unsupported entry in mixed subscription') from None
            if scheme.lower() == 'vless':
                uris.append(line)
        nodes = parse_subscription('\n'.join(uris).encode('utf-8'))
    usable = []
    for node in nodes:
        host = node['settings']['vnext'][0]['address']
        try:
            if not ipaddress.ip_address(host).is_global:
                continue
        except ValueError:
            name = host.rstrip('.').lower()
            if '.' not in name or name.endswith(('.localhost','.local','.internal')):
                continue
        usable.append(node)
    if not usable:
        raise ValueError('Subscription returned no routable VLESS nodes')
    return usable
