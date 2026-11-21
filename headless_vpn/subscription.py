"""Strict, side-effect-free subscription import. No imported routing or tags."""
import base64
import binascii
import ipaddress
import json
import re
from urllib.parse import parse_qsl, unquote, urlsplit

MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_NODES = 4096


class SubscriptionError(ValueError):
    """Subscription cannot be safely represented by the supported schema."""


def _require(condition, message):
    if not condition:
        raise SubscriptionError(message)


_FINGERPRINTS = frozenset(('chrome', 'firefox', 'safari', 'ios', 'android', 'edge',
                          '360', 'qq', 'random', 'randomized', 'randomizednoalpn'))


def _text(value, *, empty=True):
    _require(isinstance(value, str) and len(value) <= 8192
             and (empty or value) and not any(ord(c) < 32 or ord(c) == 127 for c in value),
             'Invalid text option')
    return value


def _keys(value, allowed):
    _require(isinstance(value, dict), 'Expected settings object')
    _require(not (value.keys() - set(allowed)), 'Unsupported settings option')
    return value


def _key(value):
    _text(value, empty=False)
    _require(bool(re.fullmatch(r'[A-Za-z0-9_-]{43}', value)), 'Invalid REALITY key')
    _require(len(base64.b64decode(value + '=', altchars=b'-_', validate=True)) == 32,
             'Invalid REALITY key')
    return value


def _range(value, minimum=0):
    if type(value) is int:
        low = high = value
    else:
        _require(isinstance(value, str) and bool(re.fullmatch(r'[0-9]{1,10}(?:-[0-9]{1,10})?', value)),
                 'Invalid XHTTP integer range')
        ends = [int(v) for v in value.split('-')]
        low, high = min(ends), max(ends)
    _require(minimum <= low <= high <= 2147483647, 'Invalid XHTTP integer range')
    return high


def _headers(value, *, allow_host=False):
    _require(isinstance(value, dict) and len(value) <= 64, 'Invalid HTTP headers')
    seen = set()
    for name, item in value.items():
        _require(bool(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)), 'Invalid HTTP header name')
        _require(name.lower() not in seen, 'Duplicate HTTP header')
        seen.add(name.lower())
        _require(allow_host or name.lower() != 'host', 'Use dedicated HTTP host option')
        _text(item)
    return value


def _xhttp_extra(value):
    # XHTTP's xmux controls HTTP connection reuse, not outbound Mux.Cool.
    # downloadSettings can introduce a second dialer and is deliberately excluded.
    ranges = {'xPaddingBytes', 'scMaxEachPostBytes', 'scMinPostsIntervalMs', 'scStreamUpServerSecs'}
    booleans = {'noGRPCHeader', 'noSSEHeader', 'xPaddingObfsMode'}
    integers = {'scMaxBufferedPosts', 'serverMaxHeaderBytes'}
    _keys(value, ranges | booleans | integers | {'headers', 'xmux', 'mode'})
    for name, item in value.items():
        if name == 'mode':
            _require(item in ('auto', 'packet-up', 'stream-up', 'stream-one'), 'Unsupported XHTTP extra mode')
        elif name in ranges:
            _range(item, 1 if name == 'xPaddingBytes' else 0)
        elif name in booleans:
            _require(type(item) is bool, 'Invalid XHTTP boolean')
        elif name in integers:
            _require(type(item) is int and 0 <= item <= 2147483647, 'Invalid XHTTP integer')
        elif name == 'headers':
            _headers(item)
        elif name == 'xmux':
            names = {'maxConcurrency', 'maxConnections', 'cMaxReuseTimes', 'hMaxRequestTimes', 'hMaxReusableSecs'}
            _keys(item, names | {'hKeepAlivePeriod'})
            for key, number in item.items():
                if key == 'hKeepAlivePeriod':
                    _require(type(number) is int and -1 <= number <= 2147483647, 'Invalid XHTTP keepalive')
                else:
                    _range(number)
            _require(not (_range(item.get('maxConcurrency', 0)) and _range(item.get('maxConnections', 0))),
                     'Conflicting XHTTP connection limits')
    return value


def _stream(value):
    _require(isinstance(value, dict), 'Expected stream settings object')
    value = dict(value)
    if 'sockopt' in value:
        # Interface ownership belongs to the trusted builder, never an import.
        _keys(value.pop('sockopt'), {'interface'})
    if 'rawSettings' in value:
        _require('tcpSettings' not in value, 'Conflicting transport settings')
        value['tcpSettings'] = value.pop('rawSettings')
    network = value.get('network', 'tcp')
    if network == 'raw':
        network = 'tcp'
    security = value.get('security', 'none')
    _require(network in ('tcp', 'ws', 'grpc', 'xhttp'), 'Unsupported transport')
    _require(security in ('none', 'tls', 'reality'), 'Unsupported stream security')
    transport_key = {'tcp': 'tcpSettings', 'ws': 'wsSettings', 'grpc': 'grpcSettings',
                     'xhttp': 'xhttpSettings'}[network]
    allowed = {'network', 'security', transport_key}
    if security != 'none':
        allowed.add(security + 'Settings')
    _keys(value, allowed)
    result = {'network': network, 'security': security}
    if security != 'none':
        settings = dict(value.get(security + 'Settings', {}))
        allowed_security = {'serverName', 'fingerprint'}
        allowed_security |= {'alpn'} if security == 'tls' else {'publicKey', 'password', 'shortId', 'spiderX'}
        _keys(settings, allowed_security)
        for name, item in settings.items():
            if not (security == 'tls' and name == 'alpn'):
                _text(item)
        if 'fingerprint' in settings:
            _require(settings['fingerprint'] in _FINGERPRINTS, 'Unsupported TLS fingerprint')
        if security == 'tls' and 'alpn' in settings:
            alpn = settings['alpn']
            _require(isinstance(alpn, list) and 0 < len(alpn) <= 16, 'Invalid TLS ALPN')
            for item in alpn:
                _text(item, empty=False)
                _require(len(item.encode('utf-8')) <= 255 and not item.startswith('fromMitm'), 'Unsupported TLS ALPN')
        if security == 'reality':
            _require(network != 'ws', 'REALITY is unsupported for this transport')
            _require(not ('publicKey' in settings and 'password' in settings), 'Conflicting REALITY key aliases')
            _require('publicKey' in settings or 'password' in settings, 'Missing REALITY key')
            key_name = 'password' if 'password' in settings else 'publicKey'
            _key(settings[key_name])
            _require(bool(re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', settings.get('shortId', ''))), 'Invalid REALITY short id')
            _require(settings.get('spiderX', '/').startswith('/'), 'Invalid REALITY spider path')
            settings.setdefault('fingerprint', 'chrome')
        result[security + 'Settings'] = settings
    if transport_key in value:
        transport = dict(value[transport_key])
        allowed_transport = {'tcp': {'header'}, 'ws': {'host', 'path'},
                             'grpc': {'serviceName', 'authority', 'multiMode'},
                             'xhttp': {'host', 'path', 'mode', 'extra'}}[network]
        _keys(transport, allowed_transport)
        for name, item in transport.items():
            if name == 'multiMode':
                _require(type(item) is bool, 'Invalid gRPC multiMode')
            elif name == 'extra':
                _xhttp_extra(item)
            elif name == 'header':
                _require(item == {'type': 'none'}, 'Unsupported TCP header')
            else:
                _text(item)
        if network == 'xhttp':
            _require(transport.get('mode', 'auto') in ('auto', 'packet-up', 'stream-up', 'stream-one'), 'Unsupported XHTTP mode')
            # Xray v26.7.28 overwrites extra.Mode with the outer Mode.
            # Accept redundant provider metadata, reject contradictory intent.
            extra = transport.get('extra', {})
            if 'mode' in extra:
                _require(extra['mode'] == transport.get('mode', 'auto'), 'Conflicting XHTTP mode')
        result[transport_key] = transport
    return result


def _uri(line):
    _require(not any(ord(c) < 33 or ord(c) == 127 for c in line), 'Invalid URI whitespace')
    _require(not re.search(r'%(?![0-9a-fA-F]{2})', line), 'Invalid URI encoding')
    uri = urlsplit(line)
    _require(uri.scheme == 'vless', 'Unsupported subscription protocol')
    _require(uri.password is None and uri.path in ('', '/'), 'Unsupported URI authority or path')
    ident = unquote(uri.username or '', errors='strict')
    _require(bool(re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', ident)),
             'Invalid VLESS id')
    _require(uri.hostname and uri.port is not None and 1 <= uri.port <= 65535, 'Invalid endpoint')
    pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True, errors='strict', max_num_fields=64)
    _require(len(dict(pairs)) == len(pairs), 'Duplicate URI option')
    options = dict(pairs)
    network = options.pop('type', 'tcp')
    network = 'tcp' if network == 'raw' else network
    security = options.pop('security', 'none')
    if 'support-x25519mlkem768' in options:
        # Mihomo-style capability hint. The installed Xray 26.7.28 already
        # negotiates hybrid REALITY automatically (upstream since v25.5.16).
        # Do not silently accept a request to disable it or unrelated security.
        _require(security == 'reality' and options.pop('support-x25519mlkem768') == 'true',
                 'Unsupported REALITY hybrid support hint')
    user = {'id': ident, 'encryption': options.pop('encryption', 'none')}
    _require(user['encryption'] == 'none', 'Unsupported VLESS encryption')
    if 'flow' in options:
        user['flow'] = options.pop('flow')
        _require(user['flow'] in ('', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'), 'Unsupported VLESS flow')
        _require(not user['flow'] or (network == 'tcp' and security in ('tls', 'reality')), 'Unsupported flow transport')
    stream = {'network': network, 'security': security}
    if security in ('tls', 'reality'):
        settings = {}
        mapping = {'sni': 'serverName', 'fp': 'fingerprint'}
        if security == 'reality':
            mapping.update({'pbk': 'publicKey', 'publicKey': 'publicKey', 'password': 'publicKey',
                            'sid': 'shortId', 'spx': 'spiderX'})
        for source, target in mapping.items():
            if source in options:
                _require(target not in settings, 'Conflicting URI aliases')
                settings[target] = options.pop(source)
        if security == 'tls' and 'alpn' in options:
            settings['alpn'] = options.pop('alpn').split(',')
        stream[security + 'Settings'] = settings
    if network in ('ws', 'xhttp', 'grpc'):
        transport = {}
        names = ('serviceName', 'authority') if network == 'grpc' else ('host', 'path')
        for name in names:
            if name in options:
                transport[name] = options.pop(name)
        if 'mode' in options:
            mode = options.pop('mode')
            if network == 'grpc':
                _require(mode in ('gun', 'multi'), 'Unsupported gRPC mode')
                transport['multiMode'] = mode == 'multi'
            elif network == 'xhttp':
                transport['mode'] = mode
            else:
                raise SubscriptionError('Unsupported WebSocket mode')
        if network == 'xhttp' and 'extra' in options:
            transport['extra'] = _json(options.pop('extra'))
        stream[network + 'Settings'] = transport
    if network == 'tcp' and 'headerType' in options:
        _require(options.pop('headerType') == 'none', 'Unsupported TCP header')
    _require(not options, 'Unsupported URI option')
    return {'protocol': 'vless', 'settings': {'vnext': [
        {'address': uri.hostname, 'port': uri.port, 'users': [user]}]},
        'streamSettings': _stream(stream)}


def _address(value):
    _text(value, empty=False)
    _require(len(value) <= 253 and '%' not in value, 'Invalid endpoint address')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        _require(all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                     for label in value.rstrip('.').split('.')), 'Invalid endpoint address')
    return value


def _outbound(value):
    _keys(value, {'protocol', 'settings', 'streamSettings', 'tag'})
    _require(value.get('protocol') == 'vless', 'Unsupported outbound protocol')
    settings = value.get('settings')
    _require(isinstance(settings, dict), 'Expected VLESS settings object')
    if 'vnext' in settings:
        _keys(settings, {'vnext'})
        endpoints = settings['vnext']
        _require(isinstance(endpoints, list) and len(endpoints) == 1, 'Expected one VLESS endpoint')
        endpoint = endpoints[0]
        _keys(endpoint, {'address', 'port', 'users'})
        users = endpoint.get('users')
        _require(isinstance(users, list) and len(users) == 1, 'Expected one VLESS user')
        user = users[0]
    else:
        _keys(settings, {'address', 'port', 'id', 'encryption', 'flow', 'email', 'level'})
        endpoint = settings
        user = {k: v for k, v in settings.items() if k not in ('address', 'port')}
    _keys(user, {'id', 'encryption', 'flow', 'email', 'level'})
    user = dict(user)
    ident = _text(user.get('id'), empty=False)
    _require(bool(re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', ident)), 'Invalid VLESS id')
    user.setdefault('encryption', 'none')
    _require(user['encryption'] == 'none', 'Unsupported VLESS encryption')
    flow = user.get('flow', '')
    _require(flow in ('', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'), 'Unsupported VLESS flow')
    if 'email' in user:
        _text(user['email'])
    if 'level' in user:
        _require(type(user['level']) is int and 0 <= user['level'] <= 4294967295, 'Invalid VLESS user level')
    address = _address(endpoint.get('address'))
    port = endpoint.get('port')
    _require(type(port) is int and 1 <= port <= 65535, 'Invalid endpoint port')
    stream = _stream(value.get('streamSettings', {}))
    _require(not flow or (stream['network'] == 'tcp' and stream['security'] in ('tls', 'reality')), 'Unsupported flow transport')
    return {'protocol': 'vless', 'settings': {'vnext': [{'address': address, 'port': port, 'users': [user]}]},
            'streamSettings': stream}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def _json(text):
    def invalid_constant(_):
        raise SubscriptionError('Invalid JSON constant')
    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=invalid_constant)


def _document(value, *, nested=False):
    if isinstance(value, list):
        _require(not nested and 0 < len(value) <= MAX_NODES, 'Invalid subscription list')
        result = [node for item in value for node in _document(item, nested=True)]
    elif isinstance(value, dict) and 'outbounds' in value:
        _require('protocol' not in value, 'Ambiguous JSON document')
        nodes = value['outbounds']
        _require(isinstance(nodes, list) and 0 < len(nodes) <= MAX_NODES, 'Invalid outbounds list')
        result = []
        for node in nodes:
            _require(isinstance(node, dict), 'Expected outbound object')
            # Ancillary full-config routes are rebuilt, not imported as VPN nodes.
            if node.get('protocol') in ('freedom', 'blackhole', 'dns'):
                continue
            result.append(_outbound(node))
    else:
        result = [_outbound(value)]
    _require(0 < len(result) <= MAX_NODES, 'Invalid subscription node count')
    return result


def parse_subscription(payload: bytes) -> list[dict]:
    """Return credential-bearing outbounds; callers must never log the result.

    This parser performs no I/O. Errors contain fixed messages, not source data.
    """
    try:
        _require(isinstance(payload, bytes), 'Subscription must be bytes')
        _require(0 < len(payload) <= MAX_PAYLOAD_BYTES, 'Empty or oversized subscription')
        text = payload.decode('utf-8-sig').strip()
        _require(text and not text.startswith('<'), 'Empty or HTML subscription')
        if text.startswith(('{', '[')):
            return _document(_json(text))
        if '://' not in text:
            encoded = re.sub(r'\s+', '', text)
            text = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True).decode('utf-8-sig').strip()
        _require(text and not text.startswith('<'), 'Empty or HTML subscription')
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        _require(0 < len(lines) <= MAX_NODES, 'Invalid subscription node count')
        return [_uri(line) for line in lines]
    except SubscriptionError:
        raise
    except (ValueError, TypeError, UnicodeError, binascii.Error, RecursionError):
        raise SubscriptionError('Malformed subscription') from None
