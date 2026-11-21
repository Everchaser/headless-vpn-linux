"""Loopback bootstrap DNS for Xray VPN peers only; no default-route retry."""
from contextlib import contextmanager
from copy import deepcopy
import http.client
import socket
import socketserver
import ssl
from threading import Thread

DOH = '1.1.1.1'
TIMEOUT = 4
MAX_DNS = 65535


def configure(published, port):
    config = deepcopy(published)
    for outbound in config['outbounds']:
        if outbound['protocol'] == 'vless':
            outbound['streamSettings']['sockopt']['domainStrategy'] = 'ForceIPv4'
    config['dns'] = {'queryStrategy': 'UseIPv4', 'servers': [f'tcp+local://127.0.0.1:{port}']}
    return config


def device_connection(interface, endpoint):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIMEOUT)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b'\0')
        sock.connect(endpoint)
        return sock
    except BaseException:
        sock.close()
        raise


def doh_query(interface, payload, context):
    with device_connection(interface, (DOH, 443)) as raw:
        with context.wrap_socket(raw, server_hostname=DOH) as tls:
            conn = http.client.HTTPConnection(DOH, 443, timeout=TIMEOUT)
            conn.sock = tls
            conn.auto_open = False
            conn.request('POST', '/dns-query', payload,
                         {'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'})
            with conn.getresponse() as response:
                if response.status != 200 or response.headers.get_content_type() != 'application/dns-message':
                    raise ValueError('Bootstrap DNS response rejected')
                reply = response.read(MAX_DNS + 1)
                if not 12 <= len(reply) <= MAX_DNS or reply[:2] != payload[:2]:
                    raise ValueError('Bootstrap DNS reply size or ID rejected')
                return reply


def question(payload):
    """Accept exactly one uncompressed IN/A question. Unknown callers fail closed."""
    if len(payload) < 17 or payload[2] & 0xf8 or payload[4:6] != b'\x00\x01':
        return None
    labels, i = [], 12
    while i < len(payload):
        size = payload[i]
        i += 1
        if not size:
            if payload[i:i+4] != b'\x00\x01\x00\x01':
                return None
            question_wire = payload[:4] + b'\0\x01' + b'\0'*6 + payload[12:i+4]
            return b'.'.join(labels).lower(), question_wire
        if size > 63 or i + size >= len(payload) or i + size > 267:
            return None
        labels.append(payload[i:i+size])
        i += size
    return None


class Resolver(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, interface):
        self.interface = interface
        self.context = ssl.create_default_context()
        self.peers = frozenset()
        super().__init__(('127.0.0.1', 0), QueryHandler)

    def add_peers(self, config):
        self.peers = self.peers.union(
            str(peer['address']).rstrip('.').encode('idna').lower()
            for outbound in config['outbounds'] if outbound['protocol'] == 'vless'
            for peer in outbound['settings']['vnext']
        )

    def configure(self, config):
        self.add_peers(config)
        return configure(config, self.server_address[1])


class QueryHandler(socketserver.StreamRequestHandler):
    timeout = TIMEOUT

    def handle(self):
        try:
            while header := self.rfile.read(2):
                size = int.from_bytes(header, 'big')
                payload = self.rfile.read(size)
                parsed = question(payload)
                if len(header) != 2 or len(payload) != size or parsed is None or parsed[0] not in self.server.peers:
                    return
                reply = doh_query(self.server.interface, parsed[1], self.server.context)
                self.wfile.write(len(reply).to_bytes(2, 'big') + reply)
        except (OSError, ValueError, http.client.HTTPException):
            return


@contextmanager
def resolver(interface):
    with Resolver(interface) as server:
        worker = Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            worker.join()
