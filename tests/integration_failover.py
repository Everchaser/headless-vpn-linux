#!/usr/bin/env python3
"""Exercise the real Xray balancer, entirely on loopback, without service changes.

Catches a pinned/stale selected outbound, direct all-down fallback, and failure
of observatory-driven recovery. Negative controls deliberately break the test
configuration, never manager.py or any deployed configuration.
"""
from __future__ import annotations

import argparse
import contextlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from headless_vpn import manager

HOST = "127.0.0.1"
IO_TIMEOUT = 2.0


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise OSError("connection closed")
        data.extend(part)
    return bytes(data)


def socks_connect(sock, port):
    sock.sendall(b"\x05\x01\x00")
    require(read_exact(sock, 2) == b"\x05\x00", "SOCKS authentication failed")
    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(HOST) + struct.pack("!H", port))
    version, status, _, kind = read_exact(sock, 4)
    if version != 5 or status:
        raise OSError(f"SOCKS CONNECT rejected ({status})")
    size = {1: 4, 4: 16}.get(kind)
    if kind == 3:
        size = read_exact(sock, 1)[0]
    require(size is not None, "invalid SOCKS address type")
    read_exact(sock, size + 2)


def request(origin_port, path, proxy_port=None):
    """A fresh TCP connection every time; no curl, DNS, proxy env, or pooling."""
    with socket.create_connection((HOST, proxy_port or origin_port), timeout=IO_TIMEOUT) as sock:
        sock.settimeout(IO_TIMEOUT)
        if proxy_port is not None:
            socks_connect(sock, origin_port)
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}:{origin_port}\r\n"
                      "Connection: close\r\n\r\n").encode("ascii"))
        response = http.client.HTTPResponse(sock)
        response.begin()
        body = response.read(4096)
        require(response.status == 200, f"unexpected HTTP status {response.status}")
        return json.loads(body)


class Origin(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self):
        super().__init__((HOST, 0), OriginHandler)
        self.events = []
        self.lock = threading.Lock()

    def record(self, path, node):
        with self.lock:
            self.events.append((path, node))

    def snapshot(self):
        with self.lock:
            return list(self.events)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(IO_TIMEOUT)
        return connection, address


class OriginHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        node = self.headers.get("X-Fixture-Node", "DIRECT")
        self.server.record(self.path, node)
        health = self.path == "/health"
        body = b"" if health else json.dumps({"path": self.path, "node": node}).encode()
        self.send_response(204 if health else 200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

    do_HEAD = do_GET


class Fixture(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False

    def __init__(self, name, origin_port, delay=0):
        super().__init__((HOST, 0), FixtureHandler)
        self.name = name
        self.origin_port = origin_port
        self.delay = delay
        self.healthy = threading.Event()
        self.rejections = 0
        self.lock = threading.Lock()


class FixtureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.forward()
        except (OSError, ValueError):
            # Expected for deliberately failed nodes / terminated client sockets.
            pass

    def forward(self):
        client = self.request
        client.settimeout(IO_TIMEOUT)
        version, count = read_exact(client, 2)
        methods = read_exact(client, count)
        if version != 5 or 0 not in methods:
            return
        client.sendall(b"\x05\x00")
        version, command, _, kind = read_exact(client, 4)
        if kind == 1:
            host = socket.inet_ntoa(read_exact(client, 4))
        elif kind == 3:
            host = read_exact(client, read_exact(client, 1)[0]).decode("ascii")
        else:
            return
        port = struct.unpack("!H", read_exact(client, 2))[0]
        # No arbitrary forwarding or external DNS, even with a broken config.
        if (version, command, host, port) != (5, 1, HOST, self.server.origin_port):
            client.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
            return
        if not self.server.healthy.is_set():
            with self.server.lock:
                self.server.rejections += 1
            client.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
            return
        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        data = bytearray()
        while b"\r\n\r\n" not in data:
            data.extend(read_exact(client, 1))
            if len(data) > 16384:
                raise ValueError("oversized fixture request")
        if self.server.delay:
            time.sleep(self.server.delay)
        if not self.server.healthy.is_set():
            return
        # Origin independently records which actual SOCKS transport was used.
        data = bytes(data[:-2]) + f"X-Fixture-Node: {self.server.name}\r\n\r\n".encode()
        with socket.create_connection((HOST, port), timeout=IO_TIMEOUT) as upstream:
            upstream.sendall(data)
            while chunk := upstream.recv(16384):
                client.sendall(chunk)


def wait_for(label, operation, timeout, process):
    started = time.monotonic()
    attempts = 0
    last = "not attempted"
    while time.monotonic() - started < timeout:
        require(process.poll() is None, "Xray unexpectedly exited")
        attempts += 1
        try:
            result = operation()
            if result:
                return result, attempts, round(time.monotonic() - started, 3)
            last = "condition not yet met"
        except (OSError, http.client.HTTPException) as exc:
            last = str(exc)
        time.sleep(0.15)
    raise AssertionError(f"{label} did not converge within {timeout}s: {last}")


def run(args):
    require(os.geteuid() != 0, "run this integration test as a non-root user")
    started = time.monotonic()
    servers = []
    threads = []
    ports = []
    process = None
    reservation = None
    # Explicitly avoid /tmp and all private/live VPN configuration directories.
    scratch = Path(os.environ.get("TMPDIR", Path.home() / ".hermes/cache/scratch"))
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xray-failover-", dir=scratch) as folder:
        log_path = Path(folder) / "xray.log"
        access_path = Path(folder) / "access.log"
        try:
            origin = Origin()
            servers.append(origin)
            origin_port = origin.server_address[1]
            a = Fixture("A", origin_port)
            servers.append(a)
            b = Fixture("B", origin_port, delay=0.12)
            servers.append(b)
            a.healthy.set()
            for server in servers:
                ports.append(server.server_address[1])
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
                thread.start()
                threads.append(thread)
            # Hold a kernel-assigned port until immediately before Xray starts.
            reservation = socket.socket()
            reservation.bind((HOST, 0))
            proxy_port = reservation.getsockname()[1]
            ports.append(proxy_port)
            require(len(set(ports)) == 4, "fixture ports must be distinct")
            nodes = [{"protocol": "vless", "settings": {"vnext": [{
                "address": HOST, "port": server.server_address[1],
                "users": [{"id": str(uuid.UUID(int=index)), "encryption": "none"}]
            }]}} for index, server in enumerate((a, b), 1)]
            config = manager.xray_config(nodes, "lo", port=proxy_port,
                                         probe_interval="1s", probe_url=f"http://{HOST}:{origin_port}/health")
            require(len(config["inbounds"]) == 1 and all(
                inbound.get("listen") == HOST and inbound.get("protocol") == "socks"
                and inbound.get("port") == proxy_port for inbound in config["inbounds"]),
                "builder must create only the allocated loopback SOCKS listener")
            require(len(config["outbounds"]) == 3, "unexpected additional builder outbound")
            tags = []
            for outbound, server in zip(config["outbounds"], (a, b)):
                tags.append(outbound["tag"])
                outbound.clear()
                outbound.update({"tag": tags[-1], "protocol": "socks", "settings": {
                    "servers": [{"address": HOST, "port": server.server_address[1]}]}})
            # The fixture substitution drops physical-device sockopt binding; all
            # destinations are loopback. Routing/observatory/tags stay builder-owned.
            if args.negative_control == "pin-primary":
                config["routing"]["rules"] = [{"type": "field", "network": "tcp,udp", "outboundTag": tags[0]}]
            elif args.negative_control == "direct-fallback":
                config["outbounds"][-1] = {"tag": "block", "protocol": "freedom"}
            config["log"] = {"loglevel": "info", "access": str(access_path)}
            config_path = Path(folder) / "xray.json"
            manager.private_json(config_path, config)
            version = subprocess.run([manager.XRAY, "version"], check=True, capture_output=True,
                                     text=True, timeout=10).stdout.splitlines()[0]
            validation = subprocess.run([manager.XRAY, "-test", "-c", str(config_path)],
                                        capture_output=True, text=True, timeout=20)
            require(validation.returncode == 0, "Xray rejected test config: " + validation.stdout + validation.stderr)
            emit("setup", xray=version, ports=ports, negative_control=args.negative_control,
                 node_tags=dict(zip(("A", "B"), tags)))
            reservation.close()
            reservation = None
            # Scrub ambient proxies; only our generated, credential-free config is read.
            env = {key: value for key, value in os.environ.items()
                   if "proxy" not in key.lower() and not key.lower().startswith(("xray.", "v2ray."))}
            with log_path.open("w") as log:
                process = subprocess.Popen([manager.XRAY, "run", "-c", str(config_path)],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env)

            def fetch_node(expected, phase):
                token = "/request/" + phase + "/" + uuid.uuid4().hex
                response = request(origin_port, token, proxy_port)
                require(response["path"] == token, "stale or mismatched origin response")
                require((token, response["node"]) in origin.snapshot(), "origin did not record response")
                if response["node"] != expected:
                    return False
                return response

            result, attempts, elapsed = wait_for("initial node A", lambda: fetch_node("A", "initial"), args.phase_timeout, process)
            emit("initial", node=result["node"], attempts=attempts, elapsed_s=elapsed)
            b.healthy.set()
            wait_for("backup health probe", lambda: ("/health", "B") in origin.snapshot(), args.phase_timeout, process)
            # Establish the selected node immediately before disabling it.
            wait_for("selected node A", lambda: fetch_node("A", "selected"), args.phase_timeout, process)
            a.healthy.clear()
            try:
                request(origin_port, "/control/disabled-A", a.server_address[1])
            except (OSError, http.client.HTTPException):
                pass
            else:
                raise AssertionError("selected node A still forwards after failure injection")
            require(not any(path == "/control/disabled-A" for path, _ in origin.snapshot()),
                    "disabled node A reached origin")
            emit("failure_injected", selected_node="A", direct_socks_request_failed=True)
            result, attempts, elapsed = wait_for("failover A -> B", lambda: fetch_node("B", "failover"), args.phase_timeout, process)
            require(not a.healthy.is_set(), "failed node was accidentally revived")
            emit("failover", failed_node="A", actual_node=result["node"], attempts=attempts, elapsed_s=elapsed)

            b.healthy.clear()
            # Keep the origin up: fail-closed must not be confused with a dead origin.
            require(request(origin_port, "/control/all-down")["node"] == "DIRECT", "origin positive control failed")
            blocked_before = access_path.read_text().count("[socks -> block]") if access_path.exists() else 0
            all_down_paths = []

            def closed_and_blackholed():
                token = "/request/all-down/" + uuid.uuid4().hex
                all_down_paths.append(token)
                try:
                    response = request(origin_port, token, proxy_port)
                except (OSError, http.client.HTTPException):
                    response = None
                require(response is None, f"all-down leaked to origin: {response}")
                require(not any(path == token for path, _ in origin.snapshot()), "all-down reached origin despite client failure")
                return access_path.exists() and access_path.read_text().count("[socks -> block]") > blocked_before

            _, attempts, elapsed = wait_for("all-down blackhole routing", closed_and_blackholed, args.phase_timeout, process)
            for _ in range(3):
                require(closed_and_blackholed(), "all-down no longer blackholed")
            require(not any(path in all_down_paths for path, _ in origin.snapshot()), "all-down requests reached origin")
            emit("all_down", origin_alive=True, failed_requests=len(all_down_paths), origin_arrivals=0,
                 blackhole_access_observed=True, attempts=attempts, elapsed_s=elapsed)
            a.healthy.set()
            result, attempts, elapsed = wait_for("recovery via A", lambda: fetch_node("A", "recovery"), args.phase_timeout, process)
            require(not b.healthy.is_set(), "recovery used a revived backup")
            emit("recovery", actual_node=result["node"], backup_still_down=True, attempts=attempts, elapsed_s=elapsed)
            # The same child must survive every phase: no restart-driven switching.
            require(process.poll() is None, "Xray exited after recovery")
            emit("verified", xray_pid=process.pid, one_process_all_phases=True,
                 elapsed_s=round(time.monotonic() - started, 3))
        except BaseException:
            if log_path.exists():
                print("--- isolated Xray log tail ---", file=sys.stderr)
                print("\n".join(log_path.read_text(errors="replace").splitlines()[-18:]), file=sys.stderr)
            raise
        finally:
            if reservation is not None:
                reservation.close()
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=4)
                else:
                    process.wait(timeout=1)
            for server, thread in zip(servers, threads):
                server.shutdown()
                thread.join(timeout=4)
            for server in servers:
                server.server_close()
            require(not any(thread.is_alive() for thread in threads), "fixture thread survived cleanup")
            require(process is None or process.poll() is not None, "Xray child survived cleanup")
            # Check exact owned ports rather than inspecting unrelated host listeners.
            for port in ports:
                with socket.socket() as probe:
                    probe.settimeout(0.2)
                    require(probe.connect_ex((HOST, port)) != 0, f"listener survived cleanup: {port}")
            emit("cleanup", child_reaped=process is None or process.poll() is not None,
                 fixture_threads_stopped=True, listeners_remaining=0)
    emit("PASS", elapsed_s=round(time.monotonic() - started, 3))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase-timeout", type=float, default=45, help="bounded convergence timeout per phase (seconds)")
    parser.add_argument("--negative-control", choices=("pin-primary", "direct-fallback"),
                        help="deliberately broken in-memory test config; expected exit 1")
    args = parser.parse_args()
    if not 1 <= args.phase_timeout <= 120:
        parser.error("--phase-timeout must be between 1 and 120")
    # SIGTERM should unwind owned resources just like Ctrl-C; SIGKILL cannot.
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        run(args)
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        emit("FAIL", reason=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
