"""Unprivileged Xray supervisor; applies validated generations, never manages TUN/Happ."""
import argparse

import json
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from . import bootstrap, manager as m


class Controller:
    def __init__(self, validate, start, stop, healthy, rollback):
        self.validate, self.start, self.stop = validate, start, stop
        self.healthy, self.rollback = healthy, rollback
        self.process = None
        self.generation = None

    def apply(self, generation):
        if generation == self.generation and self.process is not None: return True
        self.validate(generation)
        previous = self.generation
        if self.process is not None:
            self.stop(self.process); self.process = None
        try:
            self.process = self.start(generation)
            if not self.healthy(self.process): raise ValueError('Candidate did not pass egress check')
        except (ValueError, OSError, subprocess.SubprocessError):
            if self.process is not None:
                self.stop(self.process); self.process = None
            if previous is not None:
                self.rollback(previous)
                self.process = self.start(previous)
                try:
                    restored = self.healthy(self.process)
                except (ValueError, OSError, subprocess.SubprocessError):
                    restored = False
                if not restored:
                    self.stop(self.process); self.process = None
            return False
        self.generation = generation
        return True


def stop(process):
    if process.poll() is not None: return
    process.terminate()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)


def validate_generation(generation, previous=None, tun_snapshot=Path('/run/headless-vpn-v2/sing-box.json'), *, xray_path=None):
    m.validate_cores(xray_path or generation / 'xray.json', generation / 'sing-box.json')
    baseline = tun_snapshot if tun_snapshot.exists() else (previous / 'sing-box.json' if previous else None)
    if baseline is not None:
        old = json.loads(baseline.read_text())
        new = json.loads((generation / 'sing-box.json').read_text())
        if old != new:
            raise ValueError('TUN changes require separately approved restart')


def tick(controller, store):
    """Recover an immutable active generation before competing with slow refresh."""
    if controller.process is not None and controller.process.poll() is not None:
        controller.process = None
    if controller.process is None and controller.generation is not None:
        controller.validate(controller.generation)
        controller.process = controller.start(controller.generation)
        if not controller.healthy(controller.process):
            controller.stop(controller.process); controller.process = None
            raise ValueError('Active generation could not recover')
        # No pointer rollback here: a concurrent publisher owns its pending update.
    try:
        with store.locked(blocking=False):
            generation = store.current()
            if generation is None: raise ValueError('No prepared generation')
            if generation == controller.generation and controller.process is not None:
                return None
            try:
                success = controller.apply(generation)
                event = 'Generation applied' if success else 'Candidate failed; previous generation restored'
            except (ValueError, OSError, subprocess.SubprocessError):
                if controller.generation is None: raise
                store.point_to(controller.generation)
                event = 'Candidate validation failed; retained previous generation'
            if controller.process is None: raise ValueError('No healthy upstream')
            return event
    except BlockingIOError:
        return None


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,default=Path('/var/lib/headless-vpn/state'))
    args=parser.parse_args(argv)
    store=m.Store(args.state,{},m.default_interface())
    stopping=False
    def on_signal(signum, frame):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,on_signal);signal.signal(signal.SIGINT,on_signal)
    runtime = None

    def runtime_path(generation):
        return runtime / (generation.name + '.json')

    def validate(generation):
        path = runtime_path(generation)
        if not path.exists():
            published = json.loads((generation / 'xray.json').read_text())
            m.private_json(path, dns.configure(published))
        validate_generation(generation, controller.generation, xray_path=path)
    def start(generation):
        return subprocess.Popen([m.XRAY,'run','-c',str(runtime_path(generation))],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def healthy(process):
        deadline=time.monotonic()+45
        while not stopping and time.monotonic()<deadline:
            if process.poll() is not None:return False
            if m.http_probe(10818,timeout=6):return True
            time.sleep(1)
        return False
    controller=Controller(validate,start,stop,healthy,store.point_to)
    with bootstrap.resolver(store.interface) as dns, tempfile.TemporaryDirectory(prefix='headless-xray-') as folder:
        runtime = Path(folder)
        try:
            while not stopping:
                event = tick(controller, store)
                if event: print(event, flush=True)
                for path in runtime.glob('*.json'):
                    if controller.generation is None or path != runtime_path(controller.generation):
                        path.unlink()
                for _ in range(10):
                    if stopping:break
                    time.sleep(.5)
            return 0
        except (ValueError,OSError,subprocess.SubprocessError):
            print('Xray supervisor stopped: no valid running generation; systemd may retry',flush=True)
            return 1
        finally:
            if controller.process is not None:stop(controller.process)


if __name__=='__main__':raise SystemExit(main())
