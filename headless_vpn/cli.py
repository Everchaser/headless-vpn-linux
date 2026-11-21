"""CLI stages generations only: it never invokes systemctl."""
import utils.clients
import utils.http_session
import utils.transport
import utils.session
import argparse
import getpass
import json
from pathlib import Path
import re
import subprocess
import sys
from . import manager as m

HOME = Path.home()
DEFAULT_STATE = Path('/var/lib/headless-vpn/state')
DEFAULT_TEMPLATE = Path('/opt/headless-vpn/templates/tun.json')


def subscription_name(value):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}', value): raise ValueError('Invalid subscription name')
    return value


def parser():
    p = argparse.ArgumentParser(description='Headless VPN v2: private subscriptions and verified node generations. Does not start services; an already-active v2 runner applies accepted updates automatically.')
    p.add_argument('--state', type=Path, default=DEFAULT_STATE)
    p.add_argument('--template', type=Path, default=DEFAULT_TEMPLATE)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('init','add'): sub.add_parser(name).add_argument('file', type=Path)
    sub.add_parser('remove').add_argument('node_id')
    for name in ('list','check','probe'): sub.add_parser(name)
    subscriptions = sub.add_parser('subscription').add_subparsers(dest='action', required=True)
    add = subscriptions.add_parser('add'); add.add_argument('name'); add.add_argument('--url-stdin', action='store_true')
    add.add_argument('--device-name', help='opt in to provider-authorized HWID')
    subscriptions.add_parser('remove').add_argument('name')
    subscriptions.add_parser('list')
    subscriptions.add_parser('refresh')
    return p


def ready(nodes, interface):
    results = m.probe_nodes(nodes, interface)
    for result in results: print(json.dumps(result))
    return any(r['ok'] for r in results)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        from .subscription import parse_subscription
        template = json.loads(args.template.read_text())
        store = m.Store(args.state, template, m.default_interface())
        with store.locked():
            catalog = store.load(); changed = False; partial_failure = False
            if args.command in ('init','add'):
                if args.command == 'init' and store.current(): raise ValueError('Already initialized; use add')
                with args.file.open('rb') as stream: payload = stream.read(m.MAX_PAYLOAD + 1)
                if len(payload) > m.MAX_PAYLOAD: raise ValueError('Import exceeds payload size limit')
                nodes = parse_subscription(payload)
                if not ready(nodes, store.interface): raise ValueError('No reachable node; nothing changed')
                for node in nodes: catalog['manual'][m.node_id(node)] = node
                changed = True
            elif args.command == 'remove':
                if args.node_id not in catalog['manual']: raise ValueError('Not a manual node; remove its subscription instead')
                del catalog['manual'][args.node_id]; changed = True
            elif args.command == 'list':
                nodes = m.collect_nodes(catalog)
                print('Nodes:', len(nodes), 'Subscriptions:', len(catalog['subscriptions']))
                for node in nodes:
                    identity = m.node_id(node)
                    owners = (['manual'] if identity in catalog['manual'] else []) + [name for name, source in catalog['subscriptions'].items() if any(m.node_id(n) == identity for n in source['nodes'])]
                    print(identity, 'sources=' + ','.join(owners))
            elif args.command == 'check':
                current = store.current()
                if current is None: raise ValueError('No prepared generation')
                m.validate_effective_cores(current/'xray.json', current/'sing-box.json')
                if json.loads((current/'xray.json').read_text()) != m.xray_config(m.collect_nodes(catalog), store.interface): raise ValueError('Xray config does not match catalog/interface')
                if json.loads((current/'sing-box.json').read_text()) != m.sing_config(template,store.interface): raise ValueError('TUN config does not match template/interface')
                print('Both cores validated;', len(m.collect_nodes(catalog)), 'nodes. Live tunnel not changed.')
            elif args.command == 'probe':
                return 0 if ready(m.collect_nodes(catalog), store.interface) else 1
            elif args.command == 'subscription':
                if args.action == 'add':
                    name = subscription_name(args.name)
                    if name in catalog['subscriptions']: raise ValueError('Subscription already exists; use refresh')
                    url = sys.stdin.readline(8193).strip() if args.url_stdin else getpass.getpass('Subscription URL (hidden): ')
                    if len(url) > 8192: raise ValueError('Subscription URL too long')
                    source = {'url':url, 'nodes':[]}
                    if args.device_name is not None:
                        from .provider import valid_device_name
                        source['device_name'] = valid_device_name(args.device_name)
                    nodes = m.fetch_source(source, lambda url, **kw:m.fetch_subscription(url,store.interface,**kw), parse_subscription)
                    if not ready(nodes, store.interface): raise ValueError('No reachable subscription node; nothing changed')
                    source['nodes'] = nodes
                    catalog['subscriptions'][name] = source; changed = True
                elif args.action == 'remove':
                    name = subscription_name(args.name)
                    if name not in catalog['subscriptions']: raise ValueError('No such subscription')
                    del catalog['subscriptions'][name]; changed = True
                elif args.action == 'list':
                    for name, source in catalog['subscriptions'].items(): print(name, 'nodes=' + str(len(source['nodes'])))
                elif args.action == 'refresh':
                    fresh, errors = m.refreshed_catalog(catalog, lambda url, **kw:m.fetch_subscription(url,store.interface,**kw), parse_subscription, lambda nodes:ready(nodes,store.interface))
                    changed = fresh != catalog; catalog = fresh; partial_failure = bool(errors)
                    for name in errors: print('Refresh failed; retained old nodes:', name, file=sys.stderr)
            if changed:
                store.commit(catalog)
                print('Prepared',len(m.collect_nodes(catalog)),'nodes. No service started. An active v2 runner applies updates automatically; first activation requires separate consent.')
            elif args.command == 'subscription' and args.action == 'refresh': print('No configuration change.')
            return 1 if partial_failure else 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Parser/core/OS diagnostics can carry secrets. Never echo arbitrary exceptions.
        print('Operation failed (' + type(error).__name__ + '). No service started. Check input/connectivity and run check to verify retained state.', file=sys.stderr)
        return 1


if __name__ == '__main__': raise SystemExit(main())
