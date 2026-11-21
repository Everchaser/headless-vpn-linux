#!/usr/bin/env bash
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
target=/opt/headless-vpn
state=/var/lib/headless-vpn
owner=headless-vpn
fail() { printf '%s\n' "$*" >&2; exit 1; }
case "${1:-}" in
  --stage)
    [[ $# == 3 && $EUID == 0 ]] || fail 'Usage: sudo bash install-headless-vpn-v2.sh --stage /absolute/xray /absolute/sing-box'
    [[ $2 == /* && $3 == /* && -f $2 && -x $2 && -f $3 && -x $3 ]] || fail 'Use two absolute paths to trusted Linux executables.'
    [[ ! -e $target && ! -L $target && ! -e $state && ! -L $state ]] || fail 'Existing deployment/state: stop and review; nothing overwritten.'
    [[ -d /run/systemd/system && -c /dev/net/tun ]] || fail 'Requires systemd and /dev/net/tun.'
    python3 -c 'import sys; assert sys.version_info >= (3, 10)' || fail 'Python 3.10 or later is required.'
    for cmd in systemctl systemd-analyze curl ip install getent useradd groupadd runuser; do
      command -v "$cmd" >/dev/null || fail "Missing command: $cmd"
    done
    for unit in headless-vpn.service headless-vpn-xray.service headless-vpn-refresh.service headless-vpn-refresh.timer; do
      [[ $(systemctl show --property=LoadState --value "$unit") == not-found ]] || fail "Existing unit: $unit; use a clean host."
    done
    if getent passwd "$owner" >/dev/null || getent group "$owner" >/dev/null; then
      fail 'Existing account or group: review before staging.'
    fi
    xver=$("$2" version); sver=$("$3" version)
    [[ $xver =~ ^Xray[[:space:]]26\.7\.28[[:space:]] ]] || fail 'Expected Xray 26.7.28.'
    [[ $sver =~ ^sing-box[[:space:]]version[[:space:]]1\.12\.12($|[[:space:]]) ]] || fail 'Expected sing-box 1.12.12.'
    for file in headless_vpn/{bootstrap,cli,manager,provider,runner,subscription}.py systemd/{deployment.py,headless-vpn.service,headless-vpn-xray.service,headless-vpn-refresh.service,headless-vpn-refresh.timer} templates/tun.json; do
      [[ -f $project/$file && ! -L $project/$file ]] || fail "Missing or symlinked file: $file"
    done
    install -d -o root -g root -m 0755 "$target" "$target/bin" "$target/headless_vpn" "$target/systemd" "$target/templates"
    install -o root -g root -m 0755 "$project/install-headless-vpn-v2.sh" "$target/install-headless-vpn-v2.sh"
    for file in headless_vpn/{bootstrap,cli,manager,provider,runner,subscription}.py systemd/{deployment.py,headless-vpn.service,headless-vpn-xray.service,headless-vpn-refresh.service,headless-vpn-refresh.timer} templates/tun.json; do
      install -o root -g root -m 0644 "$project/$file" "$target/$file"
    done
    install -o root -g root -m 0755 -- "$2" "$target/bin/xray"
    install -o root -g root -m 0755 -- "$3" "$target/bin/sing-box"
    groupadd --system "$owner"
    useradd --system --no-create-home --home-dir "$state" --shell /bin/false --gid "$owner" "$owner"
    install -d -o root -g "$owner" -m 0750 "$state"
    install -d -o "$owner" -g "$owner" -m 0700 "$state/state"
    systemd-analyze verify "$target/systemd/"*.service "$target/systemd/"*.timer
    printf '%s\n' 'Staged. No units installed or started.'
    ;;
  --activate|--rollback)
    [[ $# == 1 && $EUID == 0 ]] || fail 'Activation and rollback must be explicit root actions.'
    action=activate; [[ $1 != --rollback ]] || action=rollback
    cd -- "$target"
    exec /usr/bin/python3 -I "$target/systemd/deployment.py" "$action" --activate
    ;;
  *) fail 'Usage: --stage /absolute/xray /absolute/sing-box | --activate | --rollback' ;;
esac
