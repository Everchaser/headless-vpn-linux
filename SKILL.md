---
name: headless-vpn-linux
description: Use when deploying or debugging a Linux headless VPN.
version: 0.1.0
author: Everchaser, Hermes Agent
platforms: [linux]
metadata:
  hermes:
    tags: [VPN, Linux, systemd, Xray, sing-box, HWID]
    related_skills: []
---

# Headless VPN Linux

Use for this app's fresh-host staging, subscription import, cutover or troubleshooting. Do not use to set up VPN provider infrastructure or take over an unrelated tunnel. Locating this skill doesn't install the app: resolve the checkout and read its `README.md`, `docs/deploy.md`, and `docs/operations.md` with `read_file` before executing commands.

## Procedure

1. **Inventory, read only.** Use `terminal` to inspect systemd units, current `ip` links/routes and TUN availability. Confirm a physical IPv4 uplink and a console that survives lost SSH. Stop if a different tunnel, conflicting units, or unsupported IPv6 routing is present. Never use a GUI client's CLI help to discover its state.
2. **Stage without activation.** Verify release URLs/checksums for the pinned binaries before executing them. Follow the checkout's `docs/deploy.md`; `--stage` must report no units installed or started. Keep this separate from boot enablement and route changes.
3. **Enroll privately and probe.** Give the operator the exact unprivileged import command. Subscription URLs are bearer secrets; never request them in chat or embed them in logs/argv. Use `--device-name` only for an authorized HWID subscription. `check` proves syntax; `probe` must show at least one working node, two for meaningful fallback. `ok: false` does not prove that the link itself is invalid.
4. **Cut over only after permission.** Establish the rollback command and confirm the old TUN is absent. If the portable units are already installed, use their documented start path; don't reinstall to clear a backup. If activation fails, preserve the backup, stop the new path, and verify state before returning to the old VPN.
5. **Verify traffic, then report.** Use `terminal` for service active state, TUN interface, and repeated real HTTPS probes, separately through the host route and localhost SOCKS. Confirm the new generation appeared in logs and distinguish child Xray replacement from systemd restart. Record per-host outcomes using `docs/checklist.md`. Do not label cold boot or failover verified merely because a start or subscription update succeeded.

## Pitfalls

- Live subscription publication can reconnect clients without restarting the TUN. Never test by importing arbitrary fixtures on the live service.
- The bootstrap resolver only resolves IPv4 names of configured VPN peers. Ordinary browsing DNS still goes through the VPN. Don't broaden egress or turn off TLS verification to get a test to pass.
- If host and SOCKS fail together, separate upstream failure from routing; if one public health endpoint fails, try a second and inspect restart counters before changing anything.
