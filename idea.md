# Remote RDP Access via Telegram Bot — Setup Overview

## Goal
Control access to a home PC (PC1) remotely via a Telegram bot, connecting from a second PC (PC2) that has **no VPN client installed**. No Wake-on-LAN in this version — PC1 is assumed to be already powered on.

## Components

| Component | Role |
|---|---|
| **PC1** | Target machine, receives RDP connections. Behind NAT, no public IP. Joined to a Tailscale (or self-hosted Headscale) mesh VPN. |
| **VDS** | Public IP server. Acts as: (1) Telegram bot host, (2) TCP port-forwarder bridging the public internet to the private VPN network. |
| **PC2** | Client machine, initiates RDP connection. **No VPN required** — connects directly to the VDS's public IP with a standard RDP client. |

## Network Topology

```
PC2 (no VPN) --RDP--> VDS:<custom_port> (public IP) --Tailscale tunnel--> PC1 (private tailnet IP)
```

The VDS is the only bridge between the public internet and the private mesh network. PC1 is never directly exposed.

## Access Flow

1. User sends `/rdp_on` to the Telegram bot.
2. Bot (running on VDS):
   - Connects to PC1 over the tailnet (SSH/WinRM) and enables RDP:
     - Sets `fDenyTSConnections = 0` in the registry.
     - Enables the Windows Firewall "Remote Desktop" rule group.
   - Starts a TCP forwarder on the VDS (`socat`, `iptables DNAT`, or `nginx stream`) listening on a **non-default, high port**, forwarding to PC1's tailnet IP on port 3389.
3. User connects from PC2 with a standard RDP client to `<VDS_public_ip>:<custom_port>`.
4. User sends `/rdp_off` (or an inactivity timer fires automatically):
   - Bot kills the forwarder process on the VDS → public port closes entirely.
   - Bot disables RDP and the firewall rule on PC1 via SSH/WinRM.

This gives **two independent layers of shutoff**: no open port on the VDS, and RDP itself disabled on PC1.

## Key Security Measures

- **Non-default port**: never expose 3389 directly; use a random high port for the forwarder.
- **IP whitelist**: if PC2 has a static/predictable IP, restrict the forwarded port to it via `iptables`/`ufw`.
- **Telegram auth**: bot only accepts commands from a whitelisted Telegram user ID.
- **Auto-timeout**: bot automatically tears down the forwarder and disables RDP after N minutes of inactivity or session end.
- **NLA (Network Level Authentication)** enabled on PC1.
- Avoid the default `Administrator` account name for RDP login.

## Bot Commands (suggested)

| Command | Action |
|---|---|
| `/rdp_on` | Enable RDP on PC1 + start VDS forwarder |
| `/rdp_off` | Stop VDS forwarder + disable/lock RDP on PC1 |
| `/status` | Report whether RDP access is currently open |

## Tooling Options

- **VPN mesh**: Tailscale (managed) or Headscale (self-hosted control server) — only needed on VDS + PC1.
- **Forwarder**: `socat` (simplest), `iptables` DNAT, or `nginx stream` module (more control/logging).
- **Bot framework**: `aiogram` or `python-telegram-bot`.
- **Remote command execution on PC1**: OpenSSH Server (built into Windows 10/11) or WinRM.

## Notes / Out of Scope in This Version

- Wake-on-LAN is **not** included — PC1 must already be powered on.
- PC2 requires **no VPN client**, only a standard RDP client pointed at the VDS.