# Safe Connect

A Telegram bot that opens on-demand, IP-restricted, auto-expiring RDP
access to a Windows PC (PC1) behind NAT, from a small Ubuntu VDS bridged to
it over Tailscale. No public port and no open RDP exist except during a
session you deliberately start; the VDS is treated as untrusted throughout.

```
PC2 ──RDP──► VDS:<random high port> ──Tailscale──► PC1:3389
                     ▲
               socat (per-session)
                     ▲
               bot (systemd, user `safeconnect`)
                     │
                     └──SSH forced command──► agent.ps1 on PC1
```

Setup: `docs/RUNBOOK.md`. Threat model and accepted risks:
`docs/SECURITY.md`.

| Command | Behaviour |
|---|---|
| `/rdp_on <ip>` | Open a session for that source IP. `/rdp_on any` opens to all sources. |
| `/rdp_off` | Tear down immediately. |
| `/status` | Current state, active port, source IP, time remaining on both timers. |
| `/help` | Command list. |
