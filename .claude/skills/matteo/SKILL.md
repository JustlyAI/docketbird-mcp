---
name: matteo
description: Access and operate the Pro 2 machine (code name "Matteo", hostname macbook-pro-2) over Tailscale, including running Claude Code there. Use when running a command on Pro 2, SSHing into it, copying files to/from it, or offloading Open Tennis work to Matteo. Key signals: "Pro 2", "the M2", "Matteo", "macbook-pro-2", "on the other Mac", "run this on Matteo".
---

# Matteo — Accessing the Pro 2

**Matteo** is the code name for the **Pro 2**, a second Mac (`macbook-pro-2`) on the AIF
tailnet. It has its own Claude Code install and can be used to offload work for this
project (Open Tennis).

## Host facts

| Field | Value |
|-------|-------|
| Code name | Matteo (also "the M2") |
| Hostname (MagicDNS) | `macbook-pro-2` |
| SSH user | `ofcounsel` |
| Auth | Tailscale SSH (tailnet ACL grant), not `authorized_keys` |

## The one access rule

```bash
ssh ofcounsel@macbook-pro-2 '<command>'
```

No `-i`, no key flags, no password. `known_hosts` already trusts the host.

## Pitfalls (do not repeat these)

- **Do NOT use `laurentwiesel@`** or any user other than `ofcounsel` — hits macOS `sshd`
  and fails with `Permission denied (publickey)`.
- **Do NOT pass `-i <key> -o IdentitiesOnly=yes`** — bypasses Tailscale SSH, same failure.
- **Taildrop (`tailscale file cp`) fails** — Pro 2 is owned by a different Tailscale user.
  Use `scp` instead.

## Claude Code on Matteo

Confirmed installed and reachable:

```bash
ssh ofcounsel@macbook-pro-2 'claude --version'
```

To run a one-shot Claude Code task on Matteo:

```bash
ssh ofcounsel@macbook-pro-2 'cd /path/to/repo && claude --print "<prompt>"'
```

## Copying files to Pro 2

```bash
scp <local-file> ofcounsel@macbook-pro-2:/tmp/<file>
```

## Project context

This is for the Open Tennis project (Trump Tennis 2026 contact management sprint). Use
Matteo to parallelize or offload discrete pieces of work when it makes sense — e.g.
running a long build/test/verify step on a second machine while the primary session
keeps working.
