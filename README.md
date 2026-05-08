# 🔬 Dirty Frag — Deep Technical Analysis

<p align="center">
  <img src="assets/banner.svg" alt="NullAI Lab" width="800"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/CVE-2026--43284-critical?style=for-the-badge&color=FF2D20"/>
  <img src="https://img.shields.io/badge/CVE-2026--43500-reserved-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Kernel-Linux%20LPE-informational?style=for-the-badge&color=0D1117"/>
  <img src="https://img.shields.io/badge/Analysis%20by-NullAI%20Lab-blueviolet?style=for-the-badge"/>
</p>

---

> **⚠️ Responsible Disclosure Notice**  
> This repository contains **educational analysis only**. The original vulnerability was discovered and responsibly disclosed by **Hyunwoo Kim ([@v4bel](https://x.com/v4bel))**. All technical credit belongs to the original researcher. This work is a deep-dive analysis produced by **NullAI Lab** for educational and defensive purposes.

---

## 📌 Table of Contents

- [Overview](#overview)
- [Bug Class Lineage](#bug-class-lineage)
- [Vulnerability Chain](#vulnerability-chain)
  - [CVE-2026-43284 — xfrm-ESP Page-Cache Write](#cve-2026-43284--xfrm-esp-page-cache-write)
  - [CVE-2026-43500 — RxRPC Page-Cache Write](#cve-2026-43500--rxrpc-page-cache-write)
- [Why Chaining?](#why-chaining)
- [Attack Flow](#attack-flow)
- [Affected Versions](#affected-versions)
- [Mitigation & Hardening](#mitigation--hardening)
- [Detection Guidance](#detection-guidance)
- [Timeline](#timeline)
- [References](#references)

---

## Overview

**Dirty Frag** is a **universal Linux Local Privilege Escalation (LPE)** vulnerability class
that achieves root access on all major Linux distributions by chaining two independent
**Page-Cache Write** primitives:

| Component | Bug | CVE | Status |
|-----------|-----|-----|--------|
| `net/xfrm` (ESP over UDP) | Arbitrary 4-byte write to page cache via `seq_hi` | CVE-2026-43284 | **Patched** in mainline ([f4c50a4034e6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4)) |
| `net/rxrpc` + `rxkad` | Arbitrary write via authenticated RxRPC data packets | CVE-2026-43500 | **Unpatched** — no fix in any tree |

The exploit is **deterministic** (no race condition), does **not** panic the kernel on failure,
and achieves a **very high success rate** across tested distributions.

---

## Bug Class Lineage

Dirty Frag belongs to a well-defined kernel bug family centered around **page cache contamination**:

```
Dirty Pipe (2022)              Copy Fail (2024)             Dirty Frag (2026)
     │                               │                              │
     └──── splice() + pipe ──────────┴──── page-cache STORE ───────┘
           page-cache write                    primitive
           via O_RDONLY fd
```

All three share the same **sink**: a writable reference to a read-only page cache page.
What Dirty Frag adds is **two independent sources** for that primitive, which together
cover each other's blind spots across all mainstream distributions.

For a detailed breakdown of the bug class, see [`analysis/bug-class.md`](analysis/bug-class.md).

---

## Vulnerability Chain

### CVE-2026-43284 — xfrm-ESP Page-Cache Write

**Location:** `net/xfrm/xfrm_input.c` and ESP decryption path  
**Introduced:** commit `cac2661c53f3` (2017-01-17)  
**Patched:** commit `f4c50a4034e6` (mainline, 2026-05-08)

#### Root Cause

When an **ESP-in-UDP** packet is received, the kernel decrypts the payload **in-place** using
the page-cache page that was spliced into the pipe. The `seq_hi` field of an ESN (Extended
Sequence Number) replay state structure is written into the decrypted payload **before**
verifying that the underlying page is not a shared read-only mapping.

The result: an attacker with the ability to create a user namespace (for `CAP_NET_ADMIN`)
can craft XFRM Security Associations with arbitrary `seq_hi` values, and by chaining
`splice()` + `vmsplice()`, land those bytes on any offset of any file in the page cache —
**including SUID binaries**.

#### Primitive Strength

- **Primitive type:** Arbitrary 4-byte STORE to page-cache page
- **Granularity:** 4 bytes per SA, 48 SAs needed for a minimal ELF header
- **Privilege required:** Unprivileged user namespace creation (`CLONE_NEWUSER | CLONE_NEWNET`)

---

### CVE-2026-43500 — RxRPC Page-Cache Write

**Location:** `net/rxrpc/`, `net/rxrpc/rxkad.c`  
**Introduced:** commit `2dc334f1a63a` (2023-06)  
**Patched:** Not patched in any tree as of 2026-05-08

#### Root Cause

The `rxkad` security layer in AF_RXRPC performs **in-place decryption** of incoming data
packets using `pcbc(fcrypt)`. When a malicious "server" sends a crafted DATA packet with
a valid-looking `cksum` (computed from an attacker-controlled session key embedded in an
`rxkad` v1 keyring token), the kernel decrypts the packet payload directly into the
page-cache page that was previously spliced into the socket's receive pipe.

Because `rxrpc.ko` is loaded by default on **Ubuntu** (where the xfrm path may be blocked
by AppArmor unprivileged namespace restrictions), this path provides an alternative source
for the same page-cache write primitive.

#### Primitive Strength

- **Primitive type:** Arbitrary write via chosen-plaintext + key search (brute-force in userspace)
- **Privilege required:** None — no namespace creation needed
- **Dependency:** `rxrpc.ko` module must be present (Ubuntu: default; others: rare)

---

## Why Chaining?

Neither primitive alone is universal:

| Path | Blind Spot |
|------|-----------|
| **xfrm-ESP** | Blocked on Ubuntu when AppArmor denies unprivileged `CLONE_NEWUSER` |
| **RxRPC** | `rxrpc.ko` not shipped on RHEL, Fedora, openSUSE, CentOS by default |

**Together**, they cover every major distribution:

```
Ubuntu (AppArmor blocks CLONE_NEWUSER)  →  Use RxRPC path (rxrpc.ko loaded by default)
RHEL / Fedora / openSUSE / CentOS      →  Use xfrm-ESP path (namespaces allowed)
```

This is the key insight of Dirty Frag: **chaining coverage, not complexity**.

---

## Attack Flow

See [`analysis/attack-flow.md`](analysis/attack-flow.md) for the full step-by-step breakdown.

High-level summary:

```
1. [ SETUP ]    Identify which path is viable (xfrm or rxrpc)
2. [ SPLICE ]   vmsplice() + splice() to get a page-cache reference
                into a pipe pointing at a target SUID binary (e.g. /usr/bin/su)
3. [ WRITE ]    Trigger decryption-in-place to overwrite ELF header bytes
                with a minimal root-shell ELF payload (192 bytes)
4. [ VERIFY ]   Confirm entry-point bytes match shellcode stub
5. [ EXECUTE ]  Call the patched SUID binary → setuid(0) + execve(/bin/sh)
6. [ CLEANUP ]  echo 3 > /proc/sys/vm/drop_caches  (or reboot)
```

---

## Affected Versions

### xfrm-ESP (CVE-2026-43284)

| Distribution | Kernel | Status |
|---|---|---|
| Ubuntu 24.04.4 | 6.17.0-23-generic | Affected |
| RHEL 10.1 | 6.12.0-124.49.1.el10_1.x86_64 | Affected |
| openSUSE Tumbleweed | 7.0.2-1-default | Affected |
| CentOS Stream 10 | 6.12.0-224.el10.x86_64 | Affected |
| AlmaLinux 10 | 6.12.0-124.52.3.el10_1.x86_64 | Affected |
| Fedora 44 | 6.19.14-300.fc44.x86_64 | Affected |

**Scope:** Kernels from `cac2661c53f3` (Jan 2017) → mainline (May 2026) — ~9 years.

### RxRPC (CVE-2026-43500)

**Scope:** Kernels from `2dc334f1a63a` (Jun 2023) → present. **No patch exists.**

---

## Mitigation & Hardening

> ⚠️ Because the embargo was broken, **no distribution patch exists** for CVE-2026-43500.
> Apply the following workaround immediately.

### Immediate Workaround (All Distributions)

```bash
# Block the vulnerable modules and clear contaminated page cache
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf; \
  rmmod esp4 esp6 rxrpc 2>/dev/null; \
  echo 3 > /proc/sys/vm/drop_caches; \
  true"
```

This command:
1. Permanently blacklists `esp4`, `esp6`, and `rxrpc` kernel modules via modprobe config
2. Unloads currently running modules (errors are non-fatal if modules aren't loaded)
3. Flushes the page cache to remove any in-flight contamination

### Additional Hardening

See [`mitigations/hardening-guide.md`](mitigations/hardening-guide.md) for:
- AppArmor / SELinux policy guidance
- Unprivileged namespace restriction (Ubuntu / Debian)
- Kernel lockdown mode considerations
- Monitoring and alerting rules

---

## Detection Guidance

Signs of active exploitation:

| Indicator | Notes |
|-----------|-------|
| Unusual XFRM SA creation by unprivileged process | `ip xfrm state` shows SAs with `spi 0xDEADBExx` patterns |
| `rxrpc` socket creation by non-system process | Rare outside AFS/Kerberos environments |
| `vmsplice` + `splice` calls on SUID binary fds | Audit rule: `-a always,exit -F arch=b64 -S splice -S vmsplice` |
| Page cache inconsistency on `/usr/bin/su` | Compare file hash against known-good: `sha256sum /usr/bin/su` |
| `/proc/sys/vm/drop_caches` writes | May indicate post-exploitation cleanup |

---

## Timeline

| Date | Event |
|------|-------|
| 2017-01-17 | `cac2661c53f3` introduces xfrm-ESP page-cache write primitive |
| 2023-06 | `2dc334f1a63a` introduces RxRPC write primitive |
| 2026 (early) | Hyunwoo Kim (@v4bel) discovers and chains the two primitives |
| 2026 | Reported to `linux-distros@vs.openwall.org`; embargo begins |
| 2026-05-08 | Embargo broken; public disclosure at request of maintainers |
| 2026-05-08 | CVE-2026-43284 assigned; mainline patch `f4c50a4034e6` merged |
| 2026-05-08 | CVE-2026-43500 reserved; **no patch in any tree** |

---

## References

- **Original Research:** Hyunwoo Kim (@v4bel) — https://github.com/V4bel/dirtyfrag
- **Dirty Pipe (2022):** https://dirtypipe.cm4all.com/
- **Copy Fail (2024):** https://copy.fail/
- **CVE-2026-43284 patch:** https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4
- **linux-distros list:** linux-distros@vs.openwall.org

---

## About NullAI Lab

**NullAI Lab** is an independent security research group focused on deep kernel vulnerability
analysis, defensive tooling, and responsible disclosure education.

> *"Understanding how things break is the first step to building things that don't."*

---

<p align="center">
  <sub>Analysis produced by NullAI Lab · Original discovery by Hyunwoo Kim (@v4bel) · For educational purposes only</sub>
</p>