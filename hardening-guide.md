# Hardening Guide: Defending Against Dirty Frag

**Author:** NullAI Lab  

---

## Immediate Response (All Distributions)

### 1. Block Vulnerable Modules (Recommended — Apply Now)

```bash
sudo sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf; \
  rmmod esp4 esp6 rxrpc 2>/dev/null; \
  echo 3 > /proc/sys/vm/drop_caches; \
  true"
```

**What this does:**
- Blocks `esp4`, `esp6`, and `rxrpc` from being loaded via modprobe blacklist
- Unloads currently running instances (non-fatal if not loaded)
- Flushes page cache to remove any existing contamination

**Impact assessment:**
| Module | Purpose | Impact of Disabling |
|--------|---------|-------------------|
| `esp4` | IPv4 IPsec ESP | Breaks site-to-site IPsec VPNs using ESP over IPv4 |
| `esp6` | IPv6 IPsec ESP | Breaks site-to-site IPsec VPNs using ESP over IPv6 |
| `rxrpc` | RxRPC/AFS protocol | Breaks OpenAFS client functionality |

If your environment uses IPsec VPNs, coordinate a maintenance window.
If you do not use AFS, disabling `rxrpc` has no operational impact.

---

## Distribution-Specific Mitigations

### Ubuntu / Debian

Ubuntu's AppArmor can already block the xfrm-ESP path, but the RxRPC path
remains viable since `rxrpc.ko` is loaded by default.

**Restrict unprivileged user namespaces (blocks xfrm-ESP path additionally):**
```bash
echo 'kernel.unprivileged_userns_clone=0' | sudo tee /etc/sysctl.d/99-ns-restrict.conf
sudo sysctl --system
```

> ⚠️ This may break some sandboxed applications (Chromium, Flatpak, bubblewrap).
> Test in a staging environment first.

**Ubuntu AppArmor profile for namespace restriction** (if not already applied):
```bash
sudo aa-status | grep userns
```

### RHEL / CentOS / AlmaLinux / Fedora

These distributions do not ship `rxrpc.ko` by default, so the RxRPC path is
not viable. Focus on the xfrm-ESP path:

```bash
# Check if user namespaces are enabled
sysctl user.max_user_namespaces

# Disable unprivileged user namespaces (SELinux may already block this)
echo 'user.max_user_namespaces=0' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl --system
```

**SELinux:** If SELinux is in enforcing mode, verify that unprivileged namespace
creation is denied:
```bash
ausearch -m avc -ts recent | grep "unshare"
```

### openSUSE / SUSE

Similar to RHEL — focus on namespace restriction:
```bash
sudo sysctl -w user.max_user_namespaces=0
echo 'user.max_user_namespaces=0' >> /etc/sysctl.d/99-dirtyfrag.conf
```

---

## Patch Status Tracking

Monitor these sources for official distribution patches:

| Distribution | Security Advisory Tracker |
|---|---|
| Ubuntu | https://ubuntu.com/security/cves |
| RHEL / CentOS | https://access.redhat.com/security/vulnerabilities |
| Debian | https://www.debian.org/security/ |
| Fedora | https://bodhi.fedoraproject.org/ |
| openSUSE | https://www.suse.com/security/cve/ |

**CVE-2026-43284** — Patched in mainline. Watch for distro backports.  
**CVE-2026-43500** — No patch. Apply module blacklist mitigation above.

---

## Detection Rules

### auditd Rules

Add to `/etc/audit/rules.d/dirtyfrag.rules`:

```
# Detect splice() + vmsplice() on SUID binary file descriptors
-a always,exit -F arch=b64 -S splice -S vmsplice -k dirtyfrag_splice

# Detect XFRM netlink SA creation by non-root
-a always,exit -F arch=b64 -S socket -F a0=16 -F uid!=0 -k xfrm_socket

# Detect AF_RXRPC socket creation
-a always,exit -F arch=b64 -S socket -F a0=33 -k rxrpc_socket

# Detect page cache flush (post-exploitation cleanup indicator)
-w /proc/sys/vm/drop_caches -p w -k drop_caches_write

# Detect modprobe blacklist modification
-w /etc/modprobe.d/ -p wa -k modprobe_config
```

Reload rules:
```bash
sudo augenrules --load
sudo service auditd restart
```

### File Integrity Monitoring

Add SUID binaries to your FIM solution. Manual check:

```bash
# Verify /usr/bin/su integrity against known-good hash
sha256sum /usr/bin/su

# Compare against package database (RPM systems)
rpm -V util-linux 2>/dev/null | grep su

# Compare against package database (Debian systems)
dpkg --verify util-linux 2>/dev/null | grep su
```

### YARA Rule (Memory/Disk Scan)

```yara
rule DirtyFrag_SPI_Pattern {
    meta:
        description = "Detects Dirty Frag exploit SPI pattern in memory or disk"
        author = "NullAI Lab"
        reference = "CVE-2026-43284"
    strings:
        $spi_base = { 10 BE AD DE }  // SPI base 0xDEADBE10 in network byte order
    condition:
        $spi_base
}
```

---

## Longer-Term Hardening

### Kernel Lockdown Mode

If your use case permits, enable kernel lockdown:
```bash
# In GRUB (if UEFI Secure Boot is active, lockdown may already be "integrity" mode)
GRUB_CMDLINE_LINUX="lockdown=confidentiality"
```

Lockdown `confidentiality` mode restricts many of the primitives used by
kernel exploitation techniques.

### Syscall Filtering (seccomp)

For containerized workloads, restrict `splice` and `vmsplice` via seccomp profiles
if not needed by your applications.

### Restrict `/proc/sys/kernel/perf_event_paranoid`

While not directly related to Dirty Frag, tightening kernel information leaks
reduces the attacker's ability to find kernel addresses if they need them for
follow-on exploitation:

```bash
echo 'kernel.perf_event_paranoid=3' >> /etc/sysctl.d/99-harden.conf
echo 'kernel.kptr_restrict=2' >> /etc/sysctl.d/99-harden.conf
sudo sysctl --system
```

---

## Summary Checklist

- [ ] Apply module blacklist (`esp4`, `esp6`, `rxrpc`)
- [ ] Flush page cache (`echo 3 > /proc/sys/vm/drop_caches`)
- [ ] Restrict unprivileged user namespaces (if operationally feasible)
- [ ] Verify SUID binary integrity (`sha256sum /usr/bin/su`)
- [ ] Add auditd rules for splice/vmsplice/rxrpc detection
- [ ] Monitor distribution security advisories for backported patches
- [ ] Apply official patch when available (CVE-2026-43284 — already in mainline)
