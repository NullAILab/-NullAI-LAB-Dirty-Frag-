# PoC Notes — For Security Researchers

**NullAI Lab**

---

> This file contains **conceptual notes** for understanding the exploit mechanism.
> It does **not** contain exploit code. The original PoC is maintained by the
> original researcher at https://github.com/V4bel/dirtyfrag.

---

## Key Technical Observations

### 1. Determinism vs. Traditional LPEs

Most kernel LPEs fall into one of two categories:

| Class | Example | Challenge |
|-------|---------|-----------|
| Race condition | Dirty CoW (CVE-2016-5195) | Timing window, unreliable |
| Memory corruption | heap overflow | KASLR, SMEP, SMAP bypass needed |

Dirty Frag is neither. It is a **logic bug** — the kernel's own decryption path
is the write primitive. No memory corruption, no timing window.

The implication: **traditional mitigations (KASLR, SMEP, SMAP) are irrelevant.**

---

### 2. The "blind spot coverage" principle

Chains of two primitives covering each other's blind spots is an underexplored
technique in public LPE research. Prior art focused on single-primitive exploitation.

The design insight: if primitive A works on 70% of systems and primitive B works
on a different 70%, a 2-primitive chain can achieve near-universal coverage without
requiring a more powerful (and harder-to-find) single primitive.

This suggests that future vulnerability research in this class will focus on
**identifying orthogonal primitive pairs** rather than finding single powerful primitives.

---

### 3. The fcrypt brute-force as a design pattern

The RxRPC path requires solving: "find key K such that decrypt(C, K) = desired plaintext P".

For pcbc with a single 8-byte block, PCBC(C, K, IV=0) = fcrypt_block(C, K) XOR IV = fcrypt_block(C, K).

So the search is: fcrypt_block(C, K) = P, where C is the 8 bytes in the target file at the splice offset.

This is a pure userspace computation — no oracle needed. The key space for an 8-byte
DES key is 2^56 (ignoring parity), but in practice the search space can be reduced
by fixing some bytes and varying others, since you control what bytes you want to write.

The key insight: **when you control the plaintext target, you search for K, not C**.
This inverts the usual cryptographic problem.

---

### 4. Page cache persistence

The page cache contamination is **not persistent across reboots**. The exploit
writes to the in-memory page cache, not to the disk blocks of the file.

However, the contamination **survives process exit and persists until**:
- `echo 3 > /proc/sys/vm/drop_caches` is run
- The system is rebooted
- The OS reclaims the page under memory pressure

This means the attack window during exploitation can be extended, but persistence
requires additional techniques (write to disk, cron, authorized_keys, etc.)

---

### 5. Why /usr/bin/su and not /bin/bash?

The target binary must be:
1. A **SUID binary** (so `setuid(0)` in the payload has effect when executed)
2. **Executable by the unprivileged attacker**
3. Located in the page cache (or easily brought there via a read)

`/usr/bin/su` meets all three criteria on all major distributions. `/bin/bash`
is typically not SUID. Other candidates: `/usr/bin/passwd`, `/usr/bin/pkexec`.

---

## Testing in Isolated Environments

If you want to study this vulnerability class safely:

1. Use a **VM snapshot** — take a snapshot before any testing
2. Use a **kernel config with** `CONFIG_EXPERT=y` and debugging symbols
3. Enable `CONFIG_KASAN` or `CONFIG_KMSAN` to catch additional memory issues
4. Test on a **non-production system** that is network-isolated
5. After testing, **revert to snapshot** (never rely on drop_caches in a test env)

---

## Suggested Reading

- LWN: "The page cache and its friends" — https://lwn.net/Articles/712467/
- Kernel source: `include/linux/xfrm.h` — XFRM state structures  
- Kernel source: `net/rxrpc/rxkad.c` — rxkad verification path
- "A deep dive into Linux namespaces" — https://man7.org/linux/man-pages/man7/namespaces.7.html
- Dirty Pipe write-up: https://dirtypipe.cm4all.com/
