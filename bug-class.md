# Bug Class Analysis: Page-Cache Write Primitives

**Author:** NullAI Lab  
**Original Discovery:** Hyunwoo Kim (@v4bel)  

---

## The Core Concept: Page Cache Contamination

The Linux kernel uses a **page cache** to avoid redundant disk I/O. When a file is read,
its contents are loaded into memory pages that are shared between all processes reading
that file. These pages are normally marked **read-only** to prevent accidental modification.

The vulnerability class exploited by Dirty Frag (and its predecessors) arises when the
kernel provides a code path that:

1. Obtains a **writable reference** to a page-cache page
2. Fails to properly verify that the underlying page belongs to a **writable mapping**
3. Allows an attacker to **inject controlled bytes** into that page

Because the page cache is shared, writing to it affects **every future read** of that
file — including SUID binary executions.

---

## Evolution of the Bug Class

### Dirty Pipe (CVE-2022-0847)

**Mechanism:** `splice()` + `pipe` write  
**Root cause:** A flag (`PIPE_BUF_FLAG_CAN_MERGE`) was incorrectly propagated to
splice-backed pipe buffers, allowing `write()` on a pipe to merge data into an
existing read-only page-cache page.

**Key insight:** The pipe buffer's `page` pointer pointed directly into the page cache.
By writing into the pipe after splicing, you overwrote cache contents.

**Limitation:** Required precise timing; affected kernels 5.8–5.16.11.

---

### Copy Fail (CVE-2024-XXXX)

**Mechanism:** `AF_ALG` (algif_aead) in-place decryption  
**Root cause:** The AEAD cipher interface decrypted ciphertext **in-place** into
a destination buffer that was backed by a page-cache page obtained via splice.

**Key insight:** Cryptographic operations assumed their output buffer was writable,
but the kernel did not enforce this assumption at the page level.

**Limitation:** Required `algif_aead` module availability. Mitigated on some systems
by blacklisting `algif_aead`.

---

### Dirty Frag (CVE-2026-43284 + CVE-2026-43500)

**Mechanism:** Two independent cryptographic in-place write paths  
**Key improvement:** Two separate primitives that cover each other's blind spots,
making the exploit **universal** across all major distributions.

---

## The `struct sk_buff` Angle

The name "Dirty Frag" refers to the `frag` member of `struct sk_buff` — the kernel's
socket buffer structure. Network packets are stored as chains of fragments (`skb_frag_t`),
each pointing to a page and an offset within it.

When the kernel processes an incoming encrypted packet (ESP or RxRPC), it:

1. Receives the ciphertext in an `skb` fragment
2. Decrypts it **in-place**, writing the plaintext back to the same pages
3. **Bug:** Those pages may have been spliced from a read-only file fd,
   meaning they are shared page-cache pages for a sensitive binary

The "dirtying" of the `frag` member is what gives the bug class its name.

---

## Primitive Comparison

| Feature | Dirty Pipe | Copy Fail | Dirty Frag (xfrm) | Dirty Frag (rxrpc) |
|---------|-----------|-----------|-------------------|--------------------|
| Kernel versions | 5.8–5.16.11 | 5.x–6.x | 4.10–6.x | 6.3–present |
| Race condition required | No | No | No | No |
| Namespace privilege needed | No | No | Yes (NEWUSER) | No |
| Module dependency | None | algif_aead | esp4/esp6 | rxrpc.ko |
| Write granularity | Per-byte | Block-aligned | 4 bytes | Block-aligned |
| Universal coverage | Partial | Partial | Partial | Partial |
| Combined coverage | — | — | **Universal** | **Universal** |

---

## Why "Deterministic"?

Previous exploitation of memory corruption bugs often required timing windows
(race conditions) or heap spraying with probabilistic success. Dirty Frag achieves
determinism because:

1. **No race:** The write happens synchronously in the packet processing path
2. **No KASLR dependency:** The primitive writes to user-controlled offsets in
   the page cache, not to kernel memory directly
3. **No kernel panic on failure:** If a write lands incorrectly, the worst case
   is a corrupted binary — the kernel itself remains stable
4. **Verifiable:** The exploit can read back the target file after each write
   to confirm success before proceeding

This makes Dirty Frag more similar to a **logic bug** than a traditional memory
corruption exploit.

---

## See Also

- [`attack-flow.md`](attack-flow.md) — Step-by-step exploitation flow
- [`../mitigations/hardening-guide.md`](../mitigations/hardening-guide.md) — Defensive measures
