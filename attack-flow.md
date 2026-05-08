# Attack Flow: Dirty Frag Step-by-Step

**Author:** NullAI Lab  
**Original Discovery:** Hyunwoo Kim (@v4bel)  

---

## Prerequisites

Before exploitation, the attacker must determine which of the two paths is viable:

```
┌─────────────────────────────────────────────────────┐
│             PATH SELECTION LOGIC                    │
│                                                     │
│  Is CLONE_NEWUSER allowed?  ──Yes──►  xfrm-ESP path │
│         │                                           │
│         No (AppArmor blocks it)                     │
│         │                                           │
│         ▼                                           │
│  Is rxrpc.ko loaded?  ──Yes──►  RxRPC path          │
│         │                                           │
│         No ──► System may not be vulnerable         │
└─────────────────────────────────────────────────────┘
```

**Check for AppArmor namespace restriction:**
```bash
cat /proc/sys/kernel/unprivileged_userns_clone  # 0 = blocked
```

**Check for rxrpc module:**
```bash
lsmod | grep rxrpc
```

---

## Path A: xfrm-ESP Page-Cache Write

### Step 1 — Namespace Setup

The exploit creates a new **user namespace** and **network namespace** using
`unshare(CLONE_NEWUSER | CLONE_NEWNET)`. Within this namespace, the process
gains `CAP_NET_ADMIN` (scoped to the namespace), which is required to create
XFRM Security Associations.

The loopback interface is brought up inside the new network namespace to enable
local packet routing.

```
[unprivileged process]
   │
   └─► unshare(NEWUSER | NEWNET)
         └─► gains CAP_NET_ADMIN in netns
              └─► lo interface UP
```

### Step 2 — XFRM SA Installation

For each 4-byte chunk of the payload ELF (48 chunks for a 192-byte header),
the exploit creates one XFRM Security Association via `XFRM_MSG_NEWSA` netlink:

- **SPI:** `0xDEADBE10 + i` (unique per chunk)
- **Algorithm:** ESP with AES-CBC encryption + HMAC-SHA256 authentication
- **Encapsulation:** UDP-encapsulated ESP (ESP-in-UDP, port 4500)
- **Critical field:** `xfrm_replay_state_esn.seq_hi` = the 4 bytes to write

The `seq_hi` field is the **controlled payload** — when the packet is decrypted,
these 4 bytes are written into the page-cache page at the target offset.

### Step 3 — Page Cache Reference Setup

For each write operation:

1. `open("/usr/bin/su", O_RDONLY)` — get a read-only file descriptor
2. `pipe(pfd)` — create a pipe
3. `vmsplice(pfd[1], header_iov, 1, 0)` — write ESP packet header bytes into pipe
4. `splice(file_fd, &offset, pfd[1], NULL, 16, SPLICE_F_MOVE)` — splice 16 bytes
   of the target file into the pipe

After `splice()`, the pipe buffer holds a **reference to the page-cache page** of
`/usr/bin/su` at the target offset. This page is still marked read-only.

### Step 4 — Trigger In-Place Decryption

1. Create a UDP socket bound to port 4500 with `UDP_ENCAP_ESPINUDP` option set
2. Send the pipe contents through a connected UDP socket (the "ESP packet")
3. The kernel receives the packet, matches it to the XFRM SA by SPI, and decrypts
   the payload **in-place** — writing `seq_hi` bytes into the page-cache page
4. `usleep(150ms)` — allow kernel processing to complete

### Step 5 — Verify and Repeat

After each write, the exploit reads back the target bytes from the file to confirm
the write landed correctly. This is possible because the page cache is shared:
the modified bytes are immediately visible via any subsequent `read()` of the file.

Steps 2–5 repeat 48 times to write the full 192-byte ELF header.

---

## Path B: RxRPC Page-Cache Write

### Step 1 — Key Installation

The exploit installs a custom `rxkad` v1 Kerberos token via `add_key("rxrpc", ...)`.
The token embeds an **attacker-controlled 8-byte DES session key** that will be used
by the kernel during packet authentication.

### Step 2 — Userspace Key Search

Before touching the kernel, the exploit performs a **pure userspace brute-force**:
it iterates over possible session keys, simulating the kernel's `pcbc(fcrypt)` decryption
using a userspace reimplementation of the `fcrypt` cipher, to find a key `K` such that:

```
pcbc_fcrypt_decrypt(target_ciphertext, K) = desired_plaintext_bytes
```

This search happens entirely in userspace — no kernel involvement — and once found,
the correct key is installed into the keyring token.

### Step 3 — Fake Server Setup

The exploit creates:
- A plain **UDP socket** acting as a fake "AFS server" on a chosen port
- An **AF_RXRPC client socket** configured with the installed key

The client socket initiates a call to the fake server (which receives the raw UDP packets
before the rxrpc layer processes them).

### Step 4 — Challenge/Response Handshake

The fake server receives the client's initial `DATA` packet (the kernel sends this
as part of the rxrpc handshake). The server sends back a crafted `CHALLENGE` packet
to trigger the client-side authentication flow.

### Step 5 — Malicious DATA Packet Injection

The exploit computes a valid `cksum` for a crafted `DATA` packet using the attacker-known
session key, then uses `splice()` + `vmsplice()` to construct a pipe containing:

```
[ rxrpc wire header (24 bytes) ] [ page-cache page slice of /usr/bin/su ]
```

This pipe is sent via the fake server's connected UDP socket directly to the rxrpc
client's port. When the rxrpc layer processes the incoming DATA packet:

1. It matches the epoch/cid/callNumber to the active call
2. It verifies the `cksum` (valid, because the attacker controls the key)
3. It calls `rxkad_verify_packet_1()`, which **decrypts in-place** using `pcbc(fcrypt)`
4. The decrypted bytes (attacker-controlled plaintext) land in the page-cache page

### Step 6 — Execute

Once all target bytes are written (identical final steps to Path A):

```bash
/usr/bin/su  # now executes attacker-controlled ELF → setuid(0) + execve(/bin/sh)
```

---

## Post-Exploitation Cleanup

The page cache remains contaminated after exploitation. To restore the original binary
and ensure system stability:

```bash
echo 3 > /proc/sys/vm/drop_caches
```

Or simply reboot. The contamination is **not persistent** (it lives only in RAM).

> ⚠️ Note: Once the page cache is flushed, the SUID binary is restored from disk.
> The exploit must be re-run to re-achieve root if needed. For persistence, additional
> techniques (cron jobs, authorized_keys, etc.) would need to be applied while root.

---

## See Also

- [`bug-class.md`](bug-class.md) — Theoretical background
- [`../mitigations/hardening-guide.md`](../mitigations/hardening-guide.md) — How to defend
