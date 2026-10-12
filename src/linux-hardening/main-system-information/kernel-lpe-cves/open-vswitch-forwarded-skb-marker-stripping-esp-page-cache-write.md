# Open vSwitch forwarded-skb marker stripping to ESP page-cache writes

{{#include ../../../banners/hacktricks-training.md}}

A useful Linux kernel exploitation pattern is to **launder ownership metadata from an skb without removing its foreign fragments**, then route that skb to a consumer that writes in place. In the Open vSwitch (OVS) case, a failed userspace upcall clears `SKBFL_SHARED_FRAG` from a still-live `MSG_ZEROCOPY` skb; ESP subsequently decrypts directly over a read-only file's page-cache folio. This provides a deterministic local page-cache write and has been tracked through CVE-2026-90049, CVE-2026-89487, and CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

This is a Copy Fail/Dirty Frag-class issue rather than classic memory corruption: no race or address disclosure is required, the file need only be readable, and the changed bytes exist in the page cache rather than on disk.<sup>[[2]](#references)[[3]](#references)</sup>

## Security invariant: foreign fragments must remain marked

`SKBFL_SHARED_FRAG` tells in-place consumers that an skb fragment may refer to storage they do not privately own. The ESP fast path in `esp_input()` may decrypt a nonlinear, uncloned skb in place only when `skb_has_shared_frag()` is false; otherwise `skb_cow_data()` first creates private storage. This consumer-side check was added after Dirty Frag.<sup>[[5]](#references)</sup>

The invariant therefore has two independent parts:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. In-place writers must test `SKBFL_SHARED_FRAG` and copy shared data before mutation.
2. Every clone, coalesce, transfer, or forwarding path must preserve the marker for as long as the foreign page remains attached.

Fragnesia violated the second rule while moving fragment descriptors in `skb_try_coalesce()`. The OVS path is subtly different: it does not transfer the fragment at all; it clears the marker **in place on the original skb and then continues forwarding it**.<sup>[[2]](#references)[[4]](#references)</sup>

## Unprivileged OVS reachability

OVS's kernel datapath is controlled through generic-netlink families such as `ovs_datapath`, `ovs_vport`, `ovs_flow`, and `ovs_packet`. Its mutating operations use namespace-aware `GENL_UNS_ADMIN_PERM`, so a process running under `unshare -Urn` obtains the `CAP_NET_ADMIN` needed to create a datapath, attach a veth, and install flow actions inside its own network namespace. Resolving the OVS family may also autoload `openvswitch.ko`; host `CAP_SYS_MODULE`, `ovs-vsctl`, and `ovs-vswitchd` are not required for this attack surface.<sup>[[2]](#references)[[7]](#references)</sup>

The important distinction is between two upcall types:<sup>[[2]](#references)[[7]](#references)</sup>

- A **flow miss** sends the packet to `ovs-vswitchd`; if the upcall fails, the packet is normally dropped.
- An explicit `OVS_ACTION_ATTR_USERSPACE` action sends a borrowed copy to a selected port ID, then executes later actions on the original skb.

An attacker can therefore install a flow shaped like:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

No listener owns the selected port ID, making the userspace action fail predictably, while the following `OUTPUT` action keeps the original packet alive.<sup>[[1]](#references)[[2]](#references)</sup>

## Root cause: `skb_tx_error()` on a packet that survives

The vulnerable OVS upcall error path calls `skb_tx_error(skb)`. That helper was designed for a failed transmit where the skb is freed afterward; it completes zerocopy bookkeeping through `skb_zcopy_clear()`, whose flag mask historically also removed `SKBFL_SHARED_FRAG`. OVS ignored the userspace-action error and continued its action list, violating the helper's lifetime contract.<sup>[[1]](#references)[[2]](#references)</sup>

The exploitable state transition is:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

This only works when `skb_zcopy()` finds zerocopy state. A fragment carrying only `SKBFL_SHARED_FRAG` is insufficient; `MSG_ZEROCOPY` is useful because it creates `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` and also sets `SKBFL_DONT_ORPHAN`. The latter makes `skb_orphan_frags()` skip replacement of the foreign pages during the OVS userspace copy.<sup>[[2]](#references)[[3]](#references)</sup>

## Building the write primitive

The end-to-end trigger has the following components.<sup>[[2]](#references)[[3]](#references)</sup>

1. Enter private user and network namespaces with `unshare -Urn`.
2. Map a readable target file with `PROT_READ | MAP_SHARED`.
3. Use a separate sender netns and a veth pair; local loopback would copy the borrowed pages and destroy the primitive.
4. Build an OVS datapath and the failing `USERSPACE`-then-`OUTPUT` flow.
5. Install a transport-mode ESP-in-UDP XFRM state using `rfc4106(gcm(aes))` and UDP port 4500.
6. Send one `MSG_ZEROCOPY` datagram with an iovec shaped as `[ESP header | mapped file bytes | invalid ICV]`.

The XFRM state uses 20 bytes of AES-128-GCM keying material: 16 bytes of AES key followed by the four-byte RFC 4106 salt. For a chosen eight-byte explicit IV, payload confidentiality starts with the counter block `salt || IV || be32(2)`; counter value 1 masks the authentication result instead.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Once OVS strips the marker, ESP takes its no-copy path and performs `plaintext = ciphertext XOR keystream` over the file-backed fragment. Authentication is checked **after** this transform, so an all-zero invalid ICV makes the packet fail with `-EBADMSG` only after the page-cache bytes have already changed.<sup>[[2]](#references)</sup>

### Converting GCM into chosen bytes

For current byte `C` and desired byte `P`, the first payload keystream byte must be `C XOR P`. With the AES key and salt fixed, sweep a 16-bit suffix of the explicit IV and precompute one suffix for each possible first keystream byte:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

The public implementation limits ciphertext to 32 bytes and advances the file fragment by one byte for each packet. The chosen first byte overwrites the previous packet's first collateral byte; `pread()` refreshes `C` before every packet, equal bytes are skipped, and the final packet is shortened so writes do not pass the requested range. Thus a 256-entry lookup table turns the primitive into a byte-granular chosen-content page-cache write at roughly one packet per differing byte.<sup>[[2]](#references)[[3]](#references)</sup>

## Page-cache write to root

A practical target is an existing setuid-root executable. The PoC replaces the first 160 bytes with a complete static ELF containing one fixed-address read/execute `PT_LOAD`, no `PT_INTERP`, and code that calls `setuid(0)` before `execve("/bin/sh", ...)`. This avoids assumptions about the original binary's entry point, PIE layout, dynamic loader, or relocations.<sup>[[2]](#references)[[3]](#references)</sup>

The modification is visible across user namespaces because the page cache is not namespaced. The altered folio is not marked dirty, so it is not written back; execute the target while resident, then discard the temporary corruption with `posix_fadvise(..., POSIX_FADV_DONTNEED)` so later reads reload the original disk contents.<sup>[[2]](#references)[[3]](#references)</sup>

## Exposure checks and mitigation

Check the actual vendor kernel first. Relevant exposure gates are unprivileged user namespaces, OVS availability or residency, and an available ESP implementation.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Upgrade to a kernel carrying the complete fix series; the final repair covers the recirculation path and avoids mutating shared `skb_shinfo()` state, while also closing a related strip in `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

If OVS is unused, prevent both alias and by-name loading with a modprobe `install` rule rather than relying only on `blacklist`. If the host does not terminate IPsec and ESP is modular, the same control can remove the decrypt sink.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

These rules do not help when a module is already loaded or the feature is built into the kernel. Disabling unprivileged user namespaces also removes the namespace capability source but can break browsers, Flatpak, Podman, and other sandboxing/container workloads.<sup>[[2]](#references)</sup>

## Review lessons

When auditing zero-copy networking, do not limit the search to helpers that copy or move fragments. Also identify error/completion helpers that clear grouped flags, then verify that every caller obeys the documented skb lifetime contract. A page-ownership bit grouped with zerocopy lifecycle bits is security-sensitive even when the clearing code never directly accesses a fragment.<sup>[[1]](#references)[[2]](#references)</sup>

A robust fix must cover all routes by which the skb can survive—including action continuation and recirculation—and must account for clones sharing `skb_shinfo()`. On the consumer side, authentication failure does not undo plaintext writes already performed by an in-place AEAD transform, so foreign-storage checks must happen before decryption begins.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec netdev fix series: net: don't strip zerocopy frag markers from a forwarded skb](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Open vSwitch Forwarded-SKB Marker Stripping Enables Deterministic ESP Page-Cache LPE](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec `ovs-pagecache-write` proof of concept](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Linux fix for the original Fragnesia coalescing path (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux ESP consumer-side shared-fragment check (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: The Use of Galois/Counter Mode (GCM) in IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Open vSwitch kernel datapath documentation](https://docs.openvswitch.org/en/latest/topics/datapath/)

{{#include ../../../banners/hacktricks-training.md}}
