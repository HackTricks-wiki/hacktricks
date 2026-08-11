# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara" abuses MediaTek's XFlash download path to run a modified Download Agent stage 2 (DA2) despite DA1 integrity checks. DA1 stores the expected SHA-256 of DA2 in RAM and compares it before branching. On many loaders, the host fully controls the DA2 load address/size, giving an unchecked memory write that can overwrite that in-memory hash and redirect execution to arbitrary payloads (pre-OS context with cache invalidation handled by DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** is signed/loaded by BootROM/Preloader. When Download Agent Authorization (DAA) is enabled, only signed DA1 should run.
- **DA2** is sent over USB. DA1 receives **size**, **load address**, and **SHA-256** and hashes the received DA2, comparing it to an **expected hash embedded in DA1** (copied into RAM).
- **Weakness:** On unpatched loaders, DA1 does not sanitize the DA2 load address/size and keeps the expected hash writable in memory, enabling the host to tamper with the check.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Enter the DA1→DA2 staging flow (DA1 allocates, prepares DRAM, and exposes the expected-hash buffer in RAM).
2. **Hash-slot overwrite:** Send a small payload that scans DA1 memory for the stored DA2-expected hash and overwrites it with the SHA-256 of the attacker-modified DA2. This leverages the user-controlled load to land the payload where the hash resides.
3. **Second `BOOT_TO` + digest:** Trigger another `BOOT_TO` with the patched DA2 metadata and send the raw 32-byte digest matching the modified DA2. DA1 recomputes SHA-256 over the received DA2, compares it against the now-patched expected hash, and the jump succeeds into attacker code.

On affected loaders, the unchecked address and size can provide an attacker-selected pre-OS memory-write primitive beyond the hash slot. Depending on the SoC memory map and later verification stages, this can support early-boot implants, secure-boot-bypass helpers, or rootkit-style payloads. DA code execution alone does not automatically provide persistence or a complete secure-boot bypass; a separate persistence mechanism and compatible verification chain are still required.<sup>[[1]](#references)[[2]](#references)</sup>

## Minimal PoC pattern (mtkclient-style)

```python
if self.xsend(self.Cmd.BOOT_TO):
    payload = bytes.fromhex("a4de2200000000002000000000000000")
    if self.xsend(payload) and self.status() == 0:
        import hashlib
        da_hash = hashlib.sha256(self.daconfig.da2).digest()
        if self.xsend(da_hash):
            self.status()
            self.info("All good!")
```

- The 16-byte `payload` reproduces the blob observed in the paid-tool workflow and used by the published implementation to patch the expected-hash buffer. It is loader-specific, not a portable hash-slot patch for every SoC or DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` sends raw bytes (not hex) so DA1 compares against the patched buffer.
- On a vulnerable, matched loader, DA2 can be an attacker-built image and the chosen load metadata controls its memory placement. Validate the DA/SoC combination before transmission because incorrect addresses can hang or damage the target.<sup>[[3]](#references)</sup>

## Patch landscape (hardened loaders)

- **Observed mitigation**: The hardened DAs examined by the researchers force the DA2 load address to `0x40000000` and ignore the host-supplied address, preventing writes to the observed DA1 hash region near `0x200000`. Treat both addresses as implementation-specific, not architectural constants.
- **Detecting patched DAs**: mtkclient/penumbra scan DA1 for patterns indicating the address-hardening; if found, Carbonara is skipped. Old DAs expose writable hash slots (commonly around offsets like `0x22dea4` in V5 DA1) and remain exploitable.
- **V5 vs V6**: Some V6 (XML) loaders still accept user-supplied addresses; newer V6 binaries usually enforce the fixed address and are immune to Carbonara unless downgraded.<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) note

MediaTek patched Carbonara; a newer vulnerability, **heapb8**, targets the DA2 USB file download handler on patched V6 loaders, giving code execution even when `boot_to` is hardened. It abuses a heap overflow during chunked file transfers to seize DA2 control flow. The exploit is public in Penumbra/mtk-payloads and demonstrates that Carbonara fixes do not close all DA attack surface.<sup>[[4]](#references)</sup>

## Notes for triage and hardening

- Devices where DA2 address/size are unchecked and DA1 keeps the expected hash writable are vulnerable. If a later Preloader/DA enforces address bounds or keeps the hash immutable, Carbonara is mitigated.
- Enabling DAA and ensuring DA1/Preloader validate BOOT_TO parameters (bounds + authenticity of DA2) closes the primitive. Closing only the hash patch without bounding the load still leaves arbitrary write risk.

## References

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
