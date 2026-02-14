# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara" abuses MediaTek's XFlash download path to run a modified Download Agent stage 2 (DA2) despite DA1 integrity checks. DA1 stores the expected SHA-256 of DA2 in RAM and compares it before branching. On many loaders, the host fully controls the DA2 load address/size, giving an unchecked memory write that can overwrite that in-memory hash and redirect execution to arbitrary payloads (pre-OS context with cache invalidation handled by DA).

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** is signed/loaded by BootROM/Preloader. When Download Agent Authorization (DAA) is enabled, only signed DA1 should run.
- **DA2** is sent over USB. DA1 receives **size**, **load address**, and **SHA-256** and hashes the received DA2, comparing it to an **expected hash embedded in DA1** (copied into RAM).
- **Weakness:** On unpatched loaders, DA1 does not sanitize the DA2 load address/size and keeps the expected hash writable in memory, enabling the host to tamper with the check.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Enter the DA1→DA2 staging flow (DA1 allocates, prepares DRAM, and exposes the expected-hash buffer in RAM).
2. **Hash-slot overwrite:** Send a small payload that scans DA1 memory for the stored DA2-expected hash and overwrites it with the SHA-256 of the attacker-modified DA2. This leverages the user-controlled load to land the payload where the hash resides.
3. **Second `BOOT_TO` + digest:** Trigger another `BOOT_TO` with the patched DA2 metadata and send the raw 32-byte digest matching the modified DA2. DA1 recomputes SHA-256 over the received DA2, compares it against the now-patched expected hash, and the jump succeeds into attacker code.

Because load address/size are attacker-controlled, the same primitive can write anywhere in memory (not just the hash buffer), enabling early-boot implants, secure-boot bypass helpers, or malicious rootkits.

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

- `payload` replicates the paid-tool blob that patches the expected-hash buffer inside DA1.
- `sha256(...).digest()` sends raw bytes (not hex) so DA1 compares against the patched buffer.
- DA2 can be any attacker-built image; choosing the load address/size allows arbitrary memory placement with cache invalidation handled by DA.

## Notes for triage and hardening

- Devices where DA2 address/size are unchecked and DA1 keeps the expected hash writable are vulnerable. If a later Preloader/DA enforces address bounds or keeps the hash immutable, Carbonara is mitigated.
- Enabling DAA and ensuring DA1/Preloader validate BOOT_TO parameters (bounds + authenticity of DA2) closes the primitive. Closing only the hash patch without bounding the load still leaves arbitrary write risk.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
