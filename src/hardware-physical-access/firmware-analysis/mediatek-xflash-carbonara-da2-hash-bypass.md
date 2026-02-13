# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Carbonara hutumia njia ya kupakua ya MediaTek XFlash kuendesha modified Download Agent stage 2 (DA2) licha ya ukaguzi wa uadilifu wa DA1. DA1 inahifadhi expected SHA-256 ya DA2 katika RAM na kuifanya kulinganisha kabla ya kutoka. Katika loaders nyingi, host inadhibiti kabisa anwani/size ya load ya DA2, ikitoa uandishi wa memory usiohifadhiwa ambao unaweza kufuta/hash iliyomo kwenye RAM na kuelekeza utekelezaji kwa payloads yoyote (konteksti kabla ya OS huku DA ikishughulikia cache invalidation).

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
- `payload` hufanana na blob ya paid-tool inayofanya patch kwenye buffer ya expected-hash ndani ya DA1.
- `sha256(...).digest()` hutuma baiti ghafi (si hex) hivyo DA1 inalinganisha dhidi ya buffer iliyopatchiwa.
- DA2 inaweza kuwa image yoyote iliyojengwa na mshambuliaji; kuchagua load address/size kunaruhusu kuweka kumbukumbu kwa njia yoyote huku cache invalidation ikifanywa na DA.

## Vidokezo kwa triage na kuimarisha

- Vifaa ambavyo DA2 address/size hazikukaguliwa na DA1 ikibaki na expected hash ikiwa writable viko hatarini. Ikiwa Preloader/DA iliyofuata inatekeleza mipaka ya address au inafanya hash isiweze kubadilishwa (immutable), Carbonara inapunguzwa.
- Kuwezesha DAA na kuhakikisha DA1/Preloader zinathibitisha vigezo vya BOOT_TO (mipaka + uhalali wa DA2) zinafunga primitive. Kufunga tu patch ya hash bila kuweka mipaka ya load bado kuna hatari ya kuandika kiholela.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
