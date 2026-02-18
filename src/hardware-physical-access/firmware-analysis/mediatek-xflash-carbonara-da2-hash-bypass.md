# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

"Carbonara" inatumia MediaTek's XFlash download path kuendesha modified Download Agent stage 2 (DA2) licha ya integrity checks za DA1. DA1 inahifadhi expected SHA-256 ya DA2 katika RAM na inaiweka kulinganisha kabla ya kutokea branch. Katika loaders nyingi, host anadhibiti kikamilifu the DA2 load address/size, ikitoa unchecked memory write inaweza kuandika juu ya hash hiyo ya ndani ya RAM na kuelekeza execution kwa arbitrary payloads (pre-OS context na cache invalidation inashughulikiwa na DA).

## Mipaka ya uaminifu katika XFlash (DA1 → DA2)

- **DA1** is signed/loaded by BootROM/Preloader. When Download Agent Authorization (DAA) is enabled, only signed DA1 should run.
- **DA2** inatumwa over USB. DA1 receives **size**, **load address**, and **SHA-256** na inaheshimu (hashes) the received DA2, ikilinganisha na **expected hash embedded in DA1** (copied into RAM).
- **Weakness:** Katika unpatched loaders, DA1 haitosafisha the DA2 load address/size na inaweka the expected hash writable in memory, ikiruhusu host kutamper na kubadilisha check.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Enter the DA1→DA2 staging flow (DA1 allocates, prepares DRAM, and exposes the expected-hash buffer in RAM).
2. **Hash-slot overwrite:** Send a small payload that scans DA1 memory for the stored DA2-expected hash and overwrites it with the SHA-256 of the attacker-modified DA2. This leverages the user-controlled load to land the payload where the hash resides.
3. **Second `BOOT_TO` + digest:** Trigger another `BOOT_TO` with the patched DA2 metadata and send the raw 32-byte digest matching the modified DA2. DA1 recomputes SHA-256 over the received DA2, compares it against the now-patched expected hash, and the jump succeeds into attacker code.

Kwa sababu the load address/size vinadhibitiwa na attacker, primitive hiyo inaweza kuandika mahali popote kwenye memory (si tu kwenye hash buffer), ikiruhusu early-boot implants, secure-boot bypass helpers, au malicious rootkits.

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
- `payload` inakilisha blob ya paid-tool ambayo inapatch buffer ya expected-hash ndani ya DA1.
- `sha256(...).digest()` inatuma raw bytes (si hex) hivyo DA1 inalinganisha dhidi ya buffer iliyopatchiwa.
- DA2 inaweza kuwa image yoyote iliyotengenezwa na mshambuliaji; kuchagua load address/size kunaruhusu kuweka kumbukumbu mahali popote wakati cache invalidation inashughulikiwa na DA.

## Patch landscape (hardened loaders)

- **Mitigation**: DAs zilizosasishwa zina-hardcode DA2 load address kuwa `0x40000000` na haziitii address inayotolewa na host, hivyo maandishi hayawezi kufika slot ya hash ya DA1 (~0x200000 range). Hash bado inahesabiwa lakini hawezi tena kuandikwa na mshambuliaji.
- **Detecting patched DAs**: mtkclient/penumbra hupitia DA1 kwa pattern zinazoonyesha address-hardening; ikiwa zinapatikana, Carbonara inarukwa. DA za zamani zinaonyesha writable hash slots (kawaida karibu offsets kama `0x22dea4` katika V5 DA1) na zinabaki zinaweza kutumiwa.
- **V5 vs V6**: Baadhi ya V6 (XML) loaders bado zinakubali anwani zilizotolewa na mtumiaji; binaries mpya za V6 kwa kawaida zina-enforce anwani iliyowekwa na ni immune kwa Carbonara isipokuwa ikidorongeshwa hadi toleo la zamani.

## Post-Carbonara (heapb8) note

MediaTek ilipatch Carbonara; udhaifu mpya, **heapb8**, unalenga DA2 USB file download handler kwenye patched V6 loaders, ukiruhusu code execution hata wakati `boot_to` imeimarishwa. Unatumia heap overflow wakati wa uhamisho wa faili kwa vipande (chunked) ili kuchukua mtiririko wa udhibiti wa DA2. Exploit iko wazi katika Penumbra/mtk-payloads na inaonyesha kwamba fixes za Carbonara hazifunzi uso wote wa attack surface wa DA.

## Notes for triage and hardening

- Vifaa ambavyo DA2 address/size hazikaguliwi na DA1 inaendelea kuweka expected hash writable ni dhaifu. Ikiwa Preloader/DA ya baadaye inatekeleza mipaka ya address au inafanya hash isiyoweza kubadilishwa, Carbonara inapunguzwa.
- Kuwezesha DAA na kuhakikisha DA1/Preloader zinathibitisha vigezo vya BOOT_TO (mipaka + authenticity ya DA2) kunafunga primitive. Kufunga tu patch ya hash bila kuweka mipaka ya load bado kunaacha hatari ya arbitrary write.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
