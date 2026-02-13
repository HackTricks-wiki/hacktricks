# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Sažetak

"Carbonara" zloupotrebljava MediaTek's XFlash download path da pokrene modifikovani Download Agent stage 2 (DA2) uprkos DA1 integrity checks. DA1 čuva očekivani SHA-256 DA2 u RAM i poredi ga pre grananja. Na mnogim loaders, host u potpunosti kontroliše DA2 load address/size, što daje unchecked memory write koji može prepisati taj in-memory hash i preusmeriti izvršavanje na arbitrary payloads (pre-OS context sa cache invalidation koje obrađuje DA).

## Granica poverenja u XFlash (DA1 → DA2)

- **DA1** je signed/loaded by BootROM/Preloader. Kada je Download Agent Authorization (DAA) enabled, samo signed DA1 treba da se izvršava.
- **DA2** se šalje over USB. DA1 prima **size**, **load address**, i **SHA-256** i hešira primljeni DA2, upoređujući ga sa **expected hash embedded in DA1** (kopiran u RAM).
- **Weakness:** Na unpatched loaders, DA1 ne sanitize-uje DA2 load address/size i čuva expected hash writable u memory, omogućavajući host-u da manipuliše check-om.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Uđite u DA1→DA2 staging flow (DA1 alocira, priprema DRAM, i izlaže expected-hash buffer u RAM).
2. **Hash-slot overwrite:** Pošaljite mali payload koji skenira DA1 memory za stored DA2-expected hash i prepisuje ga sa SHA-256 of the attacker-modified DA2. Ovo koristi user-controlled load da postavi payload tamo gde se hash nalazi.
3. **Second `BOOT_TO` + digest:** Trigger-ujte još jedan `BOOT_TO` sa patched DA2 metadata i pošaljite raw 32-byte digest koji se poklapa sa modified DA2. DA1 ponovo računa SHA-256 preko primljenog DA2, upoređuje ga sa sada patch-ovanim expected hash-om, i skok uspeva u attacker code.

Pošto su load address/size attacker-controlled, ista primitive može pisati bilo gde u memoriji (ne samo u hash buffer), omogućavajući early-boot implants, secure-boot bypass helpers, ili malicious rootkits.

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
- `payload` replicira blob plaćenog alata koji zakrpa expected-hash bafer unutar DA1.
- `sha256(...).digest()` šalje sirove bajtove (ne hex) pa DA1 poredi protiv zakrpanog bafera.
- DA2 može biti bilo koji napadačem napravljen image; odabirom adrese/veličine učitavanja omogućava se proizvoljno pozicioniranje u memoriji, pri čemu invalidacija keša ide preko DA.

## Napomene za trijažu i ojačavanje

- Uređaji gde adresa/veličina DA2 nisu proveravani i DA1 ostavlja expected hash zapisljivim su ranjivi. Ako kasniji Preloader/DA nameće granice adresa ili drži hash nepromenljivim, Carbonara je ublažen.
- Omogućavanje DAA i osiguravanje da DA1/Preloader validiraju BOOT_TO parametre (granice + autentičnost DA2) zatvara primitiv. Zatvaranje samo zakrpe hasha bez ograničavanja učitavanja i dalje ostavlja rizik proizvoljnog pisanja.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
