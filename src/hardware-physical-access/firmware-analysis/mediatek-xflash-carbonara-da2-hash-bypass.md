# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Opsomming

"Carbonara" misbruik MediaTek se XFlash-downloadpad om 'n gemodifiseerde Download Agent stage 2 (DA2) te laat loop ondanks DA1-integriteitskontroles. DA1 stoor die verwagte SHA-256 van DA2 in RAM en vergelyk dit voordat dit oorspring. Op baie loaders beheer die host volledig die DA2 load address/size, wat 'n ongesanitiseerde geheueskrywing skep wat daardie in-geheue hash kan oorskryf en uitvoering na arbitrêre payloads kan herlei (pre-OS konteks, met cache invalidation hanteer deur DA).

## Vertrouensgrens in XFlash (DA1 → DA2)

- **DA1** is signed/loaded by BootROM/Preloader. Wanneer Download Agent Authorization (DAA) geaktiveer is, behoort slegs ondertekende DA1 te loop.
- **DA2** word oor USB gestuur. DA1 ontvang **size**, **load address**, en **SHA-256** en bereken die hash van die ontvangde DA2, vergelyk dit met 'n **expected hash embedded in DA1** (gekopieer na RAM).
- **Weakness:** Op ongepatchte loaders sanitiseer DA1 nie die DA2 load address/size nie en hou die expected hash skryfbaar in geheue, wat die host in staat stel om die check te manipuleer.

## Carbonara vloei ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Betree die DA1→DA2 staging-flow (DA1 alokeer, berei DRAM voor, en openbaar die expected-hash buffer in RAM).
2. **Hash-slot overwrite:** Stuur 'n klein payload wat DA1 se geheue deursoek na die gestoorde DA2-expected hash en dit oorskryf met die SHA-256 van die deur die aanvaller gewysigde DA2. Dit benut die gebruiker-beheerde load om die payload te laat land waar die hash woon.
3. **Second `BOOT_TO` + digest:** Aktiveer nog 'n `BOOT_TO` met die gepatchte DA2-metadata en stuur die rou 32-byte digest wat by die gemodifiseerde DA2 pas. DA1 herbereken SHA-256 oor die ontvangde DA2, vergelyk dit teen die nou-gepatchte expected hash, en die spring na die aanvallerkode slaag.

Omdat die load address/size deur die aanvaller beheer word, kan dieselfde primitive nêrens in geheue skryf nie (nie net die hash-buffer nie), wat vroeë-boot implante, secure-boot bypass helpers, of kwaadwillige rootkits moontlik maak.

## Minimale PoC-patroon (mtkclient-style)
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
- `payload` repliseer die paid-tool blob wat die expected-hash buffer binne DA1 patch.
- `sha256(...).digest()` stuur rou bytes (nie hex nie) sodat DA1 dit teen die gepatchte buffer vergelyk.
- DA2 kan enige attacker-built image wees; deur die load address/size te kies, word arbitrêre geheue-plaatsing moontlik, met cache invalidation wat deur DA hanteer word.

## Aantekeninge vir triage en verharding

- Toestelle waar DA2 se address/size nie geverifieer word nie en DA1 die expected hash skryfbaar hou, is kwesbaar. As ’n later Preloader/DA adresgrense afdwing of die hash onveranderlik hou, word Carbonara gemitigeer.
- Deur DAA te aktiveer en te verseker dat DA1/Preloader BOOT_TO-parameters valideer (grense + egtheid van DA2), word die primitive toegemaak. As slegs die hash patch gesluit word sonder om die load te begrens, bly daar steeds ’n risiko van willekeurige skryf.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
