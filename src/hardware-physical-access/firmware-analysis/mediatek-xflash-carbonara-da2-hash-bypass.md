# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Opsomming

"Carbonara" misbruik MediaTek se XFlash download path om 'n gemodifiseerde Download Agent stage 2 (DA2) te laat loop ondanks DA1-integriteitskontroles. DA1 stoor die verwagte SHA-256 van DA2 in RAM en vergelyk dit voordat dit vertak. Op baie loaders beheer die host die DA2 load address/size volledig, wat 'n ongekontroleerde geheue-skryf moontlik maak wat daardie in-geheue hash kan oorskryf en uitvoering na arbitrêre payloads herlei (pre-OS-konteks met cache invalidation hanteer deur DA).

## Vertrouensgrens in XFlash (DA1 → DA2)

- **DA1** word deur BootROM/Preloader onderteken/gelaai. Wanneer Download Agent Authorization (DAA) geaktiveer is, moet slegs ondertekende DA1 loop.
- **DA2** word oor USB gestuur. DA1 ontvang **size**, **load address**, en **SHA-256** en bereken die hash van die ontvangde DA2, en vergelyk dit met 'n **verwagte hash ingebed in DA1** (gekopieer na RAM).
- **Swakheid:** Op nie-gepatchede loaders valideer DA1 nie die DA2 load address/size nie en hou die verwagte hash skryfbaar in geheue, wat die host in staat stel om die kontrole te manipuleer.

## Carbonara-vloei ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Betree die DA1→DA2 staging flow (DA1 ken DRAM toe, berei voor, en openbaar die expected-hash buffer in RAM).
2. **Hash-slot overwrite:** Stuur 'n klein payload wat DA1-geheue deursoek na die gestoorde verwagte DA2-hash en oorskryf dit met die SHA-256 van die deur die aanvaller gewysigde DA2. Dit benut die gebruiker-beheerde load om die payload te laat land waar die hash woon.
3. **Second `BOOT_TO` + digest:** Aktiveer nog 'n `BOOT_TO` met die gepatchede DA2-metadata en stuur die rou 32-byte digest wat by die gewysigde DA2 pas. DA1 herbereken SHA-256 oor die ontvangde DA2, vergelyk dit met die nou-gekorrigeerde verwagte hash, en die sprong slaag na aanvaller-kode.

Omdat load address/size deur die aanvaller beheer word, kan dieselfde primêre bewerking oral in geheue skryf (nie net die hash-buffers nie), wat vroeë-boot implants, secure-boot bypass helpers, of kwaadwillige rootkits moontlik maak.

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
- `payload` repliseer die betaalde tool se blob wat die expected-hash buffer binne DA1 patch.
- `sha256(...).digest()` stuur rou bytes (nie hex nie) sodat DA1 teen die ge-patchte buffer vergelyk.
- DA2 kan enige attacker-built image wees; deur die load address/size te kies word willekeurige geheueplasing toegelaat, met cache invalidation hanteer deur DA.

## Patch-landskap (verhardde loaders)

- **Versagting**: Opgedate DAs hardcode die DA2 load address na `0x40000000` en ignoreer die adres wat die host voorsien, sodat skrywe nie die DA1 hash slot (~0x200000 range) kan bereik nie. Die hash word steeds bereken maar is nie meer attacker-writable nie.
- **Opsporing van ge-patchte DAs**: mtkclient/penumbra scan DA1 vir patrone wat die address-hardening aandui; as gevind, word Carbonara oorgeslaan. Ou DAs openbaar skryfbare hash-slotte (gewoonlik rondom offsets soos `0x22dea4` in V5 DA1) en bly uitbuitbaar.
- **V5 vs V6**: Sommige V6 (XML) loaders aanvaar steeds user-supplied addresses; nuwer V6 binaries dwing gewoonlik die vaste adres af en is immuun teen Carbonara tensy gedowngrade word.

## Post-Carbonara (heapb8) nota

MediaTek het Carbonara gepatch; 'n nuwer kwesbaarheid, **heapb8**, mik na die DA2 USB file download handler op ge-patchte V6 loaders, wat code execution gee selfs wanneer `boot_to` verhard is. Dit misbruik 'n heap overflow tydens chunked file transfers om DA2 se control flow te oorneem. Die exploit is publiek in Penumbra/mtk-payloads en toon dat Carbonara-fixes nie al die DA attack surface sluit nie.

## Aantekeninge vir triage en verharding

- Toestelle waar DA2 address/size nie gekontroleer word nie en DA1 die expected hash skryfbaar hou, is kwesbaar. As 'n latere Preloader/DA address bounds afdwing of die hash onveranderlik hou, word Carbonara versag.
- Deur DAA te aktiveer en te verseker dat DA1/Preloader BOOT_TO parameters valideer (bounds + authenticiteit van DA2) sluit die primitive. Slegs die hash patch toemaak sonder om die load te begrens laat steeds risiko vir arbitrary write.

## Verwysings

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
