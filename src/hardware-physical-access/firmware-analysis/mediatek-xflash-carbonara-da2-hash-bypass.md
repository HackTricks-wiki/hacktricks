# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Opsomming

"Carbonara" misbruik MediaTek se XFlash-downloadpad om 'n gewysigde Download Agent stage 2 (DA2) uit te voer ondanks DA1-integriteitskontroles. DA1 stoor die verwagte SHA-256 van DA2 in RAM en vergelyk dit voordat dit vertak. Op baie loaders beheer die host die DA2-laaiadres/-grootte volledig, wat 'n ongekontroleerde memory write moontlik maak wat daardie hash in die geheue kan oorskryf en uitvoering na arbitrêre payloads kan herlei (pre-OS-konteks met cache invalidation wat deur DA hanteer word).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** word deur BootROM/Preloader gesigned/gelaai. Wanneer Download Agent Authorization (DAA) geaktiveer is, behoort slegs gesigned DA1 uitgevoer te word.
- **DA2** word oor USB gestuur. DA1 ontvang **grootte**, **laaiadres** en **SHA-256**, en has die ontvangde DA2, waarna dit dit vergelyk met 'n **verwagte hash wat in DA1 ingebed is** (en in RAM gekopieer word).
- **Swakheid:** Op ongepatchde loaders valideer DA1 nie die DA2-laaiadres/-grootte nie en hou dit die verwagte hash in geheue skryfbaar, wat die host in staat stel om met die kontrole te peuter.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara-vloei ("two BOOT_TO"-truuk)

1. **Eerste `BOOT_TO`:** Gaan die DA1→DA2-staging-vloei binne (DA1 allokeer, berei DRAM voor en stel die verwagte-hash-buffer in RAM bloot).
2. **Hash-slot overwrite:** Stuur 'n klein payload wat DA1-geheue skandeer vir die gestoorde DA2-verwagte hash en dit oorskryf met die SHA-256 van die aanvaller-gewysigde DA2. Dit benut die gebruikerbeheerde laaiaksie om die payload te plaas waar die hash geleë is.
3. **Tweede `BOOT_TO` + digest:** Aktiveer nog 'n `BOOT_TO` met die gepatchde DA2-metadata en stuur die rou 32-grepe digest wat met die gewysigde DA2 ooreenstem. DA1 bereken SHA-256 oor die ontvangde DA2 opnuut, vergelyk dit met die nou-gepatchde verwagte hash, en die sprong slaag na aanvallerkode.

Omdat laaiadres/-grootte deur die aanvaller beheer word, kan dieselfde primitive oral in geheue skryf (nie net die hash-buffer nie), wat early-boot implants, secure-boot-bypass-helpers of malicious rootkits moontlik maak.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload` repliseer die betaalde-nutsprogram se blob wat die verwagte-hash-buffer binne DA1 patch.
- `sha256(...).digest()` stuur rou grepe (nie hex nie), sodat DA1 dit teen die gepatchte buffer vergelyk.
- DA2 kan enige aanvaller-geboude image wees; deur die laaiadres/-grootte te kies, word arbitrêre geheueplasing moontlik, met cache-invalidasie wat deur DA hanteer word.<sup>[[3]](#references)</sup>

## Patch-landskap (geharde loaders)

- **Versagting**: Opgedateerde DAs hardcode die DA2-laaiadres na `0x40000000` en ignoreer die adres wat die host verskaf, sodat writes nie die DA1-hash-slot (~`0x200000`) kan bereik nie. Die hash word steeds bereken, maar kan nie meer deur die aanvaller geskryf word nie.
- **Opspoor van gepatchte DAs**: mtkclient/penumbra skandeer DA1 vir patrone wat op adres-verharding dui; indien dit gevind word, word Carbonara oorgeslaan. Ou DAs stel skryfbare hash-slots bloot (algemeen rondom offsets soos `0x22dea4` in V5 DA1) en bly exploiteerbaar.
- **V5 teenoor V6**: Sommige V6 (XML)-loaders aanvaar steeds adresse wat deur die gebruiker verskaf word; nuwer V6-binaries dwing gewoonlik die vaste adres af en is immuun teen Carbonara, tensy dit gedowngrade word.<sup>[[2]](#references)[[3]](#references)</sup>

## Nota ná Carbonara (heapb8)

MediaTek het Carbonara gepatch; ’n nuwer vulnerability, **heapb8**, teiken die DA2 USB-lêeraflaai-handler op gepatchte V6-loaders en bied code execution selfs wanneer `boot_to` verhard is. Dit misbruik ’n heap overflow tydens chunked-lêeroordragte om beheer oor DA2 se control flow te verkry. Die exploit is publiek in Penumbra/mtk-payloads en toon dat Carbonara-fixes nie die volledige DA-aanvalsoppervlak sluit nie.<sup>[[4]](#references)</sup>

## Notas vir triage en hardening

- Toestelle waar die DA2-adres/-grootte nie nagegaan word nie en DA1 die verwagte hash skryfbaar hou, is kwesbaar. Indien ’n latere Preloader/DA adresgrense afdwing of die hash onveranderlik hou, word Carbonara versag.
- Deur DAA te aktiveer en te verseker dat DA1/Preloader BOOT_TO-parameters (grense + egtheid van DA2) valideer, word die primitive gesluit. Deur slegs die hash-patch te sluit sonder om die laai te begrens, bly daar steeds ’n arbitrêre write-risiko.

## Verwysings

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
