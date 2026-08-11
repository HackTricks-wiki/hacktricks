# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Opsomming

"Carbonara" misbruik MediaTek se XFlash-downloadpad om ’n gewysigde Download Agent stage 2 (DA2) uit te voer ondanks DA1-integriteitskontroles. DA1 stoor die verwagte SHA-256 van DA2 in RAM en vergelyk dit voordat dit vertak. Op baie loaders beheer die host die DA2-laaiadres/-grootte volledig, wat ’n ongekontroleerde geheueskrywing moontlik maak wat daardie hash in die geheue kan oorskryf en uitvoering na arbitrêre payloads kan herlei (pre-OS-konteks met cache-invalidasie wat deur DA hanteer word).<sup>[[1]](#references)[[2]](#references)</sup>

## Vertrouensgrens in XFlash (DA1 → DA2)

- **DA1** word deur BootROM/Preloader onderteken/gelaai. Wanneer Download Agent Authorization (DAA) geaktiveer is, behoort slegs ondertekende DA1 te loop.
- **DA2** word oor USB gestuur. DA1 ontvang **grootte**, **laaiadres** en **SHA-256**, hash die ontvangde DA2, en vergelyk dit met ’n **verwagte hash wat in DA1 ingebed is** (en na RAM gekopieer word).
- **Swakheid:** Op ongepatchte loaders valideer DA1 nie die DA2-laaiadres/-grootte nie en hou dit die verwagte hash skryfbaar in die geheue, wat die host in staat stel om met die kontrole te peuter.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara-vloei ("twee BOOT_TO"-truuk)

1. **Eerste `BOOT_TO`:** Gaan die DA1→DA2-staging-vloei binne (DA1 allokeer, berei DRAM voor en stel die verwagte-hash-buffer in RAM beskikbaar).
2. **Oorskryf van hash-slot:** Stuur ’n klein payload wat DA1-geheue skandeer vir die gestoorde DA2-verwagte hash en dit oorskryf met die SHA-256 van die aanvaller-gewysigde DA2. Dit benut die gebruikersbeheerde laai om die payload te plaas waar die hash geleë is.
3. **Tweede `BOOT_TO` + digest:** Begin nog ’n `BOOT_TO` met die gepatchte DA2-metadata en stuur die rou 32-grepe digest wat met die gewysigde DA2 ooreenstem. DA1 bereken SHA-256 opnieuw oor die ontvangde DA2, vergelyk dit met die nou-gepatchte verwagte hash, en die sprong slaag na aanvallerkode.

Op geaffekteerde loaders kan die ongekontroleerde adres en grootte ’n aanvallergekose pre-OS-geheueskryf-primitief buite die hash-slot bied. Afhangend van die SoC-geheuekaart en latere verifikasiestappe kan dit vroeë-opstart-implante, secure-boot-bypass helpers of rootkit-styl payloads ondersteun. DA-kode-uitvoering alleen bied nie outomaties persistence of ’n volledige secure-boot-bypass nie; ’n afsonderlike persistence-meganisme en versoenbare verifikasieketting word steeds vereis.<sup>[[1]](#references)[[2]](#references)</sup>

## Minimum PoC-patroon (mtkclient-styl)
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
- Die 16-byte `payload` reproduseer die blob wat in die betaalde-tool workflow waargeneem is en deur die gepubliseerde implementering gebruik word om die verwagte-hash-buffer te patch. Dit is loader-spesifiek, nie 'n draagbare hash-slot-patch vir elke SoC of DA nie.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` stuur rou bytes (nie hex nie), sodat DA1 teen die gepatchde buffer vergelyk.
- Op 'n kwesbare, ooreenstemmende loader kan DA2 'n beeld wees wat deur 'n aanvaller gebou is, en die gekose load metadata beheer die geheueplasing daarvan. Valideer die DA/SoC-kombinasie voor transmissie, omdat verkeerde adresse die teiken kan laat vashaak of beskadig.<sup>[[3]](#references)</sup>

## Patch-landskap (hardened loaders)

- **Waargenome mitigering**: Die hardened DAs wat deur die navorsers ondersoek is, forseer die DA2-load address na `0x40000000` en ignoreer die adres wat deur die host verskaf word, wat writes na die waargenome DA1-hashstreek naby `0x200000` voorkom. Behandel albei adresse as implementeringspesifiek, nie as argitektoniese konstantes nie.
- **Detecting patched DAs**: mtkclient/penumbra skandeer DA1 vir patrone wat op address-hardening dui; indien dit gevind word, word Carbonara oorgeslaan. Ou DAs stel skryfbare hash-slots bloot (algemeen rondom offsets soos `0x22dea4` in V5 DA1) en bly exploitable.
- **V5 vs V6**: Sommige V6 (XML)-loaders aanvaar steeds adresse wat deur die gebruiker verskaf word; nuwer V6-binaries forseer gewoonlik die fixed address en is immuun teen Carbonara, tensy dit gedowngrade word.<sup>[[2]](#references)[[3]](#references)</sup>

## Nota ná Carbonara (heapb8)

MediaTek het Carbonara gepatch; 'n nuwer vulnerability, **heapb8**, teiken die DA2 USB file download handler op gepatchde V6-loaders en gee code execution selfs wanneer `boot_to` geharden is. Dit misbruik 'n heap overflow tydens chunked file transfers om beheer oor DA2 se control flow te verkry. Die exploit is publiek in Penumbra/mtk-payloads en toon dat Carbonara-fixes nie die hele DA attack surface sluit nie.<sup>[[4]](#references)</sup>

## Notas vir triage en hardening

- Toestelle waar DA2 address/size nie gecheck word nie en DA1 die verwagte hash skryfbaar hou, is kwesbaar. Indien 'n latere Preloader/DA address bounds afdwing of die hash onveranderlik hou, word Carbonara gemitigeer.
- Deur DAA te enable en te verseker dat DA1/Preloader BOOT_TO-parameters valideer (bounds + egtheid van DA2), word die primitive gesluit. Om slegs die hash-patch te sluit sonder om die load te begrens, laat steeds arbitrary write-risiko bestaan.

## References

- [1] [Carbonara: Die MediaTek-exploit wat niemand bedien het nie](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit-dokumentasie](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara-bronkode](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: Uitbuiting van gepatchde V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
