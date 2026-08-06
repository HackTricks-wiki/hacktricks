# Mbinu za PNG

{{#include ../../../banners/hacktricks-training.md}}

**Faili za PNG** ni za kawaida sana katika **CTFs**, **incident response**, na **malware staging** kwa sababu ni **lossless**, zina muundo wa **chunk-based**, na tools nyingi huzirender bila matatizo hata zinapokuwa na **extra metadata**, **appended payloads**, au **partially corrupted chunks**.

Ichukulie PNG kama **container**, si picha tu.

## Uchunguzi wa haraka

Anza na ukaguzi wa kiwango cha container kabla ya kuanza LSB stego. Kwa workflow ya bit-plane/LSB, angalia [ukurasa maalum wa image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Vitu muhimu vya kutafuta:

- **Chunks za ziada zisizotarajiwa** kama `tEXt`, `zTXt`, `iTXt`, `eXIf`, au `iCCP`
- **Makosa ya CRC** au urefu wa chunks ulioundwa vibaya
- **Data ya ziada baada ya `IEND`**
- **Alama nyingi za `IEND`** au vipande vya `IDAT` vinavyoweza kurejeshwa baada ya mwisho rasmi wa file
- File ambayo ni PNG halali **na** pia inaonekana kama ZIP/PDF/script inapofanyiwa carving

Kumbuka kwamba muundo wa chini kabisa unaokubalika kwa kawaida ni:

- `IHDR` (lazima iwe ya kwanza)
- `IDAT` (chunk moja au zaidi zinazofuatana)
- `IEND` (lazima iwe ya mwisho)

## Data inayofuata baada ya `IEND`

Moja ya PNG artefacts zenye signal kubwa zaidi ni **data iliyoongezwa baada ya chunk ya mwisho ya `IEND`**. Decoders wengi huipuuza, jambo linaloifanya iwe muhimu kwa:

- **Simple stego / payloads zilizofichwa**
- **PNG polyglots**
- **Malware staging**
- **Kurejesha data ya zamani ya image** kutoka kwa editors zenye bugs

Utambuzi wa haraka:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Ikiwa unataka kuchonga kila kitu baada ya `IEND` ya mwisho:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Pia jaribu generic archive parsers moja kwa moja dhidi ya PNG au carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Urejeshaji wa aina ya Acropalypse wa picha za skrini zilizokatwa/kufichwa

Mbinu ya hivi karibuni na yenye manufaa sana ya uchunguzi wa PNG ni kuangalia ikiwa kihariri cha picha ya skrini **kiliandika juu** ya PNG bila **kupunguza** faili ya zamani kwanza. Katika hali hizi, bytes kutoka kwa **picha iliyotangulia** zinaweza kubaki baada ya `IEND`, na wakati mwingine data ya ziada ya `IDAT` inaweza kurejeshwa kwa sehemu.

Hili lilijulikana sana kupitia **aCropalypse** (Google Pixel Markup) na tatizo linalohusiana la **Windows Snipping Tool**. Kwa vitendo, ikiwa PNG "iliyokatwa" au "iliyofichwa" bado ina data ya zamani mwishoni, unaweza kuweza kurejesha sehemu ya picha ya skrini ya awali.<sup>[[1]](#references)</sup>

Mtiririko wa kazi wa vitendo:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Dalili zinazoonyesha kwa nguvu kwamba uchanganuzi wa kina unahitajika:

- `pngcheck` inaripoti **additional data after `IEND`**
- Unapata **zaidi ya `IEND` moja**
- Unapata **`IDAT` chunks za ziada** baada ya mwisho unaoonekana wa picha
- Screenshot ilitoka kwenye kifaa/editor inayojulikana kuwa imeathiriwa

Hili likitokea, pitisha faili kwenye **aCropalypse recovery tool** kabla ya kuamini kuwa redaction ni salama.

## Chunk abuse inayohusika katika mazoezi

PNG chunks zinazovutia zaidi kwa uchunguzi kwa kawaida si zile za picha zilizo wazi, bali ni chunks zinazoweza kubeba **maandishi**, **metadata**, au **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata na maandishi yaliyobanwa
- `eXIf` – EXIF data ndani ya PNG
- `iCCP` – ICC profile iliyopachikwa
- `PLTE` – palette data katika picha za indexed, lakini pia ni muhimu katika matukio ya payload-smuggling<sup>[[2]](#references)</sup>

Zitoe kwa kutumia:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Kwa offensive payload persistence ndani ya PNG chunks (kwa mfano tricks za **PLTE**, **IDAT**, au **tEXt** zinazodumu kupitia baadhi ya mabadiliko ya picha ya PHP), angalia maelezo ya kina yanayolenga upload hapa<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Urekebishaji wa PNG iliyoharibika

Kwa kukagua integrity na kubaini eneo halisi lililoharibika, **pngcheck** bado ni mojawapo ya tools bora za kuanzia:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ikiwa file limeharibika badala ya kuwa malicious kimakusudi, **PCRT** inaweza kuwa muhimu katika CTFs na kazi za maabara kwa kurekebisha matatizo ya kawaida kama vile headers mbaya, thamani zisizo sahihi za IHDR, matatizo ya CRC, au chunk layouts zilizoundwa vibaya.

Ikiwa lengo lako ni kufanya **sanitize** PNG iliyo na trailer data ya kutiliwa shaka huku ukihifadhi picha inayoonekana, ExifTool inaweza kuondoa trailer hiyo waziwazi:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Kwa ushahidi nyeti, fanyia kazi **copy** kila mara na uhifadhi hashes za asili kabla ya kujaribu repairs.

## Marejeleo

- [1] [Exploiting aCropalypse: Recovering Truncated PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: How to inject PHP code in an image – and keep it there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
