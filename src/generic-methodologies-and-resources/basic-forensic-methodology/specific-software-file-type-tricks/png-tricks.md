# Mbinu za PNG

{{#include ../../../banners/hacktricks-training.md}}

**Faili za PNG** ni za kawaida sana katika **CTFs**, **mwitikio wa matukio**, na **malware staging** kwa sababu hazipotezi ubora, zinategemea **chunks**, na tools nyingi huzionyesha bila shida hata zinapokuwa na **metadata** ya ziada, **payloads** zilizoambatishwa, au **chunks** zilizoharibika kwa sehemu.

Chukulia PNG kama **container**, si picha tu.

## Ukaguzi wa haraka

Anza na ukaguzi wa kiwango cha container kabla ya kuanza LSB stego. Kwa workflow ya bit-plane/LSB, angalia [ukurasa maalum wa image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Mambo muhimu ya kutafuta:

- **Chunks za ziada zisizotarajiwa** kama `tEXt`, `zTXt`, `iTXt`, `eXIf`, au `iCCP`
- **Makosa ya CRC** au urefu wa chunk usio sahihi
- **Data ya ziada baada ya `IEND`**
- **Alama nyingi za `IEND`** au vipande vya `IDAT` vinavyoweza kurejeshwa baada ya mwisho rasmi wa file
- File ambayo ni PNG halali **na pia inaonekana kama ZIP/PDF/script inapochambuliwa kwa carving**

Kumbuka kwamba muundo wa chini kabisa unaokubalika kwa kawaida ni:

- `IHDR` (lazima iwe ya kwanza)
- `IDAT` (chunk moja au zaidi zinazofuatana)
- `IEND` (lazima iwe ya mwisho)

## Data ya ziada baada ya `IEND`

Mojawapo ya PNG artefacts zenye signal kubwa zaidi ni **data iliyoongezwa baada ya chunk ya mwisho ya `IEND`**. Decoders wengi huipuuza, jambo linaloifanya iwe muhimu kwa:

- **Simple stego / payloads zilizofichwa**
- **PNG polyglots**
- **Malware staging**
- **Kurejesha data ya zamani ya picha** kutoka kwa editors zenye bugs

Utambuzi wa haraka:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Ikiwa unataka kuchanganua kila kitu baada ya `IEND` ya mwisho:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Pia jaribu generic archive parsers moja kwa moja dhidi ya PNG au trailer iliyochongwa:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Urejeshaji wa mtindo wa Acropalypse wa picha za skrini zilizokatwa/kufichwa

Mbinu ya hivi karibuni na yenye manufaa sana ya uchunguzi wa PNG ni kuangalia ikiwa screenshot editor **iliandika juu ya** PNG bila **kukata** faili ya zamani kwanza. Katika hali hizo, bytes kutoka kwa **picha ya awali** zinaweza kubaki baada ya `IEND`, na wakati mwingine data ya ziada ya `IDAT` inaweza kujengwa upya kwa sehemu.

Hili lilijulikana sana kupitia **aCropalypse** (Google Pixel Markup) na tatizo linalohusiana la **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Kwa vitendo, ikiwa PNG "iliyokatwa" au "iliyofichwa" bado ina data ya zamani mwishoni, unaweza kurejesha sehemu ya screenshot ya awali.<sup>[[1]](#references)</sup>

Mtiririko wa kazi wa vitendo:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Dalili zinazoonyesha kwa nguvu kwamba uchambuzi wa kina unahitajika:

- `pngcheck` inaripoti **data ya ziada baada ya `IEND`**
- Unapata **zaidi ya `IEND` moja**
- Unapata **chunks za ziada za `IDAT`** baada ya mwisho unaoonekana wa image
- Screenshot ilitoka kwenye kifaa/editor unaojulikana kuwa uliathiriwa

Hili likitokea, pitisha file kwenye **aCropalypse recovery tool** kabla ya kuamini redaction.

## Matumizi mabaya ya chunks muhimu katika mazoezi

PNG chunks zinazovutia zaidi kwa uchunguzi kwa kawaida si zile za image zilizo wazi, bali ni chunks zinazoweza kubeba **text**, **metadata**, au **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata na text iliyobanwa
- `eXIf` – EXIF data ndani ya PNG
- `iCCP` – ICC profile iliyopachikwa
- `PLTE` – palette data kwenye images zilizowekwa kwa index, lakini pia ni muhimu katika hali za payload-smuggling.<sup>[[2]](#references)</sup>

Zidump kwa kutumia:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Kwa persistence ya offensive payload ndani ya PNG chunks (kwa mfano tricks za **PLTE**, **IDAT**, au **tEXt** zinazoweza kuendelea baada ya baadhi ya mabadiliko ya picha ya PHP), angalia maelezo ya kina zaidi yanayolenga upload hapa:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Urekebishaji wa PNG Iliyoharibika

Kwa kukagua integrity na kubaini eneo halisi lililoharibika, **pngcheck** bado ni mojawapo ya tools bora za kuanzia:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ikiwa file imeharibika badala ya kuwa malicious kwa makusudi, **PCRT** inaweza kuwa muhimu katika CTFs na kazi za maabara kwa kurekebisha matatizo ya kawaida kama vile headers mbaya, thamani zisizo sahihi za IHDR, matatizo ya CRC, au mipangilio ya chunks isiyo sahihi.

Ikiwa lengo lako ni **kusafisha** PNG iliyo na trailer data yenye mashaka huku ukihifadhi picha inayoonekana, ExifTool inaweza kuondoa trailer hiyo moja kwa moja:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Kwa ushahidi nyeti, kila mara fanyia kazi **nakala** na uhifadhi hashes za chanzo asili kabla ya kujaribu kurekebisha.

## References

- [1] [Kutumia aCropalypse: Kurejesha PNG Zilizokatwa](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PHP payloads zinazoendelea katika PNGs: Jinsi ya kuingiza code ya PHP kwenye picha – na kuifanya ibaki humo](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
