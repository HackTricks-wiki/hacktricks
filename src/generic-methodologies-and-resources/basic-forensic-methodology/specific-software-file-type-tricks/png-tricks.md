# Mbinu za PNG

**Faili za PNG** ni za kawaida sana katika **CTFs**, **incident response**, na **malware staging** kwa sababu ni **lossless**, zinatumia mfumo wa **chunks**, na zana nyingi huzionyesha bila tatizo hata zinapokuwa na **metadata ya ziada**, **payloads zilizoongezwa**, au **chunks zilizoharibika kwa sehemu**.

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
Vitu muhimu vya kutafuta:

- **Unexpected ancillary chunks** kama `tEXt`, `zTXt`, `iTXt`, `eXIf`, au `iCCP`
- **CRC errors** au urefu wa chunk usio sahihi
- **Additional data after `IEND`**
- **Multiple `IEND` markers** au vipande vya `IDAT` vinavyoweza kurejeshwa baada ya mwisho rasmi wa faili
- Faili ambayo ni PNG halali **na** pia inaonekana kama ZIP/PDF/script inapofanyiwa carving

Kumbuka kuwa muundo wa chini kabisa wa PNG halali kwa kawaida ni:

- `IHDR` (lazima iwe ya kwanza)
- `IDAT` (chunk moja au zaidi zinazofuatana)
- `IEND` (lazima iwe ya mwisho)

## Trailing data after `IEND`

Mojawapo ya vielelezo vya PNG vyenye **signal** ya juu zaidi ni **data iliyoongezwa baada ya `IEND` chunk ya mwisho**. Decoders wengi hupuuza data hiyo, jambo linaloifanya iwe muhimu kwa:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** kutoka kwa editors zenye bugs

Utambuzi wa haraka:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Ikiwa unataka kuchopoa kila kitu baada ya `IEND` ya mwisho:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Pia jaribu vichanganuzi vya jumla vya archive moja kwa moja dhidi ya PNG au sehemu ya mwisho iliyochongwa:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Urejeshaji wa aina ya Acropalypse wa screenshot zilizokatwa/kufichwa

Mbinu ya hivi karibuni na ya vitendo sana ya forensic ya PNG ni kuangalia ikiwa kihariri cha screenshot **kiliandika juu ya** PNG bila **kufupisha** faili ya zamani kwanza. Katika hali hizo, bytes kutoka kwa **image ya awali** zinaweza kubaki baada ya `IEND`, na wakati mwingine data ya ziada ya `IDAT` inaweza kujengwa upya kwa sehemu.

Hili lilijulikana sana kupitia **aCropalypse** (Google Pixel Markup) na tatizo linalohusiana na **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Kwa vitendo, ikiwa PNG "iliyokatwa" au "iliyofichwa" bado ina data ya zamani mwishoni, unaweza kuweza kurejesha sehemu ya screenshot ya awali.<sup>[[1]](#references)</sup>

Mtiririko wa kazi wa vitendo:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Dalili zinazoashiria kwa nguvu kwamba uchanganuzi wa kina zaidi unahitajika:

- `pngcheck` inaripoti **data ya ziada baada ya `IEND`**
- Unapata **zaidi ya `IEND` moja**
- Unapata **chunks za ziada za `IDAT`** baada ya mwisho unaoonekana wa picha
- Screenshot ilitoka kwenye kifaa/editor inayojulikana kuwa imeathiriwa

Hili likitokea, pitisha faili kwenye **aCropalypse recovery tool** kabla ya kuchukulia redaction kuwa ya kuaminika.

## Matumizi mabaya ya chunks yanayohitaji kuzingatiwa kivitendo

Chunks za PNG zinazovutia zaidi kwa uchunguzi kwa kawaida si zile za picha zilizo wazi, bali ni chunks zinazoweza kubeba **maandishi**, **metadata**, au **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadata ya maandishi na maandishi yaliyobanwa
- `eXIf` – data ya EXIF ndani ya PNG
- `iCCP` – ICC profile iliyopachikwa
- `PLTE` – data ya palette kwenye picha zilizowekwa kwa index, lakini pia ni muhimu katika hali za payload-smuggling.<sup>[[2]](#references)</sup>

Zitoe kwa kutumia:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Kwa payload persistence za offensive ndani ya PNG chunks (kwa mfano tricks za **PLTE**, **IDAT**, au **tEXt** zinazoweza kudumu baada ya baadhi ya transformations za picha za PHP), angalia notes zenye maelezo zaidi zinazolenga upload hapa:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Urekebishaji wa PNG iliyoharibika

Kwa kukagua integrity na kubaini eneo halisi lililoharibika, **pngcheck** bado ni mojawapo ya tools bora za kuanzia:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ikiwa file imeharibika badala ya kuwa malicious kwa makusudi, **PCRT** inaweza kuwa muhimu katika CTFs na kazi za maabara kwa kurekebisha matatizo ya kawaida kama vile headers mbaya, thamani za IHDR zisizo sahihi, matatizo ya CRC, au mipangilio ya chunks iliyoharibika.

Ikiwa lengo lako ni **kusafisha** PNG iliyo na trailer data inayotiliwa shaka huku ukihifadhi picha inayoonekana, ExifTool inaweza kuondoa trailer hiyo moja kwa moja:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Kwa ushahidi nyeti, daima fanyia kazi **nakala** na uhifadhi hash za nakala asili kabla ya kujaribu kuirekebisha.

## References

- [1] [Kutumia aCropalypse: Kurejesha PNG Zilizokatwa](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PHP payloads zinazoendelea katika PNGs: Jinsi ya kuingiza msimbo wa PHP kwenye picha - na kuuhifadhi humo](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
