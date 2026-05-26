# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** ni za kawaida sana katika **CTFs**, **incident response**, na **malware staging** kwa sababu ni **lossless**, **chunk-based**, na zana nyingi zitaonyesha kwa furaha hata zinapokuwa na **extra metadata**, **appended payloads**, au **partially corrupted chunks**.

Tazama PNG kama **container**, si tu kama picha.

## Quick triage

Anza na ukaguzi wa kiwango cha container kabla ya kurukia LSB stego. Kwa workflow ya bit-plane/LSB, angalia [ukurasa maalum wa image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Mambo muhimu ya kuangalia:

- **Unexpected ancillary chunks** kama `tEXt`, `zTXt`, `iTXt`, `eXIf`, au `iCCP`
- **CRC errors** au malformed chunk lengths
- **Additional data after `IEND`**
- **Multiple `IEND` markers** au recoverable `IDAT` fragments baada ya mwisho rasmi wa file
- File ambayo ni PNG halali **na** pia inaonekana kama ZIP/PDF/script wakati carved

Kumbuka muundo wa chini kabisa halali kawaida ni:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## Trailing data after `IEND`

Moja ya PNG artefacts zenye signal kubwa zaidi ni **data iliyoongezwa baada ya final `IEND` chunk**. Decoders nyingi huipuuza, jambo linaloifanya iwe muhimu kwa:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** kutoka kwa buggy editors

Quick detection:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Ikiwa unataka kukata kila kitu baada ya `IEND` ya mwisho:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Pia jaribu generic archive parsers moja kwa moja dhidi ya PNG au trailer iliyokatwa:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Urejeshaji wa mtindo wa Acropalypse wa picha za skrini zilizokatwa/kufichwa

Trick moja ya hivi karibuni na ya vitendo sana ya forensic ya PNG ni kuangalia kama screenshot editor **iliandika juu** ya PNG bila **ku-truncate** faili ya zamani kwanza. Katika hali kama hizo, bytes kutoka kwenye **picha ya awali** zinaweza kubaki baada ya `IEND`, na wakati mwingine data ya ziada ya `IDAT` inaweza kurekebishwa kwa sehemu.

Hili lilijulikana sana kupitia **aCropalypse** (Google Pixel Markup) na issue inayohusiana ya **Windows Snipping Tool**. Kwa vitendo, ikiwa PNG "iliyokatwa" au "iliyofichwa" bado ina old trailing data, unaweza kuweza kurejesha sehemu ya screenshot ya awali.

Workflow ya vitendo:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Dalili zinazothibitisha kwa nguvu uchambuzi wa kina:

- `pngcheck` inaonyesha **data ya ziada baada ya `IEND`**
- Unapata **zaidi ya moja ya `IEND`**
- Unapata **chunks za ziada za `IDAT`** baada ya kile kinachoonekana kama mwisho wa picha
- Screenshot ilitoka kwenye kifaa/editor kinachojulikana kuwa kimeathirika

Ikiwa hili linatokea, peleka faili kwenye **aCropalypse recovery tool** kabla ya kuchukulia redaction kuwa ya kuaminika.

## Chunk abuse that matters in practice

PNG chunks zinazovutia zaidi kwa uchunguzi mara nyingi si zile za wazi za picha, bali ni chunks zinazoweza kubeba **text**, **metadata**, au **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata na compressed text
- `eXIf` – EXIF data ndani ya PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data katika indexed images, lakini pia ni muhimu katika matukio ya payload-smuggling

Zidump kwa:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Kwa persistence ya offensive payload ndani ya PNG chunks (kwa mfano **PLTE**, **IDAT**, au **tEXt** tricks ambazo huendelea kuwepo baada ya baadhi ya PHP image transformations), angalia notes za kina zaidi zinazolenga uploads hapa:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Kwa kuangalia integrity na kutambua eneo haswa lililoharibika, **pngcheck** bado ni mojawapo ya tools bora za kwanza:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ikiwa file imeharibika badala ya kuwa intentionally malicious, **PCRT** inaweza kuwa useful katika CTFs na kazi za lab kwa kurekebisha issues za kawaida kama bad headers, wrong IHDR values, CRC problems, au malformed chunk layouts.

Ikiwa lengo lako ni **sanitize** PNG iliyo na suspicious trailer data huku ukihifadhi image inayoonekana, ExifTool inaweza kuondoa trailer kwa explicit:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Kwa ushahidi nyeti, daima fanya kazi kwenye **nakala** na hifadhi hashes za ya asili kabla ya kujaribu marekebisho.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
