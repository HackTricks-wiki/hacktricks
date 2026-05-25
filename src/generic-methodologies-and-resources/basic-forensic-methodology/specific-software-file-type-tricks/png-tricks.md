# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG-lêers** is baie algemeen in **CTFs**, **incident response**, en **malware staging** omdat hulle **lossless**, **chunk-based**, en baie nutsgoed sal hulle graag render selfs wanneer hulle **extra metadata**, **appended payloads**, of **partially corrupted chunks** bevat.

Behandel 'n PNG as 'n **container**, nie net as 'n beeld nie.

## Quick triage

Begin met container-vlak kontroles voordat jy na LSB stego spring. Vir die bit-plane/LSB workflow, kyk [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Nuttige goed om vir te kyk:

- **Onverwagte bykomende chunks** soos `tEXt`, `zTXt`, `iTXt`, `eXIf`, of `iCCP`
- **CRC-foute** of misvormde chunk-lengtes
- **Bykomende data ná `IEND`**
- **Veelvuldige `IEND`-merkers** of herstelbare `IDAT`-fragmente ná die formele einde van die lêer
- ’n Lêer wat ’n geldige PNG **is** en ook lyk soos ’n ZIP/PDF/script wanneer dit carved word

Onthou die minimum geldige struktuur is gewoonlik:

- `IHDR` (moet eerste wees)
- `IDAT` (een of meer opeenvolgende chunks)
- `IEND` (moet laaste wees)

## Naloopdata ná `IEND`

Een van die PNG-artefakte met die hoogste sein is **data wat ná die finale `IEND` chunk aangeheg is**. Baie decoders ignoreer dit, wat dit nuttig maak vir:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** van foutiewe editors

Vinnige opsporing:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
As jy alles ná die finale `IEND` wil uitsny:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Probeer ook generiese argiefparsers direk teen die PNG of die uitgekapte trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-styl herstel van afgekapte/geredigeerde screenshots

’n Baie praktiese onlangse PNG-forensiese truuk is om te kyk of ’n screenshot-editor ’n PNG **oor geskryf** het sonder om eers die ou lêer **af te sny**. In sulke gevalle kan bytes van die **vorige beeld** ná `IEND` oorbly, en soms kan ekstra `IDAT`-data gedeeltelik gerekonstrueer word.

Dit het goed bekend geword met **aCropalypse** (Google Pixel Markup) en die verwante **Windows Snipping Tool**-probleem. In die praktyk, as ’n "cropped" of "redacted" PNG steeds ou agterblywende data bevat, kan jy dalk ’n deel van die oorspronklike screenshot herstel.

Praktiese werkvloei:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Tekens wat sterk verder ontleding regverdig:

- `pngcheck` rapporteer **addisionele data na `IEND`**
- Jy vind **meer as een `IEND`**
- Jy vind **ekstra `IDAT` chunks** na die oënskynlike einde van die image
- Die skermskoot het gekom van 'n device/editor wat bekend is om geraak te wees

As dit gebeur, voer die file deur 'n **aCropalypse recovery tool** voordat jy die redaction as betroubaar beskou.

## Chunk abuse wat in die praktyk saak maak

Die interessantste PNG chunks vir investigations is gewoonlik nie die ooglopende image-een nie, maar die chunks wat **text**, **metadata**, of **payload bytes** kan dra:

- `tEXt` / `zTXt` / `iTXt` – text metadata en compressed text
- `eXIf` – EXIF data binne PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data in indexed images, maar ook nuttig in payload-smuggling scenarios

Dump hulle met:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Vir offenkiewe payload-persistentie binne PNG-chunks (byvoorbeeld **PLTE**, **IDAT**, of **tEXt** truuks wat sommige PHP-beeldtransformasies oorleef), kyk na die meer gedetailleerde upload-gefokusde notas hier:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Beskadigde PNG herstel

Vir die kontrolering van integriteit en die opspoor van die presiese gebreekte area, bly **pngcheck** een van die beste eerste tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

As die lêer beskadig is eerder as doelbewus kwaadwillig, kan **PCRT** nuttig wees in CTFs en labwerk om algemene probleme reg te stel soos slegte headers, verkeerde IHDR-waardes, CRC-probleme, of misvormde chunk-uitlegte.

As jou doel is om 'n PNG te **sanitize** wat verdagte trailer data bevat terwyl die sigbare beeld behoue bly, kan ExifTool die trailer eksplisiet verwyder:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Vir sensitiewe bewyse, werk altyd op ’n **kopie** en hou hashes van die oorspronklike voordat jy herstelpogings aanpak.

## Verwysings

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
