# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG-lêers** is baie algemeen in **CTFs**, **incident response**, en **malware staging** omdat hulle **verliesloos** is, **chunk-gebaseer** is, en baie tools hulle geredelik sal render selfs wanneer hulle **ekstra metadata**, **aangehegte payloads**, of **gedeeltelik korrupte chunks** bevat.

Behandel ’n PNG as ’n **houer**, nie net as ’n beeld nie.

## Quick triage

Begin met kontrole op houer-vlak voordat jy na LSB stego spring. Vir die bit-plane/LSB-workflow, kyk [die toegewyde image stego-bladsy](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Nuttige dinge om na te soek:

- **Onverwagte bykomende chunks** soos `tEXt`, `zTXt`, `iTXt`, `eXIf`, of `iCCP`
- **CRC-foute** of misvormde chunk-lengtes
- **Bykomende data ná `IEND`**
- **Veelvuldige `IEND`-merkers** of herstelbare `IDAT`-fragmente ná die formele einde van die lêer
- ’n Lêer wat ’n geldige PNG **en** ook soos ’n ZIP/PDF/script lyk wanneer dit uitgehaal word

Onthou die minimum geldige struktuur is gewoonlik:

- `IHDR` (moet eerste wees)
- `IDAT` (een of meer opeenvolgende chunks)
- `IEND` (moet laaste wees)

## Nasporende data ná `IEND`

Een van die PNG-artefakte met die hoogste sein is **data wat ná die finale `IEND`-chunk aangeheg is**. Baie dekodeerders ignoreer dit, wat dit nuttig maak vir:

- **Eenvoudige stego / verborge payloads**
- **PNG-polyglots**
- **Malware-staging**
- **Herwinning van ouer beelddata** uit foutiewe redigeerders

Vinnige opsporing:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
As jy alles ná die finale `IEND` wil uitkap:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Probeer ook generiese argief-ontleders direk teen die PNG of die uitgekapte trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style herstel van cropped/redacted screenshots

'n Baie praktiese onlangse PNG-forensiese truuk is om te kyk of 'n screenshot-editor 'n PNG **oorgeskryf** het sonder om eers die ou lêer **af te truncate**. In daardie gevalle kan bytes van die **vorige image** ná `IEND` oorbly, en soms kan ekstra `IDAT` data gedeeltelik gerekonstrueer word.

Dit het bekend geword met **aCropalypse** (Google Pixel Markup) en die verwante **Windows Snipping Tool**-issue. In die praktyk, as 'n "cropped" of "redacted" PNG steeds ou sleepdata bevat, kan jy dalk 'n deel van die oorspronklike screenshot herstel.

Praktiese workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Tekens wat sterk ’n dieper analise regverdig:

- `pngcheck` rapporteer **bykomende data na `IEND`**
- Jy vind **meer as een `IEND`**
- Jy vind **ekstra `IDAT` chunks** ná die skynbare einde van die beeld
- Die skermgreep het gekom van ’n toestel/editor wat bekend is dat dit geraak is

As dit gebeur, voer die lêer deur ’n **aCropalypse recovery tool** voordat jy die redaksie as betroubaar beskou.

## Chunk abuse that matters in practice

Die interessantste PNG chunks vir ondersoeke is gewoonlik nie die voor die hand liggende beeld-ones nie, maar die chunks wat **text**, **metadata**, of **payload bytes** kan dra:

- `tEXt` / `zTXt` / `iTXt` – text metadata en compressed text
- `eXIf` – EXIF data inside PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data in indexed images, but also useful in payload-smuggling scenarios

Dump them with:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Vir offansiewe payload-persistensie binne PNG-chunks (byvoorbeeld **PLTE**, **IDAT**, of **tEXt** truuks wat sommige PHP-beeldtransformasies oorleef), kyk na die meer gedetailleerde upload-gefokusde notas hier:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Gekorrupteerde PNG-herstel

Vir die kontrole van integriteit en die opspoor van die presiese stukkende area, bly **pngcheck** een van die beste eerste tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

As die lêer beskadig is eerder as doelbewus kwaadwillig, kan **PCRT** nuttig wees in CTFs en labwerk om algemene probleme soos slegte headers, verkeerde IHDR-waardes, CRC-probleme, of misvormde chunk-uitlegte reg te maak.

As jou doel is om ’n PNG te **sanitiseer** wat verdagte trailer-data bevat terwyl die sigbare beeld behoue bly, kan ExifTool die trailer eksplisiet verwyder:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Vir sensitiewe bewyse, werk altyd op ’n **kopie** en hou hashes van die oorspronklike voordat jy probeer herstel.

## Verwysings

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
