# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG-lêers** is baie algemeen in **CTFs**, **incident response**, en **malware staging** omdat hulle **verliesloos**, **chunk-gebaseerd** is, en baie tools hulle maklik sal render selfs wanneer hulle **ekstra metadata**, **aangehegte payloads**, of **gedeeltelik beskadigde chunks** bevat.

Behandel ’n PNG as ’n **container**, nie net as ’n prent nie.

## Vinnige triage

Begin met checks op containervlak voordat jy met LSB stego begin. Vir die bit-plane/LSB-workflow, kyk na [die toegewyde beeld-stego-bladsy](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Nuttige dinge om na te soek:

- **Onverwagte ancillary chunks** soos `tEXt`, `zTXt`, `iTXt`, `eXIf`, of `iCCP`
- **CRC-foute** of verkeerd gevormde chunk-lengtes
- **Bykomende data ná `IEND`**
- **Veelvuldige `IEND`-merkers** of herstelbare `IDAT`-fragmente ná die formele einde van die lêer
- ’n Lêer wat ’n geldige PNG is **en** ook soos ’n ZIP/PDF/script lyk wanneer dit ge-carve word

Onthou, die minimum geldige struktuur is gewoonlik:

- `IHDR` (moet eerste wees)
- `IDAT` (een of meer opeenvolgende chunks)
- `IEND` (moet laaste wees)

## Data ná `IEND`

Een van die duidelikste PNG-artefakte is **data wat ná die finale `IEND`-chunk aangeheg is**. Baie decoders ignoreer dit, wat dit nuttig maak vir:

- **Eenvoudige stego / versteekte payloads**
- **PNG-polyglots**
- **Malware-staging**
- **Herwinning van ouer beelddata** uit foutiewe editors

Vinnige opsporing:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
As jy alles ná die finale `IEND` wil carve:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Probeer ook generiese argiefparsers direk teen die PNG of die uitgekerfde sleepstuk:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Herstel in die styl van Acropalypse van gesnyde/gemaskeerde skermskote

’n Baie praktiese onlangse PNG-forensiese tegniek is om te kontroleer of ’n skermskootredigeerder ’n PNG **oorgeskryf** het sonder om eers die ou lêer te **truncaat**. In daardie gevalle kan grepe van die **vorige prent** ná `IEND` oorbly, en soms kan bykomende `IDAT`-data gedeeltelik gerekonstrueer word.

Dit het bekend geword met **aCropalypse** (Google Pixel Markup) en die verwante probleem met die **Windows Snipping Tool**. In die praktyk, indien ’n "gesnyde" of "gemaskeerde" PNG steeds ou data aan die einde bevat, kan jy moontlik ’n gedeelte van die oorspronklike skermskoot herstel.<sup>[[1]](#references)</sup>

Praktiese werkvloei:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Tekens wat diepgaande ontleding sterk regverdig:

- `pngcheck` rapporteer **bykomende data ná `IEND`**
- Jy vind **meer as een `IEND`**
- Jy vind **ekstra `IDAT`-chunks** ná die skynbare einde van die image
- Die screenshot kom van ’n device/editor waarvan bekend is dat dit geraak is

As dit gebeur, voer die file deur ’n **aCropalypse recovery tool** voordat jy die redaksie as betroubaar beskou.

## Chunk abuse wat in die praktyk belangrik is

Die interessantste PNG-chunks vir ondersoeke is gewoonlik nie die ooglopende image-chunks nie, maar die chunks wat **teks**, **metadata** of **payload bytes** kan bevat:

- `tEXt` / `zTXt` / `iTXt` – teksmetadata en compressed text
- `eXIf` – EXIF-data binne PNG
- `iCCP` – ingebedde ICC-profile
- `PLTE` – palette data in indexed images, maar ook nuttig in payload-smuggling scenarios<sup>[[2]](#references)</sup>

Dump hulle met:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Vir offensive payload persistence binne PNG chunks (byvoorbeeld **PLTE**, **IDAT** of **tEXt** tricks wat sommige PHP-beeldtransformasies oorleef), raadpleeg die meer gedetailleerde oplaaigerigte notas hier<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Herstel van korrupte PNG's

Vir die nagaan van integriteit en die opspoor van die presiese beskadigde area bly **pngcheck** een van die beste eerste tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

As die lêer beskadig eerder as opsetlik kwaadwillig is, kan **PCRT** nuttig wees in CTF's en laboratoriumwerk om algemene probleme reg te stel, soos foutiewe headers, verkeerde IHDR-waardes, CRC-probleme of verkeerd gevormde chunk-uitlegte.

As jou doel is om 'n PNG wat verdagte trailer-data bevat te **suiwer** terwyl die sigbare beeld behoue bly, kan ExifTool die trailer uitdruklik verwyder:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Vir sensitiewe bewysmateriaal, werk altyd op ’n **kopie** en hou hashes van die oorspronklike voordat jy herstelwerk probeer doen.

## References

- [1] [Exploiting aCropalypse: Recovering Truncated PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: How to inject PHP code in an image – and keep it there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
