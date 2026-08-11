# PNG-truuks

{{#include ../../../banners/hacktricks-training.md}}

**PNG-lêers** is baie algemeen in **CTF's**, **voorvalreaksie** en **malware staging** omdat hulle **verliesloos**, **brokkie-gebaseerd** is, en baie nutsprogramme hulle sonder probleme sal weergee selfs wanneer hulle **ekstra metadata**, **aangehegte payloads** of **gedeeltelik beskadigde brokkies** bevat.

Behandel 'n PNG as 'n **container**, nie net as 'n prent nie.

## Vinnige triage

Begin met kontroles op containervlak voordat jy na LSB-steganografie oorgaan. Vir die bit-plane/LSB-werkvloei, kyk na [die toegewyde beeld-stego-bladsy](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Nuttige dinge om na te kyk:

- **Onverwagte aanvullende chunks** soos `tEXt`, `zTXt`, `iTXt`, `eXIf` of `iCCP`
- **CRC-foute** of verkeerd gevormde chunk-lengtes
- **Bykomende data ná `IEND`**
- **Veelvuldige `IEND`-merkers** of herstelbare `IDAT`-fragmente ná die formele einde van die lêer
- ’n Lêer wat ’n geldige PNG is **en** ook soos ’n ZIP/PDF/script lyk wanneer dit gecarve word

Onthou, die minimum geldige struktuur is gewoonlik:

- `IHDR` (moet eerste wees)
- `IDAT` (een of meer opeenvolgende chunks)
- `IEND` (moet laaste wees)

## Data ná `IEND`

Een van die artefakte met die hoogste seinwaarde in PNG’s is **data wat ná die finale `IEND`-chunk aangeheg is**. Baie decoders ignoreer dit, wat dit nuttig maak vir:

- **Eenvoudige stego / versteekte payloads**
- **PNG-polyglots**
- **Malware staging**
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
Probeer ook generiese argief-ontleders direk op die PNG of die uitgekerfde trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Herwinning in Acropalypse-styl van geknipte/gemaskeerde skermkiekies

’n Baie praktiese onlangse PNG-forensiese truuk is om te kontroleer of ’n skermkiekie-redigeerder ’n PNG **oorgeskryf** het sonder om eers die ou lêer **af te kap**. In sulke gevalle kan grepe van die **vorige beeld** ná `IEND` oorbly, en soms kan ekstra `IDAT`-data gedeeltelik gerekonstrueer word.

Dit het goed bekend geword met **aCropalypse** (Google Pixel Markup) en die verwante **Windows Snipping Tool**-kwessie.<sup>[[3]](#references)</sup> In die praktyk, as ’n "geknipte" of "gemaskeerde" PNG steeds ou data aan die einde bevat, kan jy moontlik ’n gedeelte van die oorspronklike skermkiekie herwin.<sup>[[1]](#references)</sup>

Praktiese werkvloei:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Tekens wat verdere ontleding sterk regverdig:

- `pngcheck` rapporteer **additional data after `IEND`**
- Jy vind **meer as een `IEND`**
- Jy vind **ekstra `IDAT`-chunks** ná die skynbare einde van die image
- Die screenshot kom van ’n device/editor waarvan bekend is dat dit geraak is

As dit gebeur, voer die lêer deur ’n **aCropalypse recovery tool** voordat jy die redigering as betroubaar beskou.

## Misbruik van chunks wat in die praktyk saak maak

Die interessantste PNG-chunks vir ondersoeke is gewoonlik nie die ooglopende image-chunks nie, maar die chunks wat **teks**, **metadata** of **payload bytes** kan bevat:

- `tEXt` / `zTXt` / `iTXt` – teksmetadata en compressed text
- `eXIf` – EXIF-data binne PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data in indexed images, maar ook nuttig in payload-smuggling-scenario’s.<sup>[[2]](#references)</sup>

Dump hulle met:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Vir offensiewe payload-volharding binne PNG-chunks (byvoorbeeld **PLTE**-, **IDAT**- of **tEXt**-tegnieke wat sommige PHP-beeldtransformasies oorleef), kyk na die meer gedetailleerde, oplaaigefokusde notas hier:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Beskadigde PNG-herstel

Vir die kontrolering van integriteit en om die presiese beskadigde area op te spoor, bly **pngcheck** een van die beste eerste nutsmiddels:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

As die lêer beskadig eerder as opsetlik kwaadwillig is, kan **PCRT** nuttig wees in CTFs en laboratoriumwerk om algemene probleme reg te stel, soos foutiewe headers, verkeerde IHDR-waardes, CRC-probleme of misvormde chunk-uitlegte.

As jou doel is om ’n PNG wat verdagte trailer-data bevat te **sanitiseer** terwyl die sigbare beeld behoue bly, kan ExifTool die trailer uitdruklik verwyder:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Vir sensitiewe bewysmateriaal, werk altyd op ’n **kopie** en hou hashes van die oorspronklike voordat jy herstelwerk probeer doen.

## References

- [1] [Ontginning van aCropalypse: Herstel van afgesnyde PNG’s](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Volgehoue PHP payloads in PNG’s: Hoe om PHP-kode in ’n beeld in te spuit – en dit daar te hou](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
