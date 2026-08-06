# PNG trikovi

{{#include ../../../banners/hacktricks-training.md}}

**PNG datoteke** su veoma česte u **CTF-ovima**, **incident response-u** i **malware staging-u** zato što su **bez gubitka**, **zasnovane na chunk-ovima**, a mnogi alati će ih bez problema prikazati čak i kada sadrže **dodatne metapodatke**, **dodatne payload-e** ili **delimično oštećene chunk-ove**.

Posmatrajte PNG kao **kontejner**, a ne samo kao sliku.

## Brza trijaža

Počnite proverama na nivou kontejnera pre nego što pređete na LSB stego. Za workflow sa bit-plane/LSB tehnikom pogledajte [posebnu stranicu o image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Korisne stvari koje treba tražiti:

- **Neočekivani pomoćni chunk-ovi** kao što su `tEXt`, `zTXt`, `iTXt`, `eXIf` ili `iCCP`
- **CRC greške** ili neispravne dužine chunk-ova
- **Dodatni podaci nakon `IEND`**
- **Višestruke oznake `IEND`** ili fragmenti `IDAT` koji mogu da se oporave nakon formalnog kraja datoteke
- Datoteka koja je validan PNG **i** istovremeno izgleda kao ZIP/PDF/script kada se izvrši carving

Imajte na umu da je minimalna validna struktura obično:

- `IHDR` (mora biti prvi)
- `IDAT` (jedan ili više uzastopnih chunk-ova)
- `IEND` (mora biti poslednji)

## Podaci nakon `IEND`

Jedan od artefakata PNG-a sa najviše indikatora je **dodavanje podataka nakon poslednjeg `IEND` chunk-a**. Mnogi decoder-i ih ignorišu, što ih čini korisnim za:

- **Jednostavan stego / skrivene payload-e**
- **PNG polyglots**
- **Malware staging**
- **Oporavak starijih podataka slike** iz neispravnih editora

Brza detekcija:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Ako želite da izdvojite sve nakon poslednjeg `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Takođe direktno isprobajte generičke parsere arhiva na PNG datoteci ili izdvojenom traileru:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Oporavak u stilu Acropalypse-a isečenih/redigovanih screenshotova

Veoma praktičan noviji PNG forenzički trik jeste provera da li je editor screenshotova **prepisao** PNG bez prethodnog **skraćivanja** starog fajla. U tim slučajevima, bajtovi iz **prethodne slike** mogu ostati nakon `IEND`, a ponekad se dodatni `IDAT` podaci mogu delimično rekonstruisati.

Ovo je postalo poznato zahvaljujući **aCropalypse** (Google Pixel Markup) i povezanom problemu u alatu **Windows Snipping Tool**. U praksi, ako "isečeni" ili "redigovani" PNG i dalje sadrži stare podatke na kraju, možda ćete moći da oporavite deo originalnog screenshota.<sup>[[1]](#references)</sup>

Praktičan tok rada:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Znakovi koji snažno opravdavaju dublju analizu:

- `pngcheck` prijavljuje **additional data after `IEND`**
- Pronađete **više od jednog `IEND`**
- Pronađete **dodatne `IDAT` chunk-ove** nakon prividnog kraja slike
- Screenshot potiče sa uređaja/editora za koji je poznato da je bio pogođen

Ako se ovo desi, prosledite fajl **aCropalypse recovery tool** alatu pre nego što redakciju smatrate pouzdanom.

## Zloupotreba chunk-ova koja je važna u praksi

Najzanimljiviji PNG chunk-ovi za istrage obično nisu očigledni image chunk-ovi, već chunk-ovi koji mogu sadržati **tekst**, **metadata** ili **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata i compressed text
- `eXIf` – EXIF data unutar PNG-a
- `iCCP` – embedded ICC profile
- `PLTE` – palette data u indexed image-ovima, ali i korisno u scenarijima payload-smuggling-a<sup>[[2]](#references)</sup>

Ispišite ih pomoću:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Za persistence offensive payload-a unutar PNG chunk-ova (na primer trikovi sa **PLTE**, **IDAT** ili **tEXt** koji opstaju nakon nekih PHP transformacija slika), pogledajte detaljnije beleške usmerene na upload ovde<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Popravka oštećenog PNG-a

Za proveru integriteta i pronalaženje tačne oštećene oblasti, **pngcheck** je i dalje jedan od najboljih prvih alata:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ako je fajl oštećen, a ne namerno zlonameran, **PCRT** može biti koristan u CTF-ovima i laboratorijskom radu za popravljanje uobičajenih problema, kao što su neispravni header-i, pogrešne IHDR vrednosti, CRC problemi ili neispravni rasporedi chunk-ova.

Ako je vaš cilj da **sanitizujete** PNG koji sadrži sumnjive trailer podatke uz očuvanje vidljive slike, ExifTool može eksplicitno ukloniti trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Za osetljive dokaze uvek radite na **kopiji** i sačuvajte hash vrednosti originala pre pokušaja popravke.

## Reference

- [1] [Exploiting aCropalypse: Recovering Truncated PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: How to inject PHP code in an image – and keep it there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
