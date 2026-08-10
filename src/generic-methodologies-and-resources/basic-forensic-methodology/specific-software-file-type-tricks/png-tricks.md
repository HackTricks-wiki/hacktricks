# PNG trikovi

**PNG datoteke** su veoma česte u **CTF-ovima**, **incident response-u** i **malware staging-u** jer su **lossless**, zasnovane na **chunk-ovima**, a mnogi alati će ih bez problema prikazati čak i kada sadrže **dodatne metadata podatke**, **payload-e dodate na kraj datoteke** ili **delimično oštećene chunk-ove**.

Posmatrajte PNG kao **container**, a ne samo kao sliku.

## Brza trijaža

Počnite proverama na nivou container-a pre nego što pređete na LSB stego. Za workflow sa bit-plane/LSB proverite [posvećenu stranicu o image stego tehnikama](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Korisne stvari na koje treba obratiti pažnju:

- **Neočekivani pomoćni chunk-ovi** kao što su `tEXt`, `zTXt`, `iTXt`, `eXIf` ili `iCCP`
- **CRC greške** ili neispravne dužine chunk-ova
- **Dodatni podaci nakon `IEND`**
- **Višestruki `IEND` markeri** ili fragmenti `IDAT` koji mogu da se oporave nakon formalnog kraja datoteke
- Datoteka koja je validan PNG **i** istovremeno izgleda kao ZIP/PDF/script kada se izdvoji

Zapamtite da je minimalna validna struktura obično:

- `IHDR` (mora biti prvi)
- `IDAT` (jedan ili više uzastopnih chunk-ova)
- `IEND` (mora biti poslednji)

## Podaci nakon `IEND`

Jedan od artefakata PNG-a sa najviše indikatora je **dodavanje podataka nakon poslednjeg `IEND` chunk-a**. Mnogi dekoderi ih ignorišu, što ih čini korisnim za:

- **Simple stego / skrivene payload-e**
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
Takođe direktno testirajte generičke parserе arhiva na PNG-u ili izdvojenom završnom delu:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Oporavak u stilu Acropalypse iz isečenih/cenzurisanih snimaka ekrana

Veoma praktičan noviji PNG forenzički trik jeste provera da li je editor snimaka ekrana **prepisao** PNG bez prethodnog **skraćivanja** stare datoteke. U tim slučajevima bajtovi iz **prethodne slike** mogu ostati nakon `IEND`, a ponekad se dodatni `IDAT` podaci mogu delimično rekonstruisati.

Ovo je postalo dobro poznato kroz **aCropalypse** (Google Pixel Markup) i povezani problem sa **Windows Snipping Tool**.<sup>[[3]](#references)</sup> U praksi, ako "isečeni" ili "cenzurisani" PNG i dalje sadrži stare podatke na kraju datoteke, možda ćete moći da oporavite deo originalnog snimka ekrana.<sup>[[1]](#references)</sup>

Praktični tok rada:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Znakovi koji snažno opravdavaju dublju analizu:

- `pngcheck` prijavljuje **additional data after `IEND`**
- Pronađete **više od jednog `IEND`**
- Pronađete **dodatne `IDAT` chunks** nakon prividnog kraja slike
- Screenshot potiče sa uređaja/editor-a za koji se zna da je bio pogođen

Ako se to dogodi, prosledite fajl **aCropalypse recovery tool-u** pre nego što zamagljivanje smatrate pouzdanim.

## Zloupotreba chunk-ova koja je praktično važna

Najzanimljiviji PNG chunks za istrage obično nisu očigledni image chunks, već chunks koji mogu sadržati **text**, **metadata** ili **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata i compressed text
- `eXIf` – EXIF data unutar PNG-a
- `iCCP` – embedded ICC profile
- `PLTE` – palette data u indexed images, ali i korisno u payload-smuggling scenarijima.<sup>[[2]](#references)</sup>

Izdvojite ih pomoću:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Za persistence ofanzivnog payload-a unutar PNG chunks (na primer trikovi sa **PLTE**, **IDAT** ili **tEXt** koji opstaju nakon nekih PHP transformacija slika), pogledajte detaljnije beleške usmerene na upload ovde:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Popravka oštećenog PNG-a

Za proveru integriteta i pronalaženje tačne oštećene oblasti, **pngcheck** je i dalje jedan od najboljih alata za početnu proveru:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ako je fajl oštećen, a ne namerno zlonameran, **PCRT** može biti koristan u CTF-ovima i laboratorijskom radu za popravljanje uobičajenih problema, kao što su neispravna zaglavlja, pogrešne IHDR vrednosti, CRC problemi ili neispravno formatirani chunk-ovi.

Ako je vaš cilj da **sanitizujete** PNG koji sadrži sumnjive trailer podatke, uz očuvanje vidljive slike, ExifTool može eksplicitno ukloniti trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Za osetljive dokaze uvek radite na **kopiji** i sačuvajte hash vrednosti originala pre pokušaja popravke.

## References

- [1] [Exploiting aCropalypse: Oporavak skraćenih PNG-ova](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: Kako ubaciti PHP kod u sliku – i zadržati ga u njoj](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
