# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** su veoma česti u **CTFs**, **incident response** i **malware staging** okruženjima zato što su **lossless**, zasnovani na **chunk** strukturi i zato što će ih mnogi alati bez problema prikazati čak i kada sadrže **dodatne metapodatke**, **appended payloads** ili **delimično oštećene chunk-ove**.

Posmatrajte PNG kao **kontejner**, a ne samo kao sliku.

## Brza trijaža

Počnite proverama na nivou kontejnera pre nego što pređete na LSB stego. Za workflow sa bit-plane/LSB tehnikom pogledajte [posebnu stranicu za image stego](../../../stego/images/README.md).
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
- **Više `IEND` markera** ili fragmenti `IDAT` koji se mogu oporaviti nakon formalnog kraja datoteke
- Datoteka koja je validan PNG **i** istovremeno izgleda kao ZIP/PDF/script kada se izvrši carving

Zapamtite da je minimalna validna struktura obično:

- `IHDR` (mora biti prvi)
- `IDAT` (jedan ili više uzastopnih chunk-ova)
- `IEND` (mora biti poslednji)

## Podaci nakon `IEND`

Jedan od artefakata PNG-a sa najviše indikatora je **dodavanje podataka nakon poslednjeg `IEND` chunk-a**. Mnogi decoder-i ih ignorišu, što ih čini korisnim za:

- **Jednostavan stego / skrivene payload-e**
- **PNG polyglots**
- **Malware staging**
- **Oporavak starijih podataka slike** iz editor-a sa greškama

Brza detekcija:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Ako želite da izdvojite sve nakon konačnog `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Takođe direktno pokrenite generičke parser-e arhiva nad PNG datotekom ili izdvojenim završnim delom:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Oporavak u stilu Acropalypse-a iz isečenih/redigovanih snimaka ekrana

Veoma praktičan noviji PNG forenzički trik jeste provera da li je editor snimaka ekrana **prepisao** PNG bez prethodnog **skraćivanja** starog fajla. U tim slučajevima bajtovi iz **prethodne slike** mogu ostati nakon `IEND`, a ponekad se dodatni `IDAT` podaci mogu delimično rekonstruisati.

Ovo je postalo dobro poznato zahvaljujući alatu **aCropalypse** (Google Pixel Markup) i povezanom problemu u alatu **Windows Snipping Tool**.<sup>[[3]](#references)</sup> U praksi, ako "isečeni" ili "redigovani" PNG i dalje sadrži stare podatke na kraju fajla, možda ćete moći da povratite deo originalnog snimka ekrana.<sup>[[1]](#references)</sup>

Praktični tok rada:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Znaci koji snažno opravdavaju dublju analizu:

- `pngcheck` prijavljuje **dodatne podatke nakon `IEND`**
- Pronađeno je **više od jednog `IEND`**
- Pronađeni su **dodatni `IDAT` chunk-ovi** nakon prividnog kraja slike
- Screenshot potiče sa uređaja/editor-a za koji se zna da je bio pogođen

Ako se to dogodi, prosledite fajl **aCropalypse recovery tool-u** pre nego što redakciju smatrate pouzdanom.

## Zloupotreba chunk-ova koja je važna u praksi

Najzanimljiviji PNG chunk-ovi za istrage obično nisu očigledni image chunk-ovi, već chunk-ovi koji mogu da sadrže **tekst**, **metadata** ili **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata i compressed text
- `eXIf` – EXIF data unutar PNG-a
- `iCCP` – ugrađeni ICC profile
- `PLTE` – palette data u indexed images, ali i korisno u scenarijima payload-smuggling-a.<sup>[[2]](#references)</sup>

Izbacite ih pomoću:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Za persistence ofanzivnih payload-a unutar PNG chunk-ova (na primer trikovi sa **PLTE**, **IDAT** ili **tEXt** koji opstaju nakon nekih PHP transformacija slika), pogledajte detaljnije beleške usmerene na upload ovde:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Popravka oštećenih PNG datoteka

Za proveru integriteta i pronalaženje tačne oštećene oblasti, **pngcheck** je i dalje jedan od najboljih alata za početnu proveru:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ako je datoteka oštećena, a ne namerno maliciozna, **PCRT** može biti koristan u CTF-ovima i laboratorijskom radu za popravljanje uobičajenih problema, kao što su neispravna zaglavlja, pogrešne IHDR vrednosti, CRC problemi ili neispravan raspored chunk-ova.

Ako je vaš cilj da **sanitizujete** PNG koji sadrži sumnjive trailer podatke uz očuvanje vidljive slike, ExifTool može eksplicitno ukloniti trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Za osetljive dokaze uvek radite na **kopiji** i sačuvajte hash vrednosti originala pre pokušaja popravke.

## References

- [1] [Exploiting aCropalypse: Oporavak skraćenih PNG-ova](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: Kako ubaciti PHP kod u sliku – i zadržati ga u njoj](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
