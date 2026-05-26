# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG fajlovi** su veoma česti u **CTF-ovima**, **incident response**, i **malware staging** jer su **lossless**, **chunk-based**, i mnogi alati će ih bez problema prikazati čak i kada sadrže **extra metadata**, **appended payloads**, ili **partially corrupted chunks**.

Tretiraj PNG kao **container**, a ne samo kao sliku.

## Brza trijaža

Kreni sa proverama na nivou containera pre nego što pređeš na LSB stego. Za bit-plane/LSB workflow, pogledaj [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Korisne stvari za traženje:

- **Neočekivani pomoćni chunk-ovi** kao što su `tEXt`, `zTXt`, `iTXt`, `eXIf`, ili `iCCP`
- **CRC greške** ili nepravilne dužine chunk-ova
- **Dodatni podaci posle `IEND`**
- **Više `IEND` markera** ili oporavljivi `IDAT` fragmenti nakon formalnog kraja fajla
- Fajl koji je važeći PNG **i** takođe izgleda kao ZIP/PDF/script kada se carve-uje

Zapamtite da je minimalna važeća struktura obično:

- `IHDR` (mora biti prvi)
- `IDAT` (jedan ili više uzastopnih chunk-ova)
- `IEND` (mora biti poslednji)

## Trailing data posle `IEND`

Jedan od PNG artefakata sa najjačim signalom je **data appendovana posle finalnog `IEND` chunk-a**. Mnogi dekoderi je ignorišu, što je čini korisnom za:

- **Jednostavan stego / skriveni payload**
- **PNG polyglots**
- **Staging malware-a**
- **Oporavak starijih image data** iz buggy editor-a

Brza detekcija:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Ako želite da izdvojite sve nakon završnog `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Takođe pokušajte generic archive parsers direktno nad PNG ili carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style recovery of cropped/redacted screenshots

Veoma praktičan noviji PNG forenzički trik je proveriti da li je editor za screenshotove **prepisao** PNG bez prethodnog **trunkovanja** starog fajla. U tim slučajevima, bajtovi iz **prethodne slike** mogu ostati posle `IEND`, a ponekad se dodatni `IDAT` podaci mogu delimično rekonstruisati.

Ovo je postalo dobro poznato sa **aCropalypse** (Google Pixel Markup) i povezanim problemom sa **Windows Snipping Tool**. U praksi, ako „cropped“ ili „redacted“ PNG i dalje sadrži stare završne podatke, možda ćete moći da oporavite deo originalnog screenshot-a.

Praktičan workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Znaci koji snažno opravdavaju dublju analizu:

- `pngcheck` prijavljuje **dodatne podatke posle `IEND`**
- Nađete **više od jednog `IEND`**
- Nađete **dodatne `IDAT` chunkove** posle prividnog kraja slike
- Screenshot je došao sa uređaja/editora za koji je poznato da je bio pogođen

Ako se ovo desi, prosledite fajl u **aCropalypse recovery tool** pre nego što redakciju smatrate pouzdanom.

## Chunk abuse koji je bitan u praksi

Najzanimljiviji PNG chunkovi za istrage obično nisu očigledni image chunkovi, već chunkovi koji mogu da nose **text**, **metadata**, ili **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata i komprimovani text
- `eXIf` – EXIF data unutar PNG
- `iCCP` – ugrađeni ICC profile
- `PLTE` – palette data u indexed images, ali i korisno u payload-smuggling scenarijima

Ispraznite ih pomoću:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Za upornu prisutnost offensive payload-a unutar PNG chunk-ova (na primer **PLTE**, **IDAT**, ili **tEXt** trikovi koji prežive neke PHP transformacije slika), pogledajte detaljnije beleške fokusirane na upload ovde:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Popravka oštećenog PNG-a

Za proveru integriteta i lociranje tačne oštećene oblasti, **pngcheck** ostaje jedan od najboljih prvih alata:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ako je fajl oštećen umesto namerno maliciozan, **PCRT** može biti koristan u CTF-ovima i lab vežbama za popravljanje uobičajenih problema kao što su loši headeri, pogrešne IHDR vrednosti, CRC problemi ili neispravni chunk layout-i.

Ako vam je cilj da **sanitizujete** PNG koji sadrži sumnjive trailer podatke, a da pritom sačuvate vidljivu sliku, ExifTool može eksplicitno ukloniti trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Za osetljive dokaze, uvek radi na **kopiji** i čuvaj hash-eve originala pre nego što pokušaš popravke.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
