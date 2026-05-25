# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG fajlovi** su veoma česti u **CTFs**, **incident response**, i **malware staging** zato što su **lossless**, **chunk-based**, i mnogi alati će ih rado renderovati čak i kada sadrže **dodatne metadata**, **appended payloads**, ili **partially corrupted chunks**.

Posmatrajte PNG kao **container**, a ne samo kao sliku.

## Quick triage

Počnite sa proverenama na nivou containera pre nego što pređete na LSB stego. Za bit-plane/LSB workflow, pogledajte [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Korisne stvari za traženje:

- **Neočekivani pomoćni chunkovi** kao što su `tEXt`, `zTXt`, `iTXt`, `eXIf` ili `iCCP`
- **CRC greške** ili neispravne dužine chunkova
- **Dodatni podaci posle `IEND`**
- **Više `IEND` markera** ili oporavljivi `IDAT` fragmenti posle formalnog kraja fajla
- Fajl koji je validan PNG **i** takođe izgleda kao ZIP/PDF/script kada se carve-uje

Zapamtite da je minimalna validna struktura obično:

- `IHDR` (mora biti prvi)
- `IDAT` (jedan ili više uzastopnih chunkova)
- `IEND` (mora biti poslednji)

## Trajni podaci posle `IEND`

Jedan od PNG artefakata sa najvećim signalom su **podaci dodatni posle finalnog `IEND` chunka**. Mnogi dekoderi ih ignorišu, što ih čini korisnim za:

- **Jednostavan stego / skriveni payload**
- **PNG polyglots**
- **Malware staging**
- **Obnavljanje starijih image podataka** iz buggy editora

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
Takođe pokušaj generic archive parsers direktno na PNG ili na carved trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style oporavak isečenih/redigovanih screenshotova

Veoma praktičan noviji PNG forenzički trik je da proverite da li je editor za screenshot **prepisao** PNG bez prethodnog **truncating** starog fajla. U tim slučajevima, bajtovi iz **prethodne slike** mogu ostati posle `IEND`, a ponekad se dodatni `IDAT` podaci mogu delimično rekonstruisati.

Ovo je postalo dobro poznato kroz **aCropalypse** (Google Pixel Markup) i sličan problem u **Windows Snipping Tool**. U praksi, ako "cropped" ili "redacted" PNG i dalje sadrži stare trailing podatke, možda ćete moći da oporavite deo originalnog screenshot-a.

Praktični workflow:
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

## Zloupotreba chunkova koja je bitna u praksi

Najzanimljiviji PNG chunkovi za istrage obično nisu očigledni image chunkovi, već chunkovi koji mogu da nose **text**, **metadata** ili **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata i komprimovani text
- `eXIf` – EXIF data unutar PNG
- `iCCP` – ugrađeni ICC profile
- `PLTE` – palette data u indexed images, ali i koristan u payload-smuggling scenarijima

Ispisati ih pomoću:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Za perzistenciju offensive payload unutar PNG chunkova (na primer **PLTE**, **IDAT**, ili **tEXt** trikovi koji preživljavaju neke PHP image transformacije), pogledajte detaljnije beleške fokusirane na upload ovde:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Za proveru integriteta i lociranje tačno oštećenog dela, **pngcheck** i dalje ostaje jedan od najboljih prvih alata:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Ako je fajl oštećen umesto namerno malicious, **PCRT** može biti koristan u CTFs i lab radu za popravljanje uobičajenih problema kao što su loši headers, pogrešne IHDR vrednosti, CRC problemi ili malformed chunk rasporedi.

Ako vam je cilj da **sanitize** PNG koji sadrži suspicious trailer data uz očuvanje vidljive slike, ExifTool može eksplicitno ukloniti trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Za osetljive dokaze, uvek radi na **kopiji** i čuvaj hash-eve originala pre pokušaja popravki.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
