# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** sind sehr häufig in **CTFs**, **incident response** und **malware staging**, weil sie **verlustfrei**, **chunk-basiert** sind und viele Tools sie problemlos rendern, selbst wenn sie **zusätzliche metadata**, **appended payloads** oder **teilweise beschädigte chunks** enthalten.

Behandle ein PNG als **container**, nicht nur als Bild.

## Quick triage

Beginne mit Prüfungen auf Container-Ebene, bevor du zu LSB stego gehst. Für den bit-plane/LSB-Workflow siehe [die dedizierte image stego-Seite](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Nützliche Dinge, nach denen man suchen sollte:

- **Unerwartete zusätzliche Chunks** wie `tEXt`, `zTXt`, `iTXt`, `eXIf` oder `iCCP`
- **CRC-Fehler** oder fehlerhafte Chunk-Längen
- **Zusätzliche Daten nach `IEND`**
- **Mehrere `IEND`-Marker** oder wiederherstellbare `IDAT`-Fragmente nach dem formalen Dateiende
- Eine Datei, die ein gültiges PNG **und** außerdem wie ein ZIP/PDF/Script beim Carving aussieht

Denk daran, die minimale gültige Struktur ist normalerweise:

- `IHDR` (muss zuerst kommen)
- `IDAT` (ein oder mehrere aufeinanderfolgende Chunks)
- `IEND` (muss zuletzt kommen)

## Zusätzliche Daten nach `IEND`

Eines der PNG-Artefakte mit dem höchsten Signal ist **an den finalen `IEND`-Chunk angehängte Daten**. Viele Decoder ignorieren sie, was sie nützlich macht für:

- **Einfaches Stego / versteckte Payloads**
- **PNG-Polyglots**
- **Malware-Staging**
- **Wiederherstellen älterer Bilddaten** aus fehlerhaften Editoren

Schnelle Erkennung:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Wenn du alles nach dem letzten `IEND` ausschneiden willst:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Versuche auch generische Archiv-Parser direkt gegen die PNG oder den herausgelösten Trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style Wiederherstellung von beschnittenen/redigierten Screenshots

Ein sehr praktischer aktueller PNG-Forensik-Trick ist zu prüfen, ob ein Screenshot-Editor eine PNG **überschrieben** hat, ohne die alte Datei zuerst zu **truncaten**. In solchen Fällen können Bytes vom **vorherigen Bild** nach `IEND` verbleiben, und manchmal können zusätzliche `IDAT`-Daten teilweise rekonstruiert werden.

Das wurde mit **aCropalypse** (Google Pixel Markup) und dem verwandten Problem des **Windows Snipping Tool** bekannt. In der Praxis kannst du, wenn eine "beschnittene" oder "redigierte" PNG noch alte nachfolgende Daten enthält, möglicherweise einen Teil des ursprünglichen Screenshots wiederherstellen.

Praktischer Workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Anzeichen, die eine tiefere Analyse stark rechtfertigen:

- `pngcheck` meldet **zusätzliche Daten nach `IEND`**
- Du findest **mehr als ein `IEND`**
- Du findest **zusätzliche `IDAT` chunks** nach dem scheinbaren Ende des Bildes
- Der Screenshot stammt von einem Gerät/Editor, von dem bekannt ist, dass es betroffen war

Wenn das passiert, gib die Datei an ein **aCropalypse recovery tool** weiter, bevor du die Redaction als vertrauenswürdig behandelst.

## Chunk abuse, der in der Praxis relevant ist

Die interessantesten PNG chunks für Untersuchungen sind meist nicht die offensichtlichen Bild-Chunks, sondern die Chunks, die **Text**, **Metadaten** oder **payload bytes** enthalten können:

- `tEXt` / `zTXt` / `iTXt` – Text-Metadaten und komprimierter Text
- `eXIf` – EXIF-Daten in PNG
- `iCCP` – eingebettetes ICC-Profil
- `PLTE` – Palettendaten in indexierten Bildern, aber auch nützlich in payload-smuggling-Szenarien

Dumpe sie mit:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Für offensive payload persistence innerhalb von PNG-Chunks (zum Beispiel **PLTE**, **IDAT** oder **tEXt**-Tricks, die einige PHP image transformations überleben), schau dir die detaillierteren upload-fokussierten Notizen hier an:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Beschädigte PNG-Reparatur

Zum Prüfen der Integrität und zum Lokalisieren des genauen beschädigten Bereichs bleibt **pngcheck** eines der besten ersten Tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Wenn die Datei beschädigt und nicht absichtlich bösartig ist, kann **PCRT** in CTFs und Laborarbeiten nützlich sein, um häufige Probleme wie fehlerhafte Header, falsche IHDR-Werte, CRC-Probleme oder fehlerhafte Chunk-Layouts zu beheben.

Wenn dein Ziel ist, ein PNG zu **sanitizen**, das verdächtige Trailer-Daten enthält, während das sichtbare Bild erhalten bleibt, kann ExifTool den Trailer explizit entfernen:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Für sensible Beweise arbeite immer mit einer **Kopie** und behalte Hashes des Originals, bevor du Reparaturen versuchst.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
