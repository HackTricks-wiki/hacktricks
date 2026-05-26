# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG-Dateien** sind sehr häufig in **CTFs**, **Incident Response** und **Malware-Staging**, weil sie **verlustfrei**, **chunk-basiert** sind und viele Tools sie problemlos rendern, selbst wenn sie **zusätzliche Metadaten**, **angehängte Payloads** oder **teilweise beschädigte Chunks** enthalten.

Betrachte eine PNG als **Container** und nicht nur als Bild.

## Quick triage

Beginne mit Prüfungen auf Container-Ebene, bevor du zu LSB-Stego springst. Für den Bit-Plane/LSB-Workflow sieh dir [die dedizierte Image-Stego-Seite](../../../stego/images/README.md) an.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Nützliche Dinge, auf die man achten sollte:

- **Unerwartete zusätzliche Chunks** wie `tEXt`, `zTXt`, `iTXt`, `eXIf` oder `iCCP`
- **CRC-Fehler** oder fehlerhafte Chunk-Längen
- **Zusätzliche Daten nach `IEND`**
- **Mehrere `IEND`-Marker** oder wiederherstellbare `IDAT`-Fragmente nach dem formalen Ende der Datei
- Eine Datei, die ein gültiges PNG ist **und** beim Carven auch wie ein ZIP/PDF/Script aussieht

Denk daran, die minimale gültige Struktur ist normalerweise:

- `IHDR` (muss zuerst kommen)
- `IDAT` (ein oder mehrere aufeinanderfolgende Chunks)
- `IEND` (muss zuletzt kommen)

## Zusätzliche Daten nach `IEND`

Eines der aussagekräftigsten PNG-Artefakte sind **Daten, die nach dem letzten `IEND`-Chunk angehängt wurden**. Viele Decoder ignorieren sie, was sie nützlich macht für:

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
Wenn du alles nach dem letzten `IEND` auscarven möchtest:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Versuche auch generische Archiv-Parser direkt gegen die PNG oder das herausgeschnittene Trailer:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style Wiederherstellung von zugeschnittenen/redigierten screenshots

Ein sehr praktischer neuer PNG-Forensik-Trick ist zu prüfen, ob ein Screenshot-Editor ein PNG **überschrieben** hat, ohne die alte Datei vorher zu **truncating**. In solchen Fällen können Bytes vom **previous image** nach `IEND` erhalten bleiben, und manchmal lässt sich zusätzliches `IDAT`-Datenmaterial teilweise rekonstruieren.

Das wurde mit **aCropalypse** (Google Pixel Markup) und dem entsprechenden **Windows Snipping Tool**-Problem bekannt. In der Praxis kannst du, wenn ein "cropped" oder "redacted" PNG noch alte nachfolgende Daten enthält, eventuell einen Teil des ursprünglichen screenshots wiederherstellen.

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Anzeichen, die eine tiefere Analyse stark rechtfertigen:

- `pngcheck` meldet **additional data after `IEND`**
- Du findest **mehr als ein `IEND`**
- Du findest **extra `IDAT` chunks** nach dem scheinbaren Ende des Bildes
- Der Screenshot stammt von einem Device/Editor, von dem bekannt ist, dass er betroffen war

Wenn das passiert, gib die Datei zuerst an ein **aCropalypse recovery tool**, bevor du die Redaction als vertrauenswürdig behandelst.

## Chunk abuse that matters in practice

Die interessantesten PNG chunks für Untersuchungen sind meist nicht die offensichtlichen Bild-chunks, sondern die chunks, die **text**, **metadata** oder **payload bytes** tragen können:

- `tEXt` / `zTXt` / `iTXt` – text metadata und compressed text
- `eXIf` – EXIF data inside PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data in indexed images, aber auch nützlich in payload-smuggling-Szenarien

Dump them with:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Für offensive payload persistence innerhalb von PNG-Chunks (zum Beispiel **PLTE**, **IDAT** oder **tEXt** Tricks, die einige PHP image transformations überleben), schau dir die detaillierteren upload-fokussierten Notizen hier an:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Beschädigte PNG-Reparatur

Zum Prüfen der Integrität und zum Lokalisieren des genauen beschädigten Bereichs ist **pngcheck** weiterhin eines der besten ersten Tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Wenn die Datei beschädigt statt absichtlich bösartig ist, kann **PCRT** in CTFs und Laborarbeiten nützlich sein, um häufige Probleme wie schlechte Header, falsche IHDR-Werte, CRC-Probleme oder fehlerhafte Chunk-Layouts zu beheben.

Wenn dein Ziel ist, ein PNG zu **sanitizen**, das verdächtige trailer data enthält, während das sichtbare Bild erhalten bleibt, kann ExifTool den Trailer explizit entfernen:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Für sensible Beweismittel immer an einer **Kopie** arbeiten und die Hashes des Originals aufbewahren, bevor Reparaturen versucht werden.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
