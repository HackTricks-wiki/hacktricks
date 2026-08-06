# PNG-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG-Dateien** sind in **CTFs**, bei der **Incident Response** und beim **Malware-Staging** sehr verbreitet, da sie **verlustfrei**, **chunk-basiert** sind und viele Tools sie problemlos rendern, selbst wenn sie **zusätzliche Metadaten**, **angehängte Payloads** oder **teilweise beschädigte Chunks** enthalten.

Behandle ein PNG als **Container**, nicht nur als Bild.

## Schnelle Triage

Beginne mit Prüfungen auf Containerebene, bevor du dich mit LSB-Stego beschäftigst. Für den Bit-Plane-/LSB-Workflow siehe [die spezielle Seite zu Image-Stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Nützliche Dinge, nach denen man suchen sollte:

- **Unerwartete ancillary chunks** wie `tEXt`, `zTXt`, `iTXt`, `eXIf` oder `iCCP`
- **CRC-Fehler** oder fehlerhafte Chunk-Längen
- **Zusätzliche Daten nach `IEND`**
- **Mehrere `IEND`-Marker** oder wiederherstellbare `IDAT`-Fragmente nach dem formalen Dateiende
- Eine Datei, die ein gültiges PNG ist **und** beim Carving zugleich wie eine ZIP-/PDF-/Script-Datei aussieht

Denke daran, dass die minimale gültige Struktur normalerweise folgendermaßen aussieht:

- `IHDR` (muss an erster Stelle stehen)
- `IDAT` (ein oder mehrere aufeinanderfolgende Chunks)
- `IEND` (muss an letzter Stelle stehen)

## Nach `IEND` angehängte Daten

Eines der aussagekräftigsten PNG-Artefakte sind **Daten, die nach dem letzten `IEND`-Chunk angehängt wurden**. Viele Decoder ignorieren diese Daten, wodurch sie nützlich sind für:

- **Einfaches stego / versteckte Payloads**
- **PNG-polyglots**
- **Malware-Staging**
- **Die Wiederherstellung älterer Bilddaten** aus fehlerhaften Editoren

Schneller Nachweis:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Wenn du alles nach dem letzten `IEND` extrahieren möchtest:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Wende auch generische Archivparser direkt auf die PNG-Datei oder den extrahierten Trailer an:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Wiederherstellung nach Acropalypse-Art von zugeschnittenen/geschwärzten Screenshots

Ein sehr praktischer aktueller PNG-Forensik-Trick besteht darin zu prüfen, ob ein Screenshot-Editor eine PNG-Datei **überschrieben** hat, ohne die alte Datei zuvor **zu kürzen**. In diesen Fällen können Bytes des **vorherigen Bildes** nach `IEND` verbleiben, und manchmal können zusätzliche `IDAT`-Daten teilweise rekonstruiert werden.

Dies wurde durch **aCropalypse** (Google Pixel Markup) und das damit verbundene Problem des **Windows Snipping Tool** bekannt. Wenn eine „zugeschnittene“ oder „geschwärzte“ PNG-Datei noch alte Daten am Ende enthält, kann möglicherweise ein Teil des ursprünglichen Screenshots wiederhergestellt werden.<sup>[[1]](#references)</sup>

Praktischer Ablauf:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Anzeichen, die eine eingehendere Analyse stark rechtfertigen:

- `pngcheck` meldet **zusätzliche Daten nach `IEND`**
- Du findest **mehr als ein `IEND`**
- Du findest **zusätzliche `IDAT`-Chunks** nach dem scheinbaren Ende des Bildes
- Der Screenshot stammt von einem Gerät/Editor, von dem bekannt ist, dass er betroffen war

Wenn dies passiert, führe die Datei durch ein **aCropalypse recovery tool**, bevor du die Schwärzung als vertrauenswürdig behandelst.

## In der Praxis relevanter Chunk-Missbrauch

Die interessantesten PNG-Chunks für Untersuchungen sind normalerweise nicht die offensichtlichen Bild-Chunks, sondern die Chunks, die **Text**, **Metadaten** oder **Payload-Bytes** enthalten können:

- `tEXt` / `zTXt` / `iTXt` – Textmetadaten und komprimierter Text
- `eXIf` – EXIF-Daten innerhalb von PNG
- `iCCP` – eingebettetes ICC-Profil
- `PLTE` – Palettendaten in Bildern mit indizierten Farben, aber auch nützlich in Szenarien zum Einschleusen von Payloads<sup>[[2]](#references)</sup>

Dump sie mit:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Für die Persistenz offensiver Payloads innerhalb von PNG-Chunks (zum Beispiel **PLTE**-, **IDAT**- oder **tEXt**-Tricks, die einige PHP-Bildtransformationen überstehen) siehe die ausführlicheren, auf Uploads fokussierten Hinweise hier<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Beschädigte PNGs reparieren

Zum Überprüfen der Integrität und zum Auffinden des exakt beschädigten Bereichs bleibt **pngcheck** eines der besten Tools für den ersten Check:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Wenn die Datei beschädigt und nicht absichtlich bösartig ist, kann **PCRT** bei CTFs und in Laborumgebungen nützlich sein, um häufige Probleme wie fehlerhafte Header, falsche IHDR-Werte, CRC-Probleme oder fehlerhafte Chunk-Strukturen zu beheben.

Wenn dein Ziel darin besteht, ein PNG mit verdächtigen Trailer-Daten zu **bereinigen** und dabei das sichtbare Bild zu erhalten, kann ExifTool den Trailer ausdrücklich entfernen:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Für sensible Beweismittel solltest du immer mit einer **Kopie** arbeiten und die Hashes des Originals sichern, bevor du Reparaturen versuchst.

## Referenzen

- [1] [aCropalypse ausnutzen: Abgeschnittene PNGs wiederherstellen](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistente PHP-Payloads in PNGs: PHP-Code in ein Bild einschleusen – und dort behalten](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
