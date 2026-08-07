# Bild-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Die meisten CTF-Bild-stego-Fälle lassen sich einer dieser Kategorien zuordnen:

- LSB/Bit-Planes (PNG/BMP)
- Metadata-/Kommentar-Payloads
- PNG-Chunk-Anomalien / Reparatur von Beschädigungen
- JPEG-DCT-Domain-Tools (OutGuess usw.)
- Frame-basierte Verfahren (GIF/APNG)

## Schnelle Triage

Priorisiere Hinweise auf Container-Ebene, bevor du eine tiefgehende Inhaltsanalyse durchführst:

- Validiere die Datei und untersuche ihre Struktur: `file`, `magick identify -verbose`, Format-Validatoren (z. B. `pngcheck`).
- Extrahiere Metadata und sichtbare Strings: `exiftool -a -u -g1`, `strings`.
- Suche nach eingebetteten/angehängten Inhalten: `binwalk` und Untersuchung des Dateiende (`tail | xxd`).
- Wähle anhand des Containers den weiteren Ansatz:
- PNG/BMP: Bit-Planes/LSB und Anomalien auf Chunk-Ebene.
- JPEG: Metadata + DCT-Domain-Tooling (OutGuess/F5-artige Familien).
- GIF/APNG: Frame-Extraktion, Frame-Differenzierung, Palette-Tricks.

## Bit-Planes / LSB

### Technique

PNG/BMP sind in CTFs beliebt, weil sie Pixel auf eine Weise speichern, die **Manipulationen auf Bit-Ebene** einfach macht. Der klassische Mechanismus zum Verstecken/Extrahieren ist:

- Jeder Pixelkanal (R/G/B/A) verfügt über mehrere Bits.
- Das **Least Significant Bit** (LSB) jedes Kanals verändert das Bild nur sehr wenig.
- Angreifer verstecken Daten in diesen niederwertigen Bits, manchmal mit einem Stride, einer Permutation oder einer Auswahl pro Kanal.

Was du in Challenges erwarten kannst:

- Die Payload befindet sich nur in einem Kanal (z. B. im `R`-LSB).
- Die Payload befindet sich im Alpha-Kanal.
- Die Payload wird nach der Extraktion komprimiert/encodiert.
- Die Nachricht ist über mehrere Planes verteilt oder durch XOR zwischen Planes verborgen.

Weitere Familien, denen du begegnen kannst (implementierungsabhängig):

- **LSB matching** (nicht nur das Bit umschalten, sondern +/-1-Anpassungen vornehmen, um das Zielbit zu setzen)
- **Palette-/indexbasiertes Hiding** (indizierte PNG/GIF: Payload in Farb-Indices statt in rohen RGB-Werten)
- **Nur-Alpha-Payloads** (in der RGB-Ansicht vollständig unsichtbar)

### Tooling

#### zsteg

`zsteg` listet viele LSB-/Bit-Plane-Extraktionsmuster für PNG/BMP auf:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: führt eine Reihe von Transformationen aus (Metadaten, Bildtransformationen, Brute-Forcing von LSB-Varianten).
- `stegsolve`: manuelle visuelle Filter (Kanalisolierung, Untersuchung von Planes, XOR usw.).

Stegsolve-Download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-basierte Sichtbarkeitstricks

FFT ist keine LSB-Extraktion; sie wird für Fälle verwendet, in denen Inhalte absichtlich im Frequenzraum oder in subtilen Mustern verborgen sind.

- EPFL-Demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webbasierte Triage wird häufig in CTFs eingesetzt:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-Interna: Chunks, Korruption und versteckte Daten

### Technik

PNG ist ein Chunk-basiertes Format. In vielen Challenges wird der Payload auf Container-/Chunk-Ebene statt in den Pixelwerten gespeichert:

- **Zusätzliche Bytes nach `IEND`** (viele Viewer ignorieren nachfolgende Bytes)
- **Nicht standardmäßige ancillary Chunks**, die Payloads enthalten
- **Korrupte Header**, die Dimensionen verbergen oder Parser deaktivieren, bis sie repariert werden

Wichtige Chunk-Positionen, die überprüft werden sollten:

- `tEXt` / `iTXt` / `zTXt` (Textmetadaten, manchmal komprimiert)
- `iCCP` (ICC-Profil) und andere ancillary Chunks, die als Träger verwendet werden
- `eXIf` (EXIF-Daten in PNG)

### Triage-Befehle
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Worauf zu achten ist:

- Seltsame Kombinationen aus Breite/Höhe/Bit-Tiefe/Farbtyp
- CRC-/Chunk-Fehler (`pngcheck` verweist normalerweise auf den genauen Offset)
- Warnungen über zusätzliche Daten nach `IEND`

Falls du eine detailliertere Chunk-Ansicht benötigst:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nützliche Referenzen:

- PNG-Spezifikation (Struktur, Chunks): https://www.w3.org/TR/PNG/
- Tricks bei Dateiformaten (Sonderfälle von PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: Metadaten, Tools für die DCT-Domäne und Einschränkungen von ELA

### Technique

JPEG wird nicht als rohe Pixel gespeichert, sondern in der DCT-Domäne komprimiert. Deshalb unterscheiden sich JPEG-Stego-Tools von PNG-LSB-Tools:

- Metadaten-/Kommentar-Payloads befinden sich auf Dateiebene (hohes Signal und schnell zu untersuchen)
- Stego-Tools für die DCT-Domäne betten Bits in Frequenzkoeffizienten ein

Aus operativer Sicht sollte JPEG behandelt werden als:

- Ein Container für Metadatensegmente (hohes Signal, schnell zu untersuchen)
- Eine komprimierte Signaldomäne (DCT-Koeffizienten), in der spezialisierte Stego-Tools arbeiten

### Schnelle Prüfungen
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Orte mit hoher Signalstärke:

- EXIF/XMP/IPTC-Metadaten
- JPEG-Kommentarsegment (`COM`)
- Anwendungssegmente (`APP1` für EXIF, `APPn` für Anbieterdaten)

### Gängige Tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Wenn du speziell mit steghide-Payloads in JPEGs arbeitest, solltest du `stegseek` verwenden (schnelleres Bruteforcing als ältere Skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA hebt unterschiedliche Artefakte durch erneute Komprimierung hervor; es kann dich auf Bereiche hinweisen, die bearbeitet wurden, ist aber selbst kein Stego-Detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animierte Bilder

### Technik

Bei animierten Bildern solltest du davon ausgehen, dass die Nachricht:

- In einem einzelnen Frame enthalten ist (einfach), oder
- Über mehrere Frames verteilt ist (die Reihenfolge ist wichtig), oder
- Nur sichtbar wird, wenn du aufeinanderfolgende Frames diffst

### Frames extrahieren
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Dann behandle Frames wie normale PNGs: `zsteg`, `pngcheck`, Kanalisolierung.

Alternative Tools:

- `gifsicle --explode anim.gif` (schnelle Frame-Extraktion)
- `imagemagick`/`magick` für Transformationen pro Frame

Die Differenzbildung zwischen Frames ist oft entscheidend:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG-Container erkennen: `exiftool -a -G1 file.png | grep -i animation` oder `file`.
- Frames ohne Re-Timing extrahieren: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Payloads wiederherstellen, die als Pixelanzahl pro Frame kodiert sind:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
Animierte Challenges können jedes Byte als Anzahl einer bestimmten Farbe in jedem Frame codieren; durch Verketten der Anzahlen wird die Nachricht rekonstruiert.<sup>[[1]](#references)</sup>

## Durch ein Passwort geschützte Einbettung

Wenn du vermutest, dass die Einbettung durch eine Passphrase statt durch Manipulation auf Pixelebene geschützt ist, ist dies normalerweise der schnellste Weg.

### steghide

Unterstützt `JPEG, BMP, WAV, AU` und kann verschlüsselte Payloads einbetten bzw. extrahieren.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Unterstützt PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Referenzen

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
