# Bildsteganographie

{{#include ../../banners/hacktricks-training.md}}

Die meisten CTF image stego lassen sich in eine der folgenden Kategorien einordnen:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Schnelle Triage

Priorisiere Hinweise auf Container-Ebene, bevor du eine tiefgehende Inhaltsanalyse durchführst:

- Validiere die Datei und untersuche die Struktur: `file`, `magick identify -verbose`, Format-Validatoren (z. B. `pngcheck`).
- Extrahiere Metadaten und sichtbare Strings: `exiftool -a -u -g1`, `strings`.
- Prüfe auf eingebettete/angehängte Inhalte: `binwalk` und End-of-File-Inspektion (`tail | xxd`).
- Nach Container unterscheiden:
- PNG/BMP: bit-planes/LSB und chunk-level Anomalien.
- JPEG: Metadaten + DCT-domain Tools (OutGuess/F5-Familien).
- GIF/APNG: Frame-Extraktion, Frame-Differenzierung, Palette-Tricks.

## Bit-planes / LSB

### Technik

PNG/BMP sind in CTFs beliebt, weil sie Pixel so speichern, dass Manipulationen auf Bit-Ebene leicht möglich sind. Der klassische Hide/Extract-Mechanismus ist:

- Jeder Pixelkanal (R/G/B/A) hat mehrere Bits.
- Das **least significant bit** (LSB) jedes Kanals verändert das Bild nur sehr wenig.
- Angreifer verstecken Daten in diesen niederwertigen Bits, manchmal mit einem Stride, einer Permutation oder kanal-spezifischer Auswahl.

Was in Challenges zu erwarten ist:

- Der Payload befindet sich nur in einem Kanal (z. B. `R` LSB).
- Der Payload befindet sich im Alpha-Kanal.
- Der Payload ist nach der Extraktion komprimiert/kodiert.
- Die Nachricht ist über Ebenen verteilt oder durch XOR zwischen Ebenen verborgen.

Weitere Familien, denen du begegnen kannst (implementationabhängig):

- **LSB matching** (nicht nur das Umdrehen des Bits, sondern +/-1-Anpassungen, um das Zielbit zu erreichen)
- **Palette/index-based hiding** (indexed PNG/GIF: Payload in Farbindices statt rohem RGB)
- **Alpha-only payloads** (vollständig unsichtbar in der RGB-Ansicht)

### Tools

#### zsteg

`zsteg` listet viele LSB/bit-plane Extraktionsmuster für PNG/BMP auf:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: führt eine Reihe von Transformationsprüfungen durch (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: manuelle visuelle Filter (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT ist keine LSB-Extraktion; es wird in Fällen eingesetzt, in denen Inhalte gezielt im Frequenzraum oder in subtilen Mustern versteckt werden.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webbasierte Triagierung, die oft in CTFs verwendet wird:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-Interna: chunks, Beschädigung und versteckte Daten

### Technik

PNG ist ein chunked Format. In vielen Challenges wird die payload auf Container-/Chunk-Ebene statt in Pixelwerten gespeichert:

- **Extra bytes after `IEND`** (viele Viewer ignorieren trailing bytes)
- **Non-standard ancillary chunks** die payloads enthalten
- **Corrupted headers**, die Dimensionen verbergen oder Parser zum Absturz bringen, bis sie korrigiert sind

Wichtige Chunk-Positionen, die überprüft werden sollten:

- `tEXt` / `iTXt` / `zTXt` (text metadata, manchmal komprimiert)
- `iCCP` (ICC profile) und andere ancillary chunks, die als Träger verwendet werden
- `eXIf` (EXIF data in PNG)

### Triage-Befehle
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Worauf achten:

- Ungewöhnliche width/height/bit-depth/colour-type-Kombinationen
- CRC/chunk-Fehler (pngcheck zeigt normalerweise den genauen Offset an)
- Warnungen über zusätzliche Daten nach `IEND`

Wenn du eine detailliertere Chunk-Ansicht benötigst:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nützliche Referenzen:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: Metadaten, DCT-domain Tools und ELA-Einschränkungen

### Technik

JPEG wird nicht als rohe Pixel gespeichert; es ist im DCT-Bereich komprimiert. Deshalb unterscheiden sich JPEG stego-Tools von PNG LSB-Tools:

- Metadata/comment payloads sind auf Datei-Ebene (hohes Signal und schnell zu prüfen)
- DCT-domain stego tools betten Bits in Frequenzkoeffizienten ein

Praktisch gilt für JPEG:

- Ein Container für Metadata-Segmente (hohes Signal, schnell zu prüfen)
- Eine komprimierte Signal-Domain (DCT-Koeffizienten), in der spezialisierte stego-Tools arbeiten

### Schnelle Prüfungen
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Wichtige Orte:

- EXIF/XMP/IPTC Metadaten
- JPEG Kommentarsegment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Häufige Tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Wenn du speziell auf steghide-Payloads in JPEGs triffst, verwende `stegseek` (schnellerer bruteforce als ältere Skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA hebt verschiedene Rekompressionsartefakte hervor; es kann dir Bereiche zeigen, die bearbeitet wurden, ist aber für sich genommen kein Stego-Detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animierte Bilder

### Technik

Bei animierten Bildern gehe davon aus, dass die Nachricht:

- In einem einzelnen Frame (einfach), oder
- Über mehrere Frames verteilt (Reihenfolge ist wichtig), oder
- Nur sichtbar ist, wenn du aufeinanderfolgende Frames differenzierst

### Frames extrahieren
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Behandle die Frames dann wie normale PNGs: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (schnelles Frame-Extrahieren)
- `imagemagick`/`magick` für Transformationen pro Frame

Frame differencing ist oft entscheidend:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG Pixelanzahl-Codierung

- APNG-Container erkennen: `exiftool -a -G1 file.png | grep -i animation` oder `file`.
- Frames ohne Retiming extrahieren: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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
Animierte Challenges können jedes Byte als Anzahl einer bestimmten Farbe in jedem Frame kodieren; das Aneinanderhängen der Zählwerte rekonstruiert die Nachricht.

## Passwortgeschütztes Embedding

Wenn Sie vermuten, dass das Embedding durch eine passphrase geschützt ist statt durch Manipulation auf Pixelebene, ist dies normalerweise der schnellste Weg.

### steghide

Unterstützt `JPEG, BMP, WAV, AU` und kann verschlüsselte Payloads einbetten und extrahieren.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I can’t access external repos. Please paste the exact contents of src/stego/images/README.md here (or the parts you want translated). I will translate the English text to German following your rules and keep all markdown/html/tags, links and code unchanged.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Unterstützt PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Referenzen

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
