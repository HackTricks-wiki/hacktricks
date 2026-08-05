# Bild-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Die meisten CTF-Bild-Stego-Fälle lassen sich auf eine dieser Kategorien reduzieren:

- LSB/bit-planes (PNG/BMP)
- Metadata-/Kommentar-Payloads
- PNG-chunk-Eigenheiten / Reparatur von Beschädigungen
- JPEG-DCT-domain-Tools (OutGuess usw.)
- Frame-basierte Verfahren (GIF/APNG)

## Schnelle Triage

Priorisiere Beweise auf Container-Ebene vor einer tiefgehenden Inhaltsanalyse:

- Validiere die Datei und untersuche die Struktur: `file`, `magick identify -verbose`, Format-Validatoren (z. B. `pngcheck`).
- Extrahiere Metadata und sichtbare Strings: `exiftool -a -u -g1`, `strings`.
- Prüfe auf eingebettete/angehängte Inhalte: `binwalk` und eine Untersuchung des Dateiende (`tail | xxd`).
- Gehe je nach Container unterschiedlich vor:
- PNG/BMP: bit-planes/LSB und Anomalien auf Chunk-Ebene.
- JPEG: Metadata + DCT-domain-Tooling (OutGuess/F5-artige Familien).
- GIF/APNG: Frame-Extraktion, Frame-Differenzbildung, Palette-Tricks.

## Bit-Planes / LSB

### Technique

PNG/BMP sind in CTFs beliebt, weil sie Pixel auf eine Weise speichern, die **Manipulationen auf Bit-Ebene** einfach macht. Der klassische Mechanismus zum Verstecken/Extrahieren ist:

- Jeder Pixelkanal (R/G/B/A) enthält mehrere Bits.
- Das **least significant bit** (LSB) jedes Kanals verändert das Bild nur geringfügig.
- Angreifer verstecken Daten in diesen niederwertigen Bits, manchmal mit einem Stride, einer Permutation oder einer Auswahl pro Kanal.

Was du in Challenges erwarten kannst:

- Die Payload befindet sich nur in einem Kanal (z. B. im LSB von `R`).
- Die Payload befindet sich im Alpha-Kanal.
- Die Payload wird nach der Extraktion komprimiert/encodiert.
- Die Nachricht ist über mehrere planes verteilt oder mittels XOR zwischen planes versteckt.

Zusätzliche Familien, auf die du stoßen kannst (implementierungsabhängig):

- **LSB matching** (nicht nur das Bit umschalten, sondern Anpassungen um +/-1 vornehmen, um das Zielbit zu erreichen)
- **Palette/index-based hiding** (indizierte PNG/GIF: Payload in den Farbindizes statt in den unverarbeiteten RGB-Werten)
- **Alpha-only payloads** (bei einer RGB-Ansicht vollständig unsichtbar)

### Tooling

#### zsteg

`zsteg` listet viele LSB-/bit-plane-Extraktionsmuster für PNG/BMP auf:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: führt eine Reihe von Transformationen aus (Metadaten, Bildtransformationen, Brute-Forcing von LSB-Varianten).
- `stegsolve`: manuelle visuelle Filter (Kanalisolierung, Ebeneninspektion, XOR usw.).

Stegsolve-Download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-basierte Sichtbarkeitstricks

FFT ist keine LSB-Extraktion; sie wird für Fälle verwendet, in denen Inhalte absichtlich im Frequenzraum oder in subtilen Mustern verborgen wurden.

- EPFL-Demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webbasierte Triage wird häufig in CTFs verwendet:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-Interna: Chunks, Beschädigungen und versteckte Daten

### Technique

PNG ist ein Chunk-Format. In vielen Challenges wird der Payload auf Container-/Chunk-Ebene statt in Pixelwerten gespeichert:

- **Zusätzliche Bytes nach `IEND`** (viele Viewer ignorieren nachfolgende Bytes)
- **Nicht standardisierte Ancillary-Chunks**, die Payloads enthalten
- **Beschädigte Header**, die Dimensionen verbergen oder Parser blockieren, bis sie repariert wurden

Chunks mit hoher Signalstärke, die überprüft werden sollten:

- `tEXt` / `iTXt` / `zTXt` (Textmetadaten, manchmal komprimiert)
- `iCCP` (ICC-Profil) und andere Ancillary-Chunks, die als Träger verwendet werden
- `eXIf` (EXIF-Daten in PNG)

### Triage-Befehle
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Wonach du suchen solltest:

- Ungewöhnliche Kombinationen aus Breite/Höhe/Bit-Tiefe/Farbtyp
- CRC-/Chunk-Fehler (`pngcheck` verweist normalerweise auf den exakten Offset)
- Warnungen über zusätzliche Daten nach `IEND`

Wenn du eine detailliertere Chunk-Ansicht benötigst:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nützliche Referenzen:

- PNG-Spezifikation (Struktur, Chunks): https://www.w3.org/TR/PNG/
- Tricks mit Dateiformaten (PNG/JPEG/GIF-Sonderfälle): https://github.com/corkami/docs

## JPEG: Metadaten, DCT-domain tools und ELA-Einschränkungen

### Technique

JPEG wird nicht als Rohpixel gespeichert, sondern in der DCT-Domäne komprimiert. Deshalb unterscheiden sich JPEG-stego tools von PNG-LSB-tools:

- Metadaten-/Kommentar-Payloads befinden sich auf Dateiebene (hohes Signal und schnell zu prüfen)
- DCT-domain stego tools betten Bits in Frequenzkoeffizienten ein

Behandle JPEG operativ als:

- Einen Container für Metadatensegmente (hohes Signal, schnell zu prüfen)
- Eine komprimierte Signaldomäne (DCT-Koeffizienten), in der spezialisierte stego tools arbeiten

### Schnelle Prüfungen
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Signalstarke Fundstellen:

- EXIF/XMP/IPTC-Metadaten
- JPEG-Kommentarsegment (`COM`)
- Application-Segmente (`APP1` für EXIF, `APPn` für Herstellerdaten)

### Gängige Tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Wenn du speziell mit steghide-Payloads in JPEGs zu tun hast, solltest du `stegseek` verwenden (schnelleres Bruteforcing als ältere Scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA hebt unterschiedliche Artefakte der erneuten Komprimierung hervor; es kann dich auf Bereiche hinweisen, die bearbeitet wurden, ist aber selbst kein Stego-Detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animierte Bilder

### Technik

Bei animierten Bildern solltest du davon ausgehen, dass die Nachricht:

- In einem einzelnen Frame enthalten ist (einfach), oder
- Auf mehrere Frames verteilt ist (die Reihenfolge ist wichtig), oder
- Nur sichtbar wird, wenn du aufeinanderfolgende Frames vergleichst

### Frames extrahieren
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Behandle die Frames anschließend wie normale PNGs: `zsteg`, `pngcheck`, Kanalisolierung.

Alternative Tools:

- `gifsicle --explode anim.gif` (schnelle Frame-Extraktion)
- `imagemagick`/`magick` für Transformationen pro Frame

Die Differenzbildung zwischen Frames ist oft entscheidend:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG-Pixelanzahl-Kodierung

- APNG-Container erkennen: `exiftool -a -G1 file.png | grep -i animation` oder `file`.
- Frames ohne erneute Zeitfestlegung extrahieren: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Payloads wiederherstellen, die als Pixelanzahlen pro Frame kodiert sind:
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
Animierte Challenges können jedes Byte als Anzahl einer bestimmten Farbe in jedem Frame codieren; durch das Aneinanderhängen der Zählwerte wird die Nachricht rekonstruiert.<sup>[[1]](#references)</sup>

## Passwortgeschütztes Einbetten

Wenn du vermutest, dass das Einbetten durch eine Passphrase und nicht durch Manipulation auf Pixelebene geschützt ist, ist dies normalerweise der schnellste Weg.

### steghide

Unterstützt `JPEG, BMP, WAV, AU` und kann verschlüsselte Payloads einbetten und extrahieren.
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
