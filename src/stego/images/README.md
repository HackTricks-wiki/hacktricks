# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Die meisten CTF-Image-Stego-Fälle lassen sich in eine dieser Kategorien einordnen:

- LSB/bit-planes (PNG/BMP)
- Metadaten/Kommentar-payloads
- PNG-Chunk-Ungewöhnlichkeiten / Korruptionsreparatur
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-basiert (GIF/APNG)

## Schnelle Triage

Priorisiere Beweise auf Container-Ebene, bevor du eine tiefgehende Inhaltsanalyse durchführst:

- Prüfe die Datei und untersuche die Struktur: `file`, `magick identify -verbose`, Format-Validatoren (z. B. `pngcheck`).
- Extrahiere Metadaten und sichtbare Strings: `exiftool -a -u -g1`, `strings`.
- Suche nach eingebettetem/angefügtem Inhalt: `binwalk` und End-of-File-Inspektion (`tail | xxd`).
- Nach Container-Typ unterscheiden:
- PNG/BMP: bit-planes/LSB und Chunk-Ebene-Anomalien.
- JPEG: Metadaten + DCT-domain Tools (OutGuess/F5-ähnliche Familien).
- GIF/APNG: Frame-Extraktion, Frame-Differenzierung, Paletten-Tricks.

## Bit-planes / LSB

### Technik

PNG/BMP sind in CTFs beliebt, weil sie Pixel so speichern, dass bitweise Manipulationen einfach sind. Der klassische Hide/Extract-Mechanismus ist:

- Jeder Pixel-Kanal (R/G/B/A) hat mehrere Bits.
- Das **Least Significant Bit** (LSB) jedes Kanals verändert das Bild nur sehr wenig.
- Angreifer verstecken Daten in diesen niederwertigen Bits, manchmal mit einem stride, einer Permutation oder kanalweiser Auswahl.

Was in Challenges zu erwarten ist:

- Die Payload befindet sich nur in einem Kanal (z. B. `R` LSB).
- Die Payload befindet sich im Alpha-Kanal.
- Die Payload ist nach der Extraktion komprimiert/kodiert.
- Die Nachricht ist über Ebenen verteilt oder mittels XOR zwischen Ebenen versteckt.

Weitere Verfahren, denen du begegnen kannst (implementierungsabhängig):

- **LSB matching** (nicht nur das Umkehren des Bits, sondern +/-1-Anpassungen, um das Zielbit zu erreichen)
- **Palette/index-based hiding** (indexed PNG/GIF: Payload in Farbindices statt Roh-RGB)
- **Alpha-only payloads** (vollständig unsichtbar in der RGB-Ansicht)

### Tooling

#### zsteg

`zsteg` listet viele LSB/Bit-Ebenen-Extraktionsmuster für PNG/BMP auf:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: führt eine Reihe von Transformationsschritten aus (Metadaten, Bildtransformationen, brute forcing LSB variants).
- `stegsolve`: manuelle visuelle Filter (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT ist nicht LSB extraction; es wird in Fällen verwendet, in denen Inhalte bewusst im Frequenzraum oder in subtilen Mustern versteckt sind.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webbasierte Triage, oft in CTFs verwendet:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-Interna: Chunks, Korruption und versteckte Daten

### Technik

PNG ist ein chunk-basiertes Format. In vielen Challenges wird die payload auf Container-/Chunk-Ebene gespeichert statt in Pixelwerten:

- **Extra bytes after `IEND`** (viele Viewer ignorieren nachlaufende Bytes)
- **Non-standard ancillary chunks** die payloads tragen
- **Corrupted headers** die Dimensionen verbergen oder Parser zum Absturz bringen, bis sie repariert sind

Besonders aussagekräftige Chunk-Positionen zur Überprüfung:

- `tEXt` / `iTXt` / `zTXt` (Text-Metadaten, manchmal komprimiert)
- `iCCP` (ICC-Profil) und andere ancillary Chunks, die als Carrier verwendet werden
- `eXIf` (EXIF-Daten in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Worauf man achten sollte:

- Ungewöhnliche Breite/Höhe/Bit-Tiefe/Farbtyp-Kombinationen
- CRC/Chunk-Fehler (pngcheck zeigt normalerweise das genaue Offset an)
- Warnungen über zusätzliche Daten nach `IEND`

Wenn du eine detailliertere Chunk-Ansicht brauchst:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nützliche Referenzen:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: Metadaten, DCT-domain Tools und ELA-Einschränkungen

### Technik

JPEG wird nicht als rohe Pixel gespeichert; es wird im DCT-Bereich komprimiert. Deshalb unterscheiden sich JPEG stego-Tools von PNG-LSB-Tools:

- Metadaten-/Kommentar-Payloads sind auf Datei-Ebene (starkes Signal und schnell zu prüfen)
- DCT-domain stego-Tools betten Bits in Frequenzkoeffizienten ein

Praktisch betrachtet, behandeln Sie JPEG als:

- Einen Container für Metadaten-Segmente (starkes Signal, schnell zu prüfen)
- Eine komprimierte Signal-Domäne (DCT-Koeffizienten), in der spezialisierte stego-Tools arbeiten

### Schnellchecks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Orte mit hohem Signal:

- EXIF/XMP/IPTC-Metadaten
- JPEG-Kommentarsegment (`COM`)
- Application-Segmente (`APP1` für EXIF, `APPn` für Herstellerdaten)

### Gängige Tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Wenn du speziell auf steghide-Payloads in JPEGs stößt, erwäge die Verwendung von `stegseek` (schnelleres bruteforce als ältere Skripte):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA hebt verschiedene Rekompressions-Artefakte hervor; es kann auf Regionen hinweisen, die bearbeitet wurden, ist aber kein stego detector an sich:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Animierte Bilder

### Technik

Bei animierten Bildern gehe davon aus, dass die Nachricht:

- In einem einzelnen Frame (einfach), oder
- Über mehrere Frames verteilt ist (Reihenfolge wichtig), oder
- Nur sichtbar ist, wenn du aufeinanderfolgende Frames diffst

### Frames extrahieren
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Behandle die Frames dann wie normale PNGs: `zsteg`, `pngcheck`, channel isolation.

Alternative Werkzeuge:

- `gifsicle --explode anim.gif` (schnelle Frame-Extraktion)
- `imagemagick`/`magick` für pro-Frame-Transformationen

Frame differencing is often decisive:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Passwortgeschützte Einbettung

Wenn Sie vermuten, dass die Einbettung durch eine Passphrase geschützt ist und nicht durch pixelbasierte Manipulation, ist dies normalerweise der schnellste Weg.

### steghide

Unterstützt `JPEG, BMP, WAV, AU` und kann verschlüsselte payloads einbetten/extrahieren.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Ich habe keinen Zugriff auf das Repository. Bitte füge hier den Inhalt von src/stego/images/README.md ein, dann übersetze ich ihn gemäß deinen Vorgaben (Markdown-/HTML-Tags, Links und Pfade unberührt).
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Unterstützt PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
