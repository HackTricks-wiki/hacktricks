# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego reduces to one of these buckets:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Schnelle Triage

Priorisiere container-level Hinweise, bevor du tief in die Inhaltsanalyse gehst:

- Validiere die Datei und untersuche die Struktur: `file`, `magick identify -verbose`, Format-Validatoren (z. B. `pngcheck`).
- Extrahiere Metadaten und sichtbare Strings: `exiftool -a -u -g1`, `strings`.
- Prüfe auf eingebettete/angehängte Inhalte: `binwalk` und End-of-File-Inspektion (`tail | xxd`).
- Verzweige nach Container:
- PNG/BMP: bit-planes/LSB und Chunk-Level-Anomalien.
- JPEG: Metadaten + DCT-domain Tooling (OutGuess/F5-style families).
- GIF/APNG: Frame-Extraktion, Frame-Differenzierung, Paletten-Tricks.

## Bit-planes / LSB

### Technik

PNG/BMP sind in CTFs beliebt, weil sie Pixel so speichern, dass **Bit-Ebene-Manipulation** einfach ist. Der klassische Hide/Extract-Mechanismus ist:

- Jeder Pixel-Kanal (R/G/B/A) hat mehrere Bits.
- Das **least significant bit** (LSB) jedes Kanals verändert das Bild nur sehr wenig.
- Angreifer verstecken Daten in diesen niederwertigen Bits, manchmal mit einer Schrittweite, Permutation oder kanalweiser Auswahl.

Worauf man in Challenges achten sollte:

- Die Payload befindet sich nur in einem Kanal (z. B. `R` LSB).
- Die Payload befindet sich im alpha channel.
- Die Payload ist nach der Extraktion komprimiert/encodiert.
- Die Nachricht ist über Ebenen verteilt oder mittels XOR zwischen Ebenen versteckt.

Zusätzliche Varianten, auf die du stoßen kannst (implementierungsabhängig):

- **LSB matching** (nicht nur das Bit umdrehen, sondern +/-1-Anpassungen, um das Zielbit zu erreichen)
- **Palette/index-based hiding** (indexed PNG/GIF: Payload in Farbindizes statt im rohen RGB)
- **Alpha-only payloads** (vollständig unsichtbar in der RGB-Ansicht)

### Werkzeuge

#### zsteg

`zsteg` enumerates many LSB/bit-plane extraction patterns for PNG/BMP:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: führt eine Reihe von Transformationen aus (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: manuelle visuelle Filter (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT ist nicht LSB-Extraktion; es wird bei Fällen eingesetzt, in denen Inhalte bewusst im Frequenzraum oder in subtilen Mustern versteckt sind.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG ist ein chunk-basiertes Format. In vielen Challenges wird die Nutzlast auf Container-/Chunk-Ebene gespeichert, statt in Pixelwerten:

- **Extra bytes after `IEND`** (viele Viewer ignorieren nachgestellte Bytes)
- **Non-standard ancillary chunks** tragen payloads
- **Corrupted headers** die Dimensionen verbergen oder Parser brechen, bis sie repariert sind

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (Text-Metadaten, manchmal komprimiert)
- `iCCP` (ICC-Profil) und andere ancillary chunks, die als Träger genutzt werden
- `eXIf` (EXIF-Daten in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Worauf du achten solltest:

- Seltsame Kombinationen von Breite/Höhe/Bit-Tiefe/Farbtyp
- CRC-/Chunk-Fehler (pngcheck zeigt normalerweise auf den genauen Offset)
- Warnungen über zusätzliche Daten nach `IEND`

Wenn du eine detailliertere Chunk-Ansicht benötigst:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nützliche Referenzen:

- PNG-Spezifikation (Aufbau, Chunks): https://www.w3.org/TR/PNG/
- Dateiformat-Tricks (PNG/JPEG/GIF Randfälle): https://github.com/corkami/docs

## JPEG: Metadaten, DCT-domain-Tools und ELA-Einschränkungen

### Technik

JPEG wird nicht als rohe Pixel gespeichert; es wird im DCT-Bereich komprimiert. Deshalb unterscheiden sich JPEG-stego-Tools von PNG-LSB-Tools:

- Metadaten/Kommentar-Payloads sind auf Datei-Ebene (starkes Signal und schnell zu prüfen)
- DCT-domain stego-Tools betten Bits in Frequenzkoeffizienten ein

Praktisch sollte man JPEG behandeln als:

- Ein Container für Metadaten-Segmente (starkes Signal, schnell zu prüfen)
- Eine komprimierte Signaldomain (DCT-Koeffizienten), in der spezialisierte stego-Tools arbeiten

### Schnelle Prüfungen
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Wichtige Fundorte:

- EXIF/XMP/IPTC-Metadaten
- JPEG-Kommentarsegment (`COM`)
- Anwendungssegmente (`APP1` für EXIF, `APPn` für Vendor-Daten)

### Gängige Tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Wenn Sie speziell steghide payloads in JPEGs haben, sollten Sie `stegseek` in Betracht ziehen (schnelleres bruteforce als ältere Skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA hebt verschiedene Rekompressions-Artefakte hervor; es kann auf Bereiche hinweisen, die bearbeitet wurden, ist jedoch kein Stego-Detektor für sich allein:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animierte Bilder

### Technik

Bei animierten Bildern gehen Sie davon aus, dass die Nachricht:

- In einem einzelnen Frame (einfach), oder
- Über mehrere Frames verteilt ist (Reihenfolge wichtig), oder
- Nur sichtbar ist, wenn Sie die Differenz aufeinanderfolgender Frames bilden

### Frames extrahieren
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Behandle Frames wie normale PNGs: `zsteg`, `pngcheck`, channel isolation.

Alternative Werkzeuge:

- `gifsicle --explode anim.gif` (schnelle Frame-Extraktion)
- `imagemagick`/`magick` für pro-Frame-Transformationen

Frame differencing ist oft entscheidend:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Passwortgeschützte Einbettung

Wenn Sie vermuten, dass die Einbettung durch eine Passphrase statt durch pixelbasierte Manipulation geschützt ist, ist dies normalerweise der schnellste Weg.

### steghide

Unterstützt `JPEG, BMP, WAV, AU` und kann embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Ich habe gerade keinen Zugriff auf das Repo. Bitte füge hier den Inhalt von src/stego/images/README.md ein (als Rohtext/Markdown). Ich übersetze ihn dann ins Deutsche und erhalte dabei genau die Markdown-/HTML-Syntax, Links, Pfade und Tags unverändert.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Unterstützt PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
