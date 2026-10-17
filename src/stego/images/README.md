# Bild-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Die meisten CTF-Bild-Stego-Aufgaben lassen sich einer dieser Kategorien zuordnen:

- LSB/Bit-Ebenen (PNG/BMP)
- Metadaten-/Kommentar-Payloads
- PNG-Chunk-Besonderheiten / Reparatur beschädigter Dateien
- JPEG-DCT-Domain-Tools (OutGuess usw.)
- Frame-basiert (GIF/APNG)

## Schnelle Triage

Priorisiere Hinweise auf Containerebene, bevor du den Inhalt eingehend analysierst:

- Validiere die Datei und untersuche ihre Struktur: `file`, `magick identify -verbose`, Format-Validatoren (z. B. `pngcheck`).
- Extrahiere Metadaten und sichtbare Zeichenfolgen: `exiftool -a -u -g1`, `strings`.
- Prüfe auf eingebettete/angehängte Inhalte: `binwalk` und Dateiende-Inspektion (`tail | xxd`).
- Gehe je nach Container unterschiedlich vor:
  - PNG/BMP: Bit-Ebenen/LSB und Anomalien auf Chunk-Ebene.
  - JPEG: Metadaten und DCT-Domain-Tools (OutGuess-/F5-artige Familien).
  - GIF/APNG: Frame-Extraktion, Frame-Differenzierung, Palettentricks.

## Bit-Ebenen / LSB

### Technik

PNG/BMP sind bei CTFs beliebt, weil die Pixel so gespeichert werden, dass **Manipulationen auf Bitebene** einfach sind. Der klassische Mechanismus zum Verbergen/Extrahieren funktioniert so:

- Jeder Pixelkanal (R/G/B/A) hat mehrere Bits.
- Das **niederwertigste Bit** (LSB) jedes Kanals verändert das Bild nur geringfügig.
- Angreifer verstecken Daten in diesen niederwertigen Bits, manchmal mit einem Schrittmaß, einer Permutation oder einer Auswahl pro Kanal.

Was du bei Challenges erwarten kannst:

- Die Payload liegt in nur einem Kanal (z. B. im LSB von `R`).
- Die Payload liegt im Alphakanal.
- Die Payload wird nach der Extraktion komprimiert/kodiert.
- Die Nachricht ist über mehrere Ebenen verteilt oder durch XOR zwischen Ebenen versteckt.

Weitere mögliche Varianten (implementierungsabhängig):

- **LSB-Matching** (das Bit wird nicht einfach umgekehrt, sondern durch Anpassungen um +/-1 an das Zielbit angepasst)
- **Paletten-/indexbasiertes Verstecken** (indiziertes PNG/GIF: Payload in Farbindizes statt in rohen RGB-Werten)
- **Reine Alpha-Payloads** (im RGB-Bild vollständig unsichtbar)

### Tools

#### zsteg

`zsteg` listet zahlreiche LSB-/Bit-Ebenen-Extraktionsmuster für PNG/BMP auf:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: führt eine Reihe von Transformationen aus (Metadaten, Bildtransformationen, Brute-Force-Suche nach LSB-Varianten).
- `stegsolve`: manuelle visuelle Filter (Kanaltrennung, Ebeneninspektion, XOR usw.).

Stegsolve-Download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-basierte Sichtbarkeitstricks

FFT dient nicht der LSB-Extraktion, sondern Fällen, in denen Inhalte gezielt im Frequenzraum oder in subtilen Mustern verborgen sind.

- EPFL-Demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webbasierte Triage, die häufig bei CTFs zum Einsatz kommt:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-Interna: Chunks, Beschädigungen und versteckte Daten

### Technik

PNG ist ein Chunk-basiertes Format. Bei vielen Challenges ist der Payload auf Container-/Chunk-Ebene statt in den Pixelwerten gespeichert:

- **Zusätzliche Bytes nach `IEND`** (viele Viewer ignorieren nachfolgende Bytes)
- **Nicht standardisierte ancillary Chunks**, die Payloads enthalten; siehe den [PNG-Chunk-Scanner und Carving-Workflow](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Beschädigte Header**, die Abmessungen verbergen oder Parser außer Kraft setzen, bis sie repariert werden

Wichtige Chunk-Positionen, die überprüft werden sollten:

- `tEXt` / `iTXt` / `zTXt` (Textmetadaten, manchmal komprimiert)
- `iCCP` (ICC-Profil) und andere ancillary Chunks, die als Träger dienen
- `eXIf` (EXIF-Daten in PNG)

### Triage-Befehle

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Worauf zu achten ist:

- Ungewöhnliche Kombinationen aus Breite/Höhe/Bit-Tiefe/Farbtyp
- CRC-/Chunk-Fehler (pngcheck verweist normalerweise auf den genauen Offset)
- Warnungen zu zusätzlichen Daten nach `IEND`

Wenn du eine detailliertere Chunk-Ansicht benötigst:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Nützliche Referenzen:

- PNG-Spezifikation (Struktur, Chunks): https://www.w3.org/TR/PNG/
- Tricks mit Dateiformaten (Sonderfälle bei PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: Metadaten, Tools für den DCT-Bereich und Grenzen von ELA

### Technik

JPEG wird nicht als rohe Pixel gespeichert, sondern im DCT-Bereich komprimiert. Deshalb unterscheiden sich JPEG-Stego-Tools von PNG-LSB-Tools:

- Metadaten-/Kommentar-Payloads sind auf Dateiebene gespeichert (hohes Signal, schnell zu prüfen)
- Stego-Tools für den DCT-Bereich betten Bits in Frequenzkoeffizienten ein

In der Praxis sollte man JPEG als Folgendes betrachten:

- Einen Container für Metadatensegmente (hohes Signal, schnell zu prüfen)
- Einen komprimierten Signalbereich (DCT-Koeffizienten), in dem spezialisierte Stego-Tools arbeiten

### Schnellprüfungen

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Auffällige Fundstellen:

- EXIF/XMP/IPTC-Metadaten
- JPEG-Komment segment (`COM`)
- Application-Segmente (`APP1` für EXIF, `APPn` für Herstellerdaten)

### Gängige Tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Wenn du gezielt auf steghide-Payloads in JPEGs stößt, solltest du `stegseek` verwenden (schnelleres Brute-Forcing als ältere Skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA hebt unterschiedliche Artefakte durch die erneute Komprimierung hervor. Es kann auf bearbeitete Bereiche hinweisen, ist aber für sich genommen kein Stego-Detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animierte Bilder

### Technik

Bei animierten Bildern solltest du davon ausgehen, dass die Nachricht:

- In einem einzelnen Frame steckt (einfach), oder
- Über mehrere Frames verteilt ist (die Reihenfolge ist wichtig), oder
- Nur sichtbar wird, wenn du aufeinanderfolgende Frames vergleichst

### Frames extrahieren

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Behandle die Frames anschließend wie normale PNGs: `zsteg`, `pngcheck`, Kanalisolierung.

Alternative Tools:

- `gifsicle --explode anim.gif` (schnelle Frame-Extraktion)
- `imagemagick`/`magick` für Transformationen einzelner Frames

Der Vergleich von Frames ist oft entscheidend:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG-Pixelanzahlkodierung

- APNG-Container erkennen: `exiftool -a -G1 file.png | grep -i animation` oder `file`.
- Frames ohne Änderung der Zeitsteuerung extrahieren: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

Animierte Challenges können jedes Byte als Anzahl einer bestimmten Farbe in jedem Frame codieren; durch Aneinanderhängen der Anzahlen lässt sich die Nachricht rekonstruieren.<sup>[[1]](#references)</sup>

## Passwortgeschützte Einbettung

Wenn du vermutest, dass die Einbettung durch eine Passphrase statt durch Manipulation auf Pixelebene geschützt ist, ist dies meist der schnellste Weg.

### steghide

Unterstützt `JPEG, BMP, WAV, AU` und kann verschlüsselte Payloads einbetten und extrahieren.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repository: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Unterstützt PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
