# Bild-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Die Steganografie in CTF-Bildern fällt meist in eine dieser Kategorien:

- LSB/Bit-Ebenen (PNG/BMP)
- Metadaten-/Kommentar-Payloads
- Ungewöhnliche PNG-Chunks / Reparatur beschädigter Dateien
- JPEG-DCT-Domain-Tools (OutGuess usw.)
- Frame-basiert (GIF/APNG)

## Schnelle Erstprüfung

Priorisiere Hinweise auf Containerebene vor einer tiefergehenden Inhaltsanalyse:

- Validiere die Datei und untersuche ihre Struktur: `file`, `magick identify -verbose`, Formatvalidatoren (z. B. `pngcheck`).
- Extrahiere Metadaten und sichtbare Zeichenketten: `exiftool -a -u -g1`, `strings`.
- Prüfe auf eingebettete/angehängte Inhalte: `binwalk` und untersuche das Dateiende (`tail | xxd`).
- Gehe je nach Container unterschiedlich vor:
  - PNG/BMP: Bit-Ebenen/LSB und Anomalien auf Chunk-Ebene.
  - JPEG: Metadaten + DCT-Domain-Tools (OutGuess/F5-artige Verfahren).
  - GIF/APNG: Frames extrahieren, Unterschiede zwischen Frames untersuchen, Palettentricks.

## Bit-Ebenen / LSB

### Technik

PNG/BMP sind bei CTFs beliebt, weil die Pixel so gespeichert werden, dass sich **Bits leicht manipulieren** lassen. Der klassische Mechanismus zum Verstecken/Extrahieren ist:

- Jeder Pixelkanal (R/G/B/A) hat mehrere Bits.
- Das **least significant bit** (LSB) jedes Kanals verändert das Bild nur minimal.
- Angreifer verstecken Daten in diesen niederwertigen Bits, manchmal mit einem Schrittweitenmuster, einer Permutation oder einer Auswahl bestimmter Kanäle.

Was bei Challenges zu erwarten ist:

- Die Payload befindet sich nur in einem Kanal (z. B. im LSB von `R`).
- Die Payload befindet sich im Alpha-Kanal.
- Die Payload wird nach dem Extrahieren komprimiert/kodiert.
- Die Nachricht ist über mehrere Ebenen verteilt oder mittels XOR zwischen Ebenen versteckt.

Weitere Verfahren, denen du begegnen kannst (implementierungsabhängig):

- **LSB matching** (nicht nur das Bit umschalten, sondern Anpassungen um +/-1, damit das Zielbit übereinstimmt)
- **Paletten-/indexbasiertes Verstecken** (indiziertes PNG/GIF: Payload in Farbindizes statt in rohen RGB-Werten)
- **Nur-Alpha-Payloads** (in der RGB-Ansicht vollständig unsichtbar)

### Tools

#### zsteg

`zsteg` prüft viele Muster zum Extrahieren von LSBs/Bit-Ebenen aus PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: führt eine Reihe von Transformationen aus (Metadaten, Bildtransformationen, Brute-Force-Tests von LSB-Varianten).
- `stegsolve`: manuelle visuelle Filter (Kanalisolierung, Ebenen untersuchen, XOR usw.).

Stegsolve-Download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-basierte Sichtbarkeitstricks

FFT dient nicht der LSB-Extraktion, sondern Fällen, in denen Inhalte gezielt im Frequenzraum oder in subtilen Mustern verborgen sind.

- EPFL-Demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webbasierte Triage wird häufig bei CTFs eingesetzt:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-Interna: Chunks, Beschädigungen und versteckte Daten

### Technik

PNG ist ein Chunk-basiertes Format. In vielen Challenges wird das payload auf Container-/Chunk-Ebene gespeichert und nicht in den Pixelwerten:

- **Zusätzliche Bytes nach `IEND`** (viele Viewer ignorieren nachfolgende Bytes)
- **Nicht standardisierte ancillary Chunks**, die payloads enthalten
- **Beschädigte Header**, die Abmessungen verbergen oder Parser außer Funktion setzen, bis sie repariert werden

Chunks mit hoher Signalwahrscheinlichkeit, die überprüft werden sollten:

- `tEXt` / `iTXt` / `zTXt` (Textmetadaten, manchmal komprimiert)
- `iCCP` (ICC-Profil) und andere ancillary Chunks, die als Träger verwendet werden
- `eXIf` (EXIF-Daten in PNG)

### Triage-Befehle

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Worauf zu achten ist:

- Ungewöhnliche Kombinationen aus Breite/Höhe/Bittiefe/Farbtyp
- CRC-/Chunk-Fehler (`pngcheck` zeigt normalerweise den genauen Offset an)
- Warnungen zu zusätzlichen Daten nach `IEND`

Wenn du eine detailliertere Chunk-Ansicht benötigst:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Nützliche Referenzen:

- PNG-Spezifikation (Struktur, Chunks): https://www.w3.org/TR/PNG/
- Dateiformat-Tricks (PNG/JPEG/GIF-Sonderfälle): https://github.com/corkami/docs

## JPEG: Metadaten, DCT-Domain-Tools und ELA-Einschränkungen

### Technik

JPEG wird nicht als rohe Pixel gespeichert, sondern in der DCT-Domain komprimiert. Deshalb unterscheiden sich JPEG-stego-Tools von PNG-LSB-Tools:

- Metadaten-/Kommentar-Payloads liegen auf Dateiebene (hohe Signalstärke und schnell zu prüfen)
- DCT-Domain-stego-Tools betten Bits in Frequenzkoeffizienten ein

In der Praxis sollte JPEG behandelt werden als:

- Container für Metadatensegmente (hohe Signalstärke, schnell zu prüfen)
- Komprimierter Signalbereich (DCT-Koeffizienten), in dem spezialisierte stego-Tools arbeiten

### Schnellprüfungen

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Aussagekräftige Fundstellen:

- EXIF/XMP/IPTC-Metadaten
- JPEG-Komment сегment (`COM`)
- Application-Segmente (`APP1` für EXIF, `APPn` für Vendor-Daten)

### Gängige Tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Wenn du gezielt auf steghide-Payloads in JPEGs stößt, solltest du `stegseek` verwenden (schnelleres Brute-Forcing als ältere Skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA hebt verschiedene Rekomprimierungsartefakte hervor. Es kann auf bearbeitete Bereiche hinweisen, ist aber für sich allein kein Stego-Detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animierte Bilder

### Technik

Bei animierten Bildern solltest du davon ausgehen, dass die Nachricht:

- In einem einzelnen Frame enthalten ist (einfach), oder
- Auf mehrere Frames verteilt ist (die Reihenfolge ist wichtig), oder
- Nur sichtbar ist, wenn du aufeinanderfolgende Frames vergleichst

### Frames extrahieren

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Dann behandeln Sie Frames wie normale PNGs: `zsteg`, `pngcheck`, Kanalisolierung.

Alternative Tools:

- `gifsicle --explode anim.gif` (schnelle Frame-Extraktion)
- `imagemagick`/`magick` für Transformationen einzelner Frames

Frame-Differencing ist oft entscheidend:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG-Pixelanzahlkodierung

- APNG-Container erkennen: `exiftool -a -G1 file.png | grep -i animation` oder `file`.
- Frames ohne Retiming extrahieren: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Nutzdaten wiederherstellen, die als Pixelanzahl pro Frame kodiert sind:

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

Animierte Challenges können jedes Byte als Anzahl einer bestimmten Farbe in jedem Frame codieren; durch Aneinanderhängen der Anzahlen wird die Nachricht rekonstruiert.<sup>[[1]](#references)</sup>

## Passphrase-geschützte Einbettung

Wenn du vermutest, dass die Einbettung durch eine Passphrase statt durch Manipulation auf Pixelebene geschützt ist, ist dies normalerweise der schnellste Weg.

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

## References

- [1] [Flagvent 2025 (Mittel) — pink, Wunschliste des Weihnachtsmanns, Weihnachtsmetadaten, Aufgezeichnetes Rauschen](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
