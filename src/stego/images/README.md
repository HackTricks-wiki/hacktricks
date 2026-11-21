# Bild-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Die Bild-Stego-Aufgaben in den meisten CTFs fallen in eine dieser Kategorien:

- LSB/Bit-Ebenen (PNG/BMP)
- Metadaten-/Kommentar-Payloads
- Seltsame PNG-Chunks / Reparatur beschädigter Dateien
- JPEG-DCT-Domain-Tools (OutGuess usw.)
- Frame-basiert (GIF/APNG)

## Schnelle Triage

Priorisiere Hinweise auf Containerebene, bevor du den Inhalt genauer analysierst. Siehe den [allgemeinen Stego-Workflow](../workflow/) zur Dateierkennung und zum Carving vor bildspezifischen Tests.

- Überprüfe die Datei und untersuche ihre Struktur: `file`, `magick identify -verbose`, Formatvalidatoren (z. B. `pngcheck`).
- Extrahiere Metadaten und sichtbare Strings: `exiftool -a -u -g1`, `strings`.
- Suche nach eingebetteten/angehängten Inhalten: `binwalk` und Untersuchung des Dateiende (`tail | xxd`).
- Wähle den passenden Container:
  - PNG/BMP: Bit-Ebenen/LSB und Anomalien auf Chunk-Ebene.
  - JPEG: Metadaten + DCT-Domain-Tools (OutGuess/F5-ähnliche Familien).
  - GIF/APNG: Frame-Extraktion, Frame-Differenzierung, Palettentricks.

## Bit-Ebenen / LSB

### Technik

PNG/BMP sind in CTFs beliebt, weil sie Pixel so speichern, dass **Manipulationen auf Bitebene** einfach sind. Der klassische Mechanismus zum Verstecken/Extrahieren funktioniert so:

- Jeder Pixelkanal (R/G/B/A) hat mehrere Bits.
- Das **Least Significant Bit** (LSB) jedes Kanals verändert das Bild nur minimal.
- Angreifer verstecken Daten in diesen niederwertigen Bits, manchmal mit einem Stride, einer Permutation oder einer Auswahl pro Kanal.

Was bei Challenges zu erwarten ist:

- Der Payload befindet sich in nur einem Kanal (z. B. im LSB von `R`).
- Der Payload befindet sich im Alpha-Kanal.
- Der Payload wird nach der Extraktion komprimiert/kodiert.
- Die Nachricht ist über mehrere Ebenen verteilt oder durch XOR zwischen Ebenen versteckt.

Weitere mögliche Verfahren (implementierungsabhängig):

- **LSB matching** (das Bit wird nicht nur umgeschaltet, sondern der Wert um +/-1 angepasst, damit er dem Zielbit entspricht)
- **Paletten-/indexbasiertes Verstecken** (indiziertes PNG/GIF: Payload in Farb-Indizes statt in rohen RGB-Werten)
- **Nur-Alpha-Payloads** (in der RGB-Ansicht vollständig unsichtbar)

### Indizes indizierter Farbpaletten

Ein indiziertes PNG oder GIF speichert pro Pixel einen **Palettenindex**, kein RGB-Tripel. Zwei Indizes können derselben sichtbaren Farbe entsprechen. Daher kann eine Umwandlung in RGB vor der Analyse den versteckten Unterschied beseitigen. Untersuche doppelte oder nahezu identische Paletteneinträge und rendere anschließend eine binäre Maske der Pixel, die jeden verdächtigen Index verwenden. So wurden in aktuellen GIF-Challenges versteckter Text und Änderungen an QR-Codes entdeckt.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Bei einem indizierten PNG mit einem Frame (oder dem **ersten Frame** eines GIFs) behältst du Pillow im `P`-Modus und änderst `target` auf einen interessanten, vom Skript gemeldeten Index. Berücksichtige bei der Auswahl der Indizes neben RGB auch die Transparenz (`tRNS` oder den GIF-Transparenzindex).<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Bei animierten GIFs solltest du die Frames einzeln untersuchen. Pillow wandelt spätere Frames beim Compositing normalerweise in RGB/RGBA um; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` behält den P-Modus nur bei, solange sich die Palette nicht ändert. Wenn ein Frame eine lokale Palette hat oder bereits composited wurde, untersuche stattdessen seine ursprünglichen indizierten Frame-Daten, anstatt RGB-konvertierte Pixel als Indizes zu behandeln.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Tools

#### zsteg

`zsteg` führt zahlreiche LSB-/Bit-Plane-Extraktionsmuster für PNG/BMP auf:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: führt eine Reihe von Transformationen aus (Metadaten, Bildtransformationen, Brute-Force-Suche nach LSB-Varianten).
- `stegsolve`: manuelle visuelle Filter (Kanalisolierung, Ebenenprüfung, XOR usw.).

Stegsolve-Download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-basierte Sichtbarkeitstricks

FFT ist keine LSB-Extraktion. Sie eignet sich für Fälle, in denen Inhalte absichtlich im Frequenzraum oder in subtilen Mustern verborgen sind.

- EPFL-Demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webbasierte Triage wird häufig bei CTFs eingesetzt:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-Interna: Chunks, Beschädigungen und verborgene Daten

### Technik

PNG ist ein Chunk-basiertes Format. Bei vielen Challenges ist die Payload auf Container-/Chunk-Ebene statt in den Pixelwerten gespeichert:

- **Zusätzliche Bytes nach `IEND`** (viele Viewer ignorieren nachfolgende Bytes)
- **Nicht standardisierte Ancillary-Chunks**, die Payloads enthalten; siehe den [PNG-Chunk-Scanner und Carving-Workflow](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Beschädigte Header**, die Abmessungen verbergen oder Parser bis zur Reparatur beeinträchtigen

Wichtige Chunk-Positionen, die überprüft werden sollten:

- `tEXt` / `iTXt` / `zTXt` (Textmetadaten, manchmal komprimiert)
- `iCCP` (ICC-Profil) und andere Ancillary-Chunks, die als Träger verwendet werden
- `eXIf` (EXIF-Daten in PNG)

### PNG-Scanline-Filterbytes als Träger

PNG speichert vor jeder Scanline im dekomprimierten `IDAT`-Stream ein Filtertyp-Byte (0–4). Diese Bytes sind keine Pixelwerte; dekodierte RGB-Pixel bewahren die ursprünglichen Filterentscheidungen nicht, und eine erneute Kodierung kann sie ändern. Ein Encoder kann die Filter legitimerweise variieren, aber gezielte Muster können eine kurze Nachricht kodieren; bei einer kürzlich durchgeführten Challenge wurden die Filterwerte 1–4 als Zwei-Bit-Symbole verwendet. Untersuche die **Originaldatei** und verkette alle `IDAT`-Daten vor dem Dekomprimieren. Für den folgenden Fall mit nicht interlaced 8-Bit-RGB/RGBA entspricht der Stride der Breite multipliziert mit der Kanalanzahl; bei Adam7-Bildern sind pass-spezifische Scanline-Breiten erforderlich.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>PNG-Scanline-Filterbytes ohne erneute Kodierung auflisten</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Führe es mit `python3 filters.py suspect.png` aus. Prüfe, ob die Filtersequenz statt der decodierten Pixel einer plausiblen Symbolzuordnung folgt. Die Wahl der Zuordnung hängt von der jeweiligen Challenge ab; Abweichungen allein sind kein Beweis für Steganografie.<sup>[[3]](#references)[[7]](#references)</sup>

### Triage-Befehle

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Worauf zu achten ist:

- Ungewöhnliche Kombinationen aus Breite/Höhe/Bittiefe/Farbtyp
- CRC-/Chunk-Fehler (pngcheck zeigt normalerweise den genauen Offset an)
- Warnungen zu zusätzlichen Daten nach `IEND`

Wenn du eine detailliertere Chunk-Ansicht benötigst:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Nützliche Referenzen:

- PNG-Spezifikation (Struktur, Chunks): https://www.w3.org/TR/PNG/
- Dateiformat-Tricks (PNG/JPEG/GIF-Sonderfälle): https://github.com/corkami/docs

## JPEG: Metadaten, Tools für die DCT-Domäne und Grenzen von ELA

### Technik

JPEG wird nicht als rohe Pixel gespeichert, sondern in der DCT-Domäne komprimiert. Deshalb unterscheiden sich JPEG-stego-Tools von PNG-LSB-Tools:

- Metadaten-/Kommentar-Payloads liegen auf Dateiebene (hohes Signal und schnell zu prüfen)
- Stego-Tools für die DCT-Domäne betten Bits in Frequenzkoeffizienten ein

In der Praxis sollte JPEG behandelt werden als:

- Ein Container für Metadatensegmente (hohes Signal, schnell zu prüfen)
- Eine komprimierte Signaldomäne (DCT-Koeffizienten), in der spezialisierte Stego-Tools arbeiten

### Schnelle Prüfungen

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Signalstarke Fundstellen:

- EXIF/XMP/IPTC-Metadaten
- JPEG-Kommentarsegment (`COM`)
- Anwendungssegmente (`APP1` für EXIF, `APPn` für Herstellerdaten)

### Gängige Tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Wenn Sie gezielt nach steghide-Payloads in JPEGs suchen, sollten Sie `stegseek` verwenden (schnelleres Brute-Forcing als mit älteren Skripten):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA hebt unterschiedliche Artefakte durch erneute Komprimierung hervor. So können Bereiche sichtbar werden, die bearbeitet wurden, aber ELA ist für sich allein kein Stego-Detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animierte Bilder

### Technik

Bei animierten Bildern sollten Sie davon ausgehen, dass die Nachricht:

- In einem einzelnen Frame steckt (einfach), oder
- Über mehrere Frames verteilt ist (die Reihenfolge ist wichtig), oder
- Nur sichtbar ist, wenn Sie aufeinanderfolgende Frames vergleichen

### Frames extrahieren

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Dann behandle Frames wie normale PNGs: `zsteg`, `pngcheck`, Kanalisolierung.

Alternative Tools:

- `gifsicle --explode anim.gif` (schnelle Frame-Extraktion)
- `imagemagick`/`magick` für Transformationen einzelner Frames

Frame-Differencing ist oft entscheidend:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG-Pixelanzahlkodierung

- APNG-Container erkennen: `exiftool -a -G1 file.png | grep -i animation` oder `file`.
- Frames ohne Änderung des Timings extrahieren: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

Animierte Herausforderungen können jedes Byte als Anzahl einer bestimmten Farbe in jedem Frame kodieren; durch Aneinanderhängen der Anzahlen lässt sich die Nachricht rekonstruieren.<sup>[[1]](#references)</sup>

## Passwortgeschütztes Einbetten

Wenn du vermutest, dass das Einbetten durch eine Passphrase statt durch Manipulation auf Pixelebene geschützt ist, ist dies normalerweise der schnellste Weg.

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

- [1] [Flagvent 2025 (Medium) — pink, Wunschliste des Weihnachtsmanns, Weihnachts-Metadaten, Aufgezeichnetes Rauschen](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024-Bericht — Verdrehte Farben](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Portable Network Graphics (PNG)-Spezifikation, dritte Ausgabe](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Tief unten gibt es etwas im Wasser](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow-Bilddateiformate — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [GIF89a-Spezifikation](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — CTF-Bericht](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
