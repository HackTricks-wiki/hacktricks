# Stego-Workflow

{{#include ../../banners/hacktricks-training.md}}

Die meisten Stego-Probleme lassen sich durch systematische Triage schneller lösen als durch das Ausprobieren zufälliger Tools.

## Kernablauf

### Checkliste für die schnelle Triage

Das Ziel besteht darin, zwei Fragen effizient zu beantworten:

1. Was ist der tatsächliche Container/das tatsächliche Format?
2. Befindet sich die Payload in Metadaten, angehängten Bytes, eingebetteten Dateien oder in Content-Level-Stego?

#### 1) Den Container identifizieren
```bash
file target
ls -lah target
```
Wenn `file` und die Dateierweiterung nicht übereinstimmen, untersuche die Signatur, anstatt der Endung zu vertrauen. Auch `file` arbeitet heuristisch und kann durch fehlerhafte oder polyglotte Eingaben getäuscht werden. Behandle gängige Formate bei Bedarf als Container (beispielsweise sind OOXML-Dokumente ZIP-Pakete).<sup>[[2]](#references)</sup>

#### 2) Suche nach Metadaten und offensichtlichen Zeichenketten
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Mehrere Kodierungen ausprobieren:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Nach angehängten Daten / eingebetteten Dateien suchen
```bash
binwalk target
binwalk -e target
```
Wenn die Extraktion fehlschlägt, aber Signaturen gemeldet werden, carve die Offsets manuell mit `dd` heraus und führe `file` erneut für den herausgeschnittenen Bereich aus.

#### 4) Wenn Bild

- Anomalien untersuchen: `magick identify -verbose file`
- Bei PNG/BMP Bit-Planes/LSB aufzählen: `zsteg -a file.png`
- PNG-Struktur validieren: `pngcheck -v file.png`
- Visuelle Filter (Stegsolve / StegoVeritas) verwenden, wenn Inhalte durch Kanal-/Plane-Transformationen sichtbar werden könnten

#### 5) Wenn Audio

- Zuerst ein Spektrogramm erstellen (Sonic Visualiser)
- Streams decodieren/untersuchen: `ffmpeg -v info -i file -f null -`
- Wenn das Audio strukturierten Tönen ähnelt, DTMF-Decodierung testen

### Bewährte Standardtools

Diese erkennen häufige Fälle auf Container-Ebene: Metadaten-Payloads, angehängte Bytes und eingebettete Dateien, die durch eine falsche Dateiendung getarnt werden.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
Projekt-Repository: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### file / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Container, angehängte Daten und Polyglot-Tricks

Viele Steganografie-Herausforderungen bestehen aus zusätzlichen Bytes nach einer gültigen Datei oder aus eingebetteten Archiven, die durch ihre Dateiendung getarnt sind.

#### Angefügte Payloads

Viele Formate ignorieren nachfolgende Bytes. Ein ZIP/PDF/Script kann an einen Bild-/Audio-Container angehängt werden.

Schnelle Prüfungen:
```bash
binwalk file
tail -c 200 file | xxd
```
Wenn du einen Offset kennst, extrahiere ihn mit `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wenn `file` keine eindeutige Zuordnung liefert, suche mit `xxd` nach Magic Bytes und vergleiche sie mit bekannten Signaturen:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Versuche `7z` und `unzip`, auch wenn die Dateiendung nicht auf zip hindeutet:
```bash
7z l file
unzip -l file
```
### Stego-nahe Besonderheiten

Schnellzugriffe auf Muster, die regelmäßig neben Stego auftreten (QR-from-binary, Braille usw.).

#### QR-Codes aus Binary

Wenn die Länge eines Blobs ein perfektes Quadrat ist, könnte es sich um rohe Pixel für ein Bild/einen QR-Code handeln.
```python
import math
math.isqrt(2500)  # 50
```
Binär-zu-Bild-Hilfsprogramm:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille-Übersetzer.<sup>[[6]](#references)</sup>

Für umfangreichere Sammlungen von Steganography-Utilities und technikspezifischen Ressourcen siehe das gebündelte stego-toolkit und die kuratierte Liste von 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker-Image mit den beliebtesten gebündelten Steganography-Tools](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binärbild](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille-Übersetzer](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganography-Ressourcen](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
