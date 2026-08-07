# Stego-Workflow

{{#include ../../banners/hacktricks-training.md}}

Die meisten Stego-Probleme lassen sich durch systematische Triage schneller lösen als durch das Ausprobieren zufälliger Tools.

## Kernablauf

### Checkliste für die schnelle Triage

Das Ziel besteht darin, zwei Fragen effizient zu beantworten:

1. Was ist der tatsächliche Container/das tatsächliche Format?
2. Befindet sich der Payload in den Metadaten, in angehängten Bytes, in eingebetteten Dateien oder in Content-Level-Stego?

#### 1) Den Container identifizieren
```bash
file target
ls -lah target
```
Wenn `file` und die Dateierweiterung nicht übereinstimmen, vertraue auf `file`. Behandle gängige Formate bei Bedarf als Container (z. B. sind OOXML-Dokumente ZIP-Dateien).

#### 2) Nach Metadaten und offensichtlichen Strings suchen
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Mehrere Encodings ausprobieren:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Auf angehängte Daten / eingebettete Dateien prüfen
```bash
binwalk target
binwalk -e target
```
Wenn die Extraktion fehlschlägt, aber Signaturen gemeldet werden, carve die Offsets manuell mit `dd` und führe `file` erneut für den extrahierten Bereich aus.

#### 4) Wenn Bild

- Anomalien untersuchen: `magick identify -verbose file`
- Bei PNG/BMP Bit-Planes/LSB enumerieren: `zsteg -a file.png`
- PNG-Struktur validieren: `pngcheck -v file.png`
- Visuelle Filter (Stegsolve / StegoVeritas) verwenden, wenn Inhalte durch Kanal-/Plane-Transformationen sichtbar werden könnten

#### 5) Wenn Audio

- Zuerst ein Spektrogramm erstellen (Sonic Visualiser)
- Streams dekodieren/untersuchen: `ffmpeg -v info -i file -f null -`
- Wenn das Audio strukturierten Tönen ähnelt, DTMF-Dekodierung testen

### Grundlegende Tools

Diese erkennen die häufigsten Fälle auf Container-Ebene: Metadaten-Payloads, angehängte Bytes und eingebettete Dateien, die durch ihre Dateiendung getarnt sind.<sup>[[1]](#references)</sup>

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
#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### Datei / strings
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

#### Angehängte Payloads

Viele Formate ignorieren nachfolgende Bytes. Ein ZIP/PDF/Script kann an einen Bild-/Audio-Container angehängt werden.

Schnellprüfungen:
```bash
binwalk file
tail -c 200 file | xxd
```
Wenn du einen Offset kennst, verwende `dd` zum Carving:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wenn `file` sich nicht sicher ist, suche mit `xxd` nach Magic Bytes und vergleiche sie mit bekannten Signaturen:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Versuche `7z` und `unzip`, auch wenn die Dateiendung nicht auf eine ZIP-Datei hinweist:
```bash
7z l file
unzip -l file
```
### Stego-nahe Besonderheiten

Schnelllinks für Muster, die regelmäßig neben Stego auftreten (QR aus Binärdaten, Braille usw.).

#### QR-Codes aus Binärdaten

Wenn die Länge eines Blobs ein perfektes Quadrat ist, könnte es sich um Rohpixel für ein Bild/QR handeln.
```python
import math
math.isqrt(2500)  # 50
```
Binär-zu-Bild-Hilfsprogramm:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Referenzen

- [1] [DominicBreuker/stego-toolkit - Docker-Image mit den beliebtesten gebündelten Steganografie-Tools](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
