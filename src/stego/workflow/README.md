# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Die meisten stego-Probleme lassen sich durch systematische Triage schneller lösen als durch das Ausprobieren zufälliger Tools.

## Kernablauf

### Schnelle Triage-Checkliste

Ziel ist es, zwei Fragen effizient zu beantworten:

1. Was ist der tatsächliche Container/Format?
2. Befindet sich die payload in metadata, appended bytes, embedded files oder content-level stego?

#### 1) Container identifizieren
```bash
file target
ls -lah target
```
Wenn `file` und die Dateiendung nicht übereinstimmen, vertraue `file`. Behandle gängige Formate bei Bedarf als Container (z. B. OOXML-Dokumente sind ZIP-Dateien).

#### 2) Suche nach Metadaten und offensichtlichen strings
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Mehrere encodings ausprobieren:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Auf angehängte Daten / eingebettete Dateien prüfen
```bash
binwalk target
binwalk -e target
```
Wenn die Extraktion fehlschlägt, aber Signaturen gemeldet werden, Offsets manuell mit `dd` ausschneiden und `file` auf den ausgeschnittenen Bereich erneut ausführen.

#### 4) Falls es sich um ein Bild handelt

- Anomalien untersuchen: `magick identify -verbose file`
- Bei PNG/BMP Bit-Ebenen/LSB aufzählen: `zsteg -a file.png`
- PNG-Struktur validieren: `pngcheck -v file.png`
- Visuelle Filter verwenden (Stegsolve / StegoVeritas), wenn Inhalte durch Kanal-/Ebenentransformationen sichtbar werden könnten

#### 5) Falls es sich um Audio handelt

- Zuerst Spektrogramm erstellen (Sonic Visualiser)
- Streams decodieren/untersuchen: `ffmpeg -v info -i file -f null -`
- Wenn die Audiodatei strukturierten Tönen ähnelt, DTMF-Decodierung testen

### Grundlegende Werkzeuge

Diese fangen die häufig vorkommenden Container‑Ebene-Fälle ab: Metadaten-Payloads, angehängte Bytes und eingebettete Dateien, die durch die Dateiendung verschleiert sind.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
#### Foremost
```bash
foremost -i file
```
Ich kann das für dich übersetzen — bitte füge hier den Inhalt von src/stego/workflow/README.md ein.  
Ich übersetze dann den relevanten englischen Text ins Deutsche und lasse Code, Links, Pfade, Tags und Markdown/HTML-Syntax unverändert.
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
### Container, angehängte Daten und polyglot tricks

Viele steganography-Herausforderungen bestehen aus zusätzlichen Bytes nach einer gültigen Datei oder aus eingebetteten Archiven, die durch die Dateiendung getarnt sind.

#### Angehängte payloads

Viele Formate ignorieren nachfolgende Bytes. Eine ZIP-, PDF- oder script-Datei kann an einen image-/audio-Container angehängt werden.

Schnelle Checks:
```bash
binwalk file
tail -c 200 file | xxd
```
Wenn du einen Offset kennst, carve mit `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wenn `file` keine eindeutige Erkennung liefert, suche nach magic bytes mit `xxd` und vergleiche sie mit bekannten Signaturen:
```bash
xxd -g 1 -l 32 file
```
#### Zip getarnt

Probiere `7z` und `unzip`, auch wenn die Dateiendung nicht .zip lautet:
```bash
7z l file
unzip -l file
```
### Nahe bei stego auftauchende Auffälligkeiten

Schnellzugriffe auf Muster, die regelmäßig neben stego auftreten (QR-from-binary, braille, etc).

#### QR-Codes aus binary

Wenn die blob-Länge eine perfekte Quadratzahl ist, kann es sich um rohe Pixel für ein Bild/QR handeln.
```python
import math
math.isqrt(2500)  # 50
```
Binär-zu-Bild-Helfer:

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Referenzlisten

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
