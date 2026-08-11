# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Die meisten Stego-Probleme lassen sich durch systematisches Triage schneller lösen als durch das Ausprobieren zufälliger Tools.

## Grundlegender Ablauf

### Checkliste für die schnelle Triage

Ziel ist es, effizient zwei Fragen zu beantworten:

1. Was ist der tatsächliche Container/das tatsächliche Format?
2. Befindet sich der payload in Metadaten, angehängten Bytes, eingebetteten Dateien oder in Content-Level-Stego?

#### 1) Den Container identifizieren
```bash
file target
ls -lah target
```
Wenn `file` und die Dateierweiterung nicht übereinstimmen, untersuche die Signatur, anstatt der Endung zu vertrauen. `file` arbeitet ebenfalls heuristisch und kann durch fehlerhafte oder Polyglot-Eingaben getäuscht werden. Behandle gängige Formate gegebenenfalls als Container (beispielsweise sind OOXML-Dokumente ZIP-Pakete).<sup>[[2]](#references)</sup>

#### 2) Nach Metadaten und offensichtlichen Zeichenketten suchen
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Probiere mehrere Encodings aus:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Auf angehängte Daten / eingebettete Dateien prüfen
```bash
binwalk target
binwalk -e target
```
Wenn die Extraktion fehlschlägt, aber Signaturen gemeldet werden, die Offsets manuell mit `dd` auslesen und `file` erneut auf den ausgelesenen Bereich anwenden.

#### 4) Wenn Bild

- Anomalien untersuchen: `magick identify -verbose file`
- Bei PNG/BMP Bit-Planes/LSB enumerieren: `zsteg -a file.png`
- PNG-Struktur validieren: `pngcheck -v file.png`
- Visuelle Filter (Stegsolve / StegoVeritas) verwenden, wenn Inhalte durch Kanal-/Plane-Transformationen sichtbar werden könnten

#### 5) Wenn Audio

- Zuerst ein Spektrogramm erstellen (Sonic Visualiser)
- Streams decodieren/untersuchen: `ffmpeg -v info -i file -f null -`
- Wenn das Audio strukturierten Tönen ähnelt, DTMF-Decoding testen

### Standardwerkzeuge

Diese erkennen häufige Fälle auf Container-Ebene: Payloads in Metadaten, angehängte Bytes und eingebettete Dateien, die durch ihre Dateiendung getarnt werden.<sup>[[1]](#references)[[3]](#references)</sup>

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
#### Datei / Zeichenketten
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Container, angehängte Daten und Polyglot-Tricks

Viele Steganografie-Challenges bestehen aus zusätzlichen Bytes nach einer gültigen Datei oder aus eingebetteten Archiven, die durch ihre Dateiendung getarnt sind.

#### Angefügte Payloads

Viele Formate ignorieren nachfolgende Bytes. Ein ZIP/PDF/Script kann an einen Bild-/Audio-Container angehängt werden.

Schnellprüfungen:
```bash
binwalk file
tail -c 200 file | xxd
```
Wenn du einen Offset kennst, extrahiere mit `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic Bytes

Wenn `file` verwirrt ist, suchen Sie mit `xxd` nach Magic Bytes und vergleichen Sie sie mit bekannten Signaturen:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Versuche `7z` und `unzip`, auch wenn die Erweiterung nicht auf zip hindeutet:
```bash
7z l file
unzip -l file
```
### Ungewöhnliche Phänomene im Umfeld von stego

Schnelllinks zu Mustern, die regelmäßig im Umfeld von stego auftreten (QR aus Binärdaten, Braille usw.).

#### QR-Codes aus Binärdaten

Wenn die Länge eines Blobs ein perfektes Quadrat ist, könnte es sich um rohe Pixel für ein Bild/QR handeln.
```python
import math
math.isqrt(2500)  # 50
```
Binary-zu-Bild-Hilfswerkzeug:

- dCode Binary-Image-Hilfswerkzeug.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille-Übersetzer.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker-Image mit den beliebtesten gebündelten Steganography-Tools](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging-Konventionen](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binärbild](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille-Übersetzer](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
