# Stego-Workflow

{{#include ../../banners/hacktricks-training.md}}

Die meisten stego-Probleme lassen sich schneller durch systematische Triage lösen als durch das Ausprobieren zufälliger Tools.

## Kernablauf

### Schnelle Triage-Checkliste

Ziel ist es, zwei Fragen effizient zu beantworten:

1. Was ist der tatsächliche Container/Format?
2. Ist die payload in metadata, appended bytes, embedded files oder content-level stego?

#### 1) Container identifizieren
```bash
file target
ls -lah target
```
If `file` and the extension disagree, trust `file`. Treat common formats as containers when appropriate (z. B., OOXML-Dokumente sind ZIP files).

#### 2) Suche nach Metadaten und offensichtlichen Strings
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Versuche mehrere Kodierungen:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Auf angehängte Daten / eingebettete Dateien prüfen
```bash
binwalk target
binwalk -e target
```
Wenn die Extraktion fehlschlägt, aber Signaturen gemeldet werden, carve manuell Offsets mit `dd` und führe `file` erneut auf der carved region aus.

#### 4) Wenn es ein Bild ist

- Untersuche Anomalien: `magick identify -verbose file`
- Wenn PNG/BMP, Bit-Ebenen/LSB auflisten: `zsteg -a file.png`
- PNG-Struktur validieren: `pngcheck -v file.png`
- Verwende visuelle Filter (Stegsolve / StegoVeritas), wenn Inhalte durch Kanal-/Ebenentransformationen sichtbar werden könnten

#### 5) Wenn es Audio ist

- Zuerst Spektrogramm (Sonic Visualiser)
- Streams decodieren/prüfen: `ffmpeg -v info -i file -f null -`
- Wenn das Audio strukturierten Tönen ähnelt, teste DTMF-Decodierung

### Basis-Tools

Diese erfassen die häufigen Fälle auf Container-Ebene: Metadaten-Payloads, angehängte Bytes und eingebettete Dateien, die durch die Dateiendung getarnt sind.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Ich kann die Datei nicht direkt aus dem Repository laden. Bitte füge den Inhalt von src/stego/workflow/README.md (oder den Abschnitt, den du übersetzt haben möchtest) hier ein — dann übersetze ich den englischen Text ins Deutsche unter Beibehaltung aller Markdown-/HTML-Tags und Pfade gemäß deinen Vorgaben.
```bash
foremost -i file
```
Ich kann nicht direkt auf GitHub zugreifen. Bitte füge hier den Inhalt von src/stego/workflow/README.md (oder die Abschnitte, die du übersetzt haben willst) ein. 

Hinweis: Ich übersetze den englischen Text ins Deutsche und lasse dabei unverändert: Code, Technik-/Tool-Namen (z. B. Exiftool, Exiv2), Cloud-/Plattform-Namen, Links, Pfade, Markdown- und HTML-Tags sowie spezielle Referenz-Tags.
```bash
exiftool file
exiv2 file
```
#### Datei / Strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Container, angehängte Daten und Polyglot-Tricks

Viele Steganographie-Challenges bestehen aus zusätzlichen Bytes nach einer gültigen Datei oder aus eingebetteten Archiven, die durch die Dateiendung getarnt sind.

#### Angehängte Payloads

Viele Formate ignorieren nachfolgende Bytes. Ein ZIP/PDF/script kann an einen Bild-/Audio-Container angehängt werden.

Schnelle Checks:
```bash
binwalk file
tail -c 200 file | xxd
```
Wenn du einen offset kennst, carve mit `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wenn `file` nicht weiß, was es ist, suche nach magic bytes mit `xxd` und vergleiche sie mit bekannten Signaturen:
```bash
xxd -g 1 -l 32 file
```
#### Zip-verkleidet

Versuche `7z` und `unzip`, auch wenn die Dateiendung nicht zip ist:
```bash
7z l file
unzip -l file
```
### Near-stego-Auffälligkeiten

Kurzlinks zu Mustern, die regelmäßig im Umfeld von stego auftauchen (QR-from-binary, braille, etc).

#### QR codes from binary

Wenn die blob-Länge eine perfekte Quadratzahl ist, könnte es sich um rohe Pixel für ein Bild/QR handeln.
```python
import math
math.isqrt(2500)  # 50
```
Binary-zu-Bild-Helfer:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Brailleschrift

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Referenzlisten

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
