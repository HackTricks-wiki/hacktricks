# Stego-Workflow

{{#include ../../banners/hacktricks-training.md}}

Die meisten Stego-Probleme lassen sich durch systematische Triage schneller lösen als durch das Ausprobieren zufälliger Tools.

## Kernablauf

### Schnelle Triage-Checkliste

Das Ziel ist, effizient zwei Fragen zu beantworten:

1. Was ist der tatsächliche Container/das tatsächliche Format?
2. Befindet sich der Payload in den Metadaten, in angehängten Bytes, eingebetteten Dateien oder in Content-Level-Stego?

#### 1) Den Container identifizieren

```bash
file target
ls -lah target
```

Wenn `file` und die Dateiendung nicht übereinstimmen, untersuche die Signatur, anstatt der Endung zu vertrauen. Auch `file` arbeitet heuristisch und kann durch fehlerhafte oder polyglotte Eingaben getäuscht werden. Behandle gängige Formate gegebenenfalls als Container (zum Beispiel sind OOXML-Dokumente ZIP-Pakete).<sup>[[2]](#references)</sup>

#### 2) Suche nach Metadaten und offensichtlichen Zeichenfolgen

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Probiere mehrere Kodierungen aus:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Auf angehängte Daten / eingebettete Dateien prüfen

```bash
binwalk target
binwalk -e target
```

Wenn die Extraktion fehlschlägt, aber Signaturen gemeldet werden, die Offsets manuell mit `dd` ausschneiden und `file` erneut auf den ausgeschnittenen Bereich anwenden.

#### 4) Bei Bildern

- Anomalien untersuchen: `magick identify -verbose file`
- Bei PNG/BMP Bit-Ebenen/LSB aufzählen: `zsteg -a file.png`
- PNG-Struktur überprüfen: `pngcheck -v file.png`
- Visuelle Filter (Stegsolve / StegoVeritas) verwenden, wenn Inhalte durch Kanal-/Ebenentransformationen sichtbar werden könnten

#### 5) Bei Audio

- Zuerst ein Spektrogramm erstellen (Sonic Visualiser)
- Streams decodieren/untersuchen: `ffmpeg -v info -i file -f null -`
- Wenn das Audio strukturierten Tönen ähnelt, die DTMF-Decodierung testen

### Bewährte Werkzeuge

Diese erkennen häufige Fälle auf Containerebene: Metadaten-Payloads, angehängte Bytes und eingebettete Dateien mit irreführenden Dateiendungen.<sup>[[1]](#references)[[3]](#references)</sup>

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

Bei vielen Steganografie-Challenges handelt es sich um zusätzliche Bytes nach einer gültigen Datei oder um eingebettete Archive, die durch ihre Dateiendung getarnt werden.

#### Angehangene Payloads

Viele Formate ignorieren nachgestellte Bytes. Ein ZIP/PDF/Skript kann an einen Bild-/Audio-Container angehängt werden.

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

#### Magic bytes

Wenn `file` keine eindeutige Aussage liefert, suchen Sie mit `xxd` nach Magic Bytes und vergleichen Sie sie mit bekannten Signaturen:

```bash
xxd -g 1 -l 32 file
```

#### ZIP im Tarngewand

Probiere `7z` und `unzip` aus, auch wenn die Dateiendung nicht auf eine ZIP-Datei hinweist:

```bash
7z l file
unzip -l file
```

### Stego-nahe Merkwürdigkeiten

Schnelllinks zu Mustern, die regelmäßig im Zusammenhang mit Stego auftreten (QR aus Binärdaten, Braille usw.).

#### QR-Codes aus Binärdaten

Wenn die Länge eines Blobs eine perfekte Quadratzahl ist, könnte es sich um rohe Pixel für ein Bild/QR-Code handeln.

```python
import math
math.isqrt(2500)  # 50
```

Binär-zu-Bild-Hilfsprogramm:

- dCode-Hilfsprogramm für Binärbilder.<sup>[[5]](#references)</sup>

#### Brailleschrift

- Branah-Braille-Übersetzer.<sup>[[6]](#references)</sup>

Weitere Sammlungen von Steganografie-Hilfsprogrammen und technikspezifischen Ressourcen findest du im gebündelten stego-toolkit und in der kuratierten Liste von 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit – Docker-Image mit den beliebtesten gebündelten Steganografie-Tools](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376: Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binärbild](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille-Übersetzer](https://www.branah.com/braille-translator)
- [7] [0xRick – Steganografie-Ressourcen](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
