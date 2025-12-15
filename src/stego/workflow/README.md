# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Most stego problems are solved faster by systematic triage than by trying random tools.

## Core flow

### Quick triage checklist

The goal is to answer two questions efficiently:

1. What is the real container/format?
2. Is the payload in metadata, appended bytes, embedded files, or content-level stego?

#### 1) Identify the container

```bash
file target
ls -lah target
```

If `file` and the extension disagree, trust `file`. Treat common formats as containers when appropriate (e.g., OOXML documents are ZIP files).

#### 2) Look for metadata and obvious strings

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Try multiple encodings:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Check for appended data / embedded files

```bash
binwalk target
binwalk -e target
```

If extraction fails but signatures are reported, manually carve offsets with `dd` and re-run `file` on the carved region.

#### 4) If image

- Inspect anomalies: `magick identify -verbose file`
- If PNG/BMP, enumerate bit-planes/LSB: `zsteg -a file.png`
- Validate PNG structure: `pngcheck -v file.png`
- Use visual filters (Stegsolve / StegoVeritas) when content may be revealed by channel/plane transforms

#### 5) If audio

- Spectrogram first (Sonic Visualiser)
- Decode/inspect streams: `ffmpeg -v info -i file -f null -`
- If the audio resembles structured tones, test DTMF decoding

### Bread-and-butter tools

These catch the high-frequency container-level cases: metadata payloads, appended bytes, and embedded files disguised by extension.

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

Repo: https://github.com/korczis/foremost

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

### Containers, appended data, and polyglot tricks

Many steganography challenges are extra bytes after a valid file, or embedded archives disguised by extension.

#### Appended payloads

Many formats ignore trailing bytes. A ZIP/PDF/script can be appended to an image/audio container.

Fast checks:

```bash
binwalk file
tail -c 200 file | xxd
```

If you know an offset, carve with `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magic bytes

When `file` is confused, look for magic bytes with `xxd` and compare to known signatures:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Try `7z` and `unzip` even if the extension doesn’t say zip:

```bash
7z l file
unzip -l file
```

### Near-stego oddities

Quick links for patterns that regularly show up adjacent to stego (QR-from-binary, braille, etc).

#### QR codes from binary

If a blob length is a perfect square, it may be raw pixels for an image/QR.

```python
import math
math.isqrt(2500)  # 50
```

Binary-to-image helper:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Reference lists

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
