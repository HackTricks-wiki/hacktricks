# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego reduces to one of these buckets:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Prioritize container-level evidence before deep content analysis:

- Validate the file and inspect structure: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Extract metadata and visible strings: `exiftool -a -u -g1`, `strings`.
- Check for embedded/appended content: `binwalk` and end-of-file inspection (`tail | xxd`).
- Branch by container:
  - PNG/BMP: bit-planes/LSB and chunk-level anomalies.
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
  - GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP are popular in CTFs because they store pixels in a way that makes **bit-level manipulation** easy. The classic hide/extract mechanism is:

- Each pixel channel (R/G/B/A) has multiple bits.
- The **least significant bit** (LSB) of each channel changes the image very little.
- Attackers hide data in those low-order bits, sometimes with a stride, permutation, or per-channel choice.

What to expect in challenges:

- The payload is in one channel only (e.g., `R` LSB).
- The payload is in the alpha channel.
- Payload is compressed/encoded after extraction.
- The message is spread across planes or hidden via XOR between planes.

Additional families you may encounter (implementation-dependent):

- **LSB matching** (not just flipping the bit, but +/-1 adjustments to match target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices rather than raw RGB)
- **Alpha-only payloads** (completely invisible in RGB view)

### Tooling

#### zsteg

`zsteg` enumerates many LSB/bit-plane extraction patterns for PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: runs a battery of transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: manual visual filters (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT is not LSB extraction; it is for cases where content is deliberately hidden in frequency space or subtle patterns.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG is a chunked format. In many challenges the payload is stored at the container/chunk level rather than in pixel values:

- **Extra bytes after `IEND`** (many viewers ignore trailing bytes)
- **Non-standard ancillary chunks** carrying payloads
- **Corrupted headers** that hide dimensions or break parsers until fixed

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Triage commands

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

What to look for:

- Weird width/height/bit-depth/colour-type combinations
- CRC/chunk errors (pngcheck usually points to the exact offset)
- Warnings about additional data after `IEND`

If you need a deeper chunk view:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Useful references:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Technique

JPEG is not stored as raw pixels; it’s compressed in the DCT domain. That’s why JPEG stego tools differ from PNG LSB tools:

- Metadata/comment payloads are file-level (high-signal and quick to inspect)
- DCT-domain stego tools embed bits into frequency coefficients

Operationally, treat JPEG as:

- A container for metadata segments (high-signal, quick to inspect)
- A compressed signal domain (DCT coefficients) where specialized stego tools operate

### Quick checks

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

High-signal locations:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA highlights different recompression artifacts; it can point you to regions that were edited, but it’s not a stego detector by itself:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Animated images

### Technique

For animated images, assume the message is:

- In a single frame (easy), or
- Spread across frames (ordering matters), or
- Only visible when you diff consecutive frames

### Extract frames

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Then treat frames like normal PNGs: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (fast frame extraction)
- `imagemagick`/`magick` for per-frame transforms

Frame differencing is often decisive:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

## Password-protected embedding

If you suspect embedding protected by a passphrase rather than pixel-level manipulation, this is usually the fastest path.

### steghide

Supports `JPEG, BMP, WAV, AU` and can embed/extract encrypted payloads.

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

Supports PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
