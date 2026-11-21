# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego reduces to one of these buckets:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Prioritize container-level evidence before deep content analysis. See the [general stego workflow](../workflow/) for file identification and carving before image-specific tests.

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

### Indexed-color palette indices

An indexed PNG or GIF stores a palette **index** per pixel, not an RGB triplet. Two indices can map to the same visible color, so converting to RGB before analysis can erase the hidden distinction. Inspect duplicate or near-duplicate palette entries, then render a binary mask of pixels using each suspicious index. This has revealed hidden text and QR-code changes in recent GIF challenges.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

For a single-frame indexed PNG (or the **first frame** of a GIF), keep Pillow's `P` mode and change `target` to an interesting index reported by the script. Check transparency (`tRNS` or GIF transparency index) as well as RGB when choosing indices.<sup>[[3]](#references)[[5]](#references)</sup>

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

For animated GIFs, inspect frames separately. Pillow normally converts later frames to RGB/RGBA while compositing; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` keeps `P` mode only while the palette does not change. If a frame has a local palette or has already been composited, inspect its original indexed frame data instead of treating RGB-converted pixels as indices.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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
- **Non-standard ancillary chunks** carrying payloads; see the [PNG chunk walker and carving workflow](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Corrupted headers** that hide dimensions or break parsers until fixed

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### PNG scanline-filter bytes as a carrier

PNG stores one filter-type byte (0–4) before each scanline in the decompressed `IDAT` stream. These bytes are not pixel values; decoded RGB pixels do not preserve the original filter choices, and re-encoding can change them. An encoder may legitimately vary filters, but deliberate patterns can encode a small message; a recent challenge used filter values 1–4 as two-bit symbols. Inspect the **original file** and concatenate all `IDAT` data before decompressing. For the following non-interlaced, 8-bit RGB/RGBA case, the stride is width times channel count; Adam7 images require pass-specific scanline widths.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>List PNG scanline filter bytes without re-encoding</summary>

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

Run it as `python3 filters.py suspect.png`. Check whether the filter sequence, rather than the decoded pixels, follows a plausible symbol mapping. The choice of mapping is challenge-specific; variation alone is not proof of steganography.<sup>[[3]](#references)[[7]](#references)</sup>

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

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA highlights different recompression artifacts; it can point you to regions that were edited, but it’s not a stego detector by itself:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

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

### APNG pixel-count encoding

- Detect APNG containers: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Extract frames without re-timing: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recover payloads encoded as per-frame pixel counts:

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

Animated challenges may encode each byte as the count of a specific color in each frame; concatenating the counts reconstructs the message.<sup>[[1]](#references)</sup>

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





## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024 write-up — Twisted Colors](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Portable Network Graphics (PNG) Specification, Third Edition](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Deep Down There's something in the water](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow image file formats — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [GIF89a specification](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — CTF write-up](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
