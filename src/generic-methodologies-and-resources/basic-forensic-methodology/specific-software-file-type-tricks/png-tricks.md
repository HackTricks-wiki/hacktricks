# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** are very common in **CTFs**, **incident response**, and **malware staging** because they are **lossless**, **chunk-based**, and many tools will happily render them even when they contain **extra metadata**, **appended payloads**, or **partially corrupted chunks**.

Treat a PNG as a **container**, not just as an image.

## Quick triage

Start with container-level checks before jumping into LSB stego. For the bit-plane/LSB workflow, check [the dedicated image stego page](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Useful things to look for:

- **Unexpected ancillary chunks** such as `tEXt`, `zTXt`, `iTXt`, `eXIf`, or `iCCP`
- **CRC errors** or malformed chunk lengths
- **Additional data after `IEND`**
- **Multiple `IEND` markers** or recoverable `IDAT` fragments after the formal end of the file
- A file that is a valid PNG **and** also looks like a ZIP/PDF/script when carved

Remember the minimum valid structure is usually:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## Trailing data after `IEND`

One of the highest-signal PNG artefacts is **data appended after the final `IEND` chunk**. Many decoders ignore it, which makes it useful for:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Recovering older image data** from buggy editors

Quick detection:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

A byte search for `IEND` is only a hint: the same bytes can occur in chunk data or in a forged trailer. To carve reliably, walk the length-prefixed chunks from the PNG signature and stop at the first structural `IEND`; the [chunk walker below](#extract-ancillary-chunk-payloads) also saves the trailer.<sup>[[6]](#references)</sup>

Also try generic archive parsers directly against the PNG or the carved trailer:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Acropalypse-style recovery of cropped/redacted screenshots

A very practical recent PNG forensic trick is checking whether a screenshot editor **overwrote** a PNG without **truncating** the old file first. In those cases, bytes from the **previous image** can remain after `IEND`, and sometimes extra `IDAT` data can be partially reconstructed.

This became well known with **aCropalypse** (Google Pixel Markup) and the related **Windows Snipping Tool** issue.<sup>[[3]](#references)</sup> In practice, if a "cropped" or "redacted" PNG still contains old trailing data, you may be able to recover part of the original screenshot.<sup>[[1]](#references)</sup>

Practical workflow:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Signs that strongly justify deeper analysis:

- `pngcheck` reports **additional data after `IEND`**
- You find **more than one `IEND`**
- You find **extra `IDAT` chunks** after the apparent end of the image
- The screenshot came from a device/editor known to have been affected

If this happens, feed the file to an **aCropalypse recovery tool** before treating the redaction as trustworthy.

## Chunk abuse that matters in practice

The most interesting PNG chunks for investigations are usually not the obvious image ones, but the chunks that can carry **text**, **metadata**, or **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata and compressed text
- `eXIf` – EXIF data inside PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data in indexed images, but also useful in payload-smuggling scenarios.<sup>[[2]](#references)</sup>

Dump them with:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

For offensive payload persistence inside PNG chunks (for example **PLTE**, **IDAT**, or **tEXt** tricks that survive some PHP image transformations), check the more detailed upload-focused notes here:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Extract ancillary chunk payloads

An attacker can place arbitrary bytes in an **unknown ancillary chunk before `IEND`**. Ordinary PNG decoders can ignore an unknown ancillary chunk, while a script that fetches the image as bytes can read and use the payload; opening the PNG alone does not execute it.<sup>[[4]](#references)[[6]](#references)</sup> The original research demonstrated a compressed and encrypted custom chunk.<sup>[[4]](#references)</sup> A later browser example used the extracted bytes to supply HTML or a download.<sup>[[5]](#references)</sup>

A lowercase first chunk-type letter means *ancillary*; a lowercase second letter means *private*. For example, `paMP` is private, whereas `pAMP` uses the public namespace even though the latter was invented for the demonstration.<sup>[[4]](#references)[[6]](#references)</sup> A chunk is `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; CRC covers type and data. Parse this structure rather than grepping for a type name inside compressed `IDAT` data. The following walker validates bounds and CRCs, exports ancillary payloads as raw bytes, and writes any bytes after the structural `IEND` to `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Carve ancillary chunks and the PNG trailer</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Inspect carved bytes with `file`, `strings`, or `binwalk`; decompress only if the carrier is actually compressed.<sup>[[4]](#references)</sup> Re-encoding may strip the carrier, so compare the uploaded and retrieved bytes before relying on it.<sup>[[2]](#references)[[6]](#references)</sup>

## Corrupted PNG repair

For checking integrity and locating the exact broken area, **pngcheck** remains one of the best first tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

If the file is damaged rather than intentionally malicious, **PCRT** can be useful in CTFs and lab work for fixing common issues such as bad headers, wrong IHDR values, CRC problems, or malformed chunk layouts.

If your goal is to **sanitize** a PNG that contains suspicious trailer data while preserving the visible image, ExifTool can explicitly remove the trailer:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

For sensitive evidence, always work on a **copy** and keep hashes of the original before attempting repairs.



## References

- [1] [Exploiting aCropalypse: Recovering Truncated PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: How to inject PHP code in an image – and keep it there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Ancillary chunks are a perfect place to stock away sensitive info](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Using valid ancillary chunks to smuggle data to an endpoint](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Portable Network Graphics (PNG) Specification (Third Edition)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
