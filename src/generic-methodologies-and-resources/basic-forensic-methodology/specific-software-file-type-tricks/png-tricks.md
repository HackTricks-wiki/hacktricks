# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** are very common in **CTFs**, **incident response**, and **malware staging** because they are **lossless**, **chunk-based**, and many tools will happily render them even when they contain **extra metadata**, **appended payloads**, or **partially corrupted chunks**.

Treat a PNG as a **container**, not just as an image.

## Quick triage

Start with container-level checks before jumping into LSB stego. For the bit-plane/LSB workflow, check [the dedicated image stego page](../../../stego/images/README.md).

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

If you want to carve everything after the final `IEND`:

```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```

Also try generic archive parsers directly against the PNG or the carved trailer:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Acropalypse-style recovery of cropped/redacted screenshots

A very practical recent PNG forensic trick is checking whether a screenshot editor **overwrote** a PNG without **truncating** the old file first. In those cases, bytes from the **previous image** can remain after `IEND`, and sometimes extra `IDAT` data can be partially reconstructed.

This became well known with **aCropalypse** (Google Pixel Markup) and the related **Windows Snipping Tool** issue. In practice, if a "cropped" or "redacted" PNG still contains old trailing data, you may be able to recover part of the original screenshot.

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
- `PLTE` – palette data in indexed images, but also useful in payload-smuggling scenarios

Dump them with:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

For offensive payload persistence inside PNG chunks (for example **PLTE**, **IDAT**, or **tEXt** tricks that survive some PHP image transformations), check the more detailed upload-focused notes here:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

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

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
