# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

अधिकांश CTF image stego इन श्रेणियों में से किसी एक में आता है:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk की अजीब गड़बड़ियाँ / corruption repair
- JPEG DCT-domain tools (OutGuess आदि)
- Frame-based (GIF/APNG)

## त्वरित जाँच

गहन content analysis से पहले container-level सबूतों को प्राथमिकता दें। image-विशिष्ट परीक्षणों से पहले file identification और carving के लिए [general stego workflow](../workflow/) देखें।

- File को validate करें और structure जाँचें: `file`, `magick identify -verbose`, format validators (जैसे, `pngcheck`)।
- Metadata और दिखने वाले strings निकालें: `exiftool -a -u -g1`, `strings`।
- Embedded/appended content जाँचें: `binwalk` और file के अंत का निरीक्षण (`tail | xxd`)।
- Container के अनुसार आगे बढ़ें:
  - PNG/BMP: bit-planes/LSB और chunk-level anomalies।
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families)।
  - GIF/APNG: frame extraction, frame differencing, palette tricks।

## Bit-planes / LSB

### तकनीक

CTF में PNG/BMP लोकप्रिय हैं, क्योंकि इनमें pixels इस तरह store होते हैं कि **bit-level manipulation** आसान हो। छिपाने/निकालने का पारंपरिक तरीका यह है:

- हर pixel channel (R/G/B/A) में कई bits होते हैं।
- हर channel का **least significant bit** (LSB) image को बहुत कम बदलता है।
- Attackers इन low-order bits में data छिपाते हैं, कभी-कभी stride, permutation या प्रति-channel चयन के साथ।

Challenges में क्या देखने की उम्मीद करें:

- Payload केवल एक channel में हो (जैसे, `R` LSB)।
- Payload alpha channel में हो।
- Extraction के बाद payload compressed/encoded हो।
- Message कई planes में फैला हो या planes के बीच XOR के ज़रिए छिपाया गया हो।

अन्य families जो आपको मिल सकती हैं (implementation पर निर्भर):

- **LSB matching** (सिर्फ bit पलटने के बजाय, target bit से मेल कराने के लिए +/-1 adjustment)
- **Palette/index-based hiding** (indexed PNG/GIF में payload raw RGB के बजाय color indices में)
- **Alpha-only payloads** (RGB view में पूरी तरह अदृश्य)

### Indexed-color palette indices

Indexed PNG या GIF हर pixel के लिए RGB triplet के बजाय एक palette **index** store करता है। दो indices एक ही दिखाई देने वाले color से map हो सकते हैं, इसलिए analysis से पहले RGB में convert करने पर छिपा हुआ अंतर मिट सकता है। Duplicate या लगभग एक जैसे palette entries देखें, फिर हर संदिग्ध index का उपयोग करने वाले pixels का binary mask render करें। हाल के GIF challenges में इससे hidden text और QR-code बदलाव सामने आए हैं।<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Single-frame indexed PNG (या GIF के **पहले frame**) के लिए, Pillow का `P` mode बनाए रखें और script द्वारा बताए गए किसी दिलचस्प index पर `target` बदलें। Indices चुनते समय RGB के साथ transparency (`tRNS` या GIF transparency index) भी जाँचें।<sup>[[3]](#references)[[5]](#references)</sup>

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

Animated GIFs के लिए, frames को अलग-अलग inspect करें। compositing के दौरान Pillow आमतौर पर बाद के frames को RGB/RGBA में convert करता है; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` केवल तब तक `P` mode बनाए रखता है, जब तक palette नहीं बदलती। अगर किसी frame में local palette है या उसे पहले ही composite किया जा चुका है, तो RGB-converted pixels को indices मानने के बजाय उसका मूल indexed frame data inspect करें।<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### टूलिंग

#### zsteg

`zsteg` PNG/BMP के लिए कई LSB/bit-plane extraction patterns की सूची देता है:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: transforms का एक पूरा सेट चलाता है (metadata, image transforms, LSB variants को brute force करना)।
- `stegsolve`: मैन्युअल visual filters (channel isolation, plane inspection, XOR, आदि)।

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-आधारित visibility tricks

FFT, LSB extraction नहीं है; इसका उपयोग उन मामलों में होता है जहाँ content को जानबूझकर frequency space या subtle patterns में छिपाया जाता है।

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage का अक्सर CTFs में उपयोग होता है:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG के अंदरूनी हिस्से: chunks, corruption और hidden data

### Technique

PNG एक chunked format है। कई challenges में payload, pixel values के बजाय container/chunk level पर stored होता है:

- **`IEND` के बाद अतिरिक्त bytes** (कई viewers trailing bytes को अनदेखा करते हैं)
- **Non-standard ancillary chunks** में रखे payload; [PNG chunk walker और carving workflow](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads) देखें।
- **Corrupted headers**, जो dimensions छिपाते हैं या उन्हें ठीक किए जाने तक parsers को बाधित करते हैं

जाँचने के लिए महत्वपूर्ण chunk locations:

- `tEXt` / `iTXt` / `zTXt` (text metadata, कभी-कभी compressed)
- `iCCP` (ICC profile) और carrier के रूप में उपयोग किए गए अन्य ancillary chunks
- `eXIf` (PNG में EXIF data)

### PNG scanline-filter bytes को carrier के रूप में उपयोग करना

PNG, decompressed `IDAT` stream में हर scanline से पहले एक filter-type byte (0–4) store करता है। ये bytes pixel values नहीं हैं; decoded RGB pixels मूल filter choices को बनाए नहीं रखते, और दोबारा encoding करने से वे बदल सकते हैं। कोई encoder वैध रूप से अलग-अलग filters चुन सकता है, लेकिन जानबूझकर बनाए गए patterns एक छोटा message encode कर सकते हैं; हाल ही के एक challenge में filter values 1–4 को two-bit symbols के रूप में इस्तेमाल किया गया था। **Original file** की जाँच करें और decompress करने से पहले सारा `IDAT` data जोड़ें। नीचे दिए गए non-interlaced, 8-bit RGB/RGBA case के लिए stride, width को channel count से गुणा करने पर मिलता है; Adam7 images के लिए pass-specific scanline widths आवश्यक हैं।<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>दोबारा encoding किए बिना PNG scanline filter bytes की सूची बनाएँ</summary>

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

इसे `python3 filters.py suspect.png` के रूप में चलाएँ। जाँचें कि decoded pixels के बजाय filter sequence किसी संभावित symbol mapping का पालन करता है या नहीं। Mapping का चुनाव challenge-specific होता है; केवल variation होना steganography का प्रमाण नहीं है।<sup>[[3]](#references)[[7]](#references)</sup>

### प्रारंभिक जाँच commands

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

क्या देखना है:

- अजीब width/height/bit-depth/colour-type संयोजन
- CRC/chunk त्रुटियाँ (pngcheck आमतौर पर सटीक offset बताता है)
- `IEND` के बाद अतिरिक्त data होने की चेतावनियाँ

अगर आपको chunks का अधिक विस्तृत view चाहिए:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

उपयोगी संदर्भ:

- PNG specification (संरचना, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF के विशेष मामले): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, और ELA की सीमाएँ

### तकनीक

JPEG raw pixels के रूप में संग्रहीत नहीं होता; यह DCT domain में compressed होता है। इसी वजह से JPEG stego tools, PNG LSB tools से अलग होते हैं:

- Metadata/comment payloads file-level पर होते हैं (उच्च-सिग्नल और जल्दी जाँचने योग्य)
- DCT-domain stego tools frequency coefficients में bits embed करते हैं

व्यावहारिक रूप से, JPEG को इस तरह देखें:

- Metadata segments का एक container (उच्च-सिग्नल, जल्दी जाँचने योग्य)
- एक compressed signal domain (DCT coefficients), जिसमें विशेष stego tools काम करते हैं

### त्वरित जाँचें

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

अगर आप विशेष रूप से JPEGs में steghide payloads खोज रहे हैं, तो `stegseek` का उपयोग करने पर विचार करें (पुरानी scripts से तेज़ bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA अलग-अलग recompression artifacts को हाइलाइट करता है; यह उन क्षेत्रों की ओर संकेत कर सकता है जिन्हें edit किया गया था, लेकिन यह अपने आप में stego detector नहीं है:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animated images

### Technique

Animated images के लिए मान लें कि message:

- किसी एक frame में है (आसान), या
- frames में फैला हुआ है (क्रम मायने रखता है), या
- केवल लगातार frames का diff करने पर दिखाई देता है

### Extract frames

```bash
ffmpeg -i anim.gif frame_%04d.png
```

फिर frames को सामान्य PNGs की तरह देखें: `zsteg`, `pngcheck`, channel isolation।

वैकल्पिक tools:

- `gifsicle --explode anim.gif` (तेज़ी से frames निकालने के लिए)
- प्रति-frame transformations के लिए `imagemagick`/`magick`

Frames की तुलना अक्सर निर्णायक होती है:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG पिक्सेल-काउंट एन्कोडिंग

- APNG कंटेनर का पता लगाएँ: `exiftool -a -G1 file.png | grep -i animation` या `file`।
- री-टाइमिंग किए बिना फ़्रेम निकालें: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`।
- प्रति-फ़्रेम पिक्सेल काउंट के रूप में एन्कोड किए गए payloads पुनर्प्राप्त करें:

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

एनिमेटेड challenges में हर byte को प्रत्येक frame में किसी खास रंग की संख्या के रूप में encode किया जा सकता है; इन संख्याओं को जोड़ने से message फिर से बनाया जा सकता है।<sup>[[1]](#references)</sup>

## पासवर्ड-सुरक्षित embedding

अगर आपको लगता है कि pixel-level manipulation के बजाय passphrase से सुरक्षित embedding का इस्तेमाल हुआ है, तो यह आमतौर पर सबसे तेज़ तरीका है।

### steghide

`JPEG, BMP, WAV, AU` को support करता है और encrypted payloads को embed/extract कर सकता है।

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

PNG/BMP/GIF/WebP/WAV को सपोर्ट करता है।

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — pink, Santa की Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024 write-up — Twisted Colors](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Portable Network Graphics (PNG) विनिर्देश, तीसरा संस्करण](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — गहराई में, पानी में कुछ है](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow इमेज फ़ाइल फ़ॉर्मैट — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [GIF89a विनिर्देश](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — CTF write-up](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
