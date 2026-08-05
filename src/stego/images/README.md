# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

अधिकांश CTF image stego इन buckets में से किसी एक तक सीमित होते हैं:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk की असामान्यताएं / corruption repair
- JPEG DCT-domain tools (OutGuess, आदि)
- Frame-based (GIF/APNG)

## Quick triage

गहन content analysis से पहले container-level evidence को प्राथमिकता दें:

- File को validate करें और structure का निरीक्षण करें: `file`, `magick identify -verbose`, format validators (जैसे, `pngcheck`)।
- Metadata और visible strings extract करें: `exiftool -a -u -g1`, `strings`।
- Embedded/appended content की जांच करें: `binwalk` और end-of-file inspection (`tail | xxd`)।
- Container के आधार पर आगे बढ़ें:
- PNG/BMP: bit-planes/LSB और chunk-level anomalies।
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families)।
- GIF/APNG: frame extraction, frame differencing, palette tricks।

## Bit-planes / LSB

### Technique

PNG/BMP CTFs में लोकप्रिय हैं क्योंकि वे pixels को इस तरह store करते हैं कि **bit-level manipulation** आसान हो जाती है। छिपाने/extract करने का classic mechanism यह है:

- प्रत्येक pixel channel (R/G/B/A) में कई bits होते हैं।
- प्रत्येक channel का **least significant bit** (LSB) image में बहुत कम बदलाव करता है।
- Attackers इन low-order bits में data छिपाते हैं, कभी-कभी stride, permutation या per-channel choice के साथ।

Challenges में अपेक्षा रखें:

- Payload केवल एक channel में हो (जैसे, `R` LSB)।
- Payload alpha channel में हो।
- Extraction के बाद payload compressed/encoded हो।
- Message planes में फैला हो या planes के बीच XOR के माध्यम से छिपाया गया हो।

अन्य families जिनका आपको सामना हो सकता है (implementation-dependent):

- **LSB matching** (सिर्फ bit flip करने के बजाय target bit से match करने के लिए +/-1 adjustments)
- **Palette/index-based hiding** (indexed PNG/GIF: raw RGB के बजाय color indices में payload)
- **Alpha-only payloads** (RGB view में पूरी तरह invisible)

### Tooling

#### zsteg

`zsteg` PNG/BMP के लिए कई LSB/bit-plane extraction patterns enumerate करता है:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: transforms की एक battery चलाता है (metadata, image transforms, LSB variants की brute forcing)।
- `stegsolve`: manual visual filters (channel isolation, plane inspection, XOR, आदि)।

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT LSB extraction नहीं है; इसका उपयोग उन मामलों में होता है जहाँ content को frequency space या subtle patterns में जानबूझकर छिपाया गया हो।

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF में अक्सर Web-based triage के लिए उपयोग किए जाने वाले tools:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, और hidden data

### तकनीक

PNG एक chunked format है। कई challenges में payload pixel values के बजाय container/chunk level पर stored होता है:

- **`IEND` के बाद extra bytes** (कई viewers trailing bytes को ignore करते हैं)
- **Payload ले जाने वाले non-standard ancillary chunks**
- **Corrupted headers**, जो dimensions छिपाते हैं या parsers को तब तक break करते हैं जब तक उन्हें ठीक न किया जाए

Review करने के लिए high-signal chunk locations:

- `tEXt` / `iTXt` / `zTXt` (text metadata, कभी-कभी compressed)
- `iCCP` (ICC profile) और अन्य ancillary chunks, जिनका उपयोग carrier के रूप में किया जाता है
- `eXIf` (PNG में EXIF data)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
क्या देखें:

- अजीब width/height/bit-depth/colour-type combinations
- CRC/chunk errors (pngcheck आमतौर पर सटीक offset बताता है)
- `IEND` के बाद अतिरिक्त data के बारे में warnings

यदि आपको chunks का अधिक गहन view चाहिए:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
उपयोगी references:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, और ELA limitations

### Technique

JPEG को raw pixels के रूप में store नहीं किया जाता; इसे DCT domain में compress किया जाता है। इसी कारण JPEG stego tools, PNG LSB tools से अलग होते हैं:

- Metadata/comment payloads file-level होते हैं (high-signal और जल्दी inspect किए जा सकते हैं)
- DCT-domain stego tools, frequency coefficients में bits embed करते हैं

Operationally, JPEG को इस रूप में देखें:

- Metadata segments का एक container (high-signal, जल्दी inspect किया जा सकता है)
- एक compressed signal domain (DCT coefficients), जहाँ specialized stego tools operate करते हैं

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

यदि आप विशेष रूप से JPEGs में steghide payloads का सामना कर रहे हैं, तो `stegseek` का उपयोग करने पर विचार करें (पुरानी scripts की तुलना में तेज़ bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA अलग-अलग recompression artifacts को highlight करता है; यह आपको उन regions तक संकेत दे सकता है जिन्हें edit किया गया है, लेकिन यह अपने-आप में stego detector नहीं है:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animated images

### Technique

Animated images के लिए मान लें कि message:

- एक single frame में है (आसान), या
- frames में फैला हुआ है (ordering महत्वपूर्ण है), या
- केवल consecutive frames का diff करने पर दिखाई देता है

### Extract frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
फिर frames को सामान्य PNGs की तरह treat करें: `zsteg`, `pngcheck`, channel isolation।

वैकल्पिक tooling:

- `gifsicle --explode anim.gif` (तेज़ frame extraction)
- प्रति-frame transforms के लिए `imagemagick`/`magick`

Frame differencing अक्सर निर्णायक होता है:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG containers का पता लगाएँ: `exiftool -a -G1 file.png | grep -i animation` या `file`।
- बिना re-timing के frames extract करें: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`।
- प्रति-frame pixel counts के रूप में encoded payloads recover करें:
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
Animated challenges प्रत्येक frame में किसी specific color की count के रूप में प्रत्येक byte को encode कर सकते हैं; counts को concatenate करने पर message reconstruct होता है।<sup>[[1]](#references)</sup>

## Password-protected embedding

यदि आपको संदेह है कि embedding pixel-level manipulation के बजाय किसी passphrase से protected है, तो यह आमतौर पर सबसे तेज़ तरीका है।

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

PNG/BMP/GIF/WebP/WAV को support करता है।

Repo: https://github.com/dhsdshdhk/stegpy

## संदर्भ

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
