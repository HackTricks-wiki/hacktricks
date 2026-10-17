# इमेज स्टेगनोग्राफी

{{#include ../../banners/hacktricks-training.md}}

ज़्यादातर CTF image stego इन श्रेणियों में से किसी एक में आता है:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk की असामान्यताएँ / corruption repair
- JPEG DCT-domain tools (OutGuess, आदि)
- Frame-based (GIF/APNG)

## त्वरित जाँच

गहराई से content analysis करने से पहले container-level evidence को प्राथमिकता दें:

- फ़ाइल को validate करें और structure जाँचें: `file`, `magick identify -verbose`, format validators (जैसे `pngcheck`)।
- Metadata और दिखाई देने वाले strings निकालें: `exiftool -a -u -g1`, `strings`।
- Embedded/appended content की जाँच करें: `binwalk` और फ़ाइल के अंत का निरीक्षण (`tail | xxd`)।
- Container के अनुसार आगे बढ़ें:
  - PNG/BMP: bit-planes/LSB और chunk-level anomalies।
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families)।
  - GIF/APNG: frame extraction, frame differencing, palette tricks।

## Bit-planes / LSB

### तकनीक

PNG/BMP CTFs में लोकप्रिय हैं, क्योंकि इनमें pixels इस तरह store होते हैं कि **bit-level manipulation** आसान हो जाता है। छिपाने/निकालने का सामान्य तरीका यह है:

- हर pixel channel (R/G/B/A) में कई bits होते हैं।
- हर channel का **least significant bit** (LSB) इमेज में बहुत कम बदलाव करता है।
- हमलावर इन low-order bits में data छिपाते हैं, कभी-कभी stride, permutation या per-channel choice का इस्तेमाल करके।

Challenges में क्या देखने की उम्मीद करें:

- Payload सिर्फ़ एक channel में हो (जैसे `R` LSB)।
- Payload alpha channel में हो।
- Extraction के बाद payload compressed/encoded हो।
- Message कई planes में फैला हो या planes के बीच XOR के ज़रिए छिपाया गया हो।

अन्य families, जिनका सामना हो सकता है (implementation पर निर्भर):

- **LSB matching** (सिर्फ़ bit flip करने के बजाय, target bit से मेल कराने के लिए +/-1 adjustments)
- **Palette/index-based hiding** (indexed PNG/GIF: raw RGB के बजाय color indices में payload)
- **Alpha-only payloads** (RGB view में पूरी तरह अदृश्य)

### Tools

#### zsteg

`zsteg` PNG/BMP के लिए कई LSB/bit-plane extraction patterns की जाँच करता है:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: transforms का एक समूह चलाता है (metadata, image transforms, LSB variants की brute forcing)।
- `stegsolve`: मैन्युअल visual filters (channel isolation, plane inspection, XOR आदि)।

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-आधारित दृश्यता युक्तियाँ

FFT, LSB extraction नहीं है; इसका उपयोग उन मामलों में होता है जहाँ content को जानबूझकर frequency space या सूक्ष्म patterns में छिपाया जाता है।

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF में अक्सर web-based triage का उपयोग किया जाता है:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, और hidden data

### Technique

PNG एक chunked format है। कई challenges में payload, pixel values के बजाय container/chunk level पर stored होता है:

- **`IEND` के बाद अतिरिक्त bytes** (कई viewers trailing bytes को अनदेखा करते हैं)
- **Payload ले जाने वाले non-standard ancillary chunks**; [PNG chunk walker और carving workflow](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads) देखें।
- **Corrupted headers**, जो dimensions को छिपाते हैं या ठीक किए जाने तक parsers को बाधित करते हैं

जाँचने के लिए महत्वपूर्ण chunk locations:

- `tEXt` / `iTXt` / `zTXt` (text metadata, कभी-कभी compressed)
- `iCCP` (ICC profile) और carrier के रूप में उपयोग किए गए अन्य ancillary chunks
- `eXIf` (PNG में EXIF data)

### Triage commands

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

क्या देखें:

- अजीब width/height/bit-depth/colour-type संयोजन
- CRC/chunk त्रुटियाँ (pngcheck आमतौर पर सटीक offset बताता है)
- `IEND` के बाद अतिरिक्त डेटा होने की चेतावनियाँ

अगर आपको chunks का अधिक विस्तृत दृश्य चाहिए:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

उपयोगी संदर्भ:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, और ELA की सीमाएँ

### तकनीक

JPEG raw pixels के रूप में stored नहीं होता; यह DCT domain में compressed होता है। इसीलिए JPEG stego tools, PNG LSB tools से अलग होते हैं:

- Metadata/comment payloads file-level पर होते हैं (उच्च-सिग्नल और जल्दी inspect करने योग्य)
- DCT-domain stego tools, frequency coefficients में bits embed करते हैं

व्यावहारिक रूप से, JPEG को इस तरह देखें:

- Metadata segments के लिए एक container (उच्च-सिग्नल, जल्दी inspect करने योग्य)
- एक compressed signal domain (DCT coefficients), जिसमें specialized stego tools काम करते हैं

### त्वरित जाँचें

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

High-signal स्थान:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

अगर आपको खास तौर पर JPEGs में steghide payloads मिलते हैं, तो `stegseek` का इस्तेमाल करने पर विचार करें (पुराने scripts की तुलना में तेज़ bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA अलग-अलग recompression artifacts को हाइलाइट करता है; इससे आपको उन क्षेत्रों का पता चल सकता है जिन्हें edit किया गया है, लेकिन यह अपने आप में stego detector नहीं है:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animated images

### Technique

Animated images के लिए मान लें कि message:

- एक ही frame में है (आसान), या
- कई frames में फैला हुआ है (क्रम मायने रखता है), या
- केवल लगातार frames का diff करने पर दिखाई देता है

### Extract frames

```bash
ffmpeg -i anim.gif frame_%04d.png
```

फिर frames को सामान्य PNGs की तरह देखें: `zsteg`, `pngcheck`, channel isolation.

वैकल्पिक tools:

- `gifsicle --explode anim.gif` (तेज़ी से frames निकालने के लिए)
- हर frame पर transforms लागू करने के लिए `imagemagick`/`magick`

अक्सर frames के बीच का अंतर निर्णायक होता है:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG पिक्सेल-गिनती एन्कोडिंग

- APNG कंटेनर पहचानें: `exiftool -a -G1 file.png | grep -i animation` या `file`।
- री-टाइमिंग किए बिना फ़्रेम निकालें: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`।
- प्रति-फ़्रेम पिक्सेल गणनाओं के रूप में एन्कोड किए गए payloads पुनर्प्राप्त करें:

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

Animated challenges में प्रत्येक frame में किसी विशिष्ट रंग की संख्या को एक byte के रूप में encode किया जा सकता है; इन संख्याओं को जोड़ने पर message फिर से बन जाता है।<sup>[[1]](#references)</sup>

## पासवर्ड-सुरक्षित embedding

यदि आपको संदेह है कि pixel-level manipulation के बजाय passphrase से सुरक्षित embedding का उपयोग किया गया है, तो आमतौर पर यह सबसे तेज़ तरीका है।

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

- [1] [Flagvent 2025 (मध्यम) — pink, Santa की इच्छा-सूची, क्रिसमस मेटाडेटा, कैप्चर किया गया शोर](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
