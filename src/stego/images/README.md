# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

अधिकांश CTF image stego निम्नलिखित में से किसी एक श्रेणी में आता है:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## त्वरित जाँच

गहन कंटेंट विश्लेषण से पहले container-level सबूतों को प्राथमिकता दें:

- फ़ाइल को मान्य करें और संरचना का निरीक्षण करें: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- मेटाडेटा और दिखाई देने वाले स्ट्रिंग्स निकालें: `exiftool -a -u -g1`, `strings`.
- एम्बेडेड/ऐपेंडेड कंटेंट के लिए जांचें: `binwalk` और end-of-file निरीक्षण (`tail | xxd`).
- कंटेनर के अनुसार शाखा बनाएं:
  - PNG/BMP: bit-planes/LSB और chunk-level anomalies.
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
  - GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### तकनीक

PNG/BMP CTFs में लोकप्रिय हैं क्योंकि वे पिक्सल्स को इस तरह स्टोर करते हैं कि **bit-level manipulation** आसान हो जाता है। क्लासिक hide/extract मेकनिज़्म यह है:

- प्रत्येक पिक्सल चैनल (R/G/B/A) में कई बिट होते हैं।
- **least significant bit** प्रत्येक चैनल का इमेज को बहुत कम बदलता है।
- हमलावर उन low-order bits में डेटा छिपाते हैं, कभी-कभी stride, permutation, या per-channel चुनाव के साथ।

चैलेंज में क्या उम्मीद करें:

- payload केवल एक चैनल में है (e.g., `R` LSB)।
- payload alpha channel में है।
- extraction के बाद Payload compress/encode हो सकती है।
- संदेश planes के बीच फैला हुआ है या planes के बीच XOR के माध्यम से छिपा है।

आप जिन अतिरिक्त फैमिलीज़ से मिल सकते हैं (implementation-dependent):

- **LSB matching** (सिर्फ बिट को उलटने के बजाय लक्ष्य बिट से मिलाने के लिए +/-1 समायोजन)
- **Palette/index-based hiding** (indexed PNG/GIF: payload raw RGB के बजाय color indices में)
- **Alpha-only payloads** (RGB view में पूरी तरह अदृश्य)

### Tooling

#### zsteg

`zsteg` कई LSB/bit-plane extraction पैटर्न्स को PNG/BMP के लिए enumerate करता है:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: ट्रांसफ़ॉर्म्स की एक बैटरी चलाता है (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: मैनुअल विज़ुअल फ़िल्टर्स (channel isolation, plane inspection, XOR, आदि).

Stegsolve डाउनलोड: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT LSB extraction नहीं है; यह उन मामलों के लिए है जहां सामग्री जानबूझकर frequency space या सूक्ष्म पैटर्न में छिपाई गई हो।

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage अक्सर CTFs में इस्तेमाल होता है:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG आंतरिक: chunks, corruption, and hidden data

### तकनीक

PNG एक chunked फ़ॉर्मेट है। कई चुनौतियों में payload पिक्सेल मानों की बजाय container/chunk स्तर पर संग्रहीत होता है:

- **Extra bytes after `IEND`** (कई viewers trailing bytes को अनदेखा कर देते हैं)
- **Non-standard ancillary chunks** जो payloads को वाहक की तरह रखती हैं
- **Corrupted headers** जो dimensions छिपाते हैं या parsers को तब तक तोड़ देते हैं जब तक ठीक न किया जाए

जांचने के लिए उच्च-सिग्नल chunk स्थान:

- `tEXt` / `iTXt` / `zTXt` (text metadata, कभी-कभी compressed)
- `iCCP` (ICC profile) और अन्य ancillary chunks जो carrier के रूप में इस्तेमाल होते हैं
- `eXIf` (PNG में EXIF data)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
किस चीज़ पर ध्यान दें:

- असामान्य width/height/bit-depth/colour-type संयोजन
- CRC/chunk errors (pngcheck आमतौर पर exact offset की ओर संकेत करता है)
- `IEND` के बाद अतिरिक्त डेटा के बारे में चेतावनियाँ

यदि आपको अधिक विस्तृत chunk view चाहिए:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
उपयोगी संदर्भ:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### तकनीक

JPEG कच्चे पिक्सल के रूप में स्टोर नहीं होता; यह DCT डोमेन में कंप्रेस्ड होता है। इसी कारण JPEG stego tools, PNG LSB tools से अलग होते हैं:

- Metadata/comment payloads फ़ाइल-स्तरीय होते हैं (high-signal और जल्दी जाँच करने योग्य)
- DCT-domain stego tools frequency coefficients में bits embed करते हैं

ऑपरेशनल रूप से, JPEG को इस प्रकार देखें:

- Metadata segments के लिए एक कंटेनर (high-signal, जल्दी जाँच करने योग्य)
- एक compressed signal डोमेन (DCT coefficients), जहाँ विशेषीकृत stego tools काम करते हैं

### त्वरित जाँच
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
उच्च-सिग्नल स्थान:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### सामान्य टूल्स

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

यदि आप विशेष रूप से JPEGs में steghide payloads का सामना कर रहे हैं, तो `stegseek` उपयोग करने पर विचार करें (पुराने स्क्रिप्ट्स की तुलना में तेज bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA विभिन्न recompression artifacts को हाईलाइट करता है; यह आपको उन क्षेत्रों की ओर इशारा कर सकता है जिन्हें एडिट किया गया है, लेकिन यह अपने आप में कोई stego detector नहीं है:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## एनिमेटेड इमेज

### तकनीक

एनिमेटेड इमेज के लिए, मान लें कि संदेश:

- एक ही फ्रेम में (आसान), या
- फ्रेमों में फैला हुआ (क्रम मायने रखता है), या
- केवल तभी दिखाई देता है जब आप लगातार फ्रेमों का diff लें

### फ्रेम निकालें
```bash
ffmpeg -i anim.gif frame_%04d.png
```
फिर frames को सामान्य PNGs की तरह हैंडल करें: `zsteg`, `pngcheck`, channel isolation.

वैकल्पिक टूलिंग:

- `gifsicle --explode anim.gif` (तेज़ फ्रेम एक्सट्रैक्शन)
- `imagemagick`/`magick` प्रति-फ़्रेम रूपांतरणों के लिए

Frame differencing अक्सर निर्णायक होता है:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG कंटेनरों का पता लगाएँ: `exiftool -a -G1 file.png | grep -i animation` या `file`.
- re-timing के बिना फ्रेम निकालें: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- per-frame pixel counts के रूप में एन्कोड किए गए payloads पुनःप्राप्त करें:
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
एनिमेटेड चुनौतियाँ प्रत्येक फ्रेम में किसी विशिष्ट रंग की गिनती के रूप में प्रत्येक बाइट को एन्कोड कर सकती हैं; इन गिनतियों को जोड़ने से संदेश पुनर्निर्मित हो जाता है।

## पासवर्ड-प्रोटेक्टेड एम्बेडिंग

यदि आप संदेह करते हैं कि एम्बेडिंग पिक्सेल-स्तर पर हेरफेर के बजाय passphrase द्वारा संरक्षित है, तो यह आम तौर पर सबसे तेज़ रास्ता होता है।

### steghide

यह `JPEG, BMP, WAV, AU` का समर्थन करता है और encrypted payloads को embed/extract कर सकता है।
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I can’t access external repositories or URLs. Please paste the contents of src/stego/images/README.md here, and I will translate the English text to Hindi while preserving all markdown, tags, links, paths, and code exactly as you specified.
```bash
stegcracker file.jpg wordlist.txt
```
रिपॉजिटरी: https://github.com/Paradoxis/StegCracker

### stegpy

समर्थन: PNG/BMP/GIF/WebP/WAV.

रिपॉजिटरी: https://github.com/dhsdshdhk/stegpy

## संदर्भ

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
