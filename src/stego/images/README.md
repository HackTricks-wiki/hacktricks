# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego निम्नलिखित में से एक श्रेणी में आता है:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## शीघ्र जाँच

गहराई से कंटेंट विश्लेषण करने से पहले container-स्तर के साक्ष्य को प्राथमिकता दें:

- फ़ाइल को मान्य करें और संरचना निरीक्षण करें: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- मेटाडेटा और दृश्य स्ट्रिंग्स निकालें: `exiftool -a -u -g1`, `strings`.
- embedded/appended सामग्री की जाँच करें: `binwalk` और end-of-file निरीक्षण (`tail | xxd`).
- कंटेनर के अनुसार आगे बढ़ें:
  - PNG/BMP: bit-planes/LSB और chunk-level विसंगतियाँ।
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families)।
  - GIF/APNG: फ्रेम extraction, फ्रेम differencing, palette ट्रिक्स।

## Bit-planes / LSB

### तकनीक

PNG/BMP CTFs में लोकप्रिय हैं क्योंकि वे पिक्सल्स को इस तरह संग्रहीत करते हैं कि **bit-level manipulation** आसान हो जाता है। क्लासिक hide/extract मेकैनिज़्म है:

- प्रत्येक पिक्सल चैनल (R/G/B/A) में कई बिट होते हैं।
- प्रत्येक चैनल का **least significant bit** (LSB) इमेज को बहुत कम बदलता है।
- हमलावर उन low-order बिट्स में डेटा छिपाते हैं, कभी-कभी stride, permutation, या per-channel विकल्प के साथ।

Challenges में क्या अपेक्षा करें:

- Payload केवल एक चैनल में होता है (उदा., `R` LSB)।
- Payload alpha चैनल में होता है।
- निकालने के बाद Payload compressed/encoded होता है।
- संदेश planes में फैलाया गया होता है या planes के बीच XOR के माध्यम से छिपाया जाता है।

अतिरिक्त प्रकार जो मिल सकते हैं (implementation-dependent):

- **LSB matching** (केवल बिट फ्लिप नहीं, बल्कि target बिट से मिलाने के लिए +/-1 समायोजन)
- **Palette/index-based hiding** (indexed PNG/GIF: payload raw RGB के बजाय color indices में)
- **Alpha-only payloads** (RGB view में पूरी तरह अदृश्य)

### उपकरण

#### zsteg

`zsteg` PNG/BMP के लिए कई LSB/bit-plane extraction पैटर्न सूचीबद्ध करता है:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: ट्रांसफॉर्म की एक श्रृंखला चलाता है (metadata, image transforms, brute forcing LSB variants)।
- `stegsolve`: मैन्युअल विज़ुअल फ़िल्टर्स (channel isolation, plane inspection, XOR, आदि)।

Stegsolve डाउनलोड: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT, LSB extraction नहीं है; यह उन मामलों के लिए है जहाँ कंटेंट जानबूझकर फ़्रीक्वेंसी स्पेस या सूक्ष्म पैटर्न में छिपाया गया हो।

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage अक्सर CTFs में इस्तेमाल होता है:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG एक chunked फॉर्मेट है। कई challenges में payload पिक्सेल मानों के बजाय container/chunk स्तर पर स्टोर किया जाता है:

- **Extra bytes after `IEND`** (कई viewers ट्रेलिंग बाइट्स को अनदेखा करते हैं)
- **Non-standard ancillary chunks** जो payloads को वहन करते हैं
- **Corrupted headers** जो dimensions छिपा देते हैं या parsers को तब तक तोड़ देते हैं जब तक ठीक न किया जाए

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (text metadata, कभी-कभी compressed)
- `iCCP` (ICC profile) और अन्य ancillary chunks जिन्हें carrier के रूप में उपयोग किया जाता है
- `eXIf` (PNG में EXIF data)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
What to look for:

- असामान्य width/height/bit-depth/colour-type संयोजन
- CRC/chunk त्रुटियाँ (pngcheck आमतौर पर सटीक ऑफ़सेट की ओर इशारा करता है)
- `IEND` के बाद अतिरिक्त डेटा के बारे में चेतावनियाँ

यदि आपको chunk का गहरा दृश्य चाहिए:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
उपयोगी संदर्भ:

- PNG विशेष विवरण (संरचना, chunks): https://www.w3.org/TR/PNG/
- फ़ाइल फ़ॉर्मेट तरकीबें (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA सीमाएँ

### तकनीक

JPEG raw pixels के रूप में संग्रहित नहीं होता; यह DCT domain में कंप्रेस किया जाता है। इसलिए JPEG stego tools PNG LSB tools से भिन्न होते हैं:

- Metadata/comment payloads फ़ाइल-स्तरीय होते हैं (high-signal और जल्दी निरीक्षण के लिए)
- DCT-domain stego tools frequency coefficients में bits embed करते हैं

ऑपरेशनल रूप से, JPEG को ऐसे समझें:

- metadata segments के लिए एक container (high-signal, जल्दी निरीक्षण के लिए)
- एक compressed signal डोमेन (DCT coefficients) जहाँ specialized stego tools काम करते हैं

### त्वरित जाँच
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:

- EXIF/XMP/IPTC मेटाडेटा
- JPEG कॉमेंट सेगमेंट (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA अलग-अलग recompression artifacts को उजागर करता है; यह आपको उन क्षेत्रों की ओर इशारा कर सकता है जिन्हें संपादित किया गया था, लेकिन यह अपने आप में कोई stego detector नहीं है:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## एनिमेटेड इमेज

### तकनीक

एनिमेटेड इमेज के लिए, मान लें कि संदेश:

- एक ही फ्रेम में (आसान), या
- फ्रेमों में फैला हुआ (क्रम महत्वपूर्ण), या
- केवल तब दिखाई देता है जब आप लगातार फ्रेमों का diff करते हैं

### फ्रेम निकालें
```bash
ffmpeg -i anim.gif frame_%04d.png
```
फिर फ्रेम्स को सामान्य PNGs की तरह व्यवहार करें: `zsteg`, `pngcheck`, channel isolation.

वैकल्पिक टूल्स:

- `gifsicle --explode anim.gif` (त्वरित फ्रेम निकालना)
- `imagemagick`/`magick` प्रति-फ्रेम रूपांतरण के लिए

फ्रेमों में अंतर अक्सर निर्णायक होता है:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## पासवर्ड-प्रोटेक्टेड एम्बेडिंग

यदि आप संदेह करते हैं कि एम्बेडिंग pixel-level manipulation के बजाय passphrase द्वारा सुरक्षित है, तो यह आमतौर पर सबसे तेज़ रास्ता होता है।

### steghide

यह `JPEG, BMP, WAV, AU` को सपोर्ट करता है और एन्क्रिप्टेड payloads को embed/extract कर सकता है।
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
रिपॉजिटरी: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV का समर्थन करता है।

रिपॉजिटरी: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
