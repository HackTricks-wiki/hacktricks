# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego reduces to one of these buckets:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

गहरे कंटेंट विश्लेषण से पहले container-level सबूतों को प्राथमिकता दें:

- Validate the file and inspect structure: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Extract metadata and visible strings: `exiftool -a -u -g1`, `strings`.
- Check for embedded/appended content: `binwalk` and end-of-file inspection (`tail | xxd`).
- Branch by container:
- PNG/BMP: bit-planes/LSB and chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP CTFs में लोकप्रिय हैं क्योंकि वे पिक्सल को इस तरह स्टोर करते हैं कि **bit-level manipulation** आसान हो जाती है। क्लासिक hide/extract मेकैनिज़्म इस प्रकार है:

- प्रत्येक पिक्सल चैनल (R/G/B/A) में कई बिट्स होते हैं।
- प्रत्येक चैनल का **least significant bit** (LSB) इमेज को बहुत कम बदलता है।
- हमलावर उन निम्न-क्रम के बिट्स में डेटा छिपाते हैं, कभी-कभी stride, permutation, या per-channel choice के साथ।

Challenges में क्या अपेक्षा करें:

- Payload केवल एक चैनल में होता है (उदा., `R` LSB)।
- Payload alpha चैनल में होता है।
- Extraction के बाद Payload compressed/encoded होता है।
- संदेश planes में फैला होता है या planes के बीच XOR के जरिए छिपा होता है।

आप जिन अतिरिक्त families से मिल सकते हैं (implementation-dependent):

- **LSB matching** (केवल बिट पलटना नहीं, बल्कि target bit से मेल खाता हुआ +/-1 adjustment)
- **Palette/index-based hiding** (indexed PNG/GIF: payload raw RGB के बजाय color indices में)
- **Alpha-only payloads** (RGB view में पूरी तरह अदृश्य)

### Tooling

#### zsteg

`zsteg` PNG/BMP के लिए कई LSB/bit-plane extraction patterns को सूचीबद्ध करता है:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: transforms की एक बैटरी चलाता है (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: मैन्युअल विज़ुअल फिल्टर्स (channel isolation, plane inspection, XOR, आदि).

Stegsolve डाउनलोड: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT LSB extraction नहीं है; यह उन मामलों के लिए है जहाँ content जानबूझकर frequency space या सूक्ष्म पैटर्न्स में छिपाया जाता है।

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF में अक्सर उपयोग किए जाने वाले वेब-आधारित टूल:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG एक chunked फ़ॉर्मेट है। कई challenges में payload pixel मानों के बजाय container/chunk स्तर पर संग्रहित किया जाता है:

- **Extra bytes after `IEND`** (कई viewers trailing bytes को अनदेखा करते हैं)
- **Non-standard ancillary chunks** जो payload ले जाते हैं
- **Corrupted headers** जो dimensions छुपा देते हैं या parsers को तब तक तोड़ देते हैं जब तक ठीक न किया जाए

रिव्यू करने के लिए महत्वपूर्ण chunk स्थान:

- `tEXt` / `iTXt` / `zTXt` (text metadata, कभी-कभी compressed)
- `iCCP` (ICC profile) और अन्य ancillary chunks जो carrier के रूप में उपयोग होते हैं
- `eXIf` (PNG में EXIF data)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
किस पर ध्यान दें:

- अजीब width/height/bit-depth/colour-type संयोजन
- CRC/chunk त्रुटियाँ (pngcheck आमतौर पर सटीक ऑफ़सेट की ओर इशारा करता है)
- `IEND` के बाद अतिरिक्त डेटा के बारे में चेतावनियाँ

यदि आपको chunk का गहन दृश्य चाहिए:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
उपयोगी संदर्भ:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### तकनीक

JPEG कच्चे पिक्सल के रूप में स्टोर नहीं होता; यह DCT domain में compressed होता है। इसलिए JPEG stego tools, PNG LSB tools से अलग होते हैं:

- Metadata/comment payloads फ़ाइल-स्तर के होते हैं (high-signal और जल्दी जांचने योग्य)
- DCT-domain stego tools frequency coefficients में bits embed करते हैं

ऑपरेशनल रूप से, JPEG को इस तरह ट्रीट करें:

- metadata segments के लिए एक container (high-signal, जल्दी जांचने योग्य)
- एक compressed signal domain (DCT coefficients) जहाँ specialized stego tools काम करते हैं

### त्वरित जाँच
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### सामान्य टूल

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

यदि आप विशेष रूप से JPEGs में steghide payloads का सामना कर रहे हैं, तो `stegseek` का उपयोग करने पर विचार करें (पुराने scripts की तुलना में तेज़ bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA विभिन्न recompression artifacts को हाइलाइट करता है; यह आपको उन क्षेत्रों की ओर इशारा कर सकता है जिन्हें संपादित किया गया था, लेकिन यह स्वयं में stego detector नहीं है:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## एनीमेटेड इमेजेस

### तकनीक

एनीमेटेड इमेजेस के लिए, मान लें कि संदेश:

- एक अकेले फ़्रेम में (आसान), या
- फ़्रेमों में फैला हुआ (क्रम महत्त्वपूर्ण), या
- केवल तब दिखाई देता है जब आप लगातार फ़्रेमों का diff करें

### फ़्रेम निकालें
```bash
ffmpeg -i anim.gif frame_%04d.png
```
फिर frames को सामान्य PNGs की तरह मानें: `zsteg`, `pngcheck`, channel isolation.

वैकल्पिक टूलिंग:

- `gifsicle --explode anim.gif` (fast frame extraction)
- `imagemagick`/`magick` per-frame transforms के लिए

Frame differencing अक्सर निर्णायक होता है:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## पासवर्ड-संरक्षित एम्बेडिंग

यदि आपको संदेह है कि एम्बेडिंग पिक्सेल-स्तरीय हेरफेर के बजाय passphrase द्वारा संरक्षित है, तो यह सामान्यतः सबसे तेज़ मार्ग होता है।

### steghide

यह `JPEG, BMP, WAV, AU` को समर्थन करता है और encrypted payloads को embed/extract कर सकता है।
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to the repository files. Please paste the contents of src/stego/images/README.md here (or the portion you want translated), and I'll return the exact markdown with the English text translated to Hindi.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV का समर्थन करता है.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
