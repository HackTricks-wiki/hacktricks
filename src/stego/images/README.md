# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

अधिकांश CTF image stego इन श्रेणियों में आता है:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk की असामान्यताएँ / corruption repair
- JPEG DCT-domain tools (OutGuess आदि)
- Frame-based (GIF/APNG)

## शुरुआती जाँच

गहराई से content analysis करने से पहले container-level evidence को प्राथमिकता दें:

- File को validate करें और उसकी structure देखें: `file`, `magick identify -verbose`, format validators (जैसे, `pngcheck`)।
- Metadata और दिखाई देने वाले strings निकालें: `exiftool -a -u -g1`, `strings`।
- Embedded/appended content की जाँच करें: `binwalk` और file के अंत का निरीक्षण (`tail | xxd`)।
- Container के आधार पर आगे बढ़ें:
  - PNG/BMP: bit-planes/LSB और chunk-level anomalies।
  - JPEG: metadata और DCT-domain tooling (OutGuess/F5-style families)।
  - GIF/APNG: frame extraction, frame differencing, palette tricks।

## Bit-planes / LSB

### Technique

PNG/BMP CTFs में लोकप्रिय हैं, क्योंकि इनमें pixels इस तरह store होते हैं कि **bit-level manipulation** आसान हो जाती है। छिपाने/निकालने का पारंपरिक तरीका यह है:

- हर pixel channel (R/G/B/A) में कई bits होते हैं।
- हर channel का **least significant bit** (LSB) image में बहुत कम बदलाव करता है।
- हमलावर इन low-order bits में data छिपाते हैं, कभी-कभी stride, permutation या किसी खास channel के चयन के साथ।

Challenges में इनकी अपेक्षा रखें:

- Payload सिर्फ़ एक channel में हो (जैसे, `R` LSB)।
- Payload alpha channel में हो।
- Extraction के बाद payload compressed/encoded हो।
- Message कई planes में फैला हो या planes के बीच XOR से छिपाया गया हो।

अन्य families भी मिल सकती हैं (implementation पर निर्भर):

- **LSB matching** (सिर्फ़ bit को flip करना नहीं, बल्कि target bit से मिलाने के लिए +/-1 adjustment करना)
- **Palette/index-based hiding** (indexed PNG/GIF: raw RGB के बजाय color indices में payload)
- **Alpha-only payloads** (RGB view में पूरी तरह अदृश्य)

### Tooling

#### zsteg

`zsteg` PNG/BMP के लिए कई LSB/bit-plane extraction patterns को enumerate करता है:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: transforms का एक समूह चलाता है (metadata, image transforms, LSB variants की brute forcing)।
- `stegsolve`: manual visual filters (channel isolation, plane inspection, XOR, आदि)।

Stegsolve डाउनलोड: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-आधारित visibility tricks

FFT, LSB extraction नहीं है; इसका इस्तेमाल उन मामलों में होता है जहाँ content को जानबूझकर frequency space या subtle patterns में छिपाया गया हो।

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTFs में अक्सर इस्तेमाल होने वाले web-based triage tools:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption और छिपा हुआ data

### Technique

PNG एक chunked format है। कई challenges में payload, pixel values के बजाय container/chunk level पर stored होता है:

- **`IEND` के बाद अतिरिक्त bytes** (कई viewers trailing bytes को अनदेखा करते हैं)
- **Non-standard ancillary chunks** जिनमें payloads होते हैं
- **Corrupted headers** जो dimensions छिपाते हैं या उन्हें ठीक किए जाने तक parsers को काम करने से रोकते हैं

जाँचने के लिए high-signal chunk locations:

- `tEXt` / `iTXt` / `zTXt` (text metadata, कभी-कभी compressed)
- `iCCP` (ICC profile) और carrier के रूप में इस्तेमाल किए गए अन्य ancillary chunks
- `eXIf` (PNG में EXIF data)

### Triage commands

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

क्या देखें:

- असामान्य width/height/bit-depth/colour-type संयोजन
- CRC/chunk त्रुटियाँ (pngcheck आमतौर पर सटीक offset बताता है)
- `IEND` के बाद अतिरिक्त डेटा होने की चेतावनियाँ

अगर आपको chunks का अधिक विस्तृत दृश्य चाहिए:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

संदर्भ के लिए उपयोगी:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, और ELA की सीमाएँ

### Technique

JPEG raw pixels के रूप में stored नहीं होता; इसे DCT domain में compress किया जाता है। इसीलिए JPEG stego tools, PNG LSB tools से अलग होते हैं:

- Metadata/comment payloads file-level पर होते हैं (आसानी से दिखाई देते हैं और जल्दी inspect किए जा सकते हैं)
- DCT-domain stego tools, frequency coefficients में bits embed करते हैं

व्यावहारिक रूप से, JPEG को इस तरह देखें:

- Metadata segments का एक container (आसानी से दिखाई देता है और जल्दी inspect किया जा सकता है)
- एक compressed signal domain (DCT coefficients), जिसमें specialized stego tools काम करते हैं

### त्वरित जाँचें

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

महत्वपूर्ण स्थान:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### सामान्य टूल

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

अगर आप विशेष रूप से JPEGs में steghide payloads का सामना कर रहे हैं, तो `stegseek` इस्तेमाल करने पर विचार करें (पुरानी scripts की तुलना में तेज़ bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA अलग-अलग recompression artifacts को हाइलाइट करता है; यह उन क्षेत्रों की ओर संकेत कर सकता है जिन्हें संपादित किया गया था, लेकिन यह अपने आप में stego detector नहीं है:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## एनिमेटेड छवियां

### तकनीक

एनिमेटेड छवियों के लिए मान लें कि संदेश:

- एक ही frame में है (आसान), या
- frames में फैला हुआ है (क्रम मायने रखता है), या
- केवल लगातार frames का diff करने पर दिखाई देता है

### Frames निकालें

```bash
ffmpeg -i anim.gif frame_%04d.png
```

फिर frames को सामान्य PNGs की तरह देखें: `zsteg`, `pngcheck`, channel isolation।

वैकल्पिक tooling:

- `gifsicle --explode anim.gif` (तेज़ी से frames निकालने के लिए)
- हर frame पर transforms लागू करने के लिए `imagemagick`/`magick`

अक्सर frame differencing निर्णायक साबित होता है:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG पिक्सेल-गणना एन्कोडिंग

- APNG कंटेनरों का पता लगाएँ: `exiftool -a -G1 file.png | grep -i animation` या `file`।
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

Animated challenges में प्रत्येक byte को हर frame में किसी खास रंग की गिनती के रूप में encode किया जा सकता है; इन गिनतियों को जोड़ने पर message फिर से बन जाता है।<sup>[[1]](#references)</sup>

## पासवर्ड-सुरक्षित embedding

अगर आपको लगता है कि embedding, pixel-level manipulation के बजाय किसी passphrase से सुरक्षित है, तो आमतौर पर यह सबसे तेज़ तरीका है।

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

रिपॉजिटरी: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV को सपोर्ट करता है।

रिपॉजिटरी: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa की Wishlist, क्रिसमस मेटाडेटा, कैप्चर किया गया शोर](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
