# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

अधिकांश stego समस्याएं random tools आज़माने के बजाय systematic triage से जल्दी हल हो जाती हैं।

## Core flow

### Quick triage checklist

लक्ष्य है कि इन दो प्रश्नों के उत्तर कुशलतापूर्वक मिल जाएं:

1. असली container/format क्या है?
2. payload metadata, appended bytes, embedded files या content-level stego में है?

#### 1) Container की पहचान करें
```bash
file target
ls -lah target
```
यदि `file` और extension में असहमति हो, तो suffix पर भरोसा करने के बजाय signature की जाँच करें। `file` भी heuristic है और malformed या polyglot input से भ्रमित हो सकता है। जहाँ उचित हो, common formats को containers मानें (उदाहरण के लिए, OOXML documents ZIP packages होते हैं)।<sup>[[2]](#references)</sup>

#### 2) Metadata और obvious strings देखें
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
एकाधिक encodings आज़माएँ:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) संलग्न डेटा / एम्बेडेड फ़ाइलों की जाँच करें
```bash
binwalk target
binwalk -e target
```
यदि extraction विफल हो जाए लेकिन signatures रिपोर्ट हों, तो `dd` के साथ offsets को manually carve करें और carved region पर `file` फिर से चलाएँ।

#### 4) यदि image

- anomalies का निरीक्षण करें: `magick identify -verbose file`
- यदि PNG/BMP हो, तो bit-planes/LSB enumerate करें: `zsteg -a file.png`
- PNG structure validate करें: `pngcheck -v file.png`
- जब content channel/plane transforms से प्रकट हो सकता हो, तो visual filters (Stegsolve / StegoVeritas) का उपयोग करें

#### 5) यदि audio

- पहले spectrogram (Sonic Visualiser) देखें
- streams को decode/inspect करें: `ffmpeg -v info -i file -f null -`
- यदि audio structured tones जैसा लगे, तो DTMF decoding का परीक्षण करें

### मुख्य tools

ये high-frequency container-level cases पकड़ते हैं: metadata payloads, appended bytes, और extension द्वारा छिपाई गई embedded files।<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
रिपॉजिटरी: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
Project repository: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### फ़ाइल / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data, और polyglot tricks

कई steganography challenges में किसी valid file के बाद extra bytes होते हैं, या extension के आधार पर छिपे हुए archives होते हैं।

#### Appended payloads

कई formats trailing bytes को ignore करते हैं। किसी image/audio container के अंत में ZIP/PDF/script जोड़ा जा सकता है।

त्वरित जांच:
```bash
binwalk file
tail -c 200 file | xxd
```
यदि आपको कोई offset पता है, तो `dd` से carve करें:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

जब `file` भ्रमित हो, तो `xxd` से magic bytes खोजें और ज्ञात signatures से तुलना करें:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Extension में zip न लिखा हो, फिर भी `7z` और `unzip` आज़माएँ:
```bash
7z l file
unzip -l file
```
### Near-stego की असामान्यताएँ

ऐसे patterns के लिए quick links जो नियमित रूप से stego के आस-पास दिखाई देते हैं (binary से QR, braille आदि)।

#### binary से QR codes

यदि किसी blob की length एक perfect square है, तो वह किसी image/QR के लिए raw pixels हो सकता है।
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image सहायक:

- dCode binary-image सहायक।<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator।<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - सबसे लोकप्रिय steganography tools को एक साथ bundled करने वाली Docker image](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [ReFirmLabs/binwalk](https://github.com/korczis/foremost)
- [5] [dCode — Binary Image](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille Translator](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
