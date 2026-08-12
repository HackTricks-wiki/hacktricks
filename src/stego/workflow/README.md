# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

अधिकांश stego problems को random tools आज़माने की बजाय systematic triage द्वारा तेज़ी से हल किया जाता है।

## मुख्य प्रवाह

### त्वरित triage checklist

लक्ष्य दो प्रश्नों के उत्तर कुशलतापूर्वक देना है:

1. वास्तविक container/format क्या है?
2. क्या payload metadata, appended bytes, embedded files या content-level stego में है?

#### 1) Container की पहचान करें
```bash
file target
ls -lah target
```
यदि `file` और extension में असहमति हो, तो suffix पर भरोसा करने के बजाय signature की जाँच करें। `file` भी heuristic है और malformed या polyglot input से भ्रमित हो सकता है। उचित होने पर common formats को containers की तरह समझें (उदाहरण के लिए, OOXML documents ZIP packages होते हैं)।<sup>[[2]](#references)</sup>

#### 2) Metadata और स्पष्ट strings देखें
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
कई encodings आज़माएँ:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) जोड़ा गया डेटा / एम्बेड की गई फ़ाइलों की जाँच करें
```bash
binwalk target
binwalk -e target
```
यदि extraction विफल हो लेकिन signatures रिपोर्ट हों, तो offsets को `dd` से manually carve करें और carved region पर `file` फिर से चलाएँ।

#### 4) यदि image

- anomalies का निरीक्षण करें: `magick identify -verbose file`
- यदि PNG/BMP हो, तो bit-planes/LSB enumerate करें: `zsteg -a file.png`
- PNG structure validate करें: `pngcheck -v file.png`
- जब content channel/plane transforms से reveal हो सकता हो, तो visual filters (Stegsolve / StegoVeritas) का उपयोग करें

#### 5) यदि audio

- पहले Spectrogram (Sonic Visualiser) देखें
- streams को decode/inspect करें: `ffmpeg -v info -i file -f null -`
- यदि audio structured tones जैसा लगे, तो DTMF decoding test करें

### आवश्यक tools

ये high-frequency container-level cases पकड़ते हैं: metadata payloads, appended bytes और extension से disguised embedded files।<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

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
#### फ़ाइल / स्ट्रिंग्स
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data, और polyglot tricks

कई steganography challenges में किसी valid file के बाद extra bytes होते हैं, या extension के जरिए छिपे हुए embedded archives होते हैं।

#### Appended payloads

कई formats trailing bytes को अनदेखा कर देते हैं। किसी image/audio container के बाद ZIP/PDF/script जोड़ा जा सकता है।

त्वरित जाँच:
```bash
binwalk file
tail -c 200 file | xxd
```
यदि आपको offset पता है, तो `dd` से carve करें:
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

Extension zip न बताने पर भी `7z` और `unzip` आज़माएँ:
```bash
7z l file
unzip -l file
```
### Stego के निकट की असामान्यताएँ

ऐसे patterns के लिए quick links, जो stego के साथ अक्सर दिखाई देते हैं (QR-from-binary, braille आदि)।

#### Binary से QR codes

यदि किसी blob की length perfect square है, तो वह किसी image/QR के लिए raw pixels हो सकता है।
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator.<sup>[[6]](#references)</sup>

Steganography utilities और technique-specific resources के व्यापक संग्रहों के लिए, bundled stego-toolkit और 0xRick की curated list देखें।<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - सबसे लोकप्रिय steganography tools को एक साथ bundled करने वाली Docker image](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binary Image](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille Translator](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganography Resources](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
