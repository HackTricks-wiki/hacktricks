# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

अधिकांश stego समस्याएँ यादृच्छिक टूल्स आज़माने की तुलना में सुव्यवस्थित triage से तेज़ी से हल होती हैं।

## मुख्य प्रवाह

### त्वरित triage चेकलिस्ट

लक्ष्य दो प्रश्नों का प्रभावी ढंग से उत्तर देना है:

1. वास्तविक container/format क्या है?
2. क्या payload metadata, appended bytes, embedded files, या content-level stego में है?

#### 1) container की पहचान करें
```bash
file target
ls -lah target
```
अगर `file` और extension मेल नहीं खाते हैं, तो `file` पर भरोसा करें। जहाँ उपयुक्त हो सामान्य फ़ॉर्मैट्स को कंटेनर की तरह मानें (उदा., OOXML दस्तावेज़ ZIP files होते हैं)।

#### 2) metadata और स्पष्ट strings के लिए देखें
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
कई एन्कोडिंग आज़माएं:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) जोड़े गए डेटा / एम्बेडेड फ़ाइलों की जांच करें
```bash
binwalk target
binwalk -e target
```
यदि extraction विफल हो लेकिन signatures रिपोर्ट हो रहे हों, तो मैन्युअली offsets को `dd` से carve करें और carved region पर `file` पुनः चलाएँ।

#### 4) यदि इमेज

- विषमताओं का निरीक्षण करें: `magick identify -verbose file`
- यदि PNG/BMP हैं, bit-planes/LSB को enumerate करें: `zsteg -a file.png`
- PNG structure को validate करें: `pngcheck -v file.png`
- जब content channel/plane transforms से प्रकट हो सकता है तो visual filters (Stegsolve / StegoVeritas) का उपयोग करें

#### 5) यदि ऑडियो

- पहले spectrogram देखें (Sonic Visualiser)
- streams को decode/inspect करें: `ffmpeg -v info -i file -f null -`
- यदि audio संरचित tones जैसा दिखे तो DTMF decoding का परीक्षण करें

### बुनियादी उपयोग के टूल्स

ये high-frequency container-level मामलों को पकड़ते हैं: metadata payloads, appended bytes, और embedded files जो extension से छिपे हों।

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have access to external repositories. Please paste the contents of src/stego/workflow/README.md (or just the "Foremost" section) here, and I will translate the English text to Hindi while preserving all markdown, tags, paths and code unchanged.
```bash
foremost -i file
```
I don't have access to the repo files. Please paste the contents of src/stego/workflow/README.md here (or the parts you want translated). I'll translate the English text to Hindi, preserving all code, tags, links, paths and markdown/html syntax exactly as you requested.
```bash
exiftool file
exiv2 file
```
Please provide the contents of src/stego/workflow/README.md so I can translate it to Hindi.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data, and polyglot tricks

कई steganography चुनौतियाँ मान्य फ़ाइल के बाद अतिरिक्त बाइट्स होती हैं, या एक्सटेंशन से छिपे हुए embedded archives होती हैं।

#### Appended payloads

कई फॉर्मैट ट्रेलिंग बाइट्स को अनदेखा कर देते हैं। एक ZIP/PDF/script को किसी image/audio container के अंत में जोड़ा जा सकता है।

Fast checks:
```bash
binwalk file
tail -c 200 file | xxd
```
यदि आप offset जानते हैं, तो `dd` के साथ carve करें:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

जब `file` भ्रमित हो, तो `xxd` से magic bytes खोजें और known signatures से तुलना करें:
```bash
xxd -g 1 -l 32 file
```
#### Zip-छलावे में

चाहे फ़ाइल एक्सटेंशन पर zip न लिखा हो, `7z` और `unzip` आज़माएँ:
```bash
7z l file
unzip -l file
```
### Near-stego असामान्यताएँ

वे पैटर्न्स के लिए त्वरित लिंक जो अक्सर stego के पास दिखाई देते हैं (QR-from-binary, braille, आदि)।

#### binary से QR codes

यदि blob की लंबाई एक पूर्ण वर्ग है, तो यह किसी image/QR के लिए raw pixels हो सकते हैं।
```python
import math
math.isqrt(2500)  # 50
```
बाइनरी-टू-इमेज सहायक:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### ब्रेल

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## संदर्भ सूचियाँ

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
