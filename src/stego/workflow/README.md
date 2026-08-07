# Stego कार्यप्रवाह

{{#include ../../banners/hacktricks-training.md}}

अधिकांश stego समस्याएं random tools आज़माने की तुलना में systematic triage द्वारा अधिक तेज़ी से हल की जाती हैं।

## मुख्य flow

### Quick triage checklist

लक्ष्य दो प्रश्नों के उत्तर कुशलतापूर्वक देना है:

1. वास्तविक container/format क्या है?
2. क्या payload metadata, appended bytes, embedded files या content-level stego में है?

#### 1) Container की पहचान करें
```bash
file target
ls -lah target
```
यदि `file` और extension में असहमति हो, तो `file` पर भरोसा करें। सामान्य formats को उचित होने पर containers मानें (जैसे, OOXML documents ZIP files होते हैं)।

#### 2) Metadata और स्पष्ट strings खोजें
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
#### 3) जोड़े गए डेटा / एम्बेडेड फ़ाइलों की जाँच करें
```bash
binwalk target
binwalk -e target
```
यदि extraction विफल हो जाए लेकिन signatures रिपोर्ट किए जाएं, तो `dd` से offsets को manually carve करें और carved region पर `file` फिर से चलाएं।

#### 4) यदि image

- anomalies का निरीक्षण करें: `magick identify -verbose file`
- यदि PNG/BMP हो, तो bit-planes/LSB enumerate करें: `zsteg -a file.png`
- PNG structure validate करें: `pngcheck -v file.png`
- जब content channel/plane transforms से reveal हो सकता हो, तब visual filters (Stegsolve / StegoVeritas) का उपयोग करें

#### 5) यदि audio

- सबसे पहले spectrogram (Sonic Visualiser)
- streams decode/inspect करें: `ffmpeg -v info -i file -f null -`
- यदि audio structured tones जैसा लगे, तो DTMF decoding test करें

### रोजमर्रा के उपयोगी tools

ये high-frequency container-level cases पकड़ते हैं: metadata payloads, appended bytes और extension से disguise की गई embedded files।<sup>[[1]](#references)</sup>

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
Repo: https://github.com/korczis/foremost

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

कई steganography challenges में किसी valid file के बाद extra bytes होते हैं, या extension के अनुसार छिपाए गए archives होते हैं।

#### Appended payloads

कई formats trailing bytes को ignore करते हैं। किसी image/audio container के साथ ZIP/PDF/script जोड़ा जा सकता है।

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

जब `file` भ्रमित हो, तो `xxd` से magic bytes देखें और ज्ञात signatures से तुलना करें:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Extension में zip न लिखा हो, तब भी `7z` और `unzip` आज़माएँ:
```bash
7z l file
unzip -l file
```
### Stego के निकट की असामान्यताएँ

उन patterns के लिए quick links जो नियमित रूप से stego के पास दिखाई देते हैं (binary से QR, braille, आदि)।

#### binary से QR codes

यदि किसी blob की length एक पूर्ण वर्ग है, तो वह किसी image/QR के लिए raw pixels हो सकती है।
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### ब्रेल

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## संदर्भ

- [1] [DominicBreuker/stego-toolkit - सबसे लोकप्रिय steganography tools को एक साथ शामिल करने वाली Docker image](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
