# Stego कार्यप्रवाह

{{#include ../../banners/hacktricks-training.md}}

अधिकांश stego समस्याएँ बेतरतीब tools आज़माने के बजाय व्यवस्थित triage से जल्दी हल होती हैं।

## मुख्य प्रवाह

### त्वरित triage चेकलिस्ट

लक्ष्य दो सवालों के जवाब कुशलता से देना है:

1. असली कंटेनर/फॉर्मेट क्या है?
2. क्या payload metadata, appended bytes, embedded files या content-level stego में है?

#### 1) कंटेनर की पहचान करें

```bash
file target
ls -lah target
```

अगर `file` और extension में असहमति हो, तो suffix पर भरोसा करने के बजाय signature की जाँच करें। `file` भी heuristic पर आधारित है और malformed या polyglot input से भ्रमित हो सकता है। जहाँ उपयुक्त हो, सामान्य formats को containers मानें (उदाहरण के लिए, OOXML documents ZIP packages होते हैं)।<sup>[[2]](#references)</sup>

#### 2) Metadata और स्पष्ट strings खोजें

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

#### 3) अंत में जोड़े गए डेटा / embedded files की जाँच करें

```bash
binwalk target
binwalk -e target
```

यदि extraction विफल हो, लेकिन signatures रिपोर्ट हों, तो `dd` से offsets को manually carve करें और carved region पर `file` फिर से चलाएँ।

#### 4) यदि image हो

- anomalies की जाँच करें: `magick identify -verbose file`
- यदि PNG/BMP हो, तो bit-planes/LSB की सूची बनाएँ: `zsteg -a file.png`
- PNG structure को validate करें: `pngcheck -v file.png`
- जब channel/plane transforms से content सामने आ सकता हो, तो visual filters (Stegsolve / StegoVeritas) का उपयोग करें

#### 5) यदि audio हो

- पहले spectrogram देखें (Sonic Visualiser)
- streams को decode/inspect करें: `ffmpeg -v info -i file -f null -`
- यदि audio structured tones जैसा लगे, तो DTMF decoding आज़माएँ

### ज़रूरी tools

ये container-level के आम मामलों का पता लगाते हैं: metadata payloads, जोड़े गए bytes, और extension के पीछे छिपी embedded files।<sup>[[1]](#references)[[3]](#references)</sup>

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

प्रोजेक्ट repository: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2

```bash
exiftool file
exiv2 file
```

#### file / strings

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Containers, जोड़ा गया डेटा और polyglot tricks

कई steganography challenges में किसी मान्य फ़ाइल के बाद अतिरिक्त bytes होते हैं, या extension बदलकर छिपाए गए archives होते हैं।

#### जोड़े गए payloads

कई formats आखिर में मौजूद bytes को अनदेखा कर देते हैं। किसी image/audio container के बाद ZIP/PDF/script जोड़ा जा सकता है।

तेज़ जाँचें:

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

जब `file` भ्रमित हो, तो `xxd` से magic bytes देखें और ज्ञात signatures से तुलना करें:

```bash
xxd -g 1 -l 32 file
```

#### छद्मवेश में Zip

Extension में zip न लिखा हो, तब भी `7z` और `unzip` आज़माएँ:

```bash
7z l file
unzip -l file
```

### Stego के आस-पास दिखने वाली विचित्रताएँ

Stego के साथ अक्सर दिखने वाले patterns के लिए quick links (QR-from-binary, braille आदि)।

#### Binary से QR codes

अगर किसी blob की लंबाई एक पूर्ण वर्ग है, तो वह किसी image/QR के raw pixels हो सकते हैं।

```python
import math
math.isqrt(2500)  # 50
```

बाइनरी-से-इमेज सहायक:

- dCode बाइनरी-इमेज सहायक।<sup>[[5]](#references)</sup>

#### ब्रेल

- Branah ब्रेल अनुवादक।<sup>[[6]](#references)</sup>

steganography यूटिलिटी और तकनीक-विशिष्ट संसाधनों के व्यापक संग्रह के लिए, साथ में दिए गए stego-toolkit और 0xRick की चुनी हुई सूची देखें।<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - लोकप्रिय steganography टूल्स को एक साथ बंडल करने वाली Docker इमेज](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 ओपन पैकेजिंग कन्वेंशन्स](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [ReFirmLabs/binwalk](https://github.com/korczis/foremost)
- [5] [dCode — बाइनरी इमेज](https://www.dcode.fr/binary-image)
- [6] [Branah — ब्रेल अनुवादक](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganography संसाधन](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
