# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

सामान्य पैटर्न:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## त्वरित जाँच

विशेष उपकरणों का उपयोग करने से पहले:

- Codec/container विवरण और असामान्यताओं की पुष्टि करें:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- यदि ऑडियो में शोर जैसा कंटेंट या टोनल संरचना है, तो जल्दी spectrogram का निरीक्षण करें।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego समय/फ़्रीक्वेंसी के अनुसार ऊर्जा को आकार देकर डेटा छुपाता है, ताकि यह केवल टाइम-फ़्रीक्वेंसी प्लॉट में दिखे (अक्सर सुनने में न के बराबर या शोर जैसा महसूस होता है)।

### Sonic Visualiser

Spectrogram निरीक्षण के लिए प्राथमिक टूल:

- https://www.sonicvisualiser.org/

### Alternatives

- Audacity (स्पेक्ट्रोग्राम दृश्य, फ़िल्टर): https://www.audacityteam.org/
- `sox` CLI से स्पेक्ट्रोग्राम जनरेट कर सकता है:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### तकनीक

Uncompressed PCM (WAV) के लिए, प्रत्येक सैंपल एक पूर्णांक होता है। निचले बिट्स में बदलाव वेवफ़ॉर्म को बहुत हल्का बदलता है, इसलिए हमलावर छिपा सकते हैं:

- प्रति सैंपल 1 बिट (या अधिक)
- चैनलों में इंटरलीव्ड
- स्ट्राइड/परम्यूटेशन के साथ

अन्य ऑडियो-छुपाने की तकनीकें जिनसे आप मिल सकते हैं:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

स्रोत: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / डायल टोन

### तकनीक

DTMF अक्षरों को निश्चित जोड़ी वाली आवृत्तियों के रूप में एन्कोड करता है (telephone keypad)। यदि ऑडियो कीपैड टोन या नियमित द्वि-आवृत्ति बीप जैसा दिखता है, तो DTMF डिकोडिंग को जल्दी टेस्ट करें।

ऑनलाइन डिकोडर:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
