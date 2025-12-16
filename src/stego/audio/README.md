# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

सामान्य पैटर्न:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## त्वरित प्राथमिक जाँच

विशेषीकृत टूलिंग से पहले:

- codec/container विवरण और अनियमितताओं की पुष्टि करें:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- यदि audio में noise-like सामग्री या tonal संरचना हो, तो प्रारम्भ में spectrogram का निरीक्षण करें।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### तकनीक

Spectrogram stego समय/आवृत्ति के दौरान ऊर्जा को इस तरह आकार देकर डेटा छुपाता है कि यह केवल एक समय-आवृत्ति प्लॉट में दिखाई देता है (अक्सर सुनाई नहीं देता या शोर के रूप में महसूस होता है)।

### Sonic Visualiser

spectrogram निरीक्षण के लिए प्राथमिक उपकरण:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### विकल्प

- Audacity (spectrogram दृश्य, फ़िल्टर): https://www.audacityteam.org/
- `sox` CLI से spectrograms उत्पन्न कर सकता है:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### तकनीक

Uncompressed PCM (WAV) के लिए, प्रत्येक sample एक पूर्णांक होता है। निचले बिट्स (low bits) में संशोधन waveform को बहुत मामूली रूप से बदलता है, इसलिए हमलावर छिपा सकते हैं:

- 1 bit per sample (or more)
- Interleaved across channels
- With a stride/permutation

अन्य audio-hiding परिवार जिनका आप सामना कर सकते हैं:

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

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### तकनीक

DTMF अक्षरों को निश्चित आवृत्तियों के जोड़ों के रूप में encode करता है (telephone keypad)। अगर ऑडियो keypad tones या regular dual-frequency beeps जैसा लगे, तो DTMF decoding को जल्दी टेस्ट करें।

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
