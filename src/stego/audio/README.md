# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

सामान्य पैटर्न:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## त्वरित प्राथमिक जाँच

विशेषीकृत tooling से पहले:

- codec/container विवरण और विसंगतियों की पुष्टि करें:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- यदि audio में noise-like content या tonal structure हो, तो प्रारंभ में spectrogram का निरीक्षण करें।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### तकनीक

Spectrogram stego समय/आवृत्ति में ऊर्जा का आकार बदलकर डेटा छुपाता है, ताकि यह केवल एक time-frequency plot में दिखाई दे (अक्सर सुनने में नहीं आता या शोर के रूप में अनुभव होता है)।

### Sonic Visualiser

spectrogram निरीक्षण के लिए प्राथमिक टूल:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### विकल्प

- Audacity (spectrogram view, filters): https://www.audacityteam.org/
- `sox` CLI से spectrograms उत्पन्न कर सकता है:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed ऑडियो अक्सर स्पेक्ट्रोग्राम में alternating single tones की तरह दिखता है। एक बार जब आपके पास एक rough center/shift और baud estimate हो, तो brute force के लिए `minimodem` का उपयोग करें:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` स्वतः gain समायोजित करता है और mark/space tones को autodetect करता है; अगर आउटपुट गड़बड़ हो तो `--rx-invert` या `--samplerate` समायोजित करें।

## WAV LSB

### तकनीक

Uncompressed PCM (WAV) के लिए, प्रत्येक सैंपल एक पूर्णांक होता है। निचले बिट्स में बदलाव waveform को बहुत मामूली रूप से बदलता है, इसलिए हमलावर छुपा सकते हैं:

- प्रति सैंपल 1 bit (या अधिक)
- चैनलों में इंटरलीव्ड
- stride/permutation के साथ

अन्य audio-hiding families जिनका आप सामना कर सकते हैं:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / डायल टोन

### तकनीक

DTMF अक्षरों को निश्चित आवृत्तियों के जोड़ों के रूप में एन्कोड करता है (telephone keypad). यदि ऑडियो कीपैड टोन या नियमित द्वि-आवृत्ति बीप जैसा दिखता है, तो जल्दी DTMF डिकोडिंग टेस्ट करें।

ऑनलाइन डिकोडर:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## संदर्भ

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
