# ऑडियो स्टेगनोग्राफी

{{#include ../../banners/hacktricks-training.md}}

सामान्य पैटर्न:

- स्पेक्ट्रोग्राम संदेश
- WAV LSB एम्बेडिंग
- DTMF / डायल टोन एन्कोडिंग
- मेटाडेटा payloads

## त्वरित प्रारंभिक जाँच

विशेष टूल्स का उपयोग करने से पहले:

- कोडेक/कंटेनर की जानकारी और असामान्यताओं की पुष्टि करें:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- अगर ऑडियो में शोर जैसी सामग्री या टोनल संरचना हो, तो जल्दी ही स्पेक्ट्रोग्राम देखें।

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## स्पेक्ट्रोग्राम स्टेगनोग्राफी

### तकनीक

Spectrogram stego में समय/आवृत्ति के साथ ऊर्जा को इस तरह आकार देकर डेटा छिपाया जाता है कि वह समय-आवृत्ति प्लॉट में दिखाई दे, जबकि ऑडियो टोन या शोर जैसा सुनाई दे सकता है।<sup>[[3]](#references)</sup>

### Sonic Visualiser

स्पेक्ट्रोग्राम का निरीक्षण करने के लिए मुख्य टूल:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### विकल्प

- Audacity (स्पेक्ट्रोग्राम व्यू और फ़िल्टर)।<sup>[[6]](#references)</sup>
- `sox` CLI से स्पेक्ट्रोग्राम जनरेट कर सकता है:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / modem डिकोडिंग

Frequency-shift keyed audio अक्सर spectrogram में बारी-बारी से आने वाले single tones जैसा दिखता है। एक मोटा center/shift और baud का अनुमान मिलने के बाद, `minimodem` से brute force करें:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` Bell और अन्य FSK modes के साथ-साथ custom mark/space frequencies को support करता है; हर recording के autodetect होने की धारणा बनाने के बजाय इसके options देखें। अगर output गड़बड़ हो, तो `--rx-invert`, कोई explicit baud mode या `--samplerate <Hz>` आज़माएँ।<sup>[[4]](#references)</sup>

## WAV LSB

### तकनीक

Uncompressed PCM (WAV) में हर sample एक integer होता है। Low bits में बदलाव से waveform में बहुत मामूली परिवर्तन होता है, इसलिए हमलावर ये छिपा सकते हैं:

- हर sample में 1 bit (या उससे अधिक)
- Channels में interleaved करके
- Stride/permutation का उपयोग करके

Audio-hiding की अन्य श्रेणियाँ जिनका सामना हो सकता है:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format और tool पर निर्भर)

### WavSteg

नीचे दिए गए commands `ragibson/Steganography` toolkit के WavSteg का उपयोग करते हैं।<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- DeepSound का आधिकारिक repository और releases।<sup>[[7]](#references)</sup>

## DTMF / डायल टोन

### तकनीक

DTMF में प्रत्येक keypad signal को एक low group और एक high group की एक-एक frequency से दर्शाया जाता है। अगर audio keypad tones या नियमित dual-frequency beeps जैसी लगे, तो शुरुआत में ही DTMF decoding आज़माएँ।<sup>[[5]](#references)</sup>

ऑनलाइन decoders:

- `dtmf-detect` browser tool।<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, audio files के लिए offline decoder।<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa की Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — दस्तावेज़ीकरण](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — command-line FSK modem](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — push-button telephone sets की तकनीकी विशेषताएँ](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — आधिकारिक repository और releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
