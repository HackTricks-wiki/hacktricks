# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

सामान्य patterns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## त्वरित triage

विशेषीकृत tooling से पहले:

- codec/container details और anomalies की पुष्टि करें:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- यदि audio में noise-जैसा content या tonal structure हो, तो शुरुआत में ही spectrogram का निरीक्षण करें।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego समय/आवृत्ति के अनुसार energy को इस तरह आकार देता है कि यह time-frequency plot में दिखाई देने लगे, जबकि audio tones या noise जैसा सुनाई दे सकता है।<sup>[[3]](#references)</sup>

### Sonic Visualiser

Spectrogram inspection के लिए primary tool:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (spectrogram view और filters)।<sup>[[6]](#references)</sup>
- `sox` CLI से spectrograms generate कर सकता है:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio अक्सर spectrogram में alternating single tones जैसा दिखता है। एक rough center/shift और baud estimate मिल जाने के बाद, `minimodem` से brute force करें:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` Bell और अन्य FSK modes के साथ-साथ custom mark/space frequencies को support करता है; हर recording को autodetect किया जा सकता है, ऐसा मानने के बजाय इसके options देखें। जब output garbled हो, तो `--rx-invert`, कोई explicit baud mode, या `--samplerate <Hz>` आज़माएँ।<sup>[[4]](#references)</sup>

## WAV LSB

### तकनीक

Uncompressed PCM (WAV) में प्रत्येक sample एक integer होता है। Low bits को modify करने से waveform में बहुत मामूली बदलाव होता है, इसलिए attackers निम्न को hide कर सकते हैं:

- प्रति sample 1 bit (या अधिक)
- Channels के बीच interleaved
- किसी stride/permutation के साथ

Audio-hiding की अन्य families जिनका आपको सामना हो सकता है:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent और tool-dependent)

### WavSteg

निम्न commands `ragibson/Steganography` toolkit से WavSteg का उपयोग करते हैं।<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- DeepSound का official repository और releases।<sup>[[7]](#references)</sup>

## DTMF / डायल टोन

### तकनीक

DTMF प्रत्येक keypad signal को low group की एक frequency और high group की एक frequency का उपयोग करके दर्शाता है। यदि audio keypad tones या नियमित dual-frequency beeps जैसी लगती है, तो DTMF decoding को जल्दी test करें।<sup>[[5]](#references)</sup>

ऑनलाइन decoders:

- `dtmf-detect` browser tool।<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, एक offline audio-file decoder।<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa की Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentation](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — command-line FSK modem](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — push-button telephone sets की technical features](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — official repository और releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
