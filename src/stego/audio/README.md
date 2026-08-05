# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

सामान्य patterns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## त्वरित triage

विशेषized tooling से पहले:

- codec/container विवरण और anomalies की पुष्टि करें:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- यदि audio में noise-जैसा content या tonal structure हो, तो शुरुआती चरण में spectrogram का निरीक्षण करें।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego समय/frequency पर energy को इस तरह shape करता है कि यह केवल time-frequency plot में दिखाई दे (अक्सर inaudible होता है या noise के रूप में perceived होता है)।

### Sonic Visualiser

Spectrogram inspection के लिए primary tool:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (spectrogram view, filters): https://www.audacityteam.org/
- `sox` CLI से spectrograms generate कर सकता है:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed ऑडियो अक्सर spectrogram में alternating single tones जैसा दिखता है।<sup>[[1]](#references)</sup> एक बार आपके पास rough center/shift और baud estimate हो, तो `minimodem` के साथ brute force करें:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` mark/space tones को अपने-आप gain और detect करता है; यदि output garbled हो, तो `--rx-invert` या `--samplerate` समायोजित करें।

## WAV LSB

### Technique

Uncompressed PCM (WAV) में प्रत्येक sample एक integer होता है। Low bits को बदलने से waveform में बहुत मामूली परिवर्तन होता है, इसलिए attackers छिपा सकते हैं:

- प्रति sample 1 bit (या अधिक)
- Channels में interleaved रूप से
- किसी stride/permutation के साथ

Audio-hiding की अन्य families जिनका आपको सामना हो सकता है:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format और tool पर निर्भर)

### WavSteg

यहाँ से: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / डायल टोन

### तकनीक

DTMF वर्णों को स्थिर frequencies के युग्मों के रूप में encode करता है (telephone keypad)। यदि audio keypad tones या नियमित dual-frequency beeps जैसी लगे, तो DTMF decoding का प्रारंभ में ही परीक्षण करें।

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## संदर्भ

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
