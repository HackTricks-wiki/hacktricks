# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

सामान्य patterns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## त्वरित triage

विशेषized tooling से पहले:

- codec/container details और anomalies की पुष्टि करें:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- यदि audio में noise-like content या tonal structure है, तो जल्दी spectrogram का निरीक्षण करें।
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego समय/फ्रीक्वेंसी पर energy को इस तरह shape करता है कि यह केवल time-frequency plot में दिखाई दे (अक्सर सुनाई नहीं देता या noise जैसा महसूस होता है)।

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

Frequency-shift keyed audio अक्सर spectrogram में बारी-बारी से आने वाले single tones जैसा दिखाई देता है। एक अनुमानित center/shift और baud estimate प्राप्त हो जाने पर `minimodem` के साथ brute force करें:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` mark/space tones को स्वतः gain करता है और autodetect करता है; यदि output garbled हो, तो `--rx-invert` या `--samplerate` समायोजित करें।

## WAV LSB

### Technique

Uncompressed PCM (WAV) में प्रत्येक sample एक integer होता है। Low bits को modify करने से waveform में बहुत थोड़ा बदलाव आता है, इसलिए attackers छिपा सकते हैं:

- प्रति sample 1 bit (या अधिक)
- Channels के बीच interleaved
- एक stride/permutation के साथ

अन्य audio-hiding families जिनका आपको सामना हो सकता है:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format और tool पर निर्भर)

### WavSteg

स्रोत: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Technique

DTMF characters को fixed frequencies के pairs (telephone keypad) के रूप में encode करता है। यदि audio keypad tones या नियमित dual-frequency beeps जैसी लगती है, तो शुरुआत में ही DTMF decoding को test करें।

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
