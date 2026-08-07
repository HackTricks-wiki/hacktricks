# Steganography ya Sauti

{{#include ../../banners/hacktricks-training.md}}

Miundo ya kawaida:

- Ujumbe wa Spectrogram
- Uingizaji wa WAV LSB
- Usimbaji wa DTMF / dial tones
- Payloads za Metadata

## Triage ya haraka

Kabla ya kutumia tools maalum:

- Thibitisha maelezo ya codec/container na anomalies:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ikiwa audio ina maudhui yanayofanana na noise au muundo wa tonal, kagua spectrogram mapema.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego huficha data kwa kuunda umbo la nishati katika muda/marudio ili ionekane tu kwenye mchoro wa muda-marudio (mara nyingi haisikiki au hutambulika kama kelele).

### Sonic Visualiser

Chombo kikuu cha kukagua spectrogram:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (mwonekano wa spectrogram, filters): https://www.audacityteam.org/
- `sox` inaweza kutengeneza spectrograms kutoka CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Usimbuaji wa FSK / modem

Sauti ya frequency-shift keyed mara nyingi huonekana kama toni moja zinazobadilishana katika spectrogram. Baada ya kupata makadirio ya awali ya center/shift na baud, tumia brute force kwa `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` autogains na hugundua kiotomatiki toni za mark/space; rekebisha `--rx-invert` au `--samplerate` ikiwa matokeo yamevurugika.

## WAV LSB

### Mbinu

Kwa PCM isiyobanwa (WAV), kila sampuli ni integer. Kubadilisha biti za chini hubadilisha waveform kwa kiwango kidogo sana, hivyo attackers wanaweza kuficha:

- biti 1 kwa kila sampuli (au zaidi)
- Zikiwa zimeingiliana katika channels
- Kwa kutumia stride/permutation

Familia nyingine za audio-hiding unazoweza kukutana nazo:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (hutegemea format na tool)

### WavSteg

Kutoka: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Technique

DTMF husimba herufi kama jozi za masafa yaliyowekwa (keypad ya simu). Ikiwa sauti inafanana na milio ya keypad au milio ya kawaida ya masafa mawili, jaribu DTMF decoding mapema.

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
