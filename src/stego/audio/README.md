# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Mifumo ya kawaida:

- Ujumbe kwenye Spectrogram
- Uingizaji wa WAV LSB
- Usimbaji wa DTMF / dial tones
- Payloads za metadata

## Ukaguzi wa haraka

Kabla ya kutumia zana maalum:

- Thibitisha maelezo ya codec/container na anomalies:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ikiwa audio ina maudhui yanayofanana na noise au muundo wa tonal, kagua spectrogram mapema.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Mbinu

Spectrogram stego huficha data kwa kupanga nishati kulingana na muda/marudio ili ionekane tu katika mchoro wa muda-marudio (mara nyingi haisikiki au hutambuliwa kama kelele).

### Sonic Visualiser

Zana kuu ya kukagua spectrogram:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Mibadala

- Audacity (mwonekano wa spectrogram, vichujio): https://www.audacityteam.org/
- `sox` inaweza kutengeneza spectrogram kutoka CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decoding ya FSK / modem

Sauti yenye frequency-shift keying mara nyingi huonekana kama toni moja zinazopishana kwenye spectrogram.<sup>[[1]](#references)</sup> Ukishapata makadirio ya awali ya center/shift na baud, tumia `minimodem` kwa brute force:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` autogains na autodetects mark/space tones; rekebisha `--rx-invert` au `--samplerate` ikiwa output imevurugika.

## WAV LSB

### Technique

Kwa PCM isiyobanwa (WAV), kila sample ni integer. Kubadilisha bits za chini hubadilisha waveform kwa kiwango kidogo sana, hivyo attackers wanaweza kuficha:

- bit 1 kwa kila sample (au zaidi)
- Zikiwa zimeingiliana kwenye channels
- Kwa kutumia stride/permutation

Familia nyingine za audio-hiding unazoweza kukutana nazo:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (hutegemea format na tool)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Mbinu

DTMF husimba herufi kama jozi za frequencies zilizowekwa (keypad ya simu). Ikiwa audio inafanana na keypad tones au beep za dual-frequency zenye mpangilio wa kawaida, jaribu DTMF decoding mapema.

Decoders za mtandaoni:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Marejeleo

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
