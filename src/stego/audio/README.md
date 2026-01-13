# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Mifumo ya kawaida:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Ukaguzi wa haraka

Kabla ya zana maalum:

- Thibitisha maelezo ya codec/container na anomalia:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ikiwa audio ina maudhui yanayofanana na kelele au muundo wa toni, chunguza spectrogram mapema.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego huficha data kwa kuunda muundo wa nishati juu ya muda na frekensi hadi ionekane tu kwenye mchoro wa muda-frekuensi (mara nyingi isiosikika au inachukuliwa kama kelele).

### Sonic Visualiser

Chombo kikuu cha kukagua spectrogram:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Mbadala

- Audacity (spectrogram view, vichujio): https://www.audacityteam.org/
- `sox` can generate spectrograms from the CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio mara nyingi huonekana kama toni za pekee zinazobadilika katika spectrogram. Mara tu unapokuwa na makadirio ya takriban ya center/shift na baud, brute force with `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` hurekebisha gain moja kwa moja na hugundua ton za mark/space; rekebisha `--rx-invert` au `--samplerate` ikiwa pato limeharibika.

## WAV LSB

### Mbinu

Kwa PCM isiyobana (WAV), kila sampuli ni integer. Kubadilisha bits za chini hubadilisha waveform kwa kiasi kidogo sana, hivyo washambuliaji wanaweza kuficha:

- 1 bit kwa sampuli (au zaidi)
- Imepangwa kwa mtiririko ndani ya channels
- Kwa stride/permutation

Familia nyingine za kuficha sauti ambazo unaweza kukutana nazo:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Chanzo: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Mbinu

DTMF huwakilisha herufi kama jozi za frequencies zilizo thabiti (keypad ya simu). Ikiwa audio inaonekana kama midundo ya keypad au beep za mzunguko-mbili za kawaida, jaribu kutafsiri DTMF mapema.

Decoders za mtandaoni:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## References

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
