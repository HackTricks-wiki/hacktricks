# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Mifumo ya kawaida:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Tathmini ya haraka

Kabla ya zana maalum:

- Thibitisha maelezo ya codec/container na kasoro:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ikiwa sauti ina maudhui yanayofanana na kelele au muundo wa tonal, angalia spectrogram mapema.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Mbinu

Spectrogram stego inaficha data kwa kupangilia nishati kwa muda/frekowensi ili ionekane tu kwenye mchoro wa muda-frekowensi (mara nyingi hainsikiki au huhesabiwa kama kelele).

### Sonic Visualiser

Zana kuu ya ukaguzi wa spectrogram:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Mbadala

- Audacity (tazamo la spectrogram, vichujio): https://www.audacityteam.org/
- `sox` inaweza kutengeneza spectrograms kutoka CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Mbinu

Kwa PCM (WAV) isiyosimbuliwa, kila sampuli ni integer. Kubadilisha low bits hubadilisha mawimbi kwa kiasi kidogo sana, hivyo washambuliaji wanaweza kuficha:

- 1 bit kwa sampuli (au zaidi)
- Imepangwa kwa kuingiliana kati ya kanali
- Kwa stride/permutation

Other audio-hiding families you may encounter:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (zinategemea format na zana)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / midundo za simu

### Mbinu

DTMF huweka herufi kama jozi za masafa yaliyowekwa (keypad ya simu). Ikiwa sauti inaonekana kama midundo ya keypad au bip za masafa mawili za kawaida, jaribu udekodishaji wa DTMF mapema.

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
