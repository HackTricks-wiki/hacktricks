# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Mbinu za kawaida:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Uchunguzi wa haraka

Kabla ya zana maalum:

- Thibitisha maelezo ya codec/kontena na kasoro zisizo za kawaida:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ikiwa sauti ina maudhui yanayofanana na kelele au muundo wa toni, angalia spectrogram mapema.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Mbinu

Spectrogram stego inaficha data kwa kupangilia nishati juu ya muda/masafa ili ionekane tu kwenye mchoro wa muda-masafa (time-frequency plot) (mara nyingi haisikiki au huhisiwa kama kelele).

### Sonic Visualiser

Zana kuu kwa ukaguzi wa spectrogram:

- https://www.sonicvisualiser.org/

### Mbadala

- Audacity (mwonekano wa spectrogramu, vichujio): https://www.audacityteam.org/
- `sox` inaweza kuzalisha spectrograms kutoka CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Mbinu

Kwa PCM isiyobanwa (WAV), kila sampuli ni nambari nzima. Kubadilisha bits za chini kunabadilisha umbo la mawimbi kwa kiasi kidogo sana, hivyo washambuliaji wanaweza kuficha:

- 1 bit kwa sampuli (au zaidi)
- Imepangwa kwa kuingiliana kati ya chaneli
- kwa stride/permutation

Other audio-hiding families you may encounter:

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

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / sauti za kupiga nambari

### Mbinu

DTMF huweka characters kama jozi za masafa yaliyowekwa (keypad ya simu). Ikiwa sauti inafanana na midundo ya keypad au beep za masafa mawili za kawaida, jaribu ku-decode DTMF mapema.

Online decoders:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
