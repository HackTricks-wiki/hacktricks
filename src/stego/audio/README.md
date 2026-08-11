# Steganografia ya Sauti

{{#include ../../banners/hacktricks-training.md}}

Mifumo ya kawaida:

- Ujumbe wa Spectrogram
- Uingizaji wa WAV LSB
- Usimbaji wa DTMF / dial tones
- Payloads za Metadata

## Uchunguzi wa haraka

Kabla ya kutumia zana maalum:

- Thibitisha maelezo ya codec/container na anomalies:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ikiwa audio ina maudhui yanayofanana na noise au muundo wa tones, kagua spectrogram mapema.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Mbinu

Spectrogram stego huficha data kwa kuunda mpangilio wa nishati kwa muda/marudio ili ionekane katika mchoro wa time-frequency, huku sauti ikiweza kusikika kama tones au noise.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Zana kuu ya kukagua spectrogram:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Njia mbadala

- Audacity (mwonekano wa spectrogram na filters).<sup>[[6]](#references)</sup>
- `sox` inaweza kutengeneza spectrograms kutoka kwa CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Sauti iliyowekwa kwa Frequency-shift keying mara nyingi huonekana kama toni moja zinazopishana kwenye spectrogramu. Baada ya kupata makadirio ya takribani ya center/shift na baud, tumia brute force kwa `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` inasaidia Bell na modes nyingine za FSK pamoja na mark/space frequencies maalum; angalia options zake badala ya kudhani kwamba kila recording inaweza kutambuliwa kiotomatiki. Jaribu `--rx-invert`, baud mode iliyo wazi, au `--samplerate <Hz>` wakati output haieleweki.<sup>[[4]](#references)</sup>

## WAV LSB

### Technique

Kwa PCM isiyobanwa (WAV), kila sample ni integer. Kubadilisha bits za chini hubadilisha waveform kwa kiwango kidogo sana, hivyo attackers wanaweza kuficha:

- bit 1 kwa kila sample (au zaidi)
- Zikiwa zimeingiliana kati ya channels
- Kwa kutumia stride/permutation

Familia nyingine za kuficha data kwenye audio unazoweza kukutana nazo:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (hutegemea format na tool)

### WavSteg

Commands zifuatazo zinatumia WavSteg kutoka kwenye toolkit ya `ragibson/Steganography`.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Hifadhi rasmi ya DeepSound na matoleo yake.<sup>[[7]](#references)</sup>

## DTMF / toni za kupiga

### Mbinu

DTMF huwakilisha kila ishara ya vitufe kwa kutumia frequency moja kutoka kwenye kundi la chini na frequency moja kutoka kwenye kundi la juu. Ikiwa audio inafanana na toni za vitufe au milio miwili ya frequency inayojirudia, jaribu decoding ya DTMF mapema.<sup>[[5]](#references)</sup>

Decoders za mtandaoni:

- Tool ya browser ya `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, decoder ya offline ya mafaili ya audio.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Orodha ya Matamanio ya Santa, Metadata ya Krismasi, Noise Iliyorekodiwa](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — nyaraka](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem ya FSK ya command-line](https://github.com/kamalmostafa/minimodem)
- [5] [Pendekezo la ITU-T Q.23 — vipengele vya kiufundi vya simu zenye vitufe vya kubonyeza](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — hifadhi rasmi na matoleo](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
