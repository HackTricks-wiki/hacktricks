# Steganografia ya Sauti

{{#include ../../banners/hacktricks-training.md}}

Miundo ya kawaida:

- Ujumbe kwenye spectrogram
- Uingizaji wa LSB kwenye WAV
- Usimbaji kwa DTMF / toni za kupiga nambari
- Payloads kwenye metadata

## Uchunguzi wa haraka

Kabla ya kutumia zana maalum:

- Thibitisha maelezo na hitilafu za codec/container:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Ikiwa sauti ina maudhui yanayofanana na kelele au muundo wa toni, kagua spectrogram mapema.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Steganografia ya spectrogramu

### Mbinu

Stego ya spectrogramu huficha data kwa kuunda nishati kwa wakati/marudio ili ionekane kwenye mchoro wa wakati-marudio, huku sauti ikiweza kusikika kama toni au kelele.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Zana kuu ya kukagua spectrogramu:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Njia mbadala

- Audacity (mwonekano wa spectrogramu na vichujio).<sup>[[6]](#references)</sup>
- `sox` inaweza kutengeneza spectrogramu kupitia CLI:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / usimbuaji wa modem

Sauti iliyosimbwa kwa frequency-shift keying mara nyingi huonekana kama toni moja moja zinazopishana kwenye spectrogram. Ukishapata makadirio ya takriban center/shift na baud, tumia brute force kwa `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` inasaidia Bell na modes nyingine za FSK pamoja na masafa maalum ya mark/space; angalia chaguo zake badala ya kudhani kuwa kila rekodi inaweza kutambuliwa kiotomatiki. Jaribu `--rx-invert`, baud mode mahususi, au `--samplerate <Hz>` ikiwa matokeo yamevurugika.<sup>[[4]](#references)</sup>

## WAV LSB

### Mbinu

Kwa PCM isiyobanwa (WAV), kila sample ni integer. Kubadilisha bits za chini hubadilisha waveform kwa kiwango kidogo sana, hivyo washambuliaji wanaweza kuficha:

- bit 1 kwa kila sample (au zaidi)
- Zikiwa zimeingiliana kwenye channels
- Kwa kutumia stride/permutation

Familia nyingine za kuficha data kwenye sauti unazoweza kukutana nazo:

- Phase coding
- Echo hiding
- Uingizaji wa spread-spectrum
- Njia fiche za upande wa codec (hutegemea format na tool)

### WavSteg

Amri zifuatazo zinatumia WavSteg kutoka kwenye toolkit ya `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Hifadhi rasmi ya DeepSound na matoleo yake.<sup>[[7]](#references)</sup>

## DTMF / sauti za kupiga simu

### Mbinu

DTMF huwakilisha kila ishara ya kitufe kwa kutumia masafa moja kutoka kundi la chini na jingine kutoka kundi la juu. Ikiwa sauti inafanana na toni za vitufe au milio ya kawaida ya masafa mawili, jaribu kusimbua DTMF mapema.<sup>[[5]](#references)</sup>

Visimbuaji vya mtandaoni:

- Zana ya kivinjari ya `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, kisimbuaji cha faili za sauti kinachofanya kazi bila intaneti.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Orodha ya Matamanio ya Santa, Metadata za Krismasi, Kelele Zilizonaswa](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — nyaraka](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modemu ya FSK ya mstari wa amri](https://github.com/kamalmostafa/minimodem)
- [5] [Pendekezo la ITU-T Q.23 — sifa za kiufundi za simu zenye vitufe vya kubonyeza](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — hifadhi rasmi na matoleo](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
