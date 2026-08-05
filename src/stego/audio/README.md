# Oudio-steganografie

{{#include ../../banners/hacktricks-training.md}}

Algemene patrone:

- Spektrogram-boodskappe
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Vinnige triage

Voor gespesialiseerde tooling:

- Bevestig codec-/containerbesonderhede en anomalieë:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- As die oudio ruisagtige inhoud of tonale struktuur bevat, ondersoek vroegtydig ’n spektrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spektrogram-steganografie

### Tegniek

Spektrogram-stego verberg data deur energie oor tyd/frekwensie te vorm, sodat dit slegs in ’n tyd-frekwensie-grafiek sigbaar word (dikwels onhoorbaar of as geraas waargeneem).

### Sonic Visualiser

Primêre hulpmiddel vir spektrogram-inspeksie:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatiewe

- Audacity (spektrogram-aansig, filters): https://www.audacityteam.org/
- `sox` kan spektrogramme vanaf die CLI genereer:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem-dekodering

Frequency-shift keyed-udio lyk dikwels soos afwisselende enkeltone in ’n spektrogram.<sup>[[1]](#references)</sup> Sodra jy ’n rowwe sentrum-/skuif- en baud-skatting het, gebruik `minimodem` vir brute force:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` pas outomaties die gain aan en bespeur mark/space-tone outomaties; pas `--rx-invert` of `--samplerate` aan indien die uitvoer deurmekaar is.

## WAV LSB

### Technique

Vir ongekomprimeerde PCM (WAV) is elke sample ’n heelgetal. Deur lae bisse te wysig, verander die golfvorm baie effens, sodat aanvallers die volgende kan versteek:

- 1 bis per sample (of meer)
- Geïnterleave oor kanale
- Met ’n stride/permutation

Ander audio-hiding-families wat jy kan teëkom:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (formaat-afhanklik en tool-afhanklik)

### WavSteg

Van: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / kiestone

### Tegniek

DTMF kodeer karakters as pare vaste frekwensies (telefoonsleutelbord). As die klank soos sleutelbordtone of gereelde dubbel-frekwensie-piepseine klink, toets DTMF-dekodering vroeg.

Aanlyn-dekodeerders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Verwysings

- [1] [Flagvent 2025 (Medium) — pienk, Kersvader se wenslys, Kersfees-metadata, vasgelegde geraas](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
