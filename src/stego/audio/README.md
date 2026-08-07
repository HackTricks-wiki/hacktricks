# Audio-steganografie

{{#include ../../banners/hacktricks-training.md}}

Algemene patrone:

- Spectrogram-boodskappe
- WAV LSB-embedding
- DTMF / kiestone-enkodering
- Metadata-payloads

## Vinnige triage

Voor gespesialiseerde tooling:

- Bevestig codec-/containerbesonderhede en anomalieë:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- As die audio geraasagtige inhoud of tonale struktuur bevat, inspekteer vroegtydig 'n spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganografie

### Tegniek

Spectrogram stego verberg data deur energie oor tyd/frekwensie te vorm sodat dit slegs in ’n tyd-frekwensie-grafiek sigbaar word (dikwels onhoorbaar of as geraas waargeneem).

### Sonic Visualiser

Primêre hulpmiddel vir spektrogram-ondersoek:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatiewe

- Audacity (spektrogram-aansig, filters): https://www.audacityteam.org/
- `sox` kan spektrogramme vanaf die CLI genereer:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem-dekodering

Frequency-shift keyed-klank lyk dikwels soos afwisselende enkeltonings in ’n spektrogram. Sodra jy ’n ruwe sentrum-/skuif- en baud-skatting het, brute force met `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` verstel die wins outomaties en bespeur mark-/spasietone outomaties; pas `--rx-invert` of `--samplerate` aan indien die uitvoer onverstaanbaar is.

## WAV LSB

### Tegniek

Vir ongekomprimeerde PCM (WAV) is elke sample ’n heelgetal. Deur lae bisse te wysig, verander die golfvorm baie effens, sodat aanvallers die volgende kan versteek:

- 1 bis per sample (of meer)
- Geïnterleaveer oor kanale
- Met ’n stride/permutasie

Ander families van audio-hiding wat jy kan teëkom:

- Fasekodering
- Eggo-verberging
- Spread-spectrum embedding
- Codec-side channels (afhanklik van formaat en tool)

### WavSteg

Van: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / skakeltonе

### Tegniek

DTMF enkodeer karakters as pare vaste frekwensies (telefoonsleutelbord). As die klank soos sleutelbordtone of gereelde dubbelfrekwensie-piepings lyk, toets DTMF-dekodering vroeg.

Aanlyn-dekodeerders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Verwysings

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
