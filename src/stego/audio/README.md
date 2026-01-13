# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Algemene patrone:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Vinnige triage

Voor gespesialiseerde gereedskap:

- Bevestig codec/container besonderhede en anomalieë:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- As die audio geraasagtige inhoud of tonale strukture bevat, ondersoek vroegtydig 'n spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tegniek

Spectrogram stego versteek data deur energie oor tyd/frekwensie te vorm, sodat dit slegs in 'n tyd-frekwensie-plot sigbaar is (dikwels onhoorbaar of as geraas ervaar).

### Sonic Visualiser

Primêre hulpmiddel vir spectrogram-inspeksie:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatiewe

- Audacity (spectrogram-uitsig, filters): https://www.audacityteam.org/
- `sox` kan spectrograms vanaf die CLI genereer:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem-dekodering

Frequency-shift keyed audio lyk dikwels soos afwisselende enkele toone in 'n spektrogram. Sodra jy 'n rowwe sentrum/verskuiwing en baud-skatting het, brute force met `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` het outomatiese winsaanpassing en outomatiese opsporing van mark/space-tone; pas `--rx-invert` of `--samplerate` aan as die uitset gestoord is.

## WAV LSB

### Tegniek

Vir ongekomprimeerde PCM (WAV) is elke monster 'n heelgetal. Die verandering van lae bits verander die golfvorm baie effens, sodat aanvallers kan wegsteek:

- 1 bit per monster (of meer)
- Afgewissel oor kanale
- Met 'n stride/permutasie

Ander audio-verborgingsfamilies wat jy moontlik teëkom:

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

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / kiesklanke

### Tegniek

DTMF kodeer karakters as pare van vaste frekwensies (telefoon-toetsenbord). As die klank soos toetsbord-tone of gereelde tweefrekwensie-piepies klink, toets DTMF-dekodering vroeg.

Aanlyn dekodeerders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Verwysings

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
