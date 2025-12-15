# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Algemene patrone:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Vinnige triage

Voor gespesialiseerde tooling:

- Bevestig codec/container besonderhede en anomalieë:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Indien die audio geraasagtige inhoud of 'n tonale struktuur bevat, ondersoek vroeg 'n spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tegniek

Spectrogram stego verberg data deur energie oor tyd/frekwensie te vorm, sodat dit slegs in 'n tyd-frekwensie-grafiek sigbaar word (dikwels onhoorbaar of as geraas ervaar).

### Sonic Visualiser

Primêre hulpmiddel vir spectrogram-inspeksie:

- https://www.sonicvisualiser.org/

### Alternatiewe

- Audacity (spectrogram-aansig, filters): https://www.audacityteam.org/
- `sox` kan spectrogramme vanaf die CLI genereer:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Tegniek

Vir ongekomprimeerde PCM (WAV) is elke monster 'n heelgetal. Die wysiging van lae bits verander die golfvorm baie effens, sodat aanvallers kan wegsteek:

- 1 bit per monster (of meer)
- Geïnterleef oor kanale
- Met 'n stride/permutasie

Ander audio-wegsteekfamilies wat jy kan teëkom:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Van: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / skakeltonne

### Tegniek

DTMF kodeer karakters as pare van vaste frekwensies (telefoontoetsenbord). As die klank soos toetsentone of gereelde dubbelfrekwensie-piepies klink, toets DTMF-dekodering vroeg.

Aanlyn-dekoders:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
