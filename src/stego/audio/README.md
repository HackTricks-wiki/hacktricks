# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Algemene patrone:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Vinnige triage

Voor gespesialiseerde gereedskap:

- Bevestig codec/container-besonderhede en anomalieë:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- As die audio geraas-agtige klankinhoud of tonale struktuur bevat, ondersoek vroegtydig 'n spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tegniek

Spectrogram stego verberg data deur energie oor tyd/frekwensie te vorm, sodat dit slegs in ’n tyd-frekwensie-grafiek sigbaar word (dikwels onhoorbaar of as geraas waargeneem).

### Sonic Visualiser

Primêre hulpmiddel vir die inspeksie van spektrogramme:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatiewe

- Audacity (spektrogram-uitsig en filters): https://www.audacityteam.org/
- `sox` kan spektrogramme vanaf die CLI genereer:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Tegniek

Vir uncompressed PCM (WAV) is elke sample ŉ heelgetal. Deur die lae bits aan te pas verander die golfvorm baie min, sodat aanvallers kan wegsteek:

- 1 bit per sample (of meer)
- Geïnterleef oor kanale
- Met 'n stride/permutation

Andere audio-hiding families wat jy mag teëkom:

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

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / kiesklanke

### Tegniek

DTMF enkodeer karakters as pare vaste frekwensies (telefoontoetsbord). As die klank soos toetsbordtone of gereelde tweefrekwensie-piepies lyk, toets DTMF-dekodering vroeg.

Aanlyn-dekoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
