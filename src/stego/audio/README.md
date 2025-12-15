# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Uobičajeni obrasci:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Brza trijaža

Pre specijalizovanih alata:

- Potvrdite codec/container detalje i anomalije:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ako audio sadrži sadržaj sličan šumu ili tonalnu strukturu, rano pregledajte spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tehnika

Spectrogram stego skriva podatke oblikovanjem energije tokom vremena/frekvencije tako da postanu vidljivi samo na vremensko-frekvencijskom prikazu (često nečujno ili percipirano kao šum).

### Sonic Visualiser

Primarni alat za inspekciju spektrograma:

- https://www.sonicvisualiser.org/

### Alternative

- Audacity (spektrogram prikaz, filteri): https://www.audacityteam.org/
- `sox` može generisati spektrograme iz CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Tehnika

Za nekompresovani PCM (WAV), svaki uzorak je ceo broj. Izmena niskih bitova menja talasni oblik vrlo malo, pa napadači mogu sakriti:

- 1 bit po uzorku (ili više)
- Naizmenično po kanalima
- Sa stride/permutacijom

Druge porodice tehnika skrivanja u zvuku koje možete sresti:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (zavisno od formata i alata)

### WavSteg

Izvor: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / dial tones

### Tehnika

DTMF enkodira karaktere kao parove fiksnih frekvencija (telefonska tastatura). Ako audio podseća na tonove tastature ili regularne dvofrekventne bipove, testirajte DTMF dekodiranje što ranije.

Online dekoderi:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
