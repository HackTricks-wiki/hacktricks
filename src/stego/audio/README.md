# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Uobičajeni obrasci:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Brza trijaža

Pre nego što koristite specijalizovane alate:

- Potvrdite detalje kodeka/kontejnera i anomalije:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ako audio sadrži sadržaj nalik šumu ili tonalnu strukturu, rano pregledajte spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tehnika

Spectrogram stego skriva podatke oblikovanjem energije tokom vremena/frekvencije tako da postanu vidljivi samo na vremensko-frekvencijskom prikazu (često nečujno ili percipirano kao šum).

### Sonic Visualiser

Primarni alat za pregled spektrograma:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativni alati

- Audacity (pregled spektrograma, filteri): https://www.audacityteam.org/
- `sox` može generisati spektrograme iz komandne linije:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Tehnika

Za nekompresovani PCM (WAV), svaki uzorak je ceo broj. Izmena najmanje značajnih bitova menja talasni oblik veoma malo, tako da napadači mogu sakriti:

- 1 bit po uzorku (ili više)
- Mešano po kanalima
- Sa korakom/permutaacijom

Druge tehnike skrivanja u audio zapisima na koje možete naići:

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

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tonovi biranja

### Tehnika

DTMF kodira karaktere kao parove fiksnih frekvencija (tastatura telefona). Ako audio podseća na tonove tastature ili na uobičajene dvofrekventne bipove, testirajte DTMF dekodiranje što ranije.

Online dekoderi:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
