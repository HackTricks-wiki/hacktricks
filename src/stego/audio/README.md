# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Uobičajeni obrasci:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Brza trijaža

Pre specijalizovanih alata:

- Potvrdite detalje codec/container-a i anomalije:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ako audio sadrži šumolik sadržaj ili tonalnu strukturu, rano pregledajte spektrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tehnika

Spectrogram stego skriva podatke oblikovanjem energije tokom vremena/frekvencije tako da postanu vidljivi samo u vremensko-frekvencijskom prikazu (često nečujno ili percipirano kao šum).

### Sonic Visualiser

Primarni alat za pregled spektrograma:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternative

- Audacity (pregled spektrograma, filteri): https://www.audacityteam.org/
- `sox` može generisati spektrograme iz CLI-ja:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio često izgleda kao naizmenični pojedinačni tonovi u spektrogramu. Kada imate grubu procenu center/shift i baud, brute force sa `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` automatski reguliše gain i automatski detektuje mark/space tonove; podesite `--rx-invert` ili `--samplerate` ako je izlaz izobličen.

## WAV LSB

### Tehnika

Za nekompresovani PCM (WAV), svaki uzorak je ceo broj. Izmena niskih bitova menja talasni oblik vrlo malo, pa napadači mogu sakriti:

- 1 bit po uzorku (ili više)
- Naizmenično raspoređeno preko kanala
- Sa korakom/permutacijom

Ostale kategorije skrivanja u audio zapisu koje možete sresti:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Iz: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tonovi biranja

### Tehnika

DTMF kodira karaktere kao parove fiksnih frekvencija (telefonska tastatura). Ako audio podseća na tonove tastature ili na regularne bipove sa dve frekvencije, testirajte DTMF dekodiranje rano.

Online dekoderi:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Izvori

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
