# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Uobičajeni obrasci:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Brza trijaža

Pre korišćenja specijalizovanih alata:

- Proverite detalje codec/container formata i anomalije:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ako audio sadrži sadržaj nalik šumu ili tonalnu strukturu, rano pregledajte spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Steganografija spektrograma

### Tehnika

Spectrogram stego skriva podatke oblikovanjem energije kroz vreme/frekvenciju, tako da postaju vidljivi samo na grafiku vremena i frekvencije (često su nečujni ili se doživljavaju kao šum).

### Sonic Visualiser

Primarni alat za pregled spektrograma:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternative

- Audacity (prikaz spektrograma, filteri): https://www.audacityteam.org/
- `sox` može da generiše spektrograme iz CLI-ja:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem dekodiranje

Audio sa frequency-shift keying često izgleda kao smenjivanje pojedinačnih tonova u spektrogramu.<sup>[[1]](#references)</sup> Kada imate približnu procenu centra/pomaka i baud rate-a, primenite brute force pomoću `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` automatski podešava pojačanje i automatski detektuje mark/space tonove; podesite `--rx-invert` ili `--samplerate` ako je izlaz nečitak.

## WAV LSB

### Technique

Kod nekompresovanog PCM-a (WAV), svaki uzorak je ceo broj. Izmena bitova nižeg reda veoma malo menja talasni oblik, pa napadači mogu sakriti:

- 1 bit po uzorku (ili više)
- Prošarano između kanala
- Pomoću koraka/permutacije

Druge familije za skrivanje u audio-zapisima na koje možete naići:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (zavisno od formata i alata)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tonovi biranja

### Tehnika

DTMF kodira znakove kao parove fiksnih frekvencija (telefonska tastatura). Ako audio podseća na tonove tastature ili pravilne dvostruke frekvencijske tonove, rano testirajte DTMF dekodiranje.

Online dekoderi:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Reference

- [1] [Flagvent 2025 (Medium) — pink, Deda Mrazova lista želja, Božićni metapodaci, Uhvaćeni šum](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
