# Audio steganografija

{{#include ../../banners/hacktricks-training.md}}

Uobičajeni obrasci:

- Poruke u spektrogramu
- WAV LSB embedding
- DTMF / kodiranje tonskih signala
- Payloadi u metapodacima

## Brza trijaža

Pre korišćenja specijalizovanih alata:

- Proverite detalje kodeka/kontejnera i anomalije:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ako audio sadrži sadržaj nalik šumu ili tonalnu strukturu, rano pregledajte spektrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Steganografija pomoću spektrograma

### Tehnika

Spectrogram stego skriva podatke oblikovanjem energije kroz vreme/frekvenciju, tako da postaju vidljivi samo na prikazu vremensko-frekvencijskog odnosa (često su nečujni ili se doživljavaju kao šum).

### Sonic Visualiser

Primarni alat za analizu spektrograma:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternative

- Audacity (prikaz spektrograma, filteri): https://www.audacityteam.org/
- `sox` može da generiše spektrograme iz CLI-ja:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / dekodiranje modema

Audio sa frekvencijskim pomeranjem često izgleda kao smenjivanje pojedinačnih tonova na spektrogramu. Kada imate približnu procenu centralne frekvencije/pomeraja i baud rate-a, primenite brute force pomoću `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` automatski podešava pojačanje i detektuje mark/space tonove; prilagodite `--rx-invert` ili `--samplerate` ako je izlaz nečitljiv.

## WAV LSB

### Technique

Za nekompresovani PCM (WAV), svaki sample je ceo broj. Izmena bitova nižeg reda veoma malo menja talasni oblik, pa napadači mogu sakriti:

- 1 bit po sample-u (ili više)
- Između kanala
- Pomoću stride/permutation

Druge familije za skrivanje u audio-zapisima na koje možete naići:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (zavisi od formata i alata)

### WavSteg

Izvor: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tonski signali

### Tehnika

DTMF kodira znakove kao parove fiksnih frekvencija (telefonska tastatura). Ako audio podseća na tonove tastature ili pravilne dvostruke frekvencijske zvučne signale, rano testirajte DTMF dekodiranje.

Online dekoderi:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Reference

- [1] [Flagvent 2025 (Medium) — pink, Deda Mrazova lista želja, Božićni metapodaci, Uhvaćeni šum](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
