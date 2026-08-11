# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Uobičajeni obrasci:

- Poruke u spektrogramu
- WAV LSB embedding
- DTMF / kodiranje tonova biranja
- Metadata payloads

## Brza trijaža

Pre korišćenja specijalizovanih alata:

- Potvrdite detalje codec/container formata i anomalije:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ako audio sadrži sadržaj nalik šumu ili tonalnu strukturu, rano pregledajte spektrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spektrogramska steganografija

### Technique

Spectrogram stego skriva podatke oblikovanjem energije kroz vreme/frekvenciju, tako da postanu vidljivi na vremensko-frekvencijskom prikazu, dok zvuk može podsećati na tonove ili šum.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Primarni alat za analizu spektrograma:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (prikaz spektrograma i filteri).<sup>[[6]](#references)</sup>
- `sox` može da generiše spektrograme iz CLI-ja:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / dekodiranje modema

Audio sa frequency-shift keying-om često izgleda kao smenjivanje pojedinačnih tonova na spektrogramu. Kada imate grubu procenu centralne frekvencije/pomaka i baud rate-a, koristite brute force sa `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` podržava Bell i druge FSK režime, kao i prilagođene mark/space frekvencije; proverite njegove opcije umesto da pretpostavite da se svaki snimak može automatski detektovati. Isprobajte `--rx-invert`, eksplicitni baud režim ili `--samplerate <Hz>` kada je izlaz nečitljiv.<sup>[[4]](#references)</sup>

## WAV LSB

### Tehnika

Za nekompresovani PCM (WAV), svaki sample je ceo broj. Izmena bitova niskog reda veoma malo menja talasni oblik, pa napadači mogu sakriti:

- 1 bit po sample-u (ili više)
- Interleaved između kanala
- Uz stride/permutation

Druge porodice tehnika za skrivanje u zvuku na koje možete naići:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (u zavisnosti od formata i alata)

### WavSteg

Sledeće komande koriste WavSteg iz `ragibson/Steganography` toolkit-a.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Zvanični repository i izdanja alata DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tonovi biranja

### Tehnika

DTMF predstavlja svaki signal tastature koristeći jednu frekvenciju iz niske grupe i jednu iz visoke grupe. Ako audio zapis podseća na tonove tastature ili pravilne dvostrukofrekventne zvučne signale, rano testirajte DTMF decoding.<sup>[[5]](#references)</sup>

Online dekoderi:

- `dtmf-detect` alat za browser.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, offline decoder audio datoteka.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — dokumentacija](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — FSK modem komandne linije](https://github.com/kamalmostafa/minimodem)
- [5] [Preporuka ITU-T Q.23 — tehničke karakteristike telefonskih aparata sa tasterima](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — zvanični repository i izdanja](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
