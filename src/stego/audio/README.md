# Steganografija u zvuku

{{#include ../../banners/hacktricks-training.md}}

Uobičajeni obrasci:

- Poruke u spektrogramu
- WAV LSB embedding
- DTMF / kodiranje tonovima biranja
- Payloadi u metapodacima

## Brza trijaža

Pre upotrebe specijalizovanih alata:

- Proveri detalje kodeka/kontejnera i anomalije:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Ako audio sadrži sadržaj nalik šumu ili tonsku strukturu, rano pregledaj spektrogram.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Steganografija spektrograma

### Tehnika

Steganografija spektrograma skriva podatke oblikovanjem energije tokom vremena/frekvencije tako da postanu vidljivi na vremensko-frekvencijskom grafikonu, dok zvuk može da podseća na tonove ili šum.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Primarni alat za pregled spektrograma:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternative

- Audacity (prikaz spektrograma i filteri).<sup>[[6]](#references)</sup>
- `sox` može da generiše spektrograme iz CLI-ja:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / dekodiranje modema

Audio modulisan frekvencijskim pomeranjem često izgleda kao niz naizmeničnih pojedinačnih tonova na spektrogramu. Kada približno procenite centralnu frekvenciju, pomak i baud rate, isprobajte različite vrednosti pomoću `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` podržava Bell i druge FSK režime, kao i prilagođene mark/space frekvencije; proverite njegove opcije umesto da pretpostavite da svako snimanje može automatski da se prepozna. Ako je izlaz nečitljiv, probajte `--rx-invert`, eksplicitni baud režim ili `--samplerate <Hz>`.<sup>[[4]](#references)</sup>

## WAV LSB

### Tehnika

Kod nekompresovanog PCM-a (WAV), svaki uzorak je ceo broj. Izmena bitova nižeg reda veoma malo menja talasni oblik, pa napadači mogu da sakriju podatke:

- 1 bit po uzorku (ili više)
- Prošarano kroz kanale
- Uz korak/permutaciju

Druge porodice tehnika za skrivanje podataka u zvuku na koje možete naići:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Sporedni kanali kodeka (zavise od formata i alata)

### WavSteg

Sledeće komande koriste WavSteg iz skupa alata `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Zvanični repozitorijum i izdanja za DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tonski signali biranja

### Tehnika

DTMF predstavlja svaki signal na tastaturi pomoću jedne frekvencije iz niske grupe i jedne iz visoke grupe. Ako zvuk podseća na tonove tastature ili pravilne dvostruke tonske signale, rano isprobajte DTMF dekodiranje.<sup>[[5]](#references)</sup>

Onlajn dekoderi:

- Veb-alat `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, dekoder audio datoteka koji radi van mreže.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Deda Mrazova lista želja, božićni metapodaci, snimljeni šum](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — dokumentacija](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — FSK modem komandne linije](https://github.com/kamalmostafa/minimodem)
- [5] [Preporuka ITU-T Q.23 — tehničke karakteristike telefonskih aparata sa tasterima](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — zvanični repozitorijum i izdanja](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
