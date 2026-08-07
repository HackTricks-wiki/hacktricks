# Steganografia audio

{{#include ../../banners/hacktricks-training.md}}

Pattern comuni:

- Messaggi nello spettrogramma
- Embedding LSB WAV
- Encoding DTMF / toni di composizione
- Payload nei metadati

## Triage rapido

Prima di utilizzare strumenti specializzati:

- Conferma i dettagli del codec/container e le anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se l'audio contiene contenuti simili a rumore o una struttura tonale, analizza tempestivamente uno spettrogramma.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Steganografia tramite spettrogramma

### Technique

Spectrogram stego nasconde i dati modellando l'energia nel tempo e nella frequenza, in modo che diventino visibili solo in un grafico tempo-frequenza (spesso impercettibili o percepiti come rumore).

### Sonic Visualiser

Strumento principale per l'analisi degli spettrogrammi:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (visualizzazione dello spettrogramma, filtri): https://www.audacityteam.org/
- `sox` può generare spettrogrammi dalla CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodifica FSK / modem

L'audio con frequency-shift keying appare spesso come una sequenza alternata di toni singoli in uno spettrogramma. Una volta ottenuta una stima approssimativa della frequenza centrale/dello shift e del baud rate, esegui il brute force con `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` autogains e autodetects i toni mark/space; regola `--rx-invert` o `--samplerate` se l'output è illeggibile.

## WAV LSB

### Tecnica

Per il PCM non compresso (WAV), ogni sample è un intero. La modifica dei bit meno significativi cambia la forma d'onda in modo molto lieve, quindi gli attacker possono nascondere:

- 1 bit per sample (o più)
- Interleaved tra i canali
- Con uno stride/una permutazione

Altre famiglie di audio-hiding che potresti incontrare:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (in base al formato e al tool)

### WavSteg

Da: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / toni di composizione

### Tecnica

DTMF codifica i caratteri come coppie di frequenze fisse (tastiera telefonica). Se l’audio ricorda i toni di una tastiera o dei beep regolari a doppia frequenza, prova per prima cosa la decodifica DTMF.

Decoder online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Riferimenti

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
