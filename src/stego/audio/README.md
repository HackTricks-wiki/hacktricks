# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Schemi comuni:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triage rapido

Prima di utilizzare strumenti specializzati:

- Conferma i dettagli del codec/container e le anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se l'audio contiene contenuti simili al rumore o una struttura tonale, esamina subito uno spettrogramma.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tecnica

Spectrogram stego nasconde dati modellando l'energia nel tempo/frequenza in modo che diventi visibile solo in un grafico tempo-frequenza (spesso inaudibile o percepito come rumore).

### Sonic Visualiser

Strumento principale per l'ispezione degli spettrogrammi:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternative

- Audacity (visualizzazione spettrogramma, filtri): https://www.audacityteam.org/
- `sox` può generare spettrogrammi dalla CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodifica FSK / modem

L'audio frequency-shift keyed spesso appare come toni singoli alternati in uno spettrogramma. Una volta che hai una stima approssimativa del centro/shift e del baud, esegui brute force con `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` imposta automaticamente il guadagno e rileva automaticamente le tonalità mark/space; regola `--rx-invert` o `--samplerate` se l'output è corrotto.

## WAV LSB

### Tecnica

Per PCM non compresso (WAV), ogni sample è un intero. Modificare i bit meno significativi cambia la forma d'onda molto leggermente, quindi gli attaccanti possono nascondere:

- 1 bit per sample (o più)
- Interlacciato tra i canali
- Con uno stride/permutation

Altre famiglie di nascondimento audio che potresti incontrare:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (dipendenti dal formato e dallo strumento)

### WavSteg

Da: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / toni di composizione

### Tecnica

DTMF codifica i caratteri come coppie di frequenze fisse (tastierino telefonico). Se l'audio somiglia a toni del tastierino o a bip regolari a doppia frequenza, verifica la decodifica DTMF il prima possibile.

Decoder online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Riferimenti

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
