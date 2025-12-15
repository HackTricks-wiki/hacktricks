# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Pattern comuni:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triage rapido

Prima di tooling specializzato:

- Conferma i dettagli di codec/container e anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se l'audio contiene contenuti simili a rumore o una struttura tonale, ispeziona uno spectrogram fin da subito.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tecnica

Spectrogram stego nasconde i dati modellando l'energia nel tempo/frequenza in modo che diventi visibile solo in un grafico tempo-frequenza (spesso inaudibile o percepito come rumore).

### Sonic Visualiser

Strumento principale per l'ispezione dello spettrogramma:

- https://www.sonicvisualiser.org/

### Alternative

- Audacity (visualizzazione spettrogramma, filtri): https://www.audacityteam.org/
- `sox` può generare spettrogrammi dalla CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Tecnica

Per PCM non compresso (WAV), ogni campione è un intero. Modificando i bit meno significativi si altera la forma d'onda in modo molto lieve, quindi un attaccante può nascondere:

- 1 bit per campione (o più)
- Interlacciati tra i canali
- Con uno stride/permutazione

Altre famiglie di nascondimento audio che potresti incontrare:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Da: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / toni di composizione

### Tecnica

DTMF codifica i caratteri come coppie di frequenze fisse (tastierino telefonico). Se l'audio somiglia a toni del tastierino o a segnali regolari a doppia frequenza, prova la decodifica DTMF subito.

Decoder online:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
