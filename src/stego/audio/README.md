# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Pattern comuni:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triage rapido

Before specialized tooling:

- Conferma i dettagli del codec/container e eventuali anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se l'audio contiene contenuto simile a rumore o una struttura tonale, ispeziona precocemente un spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Tecnica

Spectrogram stego nasconde dati modellando l'energia nel dominio tempo/frequenza in modo che diventino visibili solo in un grafico tempo-frequenza (spesso inaudibili o percepiti come rumore).

### Sonic Visualiser

Strumento principale per l'analisi degli spettrogrammi:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternative

- Audacity (visualizzazione spettrogramma, filtri): https://www.audacityteam.org/
- `sox` può generare spettrogrammi dalla riga di comando (CLI):
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Tecnica

Per PCM non compresso (WAV), ogni sample è un intero. Modificando i bit meno significativi la forma d'onda cambia molto poco, quindi attackers possono nascondere:

- 1 bit per sample (o più)
- Interlacciato tra i canali
- Con uno stride/permutation

Altre famiglie di tecniche di nascondimento audio che potresti incontrare:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Tecnica

DTMF codifica caratteri come coppie di frequenze fisse (tastierino del telefono). Se l'audio somiglia a toni del tastierino o a bip regolari a doppia frequenza, verifica la decodifica DTMF subito.

Decodificatori online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
