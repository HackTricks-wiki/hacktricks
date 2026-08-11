# Steganografia audio

{{#include ../../banners/hacktricks-training.md}}

Pattern comuni:

- Messaggi nello spettrogramma
- Embedding LSB in WAV
- Codifica DTMF / dei toni di chiamata
- Payload nei metadati

## Triage rapido

Prima di usare strumenti specializzati:

- Verifica i dettagli del codec/contenitore e le anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se l'audio contiene contenuti simili a rumore o una struttura tonale, analizza presto uno spettrogramma.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Steganografia dello spettrogramma

### Tecnica

Lo stego dello spettrogramma nasconde i dati modellando l'energia nel tempo e nella frequenza, in modo che diventi visibile in un grafico tempo-frequenza, mentre l'audio può suonare come toni o rumore.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Strumento principale per l'analisi degli spettrogrammi:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternative

- Audacity (visualizzazione dello spettrogramma e filtri).<sup>[[6]](#references)</sup>
- `sox` può generare spettrogrammi dalla CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Decodifica FSK / modem

L'audio con frequency-shift keying appare spesso come toni singoli alternati in uno spettrogramma. Una volta ottenuta una stima approssimativa della frequenza centrale/dello shift e del baud rate, esegui il brute force con `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` supporta le modalità Bell e altri modi FSK, oltre a frequenze mark/space personalizzate; consulta le sue opzioni invece di presumere che ogni registrazione possa essere autodetected. Prova `--rx-invert`, una modalità baud esplicita oppure `--samplerate <Hz>` quando l'output è illeggibile.<sup>[[4]](#references)</sup>

## WAV LSB

### Tecnica

Per il PCM non compresso (WAV), ogni campione è un intero. La modifica dei bit meno significativi cambia la forma d'onda in modo minimo, quindi gli aggressori possono nascondere:

- 1 bit per campione (o più)
- Interleaved tra i canali
- Con uno stride/una permutazione

Altre famiglie di tecniche di audio-hiding che potresti incontrare:

- Codifica di fase
- Echo hiding
- Embedding a spettro espanso
- Canali lato codec (dipendenti dal formato e dallo strumento)

### WavSteg

I comandi seguenti usano WavSteg del toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Repository ufficiale e release di DeepSound.<sup>[[7]](#references)</sup>

## DTMF / toni di composizione

### Tecnica

DTMF rappresenta ogni segnale della tastiera utilizzando una frequenza di un gruppo basso e una di un gruppo alto. Se l'audio ricorda i toni della tastiera o beep regolari a doppia frequenza, prova a eseguire presto la decodifica DTMF.<sup>[[5]](#references)</sup>

Decoder online:

- Strumento browser `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, un decoder offline per file audio.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Lista dei desideri di Santa, Metadati natalizi, Rumore acquisito](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentazione](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK a riga di comando](https://github.com/kamalmostafa/minimodem)
- [5] [Raccomandazione ITU-T Q.23 — caratteristiche tecniche degli apparecchi telefonici a pulsanti](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — repository ufficiale e release](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
