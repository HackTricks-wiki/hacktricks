# Steganografia audio

{{#include ../../banners/hacktricks-training.md}}

Pattern comuni:

- Messaggi nello spettrogramma
- Embedding LSB in WAV
- Codifica DTMF / toni di chiamata
- Payload nei metadati

## Triage rapido

Prima di usare strumenti specializzati:

- Verifica i dettagli del codec e del container e cerca anomalie:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Se l’audio contiene rumore o una struttura tonale, esamina subito uno spettrogramma.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Steganografia dello spettrogramma

### Tecnica

La steganografia nello spettrogramma nasconde i dati modellando l’energia nel tempo e in frequenza, rendendola visibile in un grafico tempo-frequenza, mentre l’audio può sembrare composto da toni o rumore.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Strumento principale per l’ispezione degli spettrogrammi:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternative

- Audacity (visualizzazione dello spettrogramma e filtri).<sup>[[6]](#references)</sup>
- `sox` può generare spettrogrammi dalla CLI:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## Decodifica FSK / modem

L'audio modulato con frequency-shift keying spesso appare come una successione alternata di toni singoli in uno spettrogramma. Dopo aver stimato approssimativamente la frequenza centrale, lo shift e il baud rate, prova a forza bruta con `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` supporta Bell e altre modalità FSK, oltre a frequenze mark/space personalizzate; consulta le sue opzioni invece di presumere che ogni registrazione possa essere rilevata automaticamente. Prova `--rx-invert`, una modalità baud esplicita o `--samplerate <Hz>` se l'output è distorto.<sup>[[4]](#references)</sup>

## WAV LSB

### Tecnica

Per il PCM non compresso (WAV), ogni sample è un intero. Modificare i bit meno significativi cambia la forma d'onda in misura minima, quindi gli attaccanti possono nascondere:

- 1 bit per sample (o più)
- Intercalati tra i canali
- Con uno stride/una permutazione

Altre famiglie di tecniche di occultamento audio che potresti incontrare:

- Phase coding
- Echo hiding
- Embedding spread-spectrum
- Canali laterali a livello di codec (dipendenti dal formato e dallo strumento)

### WavSteg

I comandi seguenti usano WavSteg del toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Repository ufficiale e release di DeepSound.<sup>[[7]](#references)</sup>

## DTMF / toni di selezione

### Tecnica

DTMF rappresenta ogni segnale della tastiera usando una frequenza di un gruppo basso e una di un gruppo alto. Se l’audio sembra contenere toni di tastiera o bip regolari a doppia frequenza, prova subito la decodifica DTMF.<sup>[[5]](#references)</sup>

Decoder online:

- Strumento browser `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, un decoder offline per file audio.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — rosa, Lista dei desideri di Santa, Metadati natalizi, Rumore catturato](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentazione](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK da riga di comando](https://github.com/kamalmostafa/minimodem)
- [5] [Raccomandazione ITU-T Q.23 — caratteristiche tecniche dei telefoni a tastiera](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — repository ufficiale e release](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
