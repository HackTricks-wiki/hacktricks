# Audio-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Häufige Muster:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Schnelle Triage

Vor dem Einsatz spezialisierter Tools:

- Codec-/Container-Details und Anomalien überprüfen:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Wenn das Audio rauschähnliche Inhalte oder tonale Strukturen enthält, frühzeitig ein Spectrogram untersuchen.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spektrogramm-Steganografie

### Technik

Spectrogram stego versteckt Daten, indem die Energie über Zeit/Frequenz so geformt wird, dass sie in einem Zeit-Frequenz-Diagramm sichtbar wird, während das Audio wie Töne oder Rauschen klingen kann.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Primäres Tool zur Untersuchung von Spektrogrammen:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternativen

- Audacity (Spektrogrammansicht und Filter).<sup>[[6]](#references)</sup>
- `sox` kann Spektrogramme über die CLI erzeugen:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / Modem-Dekodierung

Frequency-shift keyed audio sieht in einem Spektrogramm oft wie abwechselnde Einzeltöne aus. Sobald du eine grobe Schätzung von Center/Shift und Baudrate hast, probiere per Brute-Force `minimodem` aus:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` unterstützt Bell- und andere FSK-Modi sowie benutzerdefinierte Mark-/Space-Frequenzen; konsultieren Sie die Optionen, statt davon auszugehen, dass jede Aufnahme automatisch erkannt werden kann. Probieren Sie `--rx-invert`, einen expliziten Baud-Modus oder `--samplerate <Hz>`, wenn die Ausgabe unleserlich ist.<sup>[[4]](#references)</sup>

## WAV LSB

### Technik

Bei unkomprimiertem PCM (WAV) ist jedes Sample eine Ganzzahl. Das Ändern der niedrigen Bits verändert die Wellenform nur sehr geringfügig, sodass Angreifer Folgendes verbergen können:

- 1 Bit pro Sample (oder mehr)
- Über mehrere Kanäle verschachtelt
- Mit einem stride/einer permutation

Weitere Audio-Hiding-Verfahren, denen Sie begegnen können:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format- und toolabhängig)

### WavSteg

Die folgenden Befehle verwenden WavSteg aus dem `ragibson/Steganography`-Toolkit.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Das offizielle Repository und die Releases von DeepSound.<sup>[[7]](#references)</sup>

## DTMF / Wähltöne

### Technik

DTMF stellt jedes Tastensignal mithilfe einer Frequenz aus einer niedrigen Gruppe und einer Frequenz aus einer hohen Gruppe dar. Wenn das Audio wie Tastentöne oder regelmäßige Töne mit zwei Frequenzen klingt, sollte die DTMF-Dekodierung früh getestet werden.<sup>[[5]](#references)</sup>

Online-Decoder:

- Browser-Tool `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, ein Offline-Decoder für Audiodateien.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santas Wunschliste, Weihnachtsmetadaten, aufgezeichnetes Rauschen](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — Dokumentation](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — FSK-Modem für die Kommandozeile](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — technische Merkmale von Tastentelefonen](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — offizielles Repository und Releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
