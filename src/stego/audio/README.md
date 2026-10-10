# Audio-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Häufige Muster:

- Spektrogramm-Nachrichten
- WAV-LSB-Einbettung
- DTMF- / Wähltöne-Codierung
- Metadaten-Payloads

## Schnelle Erstprüfung

Vor dem Einsatz spezieller Tools:

- Codec-/Containerdetails und Auffälligkeiten überprüfen:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Wenn das Audio rauschartige Inhalte oder tonale Strukturen enthält, frühzeitig ein Spektrogramm untersuchen.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Steganografie im Spektrogramm

### Technique

Spektrogramm-Stego verbirgt Daten, indem Energie über Zeit und Frequenz so geformt wird, dass sie in einem Zeit-Frequenz-Diagramm sichtbar wird, während das Audio wie Töne oder Rauschen klingen kann.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Primäres Tool zur Spektrogramm-Inspektion:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (Spektrogrammansicht und Filter).<sup>[[6]](#references)</sup>
- `sox` kann Spektrogramme über die CLI erzeugen:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / Modem-Decodierung

Audio mit Frequenzumtastung sieht in einem Spektrogramm oft wie abwechselnde Einzeltöne aus. Sobald du ungefähre Werte für Mittenfrequenz, Frequenzhub und Baudrate hast, probiere verschiedene Einstellungen mit `minimodem` per Brute-Force aus:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` unterstützt Bell- und andere FSK-Modi sowie benutzerdefinierte Mark-/Space-Frequenzen. Prüfe die Optionen, statt davon auszugehen, dass jede Aufnahme automatisch erkannt werden kann. Versuche `--rx-invert`, einen expliziten Baud-Modus oder `--samplerate <Hz>`, wenn die Ausgabe unverständlich ist.<sup>[[4]](#references)</sup>

## WAV LSB

### Technik

Bei unkomprimiertem PCM (WAV) ist jedes Sample eine Ganzzahl. Änderungen an den niederwertigen Bits verändern die Wellenform nur sehr geringfügig, sodass Angreifer Folgendes verbergen können:

- 1 Bit pro Sample (oder mehr)
- Verschachtelt über mehrere Kanäle
- Mit einem stride/einer Permutation

Weitere Audio-Steganografie-Methoden, denen du begegnen kannst:

- Phasencodierung
- Echo-Hiding
- Spread-Spectrum-Einbettung
- Codec-seitige Seitenkanäle (format- und toolabhängig)

### WavSteg

Die folgenden Befehle verwenden WavSteg aus dem Toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Das offizielle Repository und die Releases von DeepSound.<sup>[[7]](#references)</sup>

## DTMF / Wähltöne

### Technik

DTMF codiert jedes Tastensignal mit einer Frequenz aus einer niedrigen und einer aus einer hohen Frequenzgruppe. Wenn das Audio wie Tastentöne oder regelmäßige Dualfrequenz-Pieptöne klingt, sollte die DTMF-Decodierung früh getestet werden.<sup>[[5]](#references)</sup>

Online-Decoder:

- Browser-Tool `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, ein Decoder für Audiodateien, der offline funktioniert.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wunschzettel, Weihnachtsmetadaten, aufgezeichnetes Rauschen](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — Dokumentation](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — Kommandozeilen-FSK-Modem](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T-Empfehlung Q.23 — technische Merkmale von Tastentelefonen](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — offizielles Repository und Releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
