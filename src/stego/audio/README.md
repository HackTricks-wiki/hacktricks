# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Häufige Muster:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Schnelle Triage

Vor spezialisierten Tools:

- Codec-/Container-Details und Anomalien prüfen:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Sollte die Audiodatei rauschähnliche Inhalte oder tonale Strukturen enthalten, frühzeitig ein Spectrogram prüfen.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technik

Spectrogram stego versteckt Daten, indem es die Energie über Zeit/Frequenz formt, sodass sie nur in einer Zeit-Frequenz-Darstellung sichtbar wird (oft unhörbar oder als Rauschen wahrgenommen).

### Sonic Visualiser

Primäres Tool zur Betrachtung von Spektrogrammen:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativen

- Audacity (Spektrogramm-Ansicht, Filter): https://www.audacityteam.org/
- `sox` kann Spektrogramme aus der CLI erzeugen:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio sieht in einem Spektrogramm oft wie abwechselnde Einzeltöne aus. Sobald Sie eine grobe center/shift- und baud-Schätzung haben, brute force mit `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` stellt die Verstärkung automatisch ein und erkennt mark/space-Töne automatisch; passen Sie `--rx-invert` oder `--samplerate` an, wenn die Ausgabe verzerrt ist.

## WAV LSB

### Technik

Bei unkomprimiertem PCM (WAV) ist jedes Sample eine Ganzzahl. Das Ändern der niedrigsten Bits verändert die Wellenform nur sehr leicht, sodass Angreifer folgendes verstecken können:

- 1 Bit pro Sample (oder mehr)
- Über die Kanäle verteilt
- Mit einer Schrittweite/Permutation

Weitere Audio-Versteckverfahren, denen Sie begegnen könnten:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Quelle: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / Wähltöne

### Technik

DTMF kodiert Zeichen als Paare fester Frequenzen (Telefon-Tastatur). Wenn die Audioaufnahme Tastenklänge oder regelmäßige Dualfrequenz-Pieptöne ähnelt, teste frühzeitig eine DTMF-Decodierung.

Online-Decoder:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referenzen

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
