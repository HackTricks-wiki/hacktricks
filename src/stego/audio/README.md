# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Häufige Muster:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Schnelle Ersteinschätzung

Vor spezialisierten Tools:

- Codec-/Container-Details und Anomalien prüfen:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Wenn die Audiodatei rauschähnlichen Inhalt oder tonale Strukturen enthält, frühzeitig ein Spektrogramm prüfen.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technik

Spectrogram stego versteckt Daten, indem es Energie über Zeit/Frequenz formt, sodass sie nur in einer Zeit-Frequenz-Darstellung sichtbar werden (oft unhörbar oder als Rauschen wahrgenommen).

### Sonic Visualiser

Hauptwerkzeug zur Spektrogramm-Analyse:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativen

- Audacity (Spektrogramm-Ansicht, Filter): https://www.audacityteam.org/
- `sox` kann Spektrogramme über die CLI erzeugen:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Technik

Bei unkomprimiertem PCM (WAV) ist jedes Sample ein Integer. Das Verändern der niederwertigen Bits verändert die Wellenform nur sehr geringfügig, sodass Angreifer verbergen können:

- 1 Bit pro Sample (oder mehr)
- Interleaved über Kanäle
- Mit einer Schrittweite/Permutation

Weitere Audio-Hiding-Familien, denen du begegnen könntest:

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

## DTMF / Wählton

### Technik

DTMF kodiert Zeichen als Paare fester Frequenzen (Telefon-Tastenfeld). Wenn das Audio wie Tasten-Töne oder regelmäßige Dual-Frequenz-Pieptöne klingt, teste frühzeitig eine DTMF-Decodierung.

Online-Decoder:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
