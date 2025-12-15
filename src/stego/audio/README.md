# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Häufige Muster:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Schnelle Triage

Vor spezialisierten Tools:

- Codec-/Container-Details und Anomalien bestätigen:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Wenn das Audio rauschähnlichen Inhalt oder tonale Strukturen enthält, untersuche frühzeitig ein Spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technik

Spectrogram stego versteckt Daten, indem es Energie über Zeit/Frequenz formt, sodass sie nur in einem Zeit-Frequenz-Diagramm sichtbar wird (oft unhörbar oder als Rauschen wahrgenommen).

### Sonic Visualiser

Hauptwerkzeug für die Spektrogramm-Analyse:

- https://www.sonicvisualiser.org/

### Alternativen

- Audacity (Spektrogramm-Ansicht, Filter): https://www.audacityteam.org/
- `sox` kann Spektrogramme über die CLI erzeugen:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Technik

Bei unkomprimiertem PCM (WAV) ist jedes Sample eine ganze Zahl. Das Ändern der niederwertigen Bits verändert die Wellenform nur minimal, daher können Angreifer darin verstecken:

- 1 Bit pro Sample (oder mehr)
- Versetzt über die Kanäle
- Mit einer Schrittweite/Permutation

Andere Audio-Versteck-Methoden, denen Sie begegnen könnten:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Von: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / Wähltöne

### Technik

DTMF kodiert Zeichen als Paare fester Frequenzen (Telefon-Tastatur). Wenn das Audio Tastentöne oder regelmäßige Dual-Frequenz-Pieptöne ähnelt, teste frühzeitig eine DTMF-Decodierung.

Online-Decoder:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
