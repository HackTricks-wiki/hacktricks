# Audio-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Häufige Muster:

- Nachrichten in Spektrogrammen
- WAV-LSB-Einbettung
- DTMF- / Wähltöne-Codierung
- Metadaten-Payloads

## Schnelle Triage

Vor dem Einsatz spezialisierter Tools:

- Codec-/Container-Details und Anomalien bestätigen:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Wenn das Audio rauschartige Inhalte oder tonale Strukturen enthält, frühzeitig ein Spektrogramm untersuchen.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spektrogramm-Steganografie

### Technik

Spectrogram stego verbirgt Daten, indem Energie über Zeit/Frequenz geformt wird, sodass sie nur in einer Zeit-Frequenz-Darstellung sichtbar wird (oft unhörbar oder als Rauschen wahrgenommen).

### Sonic Visualiser

Primäres Tool zur Spektrogramm-Inspektion:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativen

- Audacity (Spektrogramm-Ansicht, Filter): https://www.audacityteam.org/
- `sox` kann Spektrogramme über die CLI erzeugen:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK-/Modem-Decodierung

Frequenzumtastete Audiosignale sehen in einem Spektrogramm oft wie abwechselnde einzelne Töne aus.<sup>[[1]](#references)</sup> Sobald du eine grobe Schätzung für Center/Shift und Baudrate hast, kannst du mit `minimodem` einen Brute-Force-Versuch starten:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` führt automatisch eine Verstärkungsanpassung durch und erkennt Mark-/Space-Töne automatisch. Passe `--rx-invert` oder `--samplerate` an, wenn die Ausgabe unleserlich ist.

## WAV LSB

### Technique

Bei unkomprimiertem PCM (WAV) ist jedes Sample eine Ganzzahl. Das Ändern der niederwertigen Bits verändert die Wellenform nur sehr geringfügig, sodass Angreifer Folgendes verstecken können:

- 1 Bit pro Sample (oder mehr)
- Über mehrere Kanäle verschachtelt
- Mit einem Stride/einer Permutation

Weitere Audio-Hiding-Familien, auf die du stoßen kannst:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (formatabhängig und vom Tool abhängig)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / Wähltöne

### Technik

DTMF kodiert Zeichen als Paare fester Frequenzen (Telefontastatur). Wenn das Audio wie Tastentöne oder regelmäßige Zweifrequenz-Pieptöne klingt, sollte frühzeitig eine DTMF-Dekodierung getestet werden.

Online-Dekoder:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referenzen

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
