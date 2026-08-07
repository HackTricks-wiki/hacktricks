# Audiosteganografie

{{#include ../../banners/hacktricks-training.md}}

Häufige Muster:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Schnelle Triage

Vor dem Einsatz spezialisierter Tools:

- Codec-/Containerdetails und Anomalien bestätigen:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Wenn das Audio rauschähnliche Inhalte oder eine tonale Struktur enthält, frühzeitig ein Spectrogramm untersuchen.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego versteckt Daten, indem Energie über Zeit/Frequenz geformt wird, sodass sie nur in einer Zeit-Frequenz-Darstellung sichtbar wird (oft unhörbar oder als Rauschen wahrgenommen).

### Sonic Visualiser

Primäres Tool zur Untersuchung von Spektrogrammen:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (Spektrogramm-Ansicht, Filter): https://www.audacityteam.org/
- `sox` kann über die CLI Spektrogramme erzeugen:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / Modem-Dekodierung

Frequency-shift keyed Audio sieht in einem Spektrogramm häufig wie abwechselnde einzelne Töne aus. Sobald du eine ungefähre Mittenfrequenz, Shift- und Baudraten-Schätzung hast, kannst du mit `minimodem` einen Brute-Force-Versuch durchführen:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` führt automatisch die Verstärkung aus und erkennt Mark-/Space-Töne automatisch; passe `--rx-invert` oder `--samplerate` an, wenn die Ausgabe unverständlich ist.

## WAV LSB

### Technik

Bei unkomprimiertem PCM (WAV) ist jedes Sample eine Ganzzahl. Das Ändern niedriger Bits verändert die Wellenform nur sehr geringfügig, sodass Angreifer Folgendes verstecken können:

- 1 Bit pro Sample (oder mehr)
- Über mehrere Kanäle verschachtelt
- Mit einer Schrittweite/Permutation

Weitere Audio-Hiding-Familien, denen du begegnen kannst:

- Phasencodierung
- Echo-Hiding
- Spread-Spectrum-Embedding
- Codec-seitige Channels (format- und toolabhängig)

### WavSteg

Von: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / Wähltöne

### Technik

DTMF codiert Zeichen als Paare fester Frequenzen (Telefontastatur). Wenn das Audio wie Tastentöne oder regelmäßige Doppelfrequenz-Pieptöne klingt, sollte die DTMF-Dekodierung früh getestet werden.

Online-Dekodierer:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referenzen

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
