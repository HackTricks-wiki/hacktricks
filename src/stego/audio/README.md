# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Typowe wzorce:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Szybka analiza wstępna

Przed użyciem specjalistycznych narzędzi:

- Sprawdź informacje o kodeku/kontenerze i anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Jeśli audio zawiera treść przypominającą szum lub strukturę tonalną, sprawdź spectrogram na wczesnym etapie.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technika

Spectrogram stego ukrywa dane, kształtując energię w czasie/częstotliwości, tak że stają się widoczne tylko na wykresie czas-częstotliwość (często niesłyszalne lub postrzegane jako szum).

### Sonic Visualiser

Główne narzędzie do inspekcji spektrogramów:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatywy

- Audacity (widok spektrogramu, filtry): https://www.audacityteam.org/
- `sox` może generować spektrogramy z poziomu CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Technika

Dla nieskompresowanego PCM (WAV), każda próbka jest liczbą całkowitą. Modyfikacja niskich bitów zmienia przebieg fali bardzo nieznacznie, więc atakujący mogą ukryć:

- 1 bit na próbkę (lub więcej)
- Przeplatane między kanałami
- Z krokiem/permutacją

Inne rodziny technik ukrywania audio, które możesz napotkać:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Źródło: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tony wybierania

### Technika

DTMF koduje znaki jako pary stałych częstotliwości (telefoniczna klawiatura). Jeśli audio przypomina tony klawiatury lub regularne dwuczęstotliwościowe piknięcia, przetestuj dekodowanie DTMF jak najszybciej.

Dekodery online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
