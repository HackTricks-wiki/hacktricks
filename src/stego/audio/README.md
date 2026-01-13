# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Typowe wzorce:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Szybkie rozpoznanie

Przed użyciem specjalistycznych narzędzi:

- Potwierdź szczegóły kodeka/kontenera i anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Jeśli plik audio zawiera treść przypominającą szum lub strukturę tonalną, jak najwcześniej sprawdź spectrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technika

Spectrogram stego ukrywa dane poprzez kształtowanie energii w czasie i częstotliwości, tak że stają się widoczne tylko na wykresie czasowo-częstotliwościowym (często niesłyszalne lub odbierane jako szum).

### Sonic Visualiser

Podstawowe narzędzie do analizy spektrogramów:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatywy

- Audacity (widok spektrogramu, filtry): https://www.audacityteam.org/
- `sox` może generować spektrogramy z linii poleceń:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

FSK audio często w spektrogramie wygląda jak naprzemienne pojedyncze tony. Gdy masz przybliżone oszacowanie centrum/przesunięcia i baudu, przeprowadź brute force z `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` automatycznie dopasowuje wzmocnienie i autodetekuje mark/space tones; dostosuj `--rx-invert` lub `--samplerate`, jeśli wyjście jest zniekształcone.

## WAV LSB

### Technika

Dla nieskompresowanego PCM (WAV) każda próbka jest liczbą całkowitą. Modyfikacja niskich bitów zmienia przebieg fali bardzo nieznacznie, więc atakujący mogą ukryć:

- 1 bit na próbkę (lub więcej)
- Przeplatane między kanałami
- Z krokiem/permutacją

Inne rodziny ukrywania audio, które możesz napotkać:

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

## DTMF / dial tones

### Technika

DTMF koduje znaki jako pary stałych częstotliwości (klawiatura telefonu). Jeśli audio przypomina tony klawiatury lub regularne dwuczęstotliwościowe sygnały, przetestuj dekodowanie DTMF jak najwcześniej.

Dekodery online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Źródła

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
