# Steganografia audio

{{#include ../../banners/hacktricks-training.md}}

Typowe wzorce:

- Wiadomości w spektrogramie
- Osadzanie WAV LSB
- Kodowanie DTMF / tonów wybierania
- Ładunki w metadanych

## Szybka analiza wstępna

Przed użyciem specjalistycznych narzędzi:

- Sprawdź szczegóły kodeka/kontenera i anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Jeśli audio zawiera treści przypominające szum lub strukturę tonalną, wcześnie przeanalizuj spektrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Steganografia spektrogramu

### Technika

Spectrogram stego ukrywa dane poprzez kształtowanie energii w czasie/częstotliwości, dzięki czemu stają się one widoczne wyłącznie na wykresie czasowo-częstotliwościowym (często są niesłyszalne lub odbierane jako szum).

### Sonic Visualiser

Podstawowe narzędzie do inspekcji spektrogramów:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatywy

- Audacity (widok spektrogramu, filtry): https://www.audacityteam.org/
- `sox` może generować spektrogramy z poziomu CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / dekodowanie modemu

Dźwięk z kluczowaniem z przesuwem częstotliwości często wygląda na spektrogramie jak naprzemienne pojedyncze tony.<sup>[[1]](#references)</sup> Gdy masz już przybliżone wartości częstotliwości środkowej, przesunięcia i baud rate, użyj brute force z `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` automatycznie dostosowuje wzmocnienie i wykrywa tony mark/space; dostosuj `--rx-invert` lub `--samplerate`, jeśli wynik jest zniekształcony.

## WAV LSB

### Technika

W przypadku nieskompresowanego PCM (WAV) każda próbka jest liczbą całkowitą. Modyfikowanie najmłodszych bitów nieznacznie zmienia przebieg fali, dlatego atakujący mogą ukrywać:

- 1 bit na próbkę (lub więcej)
- Dane przeplatane między kanałami
- Dane z użyciem kroku/permutacji

Inne rodziny technik ukrywania danych w audio, z którymi możesz się spotkać:

- Kodowanie fazy
- Ukrywanie echa
- Osadzanie z użyciem spread-spectrum
- Kanały po stronie kodeka (zależne od formatu i narzędzia)

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

DTMF koduje znaki jako pary stałych częstotliwości (klawiatura telefonu). Jeśli dźwięk przypomina tony klawiatury lub regularne sygnały o podwójnej częstotliwości, wcześnie przetestuj dekodowanie DTMF.

Dekodery online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referencje

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
