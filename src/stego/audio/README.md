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
- Jeśli plik audio zawiera treść przypominającą szum lub strukturę tonalną, sprawdź spektrogram jak najwcześniej.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego chowa dane przez kształtowanie energii w czasie/częstotliwości, tak że stają się widoczne tylko na wykresie czas‑częstotliwości (często niesłyszalne lub postrzegane jako szum).

### Sonic Visualiser

Główne narzędzie do analizy spektrogramów:

- https://www.sonicvisualiser.org/

### Alternatives

- Audacity (widok spektrogramu, filtry): https://www.audacityteam.org/
- `sox` może generować spektrogramy z CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Technika

Dla niekompresowanego PCM (WAV) każda próbka jest liczbą całkowitą. Modyfikacja niskich bitów zmienia przebieg fali bardzo nieznacznie, więc attackers mogą ukryć:

- 1 bit na próbkę (lub więcej)
- Przeplatane między kanałami
- Z przeskokiem/permutacją

Inne rodziny metod ukrywania w dźwięku, które możesz napotkać:

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

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / tony wybierania

### Technika

DTMF koduje znaki jako pary stałych częstotliwości (klawiatura telefoniczna). Jeśli audio przypomina tony klawiatury lub regularne dwuczęstotliwościowe sygnały dźwiękowe, przetestuj dekodowanie DTMF na wczesnym etapie.

Dekodery online:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
