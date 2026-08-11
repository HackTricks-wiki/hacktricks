# Steganografia audio

{{#include ../../banners/hacktricks-training.md}}

Typowe wzorce:

- Wiadomości w spektrogramie
- Osadzanie LSB w WAV
- Kodowanie DTMF / dial tones
- Ładunki w metadanych

## Szybki triage

Przed użyciem specjalistycznych narzędzi:

- Sprawdź szczegóły kodeka/kontenera i anomalie:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Jeśli audio zawiera treści przypominające szum lub strukturę tonalną, wcześnie sprawdź spektrogram.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Steganografia spektrogramu

### Technika

Stego spektrogramu ukrywa dane poprzez kształtowanie energii w czasie i częstotliwości, dzięki czemu stają się one widoczne na wykresie czas-częstotliwość, podczas gdy dźwięk może brzmieć jak tony lub szum.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Podstawowe narzędzie do analizy spektrogramów:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatywy

- Audacity (widok spektrogramu i filtry).<sup>[[6]](#references)</sup>
- `sox` może generować spektrogramy z CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Dekodowanie FSK / modemu

Dźwięk z kluczowaniem z przesuwem częstotliwości często wygląda na spektrogramie jak naprzemienne pojedyncze tony. Gdy masz już przybliżone wartości częstotliwości centralnej, przesunięcia i baud rate, użyj brute force za pomocą `minimodem`:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` obsługuje Bell i inne tryby FSK, a także niestandardowe częstotliwości mark/space; sprawdź jego opcje, zamiast zakładać, że każde nagranie może zostać automatycznie wykryte. Jeśli wynik jest zniekształcony, wypróbuj `--rx-invert`, jawnie określony tryb baud lub `--samplerate <Hz>`.<sup>[[4]](#references)</sup>

## WAV LSB

### Technika

W przypadku nieskompresowanego PCM (WAV) każda próbka jest liczbą całkowitą. Modyfikowanie bitów o niskiej wadze bardzo nieznacznie zmienia przebieg fali, dlatego atakujący mogą ukrywać:

- 1 bit na próbkę (lub więcej)
- Przeplatane między kanałami
- Z użyciem stride/permutacji

Inne rodziny metod ukrywania danych w audio, z którymi możesz się spotkać:

- Kodowanie fazowe
- Ukrywanie w echu
- Osadzanie z widmem rozproszonym
- Kanały po stronie kodeka (zależne od formatu i narzędzia)

### WavSteg

Poniższe polecenia używają WavSteg z toolkitu `ragibson/Steganography`.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- Oficjalne repozytorium i wydania DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tony wybierania

### Technika

DTMF reprezentuje każdy sygnał klawiatury za pomocą jednej częstotliwości z grupy niskiej i jednej z grupy wysokiej. Jeśli dźwięk przypomina tony klawiatury lub regularne dwuczęstotliwościowe sygnały dźwiękowe, wcześnie przetestuj dekodowanie DTMF.<sup>[[5]](#references)</sup>

Dekodery online:

- Narzędzie przeglądarkowe `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, dekoder plików audio działający offline.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, lista życzeń Świętego Mikołaja, metadane świąteczne, przechwycony szum](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — dokumentacja](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK wiersza poleceń](https://github.com/kamalmostafa/minimodem)
- [5] [Zalecenie ITU-T Q.23 — parametry techniczne telefonów z klawiaturą przyciskową](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — oficjalne repozytorium i wydania](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
