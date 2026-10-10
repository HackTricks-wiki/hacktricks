# Steganografia audio

{{#include ../../banners/hacktricks-training.md}}

Typowe wzorce:

- Wiadomości w spektrogramie
- Osadzanie LSB w WAV
- Kodowanie DTMF / tonami wybierania
- Payloady w metadanych

## Szybka analiza wstępna

Przed użyciem specjalistycznych narzędzi:

- Sprawdź szczegóły kodeka/kontenera i anomalie:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Jeśli audio zawiera szumopodobne treści lub strukturę tonalną, wcześnie sprawdź spektrogram.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Steganografia w spektrogramie

### Technika

Stego w spektrogramie ukrywa dane, kształtując energię w czasie i częstotliwości, tak aby stały się widoczne na wykresie czasowo-częstotliwościowym, podczas gdy dźwięk może przypominać tony lub szum.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Podstawowe narzędzie do analizy spektrogramów:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatywy

- Audacity (widok spektrogramu i filtry).<sup>[[6]](#references)</sup>
- `sox` może generować spektrogramy z poziomu CLI:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / dekodowanie modemu

Dźwięk z kluczowaniem z przesuwem częstotliwości często wygląda na spektrogramie jak naprzemienne pojedyncze tony. Gdy oszacujesz w przybliżeniu częstotliwość środkową i przesunięcie oraz szybkość transmisji w bodach, użyj brute force z `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` obsługuje Bell i inne tryby FSK oraz niestandardowe częstotliwości mark/space; sprawdź jego opcje, zamiast zakładać, że każde nagranie można automatycznie zdekodować. Jeśli wynik jest zniekształcony, spróbuj użyć `--rx-invert`, jawnie określonego trybu baud lub `--samplerate <Hz>`.<sup>[[4]](#references)</sup>

## WAV LSB

### Technika

W nieskompresowanym PCM (WAV) każda próbka jest liczbą całkowitą. Modyfikowanie najmłodszych bitów bardzo nieznacznie zmienia przebieg, dzięki czemu atakujący mogą ukrywać:

- 1 bit na próbkę (lub więcej)
- Dane przeplatane między kanałami
- Dane rozmieszczone z użyciem kroku lub permutacji

Inne techniki ukrywania danych w dźwięku, z którymi możesz się spotkać:

- Kodowanie fazowe
- Ukrywanie w echu
- Osadzanie z rozpraszaniem widma
- Kanały boczne kodeka (zależne od formatu i narzędzia)

### WavSteg

Poniższe polecenia korzystają z WavSteg z zestawu narzędzi `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Oficjalne repozytorium i wydania DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tony wybierania

### Technika

DTMF koduje każdy sygnał klawiatury za pomocą jednej częstotliwości z niskiego zakresu i jednej z wysokiego zakresu. Jeśli dźwięk przypomina tony klawiatury lub regularne sygnały o dwóch częstotliwościach, wcześnie przetestuj dekodowanie DTMF.<sup>[[5]](#references)</sup>

Dekodery online:

- Narzędzie przeglądarkowe `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, dekoder plików audio działający offline.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, lista życzeń Świętego Mikołaja, metadane świąteczne, przechwycony szum](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — dokumentacja](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK wiersza poleceń](https://github.com/kamalmostafa/minimodem)
- [5] [Zalecenie ITU-T Q.23 — charakterystyka techniczna telefonów z klawiaturą przyciskową](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — oficjalne repozytorium i wydania](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
