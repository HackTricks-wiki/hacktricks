# Różne zagadnienia z Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

Ta sekcja zawiera techniki stosowane w wyzwaniach kryptograficznych, które nie pasują do pozostałych kategorii.

## Języki ezoteryczne

### Technika

Skorzystaj z tego procesu, gdy wyzwanie wymaga uruchomienia programu napisanego w języku ezoterycznym i zdekodowania jego wyniku.

Jeśli wyzwanie zawiera kod, który nie przypomina kodu w standardowym języku:

- Zidentyfikuj język, wyszukując charakterystyczny token lub sekwencję instrukcji.
- Użyj interpretera online lub obrazu Docker.
- Jeśli wynik jest dziwny, sprawdź, czy po wykonaniu kodu nie zastosowano kolejnych warstw kodowania lub kompresji.

Przydatny indeks języków znajdziesz w wiki Esolang.<sup>[[1]](#references)</sup> W przypadku standardowych warstw kodowania i kompresji skorzystaj z [Crypto CTF workflow](../ctf-workflow/). Jeśli wskazówką jest niewidoczny tekst, a nie składnia wykonywalna, sprawdź [text steganography](../../stego/text/).

### Eksfiltracja wstępnie załadowanego stanu interpretera

Jeśli wyzwanie przyjmuje kod źródłowy w języku ezoterycznym i uruchamia go w **custom interpreter**, przed potraktowaniem kodu jako łamigłówki dekodującej sprawdź początkową pamięć, stos i instrukcje wyjścia interpretera. Gdy interpreter wstępnie umieszcza sekret na stosie Befunge, krótki program może zdjąć istniejące bajty ze stosu i je wypisać, bez ich obliczania. Wymaga to kontroli nad wykonywanym kodem źródłowym oraz opcode'u wyjścia; nie zadziała w standardowym, pustym interpreterze. W wyzwaniu Befunge poniższy kod wielokrotnie wypisywał znaki z flagi wstępnie umieszczonej na stosie w odwrotnej kolejności.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` rozpoczyna wykonywanie w prawo, `,` zdejmuje znak ze stosu i go wyświetla, a `<` cofa wskaźnik instrukcji do `,`. Sprawdź zachowanie niestandardowego interpretera w przypadku niedomiaru stosu i limitu instrukcji: cytowana implementacja kończy działanie, gdy stos się wyczerpie lub po wykonaniu 1 024 instrukcji. Jeśli sekretu nie ma bezpośrednio na stosie, sprawdź inne zainicjowane stany oraz dostępne instrukcje wyjścia i odczytu, zamiast zakładać standardową semantykę Befunge.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, wiki ezoterycznych języków programowania](https://esolangs.org/wiki/Main_Page)
- [2] [Oryginalny opis rozwiązania WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [Kod źródłowy interpretera WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Dokumentacja języka Befunge](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
