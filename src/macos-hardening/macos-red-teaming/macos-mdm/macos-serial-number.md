# Numer seryjny macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Nie zakładaj, że każdy Mac ma możliwy do zdekodowania 12-znakowy numer seryjny. Starszy format Apple kodował informacje o produkcji i konfiguracji, ale w 2021 roku Apple zaczęło wprowadzać losowe numery seryjne w nowych produktach. Losowy format nie ujawnia szczegółów dotyczących produkcji ani konfiguracji.<sup>[[1]](#references)</sup>

### Starszy format 12-znakowy

W przypadku wielu urządzeń wyprodukowanych od 2010 roku do przejścia na losowy format 12-znakowy format nadal może dostarczyć przydatnych wskazówek inwentaryzacyjnych:<sup>[[3]](#references)</sup>

- Znaki 1–3 określają miejsce produkcji.
- Znaki 4–5 kodują półrocze i tydzień produkcji.
- Znaki 6–8 rozróżniają urządzenia wyprodukowane w tym samym miejscu i czasie.
- Znaki 9–12 określają kod modelu lub konfiguracji.

Na przykład `C02L13ECF8J2` jest zgodny z tą starszą strukturą. Utrzymywane przez społeczność mapowania fabryk obejmują prefiksy takie jak `FC`, `F`, `XA`, `XB`, `QP` i `G8` dla lokalizacji w Stanach Zjednoczonych; `RN` dla Meksyku; `CK` dla Cork; `VM` dla lokalizacji Foxconn w Czechach; `SG` lub `E` dla Singapuru; `MB` dla Malezji; `PT` lub `CY` dla Korei; oraz `EE`, `QT` lub `UV` dla Tajwanu. Liczne prefiksy — w tym `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` i `C7` — były kojarzone z chińskimi fabrykami; `RM` był kojarzony z urządzeniami odnowionymi.<sup>[[3]](#references)</sup>

Kody daty na czwartym znaku obejmują zakres od `C` (pierwsza połowa 2010 roku) do `Z` (druga połowa 2019 roku), a następnie sekwencja jest ponownie wykorzystywana. W przypadku piątego znaku cyfry `1`–`9` oznaczają tygodnie 1–9, natomiast litery `C`–`Y`, z wyłączeniem samogłosek i `S`, oznaczają tygodnie 10–27; dodaj 26, gdy czwarty znak oznacza drugą połowę roku.<sup>[[3]](#references)</sup>

Mapowania te są przydatne podczas wstępnej analizy starszych urządzeń, ale nie stanowią autorytatywnego dowodu pochodzenia, wieku ani autentyczności. Potwierdź wynik za pomocą danych inwentaryzacyjnych Apple.

Aby uzyskać wiarygodną identyfikację, odczytaj numer seryjny z urządzenia i skorzystaj z wyszukiwarki zakresu gwarancji lub specyfikacji technicznych Apple, zamiast próbować ustalać model na podstawie pozycji znaków.<sup>[[2]](#references)</sup>

### Odczytywanie numeru seryjnego

Interfejs graficzny wyświetla go w sekcji **Apple menu > About This Mac**.<sup>[[2]](#references)</sup> Z poziomu powłoki dowolne z poniższych poleceń odczytuje numer seryjny platformy:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Traktuj numer seryjny jako identyfikator, a nie element uwierzytelniający: przed podjęciem decyzji dotyczących rejestracji lub własności potwierdź urządzenie za pomocą odpowiedniego procesu inwentaryzacji Apple lub MDM.

## References

- [1] [MacRumors - Apple rozpoczyna przejście na losowe numery seryjne](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Znajdowanie nazwy modelu i numeru seryjnego komputera Mac](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Odkodowywanie znaczenia numeru seryjnego Apple](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
