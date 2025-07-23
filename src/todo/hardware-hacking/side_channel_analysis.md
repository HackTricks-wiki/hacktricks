# Ataki Analizy Kanałów Bocznych

{{#include ../../banners/hacktricks-training.md}}

Ataki kanałów bocznych odzyskują sekrety poprzez obserwację fizycznego lub mikro-architektonicznego "wycieku", który jest *skorelowany* z wewnętrznym stanem, ale *nie* jest częścią logicznego interfejsu urządzenia. Przykłady obejmują pomiar chwilowego prądu pobieranego przez kartę inteligentną do nadużywania efektów zarządzania mocą CPU przez sieć.

---

## Główne Kanały Wycieku

| Kanał | Typowy Cel | Instrumentacja |
|-------|------------|-----------------|
| Zużycie energii | Karty inteligentne, MCU IoT, FPGA | Oscyloskop + rezystor szeregowy/probe HS (np. CW503) |
| Pole elektromagnetyczne (EM) | CPU, RFID, akceleratory AES | Proba H-field + LNA, ChipWhisperer/RTL-SDR |
| Czas wykonania / pamięci podręczne | CPU desktopowe i chmurowe | Wysokoprecyzyjne timery (rdtsc/rdtscp), zdalny czas przelotu |
| Akustyczny / mechaniczny | Klawiatury, drukarki 3D, przekaźniki | Mikrofon MEMS, wibrometr laserowy |
| Optyczny i termiczny | LED-y, drukarki laserowe, DRAM | Fotodioda / kamera wysokiej prędkości, kamera IR |
| Wywołany błędem | Kryptografia ASIC/MCU | Glitch zegara/napięcia, EMFI, wstrzyknięcie laserowe |

---

## Analiza Mocy

### Prosta Analiza Mocy (SPA)
Obserwuj *pojedynczy* ślad i bezpośrednio kojarz szczyty/doliny z operacjami (np. S-boxy DES).
```python
# ChipWhisperer-husky example – capture one AES trace
from chipwhisperer.capture.api.programmers import STMLink
from chipwhisperer.capture import CWSession
cw = CWSession(project='aes')
trig = cw.scope.trig
cw.connect(cw.capture.scopes[0])
cw.capture.init()
trace = cw.capture.capture_trace()
print(trace.wave)  # numpy array of power samples
```
### Analiza Mocy Różnicowej/Korelacyjnej (DPA/CPA)
Zdobądź *N > 1 000* śladów, hipotetyzuj bajt klucza `k`, oblicz model HW/HD i skoreluj z wyciekiem.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA pozostaje na czołowej pozycji, ale warianty uczenia maszynowego (MLA, SCA głębokiego uczenia) dominują teraz w zawodach takich jak ASCAD-v2 (2023).

---

## Analiza elektromagnetyczna (EMA)
Proby EM w bliskim polu (500 MHz–3 GHz) ujawniają identyczne informacje jak analiza mocy *bez* wstawiania shuntów. Badania z 2024 roku wykazały odzyskiwanie kluczy w **>10 cm** od STM32 przy użyciu korelacji widma i niskokosztowych front-endów RTL-SDR.

---

## Ataki czasowe i mikroarchitektoniczne
Nowoczesne procesory ujawniają sekrety przez wspólne zasoby:
* **Hertzbleed (2022)** – skalowanie częstotliwości DVFS koreluje z wagą Hamming'a, co pozwala na *zdalne* wydobycie kluczy EdDSA.
* **Downfall / Gather Data Sampling (Intel, 2023)** – wykonanie przejściowe do odczytu danych AVX-gather przez wątki SMT.
* **Zenbleed (AMD, 2023) i Inception (AMD, 2023)** – spekulacyjne błędne przewidywanie wektorów ujawnia rejestry międzydomenowe.

Aby uzyskać szerokie omówienie problemów klasy Spectre, zobacz {{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}

---

## Ataki akustyczne i optyczne
* W 2024 roku "​iLeakKeys" wykazało 95% dokładność w odzyskiwaniu naciśnięć klawiszy laptopa z **mikrofonu smartfona przez Zoom** przy użyciu klasyfikatora CNN.
* Fotodiody o wysokiej prędkości rejestrują aktywność LED DDR4 i rekonstruują klucze rundy AES w czasie <1 minuty (BlackHat 2023).

---

## Wstrzykiwanie błędów i różnicowa analiza błędów (DFA)
Łączenie błędów z wyciekiem kanału bocznego skraca poszukiwanie kluczy (np. 1-ślad AES DFA). Ostatnie narzędzia w cenie dla hobbystów:
* **ChipSHOUTER i PicoEMP** – zakłócanie impulsami elektromagnetycznymi poniżej 1 ns.
* **GlitchKit-R5 (2025)** – platforma do zakłócania zegara/napięcia typu open-source wspierająca SoC RISC-V.

---

## Typowy przebieg ataku
1. Zidentyfikuj kanał wycieku i punkt montażowy (pin VCC, kondensator odsprzęgający, miejsce w bliskim polu).
2. Wstaw wyzwalacz (GPIO lub oparty na wzorze).
3. Zbierz >1 k śladów z odpowiednim próbkowaniem/filtrami.
4. Wstępne przetwarzanie (wyrównanie, usunięcie średniej, filtr LP/HP, falowód, PCA).
5. Statystyczne lub ML odzyskiwanie kluczy (CPA, MIA, DL-SCA).
6. Walidacja i iteracja na odstających wynikach.

---

## Ochrona i wzmocnienie
* **Implementacje o stałym czasie** i algorytmy odporne na pamięć.
* **Maskowanie/tasowanie** – podziel sekrety na losowe udziały; odporność pierwszego rzędu certyfikowana przez TVLA.
* **Ukrywanie** – regulatory napięcia na chipie, zrandomizowany zegar, logika dual-rail, osłony EM.
* **Wykrywanie błędów** – redundantne obliczenia, podpisy progowe.
* **Operacyjne** – wyłącz DVFS/turbo w jądrach kryptograficznych, izoluj SMT, zabroń współlokacji w chmurach wielodostępnych.

---

## Narzędzia i ramy
* **ChipWhisperer-Husky** (2024) – oscyloskop 500 MS/s + wyzwalacz Cortex-M; API Python jak powyżej.
* **Riscure Inspector i FI** – komercyjne, wspiera automatyczną ocenę wycieków (TVLA-2.0).
* **scaaml** – biblioteka SCA oparta na głębokim uczeniu TensorFlow (v1.2 – 2025).
* **pyecsca** – otwartoźródłowa ramy ECC SCA ANSSI.

---

## Odniesienia

* [Dokumentacja ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
* [Artykuł o ataku Hertzbleed](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
