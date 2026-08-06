# Ataki typu Side Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Ataki side-channel odzyskują sekrety poprzez obserwowanie fizycznego lub mikroarchitektonicznego „leakage”, który jest *skorelowany* ze stanem wewnętrznym, ale *nie* stanowi części logicznego interfejsu urządzenia. Przykłady obejmują zarówno pomiar chwilowego prądu pobieranego przez kartę smart-card, jak i wykorzystywanie efektów zarządzania energią CPU przez sieć.

---

## Główne kanały leakage

| Kanał | Typowy cel | Instrumentacja |
|---------|---------------|-----------------|
| Pobór mocy | Smart-cards, MCU IoT, FPGA | Oscyloskop + rezystor bocznikowy / sonda HS (np. CW503)
| Pole elektromagnetyczne (EM) | CPU, RFID, akceleratory AES | Sonda H-field + LNA, ChipWhisperer/RTL-SDR
| Czas wykonania / cache | CPU desktopowe i cloud | Timery o wysokiej precyzji (rdtsc/rdtscp), zdalny pomiar czasu przelotu
| Akustyka / mechanika | Klawiatury, drukarki 3D, przekaźniki | Mikrofon MEMS, wibrometr laserowy
| Optyka i temperatura | LED-y, drukarki laserowe, DRAM | Fotodioda / kamera high-speed, kamera IR
| Wywołanie błędu | Kryptografia ASIC/MCU | Glitch zegara/napięcia, EMFI, iniekcja laserowa

---

## Analiza poboru mocy

### Simple Power Analysis (SPA)
Obserwuj *pojedynczy* trace i bezpośrednio powiąż piki/doliny z operacjami (np. S-boxami DES).<sup>[[1]](#references)</sup>
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
### Differential/Correlation Power Analysis (DPA/CPA)
Pozyskaj *N > 1 000* śladów pomiarowych, przyjmij hipotezę dotyczącą bajtu klucza `k`, oblicz model HW/HD i skoreluj go z leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA pozostaje metodą state-of-the-art, ale warianty oparte na machine learning (MLA, deep-learning SCA) dominują obecnie w konkursach takich jak ASCAD-v2 (2023).

---

## Analiza elektromagnetyczna (EMA)
Sondy EM pola bliskiego (500 MHz–3 GHz) ujawniają identyczne informacje jak power analysis, *bez* konieczności wprowadzania shuntów. Badania z 2024 roku wykazały możliwość odzyskania klucza w odległości **>10 cm** od STM32 przy użyciu korelacji widmowej i tanich front-endów RTL-SDR.

---

## Ataki czasowe i mikroarchitektoniczne
Nowoczesne procesory ujawniają sekrety przez współdzielone zasoby:
* **Hertzbleed (2022)** – skalowanie częstotliwości DVFS koreluje z wagą Hamminga, umożliwiając *zdalne* wydobycie kluczy EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution umożliwia odczyt danych AVX-gather między wątkami SMT.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – spekulacyjne błędne przewidywanie operacji wektorowych ujawnia rejestry między domenami.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Ataki akustyczne i optyczne
* Badanie „​iLeakKeys” z 2024 roku wykazało 95-procentową dokładność odzyskiwania naciśnięć klawiszy laptopa z **mikrofonu smartfona podczas rozmowy przez Zoom** przy użyciu klasyfikatora CNN.
* Szybkie fotodiody rejestrują diodę LED aktywności DDR4 i rekonstruują klucze rund AES w czasie krótszym niż 1 minuta (BlackHat 2023).

---

## Fault Injection i Differential Fault Analysis (DFA)
Łączenie faultów z leakage side-channel skraca wyszukiwanie klucza (np. 1-trace AES DFA). Najnowsze narzędzia w cenach dostępnych dla hobbystów:
* **ChipSHOUTER & PicoEMP** – glitching impulsami elektromagnetycznymi krótszymi niż 1 ns.
* **GlitchKit-R5 (2025)** – open-source'owa platforma do clock/voltage glitchingu obsługująca SoC RISC-V.

---

## Typowy przebieg ataku
1. Zidentyfikuj kanał leakage i punkt montażu (pin VCC, kondensator odsprzęgający, punkt pola bliskiego).
2. Wstaw trigger (GPIO lub oparty na wzorcu).
3. Zbierz >1 k trace'ów z odpowiednim próbkowaniem i filtrami.
4. Wykonaj pre-processing (alignment, usuwanie średniej, filtr LP/HP, wavelet, PCA).
5. Odzyskaj klucz metodami statystycznymi lub ML (CPA, MIA, DL-SCA).
6. Zweryfikuj wyniki i powtórz procedurę dla wartości odstających.

---

## Obrona i hardening
* Implementacje **constant-time** i algorytmy memory-hard.
* **Masking/shuffling** – podziel sekrety na losowe shares; odporność pierwszego rzędu certyfikowana przez TVLA.
* **Hiding** – regulatory napięcia on-chip, losowy clock, logika dual-rail, osłony EM.
* **Fault detection** – redundantne obliczenia, sygnatury progowe.
* **Operacyjne** – wyłącz DVFS/turbo w kernelach kryptograficznych, izoluj SMT, zabroń co-location w chmurach multi-tenant.

---

## Narzędzia i frameworki
* **ChipWhisperer-Husky** (2024) – scope 500 MS/s + trigger Cortex-M; API Python jak wyżej.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – rozwiązanie komercyjne obsługujące automatyczną ocenę leakage (TVLA-2.0).
* **scaaml** – biblioteka deep-learning SCA oparta na TensorFlow (v1.2 – 2025).
* **pyecsca** – open-source'owy framework ANSSI do SCA krzywych eliptycznych.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
