# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Ataki side-channel odzyskują sekrety poprzez obserwowanie fizycznego lub mikroarchitektonicznego „leakage”, które jest *skorelowane* ze stanem wewnętrznym, ale nie jest częścią logicznego interfejsu urządzenia. Przykłady obejmują pomiar chwilowego prądu pobieranego przez smart-card oraz wykorzystywanie efektów zarządzania energią CPU przez sieć.

---

## Główne kanały leakage

| Kanał | Typowy cel | Oprzyrządowanie |
|---------|---------------|-----------------|
| Zużycie energii | Smart-cards, IoT MCUs, FPGAs | Oscyloskop + rezystor bocznikowy/sonda HS (np. CW503)
| Pole elektromagnetyczne (EM) | CPUs, RFID, akceleratory AES | Sonda pola H + LNA, ChipWhisperer/RTL-SDR
| Czas wykonania / caches | CPUs desktopowe i cloud | Timery o wysokiej precyzji (rdtsc/rdtscp), zdalny pomiar czasu przelotu
| Akustyczne / mechaniczne | Klawiatury, drukarki 3-D, przekaźniki | Mikrofon MEMS, wibrometr laserowy
| Optyczne i termiczne | LEDs, drukarki laserowe, DRAM | Fotodioda / kamera high-speed, kamera IR
| Wywołane faultami | Kryptografia ASIC/MCU | Glitch zegara/napięcia, EMFI, iniekcja laserowa

---

## Power Analysis

### Simple Power Analysis (SPA)
Obserwuj *pojedynczy* trace i bezpośrednio powiąż piki/doliny z operacjami (np. S-boxami DES).
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
### Różnicowa analiza mocy/analiza korelacyjna mocy (DPA/CPA)
Zbierz *N > 1 000* trace'ów, postaw hipotezę dotyczącą bajtu klucza `k`, oblicz model HW/HD i skoreluj go z leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA nadal pozostaje state-of-the-art, ale warianty machine-learning (MLA, deep-learning SCA) dominują obecnie w zawodach takich jak ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Sondy EM pola bliskiego (500 MHz–3 GHz) leakują identyczne informacje jak power analysis *bez* konieczności wstawiania shuntów. Badania z 2024 roku wykazały możliwość odzyskania klucza w odległości **>10 cm** od STM32 przy użyciu spectrum correlation i tanich front-endów RTL-SDR.

---

## Timing & Micro-architectural Attacks
Współczesne CPU leakują sekrety przez współdzielone zasoby:
* **Hertzbleed (2022)** – skalowanie częstotliwości DVFS koreluje z wagą Hamminga, umożliwiając *zdalne* wydobycie kluczy EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution umożliwia odczyt danych AVX-gather między wątkami SMT.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction leakuje rejestry między domenami.

---

## Acoustic & Optical Attacks
* W 2024 roku „​iLeakKeys” wykazał 95% skuteczności odzyskiwania naciśnięć klawiszy laptopa z użyciem **mikrofonu smartfona podczas rozmowy przez Zoom** i klasyfikatora CNN.
* Szybkie fotodiody rejestrują aktywność diody LED DDR4 i odtwarzają klucze rund AES w czasie <1 minuty (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Łączenie faultów z side-channel leakage skraca przeszukiwanie klucza (np. 1-trace AES DFA). Najnowsze narzędzia w cenach dostępnych dla hobbystów:
* **ChipSHOUTER & PicoEMP** – glitching impulsami elektromagnetycznymi krótszymi niż 1 ns.
* **GlitchKit-R5 (2025)** – open-source platforma do clock/voltage glitchingu obsługująca SoC RISC-V.

---

## Typical Attack Workflow
1. Zidentyfikuj kanał leakage i punkt podłączenia (pin VCC, kondensator odsprzęgający, punkt pola bliskiego).
2. Wstaw trigger (GPIO lub oparty na wzorcu).
3. Zbierz >1 k trace’ów z odpowiednim próbkowaniem i filtrami.
4. Wykonaj pre-processing (alignment, mean removal, filtr LP/HP, wavelet, PCA).
5. Przeprowadź statystyczne lub oparte na ML odzyskiwanie klucza (CPA, MIA, DL-SCA).
6. Zweryfikuj wyniki i powtórz proces dla outlierów.

---

## Defences & Hardening
* Implementacje **constant-time** i memory-hard algorithms.
* **Masking/shuffling** – podziel sekrety na losowe udziały; odporność pierwszego rzędu certyfikowana przez TVLA.
* **Hiding** – regulatory napięcia on-chip, randomizowany zegar, logika dual-rail, osłony EM.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – wyłącz DVFS/turbo w crypto kernels, odizoluj SMT, zabroń co-location w multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – oscyloskop 500 MS/s + trigger Cortex-M; API Pythona jak wyżej.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – rozwiązanie komercyjne obsługujące automated leakage assessment (TVLA-2.0).
* **scaaml** – biblioteka deep-learning SCA oparta na TensorFlow (v1.2 – 2025).
* **pyecsca** – open-source framework ANSSI do ECC SCA.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
