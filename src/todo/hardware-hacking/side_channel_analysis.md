# Napadi analizom sporednog kanala

{{#include ../../banners/hacktricks-training.md}}

Napadi sporednim kanalima otkrivaju tajne posmatranjem fizičkog ili mikroarhitektonskog „leakage-a“ koji je *u korelaciji* sa internim stanjem, ali nije deo logičkog interfejsa uređaja. Primeri se kreću od merenja trenutne struje koju troši smart-card do zloupotrebe efekata upravljanja napajanjem CPU-a preko mreže.

---

## Glavni kanali leakage-a

| Kanal | Tipična meta | Instrumentacija |
|---------|---------------|-----------------|
| Potrošnja energije | Smart-card uređaji, IoT MCU-ovi, FPGA-ovi | Osciloskop + šant otpornik/HS sonda (npr. CW503)
| Elektromagnetno polje (EM) | CPU-ovi, RFID, AES akceleratori | H-field sonda + LNA, ChipWhisperer/RTL-SDR
| Vreme izvršavanja / keš memorije | Desktop i cloud CPU-ovi | Precizni tajmeri (rdtsc/rdtscp), udaljeno merenje vremena putovanja
| Akustika / mehanika | Tastature, 3-D štampači, releji | MEMS mikrofon, laserski vibrometar
| Optika i toplota | LED diode, laserski štampači, DRAM | Fotodioda / high-speed kamera, IR kamera
| Izazvane greške | ASIC/MCU kriptografija | Glitchovanje takta/napona, EMFI, laserska injekcija

---

## Power Analysis

### Simple Power Analysis (SPA)
Posmatrajte *jedan* trace i direktno povežite vrhove i udoline sa operacijama (npr. DES S-boxovima).
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
### Diferencijalna/ korelaciona analiza potrošnje (DPA/CPA)
Prikupite *N > 1 000* tragova, postavite hipotezu o bajtu ključa `k`, izračunajte HW/HD model i korelišite ga sa curenjem.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ostaje state-of-the-art, ali varijante zasnovane na machine learningu (MLA, deep-learning SCA) sada dominiraju takmičenjima kao što je ASCAD-v2 (2023).

---

## Elektromagnetna analiza (EMA)
Near-field EM probes (500 MHz–3 GHz) leak identične informacije kao power analysis *bez* umetanja shuntova. Istraživanje iz 2024. pokazalo je oporavak ključa na udaljenosti od **>10 cm** od STM32 uređaja korišćenjem spectrum correlation pristupa i jeftinih RTL-SDR front-endova.

---

## Timing & Micro-architectural Attacks
Moderni CPU-ovi leak-uju tajne kroz deljene resurse:
* **Hertzbleed (2022)** – DVFS frequency scaling korelira sa Hamming weight, omogućavajući *remote* ekstrakciju EdDSA ključeva.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution za čitanje AVX-gather podataka između SMT threadova.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction leak-uje registre između domena.

---

## Acoustic & Optical Attacks
* Istraživanje „​iLeakKeys“ iz 2024. pokazalo je 95 % tačnosti u oporavku pritisnutih tastera laptopa pomoću mikrofona **smartphone-a preko Zoom-a**, uz korišćenje CNN classifier-a.
* High-speed photodiodes snimaju aktivnost DDR4 activity LED-a i rekonstruišu AES round keys za manje od 1 minuta (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Kombinovanje faultova sa side-channel leakage-om skraćuje pretragu ključa (npr. 1-trace AES DFA). Nedavni alati po ceni dostupnoj hobistima:
* **ChipSHOUTER & PicoEMP** – electromagnetic pulse glitching kraći od 1 ns.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch platforma sa podrškom za RISC-V SoC-ove.

---

## Tipičan tok napada
1. Identifikujte leakage channel i mount point (VCC pin, decoupling cap, near-field spot).
2. Umetnite trigger (GPIO ili zasnovan na patternu).
3. Prikupite >1 k trace-ova uz pravilno samplingovanje i filtere.
4. Preprocesirajte podatke (alignment, uklanjanje srednje vrednosti, LP/HP filter, wavelet, PCA).
5. Statistički ili ML key recovery (CPA, MIA, DL-SCA).
6. Validirajte rezultate i ponovite postupak za outlier-e.

---

## Defences & Hardening
* Implementacije sa **constant-time** izvršavanjem i memory-hard algoritmi.
* **Masking/shuffling** – podelite tajne na random shares; first-order resistance sertifikovan pomoću TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – onemogućite DVFS/turbo u crypto kernelima, izolujte SMT i zabranite co-location u multi-tenant cloudovima.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – osciloskop sa 500 MS/s + Cortex-M trigger; Python API kao iznad.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – komercijalni alati sa podrškom za automated leakage assessment (TVLA-2.0).
* **scaaml** – TensorFlow-based deep-learning SCA biblioteka (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
