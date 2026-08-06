# Napadi analizom sporednog kanala

{{#include ../../banners/hacktricks-training.md}}

Napadi sporednim kanalima otkrivaju tajne posmatranjem fizičkog ili mikroarhitektonskog "leakage-a" koji je *povezan* sa internim stanjem, ali *nije* deo logičkog interfejsa uređaja. Primeri obuhvataju merenje trenutne struje koju troši smart-card, kao i zloupotrebu efekata upravljanja napajanjem CPU-a preko mreže.

---

## Glavni kanali leakage-a

| Kanal | Tipična meta | Instrumentacija |
|---------|---------------|-----------------|
| Potrošnja energije | Smart-cards, IoT MCU-ovi, FPGA | Osciloskop + šant otpornik/HS sonda (npr. CW503)
| Elektromagnetno polje (EM) | CPU-ovi, RFID, AES akceleratori | H-field sonda + LNA, ChipWhisperer/RTL-SDR
| Vreme izvršavanja / keš memorije | Desktop i cloud CPU-ovi | High-precision timer-i (rdtsc/rdtscp), remote time-of-flight
| Akustički / mehanički | Tastature, 3-D štampači, releji | MEMS mikrofon, laserski vibrometar
| Optički i termalni | LED-ovi, laserski štampači, DRAM | Fotodioda / high-speed kamera, IR kamera
| Izazvano greškom | Kriptografija za ASIC/MCU | Clock/voltage glitch, EMFI, laser injection

---

## Analiza potrošnje energije

### Simple Power Analysis (SPA)
Posmatrajte *jedan* trace i direktno povežite vrhove/doline sa operacijama (npr. DES S-boxovima).<sup>[[1]](#references)</sup>
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
Prikupite *N > 1 000* trace-ova, postavite hipotezu o bajtu ključa `k`, izračunajte HW/HD model i korelirajte ga sa leak-om.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ostaje state-of-the-art, ali varijante zasnovane na machine learningu (MLA, deep-learning SCA) sada dominiraju takmičenjima kao što je ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Near-field EM probe (500 MHz–3 GHz) leak identične informacije kao power analysis *bez* umetanja shuntova. Istraživanje iz 2024. godine demonstriralo je oporavak ključa na udaljenosti od **>10 cm** od STM32 uređaja, korišćenjem spectrum correlation i jeftinih RTL-SDR front-endova.

---

## Timing & Micro-architectural Attacks
Moderni CPU-ovi leak-uju tajne kroz deljene resurse:
* **Hertzbleed (2022)** – DVFS frequency scaling korelira sa Hamming weight, što omogućava *remote* ekstrakciju EdDSA ključeva.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution za čitanje AVX-gather podataka između SMT threadova.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction leak-uje registre između domena.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
* Istraživanje "iLeakKeys" iz 2024. godine pokazalo je 95 % tačnosti pri oporavku pritisnutih tastera laptopa pomoću **mikrofona smart-phone uređaja preko Zoom-a**, koristeći CNN classifier.
* High-speed photodiodes hvataju DDR4 activity LED i rekonstruišu AES round keys za manje od 1 minuta (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Kombinovanje faultova sa side-channel leakage-om skraćuje pretragu ključa (npr. 1-trace AES DFA). Nedavno dostupni alati po ceni pristupačnoj hobistima:
* **ChipSHOUTER & PicoEMP** – electromagnetic pulse glitching kraći od 1 ns.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch platforma sa podrškom za RISC-V SoC-ove.

---

## Typical Attack Workflow
1. Identifikovati leakage channel i mount point (VCC pin, decoupling cap, near-field spot).
2. Ubaciti trigger (GPIO ili pattern-based).
3. Prikupiti >1 k trace-ova uz odgovarajuće sampling/filtere.
4. Pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical ili ML key recovery (CPA, MIA, DL-SCA).
6. Validirati rezultate i ponoviti postupak za outlier-e.

---

## Defences & Hardening
* **Constant-time** implementacije i memory-hard algoritmi.
* **Masking/shuffling** – podeliti tajne na random shares; first-order resistance sertifikovan pomoću TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – onemogućiti DVFS/turbo u crypto kernelima, izolovati SMT, zabraniti co-location u multi-tenant cloudovima.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – osciloskop od 500 MS/s + Cortex-M trigger; Python API kao gore.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – komercijalni alat sa podrškom za automated leakage assessment (TVLA-2.0).
* **scaaml** – TensorFlow-based deep-learning SCA biblioteka (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
