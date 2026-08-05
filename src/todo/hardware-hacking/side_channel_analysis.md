# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks herwin geheime deur fisiese of mikro-argitektoniese "leakage" waar te neem wat *gekorreleer* is met interne toestand, maar *nie* deel is van die logiese koppelvlak van die toestel nie. Voorbeelde wissel van die meting van die oombliklike stroom wat deur 'n smart-card getrek word tot die misbruik van CPU-kragbestuur-effekte oor 'n netwerk.

---

## Main Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | Smart-cards, IoT MCUs, FPGAs | Ossilloskoop + shunt-resistor/HS-probe (bv. CW503)
| Electromagnetic field (EM) | CPUs, RFID, AES accelerators | H-veld-probe + LNA, ChipWhisperer/RTL-SDR
| Execution time / caches | Desktop & cloud CPUs | Hoëpresisie-timers (rdtsc/rdtscp), afgeleë time-of-flight
| Acoustic / mechanical | Keyboards, 3-D printers, relays | MEMS-mikrofoon, laser-vibrometer
| Optical & thermal | LEDs, laser printers, DRAM | Fotodiode / hoëspoedkamera, IR-kamera
| Fault-induced | ASIC/MCU cryptos | Klok/spanning-glitch, EMFI, laser-inspuiting

---

## Power Analysis

### Simple Power Analysis (SPA)
Neem 'n *enkele* trace waar en assosieer pieke/dale direk met bewerkings (bv. DES S-boxes).
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
Versamel *N > 1 000* traces, stel ’n hipotese oor sleutelgreep `k` op, bereken die HW/HD-model en korreleer dit met die leak.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA bly state-of-the-art, maar machine-learning-variante (MLA, deep-learning SCA) oorheers nou kompetisies soos ASCAD-v2 (2023).

---

## Elektromagnetiese Analise (EMA)
Near-field EM probes (500 MHz–3 GHz) lek identiese inligting as power analysis *sonder* om shunts in te voeg. Navorsing in 2024 het key recovery op **>10 cm** van ’n STM32 gedemonstreer met spectrum correlation en laekoste RTL-SDR-front-ends.

---

## Timing & Mikro-argitektoniese Aanvalle
Moderne SVE’s lek geheime deur gedeelde hulpbronne:
* **Hertzbleed (2022)** – DVFS frequency scaling korreleer met Hamming weight, wat *remote* extraction van EdDSA-keys moontlik maak.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution om AVX-gather-data oor SMT-threads heen te lees.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction lek registers oor domeine heen.

---

## Akoestiese & Optiese Aanvalle
* 2024 se "​iLeakKeys" het 95 % akkuraatheid getoon met die recovery van laptop-keystrokes vanaf ’n **smart-phone microphone oor Zoom** deur ’n CNN-classifier te gebruik.
* High-speed photodiodes vang DDR4-aktiwiteit-LED vas en rekonstrueer AES-round keys binne <1 minuut (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Die kombinasie van faults met side-channel leakage verkort key search (bv. 1-trace AES DFA). Onlangse tools teen hobbyist-pryse:
* **ChipSHOUTER & PicoEMP** – sub-1 ns electromagnetic pulse glitching.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch-platform met ondersteuning vir RISC-V-SoC’s.

---

## Tipiese Aanval-Workflow
1. Identifiseer die leakage channel & mount point (VCC-pin, decoupling cap, near-field-spot).
2. Voeg ’n trigger in (GPIO of pattern-based).
3. Versamel >1 k traces met behoorlike sampling/filters.
4. Pre-process (alignment, mean removal, LP/HP-filter, wavelet, PCA).
5. Statistical of ML key recovery (CPA, MIA, DL-SCA).
6. Valideer en herhaal op outliers.

---

## Defences & Hardening
* **Constant-time**-implementasies & memory-hard algorithms.
* **Masking/shuffling** – verdeel secrets in random shares; first-order resistance gesertifiseer deur TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM-shields.
* **Fault detection** – redundante berekening, threshold signatures.
* **Operational** – deaktiveer DVFS/turbo in crypto-kernels, isoleer SMT, verbied co-location in multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s-scope + Cortex-M-trigger; Python-API soos hierbo.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – kommersieel, ondersteun geoutomatiseerde leakage-assessment (TVLA-2.0).
* **scaaml** – TensorFlow-gebaseerde deep-learning SCA-library (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA-framework.

---

## Verwysings

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
