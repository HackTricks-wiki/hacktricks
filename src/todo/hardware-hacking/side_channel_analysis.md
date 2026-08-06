# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks herwin geheime deur fisiese of mikro-argitektoniese "leakage" waar te neem wat *gekorreleer* is met interne toestand, maar *nie* deel is van die logiese koppelvlak van die toestel nie. Voorbeelde strek van die meting van die oombliklike stroom wat deur ’n smart-card getrek word tot die misbruik van CPU-kragbestuurseffekte oor ’n netwerk.

---

## Hoof-leakage-kanale

| Kanaal | Tipiese teiken | Instrumentasie |
|---------|---------------|-----------------|
| Kragverbruik | Smart-cards, IoT MCUs, FPGAs | Ossilloskoop + shuntweerstand/HS-probe (bv. CW503)
| Elektromagnetiese veld (EM) | CPUs, RFID, AES-accelerators | H-veld-probe + LNA, ChipWhisperer/RTL-SDR
| Uitvoeringstyd / caches | Desktop- en cloud-CPUs | Hoëpresisie-timers (rdtsc/rdtscp), afgeleë time-of-flight
| Akoesties / meganies | Sleutelborde, 3D-drukkers, relais | MEMS-mikrofoon, laservibrometer
| Opties & termies | LEDs, laserdrukkers, DRAM | Fotodiode / hoëspoedkamera, IR-kamera
| Fault-induced | ASIC/MCU-kriptografie | Clock/voltage glitch, EMFI, laser-injection

---

## Kraganalise

### Simple Power Analysis (SPA)
Neem ’n *enkele* trace waar en assosieer pieke/dale direk met bewerkings (bv. DES S-boxes).<sup>[[1]](#references)</sup>
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
Versamel *N > 1 000* traces, formuleer ’n hipotese oor sleutelgreep `k`, bereken die HW/HD-model en korreleer dit met leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA bly state-of-the-art, maar machine-learning-variante (MLA, deep-learning SCA) oorheers nou kompetisies soos ASCAD-v2 (2023).

---

## Elektromagnetiese Analise (EMA)
Near-field EM-probes (500 MHz–3 GHz) lek identiese inligting as power analysis *sonder* om shunts in te voeg. Navorsing in 2024 het key recovery op **>10 cm** vanaf ’n STM32 gedemonstreer deur spectrum correlation en goedkoop RTL-SDR-front-ends te gebruik.

---

## Tydsberekening- & Mikro-argitektoniese Aanvalle
Moderne CPUs lek geheime deur gedeelde hulpbronne:
* **Hertzbleed (2022)** – DVFS frequency scaling korreleer met Hamming weight, wat *remote* extraction van EdDSA-sleutels moontlik maak.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution om AVX-gather-data oor SMT-threads te lees.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction lek registers oor domeine heen.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Akoestiese & Optiese Aanvalle
* 2024 se "​iLeakKeys" het 95 % akkuraatheid getoon met die recovery van laptop-keystrokes vanaf ’n **smart-phone-mikrofoon oor Zoom** deur ’n CNN-classifier te gebruik.
* High-speed photodiodes vang DDR4-aktiwiteit se LED op en rekonstrueer AES-round keys binne <1 minuut (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Deur faults met side-channel leakage te kombineer, word key search verkort (bv. 1-trace AES DFA). Onlangse tools teen hobbyist-pryse:
* **ChipSHOUTER & PicoEMP** – sub-1 ns elektromagnetiese pulse glitching.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch-platform met ondersteuning vir RISC-V SoCs.

---

## Tipiese Aanval-Workflow
1. Identifiseer leakage channel & mount point (VCC-pin, decoupling cap, near-field-plek).
2. Voeg trigger in (GPIO of pattern-based).
3. Versamel >1 k traces met behoorlike sampling/filters.
4. Pre-process (alignment, mean removal, LP/HP-filter, wavelet, PCA).
5. Statistiese of ML key recovery (CPA, MIA, DL-SCA).
6. Valideer en herhaal op outliers.

---

## Defences & Hardening
* **Constant-time**-implementasies & memory-hard algorithms.
* **Masking/shuffling** – verdeel geheime in random shares; first-order resistance gesertifiseer deur TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM-shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – deaktiveer DVFS/turbo in crypto-kernels, isoleer SMT, verbied co-location in multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M-trigger; Python API soos hierbo.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – kommersieel, ondersteun geoutomatiseerde leakage-assessment (TVLA-2.0).
* **scaaml** – TensorFlow-gebaseerde deep-learning SCA-library (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA-framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
