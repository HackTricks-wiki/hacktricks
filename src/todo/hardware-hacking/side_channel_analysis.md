# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks hurejesha siri kwa kuchunguza "leakage" ya kimwili au ya micro-architectural ambayo *inahusiana* na hali ya ndani, lakini *si sehemu* ya logical interface ya kifaa. Mifano inaanzia kupima current ya papo hapo inayotumiwa na smart-card hadi kutumia athari za CPU power-management kupitia network.

---

## Njia Kuu za Leakage

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | Smart-cards, IoT MCUs, FPGAs | Oscilloscope + shunt resistor/HS probe (e.g. CW503)
| Electromagnetic field (EM) | CPUs, RFID, AES accelerators | H-field probe + LNA, ChipWhisperer/RTL-SDR
| Execution time / caches | Desktop & cloud CPUs | High-precision timers (rdtsc/rdtscp), remote time-of-flight
| Acoustic / mechanical | Keyboards, 3-D printers, relays | MEMS microphone, laser vibrometer
| Optical & thermal | LEDs, laser printers, DRAM | Photodiode / high-speed camera, IR camera
| Fault-induced | ASIC/MCU cryptos | Clock/voltage glitch, EMFI, laser injection

---

## Power Analysis

### Simple Power Analysis (SPA)
Chunguza *trace* moja na uhusishe moja kwa moja peaks/valleys na operations (kwa mfano, DES S-boxes).
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
Kusanya *N > 1 000* traces, weka hypothesis ya key byte `k`, hesabu HW/HD model na ulinganishe na leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA bado ni state-of-the-art, lakini variants za machine-learning (MLA, deep-learning SCA) sasa zinatawala mashindano kama ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Near-field EM probes (500 MHz–3 GHz) hu-leak taarifa zinazofanana na power analysis *bila* kuingiza shunts. Utafiti wa 2024 ulionyesha key recovery kwa umbali wa **>10 cm** kutoka kwa STM32 kwa kutumia spectrum correlation na RTL-SDR front-ends za gharama nafuu.

---

## Timing & Micro-architectural Attacks
CPU za kisasa hu-leak secrets kupitia shared resources:
* **Hertzbleed (2022)** – DVFS frequency scaling inahusiana na Hamming weight, na kuruhusu *remote* extraction ya EdDSA keys.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution kusoma AVX-gather data kwenye SMT threads.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction hu-leak registers katika cross-domain.

---

## Acoustic & Optical Attacks
* 2024 "​iLeakKeys" ilionyesha usahihi wa 95 % katika kurejesha laptop keystrokes kutoka kwa **smart-phone microphone over Zoom** kwa kutumia CNN classifier.
* High-speed photodiodes hunasa DDR4 activity LED na kujenga upya AES round keys ndani ya <1 minute (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Kuchanganya faults na side-channel leakage hupunguza key search (kwa mfano, 1-trace AES DFA). Zana za hivi karibuni zenye bei kwa hobbyists:
* **ChipSHOUTER & PicoEMP** – electromagnetic pulse glitching ya chini ya 1 ns.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch platform inayotumia RISC-V SoCs.

---

## Typical Attack Workflow
1. Tambua leakage channel na mount point (VCC pin, decoupling cap, near-field spot).
2. Weka trigger (GPIO au pattern-based).
3. Kusanya >1 k traces kwa sampling/filters zinazofaa.
4. Fanya pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Fanya statistical au ML key recovery (CPA, MIA, DL-SCA).
6. Thibitisha na urudie mchakato kwa outliers.

---

## Defences & Hardening
* Implementations za **Constant-time** na memory-hard algorithms.
* **Masking/shuffling** – gawanya secrets kuwa random shares; first-order resistance iliyothibitishwa na TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – zima DVFS/turbo kwenye crypto kernels, tenga SMT, kataza co-location katika multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; Python API kama ilivyo hapo juu.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial, inaunga mkono automated leakage assessment (TVLA-2.0).
* **scaaml** – TensorFlow-based deep-learning SCA library (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
