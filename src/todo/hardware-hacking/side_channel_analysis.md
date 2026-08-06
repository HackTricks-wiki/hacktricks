# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks hurejesha siri kwa kuchunguza "leakage" ya kimwili au ya micro-architectural ambayo *inahusiana* na hali ya ndani lakini *si sehemu* ya logical interface ya kifaa. Mifano inaanzia kupima current ya papo hapo inayotumiwa na smart-card hadi kutumia vibaya athari za CPU power-management kupitia network.

---

## Main Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | Smart-cards, IoT MCUs, FPGAs | Oscilloscope + shunt resistor/HS probe (mfano, CW503)
| Electromagnetic field (EM) | CPUs, RFID, AES accelerators | H-field probe + LNA, ChipWhisperer/RTL-SDR
| Execution time / caches | Desktop & cloud CPUs | High-precision timers (rdtsc/rdtscp), remote time-of-flight
| Acoustic / mechanical | Keyboards, 3-D printers, relays | MEMS microphone, laser vibrometer
| Optical & thermal | LEDs, laser printers, DRAM | Photodiode / high-speed camera, IR camera
| Fault-induced | ASIC/MCU cryptos | Clock/voltage glitch, EMFI, laser injection

---

## Power Analysis

### Simple Power Analysis (SPA)
Chunguza *trace* moja na uhusishe moja kwa moja peaks/valleys na operations (kwa mfano, DES S-boxes).<sup>[[1]](#references)</sup>
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
Kusanya *N > 1 000* traces, weka dhana kuhusu key byte `k`, hesabu HW/HD model na uhusianishe na leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA bado ni ya kiwango cha juu zaidi, lakini variants za machine-learning (MLA, deep-learning SCA) sasa zinatawala mashindano kama ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Near-field EM probes (500 MHz–3 GHz) huvuja taarifa zinazofanana na power analysis *bila* kuingiza shunts. Utafiti wa 2024 ulionyesha key recovery katika umbali wa **>10 cm** kutoka kwa STM32 kwa kutumia spectrum correlation na RTL-SDR front-ends za gharama nafuu.

---

## Timing & Micro-architectural Attacks
Modern CPUs huvuja secrets kupitia shared resources:
* **Hertzbleed (2022)** – DVFS frequency scaling inahusiana na Hamming weight, na hivyo kuruhusu *remote* extraction ya EdDSA keys.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution kusoma AVX-gather data kupitia SMT threads.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction huvuja registers kati ya domains.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
* "​iLeakKeys" ya 2024 ilionyesha usahihi wa 95 % katika recovering laptop keystrokes kutoka kwa **smart-phone microphone kupitia Zoom** kwa kutumia CNN classifier.
* High-speed photodiodes hunasa DDR4 activity LED na kujenga upya AES round keys ndani ya <1 minute (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Kuchanganya faults na side-channel leakage hupunguza key search (kwa mfano, 1-trace AES DFA). Zana za hivi karibuni zenye bei inayoweza kufikiwa na hobbyists:
* **ChipSHOUTER & PicoEMP** – sub-1 ns electromagnetic pulse glitching.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch platform inayotumia RISC-V SoCs.

---

## Typical Attack Workflow
1. Tambua leakage channel & mount point (VCC pin, decoupling cap, near-field spot).
2. Weka trigger (GPIO au pattern-based).
3. Kusanya >1 k traces kwa sampling/filters zinazofaa.
4. Fanya pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical au ML key recovery (CPA, MIA, DL-SCA).
6. Thibitisha na urudie mchakato kwa outliers.

---

## Defences & Hardening
* Implementations za **Constant-time** & memory-hard algorithms.
* **Masking/shuffling** – gawanya secrets kuwa random shares; first-order resistance iliyothibitishwa na TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – disable DVFS/turbo katika crypto kernels, tenga SMT, kataza co-location katika multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; Python API kama ilivyo hapo juu.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial, inasaidia automated leakage assessment (TVLA-2.0).
* **scaaml** – TensorFlow-based deep-learning SCA library (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
