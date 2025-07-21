# Side Channel Analysis Attacks 

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks recover secrets by observing physical or micro-architectural "leakage" that is *correlated* with internal state but is *not* part of the logical interface of the device.  Examples range from measuring the instantaneous current drawn by a smart-card to abusing CPU power-management effects over a network.

---

## Main Leakage Channels

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
Observe a *single* trace and directly associate peaks/valleys with operations (e.g. DES S-boxes).  
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
Acquire *N > 1 000* traces, hypothesise key byte `k`, compute HW/HD model and correlate with leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA remains state-of-the-art but machine-learning variants (MLA, deep-learning SCA) now dominate competitions such as ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Near-field EM probes (500 MHz–3 GHz) leak identical information to power analysis *without* inserting shunts. 2024 research demonstrated key recovery at **>10 cm** from an STM32 using spectrum correlation and low-cost RTL-SDR front-ends.

---

## Timing & Micro-architectural Attacks
Modern CPUs leak secrets through shared resources:
* **Hertzbleed (2022)** – DVFS frequency scaling correlates with Hamming weight, allowing *remote* extraction of EdDSA keys.
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution to read AVX-gather data across SMT threads.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction leaks registers cross-domain.

For a broad treatment of Spectre-class issues see {{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}

---

## Acoustic & Optical Attacks
* 2024 "​iLeakKeys" showed 95 % accuracy recovering laptop keystrokes from a **smart-phone microphone over Zoom** using a CNN classifier.
* High-speed photodiodes capture DDR4 activity LED and reconstruct AES round keys within <1 minute (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Combining faults with side-channel leakage shortcuts key search (e.g. 1-trace AES DFA).  Recent hobbyist-priced tools:
* **ChipSHOUTER & PicoEMP** – sub-1 ns electromagnetic pulse glitching.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch platform supporting RISC-V SoCs.

---

## Typical Attack Workflow
1. Identify leakage channel & mount point (VCC pin, decoupling cap, near-field spot).
2. Insert trigger (GPIO or pattern-based).  
3. Collect >1 k traces with proper sampling/filters.
4. Pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical or ML key recovery (CPA, MIA, DL-SCA).
6. Validate and iterate on outliers.

---

## Defences & Hardening
* **Constant-time** implementations & memory-hard algorithms.
* **Masking/shuffling** – split secrets into random shares; first-order resistance certified by TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – disable DVFS/turbo in crypto kernels, isolate SMT, prohibit co-location in multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; Python API as above.
* **Riscure Inspector & FI** – commercial, supports automated leakage assessment (TVLA-2.0).
* **scaaml** – TensorFlow-based deep-learning SCA library (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}