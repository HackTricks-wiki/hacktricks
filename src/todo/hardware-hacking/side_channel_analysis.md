# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks ऐसे secrets recover करते हैं जो physical या micro-architectural "leakage" को observe करके प्राप्त किए जाते हैं। यह "leakage" internal state के साथ *correlated* होता है, लेकिन device के logical interface का हिस्सा नहीं होता। इसके उदाहरण smart-card द्वारा खींचे जाने वाले instantaneous current को मापने से लेकर network के माध्यम से CPU power-management effects का दुरुपयोग करने तक होते हैं।

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
एक *single* trace को observe करें और peaks/valleys को operations (जैसे DES S-boxes) के साथ सीधे associate करें।
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
*N > 1 000* traces प्राप्त करें, key byte `k` की परिकल्पना करें, HW/HD model की गणना करें और leakage के साथ correlate करें।
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA अभी भी state-of-the-art है, लेकिन machine-learning variants (MLA, deep-learning SCA) अब ASCAD-v2 (2023) जैसी competitions में प्रमुख हैं।

---

## Electromagnetic Analysis (EMA)
Near-field EM probes (500 MHz–3 GHz) shunts डाले बिना power analysis के समान information leak करते हैं। 2024 के research ने spectrum correlation और low-cost RTL-SDR front-ends का उपयोग करके STM32 से **>10 cm** की दूरी पर key recovery प्रदर्शित की।

---

## Timing & Micro-architectural Attacks
Modern CPUs shared resources के माध्यम से secrets leak करते हैं:
* **Hertzbleed (2022)** – DVFS frequency scaling Hamming weight से correlate होती है, जिससे *remote* EdDSA keys extraction संभव होता है।<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – SMT threads के बीच AVX-gather data पढ़ने के लिए transient-execution।
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction cross-domain registers leak करता है।

---

## Acoustic & Optical Attacks
* 2024 के "​iLeakKeys" ने CNN classifier का उपयोग करके **smart-phone microphone over Zoom** से laptop keystrokes recover करने में 95 % accuracy प्रदर्शित की।
* High-speed photodiodes DDR4 activity LED को capture करते हैं और AES round keys को <1 minute में reconstruct करते हैं (BlackHat 2023)।

---

## Fault Injection & Differential Fault Analysis (DFA)
Faults को side-channel leakage के साथ combine करने से key search आसान हो जाती है (जैसे, 1-trace AES DFA)। Recent hobbyist-priced tools:
* **ChipSHOUTER & PicoEMP** – sub-1 ns electromagnetic pulse glitching।
* **GlitchKit-R5 (2025)** – RISC-V SoCs को support करने वाला open-source clock/voltage glitch platform।

---

## Typical Attack Workflow
1. Leakage channel और mount point की पहचान करें (VCC pin, decoupling cap, near-field spot)।
2. Trigger insert करें (GPIO या pattern-based)।
3. Proper sampling/filters के साथ >1 k traces collect करें।
4. Pre-process करें (alignment, mean removal, LP/HP filter, wavelet, PCA)।
5. Statistical या ML key recovery करें (CPA, MIA, DL-SCA)।
6. Validate करें और outliers पर iterate करें।

---

## Defences & Hardening
* **Constant-time** implementations और memory-hard algorithms।
* **Masking/shuffling** – secrets को random shares में split करें; first-order resistance TVLA द्वारा certified हो।
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields।
* **Fault detection** – redundant computation, threshold signatures।
* **Operational** – crypto kernels में DVFS/turbo disable करें, SMT isolate करें, multi-tenant clouds में co-location prohibit करें।

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; ऊपर दिया गया Python API।<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial, automated leakage assessment (TVLA-2.0) support करता है।
* **scaaml** – TensorFlow-based deep-learning SCA library (v1.2 – 2025)।
* **pyecsca** – ANSSI open-source ECC SCA framework।

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
