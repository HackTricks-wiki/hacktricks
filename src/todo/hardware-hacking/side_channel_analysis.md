# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks ऐसे secrets recover करते हैं जो physical या micro-architectural "leakage" को observe करके प्राप्त किए जाते हैं। यह leakage internal state के साथ *correlated* होती है, लेकिन device के logical interface का हिस्सा नहीं होती। उदाहरणों में smart-card द्वारा खींचे गए instantaneous current को मापने से लेकर network के माध्यम से CPU power-management effects का दुरुपयोग करना शामिल है।

---

## Main Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | Smart cards, IoT MCUs, FPGAs | Oscilloscope के साथ shunt resistor या differential probe; CW503 probes/LNAs के लिए power supply है, स्वयं probe नहीं<sup>[[11]](#references)</sup> |
| Electromagnetic field (EM) | CPUs, RFID, AES accelerators | H-field/near-field probe के साथ low-noise amplifier और oscilloscope या RTL-SDR जैसे SDR receiver<sup>[[13]](#references)</sup> |
| Execution time / caches | Desktop और cloud CPUs | High-precision timers (`rdtsc`/`rdtscp`) या remote time-of-flight |
| Acoustic / mechanical | Keyboards, 3-D printers, printers, relays, और CPU voltage regulators | MEMS microphone या laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optical & thermal | Status LEDs, displays, DRAM, और thermally coupled devices | Photodiode, high-speed camera, या IR camera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU cryptography | Clock/voltage glitch, EMFI, या laser injection |

---

## Power Analysis

### Simple Power Analysis (SPA)
एक *single* trace observe करें और visible features को branches, modular multiplication, या अलग-अलग instruction sequences जैसी operations से associate करें।<sup>[[1]](#references)</sup>

Exact setup target-specific होता है। निम्न उदाहरण उस current high-level ChipWhisperer capture API का उपयोग करता है, जब scope और target connect तथा configure किए जा चुके हों:<sup>[[1]](#references)</sup>
```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
print(trace.wave)  # NumPy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
कई traces प्राप्त करें, एक key byte `k` की परिकल्पना करें, Hamming-weight (HW) या Hamming-distance (HD) leakage model की गणना करें, और इसे प्रत्येक sample के साथ correlate करें। आवश्यक trace count target, noise, alignment, countermeasures और leakage model से निर्धारित होता है; यह कोई fixed threshold नहीं है।
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA एक standard baseline है। जब leakage nonlinear हो या traces ठीक से aligned न हों, तब Template attacks, mutual-information analysis और machine-learning approaches उपयोगी हो सकते हैं।

---

## Electromagnetic Analysis (EMA)
Near-field EM analysis, supply path में shunt लगाए बिना data-dependent activity को observe कर सकता है। यह आवश्यक नहीं है कि इससे power trace जैसा ही signal मिले: probe position, orientation, bandwidth, front-end gain, trigger quality और distance सभी महत्वपूर्ण होते हैं।

---

## Timing & Micro-architectural Attacks
Modern CPUs shared resources के माध्यम से secrets leak करते हैं:
* **Hertzbleed (2022)** – Data-dependent dynamic voltage and frequency scaling एक remote timing channel बनाता है। Original end-to-end key-recovery demonstration ने SIKE को target किया था; follow-up work में अन्य primitives पर चर्चा की गई है।<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution, security boundaries के पार vector gather instructions द्वारा उपयोग किए गए data को expose कर सकता है।<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Speculative vector-register state की गलत handling, उसी physical core से data disclose कर सकती है।<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – एक transient-execution attack, phantom execution को transient execution में training के साथ combine करके attacker-controlled misprediction gadgets बनाता है।<sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
एक controlled experiment में laptop noise से RSA keys recover करने के लिए Acoustic leakage का उपयोग किया गया है, जिसमें पास के mobile phone microphone का भी उपयोग किया गया था।<sup>[[6]](#references)</sup> एक अलग 2023 keyboard study ने पास के phone से की गई recordings पर train किए जाने पर keystrokes को 95% accuracy के साथ और Zoom audio पर train किए जाने पर 93% accuracy के साथ classify किया; ये आंकड़े उस paper के trained-device experiment को दर्शाते हैं, किसी arbitrary keyboard या victim को नहीं।<sup>[[9]](#references)</sup> Status LEDs से होने वाली Optical emanations को भी processed data के साथ correlate किया जा सकता है। ये results target- और setup-specific हैं; इनकी range या success rate को unrelated devices पर generalize न करें।<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
Controlled faults को side-channel observations के साथ combine करने से कुछ algorithms और implementations के लिए key search कम किया जा सकता है। Common lab platforms में ChipWhisperer की voltage/clock glitching features और ChipSHOUTER या PicoEMP जैसे dedicated EM fault-injection tools शामिल हैं। Earlier draft के “sub-1 ns” description का उपयोग specification के रूप में नहीं किया जाना चाहिए: ChipSHOUTER के published manual में इसके 1 mm tip के साथ typical inserted-pulse widths **15–80 ns** और 4 mm tip के साथ **24–480 ns** दी गई हैं (हालांकि trigger/pulse jitter को picoseconds में specify किया गया है)। आवश्यक timing resolution, probe placement और faulty outputs की संख्या target और fault model पर निर्भर करती है।<sup>[[1]](#references)[[10]](#references)</sup>

## Earlier Draft से Retained Unverified Research Leads

Earlier draft में यह भी दावा किया गया था: RTL-SDR का उपयोग करके **500 MHz–3 GHz** EM setup से **10 cm** से अधिक दूरी पर STM32 key recover करना; “Black Hat 2023” में एक DDR4 activity LED द्वारा एक मिनट से कम समय में AES round key reveal करना; और **GlitchKit-R5** नामक 2025 का open-source RISC-V glitching platform। इस audit के दौरान matching primary paper, conference material या project repository locate नहीं किया जा सका। ये exact details established results या tooling recommendations के रूप में नहीं, बल्कि search/reproduction leads के रूप में retained हैं।

---

## Typical Attack Workflow
1. Leakage channel और mount point identify करें (VCC pin, decoupling cap, near-field spot)।
2. Trigger insert करें (GPIO या pattern-based)।
3. चुने गए statistical test के लिए पर्याप्त traces collect करें और plaintext/ciphertext तथा अन्य metadata record करें।
4. Pre-process करें (alignment, mean removal, LP/HP filter, wavelet, PCA)।
5. Statistical या ML key recovery करें (CPA, MIA, DL-SCA)।
6. Outliers को validate करें और प्रक्रिया दोहराएँ।

---

## Defences & Hardening
* **Constant-time** implementations और memory-hard algorithms।
* **Masking/shuffling** – secrets को random shares में split करें; first-order resistance को TVLA द्वारा certify किया जाता है।
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields।
* **Fault detection** – redundant computation, threshold signatures।
* **Operational** – crypto kernels में DVFS/turbo disable करें, SMT isolate करें, multi-tenant clouds में co-location prohibit करें।

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; ऊपर बताए अनुसार Python API।<sup>[[1]](#references)</sup>
* **Riscure Inspector और fault-injection products** – commercial analysis और automated test tooling।
* **scaaml** – TensorFlow-based deep-learning SCA tooling और datasets।<sup>[[12]](#references)</sup>
* **pyecsca** – side channels के माध्यम से black-box ECC implementations को reverse-engineer करने के लिए open-source toolkit।<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Training in Transient Execution के साथ New Attack Surfaces को Expose करना](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Low-Bandwidth Acoustic Cryptanalysis के माध्यम से RSA Key Extraction](https://eprint.iacr.org/2013/857.pdf)
- [7] [Optical Emanations से Information Leakage](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifact documentation](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Keyboards पर एक Practical Deep Learning-Based Acoustic Side Channel Attack](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER user manual](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer documentation — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML documentation](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDR का उपयोग करके Low-Cost Electromagnetic Side-Channel Attacks करना](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decoding Intellectual Property: 3-D Printer पर Acoustic और Magnetic Side-Channel Attack](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Printers पर Acoustic Side-Channel Attacks](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Spying on Temperature using DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
