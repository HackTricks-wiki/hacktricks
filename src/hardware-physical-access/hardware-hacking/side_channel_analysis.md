# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks डिवाइस की भौतिक या micro-architectural "leakage" को देखकर secrets हासिल करते हैं। यह leakage आंतरिक स्थिति से *correlated* होती है, लेकिन डिवाइस के logical interface का हिस्सा *नहीं* होती। उदाहरणों में smart-card द्वारा खींची जाने वाली तात्कालिक current को मापने से लेकर network के ज़रिए CPU के power-management प्रभावों का दुरुपयोग करना शामिल है।

---

## मुख्य Leakage Channels

| Channel | सामान्य Target | उपकरण |
|---------|---------------|-----------------|
| बिजली की खपत | Smart cards, IoT MCUs, FPGAs | Oscilloscope के साथ shunt resistor या differential probe; CW503 probes/LNAs के लिए power supply है, खुद probe नहीं<sup>[[11]](#references)</sup> |
| Electromagnetic field (EM) | CPUs, RFID, AES accelerators | H-field/near-field probe के साथ low-noise amplifier और oscilloscope या RTL-SDR जैसा SDR receiver<sup>[[13]](#references)</sup> |
| Execution time / caches | Desktop और cloud CPUs | High-precision timers (`rdtsc`/`rdtscp`) या remote time-of-flight |
| Acoustic / mechanical | Keyboards, 3-D printers, printers, relays, और CPU voltage regulators | MEMS microphone या laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optical & thermal | Status LEDs, displays, DRAM, और thermally coupled devices | Photodiode, high-speed camera, या IR camera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU cryptography | Clock/voltage glitch, EMFI, या laser injection |

---

## Power Analysis

### Simple Power Analysis (SPA)
एक *single* trace देखें और उसके दिखने वाले features को branches, modular multiplication, या अलग-अलग instruction sequences जैसे operations से जोड़ें।<sup>[[1]](#references)</sup>

सटीक setup target पर निर्भर करता है। निम्न उदाहरण में scope और target को connect तथा configure करने के बाद, मौजूदा high-level ChipWhisperer capture API का उपयोग किया गया है:<sup>[[1]](#references)</sup>

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
कई traces प्राप्त करें, key byte `k` की परिकल्पना करें, Hamming-weight (HW) या Hamming-distance (HD) leakage model की गणना करें, और इसे प्रत्येक sample के साथ correlate करें। आवश्यक traces की संख्या target, noise, alignment, countermeasures और leakage model पर निर्भर करती है; इसकी कोई निश्चित सीमा नहीं है।
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA एक मानक बेसलाइन है। जब leakage nonlinear हो या traces ठीक से aligned न हों, तब Template attacks, mutual-information analysis और machine-learning approaches उपयोगी हो सकती हैं।

---

## Electromagnetic Analysis (EMA)
Near-field EM analysis, supply path में shunt डाले बिना data-dependent activity को देख सकता है। यह ज़रूरी नहीं कि power trace जैसा ही signal दिखाए: probe की position, orientation, bandwidth, front-end gain, trigger quality और दूरी—सभी मायने रखते हैं।

---

## Timing & Micro-architectural Attacks
आधुनिक CPUs shared resources के ज़रिए secrets leak करते हैं:
* **Hertzbleed (2022)** – Data-dependent dynamic voltage and frequency scaling एक remote timing channel बनाता है। मूल end-to-end key-recovery demonstration ने SIKE को target किया था; बाद के काम में अन्य primitives पर चर्चा की गई है।<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution, security boundaries के पार vector gather instructions द्वारा इस्तेमाल किए गए data को उजागर कर सकता है।<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Speculative vector-register state को गलत ढंग से संभालने से उसी physical core का data उजागर हो सकता है।<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – यह transient-execution attack, phantom execution को transient execution में training के साथ जोड़कर attacker-controlled misprediction gadgets बनाता है।<sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
एक नियंत्रित प्रयोग में, laptop के शोर से RSA keys recover करने के लिए acoustic leakage का उपयोग किया गया था; इसमें पास के mobile phone के microphone का उपयोग भी शामिल था।<sup>[[6]](#references)</sup> 2023 के एक अलग keyboard अध्ययन में, पास के phone से की गई recordings पर train करने पर keystrokes को 95% accuracy से और Zoom audio पर train करने पर 93% accuracy से classify किया गया। ये आँकड़े उस paper के trained-device experiment के हैं, किसी भी keyboard या victim के लिए नहीं।<sup>[[9]](#references)</sup> Status LEDs से निकलने वाली optical emanations को भी processed data के साथ correlate किया जा सकता है। ये नतीजे target और setup पर निर्भर हैं; इनकी range या success rate को असंबंधित devices पर लागू न मानें।<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
Controlled faults को side-channel observations के साथ जोड़ने से कुछ algorithms और implementations के लिए key search कम की जा सकती है। आम lab platforms में ChipWhisperer की voltage/clock glitching सुविधाएँ और ChipSHOUTER या PicoEMP जैसे dedicated EM fault-injection tools शामिल हैं। पहले के draft में दिया गया “sub-1 ns” विवरण specification के तौर पर इस्तेमाल नहीं किया जाना चाहिए: ChipSHOUTER के प्रकाशित manual में उसके 1 mm tip के साथ डाली गई pulse width आम तौर पर **15–80 ns** और 4 mm tip के साथ **24–480 ns** बताई गई है (हालाँकि trigger/pulse jitter को picoseconds में निर्दिष्ट किया गया है)। आवश्यक timing resolution, probe placement और faulty outputs की संख्या target और fault model पर निर्भर करती है।<sup>[[1]](#references)[[10]](#references)</sup>

## पहले के Draft से रखे गए अप्रमाणित Research Leads

पहले के draft में ये दावे भी थे: RTL-SDR का उपयोग करके **500 MHz–3 GHz** EM setup से **10 cm** से अधिक दूरी पर STM32 key recover करना; “Black Hat 2023” में DDR4 activity LED से एक मिनट से कम समय में AES round key उजागर करना; और 2025 का **GlitchKit-R5** नामक open-source RISC-V glitching platform। इस audit के दौरान इनसे मेल खाता कोई primary paper, conference material या project repository नहीं मिला। इन सटीक विवरणों को स्थापित नतीजों या tooling recommendations के रूप में नहीं, बल्कि खोज/reproduction leads के रूप में रखा गया है।

---

## Typical Attack Workflow
1. Leakage channel और mount point पहचानें (VCC pin, decoupling cap, near-field spot)।
2. Trigger डालें (GPIO या pattern-based)।
3. चुने गए statistical test के लिए पर्याप्त traces इकट्ठा करें और plaintext/ciphertext तथा अन्य metadata दर्ज करें।
4. Pre-process करें (alignment, mean removal, LP/HP filter, wavelet, PCA)।
5. Statistical या ML key recovery करें (CPA, MIA, DL-SCA)।
6. Outliers की जाँच करें और प्रक्रिया दोहराएँ।

---

## Defences & Hardening
* **Constant-time** implementations और memory-hard algorithms।
* **Masking/shuffling** – secrets को random shares में बाँटें; first-order resistance को TVLA से certify किया जाता है।
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields।
* **Fault detection** – redundant computation, threshold signatures।
* **Operational** – crypto kernels में DVFS/turbo बंद करें, SMT को isolate करें और multi-tenant clouds में co-location पर रोक लगाएँ।

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; ऊपर दिया गया Python API।<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – commercial analysis और automated test tooling।
* **scaaml** – TensorFlow-आधारित deep-learning SCA tooling और datasets।<sup>[[12]](#references)</sup>
* **pyecsca** – side channels के ज़रिए black-box ECC implementations की reverse-engineering के लिए open-source toolkit।<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer दस्तावेज़](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Speculative Data Gathering का दोहन](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Transient Execution में Training से नए Attack Surfaces उजागर करना](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Low-Bandwidth Acoustic Cryptanalysis के ज़रिए RSA Key Extraction](https://eprint.iacr.org/2013/857.pdf)
- [7] [Optical Emanations से Information Leakage](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifact documentation](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Keyboards पर Practical Deep Learning-Based Acoustic Side Channel Attack](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER user manual](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer documentation — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML documentation](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDR का उपयोग करके कम लागत वाले electromagnetic side-channel attacks करना](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Intellectual Property को Decode करना: 3-D Printer पर Acoustic और Magnetic Side-Channel Attack](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Printers पर Acoustic Side-Channel Attacks](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAM का उपयोग करके Temperature पर जासूसी](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
