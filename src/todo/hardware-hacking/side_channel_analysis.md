# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks recover secrets by observing physical or micro-architectural "leakage" that is *correlated* with internal state but is *not* part of the logical interface of the device.  Examples range from measuring the instantaneous current drawn by a smart-card to abusing CPU power-management effects over a network.

---

## Main Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | Smart cards, IoT MCUs, FPGAs | Oscilloscope plus shunt resistor or differential probe; the CW503 is a power supply for probes/LNAs, not itself a probe<sup>[[11]](#references)</sup> |
| Electromagnetic field (EM) | CPUs, RFID, AES accelerators | H-field/near-field probe plus low-noise amplifier and oscilloscope or SDR receiver such as an RTL-SDR<sup>[[13]](#references)</sup> |
| Execution time / caches | Desktop and cloud CPUs | High-precision timers (`rdtsc`/`rdtscp`) or remote time-of-flight |
| Acoustic / mechanical | Keyboards, 3-D printers, printers, relays, and CPU voltage regulators | MEMS microphone or laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optical & thermal | Status LEDs, displays, DRAM, and thermally coupled devices | Photodiode, high-speed camera, or IR camera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU cryptography | Clock/voltage glitch, EMFI, or laser injection |

---

## Power Analysis

### Simple Power Analysis (SPA)
Observe a *single* trace and associate visible features with operations such as branches, modular multiplication, or different instruction sequences.<sup>[[1]](#references)</sup>

The exact setup is target-specific. The following uses the current high-level ChipWhisperer capture API after the scope and target have been connected and configured:<sup>[[1]](#references)</sup>

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
Acquire multiple traces, hypothesize a key byte `k`, compute a Hamming-weight (HW) or Hamming-distance (HD) leakage model, and correlate it with each sample. The required trace count is determined by the target, noise, alignment, countermeasures, and leakage model; it is not a fixed threshold.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA is a standard baseline. Template attacks, mutual-information analysis, and machine-learning approaches can be useful when leakage is nonlinear or traces are poorly aligned.

---

## Electromagnetic Analysis (EMA)
Near-field EM analysis can observe data-dependent activity without inserting a shunt in the supply path. It does not necessarily expose the same signal as a power trace: probe position, orientation, bandwidth, front-end gain, trigger quality, and distance all matter.

---

## Timing & Micro-architectural Attacks
Modern CPUs leak secrets through shared resources:
* **Hertzbleed (2022)** – Data-dependent dynamic voltage and frequency scaling creates a remote timing channel. The original end-to-end key-recovery demonstration targeted SIKE; follow-up work discusses other primitives.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution can expose data used by vector gather instructions across security boundaries.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Incorrect handling of speculative vector-register state can disclose data from the same physical core.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – A transient-execution attack combines phantom execution with training in transient execution to create attacker-controlled misprediction gadgets.<sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
Acoustic leakage has been used to recover RSA keys from laptop noise in a controlled experiment, including with a nearby mobile phone microphone.<sup>[[6]](#references)</sup> A separate 2023 keyboard study classified keystrokes with 95% accuracy when trained on recordings from a nearby phone and 93% when trained on Zoom audio; these figures describe that paper's trained-device experiment, not an arbitrary keyboard or victim.<sup>[[9]](#references)</sup> Optical emanations from status LEDs can also be correlated with processed data. These results are target- and setup-specific; do not generalize their range or success rate to unrelated devices.<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
Combining controlled faults with side-channel observations can reduce the key search for some algorithms and implementations. Common lab platforms include ChipWhisperer's voltage/clock glitching features and dedicated EM fault-injection tools such as ChipSHOUTER or PicoEMP. The earlier draft's “sub-1 ns” description should not be used as a specification: ChipSHOUTER's published manual lists typical inserted-pulse widths of **15–80 ns** with its 1 mm tip and **24–480 ns** with its 4 mm tip (although trigger/pulse jitter is specified in picoseconds). The required timing resolution, probe placement, and number of faulty outputs depend on the target and fault model.<sup>[[1]](#references)[[10]](#references)</sup>

## Unverified Research Leads Retained from the Earlier Draft

The earlier draft also claimed: a **500 MHz–3 GHz** EM setup recovering an STM32 key from more than **10 cm** using an RTL-SDR; a DDR4 activity LED revealing an AES round key in under one minute at “Black Hat 2023”; and a 2025 open-source RISC-V glitching platform called **GlitchKit-R5**. No matching primary paper, conference material, or project repository could be located during this audit. These exact details are retained as search/reproduction leads, not as established results or tooling recommendations.

---

## Typical Attack Workflow
1. Identify leakage channel & mount point (VCC pin, decoupling cap, near-field spot).
2. Insert trigger (GPIO or pattern-based).  
3. Collect enough traces for the chosen statistical test, recording plaintext/ciphertext and other metadata.
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
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; Python API as above.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – commercial analysis and automated test tooling.
* **scaaml** – TensorFlow-based deep-learning SCA tooling and datasets.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source toolkit for reverse-engineering black-box ECC implementations through side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis](https://eprint.iacr.org/2013/857.pdf)
- [7] [Information Leakage from Optical Emanations](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifact documentation](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [A Practical Deep Learning-Based Acoustic Side Channel Attack on Keyboards](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER user manual](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer documentation — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML documentation](https://google.github.io/scaaml/)
- [13] [FOSDEM — Performing low-cost electromagnetic side-channel attacks using RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decoding Intellectual Property: Acoustic and Magnetic Side-Channel Attack on a 3-D Printer](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Acoustic Side-Channel Attacks on Printers](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Spying on Temperature using DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)

{{#include ../../banners/hacktricks-training.md}}
