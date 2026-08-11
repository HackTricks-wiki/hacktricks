# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks hurejesha siri kwa kuchunguza "leakage" ya kimwili au ya micro-architectural ambayo *inahusiana* na hali ya ndani lakini *si* sehemu ya interface ya kimantiki ya kifaa. Mifano huanzia kupima current ya papo kwa papo inayotumiwa na smart-card hadi kutumia athari za CPU power-management kupitia mtandao.

---

## Main Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Matumizi ya nguvu | Smart cards, IoT MCUs, FPGAs | Oscilloscope pamoja na shunt resistor au differential probe; CW503 ni power supply ya probes/LNAs, si probe yenyewe<sup>[[11]](#references)</sup> |
| Uga wa elektromagneti (EM) | CPUs, RFID, AES accelerators | H-field/near-field probe pamoja na low-noise amplifier na oscilloscope au SDR receiver kama RTL-SDR<sup>[[13]](#references)</sup> |
| Muda wa utekelezaji / caches | Desktop na cloud CPUs | High-precision timers (`rdtsc`/`rdtscp`) au remote time-of-flight |
| Acoustic / mechanical | Keyboards, 3-D printers, printers, relays, na CPU voltage regulators | MEMS microphone au laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optical & thermal | Status LEDs, displays, DRAM, na vifaa vilivyounganishwa kwa joto | Photodiode, high-speed camera, au IR camera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU cryptography | Clock/voltage glitch, EMFI, au laser injection |

---

## Power Analysis

### Simple Power Analysis (SPA)
Chunguza *trace* moja na uhusishe vipengele vinavyoonekana na operations kama branches, modular multiplication, au mfuatano tofauti wa instructions.<sup>[[1]](#references)</sup>

Usanidi halisi hutegemea target. Ifuatayo hutumia current high-level ChipWhisperer capture API baada ya scope na target kuunganishwa na kusanidiwa:<sup>[[1]](#references)</sup>
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
Kusanya traces nyingi, unda dhana ya key byte `k`, kokotoa leakage model ya Hamming-weight (HW) au Hamming-distance (HD), kisha ulinganishe na kila sample. Idadi ya traces inayohitajika huamuliwa na target, noise, alignment, countermeasures na leakage model; si threshold isiyobadilika.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ni baseline ya kawaida. Template attacks, mutual-information analysis, na machine-learning approaches zinaweza kuwa muhimu wakati leakage si ya mstari au traces hazija-aligniwa vizuri.

---

## Uchambuzi wa Electromagnetic (EMA)
Near-field EM analysis inaweza kuchunguza shughuli zinazotegemea data bila kuingiza shunt kwenye njia ya supply. Si lazima ifichue signal ileile inayopatikana kwenye power trace: mahali pa probe, mwelekeo, bandwidth, front-end gain, ubora wa trigger, na umbali vyote ni muhimu.

---

## Timing & Micro-architectural Attacks
CPU za kisasa hufichua secrets kupitia shared resources:
* **Hertzbleed (2022)** – Data-dependent dynamic voltage and frequency scaling huunda remote timing channel. Demonstration ya awali ya end-to-end key-recovery ililenga SIKE; utafiti wa baadaye unajadili primitives nyingine.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution inaweza kufichua data inayotumiwa na vector gather instructions katika mipaka ya usalama.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Ushughulikiaji usio sahihi wa speculative vector-register state unaweza kufichua data kutoka kwenye physical core ileile.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Transient-execution attack huchanganya phantom execution na training katika transient execution ili kuunda misprediction gadgets zinazodhibitiwa na attacker.<sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
Acoustic leakage imetumiwa kurejesha RSA keys kutoka kwenye noise ya laptop katika controlled experiment, ikiwemo kwa kutumia microphone ya mobile phone iliyo karibu.<sup>[[6]](#references)</sup> Utafiti mwingine wa keyboard wa 2023 uliainisha keystrokes kwa usahihi wa 95% ulipofunzwa kwa recordings kutoka kwenye simu iliyo karibu, na 93% ulipofunzwa kwa Zoom audio; takwimu hizi zinaelezea trained-device experiment ya paper hiyo, si keyboard au victim yoyote kwa ujumla.<sup>[[9]](#references)</sup> Optical emanations kutoka kwenye status LEDs pia zinaweza kuhusishwa na data iliyochakatwa. Matokeo haya yanategemea target na setup; usijumlishe range au success rate yake kwa devices zisizohusiana.<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
Kuchanganya controlled faults na side-channel observations kunaweza kupunguza key search kwa baadhi ya algorithms na implementations. Lab platforms zinazotumika mara nyingi zinajumuisha voltage/clock glitching features za ChipWhisperer na dedicated EM fault-injection tools kama ChipSHOUTER au PicoEMP. Maelezo ya awali ya draft kuhusu “sub-1 ns” hayapaswi kutumiwa kama specification: manual iliyochapishwa ya ChipSHOUTER inaorodhesha typical inserted-pulse widths za **15–80 ns** kwa 1 mm tip yake na **24–480 ns** kwa 4 mm tip yake (ingawa trigger/pulse jitter imeainishwa kwa picoseconds). Timing resolution inayohitajika, probe placement, na idadi ya faulty outputs hutegemea target na fault model.<sup>[[1]](#references)[[10]](#references)</sup>

## Unverified Research Leads Retained from the Earlier Draft

Draft ya awali pia ilidai: EM setup ya **500 MHz–3 GHz** iliyorejesha STM32 key kutoka zaidi ya **10 cm** kwa kutumia RTL-SDR; DDR4 activity LED iliyofichua AES round key kwa chini ya dakika moja katika “Black Hat 2023”; na open-source RISC-V glitching platform ya 2025 iliyoitwa **GlitchKit-R5**. Hakuna matching primary paper, conference material, au project repository iliyoweza kupatikana wakati wa audit hii. Maelezo haya kamili yamehifadhiwa kama search/reproduction leads, si kama established results au tooling recommendations.

---

## Typical Attack Workflow
1. Tambua leakage channel na mount point (VCC pin, decoupling cap, near-field spot).
2. Weka trigger (GPIO au pattern-based).
3. Kusanya traces za kutosha kwa statistical test iliyochaguliwa, ukirekodi plaintext/ciphertext na metadata nyingine.
4. Fanya pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical au ML key recovery (CPA, MIA, DL-SCA).
6. Validate na iterate kwenye outliers.

---

## Defences & Hardening
* **Constant-time** implementations na memory-hard algorithms.
* **Masking/shuffling** – gawanya secrets kuwa random shares; first-order resistance iliyothibitishwa na TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – zima DVFS/turbo katika crypto kernels, isolate SMT, kataza co-location katika multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; Python API kama ilivyo hapo juu.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – commercial analysis na automated test tooling.
* **scaaml** – TensorFlow-based deep-learning SCA tooling na datasets.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source toolkit ya reverse-engineering black-box ECC implementations kupitia side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Nyaraka za ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Paper ya Hertzbleed Attack](https://www.hertzbleed.com/)
- [3] [Downfall: Kutumia Vibaya Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Kufichua Attack Surfaces Mpya kwa Training katika Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Utoaji wa RSA Key kupitia Low-Bandwidth Acoustic Cryptanalysis](https://eprint.iacr.org/2013/857.pdf)
- [7] [Information Leakage kutoka Optical Emanations](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Nyaraka za pyecsca artifact](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Practical Deep Learning-Based Acoustic Side Channel Attack kwenye Keyboards](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Mwongozo wa mtumiaji wa ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Nyaraka za ChipWhisperer — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Nyaraka za Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Kufanya low-cost electromagnetic side-channel attacks kwa kutumia RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Kuddecode Intellectual Property: Acoustic and Magnetic Side-Channel Attack kwenye 3-D Printer](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Acoustic Side-Channel Attacks kwenye Printers](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Kuchunguza Temperature kwa kutumia DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
