# Side-Channel Analysis-aanvalle

{{#include ../../banners/hacktricks-training.md}}

Side-channel-aanvalle herwin geheime deur fisiese of mikro-argitektoniese "leakage" waar te neem wat *gekorreleer* is met interne toestand, maar *nie* deel is van die logiese koppelvlak van die toestel nie. Voorbeelde wissel van die meting van die oombliklike stroom wat deur ’n smart card getrek word tot die misbruik van CPU-kragbestuurseffekte oor ’n netwerk.

---

## Belangrikste Leakage-kanale

| Kanaal | Tipiese teiken | Instrumentasie |
|---------|---------------|-----------------|
| Kragverbruik | Smart cards, IoT-MCUs, FPGAs | Ossilloskoop plus shuntweerstand of differensiële probe; die CW503 is ’n kragtoevoer vir probes/LNAs, nie self ’n probe nie<sup>[[11]](#references)</sup> |
| Elektromagnetiese veld (EM) | CPUs, RFID, AES-accelerators | H-veld-/near-field-probe plus lae-geraas-versterker en ossilloskoop of SDR-ontvanger soos ’n RTL-SDR<sup>[[13]](#references)</sup> |
| Uitvoeringstyd / caches | Desktop- en cloud-CPUs | Hoëpresisie-tellers (`rdtsc`/`rdtscp`) of afgeleë time-of-flight |
| Akoesties / meganies | Keyboards, 3-D-printers, printers, relays en CPU-spanningsreguleerders | MEMS-mikrofoon of laser-vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Opties & termies | Status-LED’s, displays, DRAM en termies gekoppelde toestelle | Fotodiode, hoëspoedkamera of IR-kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU-kriptografie | Klok-/spanning-glitch, EMFI of laser-inspuiting |

---

## Krag-analise

### Simple Power Analysis (SPA)
Neem ’n *enkele* trace waar en koppel sigbare kenmerke aan bewerkings soos vertakkings, modulêre vermenigvuldiging of verskillende instruksievolgordes.<sup>[[1]](#references)</sup>

Die presiese opstelling is teikenspesifiek. Die volgende gebruik die huidige hoëvlak ChipWhisperer-capture-API nadat die scope en target verbind en gekonfigureer is:<sup>[[1]](#references)</sup>
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
Verkry veelvuldige traces, maak ’n hipotese oor ’n key byte `k`, bereken ’n Hamming-weight (HW)- of Hamming-distance (HD)-leakage model, en korreleer dit met elke sample. Die vereiste aantal traces word deur die teiken, geraas, belyning, teenmaatreëls en leakage model bepaal; dit is nie ’n vaste drempel nie.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA is 'n standaard-baseline. Template attacks, mutual-information analysis, en machine-learning-benaderings kan nuttig wees wanneer leakage nie-lineêr is of traces swak belyn is.

---

## Elektromagnetiese Analise (EMA)
Near-field EM analysis kan data-afhanklike aktiwiteit waarneem sonder om 'n shunt in die toevoerpad in te voeg. Dit stel nie noodwendig dieselfde sein as 'n power trace bloot nie: probe-posisie, oriëntasie, bandwydte, front-end gain, trigger-gehalte en afstand is alles belangrik.

---

## Timing- & Mikro-argitektoniese Aanvalle
Moderne CPUs lek geheime deur gedeelde hulpbronne:
* **Hertzbleed (2022)** – Data-afhanklike dynamic voltage and frequency scaling skep 'n remote timing channel. Die oorspronklike end-to-end key-recovery-demonstrasie het SIKE geteiken; opvolgwerk bespreek ander primitives.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution kan data blootstel wat deur vector gather-instruksies oor security boundaries heen gebruik word.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Verkeerde hantering van speculative vector-register state kan data vanaf dieselfde physical core bekend maak.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – 'n Transient-execution-aanval kombineer phantom execution met training in transient execution om attacker-controlled misprediction gadgets te skep.<sup>[[5]](#references)</sup>

---

## Akoestiese & Optiese Aanvalle
Acoustic leakage is gebruik om RSA keys uit skootrekenaargeruis in 'n beheerde eksperiment te herwin, insluitend met 'n nabygeleë selfoonmikrofoon.<sup>[[6]](#references)</sup> 'n Afsonderlike keyboard-studie uit 2023 het keystrokes met 95% akkuraatheid geklassifiseer wanneer dit op opnames vanaf 'n nabygeleë foon opgelei is, en 93% wanneer dit op Zoom-audio opgelei is; hierdie syfers beskryf daardie paper se trained-device-eksperiment, nie 'n arbitrêre keyboard of victim nie.<sup>[[9]](#references)</sup> Optical emanations van status-LEDs kan ook met verwerkte data gekorreleer word. Hierdie resultate is target- en setup-spesifiek; moenie hul reeks of success rate na onverwante devices veralgemeen nie.<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
Deur controlled faults met side-channel-waarnemings te kombineer, kan die key search vir sommige algorithms en implementasies verminder word. Algemene lab-platforms sluit ChipWhisperer se voltage/clock glitching-features en toegewyde EM fault-injection-tools soos ChipSHOUTER of PicoEMP in. Die vroeëre draft se “sub-1 ns”-beskrywing moet nie as 'n spesifikasie gebruik word nie: ChipSHOUTER se gepubliseerde manual lys tipiese inserted-pulse widths van **15–80 ns** met sy 1 mm-tip en **24–480 ns** met sy 4 mm-tip (hoewel trigger/pulse jitter in picoseconds gespesifiseer word). Die vereiste timing resolution, probe placement en aantal faulty outputs hang van die target en fault model af.<sup>[[1]](#references)[[10]](#references)</sup>

## Ongeverifieerde Navorsingsleidrade wat uit die Vroeëre Draft Behou is

Die vroeëre draft het ook beweer: 'n **500 MHz–3 GHz** EM-setup wat 'n STM32-key vanaf meer as **10 cm** met behulp van 'n RTL-SDR herwin; 'n DDR4 activity LED wat 'n AES round key binne minder as een minuut by “Black Hat 2023” onthul; en 'n 2025 open-source RISC-V glitching-platform genaamd **GlitchKit-R5**. Geen ooreenstemmende primary paper, conference material of project repository kon tydens hierdie audit opgespoor word nie. Hierdie presiese besonderhede word as search/reproduction leads behou, nie as gevestigde resultate of tooling recommendations nie.

---

## Tipiese Aanvalswerksvloei
1. Identifiseer leakage channel & mount point (VCC pin, decoupling cap, near-field spot).
2. Voeg trigger in (GPIO of pattern-based).
3. Versamel genoeg traces vir die gekose statistical test, en teken plaintext/ciphertext en ander metadata aan.
4. Pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical of ML key recovery (CPA, MIA, DL-SCA).
6. Valideer en herhaal vir outliers.

---

## Defences & Hardening
* **Constant-time**-implementasies & memory-hard algorithms.
* **Masking/shuffling** – verdeel secrets in random shares; first-order resistance gesertifiseer deur TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – disable DVFS/turbo in crypto kernels, isoleer SMT, verbied co-location in multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; Python API soos hierbo.<sup>[[1]](#references)</sup>
* **Riscure Inspector en fault-injection products** – kommersiële analysis- en automated test tooling.
* **scaaml** – TensorFlow-gebaseerde deep-learning SCA tooling en datasets.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source toolkit vir reverse-engineering van black-box ECC-implementasies deur side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer-dokumentasie](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed-aanvalspaper](https://www.hertzbleed.com/)
- [3] [Downfall: Ontginning van Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Blootstelling van nuwe aanvaloppervlakke met Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis](https://eprint.iacr.org/2013/857.pdf)
- [7] [Information Leakage from Optical Emanations](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca-artifactdokumentasie](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [A Practical Deep Learning-Based Acoustic Side Channel Attack on Keyboards](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER-gebruikershandleiding](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer-dokumentasie — CW503-probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML-dokumentasie](https://google.github.io/scaaml/)
- [13] [FOSDEM — Performing low-cost electromagnetic side-channel attacks using RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decoding Intellectual Property: Acoustic and Magnetic Side-Channel Attack on a 3-D Printer](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Acoustic Side-Channel Attacks on Printers](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Spying on Temperature using DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
