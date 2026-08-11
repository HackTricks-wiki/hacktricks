# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel napadi otkrivaju tajne posmatranjem fizičkog ili mikroarhitektonskog „curenja“ koje je *u korelaciji* sa internim stanjem, ali *nije* deo logičkog interfejsa uređaja. Primeri obuhvataju merenje trenutne struje koju povlači smart-card, kao i zloupotrebu efekata upravljanja napajanjem CPU-a preko mreže.

---

## Glavni kanali curenja

| Kanal | Tipična meta | Instrumentacija |
|---------|---------------|-----------------|
| Potrošnja energije | Smart cards, IoT MCUs, FPGAs | Osciloskop sa šant otpornikom ili diferencijalnom sondom; CW503 je napajanje za sonde/LNA uređaje, a ne sama sonda<sup>[[11]](#references)</sup> |
| Elektromagnetno polje (EM) | CPUs, RFID, AES accelerators | H-field/near-field sonda sa low-noise amplifier uređajem i osciloskopom ili SDR prijemnikom kao što je RTL-SDR<sup>[[13]](#references)</sup> |
| Vreme izvršavanja / keš memorije | Desktop i cloud CPUs | Precizni tajmeri (`rdtsc`/`rdtscp`) ili daljinsko merenje vremena prenosa |
| Akustičko / mehaničko | Tastature, 3-D printers, štampači, releji i regulatori napona CPU-a | MEMS mikrofon ili laserski vibrometar<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optičko i termalno | Statusne LED diode, displeji, DRAM i termički povezani uređaji | Fotodioda, high-speed kamera ili IR kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU kriptografija | Glitchovanje takta/napona, EMFI ili lasersko ubrizgavanje |

---

## Power Analysis

### Simple Power Analysis (SPA)
Posmatrajte *jedan* trace i povežite vidljive karakteristike sa operacijama kao što su grananja, modularno množenje ili različite sekvence instrukcija.<sup>[[1]](#references)</sup>

Tačno podešavanje zavisi od mete. U nastavku se koristi aktuelni high-level ChipWhisperer capture API nakon povezivanja i konfigurisanja scope-a i target-a:<sup>[[1]](#references)</sup>
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
Prikupite više tragova, pretpostavite bajt ključa `k`, izračunajte model curenja Hamming-weight (HW) ili Hamming-distance (HD) i korelirajte ga sa svakim uzorkom. Potreban broj tragova zavisi od cilja, šuma, poravnanja, countermeasures i modela curenja; to nije fiksni prag.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA je standardna osnovna metoda. Template attacks, mutual-information analysis i machine-learning pristupi mogu biti korisni kada je leakage nelinearan ili su trace-ovi loše poravnati.

---

## Elektromagnetna analiza (EMA)
Near-field EM analiza može posmatrati aktivnost zavisnu od podataka bez umetanja shunt-a u napojni put. Ona ne mora nužno da izlaže isti signal kao power trace: položaj sonde, orijentacija, bandwidth, gain front-end-a, kvalitet trigger-a i udaljenost — sve je važno.

---

## Timing i mikroarhitektonski napadi
Moderni CPU-ovi otkrivaju secrets kroz deljene resurse:
* **Hertzbleed (2022)** – Dinamičko skaliranje napona i frekvencije zavisno od podataka stvara remote timing channel. Originalna end-to-end demonstracija oporavka ključa ciljala je SIKE; naknadni radovi razmatraju druge primitive.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution može izložiti podatke koje koriste vector gather instrukcije preko security granica.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Neispravno rukovanje stanjem speculative vector-register-a može otkriti podatke sa istog fizičkog jezgra.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Transient-execution napad kombinuje phantom execution sa training-om u transient execution-u radi kreiranja attacker-controlled misprediction gadgets.<sup>[[5]](#references)</sup>

---

## Akustični i optički napadi
Acoustic leakage je korišćen za oporavak RSA ključeva iz buke laptopa u kontrolisanom eksperimentu, uključujući i upotrebu mikrofona obližnjeg mobilnog telefona.<sup>[[6]](#references)</sup> Odvojena studija tastatura iz 2023. klasifikovala je pritisnute tastere sa 95% preciznosti kada je trenirana na snimcima sa obližnjeg telefona i sa 93% kada je trenirana na Zoom audio-snimcima; ove brojke opisuju eksperiment sa treniranim uređajem iz tog rada, a ne proizvoljnu tastaturu ili victim uređaj.<sup>[[9]](#references)</sup> Optičke emanacije statusnih LED-ova takođe mogu biti korelisane sa obrađenim podacima. Ovi rezultati zavise od target-a i setup-a; njihov domet ili stopu uspeha ne treba generalizovati na nepovezane uređaje.<sup>[[7]](#references)</sup>

---

## Fault Injection i Differential Fault Analysis (DFA)
Kombinovanje kontrolisanih fault-ova sa side-channel posmatranjima može smanjiti pretragu ključa za neke algoritme i implementacije. Uobičajene laboratorijske platforme uključuju ChipWhisperer funkcije za voltage/clock glitching i namenski EM fault-injection alat kao što su ChipSHOUTER ili PicoEMP. Raniji nacrt navodio je opis „sub-1 ns“, koji ne treba koristiti kao specifikaciju: objavljeni ChipSHOUTER priručnik navodi tipične širine ubačenih pulseva od **15–80 ns** sa vrhom od 1 mm i **24–480 ns** sa vrhom od 4 mm (iako je trigger/pulse jitter specifikovan u pikosekundama). Potrebna vremenska rezolucija, položaj sonde i broj neispravnih izlaza zavise od target-a i modela fault-a.<sup>[[1]](#references)[[10]](#references)</sup>

## Nepotvrđeni istraživački pravci zadržani iz ranijeg nacrta

Raniji nacrt je takođe tvrdio: EM setup od **500 MHz–3 GHz** koji je pomoću RTL-SDR-a oporavio STM32 ključ sa udaljenosti veće od **10 cm**; LED za DDR4 aktivnost koja je otkrila round key za AES za manje od jednog minuta na događaju „Black Hat 2023“; i open-source RISC-V glitching platformu iz 2025. pod nazivom **GlitchKit-R5**. Tokom ove revizije nije pronađen odgovarajući primarni rad, konferencijski materijal ili project repository. Ovi konkretni detalji zadržani su kao pravci za pretragu/reprodukciju, a ne kao potvrđeni rezultati ili preporuke za tooling.

---

## Tipičan tok napada
1. Identifikovati leakage channel i mount point (VCC pin, decoupling cap, near-field spot).
2. Ubaciti trigger (GPIO ili zasnovan na pattern-u).
3. Prikupiti dovoljno trace-ova za izabrani statistički test, uz beleženje plaintext/ciphertext-a i drugih metadata.
4. Pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistički ili ML key recovery (CPA, MIA, DL-SCA).
6. Validirati rezultate i ponavljati postupak za outlier-e.

---

## Odbrane i hardening
* **Constant-time** implementacije i memory-hard algoritmi.
* **Masking/shuffling** – podeliti secrets na random shares; otpornost prvog reda sertifikovana pomoću TVLA.
* **Hiding** – on-chip voltage regulator-i, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – onemogućiti DVFS/turbo u crypto kernel-ima, izolovati SMT, zabraniti co-location u multi-tenant cloud-ovima.

---

## Alati i Frameworks
* **ChipWhisperer-Husky** (2024) – osciloskop od 500 MS/s + Cortex-M trigger; Python API kao iznad.<sup>[[1]](#references)</sup>
* **Riscure Inspector i fault-injection proizvodi** – komercijalni alati za analizu i automatizovano testiranje.
* **scaaml** – TensorFlow-based deep-learning SCA alati i dataset-ovi.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source toolkit za reverse-engineering black-box ECC implementacija kroz side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer dokumentacija](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Rad o Hertzbleed napadu](https://www.hertzbleed.com/)
- [3] [Downfall: Iskorišćavanje speculative data gathering-a](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Otkrivanje novih attack surface-a pomoću training-a u transient execution-u](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Ekstrakcija RSA ključa pomoću low-bandwidth acoustic cryptanalysis-a](https://eprint.iacr.org/2013/857.pdf)
- [7] [Curenje informacija iz optičkih emanacija](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifact dokumentacija](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Praktični deep learning-based acoustic side-channel napad na tastature](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER korisničko uputstvo](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer dokumentacija — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML dokumentacija](https://google.github.io/scaaml/)
- [13] [FOSDEM — Izvođenje low-cost electromagnetic side-channel napada pomoću RTL-SDR-a](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Dekodiranje intelektualne svojine: Acoustic and Magnetic Side-Channel Attack na 3-D printer](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Acoustic Side-Channel Attacks na štampače](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Špijuniranje temperature pomoću DRAM-a](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
