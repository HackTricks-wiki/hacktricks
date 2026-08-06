# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Gli attacchi side-channel recuperano segreti osservando la "leakage" fisica o micro-architetturale che è *correlata* allo stato interno, ma *non* fa parte dell'interfaccia logica del dispositivo. Gli esempi spaziano dalla misurazione della corrente istantanea assorbita da una smart-card allo sfruttamento degli effetti di power-management della CPU tramite rete.

---

## Principali canali di leakage

| Canale | Target tipico | Strumentazione |
|---------|---------------|-----------------|
| Consumo energetico | Smart-card, MCU IoT, FPGA | Oscilloscopio + resistore shunt/sonda HS (ad es. CW503)
| Campo elettromagnetico (EM) | CPU, RFID, acceleratori AES | Sonda H-field + LNA, ChipWhisperer/RTL-SDR
| Tempo di esecuzione / cache | CPU desktop e cloud | Timer ad alta precisione (rdtsc/rdtscp), time-of-flight remoto
| Acustico / meccanico | Tastiere, stampanti 3D, relè | Microfono MEMS, vibrometro laser
| Ottico e termico | LED, stampanti laser, DRAM | Fotodiodo / telecamera ad alta velocità, telecamera IR
| Indotto da fault | Crittografia ASIC/MCU | Clock/voltage glitch, EMFI, iniezione laser

---

## Power Analysis

### Simple Power Analysis (SPA)
Osserva una *singola* traccia e associa direttamente picchi e avvallamenti alle operazioni (ad es. le S-box DES).<sup>[[1]](#references)</sup>
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
Acquisisci *N > 1 000* tracce, ipotizza il key byte `k`, calcola il modello HW/HD e correla con la leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA rimane all'avanguardia, ma le varianti basate sul machine learning (MLA, deep-learning SCA) dominano ormai competizioni come ASCAD-v2 (2023).

---

## Analisi elettromagnetica (EMA)
Le sonde EM near-field (500 MHz–3 GHz) fanno leak di informazioni identiche a quelle dell'analisi dei consumi *senza* inserire shunt. Una ricerca del 2024 ha dimostrato il key recovery a **oltre 10 cm** da uno STM32 usando la spectrum correlation e front-end RTL-SDR a basso costo.

---

## Attacchi temporali e micro-architetturali
Le CPU moderne fanno leak di segreti attraverso risorse condivise:
* **Hertzbleed (2022)** – il frequency scaling DVFS è correlato all'Hamming weight, consentendo l'*extraction* remota di chiavi EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution per leggere dati AVX-gather tra thread SMT.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – la speculative vector mis-prediction fa leak dei registri tra domini.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Attacchi acustici e ottici
* Nel 2024, "​iLeakKeys" ha mostrato un'accuratezza del 95% nel recuperare le battute da tastiera di un laptop tramite un **microfono di smartphone su Zoom**, usando un classificatore CNN.
* Fotodiodi ad alta velocità catturano l'attività del LED DDR4 e ricostruiscono le chiavi dei round AES in meno di 1 minuto (BlackHat 2023).

---

## Fault Injection e Differential Fault Analysis (DFA)
La combinazione di fault e side-channel leakage abbrevia la ricerca delle chiavi (ad esempio, 1-trace AES DFA). Tool recenti dal costo accessibile agli hobbisti:
* **ChipSHOUTER & PicoEMP** – electromagnetic pulse glitching sotto 1 ns.
* **GlitchKit-R5 (2025)** – piattaforma open-source per clock/voltage glitching compatibile con SoC RISC-V.

---

## Workflow tipico di un attacco
1. Identificare il canale di leakage e il punto di accesso (pin VCC, condensatore di disaccoppiamento, punto near-field).
2. Inserire il trigger (GPIO o basato su pattern).
3. Raccogliere >1 k trace con sampling/filtering appropriati.
4. Pre-processare (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Key recovery statistico o basato su ML (CPA, MIA, DL-SCA).
6. Convalidare e iterare sugli outlier.

---

## Difese e hardening
* Implementazioni **constant-time** e algoritmi memory-hard.
* **Masking/shuffling** – suddividere i segreti in share casuali; resistenza di primo ordine certificata da TVLA.
* **Hiding** – voltage regulator on-chip, clock randomizzato, logica dual-rail, schermature EM.
* **Fault detection** – calcolo ridondante, threshold signatures.
* **Operative** – disabilitare DVFS/turbo nei kernel crittografici, isolare SMT, vietare la co-location nei cloud multi-tenant.

---

## Tool e framework
* **ChipWhisperer-Husky** (2024) – oscilloscopio a 500 MS/s + trigger Cortex-M; API Python come sopra.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commerciali, supportano la valutazione automatizzata del leakage (TVLA-2.0).
* **scaaml** – libreria di deep-learning SCA basata su TensorFlow (v1.2 – 2025).
* **pyecsca** – framework open-source ANSSI per ECC SCA.

---

## Riferimenti

- [1] [Documentazione di ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Paper sull'attacco Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: sfruttare la raccolta speculativa dei dati](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: esporre nuove superfici di attacco con il training nella transient execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
