# Attacchi di Side Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Gli attacchi side-channel recuperano segreti osservando il "leakage" fisico o micro-architetturale che è *correlato* allo stato interno, ma non fa parte dell'interfaccia logica del dispositivo. Gli esempi spaziano dalla misurazione della corrente istantanea assorbita da una smart-card allo sfruttamento degli effetti della gestione energetica della CPU attraverso una rete.

---

## Principali canali di leakage

| Canale | Target tipico | Strumentazione |
|---------|---------------|-----------------|
| Consumo energetico | Smart-card, MCU IoT, FPGA | Oscilloscopio + shunt resistor/sonda HS (ad es. CW503)
| Campo elettromagnetico (EM) | CPU, RFID, acceleratori AES | Sonda H-field + LNA, ChipWhisperer/RTL-SDR
| Tempo di esecuzione / cache | CPU desktop e cloud | Timer ad alta precisione (rdtsc/rdtscp), time-of-flight remoto
| Acustico / meccanico | Tastiere, stampanti 3D, relè | Microfono MEMS, vibrometro laser
| Ottico e termico | LED, stampanti laser, DRAM | Fotodiodo / fotocamera ad alta velocità, termocamera IR
| Indotto da fault | Crittografia ASIC/MCU | Clock/voltage glitch, EMFI, iniezione laser

---

## Power Analysis

### Simple Power Analysis (SPA)
Osserva una *singola* traccia e associa direttamente picchi e avvallamenti alle operazioni (ad es. le S-box di DES).
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
Acquisisci *N > 1 000* tracce, formula un'ipotesi sul byte della chiave `k`, calcola il modello HW/HD e correla con il leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA resta lo state-of-the-art, ma le varianti di machine learning (MLA, deep-learning SCA) ora dominano competizioni come ASCAD-v2 (2023).

---

## Analisi elettromagnetica (EMA)
Le sonde EM near-field (500 MHz–3 GHz) fanno trapelare informazioni identiche a quelle ottenute tramite power analysis *senza* inserire shunt. Una ricerca del 2024 ha dimostrato il recupero della chiave a **>10 cm** da un STM32 usando la spectrum correlation e front-end RTL-SDR a basso costo.

---

## Timing & Attacchi micro-architetturali
Le CPU moderne fanno trapelare segreti attraverso risorse condivise:
* **Hertzbleed (2022)** – il frequency scaling DVFS è correlato all'Hamming weight, consentendo l'estrazione *remota* di chiavi EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution per leggere dati AVX-gather tra thread SMT.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – la speculative vector mis-prediction fa trapelare registri tra domini.

---

## Attacchi acustici e ottici
* Nel 2024, "​iLeakKeys" ha mostrato un'accuratezza del 95% nel recupero dei tasti premuti su laptop da un **microfono di smartphone tramite Zoom**, usando un classificatore CNN.
* Fotodiodi ad alta velocità catturano l'attività del LED DDR4 e ricostruiscono le chiavi dei round AES in meno di 1 minuto (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
La combinazione di fault e side-channel leakage riduce la ricerca della chiave (ad esempio, 1-trace AES DFA). Strumenti recenti dal prezzo accessibile agli hobbisti:
* **ChipSHOUTER & PicoEMP** – glitching con impulsi elettromagnetici inferiori a 1 ns.
* **GlitchKit-R5 (2025)** – piattaforma open-source per clock/voltage glitching con supporto ai SoC RISC-V.

---

## Workflow tipico di un attacco
1. Identificare il canale di leakage e il punto di misura (pin VCC, condensatore di disaccoppiamento, punto near-field).
2. Inserire un trigger (GPIO o basato su pattern).
3. Raccogliere >1 k tracce con sampling e filtri appropriati.
4. Pre-processare (allineamento, rimozione della media, filtro LP/HP, wavelet, PCA).
5. Recuperare la chiave tramite analisi statistica o ML (CPA, MIA, DL-SCA).
6. Validare e iterare sugli outlier.

---

## Difese e hardening
* Implementazioni **constant-time** e algoritmi memory-hard.
* **Masking/shuffling** – suddividere i segreti in share casuali; resistenza di primo ordine certificata da TVLA.
* **Hiding** – regolatori di tensione on-chip, clock randomizzato, logica dual-rail, schermature EM.
* **Fault detection** – calcolo ridondante, threshold signatures.
* **Operativo** – disabilitare DVFS/turbo nei kernel crittografici, isolare SMT, vietare la co-location nei cloud multi-tenant.

---

## Tool e framework
* **ChipWhisperer-Husky** (2024) – oscilloscopio da 500 MS/s + trigger Cortex-M; API Python come sopra.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commerciale, supporta la valutazione automatizzata del leakage (TVLA-2.0).
* **scaaml** – libreria di deep-learning SCA basata su TensorFlow (v1.2 – 2025).
* **pyecsca** – framework SCA open-source per ECC di ANSSI.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
