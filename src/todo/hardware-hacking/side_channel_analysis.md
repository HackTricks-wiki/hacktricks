# Attacchi di Analisi dei Canali Laterali

{{#include ../../banners/hacktricks-training.md}}

Gli attacchi di canale laterale recuperano segreti osservando la "leak" fisica o micro-architetturale che è *correlata* con lo stato interno ma *non* fa parte dell'interfaccia logica del dispositivo. Gli esempi variano dalla misurazione della corrente istantanea assorbita da una smart-card all'abuso degli effetti di gestione della potenza della CPU su una rete.

---

## Principali Canali di Leak

| Canale | Obiettivo Tipico | Strumentazione |
|--------|------------------|----------------|
| Consumo di potenza | Smart-card, MCU IoT, FPGA | Oscilloscopio + resistore shunt/probe HS (es. CW503) |
| Campo elettromagnetico (EM) | CPU, RFID, acceleratori AES | Probe H-field + LNA, ChipWhisperer/RTL-SDR |
| Tempo di esecuzione / cache | CPU desktop e cloud | Timer ad alta precisione (rdtsc/rdtscp), tempo di volo remoto |
| Acustico / meccanico | Tastiere, stampanti 3-D, relè | Microfono MEMS, vibrometro laser |
| Ottico e termico | LED, stampanti laser, DRAM | Fotodiodo / telecamera ad alta velocità, telecamera IR |
| Indotto da guasti | ASIC/MCU crittografici | Glitch di clock/voltaggio, EMFI, iniezione laser |

---

## Analisi della Potenza

### Analisi della Potenza Semplice (SPA)
Osserva un *singolo* tracciato e associa direttamente picchi/valle a operazioni (es. S-box DES).
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
### Analisi Differenziale/Corrrelazione del Potere (DPA/CPA)
Acquisire *N > 1 000* tracce, ipotizzare il byte della chiave `k`, calcolare il modello HW/HD e correlare con la leak.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA rimane all'avanguardia, ma le varianti di machine learning (MLA, deep-learning SCA) ora dominano competizioni come ASCAD-v2 (2023).

---

## Analisi Elettromagnetica (EMA)
Le sonde EM a campo vicino (500 MHz–3 GHz) rilasciano informazioni identiche all'analisi della potenza *senza* inserire shunt. La ricerca del 2024 ha dimostrato il recupero della chiave a **>10 cm** da un STM32 utilizzando la correlazione spettrale e front-end RTL-SDR a basso costo.

---

## Attacchi di Timing e Micro-architetturali
Le CPU moderne rilasciano segreti attraverso risorse condivise:
* **Hertzbleed (2022)** – la scalabilità della frequenza DVFS si correla con il peso di Hamming, consentendo l'estrazione *remota* delle chiavi EdDSA.
* **Downfall / Gather Data Sampling (Intel, 2023)** – esecuzione transitoria per leggere i dati AVX-gather attraverso i thread SMT.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – la previsione errata speculativa dei vettori rilascia registri cross-domain.

Per un trattamento ampio delle questioni di classe Spectre vedere {{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}

---

## Attacchi Acustici e Ottici
* Il 2024 "​iLeakKeys" ha mostrato il 95 % di accuratezza nel recupero dei tasti digitati su laptop da un **microfono di smartphone su Zoom** utilizzando un classificatore CNN.
* I fotodiodi ad alta velocità catturano l'attività LED DDR4 e ricostruiscono le chiavi di round AES in meno di 1 minuto (BlackHat 2023).

---

## Iniezione di Errori e Analisi Differenziale degli Errori (DFA)
Combinare errori con perdite di canale laterale accelera la ricerca della chiave (ad es. DFA AES a 1 traccia). Strumenti recenti a prezzi da hobbista:
* **ChipSHOUTER & PicoEMP** – glitching di impulsi elettromagnetici sub-1 ns.
* **GlitchKit-R5 (2025)** – piattaforma di glitching di clock/voltaggio open-source che supporta SoC RISC-V.

---

## Flusso di Lavoro Tipico dell'Attacco
1. Identificare il canale di perdita e il punto di montaggio (pin VCC, condensatore di disaccoppiamento, punto a campo vicino).
2. Inserire il trigger (GPIO o basato su pattern).
3. Raccogliere >1 k tracce con campionamento/filtri appropriati.
4. Pre-processare (allineamento, rimozione della media, filtro LP/HP, wavelet, PCA).
5. Recupero della chiave statistico o ML (CPA, MIA, DL-SCA).
6. Validare e iterare sugli outlier.

---

## Difese e Indurimento
* Implementazioni **a tempo costante** e algoritmi a memoria dura.
* **Mascheramento/shuffling** – suddividere i segreti in condivisioni casuali; resistenza di primo ordine certificata da TVLA.
* **Nascondere** – regolatori di tensione on-chip, clock randomizzati, logica dual-rail, scudi EM.
* **Rilevamento di errori** – computazione ridondante, firme di soglia.
* **Operativo** – disabilitare DVFS/turbo nei kernel crittografici, isolare SMT, vietare la co-locazione nei cloud multi-tenant.

---

## Strumenti e Framework
* **ChipWhisperer-Husky** (2024) – oscilloscopio 500 MS/s + trigger Cortex-M; API Python come sopra.
* **Riscure Inspector & FI** – commerciale, supporta la valutazione automatizzata delle perdite (TVLA-2.0).
* **scaaml** – libreria SCA di deep-learning basata su TensorFlow (v1.2 – 2025).
* **pyecsca** – framework SCA ECC open-source di ANSSI.

---

## Riferimenti

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
