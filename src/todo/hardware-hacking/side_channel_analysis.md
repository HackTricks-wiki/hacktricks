# Attacchi di Side-Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Gli attacchi side-channel recuperano segreti osservando un "leakage" fisico o micro-architetturale che è *correlato* allo stato interno, ma non fa parte dell'interfaccia logica del dispositivo. Gli esempi vanno dalla misurazione della corrente istantanea assorbita da una smart card allo sfruttamento degli effetti della gestione energetica della CPU tramite una rete.

---

## Principali canali di leakage

| Canale | Target tipico | Strumentazione |
|---------|---------------|-----------------|
| Consumo energetico | Smart card, MCU IoT, FPGA | Oscilloscopio più resistore shunt o sonda differenziale; il CW503 è un alimentatore per probe/LNA, non è una probe<sup>[[11]](#references)</sup> |
| Campo elettromagnetico (EM) | CPU, RFID, acceleratori AES | Probe H-field/near-field più amplificatore a basso rumore e oscilloscopio o ricevitore SDR come un RTL-SDR<sup>[[13]](#references)</sup> |
| Tempo di esecuzione / cache | CPU desktop e cloud | Timer ad alta precisione (`rdtsc`/`rdtscp`) o time-of-flight remoto |
| Acustico / meccanico | Tastiere, stampanti 3D, stampanti, relè e regolatori di tensione delle CPU | Microfono MEMS o vibrometro laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Ottico e termico | LED di stato, display, DRAM e dispositivi accoppiati termicamente | Fotodiodo, telecamera ad alta velocità o telecamera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | Crittografia ASIC/MCU | Clock/voltage glitch, EMFI o iniezione laser |

---

## Analisi dei consumi

### Simple Power Analysis (SPA)
Osservare una *singola* traccia e associare le caratteristiche visibili a operazioni come branch, moltiplicazione modulare o sequenze di istruzioni differenti.<sup>[[1]](#references)</sup>

La configurazione esatta dipende dal target. Di seguito viene utilizzata l'API di cattura di alto livello di ChipWhisperer dopo che lo scope e il target sono stati collegati e configurati:<sup>[[1]](#references)</sup>
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
Acquisisci più trace, formula un'ipotesi sul byte della chiave `k`, calcola un modello di leakage basato sul peso di Hamming (HW) o sulla distanza di Hamming (HD), quindi correla il modello con ogni sample. Il numero di trace richiesto è determinato dal target, dal noise, dall'allineamento, dalle contromisure e dal modello di leakage; non è una soglia fissa.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA è una baseline standard. Template attacks, mutual-information analysis e gli approcci di machine learning possono essere utili quando la leakage è non lineare o le traces sono scarsamente allineate.

---

## Analisi elettromagnetica (EMA)
L'analisi EM in near-field può osservare attività dipendente dai dati senza inserire uno shunt nel percorso di alimentazione. Non espone necessariamente lo stesso segnale di una power trace: posizione della probe, orientamento, bandwidth, guadagno del front-end, qualità del trigger e distanza sono tutti fattori importanti.

---

## Attacchi temporali e micro-architetturali
Le CPU moderne fanno leak di segreti attraverso risorse condivise:
* **Hertzbleed (2022)** – Il dynamic voltage and frequency scaling dipendente dai dati crea un canale temporale remoto. La dimostrazione originale end-to-end di key recovery aveva come obiettivo SIKE; i lavori successivi discutono altre primitive.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – L'esecuzione transient può esporre dati utilizzati dalle istruzioni vector gather oltre i confini di sicurezza.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Una gestione errata dello stato speculativo dei vector register può divulgare dati dallo stesso core fisico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Un attacco di transient execution combina phantom execution con il training nella transient execution per creare gadget di misprediction controllati dall'attaccante.<sup>[[5]](#references)</sup>

---

## Attacchi acustici e ottici
La leakage acustica è stata utilizzata per recuperare chiavi RSA dal rumore di un laptop in un esperimento controllato, anche mediante il microfono di un telefono cellulare nelle vicinanze.<sup>[[6]](#references)</sup> Uno studio separato del 2023 sulle tastiere ha classificato le battute con un'accuratezza del 95% quando il training utilizzava registrazioni provenienti da un telefono vicino e del 93% quando utilizzava audio di Zoom; queste cifre descrivono l'esperimento dello studio su un dispositivo sottoposto a training, non una tastiera o una vittima qualsiasi.<sup>[[9]](#references)</sup> Le emanazioni ottiche dei LED di stato possono inoltre essere correlate ai dati elaborati. Questi risultati dipendono dall'obiettivo e dalla configurazione; non bisogna generalizzare la loro portata o percentuale di successo a dispositivi non correlati.<sup>[[7]](#references)</sup>

---

## Fault Injection e Differential Fault Analysis (DFA)
La combinazione di fault controllati con osservazioni side-channel può ridurre la ricerca della chiave per alcuni algoritmi e implementazioni. Le piattaforme di laboratorio comuni includono le funzionalità di voltage/clock glitching di ChipWhisperer e strumenti dedicati di EM fault injection come ChipSHOUTER o PicoEMP. La descrizione precedente di “sub-1 ns” non deve essere utilizzata come specifica: il manuale pubblicato di ChipSHOUTER indica larghezze tipiche degli impulsi inseriti di **15–80 ns** con la punta da 1 mm e di **24–480 ns** con la punta da 4 mm (sebbene il trigger/pulse jitter sia specificato in picosecondi). La risoluzione temporale richiesta, il posizionamento della probe e il numero di output errati dipendono dall'obiettivo e dal fault model.<sup>[[1]](#references)[[10]](#references)</sup>

## Unverified Research Leads Retained from the Earlier Draft

La bozza precedente affermava inoltre: una configurazione EM da **500 MHz–3 GHz** in grado di recuperare una chiave STM32 da oltre **10 cm** utilizzando un RTL-SDR; un LED di attività DDR4 in grado di rivelare una chiave di round AES in meno di un minuto durante il “Black Hat 2023”; e una piattaforma open-source RISC-V di glitching del 2025 denominata **GlitchKit-R5**. Durante questo audit non è stato possibile individuare alcun paper primario, materiale di conferenza o repository di progetto corrispondente. Questi dettagli esatti sono mantenuti come piste per la ricerca e la riproduzione, non come risultati consolidati o raccomandazioni relative agli strumenti.

---

## Workflow tipico di un attacco
1. Identificare il canale di leakage e il punto di collegamento (pin VCC, condensatore di disaccoppiamento, punto in near-field).
2. Inserire il trigger (GPIO o basato su pattern).
3. Raccogliere un numero sufficiente di traces per il test statistico scelto, registrando plaintext/ciphertext e altri metadati.
4. Pre-processare (allineamento, rimozione della media, filtro LP/HP, wavelet, PCA).
5. Key recovery statistico o tramite ML (CPA, MIA, DL-SCA).
6. Convalidare e ripetere il processo sugli outlier.

---

## Difese e hardening
* Implementazioni **constant-time** e algoritmi **memory-hard**.
* **Masking/shuffling** – suddividere i segreti in share casuali; resistenza di primo ordine certificata da TVLA.
* **Hiding** – voltage regulator on-chip, clock randomizzato, logica dual-rail, schermature EM.
* **Fault detection** – calcolo ridondante, threshold signature.
* **Operative** – disabilitare DVFS/turbo nei kernel crittografici, isolare SMT, vietare la co-location nei cloud multi-tenant.

---

## Strumenti e framework
* **ChipWhisperer-Husky** (2024) – oscilloscopio da 500 MS/s + trigger Cortex-M; API Python come sopra.<sup>[[1]](#references)</sup>
* **Riscure Inspector e prodotti di fault injection** – strumenti commerciali di analisi e test automatizzati.
* **scaaml** – strumenti e dataset di SCA basati sul deep learning e su TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit open-source per il reverse engineering di implementazioni ECC black-box attraverso side-channel.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentazione di ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Paper sull'attacco Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: sfruttare la raccolta speculativa dei dati](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: esporre nuove superfici di attacco con il training nella transient execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Estrazione di chiavi RSA tramite crittoanalisi acustica a bassa bandwidth](https://eprint.iacr.org/2013/857.pdf)
- [7] [Leakage di informazioni dalle emanazioni ottiche](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentazione dell'artefatto pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Un pratico attacco side-channel acustico sulle tastiere basato sul deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - manuale utente di ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentazione di ChipWhisperer — alimentazione della probe CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentazione di Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — esecuzione di attacchi side-channel elettromagnetici a basso costo mediante RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decodificare la proprietà intellettuale: attacco side-channel acustico e magnetico su una stampante 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — attacchi side-channel acustici sulle stampanti](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Spiare la temperatura utilizzando la DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
