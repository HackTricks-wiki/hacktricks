# Attacchi di analisi side-channel

{{#include ../../banners/hacktricks-training.md}}

Gli attacchi side-channel recuperano segreti osservando il "leakage" fisico o microarchitetturale *correlato* allo stato interno, ma che *non* fa parte dell'interfaccia logica del dispositivo. Gli esempi vanno dalla misurazione della corrente istantanea assorbita da una smart card allo sfruttamento degli effetti della gestione dell'alimentazione della CPU attraverso una rete.

Per un target con hardware di debug ARM accessibile, [il tracing CoreSight ETM tramite SWO](arm-coresight-instruction-tracing.md) può fornire un riferimento del percorso di esecuzione insieme alle acquisizioni di potenza o EM; si tratta di una traccia di debug, non di un canale di leakage.<sup>[[17]](#references)</sup>

---

## Principali canali di leakage

| Canale | Target tipico | Strumentazione |
|---------|---------------|-----------------|
| Consumo energetico | Smart card, MCU IoT, FPGA | Oscilloscopio con resistore shunt o sonda differenziale; il CW503 è un alimentatore per sonde/LNA, non una sonda<sup>[[11]](#references)</sup> |
| Campo elettromagnetico (EM) | CPU, RFID, acceleratori AES | Sonda H-field/near-field con amplificatore a basso rumore e oscilloscopio o ricevitore SDR, come un RTL-SDR<sup>[[13]](#references)</sup> |
| Tempo di esecuzione / cache | CPU desktop e cloud | Timer ad alta precisione (`rdtsc`/`rdtscp`) o misurazione remota del tempo di volo |
| Acustica / meccanica | Tastiere, stampanti 3D, stampanti, relè e regolatori di tensione della CPU | Microfono MEMS o vibrometro laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Ottica e termica | LED di stato, display, DRAM e dispositivi accoppiati termicamente | Fotodiodo, telecamera ad alta velocità o telecamera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Iniezione di fault | Crittografia ASIC/MCU | Glitch di clock/tensione, EMFI o iniezione laser |

---

## Analisi della potenza

### Simple Power Analysis (SPA)
Osserva una *singola* traccia e associa le caratteristiche visibili a operazioni come salti, moltiplicazioni modulari o sequenze di istruzioni diverse.<sup>[[1]](#references)</sup>

La configurazione esatta dipende dal target. L'esempio seguente usa l'API di acquisizione ChipWhisperer di alto livello attuale, dopo aver collegato e configurato lo scope e il target:<sup>[[1]](#references)</sup>

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
Acquisisci più traces, ipotizza un byte della chiave `k`, calcola un modello di leakage basato sul peso di Hamming (HW) o sulla distanza di Hamming (HD) e correlalo con ogni campione. Il numero di traces necessario dipende dal target, dal rumore, dall’allineamento, dalle contromisure e dal modello di leakage; non esiste una soglia fissa.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA è un baseline standard. Template attacks, mutual-information analysis e approcci di machine learning possono essere utili quando il leakage è non lineare o le tracce sono scarsamente allineate.

---

## Analisi elettromagnetica (EMA)
L'analisi EM in near-field può osservare attività dipendenti dai dati senza inserire uno shunt nel percorso di alimentazione. Non espone necessariamente lo stesso segnale di una traccia di potenza: contano la posizione e l'orientamento della sonda, la banda passante, il guadagno del front-end, la qualità del trigger e la distanza.

---

## Timing e attacchi microarchitetturali
Le CPU moderne fanno trapelare segreti attraverso risorse condivise:
* **Hertzbleed (2022)** – Il ridimensionamento dinamico di tensione e frequenza dipendente dai dati crea un canale di timing remoto. La dimostrazione originale di recupero della chiave end-to-end prendeva di mira SIKE; i lavori successivi discutono altre primitive.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – L'esecuzione transient può esporre dati utilizzati dalle istruzioni vector gather oltre i confini di sicurezza.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – La gestione errata dello stato speculativo dei registri vector può divulgare dati dallo stesso core fisico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Un attacco di esecuzione transient combina l'esecuzione fantasma con il training nell'esecuzione transient per creare gadget di misprediction controllati dall'attaccante.<sup>[[5]](#references)</sup>

---

## Attacchi acustici e ottici
Il leakage acustico è stato usato per recuperare chiavi RSA dal rumore di un laptop in un esperimento controllato, anche utilizzando il microfono di un telefono cellulare nelle vicinanze.<sup>[[6]](#references)</sup> Uno studio distinto del 2023 sulle tastiere ha classificato i tasti premuti con un'accuratezza del 95% quando il training era basato su registrazioni effettuate con un telefono nelle vicinanze e del 93% quando era basato sull'audio di Zoom; questi valori descrivono l'esperimento dello studio con dispositivi su cui era stato eseguito il training, non una tastiera o una vittima qualsiasi.<sup>[[9]](#references)</sup> Anche le emissioni ottiche dei LED di stato possono essere correlate ai dati elaborati. Questi risultati dipendono dal target e dalla configurazione; non generalizzare la portata o il tasso di successo a dispositivi non correlati.<sup>[[7]](#references)</sup>

---

## Fault injection e Differential Fault Analysis (DFA)
La combinazione di fault controllati e osservazioni side-channel può ridurre la ricerca della chiave per alcuni algoritmi e implementazioni. Le piattaforme di laboratorio più comuni includono le funzionalità di voltage/clock glitching di ChipWhisperer e strumenti dedicati di fault injection EM come ChipSHOUTER o PicoEMP. La descrizione della bozza precedente «sub-1 ns» non va usata come specifica: il manuale pubblicato di ChipSHOUTER indica larghezze tipiche degli impulsi inseriti di **15–80 ns** con la punta da 1 mm e **24–480 ns** con quella da 4 mm (sebbene il jitter di trigger/impulso sia specificato in picosecondi). La risoluzione temporale richiesta, il posizionamento della sonda e il numero di output con fault dipendono dal target e dal modello di fault.<sup>[[1]](#references)[[10]](#references)</sup>

## Piste di ricerca non verificate mantenute dalla bozza precedente

La bozza precedente affermava inoltre: una configurazione EM da **500 MHz–3 GHz** in grado di recuperare una chiave STM32 da oltre **10 cm** usando un RTL-SDR; un LED di attività DDR4 che rivelava una chiave di round AES in meno di un minuto al «Black Hat 2023»; e una piattaforma open-source di glitching RISC-V del 2025 chiamata **GlitchKit-R5**. Durante questa verifica non è stato possibile individuare alcun articolo, materiale di conferenza o repository di progetto corrispondente. Questi dettagli precisi sono mantenuti come piste per la ricerca/riproduzione, non come risultati accertati o raccomandazioni di strumenti.

---

## Flusso di lavoro tipico di un attacco
1. Identificare il canale di leakage e il punto di prelievo (pin VCC, condensatore di disaccoppiamento, punto near-field).
2. Inserire un trigger (GPIO o basato su pattern).  
3. Raccogliere un numero sufficiente di tracce per il test statistico scelto, registrando testo in chiaro/ciphertext e altri metadati.
4. Pre-elaborare (allineamento, rimozione della media, filtro LP/HP, wavelet, PCA).
5. Recupero della chiave tramite metodi statistici o ML (CPA, MIA, DL-SCA).
6. Convalidare e iterare sui valori anomali.

---

## Difese e hardening
* Implementazioni **constant-time** e algoritmi memory-hard.
* **Masking/shuffling** – suddividere i segreti in share casuali; resistenza al primo ordine certificata tramite TVLA.
* **Hiding** – regolatori di tensione on-chip, clock randomizzato, logica dual-rail, schermature EM.
* **Rilevamento dei fault** – calcolo ridondante, threshold signatures.
* **Operative** – disabilitare DVFS/turbo nei kernel crittografici, isolare SMT, vietare la co-locazione nei cloud multi-tenant.

---

## Strumenti e framework
* **ChipWhisperer-Husky** (2024) – oscilloscopio da 500 MS/s + trigger Cortex-M; API Python come sopra.<sup>[[1]](#references)</sup>
* **Riscure Inspector e prodotti di fault injection** – strumenti commerciali per l'analisi e i test automatizzati.
* **scaaml** – strumenti e dataset per SCA basati su deep learning e TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit open-source per il reverse engineering di implementazioni ECC black-box tramite side-channel.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentazione di ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Articolo sull'attacco Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: sfruttare la raccolta speculativa dei dati](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: esporre nuove superfici di attacco con il training nell'esecuzione transient](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Estrazione di chiavi RSA tramite crittoanalisi acustica a banda ridotta](https://eprint.iacr.org/2013/857.pdf)
- [7] [Leakage di informazioni dalle emissioni ottiche](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentazione dell'artefatto pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Un pratico attacco side-channel acustico alle tastiere basato sul deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Manuale utente di ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentazione di ChipWhisperer — alimentatore per sonda CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentazione di Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Esecuzione di attacchi side-channel elettromagnetici a basso costo con RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decodificare la proprietà intellettuale: attacco side-channel acustico e magnetico a una stampante 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Attacchi side-channel acustici alle stampanti](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Spiare la temperatura usando la DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Seguire le istruzioni: tracing ARM in tempo reale con ETM, ITM e TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
