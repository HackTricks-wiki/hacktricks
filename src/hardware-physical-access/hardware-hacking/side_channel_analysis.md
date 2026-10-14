# Attacchi di analisi side-channel

{{#include ../../banners/hacktricks-training.md}}

Gli attacchi side-channel recuperano segreti osservando il "leakage" fisico o micro-architetturale, *correlato* allo stato interno ma *non* parte dell'interfaccia logica del dispositivo. Gli esempi spaziano dalla misurazione della corrente istantanea assorbita da una smart card allo sfruttamento degli effetti della gestione energetica della CPU tramite rete.

---

## Principali canali di leakage

| Canale | Target tipico | Strumentazione |
|---------|---------------|-----------------|
| Consumo energetico | Smart card, MCU IoT, FPGA | Oscilloscopio con resistore shunt o sonda differenziale; il CW503 è un alimentatore per sonde/LNA, non è una sonda<sup>[[11]](#references)</sup> |
| Campo elettromagnetico (EM) | CPU, RFID, acceleratori AES | Sonda H-field/near-field con amplificatore a basso rumore e oscilloscopio o ricevitore SDR, come un RTL-SDR<sup>[[13]](#references)</sup> |
| Tempo di esecuzione / cache | CPU desktop e cloud | Timer ad alta precisione (`rdtsc`/`rdtscp`) o misurazione remota del tempo di percorrenza |
| Acustica / meccanica | Tastiere, stampanti 3D, stampanti, relè e regolatori di tensione delle CPU | Microfono MEMS o vibrometro laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Ottica e termica | LED di stato, display, DRAM e dispositivi accoppiati termicamente | Fotodiodo, videocamera ad alta velocità o termocamera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | Crittografia ASIC/MCU | Glitch di clock/tensione, EMFI o iniezione laser |

---

## Analisi della potenza

### Simple Power Analysis (SPA)
Osserva una *singola* traccia e associa le caratteristiche visibili a operazioni come branch, moltiplicazioni modulari o sequenze di istruzioni diverse.<sup>[[1]](#references)</sup>

La configurazione esatta dipende dal target. L'esempio seguente usa l'API di acquisizione di alto livello corrente di ChipWhisperer, dopo aver collegato e configurato lo scope e il target:<sup>[[1]](#references)</sup>

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
Acquisisci più traces, ipotizza un byte della chiave `k`, calcola un modello di leakage basato sul peso di Hamming (HW) o sulla distanza di Hamming (HD) e correlalo con ciascun campione. Il numero di traces richiesto dipende dal target, dal rumore, dall’allineamento, dalle contromisure e dal modello di leakage; non esiste una soglia fissa.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA è una baseline standard. Gli attacchi template, l’analisi dell’informazione mutua e gli approcci di machine learning possono essere utili quando la leakage è non lineare o le tracce sono allineate male.

---

## Analisi elettromagnetica (EMA)
L’analisi EM in campo vicino può osservare attività dipendenti dai dati senza inserire uno shunt nel percorso di alimentazione. Non espone necessariamente lo stesso segnale di una traccia di potenza: contano la posizione e l’orientamento della sonda, la larghezza di banda, il guadagno dello stadio d’ingresso, la qualità del trigger e la distanza.

---

## Attacchi temporali e microarchitetturali
Le CPU moderne fanno leak di segreti attraverso risorse condivise:
* **Hertzbleed (2022)** – La scalabilità dinamica di tensione e frequenza, dipendente dai dati, crea un canale temporale remoto. La dimostrazione originale di recupero end-to-end della chiave prendeva di mira SIKE; i lavori successivi analizzano altre primitive.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – L’esecuzione transitoria può esporre dati usati dalle istruzioni di gather vettoriale attraverso i confini di sicurezza.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – La gestione errata dello stato speculativo dei registri vettoriali può divulgare dati dallo stesso core fisico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Un attacco di esecuzione transitoria combina l’esecuzione fantasma con l’addestramento nell’esecuzione transitoria per creare gadget di predizione errata controllati dall’attaccante.<sup>[[5]](#references)</sup>

---

## Attacchi acustici e ottici
La leakage acustica è stata usata per recuperare chiavi RSA dal rumore di un laptop in un esperimento controllato, anche con il microfono di un telefono cellulare nelle vicinanze.<sup>[[6]](#references)</sup> Uno studio distinto del 2023 sulle tastiere ha classificato le battute con un’accuratezza del 95% dopo l’addestramento su registrazioni effettuate con un telefono nelle vicinanze e del 93% dopo l’addestramento su audio di Zoom; queste percentuali descrivono l’esperimento dello studio con dispositivi di addestramento, non una tastiera o una vittima qualsiasi.<sup>[[9]](#references)</sup> Anche le emissioni ottiche dei LED di stato possono essere correlate ai dati elaborati. Questi risultati dipendono dal bersaglio e dalla configurazione; non generalizzare portata o percentuali di successo a dispositivi non correlati.<sup>[[7]](#references)</sup>

---

## Iniezione di fault e Differential Fault Analysis (DFA)
La combinazione di fault controllati e osservazioni side-channel può ridurre la ricerca della chiave per alcuni algoritmi e implementazioni. Tra le piattaforme di laboratorio più comuni figurano le funzionalità di voltage/clock glitching di ChipWhisperer e strumenti dedicati all’iniezione di fault EM, come ChipSHOUTER o PicoEMP. La descrizione della bozza precedente, “sub-1 ns”, non va usata come specifica: il manuale pubblicato di ChipSHOUTER indica larghezze tipiche degli impulsi iniettati di **15–80 ns** con la punta da 1 mm e **24–480 ns** con quella da 4 mm (sebbene il jitter di trigger/impulso sia specificato in picosecondi). La risoluzione temporale necessaria, la posizione della sonda e il numero di output difettosi dipendono dal bersaglio e dal modello di fault.<sup>[[1]](#references)[[10]](#references)</sup>

## Piste di ricerca non verificate mantenute dalla bozza precedente

La bozza precedente affermava inoltre che: una configurazione EM da **500 MHz–3 GHz** aveva recuperato una chiave STM32 da oltre **10 cm** di distanza usando un RTL-SDR; un LED di attività DDR4 aveva rivelato una chiave di un round AES in meno di un minuto a “Black Hat 2023”; e nel 2025 era stata creata una piattaforma open-source per il glitching RISC-V chiamata **GlitchKit-R5**. Durante questa verifica non è stato possibile trovare alcun articolo accademico, materiale di conferenze o repository di progetto corrispondente. Questi dettagli esatti sono mantenuti come piste per ulteriori ricerche e riproduzioni, non come risultati accertati o raccomandazioni di strumenti.

---

## Flusso di lavoro tipico di un attacco
1. Identificare il canale di leakage e il punto di accesso (pin VCC, condensatore di disaccoppiamento, punto in campo vicino).
2. Inserire un trigger (GPIO o basato su pattern).  
3. Raccogliere un numero sufficiente di tracce per il test statistico scelto, registrando testo in chiaro/testo cifrato e altri metadati.
4. Pre-elaborare (allineamento, rimozione della media, filtro LP/HP, wavelet, PCA).
5. Recupero statistico o ML della chiave (CPA, MIA, DL-SCA).
6. Convalidare e ripetere l’analisi degli outlier.

---

## Difese e hardening
* Implementazioni **constant-time** e algoritmi memory-hard.
* **Masking/shuffling** – suddividere i segreti in share casuali; resistenza di primo ordine certificata tramite TVLA.
* **Hiding** – regolatori di tensione on-chip, clock randomizzato, logica dual-rail, schermature EM.
* **Rilevamento dei fault** – calcolo ridondante, firme a soglia.
* **Operative** – disabilitare DVFS/turbo nei kernel crittografici, isolare SMT, vietare la co-locazione nei cloud multi-tenant.

---

## Strumenti e framework
* **ChipWhisperer-Husky** (2024) – oscilloscopio da 500 MS/s + trigger Cortex-M; API Python come sopra.<sup>[[1]](#references)</sup>
* **Riscure Inspector e prodotti per l’iniezione di fault** – strumenti commerciali per l’analisi e test automatizzati.
* **scaaml** – strumenti e dataset SCA di deep learning basati su TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit open-source per il reverse engineering di implementazioni ECC black-box tramite side-channel.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentazione ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Articolo sull’attacco Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: sfruttare la raccolta speculativa dei dati](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: esporre nuove superfici di attacco con l’addestramento nell’esecuzione transitoria](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Estrazione di chiavi RSA tramite crittoanalisi acustica a bassa larghezza di banda](https://eprint.iacr.org/2013/857.pdf)
- [7] [Leakage di informazioni dalle emissioni ottiche](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentazione dell’artefatto pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Un pratico attacco side-channel acustico alle tastiere basato sul deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - manuale utente di ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentazione ChipWhisperer — alimentatore per sonda CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentazione Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — esecuzione di attacchi side-channel elettromagnetici a basso costo con RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decodificare la proprietà intellettuale: attacco side-channel acustico e magnetico a una stampante 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — attacchi side-channel acustici alle stampanti](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Spiare la temperatura usando la DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
