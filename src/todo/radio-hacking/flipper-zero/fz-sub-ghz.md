# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero può **ricevere e trasmettere frequenze radio nell'intervallo 300-928 MHz** con il suo modulo integrato, che può leggere, salvare ed emulare telecomandi. Questi controlli vengono utilizzati per interagire con cancelli, barriere, serrature radio, interruttori telecomandati, campanelli wireless, luci smart e altro ancora. Flipper Zero può aiutarti a capire se la tua sicurezza è compromessa.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero dispone di un modulo sub-1 GHz integrato basato su un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) e un'antenna radio (la portata massima è di 50 metri). Sia il chip CC1101 sia l'antenna sono progettati per operare nelle bande 300-348 MHz, 387-464 MHz e 779-928 MHz.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Azioni

### Frequency Analyser

> [!TIP]
> Come trovare la frequenza utilizzata dal telecomando

Durante l'analisi, Flipper Zero scansiona la potenza dei segnali (RSSI) su tutte le frequenze disponibili nella configurazione delle frequenze. Flipper Zero visualizza la frequenza con il valore RSSI più elevato, con una potenza del segnale superiore a -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Per determinare la frequenza del telecomando, procedi come segue:

1. Posiziona il telecomando molto vicino, a sinistra di Flipper Zero.
2. Vai a **Main Menu** **→ Sub-GHz**.
3. Seleziona **Frequency Analyzer**, quindi tieni premuto il pulsante del telecomando che vuoi analizzare.
4. Controlla il valore della frequenza sullo schermo.

### Read

> [!TIP]
> Trovare informazioni sulla frequenza utilizzata (un altro modo per trovare quale frequenza viene utilizzata)

L'opzione **Read** **ascolta sulla frequenza configurata** con la modulazione indicata: 433.92 AM per impostazione predefinita. Se durante la lettura **viene trovato qualcosa**, sullo schermo vengono visualizzate **informazioni**. Queste informazioni possono essere utilizzate per replicare il segnale in futuro.<sup>[[1]](#references)</sup>

Mentre Read è in uso, è possibile premere il **pulsante sinistro** e **configurarlo**.\
Al momento sono disponibili **4 modulazioni** (AM270, AM650, FM328 e FM476) e sono memorizzate **diverse frequenze rilevanti**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Puoi impostare **quella che ti interessa**, tuttavia, se **non sei sicuro di quale frequenza** possa essere quella utilizzata dal telecomando che possiedi, **imposta Hopping su ON** (disattivato per impostazione predefinita) e premi più volte il pulsante finché Flipper non la acquisisce e non ti fornisce le informazioni necessarie per impostare la frequenza.

> [!CAUTION]
> Il passaggio da una frequenza all'altra richiede del tempo, pertanto i segnali trasmessi durante il cambio possono andare persi. Per una migliore ricezione del segnale, imposta una frequenza fissa determinata con Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Rubare (e riprodurre) un segnale sulla frequenza configurata

L'opzione **Read Raw** **registra i segnali** inviati sulla frequenza in ascolto. Può essere utilizzata per **rubare** un segnale e **ripeterlo**.<sup>[[1]](#references)</sup>

Per impostazione predefinita, **Read Raw è anch'esso impostato su 433.92 in AM650**, ma se con l'opzione Read hai scoperto che il segnale che ti interessa si trova su una **frequenza/modulazione diversa, puoi modificarla** premendo il pulsante sinistro (mentre ti trovi nell'opzione Read Raw).

### Brute-Force

Se conosci il protocollo utilizzato, ad esempio, dal cancello del garage, è possibile **generare tutti i codici e inviarli con Flipper Zero.** Questo è un esempio che supporta i tipi comuni e generici di garage: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Aggiungere segnali da un elenco configurato di protocolli

#### Elenco dei [protocolli supportati](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (funziona con la maggior parte dei sistemi a codice statico) | 433.92 | Statico  |
| --------------------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                                           | 433.92 | Statico  |
| Nice Flo 24bit_433                                                           | 433.92 | Statico  |
| CAME 12bit_433                                                               | 433.92 | Statico  |
| CAME 24bit_433                                                               | 433.92 | Statico  |
| Linear_300                                                                   | 300.00 | Statico  |
| CAME TWEE                                                                    | 433.92 | Statico  |
| Gate TX_433                                                                  | 433.92 | Statico  |
| DoorHan_315                                                                  | 315.00 | Dinamico |
| DoorHan_433                                                                  | 433.92 | Dinamico |
| LiftMaster_315                                                               | 315.00 | Dinamico |
| LiftMaster_390                                                               | 390.00 | Dinamico |
| Security+2.0_310                                                             | 310.00 | Dinamico |
| Security+2.0_315                                                             | 315.00 | Dinamico |
| Security+2.0_390                                                             | 390.00 | Dinamico |

### Venditori Sub-GHz supportati

Controlla l'elenco in [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frequenze supportate per regione

Controlla l'elenco in [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> Ottenere i dBm delle frequenze salvate

## Riferimenti

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
