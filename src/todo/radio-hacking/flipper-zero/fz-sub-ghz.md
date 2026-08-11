# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#introduction" id="introduction"></a>

Flipper Zero può **ricevere e trasmettere frequenze radio nell'intervallo 300-928 MHz** con il suo modulo integrato, in base alle restrizioni di frequenza della regione configurata. Può leggere, salvare ed emulare telecomandi compatibili utilizzati con cancelli, barriere, serrature radio, interruttori, campanelli wireless, luci smart e altri dispositivi.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero dispone di un modulo integrato sub-1 GHz basato su un ricetrasmettitore CC1101 e su un'antenna radio. La portata effettiva dipende dalla frequenza, dall'antenna, dall'ambiente e dal trasmettitore; la documentazione di Flipper indica circa 50 metri in condizioni favorevoli. L'hardware copre 300-348 MHz, 387-464 MHz e 779-928 MHz, mentre il firmware e le normative regionali limitano ulteriormente la trasmissione.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Azioni

### Frequency Analyser

> [!TIP]
> Come trovare la frequenza utilizzata dal telecomando

Durante l'analisi, Flipper Zero scansiona la potenza dei segnali (RSSI) a tutte le frequenze disponibili nella configurazione delle frequenze. Flipper Zero mostra la frequenza con il valore RSSI più alto, con una potenza del segnale superiore a -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Per determinare la frequenza del telecomando, procedi come segue:

1. Posiziona il telecomando molto vicino al lato sinistro di Flipper Zero.
2. Vai a **Main Menu** **→ Sub-GHz**.
3. Seleziona **Frequency Analyzer**, quindi tieni premuto il pulsante del telecomando che vuoi analizzare.
4. Controlla il valore della frequenza sullo schermo.

### Read

> [!TIP]
> Trovare informazioni sulla frequenza utilizzata (anche un altro modo per trovare quale frequenza viene utilizzata)

L'opzione **Read** ascolta sulla frequenza e sulla modulazione configurate (433.92 MHz AM per impostazione predefinita). Quando riconosce un segnale supportato, lo schermo mostra informazioni che possono essere salvate e riprodotte in seguito.<sup>[[1]](#references)</sup>

Durante l'utilizzo di Read, è possibile premere il **pulsante sinistro** e **configurarlo**.\
Al momento dispone di **4 modulazioni** (AM270, AM650, FM328 e FM476) e di **diverse frequenze rilevanti** memorizzate:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Puoi selezionare qualsiasi frequenza consentita. Se non sai quale frequenza utilizza il telecomando, imposta **Hopping su ON** (disattivato per impostazione predefinita), quindi premi più volte il pulsante del telecomando finché Flipper non acquisisce il segnale e comunica la frequenza.

> [!CAUTION]
> Il passaggio da una frequenza all'altra richiede del tempo, pertanto i segnali trasmessi durante il passaggio possono andare persi. Per una ricezione migliore del segnale, imposta una frequenza fissa determinata da Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Rubare (e riprodurre) un segnale sulla frequenza configurata

L'opzione **Read Raw** registra i segnali inviati sulla frequenza selezionata. Può essere utilizzata per catturare e riprodurre un segnale durante un test autorizzato.<sup>[[1]](#references)</sup>

Per impostazione predefinita, **Read Raw utilizza anch'esso 433.92 MHz con AM650**. Se l'opzione Read ha rilevato un segnale su una frequenza o modulazione diversa, premi Left all'interno di Read Raw per modificare queste impostazioni.

### Brute-Force

Se conosci il protocollo utilizzato da un dispositivo, come una porta da garage, potrebbe essere possibile **generare codici candidati e trasmetterli con Flipper Zero**. Il progetto `flipperzero-bruteforce` supporta diversi protocolli comuni con codice statico.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Aggiungere segnali da un elenco configurato di protocolli

#### Elenco dei protocolli supportati <a href="#id-3iglu" id="id-3iglu"></a>

Il menu Add Manually espone i preset dei protocolli documentati da Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (funziona con la maggior parte dei sistemi a codice statico) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Vendor Sub-GHz supportati

Controlla l'elenco dei vendor supportati da Flipper Zero.<sup>[[5]](#references)</sup>

### Frequenze supportate per regione

Controlla l'elenco ufficiale delle frequenze regionali prima di trasmettere.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Ottenere i dBm delle frequenze salvate

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
