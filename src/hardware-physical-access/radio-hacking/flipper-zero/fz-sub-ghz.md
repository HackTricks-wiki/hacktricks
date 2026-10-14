# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#introduction" id="introduction"></a>

Flipper Zero può **ricevere e trasmettere frequenze radio nell'intervallo 300-928 MHz** grazie al modulo integrato, nel rispetto delle restrizioni di frequenza previste per la regione configurata. Può leggere, salvare ed emulare telecomandi compatibili utilizzati per cancelli, sbarre, serrature radio, interruttori, campanelli wireless, luci smart e altri dispositivi.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero dispone di un modulo sub-1 GHz integrato basato su un ricetrasmettitore CC1101 e un'antenna radio. La portata effettiva dipende dalla frequenza, dall'antenna, dall'ambiente e dal trasmettitore; Flipper dichiara una portata fino a circa 50 metri in condizioni favorevoli. L'hardware copre 300-348 MHz, 387-464 MHz e 779-928 MHz, mentre il firmware e le normative regionali limitano ulteriormente la trasmissione.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Azioni

### Frequency Analyser

> [!TIP]
> Come individuare la frequenza utilizzata dal telecomando

Durante l'analisi, Flipper Zero esegue la scansione della potenza del segnale (RSSI) su tutte le frequenze disponibili nella configurazione delle frequenze. Flipper Zero mostra la frequenza con il valore RSSI più alto, con una potenza del segnale superiore a -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Per determinare la frequenza del telecomando:

1. Avvicina molto il telecomando al lato sinistro di Flipper Zero.
2. Vai a **Main Menu** **→ Sub-GHz**.
3. Seleziona **Frequency Analyzer**, quindi tieni premuto il pulsante del telecomando che vuoi analizzare.
4. Controlla il valore della frequenza sullo schermo.

### Read

> [!TIP]
> Trova informazioni sulla frequenza utilizzata (un altro modo per individuarla)

L'opzione **Read** ascolta sulla frequenza e con la modulazione configurate (433.92 MHz AM per impostazione predefinita). Quando riconosce un segnale supportato, lo schermo mostra informazioni che possono essere salvate e riprodotte in seguito.<sup>[[1]](#references)</sup>

Durante l'uso di Read, è possibile premere il **pulsante sinistro** e **configurarlo**.\
Al momento sono disponibili **4 modulazioni** (AM270, AM650, FM328 e FM476) e **diverse frequenze rilevanti**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Puoi selezionare qualsiasi frequenza consentita. Se non sai quale frequenza usa il telecomando, imposta **Hopping su ON** (disattivato per impostazione predefinita), quindi premi più volte il pulsante del telecomando finché Flipper non acquisisce il segnale e ne indica la frequenza.

> [!CAUTION]
> Il passaggio da una frequenza all'altra richiede tempo, perciò i segnali trasmessi durante il cambio potrebbero non essere acquisiti. Per una ricezione migliore, imposta una frequenza fissa individuata con Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Acquisisci (e riproduci) un segnale sulla frequenza configurata

L'opzione **Read Raw** registra i segnali trasmessi sulla frequenza selezionata. Può essere usata per acquisire e riprodurre un segnale durante test autorizzati.<sup>[[1]](#references)</sup>

Per impostazione predefinita, **Read Raw usa anch'esso 433.92 MHz con AM650**. Se l'opzione Read ha rilevato un segnale su una frequenza o modulazione diversa, premi Left all'interno di Read Raw per modificare queste impostazioni.

### Brute-Force

Se conosci il protocollo utilizzato da un dispositivo, ad esempio una porta da garage, potrebbe essere possibile **generare codici candidati e trasmetterli con Flipper Zero**. Il progetto `flipperzero-bruteforce` supporta diversi protocolli comuni a codice statico.<sup>[[3]](#references)</sup>

### Aggiungi manualmente

> [!TIP]
> Aggiungi segnali da un elenco configurato di protocolli

#### Elenco dei protocolli supportati <a href="#id-3iglu" id="id-3iglu"></a>

Il menu Add Manually mostra le preimpostazioni dei protocolli documentate da Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (funziona con la maggior parte dei sistemi a codice statico) | 433.92 | Statico |
| -------------------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                                         | 433.92 | Statico |
| Nice Flo 24bit_433                                                         | 433.92 | Statico |
| CAME 12bit_433                                                             | 433.92 | Statico |
| CAME 24bit_433                                                             | 433.92 | Statico |
| Linear_300                                                                 | 300.00 | Statico |
| CAME TWEE                                                                  | 433.92 | Statico |
| Gate TX_433                                                                | 433.92 | Statico |
| DoorHan_315                                                                | 315.00 | Dinamico |
| DoorHan_433                                                                | 433.92 | Dinamico |
| LiftMaster_315                                                             | 315.00 | Dinamico |
| LiftMaster_390                                                             | 390.00 | Dinamico |
| Security+2.0_310                                                           | 310.00 | Dinamico |
| Security+2.0_315                                                           | 315.00 | Dinamico |
| Security+2.0_390                                                           | 390.00 | Dinamico |

### Vendor Sub-GHz supportati

Consulta l'elenco dei vendor supportati da Flipper Zero.<sup>[[5]](#references)</sup>

### Frequenze supportate per regione

Prima di trasmettere, consulta l'elenco ufficiale delle frequenze regionali.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Ottieni i dBm delle frequenze salvate

## References

- [1] [Sub-GHz - Documentazione utente di Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Scheda tecnica Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Aggiungere un telecomando creato manualmente](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Vendor Sub-GHz supportati](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Frequenze Sub-GHz regionali](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
