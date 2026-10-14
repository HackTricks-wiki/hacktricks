# Hacking hardware

{{#include ../../banners/hacktricks-training.md}}

Per un dispositivo a cui si ha accesso fisico, inizia dall’interfaccia esposta dalla scheda o dai segnali: [console seriali UART](uart.md), [accesso debug JTAG/SWD](jtag.md), bus [I²C](i2c.md) e [flash SPI](spi.md). L’[analisi side-channel](side_channel_analysis.md) e l’[iniezione di guasti](fault_injection_attacks.md) riguardano rispettivamente attività di misurazione e glitching; l’[analisi dei segnali radio](radio.md) tratta un punto di accesso via etere. Per procedure specifiche del target relative a RFID/NFC, sub-GHz, infrarossi, BLE, LoRaWAN e iButton, consulta [Radio Hacking e interfacce di prossimità](../radio-hacking/README.md). Prima di collegare gli strumenti, controlla i livelli elettrici del target e le limitazioni indicate nel capitolo pertinente.

## JTAG

JTAG (IEEE 1149.1) supporta i test boundary-scan tramite celle disposte attorno ai pin I/O di un dispositivo. Molti processori espongono anche funzioni di debug specifiche del produttore tramite lo stesso Test Access Port (TAP); il boundary scan e il debug della CPU sono usi correlati di JTAG, non sinonimi.<sup>[[1]](#references)</sup>

Lo standard JTAG definisce **comandi specifici per eseguire scansioni boundary-scan**, tra cui:

- **BYPASS** seleziona un registro bypass a un bit, così da poter raggiungere gli altri dispositivi della catena di scansione con un overhead minimo.
- **SAMPLE/PRELOAD** acquisisce i valori dei pin durante il normale funzionamento e può precaricare il registro boundary-scan prima di un’altra istruzione.
- **EXTEST** imposta e legge gli stati dei pin.

Può supportare anche altri comandi, come:

- **IDCODE** per identificare un dispositivo
- **INTEST** per il test interno del dispositivo

Potresti incontrare queste istruzioni utilizzando uno strumento come JTAGulator.

### Test Access Port

Il **Test Access Port (TAP)** consente di accedere alla logica di test JTAG di un componente. Sono necessari quattro segnali; `TRST` è opzionale:<sup>[[1]](#references)</sup>

- Ingresso clock di test (**TCK**) Il TCK è il **clock** che determina con quale frequenza il controller TAP esegue una singola azione (in altre parole, passa allo stato successivo della macchina a stati).
- Ingresso selezione modalità di test (**TMS**) Il TMS controlla la **macchina a stati finiti**. A ogni ciclo di clock, il controller JTAG TAP del dispositivo controlla la tensione sul pin TMS. Se la tensione è inferiore a una certa soglia, il segnale è considerato basso e interpretato come 0; se supera una certa soglia, è considerato alto e interpretato come 1.
- Ingresso dati di test (**TDI**) Sposta istruzioni seriali o dati di test nel registro TAP selezionato. IEEE 1149.1 definisce il comportamento dei trasferimenti TAP, mentre i produttori definiscono istruzioni opzionali e registri di debug.
- Uscita dati di test (**TDO**) Il TDO è il pin che invia i **dati fuori dal chip**.
- Ingresso reset di test (**TRST**) Il TRST opzionale riporta la macchina a stati finiti **a uno stato noto e valido**. In alternativa, mantenendo il TMS a 1 per cinque cicli di clock consecutivi si attiva un reset, come avverrebbe tramite il pin TRST: ecco perché TRST è opzionale.

A volte è possibile trovare questi pin contrassegnati sulla PCB. In altri casi, potrebbe essere necessario **individuarli**.

### Identificazione dei pin JTAG

Un’opzione rapida, progettata appositamente per rilevare le porte JTAG ma relativamente costosa è **JTAGulator**, che può anche identificare i pin UART.<sup>[[2]](#references)</sup>

Dispone di **24 canali** collegabili ai punti di test della scheda. Enumera le combinazioni candidate di pin usando scansioni **IDCODE** e **BYPASS**, quindi indica i canali corrispondenti ai segnali JTAG rilevati.

Un metodo più economico, ma molto più lento, per identificare i pin JTAG consiste nell’usare [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Con **JTAGenum**, definisci innanzitutto i pin del microcontrollore di probing da usare per l’enumerazione. Consulta il relativo pinout, quindi collega quei pin ai punti di test candidati sulla scheda target.<sup>[[3]](#references)</sup>

Un **terzo metodo** per identificare i pin JTAG consiste nell’**ispezionare la PCB** alla ricerca di un’impronta nota. Alcune schede espongono un’impronta **Tag-Connect**, anche se Tag-Connect è un sistema di connettori che può trasportare JTAG, SWD, UART o un’altra interfaccia: da sola, non dimostra che i pin siano JTAG. Le schede tecniche dei componenti e le misurazioni di continuità possono quindi aiutare a identificare i segnali effettivi.<sup>[[5]](#references)</sup>

## SDW

SWD è un’interfaccia di debug a due pin e basata su pacchetti di Arm.<sup>[[4]](#references)</sup>

L’interfaccia usa **SWDIO** bidirezionale per i dati e **SWCLK** per il clock. Molti dispositivi implementano un **Serial Wire/JTAG Debug Port (SWJ-DP)** che consente di selezionare SWD o JTAG su pin condivisi.<sup>[[4]](#references)</sup>

## References

- [1] [Gruppo di lavoro IEEE 1149.1 — JTAG e boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentazione JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumerazione dei pin JTAG su Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfacce di debug a basso numero di pin per sistemi multi-dispositivo](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Impronte per cavi di debug e programmazione](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
