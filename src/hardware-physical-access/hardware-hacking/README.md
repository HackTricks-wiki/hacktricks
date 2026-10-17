# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

Per un dispositivo a cui si ha accesso fisico, si parte dalle interfacce esposte dalla scheda o dai segnali: [console seriali UART](uart.md), [accesso debug JTAG/SWD](jtag.md), [tracciamento delle istruzioni CoreSight](arm-coresight-instruction-tracing.md), bus [I²C](i2c.md) e [flash SPI](spi.md). [L'analisi side-channel](side_channel_analysis.md) e [il fault injection](fault_injection_attacks.md) riguardano attività diverse di misurazione e glitching; [l'analisi dei segnali radio](radio.md) tratta un punto di ingresso over-the-air. Per le procedure specifiche al target relative a RFID/NFC, sub-GHz, infrarossi, BLE, LoRaWAN e iButton, consulta [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Prima di collegare gli strumenti, verifica i livelli elettrici del target e le limitazioni indicate nel capitolo pertinente.

## JTAG

JTAG (IEEE 1149.1) supporta i test boundary-scan tramite celle disposte intorno ai pin I/O di un dispositivo. Molti processori espongono anche funzioni di debug specifiche del vendor attraverso lo stesso Test Access Port (TAP); boundary scan e debug della CPU sono usi correlati di JTAG, non sinonimi.<sup>[[1]](#references)</sup>

Lo standard JTAG definisce **comandi specifici per eseguire scansioni boundary-scan**, tra cui:

- **BYPASS** seleziona un registro bypass a un bit, così da poter raggiungere gli altri dispositivi in una scan chain con un overhead minimo.
- **SAMPLE/PRELOAD** acquisisce i valori dei pin durante il normale funzionamento e può precaricare il registro boundary-scan prima di un'altra istruzione.
- **EXTEST** imposta e legge gli stati dei pin.

Può inoltre supportare altri comandi, come:

- **IDCODE** per identificare un dispositivo
- **INTEST** per il test interno del dispositivo

Potresti incontrare queste istruzioni utilizzando uno strumento come JTAGulator.

### Il Test Access Port

Il **Test Access Port (TAP)** fornisce accesso alla logica di test JTAG di un componente. Sono necessari quattro segnali, mentre `TRST` è opzionale:<sup>[[1]](#references)</sup>

- Ingresso clock di test (**TCK**) TCK è il **clock** che definisce con quale frequenza il controller TAP esegue una singola azione (in altre parole, passa allo stato successivo della macchina a stati).
- Ingresso di selezione della modalità di test (**TMS**) TMS controlla la **macchina a stati finiti**. A ogni impulso di clock, il controller JTAG TAP del dispositivo controlla la tensione sul pin TMS. Se la tensione è inferiore a una certa soglia, il segnale viene considerato basso e interpretato come 0; se supera tale soglia, viene considerato alto e interpretato come 1.
- Ingresso dati di test (**TDI**) trasferisce serialmente le istruzioni o i dati di test nel registro TAP selezionato. IEEE 1149.1 definisce il comportamento del trasferimento TAP, mentre i vendor definiscono le istruzioni opzionali e i registri di debug.
- Uscita dati di test (**TDO**) TDO è il pin che invia **i dati fuori dal chip**.
- Ingresso di reset del test (**TRST**) Il TRST opzionale resetta la macchina a stati finiti **portandola a uno stato noto e valido**. In alternativa, mantenendo TMS a 1 per cinque cicli di clock consecutivi si attiva un reset, proprio come con il pin TRST, motivo per cui TRST è opzionale.

A volte è possibile trovare questi pin indicati sulla PCB. In altri casi potrebbe essere necessario **individuarli**.

### Identificazione dei pin JTAG

Un'opzione rapida, progettata appositamente per rilevare le porte JTAG, ma relativamente costosa, è **JTAGulator**, che può anche identificare i pinout UART.<sup>[[2]](#references)</sup>

Dispone di **24 canali** collegabili ai punti di test della scheda. Enumera le combinazioni candidate di pin usando scansioni **IDCODE** e **BYPASS** e segnala i canali corrispondenti ai segnali JTAG rilevati.

Un metodo più economico ma molto più lento per identificare i pinout JTAG consiste nell'usare [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Con **JTAGenum**, definisci innanzitutto i pin del microcontrollore di probing usati per l'enumerazione. Consulta il relativo pinout, quindi collega quei pin ai punti di test candidati sulla scheda target.<sup>[[3]](#references)</sup>

Un **terzo metodo** per identificare i pin JTAG consiste nell'**ispezionare la PCB** alla ricerca di un footprint noto. Alcune schede espongono un footprint **Tag-Connect**, ma Tag-Connect è un sistema di connettori che può trasportare JTAG, SWD, UART o un'altra interfaccia: la sua presenza non dimostra, da sola, che i pin siano JTAG. Le schede tecniche dei componenti e le misurazioni di continuità possono quindi aiutare a identificare i segnali effettivi.<sup>[[5]](#references)</sup>

## SDW

SWD è un'interfaccia di debug Arm a due pin basata su pacchetti.<sup>[[4]](#references)</sup>

L'interfaccia usa **SWDIO** bidirezionale per i dati e **SWCLK** per il clock. Molti dispositivi implementano un **Serial Wire/JTAG Debug Port (SWJ-DP)** che consente di selezionare SWD o JTAG sui pin condivisi.<sup>[[4]](#references)</sup>

## References

- [1] [Gruppo di lavoro IEEE 1149.1 — JTAG e boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentazione JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Enumerazione dei pin JTAG con Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfacce di debug a basso numero di pin per sistemi multi-dispositivo](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprint per cavi di debug e programmazione](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
