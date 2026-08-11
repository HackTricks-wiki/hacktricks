# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) supporta i test boundary-scan tramite celle posizionate attorno ai pin di I/O di un dispositivo. Molti processori espongono anche funzioni di debug specifiche del vendor attraverso lo stesso Test Access Port (TAP); il boundary scan e il debugging della CPU sono utilizzi correlati di JTAG, non sinonimi.<sup>[[1]](#references)</sup>

Lo standard JTAG definisce **comandi specifici per eseguire boundary scan**, tra cui:

- **BYPASS** seleziona un registro di bypass a un bit, consentendo di raggiungere gli altri dispositivi in una catena di scansione con un overhead minimo.
- **SAMPLE/PRELOAD** acquisisce i valori dei pin durante il normale funzionamento e può precaricare il registro boundary-scan prima di un'altra istruzione.
- **EXTEST** imposta e legge gli stati dei pin.

Può inoltre supportare altri comandi, come:

- **IDCODE** per identificare un dispositivo
- **INTEST** per il test interno del dispositivo

Potresti incontrare queste istruzioni quando usi uno strumento come JTAGulator.

### Il Test Access Port

Il **Test Access Port (TAP)** fornisce l'accesso alla logica di test JTAG di un componente. Sono necessari quattro segnali e `TRST` è opzionale:<sup>[[1]](#references)</sup>

- Ingresso del clock di test (**TCK**) TCK è il **clock** che definisce la frequenza con cui il controller TAP esegue una singola azione (in altre parole, passa allo stato successivo nella macchina a stati).
- Ingresso di selezione della modalità di test (**TMS**) TMS controlla la **macchina a stati finiti**. A ogni ciclo del clock, il controller JTAG TAP del dispositivo controlla la tensione sul pin TMS. Se la tensione è inferiore a una determinata soglia, il segnale viene considerato basso e interpretato come 0; se la tensione è superiore a una determinata soglia, il segnale viene considerato alto e interpretato come 1.
- Ingresso dei dati di test (**TDI**) sposta istruzioni seriali o dati di test nel registro TAP selezionato. IEEE 1149.1 definisce il comportamento del trasferimento TAP, mentre i vendor definiscono istruzioni opzionali e registri di debug.
- Uscita dei dati di test (**TDO**) TDO è il pin che invia **i dati fuori dal chip**.
- Ingresso del reset di test (**TRST**) Il TRST opzionale reimposta la macchina a stati finiti **a uno stato noto e funzionante**. In alternativa, se TMS viene mantenuto a 1 per cinque cicli consecutivi del clock, viene eseguito un reset, nello stesso modo in cui verrebbe utilizzato il pin TRST; per questo TRST è opzionale.

A volte potrai trovare questi pin contrassegnati sulla PCB. In altri casi potresti doverli **individuare**.

### Identificazione dei pin JTAG

Un'opzione rapida e progettata appositamente, ma relativamente costosa, per rilevare le porte JTAG è **JTAGulator**, che può anche identificare i pinout UART.<sup>[[2]](#references)</sup>

Dispone di **24 canali** collegabili ai test point della scheda. Enumera le combinazioni candidate di pin usando scansioni **IDCODE** e **BYPASS** e segnala i canali corrispondenti ai segnali JTAG rilevati.

Un metodo più economico, ma molto più lento, per identificare i pinout JTAG consiste nell'utilizzare [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Con **JTAGenum**, definisci innanzitutto i pin del microcontrollore di probing utilizzati per l'enumerazione. Consulta il relativo pinout, quindi collega questi pin ai test point candidati sulla scheda target.<sup>[[3]](#references)</sup>

Un **terzo metodo** per identificare i pin JTAG consiste nell'**ispezionare la PCB** alla ricerca di un footprint noto. Alcune schede espongono un footprint **Tag-Connect**, anche se Tag-Connect è un sistema di connettori che può trasportare JTAG, SWD, UART o un'altra interfaccia: da solo non dimostra che i pin siano JTAG. I datasheet dei componenti e le misurazioni di continuità possono quindi identificare i segnali effettivi.<sup>[[5]](#references)</sup>

## SDW

SWD è l'interfaccia di debug a due pin e basata su pacchetti di Arm.<sup>[[4]](#references)</sup>

L'interfaccia utilizza **SWDIO** bidirezionale per i dati e **SWCLK** per il clock. Molti dispositivi implementano una **Serial Wire/JTAG Debug Port (SWJ-DP)** che consente di selezionare SWD o JTAG su pin condivisi.<sup>[[4]](#references)</sup>

## References

- [1] [Gruppo di lavoro IEEE 1149.1 — JTAG e boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentazione di JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Enumerazione dei pin JTAG con Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfacce di debug con pochi pin per sistemi multi-dispositivo](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprint per cavi di debug e programmazione](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
