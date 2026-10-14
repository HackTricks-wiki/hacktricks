# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

Per un dispositivo a cui si ha accesso fisico, si parte dalle interfacce esposte dalla scheda o dai segnali: [console seriali UART](uart.md), [accesso debug JTAG/SWD](jtag.md), bus [I²C](i2c.md) e [flash SPI](spi.md). [L'analisi side-channel](side_channel_analysis.md) e [la fault injection](fault_injection_attacks.md) affrontano attività diverse di misurazione e glitching; [l'analisi dei segnali radio](radio.md) riguarda un punto di accesso over-the-air. Prima di collegare gli strumenti, controlla i livelli elettrici del target e le limitazioni descritte nel capitolo pertinente.

## JTAG

JTAG (IEEE 1149.1) supporta il boundary-scan testing tramite celle posizionate intorno ai pin I/O di un dispositivo. Molti processori espongono anche funzioni di debug specifiche del vendor attraverso lo stesso Test Access Port (TAP); il boundary scan e il debugging della CPU sono usi correlati di JTAG, non sinonimi.<sup>[[1]](#references)</sup>

Lo standard JTAG definisce **comandi specifici per eseguire boundary scan**, tra cui:

- **BYPASS** seleziona un registro bypass a un bit, così da poter raggiungere gli altri dispositivi in una scan chain con un overhead minimo.
- **SAMPLE/PRELOAD** acquisisce i valori dei pin durante il normale funzionamento e può precaricare il registro boundary-scan prima di un'altra istruzione.
- **EXTEST** imposta e legge gli stati dei pin.

Può supportare anche altri comandi, come:

- **IDCODE** per identificare un dispositivo
- **INTEST** per il test interno del dispositivo

Potresti incontrare queste istruzioni usando uno strumento come JTAGulator.

### The Test Access Port

Il **Test Access Port (TAP)** fornisce accesso alla logica di test JTAG di un componente. Sono necessari quattro segnali e `TRST` è opzionale:<sup>[[1]](#references)</sup>

- Ingresso del clock di test (**TCK**) TCK è il **clock** che determina ogni quanto il controller TAP esegue una singola azione (in altre parole, passa allo stato successivo della macchina a stati).
- Ingresso di selezione della modalità di test (**TMS**) TMS controlla la **macchina a stati finiti**. A ogni impulso del clock, il controller JTAG TAP del dispositivo controlla la tensione sul pin TMS. Se la tensione è inferiore a una certa soglia, il segnale è considerato basso e interpretato come 0; se invece è superiore a una certa soglia, il segnale è considerato alto e interpretato come 1.
- Ingresso dei dati di test (**TDI**) sposta in serie istruzioni o dati di test nel registro TAP selezionato. IEEE 1149.1 definisce il comportamento di trasferimento del TAP, mentre i vendor definiscono le istruzioni opzionali e i registri di debug.
- Uscita dei dati di test (**TDO**) TDO è il pin che invia i **dati fuori dal chip**.
- Ingresso di reset del test (**TRST**) Il TRST opzionale riporta la macchina a stati finiti **a uno stato noto e sicuro**. In alternativa, tenendo TMS a 1 per cinque cicli di clock consecutivi si attiva un reset, come avverrebbe usando il pin TRST; per questo TRST è opzionale.

A volte è possibile trovare questi pin contrassegnati sulla PCB. In altri casi, potresti doverli **individuare**.

### Identificare i pin JTAG

Un'opzione rapida, progettata appositamente per individuare le porte JTAG, ma relativamente costosa, è **JTAGulator**, che può anche identificare i pinout UART.<sup>[[2]](#references)</sup>

Dispone di **24 canali** che possono essere collegati ai punti di test della scheda. Enumera le combinazioni candidate di pin usando scansioni **IDCODE** e **BYPASS** e indica i canali corrispondenti ai segnali JTAG rilevati.

Un metodo più economico, ma molto più lento, per identificare i pinout JTAG consiste nell'usare [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Con **JTAGenum**, per prima cosa definisci i pin del microcontrollore di probing da usare per l'enumerazione. Consulta il suo pinout, quindi collega questi pin ai punti di test candidati sulla scheda target.<sup>[[3]](#references)</sup>

Un **terzo metodo** per identificare i pin JTAG consiste nell'**ispezionare la PCB** alla ricerca di un footprint noto. Alcune schede espongono un footprint **Tag-Connect**, anche se Tag-Connect è un sistema di connettori che può trasportare JTAG, SWD, UART o un'altra interfaccia: da solo, non dimostra che i pin siano JTAG. Le schede tecniche dei componenti e le misurazioni di continuità possono quindi aiutare a identificare i segnali effettivi.<sup>[[5]](#references)</sup>

## SDW

SWD è un'interfaccia di debug Arm a due pin e basata su pacchetti.<sup>[[4]](#references)</sup>

L'interfaccia usa **SWDIO** bidirezionale per i dati e **SWCLK** per il clock. Molti dispositivi implementano un **Serial Wire/JTAG Debug Port (SWJ-DP)** che consente di selezionare SWD o JTAG sugli stessi pin.<sup>[[4]](#references)</sup>

## References

- [1] [Gruppo di lavoro IEEE 1149.1 — JTAG e boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentazione di JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Enumerazione dei pin JTAG con Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfacce di debug a basso numero di pin per sistemi multi-dispositivo](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprint per cavi di debug e programmazione](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
