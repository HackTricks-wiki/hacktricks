# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG consente di eseguire una boundary scan. La boundary scan analizza determinati circuiti, incluse le boundary-scan cells integrate e i registri per ciascun pin.

Lo standard JTAG definisce **comandi specifici per eseguire boundary scan**, tra cui:

- **BYPASS** consente di testare uno specifico chip senza il sovraccarico dovuto al passaggio attraverso altri chip.
- **SAMPLE/PRELOAD** acquisisce un campione dei dati in ingresso e in uscita dal dispositivo quando si trova nella sua modalità di funzionamento normale.
- **EXTEST** imposta e legge gli stati dei pin.

Può inoltre supportare altri comandi, come:

- **IDCODE** per identificare un dispositivo
- **INTEST** per il test interno del dispositivo

Potresti incontrare queste istruzioni quando usi uno strumento come JTAGulator.

### The Test Access Port

Le boundary scan includono test della porta a quattro fili **Test Access Port (TAP)**, una porta generica che fornisce **accesso alle funzioni di supporto ai test JTAG** integrate in un componente. TAP utilizza i seguenti cinque segnali:

- Ingresso del test clock (**TCK**) TCK è il **clock** che definisce con quale frequenza il controller TAP eseguirà una singola azione (in altre parole, passerà allo stato successivo nella macchina a stati).
- Ingresso Test mode select (**TMS**) TMS controlla la **finite state machine**. A ogni impulso del clock, il controller JTAG TAP del dispositivo verifica la tensione sul pin TMS. Se la tensione è inferiore a una determinata soglia, il segnale viene considerato basso e interpretato come 0, mentre se la tensione è superiore a una determinata soglia, il segnale viene considerato alto e interpretato come 1.
- Ingresso Test data input (**TDI**) TDI è il pin che invia **dati nel chip attraverso le scan cells**. Ogni vendor è responsabile della definizione del protocollo di comunicazione su questo pin, perché JTAG non lo definisce.
- Uscita Test data output (**TDO**) TDO è il pin che invia **dati fuori dal chip**.
- Ingresso Test reset (**TRST**) L'ingresso opzionale TRST reimposta la finite state machine **a uno stato noto e funzionante**. In alternativa, se TMS viene mantenuto a 1 per cinque cicli di clock consecutivi, viene eseguito un reset, nello stesso modo in cui verrebbe eseguito dal pin TRST; per questo TRST è opzionale.

A volte sarà possibile trovare questi pin contrassegnati sul PCB. In altri casi potrebbe essere necessario **trovarli**.

### Identifying JTAG pins

Il modo più rapido, ma più costoso, per rilevare le porte JTAG consiste nell'utilizzare **JTAGulator**, un dispositivo creato appositamente per questo scopo (anche se può **rilevare anche i pinout UART**).

Dispone di **24 canali** che puoi collegare ai pin della scheda. Esegue quindi un **BF attack** di tutte le combinazioni possibili, inviando i comandi di boundary scan **IDCODE** e **BYPASS**. Se riceve una risposta, mostra il canale corrispondente a ciascun segnale JTAG.

Un modo più economico, ma molto più lento, per identificare i pinout JTAG consiste nell'utilizzare [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Utilizzando **JTAGenum**, per prima cosa dovresti **definire i pin del dispositivo di probing** che userai per l'enumerazione. Dovresti fare riferimento allo schema del pinout del dispositivo e poi collegare questi pin ai test point del dispositivo target.

Un **terzo modo** per identificare i pin JTAG consiste nell'**ispezionare il PCB** alla ricerca di uno dei pinout. In alcuni casi, i PCB potrebbero fornire comodamente l'**interfaccia Tag-Connect**, una chiara indicazione del fatto che la scheda dispone anche di un connettore JTAG. Puoi vedere l'aspetto di questa interfaccia all'indirizzo [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Inoltre, l'ispezione dei **datasheet dei chipset sul PCB** potrebbe rivelare schemi dei pinout che indicano la presenza di interfacce JTAG.

## SDW

SWD è un protocollo specifico di ARM progettato per il debugging.

L'interfaccia SWD richiede **due pin**: un segnale bidirezionale **SWDIO**, equivalente ai **pin TDI e TDO e a un clock** di JTAG, e **SWCLK**, equivalente a **TCK** in JTAG. Molti dispositivi supportano il **Serial Wire or JTAG Debug Port (SWJ-DP)**, un'interfaccia combinata JTAG e SWD che consente di collegare al target una probe SWD o JTAG.

{{#include ../../banners/hacktricks-training.md}}
