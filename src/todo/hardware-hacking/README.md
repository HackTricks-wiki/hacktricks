# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG consente di eseguire una scansione dei confini. La scansione dei confini analizza alcuni circuiti, inclusi i circuiti integrati di scansione e i registri incorporati per ogni pin.

Lo standard JTAG definisce **comandi specifici per condurre scansioni dei confini**, inclusi i seguenti:

- **BYPASS** consente di testare un chip specifico senza il sovraccarico di passare attraverso altri chip.
- **SAMPLE/PRELOAD** prende un campione dei dati che entrano ed escono dal dispositivo quando è nella sua modalità di funzionamento normale.
- **EXTEST** imposta e legge gli stati dei pin.

Può anche supportare altri comandi come:

- **IDCODE** per identificare un dispositivo
- **INTEST** per il test interno del dispositivo

Potresti imbatterti in queste istruzioni quando utilizzi uno strumento come il JTAGulator.

### The Test Access Port

Le scansioni dei confini includono test del **Test Access Port (TAP)** a quattro fili, una porta di uso generale che fornisce **accesso alle funzioni di supporto ai test JTAG** integrate in un componente. TAP utilizza i seguenti cinque segnali:

- Test clock input (**TCK**) Il TCK è il **clock** che definisce quanto spesso il controller TAP eseguirà un'azione singola (in altre parole, salterà al prossimo stato nella macchina a stati).
- Test mode select (**TMS**) input TMS controlla la **macchina a stati finiti**. Ad ogni battito del clock, il controller TAP JTAG del dispositivo controlla la tensione sul pin TMS. Se la tensione è al di sotto di una certa soglia, il segnale è considerato basso e interpretato come 0, mentre se la tensione è al di sopra di una certa soglia, il segnale è considerato alto e interpretato come 1.
- Test data input (**TDI**) TDI è il pin che invia **dati nel chip attraverso le celle di scansione**. Ogni fornitore è responsabile della definizione del protocollo di comunicazione su questo pin, poiché JTAG non lo definisce.
- Test data output (**TDO**) TDO è il pin che invia **dati fuori dal chip**.
- Test reset (**TRST**) input Il TRST opzionale ripristina la macchina a stati finiti **a uno stato noto buono**. In alternativa, se il TMS è mantenuto a 1 per cinque cicli di clock consecutivi, invoca un ripristino, nello stesso modo in cui farebbe il pin TRST, motivo per cui TRST è opzionale.

A volte sarai in grado di trovare quei pin contrassegnati nel PCB. In altre occasioni potresti dover **trovarli**.

### Identifying JTAG pins

Il modo più veloce ma più costoso per rilevare le porte JTAG è utilizzare il **JTAGulator**, un dispositivo creato specificamente per questo scopo (anche se può **rilevare anche i pin UART**).

Ha **24 canali** che puoi collegare ai pin delle schede. Poi esegue un **attacco BF** di tutte le possibili combinazioni inviando comandi di scansione dei confini **IDCODE** e **BYPASS**. Se riceve una risposta, visualizza il canale corrispondente a ciascun segnale JTAG.

Un modo più economico ma molto più lento per identificare i pin JTAG è utilizzare il [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) caricato su un microcontrollore compatibile con Arduino.

Utilizzando **JTAGenum**, dovresti prima **definire i pin del dispositivo di sondaggio** che utilizzerai per l'enumerazione. Dovresti fare riferimento al diagramma dei pin del dispositivo e poi collegare questi pin ai punti di test sul tuo dispositivo target.

Un **terzo modo** per identificare i pin JTAG è **ispezionare il PCB** per uno dei pinout. In alcuni casi, i PCB potrebbero fornire convenientemente l'**interfaccia Tag-Connect**, che è un chiaro indicatore che la scheda ha anche un connettore JTAG. Puoi vedere come appare quell'interfaccia su [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Inoltre, ispezionare i **datasheet dei chip sul PCB** potrebbe rivelare diagrammi dei pin che indicano interfacce JTAG.

## SDW

SWD è un protocollo specifico per ARM progettato per il debug.

L'interfaccia SWD richiede **due pin**: un segnale bidirezionale **SWDIO**, che è l'equivalente dei pin **TDI e TDO di JTAG** e un clock, e **SWCLK**, che è l'equivalente di **TCK** in JTAG. Molti dispositivi supportano il **Serial Wire o JTAG Debug Port (SWJ-DP)**, un'interfaccia combinata JTAG e SWD che ti consente di collegare un sondino SWD o JTAG al target.

{{#include ../../banners/hacktricks-training.md}}
