# FZ - Infrarossi

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Per ulteriori informazioni su come funziona l'infrarosso, controlla:

{{#ref}}
../infrared.md
{{#endref}}

## Ricevitore di segnale IR in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utilizza un ricevitore di segnale IR digitale TSOP, che **consente di intercettare segnali da telecomandi IR**. Ci sono alcuni **smartphone** come Xiaomi, che hanno anche una porta IR, ma tieni presente che **la maggior parte di essi può solo trasmettere** segnali e **non è in grado di riceverli**.

Il **ricevitore infrarosso di Flipper è piuttosto sensibile**. Puoi anche **catturare il segnale** rimanendo **da qualche parte in mezzo** tra il telecomando e la TV. Puntare il telecomando direttamente sulla porta IR di Flipper non è necessario. Questo è utile quando qualcuno sta cambiando canale mentre si trova vicino alla TV, e sia tu che Flipper siete a una certa distanza.

Poiché la **decodifica del segnale infrarosso** avviene sul lato **software**, Flipper Zero supporta potenzialmente la **ricezione e trasmissione di qualsiasi codice remoto IR**. Nel caso di protocolli **sconosciuti** che non possono essere riconosciuti - **registra e riproduce** il segnale grezzo esattamente come ricevuto.

## Azioni

### Telecomandi Universali

Flipper Zero può essere utilizzato come un **telecomando universale per controllare qualsiasi TV, condizionatore d'aria o centro multimediale**. In questa modalità, Flipper **esegue un attacco di forza bruta** su tutti i **codici noti** di tutti i produttori supportati **secondo il dizionario della scheda SD**. Non è necessario scegliere un telecomando particolare per spegnere una TV in un ristorante.

Basta premere il pulsante di accensione nella modalità Telecomando Universale, e Flipper **invierà "Power Off"** in sequenza per tutte le TV che conosce: Sony, Samsung, Panasonic... e così via. Quando la TV riceve il suo segnale, reagirà e si spegnerà.

Tale attacco di forza bruta richiede tempo. Più grande è il dizionario, più a lungo ci vorrà per completarlo. È impossibile scoprire quale segnale esattamente la TV ha riconosciuto poiché non c'è feedback dalla TV.

### Impara Nuovo Telecomando

È possibile **catturare un segnale infrarosso** con Flipper Zero. Se **trova il segnale nel database**, Flipper **saprà automaticamente a quale dispositivo si riferisce** e ti permetterà di interagire con esso.\
Se non lo trova, Flipper può **memorizzare** il **segnale** e ti permetterà di **riprodurlo**.

## Riferimenti

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
