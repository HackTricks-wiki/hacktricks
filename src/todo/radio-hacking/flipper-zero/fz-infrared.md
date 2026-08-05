# FZ - Infrarossi

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Per maggiori informazioni sul funzionamento degli infrarossi, consulta:


{{#ref}}
../infrared.md
{{#endref}}

## Ricevitore di segnali IR in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utilizza un ricevitore di segnali IR digitale TSOP, che **consente di intercettare i segnali dei telecomandi IR**. Esistono alcuni **smartphone** come Xiaomi che dispongono anch'essi di una porta IR, ma tieni presente che **la maggior parte di essi può solo trasmettere** segnali e **non è in grado di riceverli**.<sup>[[1]](#references)</sup>

Il **ricevitore a infrarossi di Flipper è piuttosto sensibile**. Puoi persino **catturare il segnale** rimanendo **in un punto intermedio** tra il telecomando e la TV. Non è necessario puntare direttamente il telecomando verso la porta IR di Flipper. Questo è utile quando qualcuno cambia canale vicino alla TV e sia tu sia Flipper vi trovate a una certa distanza.

Poiché la **decodifica del segnale a infrarossi** avviene sul lato **software**, Flipper Zero supporta potenzialmente la **ricezione e la trasmissione di qualsiasi codice per telecomandi IR**. Nel caso di protocolli **sconosciuti** che non possono essere riconosciuti, **registra e riproduce** il segnale grezzo esattamente come è stato ricevuto.<sup>[[1]](#references)</sup>

## Azioni

### Telecomandi universali

Flipper Zero può essere utilizzato come **telecomando universale per controllare qualsiasi TV, condizionatore o media center**. In questa modalità, Flipper **bruteforces** tutti i **codici conosciuti** di tutti i produttori supportati **in base al dizionario presente sulla scheda SD**. Non è necessario scegliere un telecomando specifico per spegnere la TV di un ristorante.<sup>[[1]](#references)</sup>

È sufficiente premere il pulsante di accensione nella modalità Universal Remote e Flipper invierà **sequenzialmente i comandi "Power Off"** di tutti i televisori che conosce: Sony, Samsung, Panasonic... e così via. Quando la TV riceve il segnale, reagirà e si spegnerà.

Questo brute-force richiede tempo. Più grande è il dizionario, più tempo sarà necessario per completare l'operazione. È impossibile sapere quale segnale sia stato riconosciuto esattamente dalla TV, poiché non c'è alcun feedback da parte del televisore.

### Apprendere un nuovo telecomando

È possibile **catturare un segnale a infrarossi** con Flipper Zero. Se **trova il segnale nel database**, Flipper **riconoscerà automaticamente il dispositivo** e ti permetterà di interagirci.\
Se non lo trova, Flipper può **memorizzare** il **segnale** e consentirti di **riprodurlo**.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
