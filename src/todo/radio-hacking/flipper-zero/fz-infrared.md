# FZ - Infrarossi

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Per maggiori informazioni sul funzionamento degli infrarossi, consulta:


{{#ref}}
../infrared.md
{{#endref}}

## Ricevitore di segnali IR in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero utilizza un ricevitore IR demodulante per catturare i segnali dei comuni telecomandi IR. Alcuni telefoni, inclusi determinati modelli Xiaomi, integrano un trasmettitore IR, ma la maggior parte non è in grado di ricevere e decodificare i segnali dei telecomandi.<sup>[[1]](#references)</sup>

Il **ricevitore a infrarossi di Flipper è molto sensibile**. Puoi persino **captare il segnale** rimanendo **da qualche parte tra** il telecomando e il televisore. Non è necessario puntare direttamente il telecomando verso la porta IR di Flipper. Questo è utile quando qualcuno cambia canale stando vicino al televisore, mentre tu e Flipper vi trovate a una certa distanza.

La decodifica del protocollo avviene nel software. I protocolli riconosciuti possono essere salvati come comandi decodificati; i protocolli non supportati possono essere catturati e riprodotti come dati grezzi di temporizzazione, entro i limiti della frequenza portante e della temporizzazione dell'hardware.<sup>[[1]](#references)</sup>

## Azioni

### Telecomandi universali

La modalità telecomando universale di Flipper Zero scorre i comandi conosciuti dal suo database di infrarossi per televisori, apparecchiature audio, proiettori e condizionatori supportati. Non è garantito che controlli ogni dispositivo e deve essere utilizzata solo su apparecchiature di tua proprietà o che sei autorizzato a testare.<sup>[[1]](#references)</sup>

È sufficiente premere il pulsante di accensione nella modalità Telecomando universale: Flipper invierà **in sequenza i comandi "Power Off"** di tutti i televisori che conosce: Sony, Samsung, Panasonic... e così via. Quando il televisore riceve il segnale corrispondente, reagirà spegnendosi.

Questo brute-force richiede tempo. Più grande è il dizionario, più tempo sarà necessario per completare l'operazione. Non è possibile sapere quale segnale sia stato riconosciuto esattamente dal televisore, poiché non viene fornito alcun feedback dal televisore.

### Apprendere un nuovo telecomando

Flipper Zero può **catturare un segnale a infrarossi**. Se riconosce il protocollo e il comando, salva una rappresentazione decodificata; altrimenti può salvare i dati grezzi di temporizzazione per la successiva riproduzione.<sup>[[1]](#references)</sup>

## References

- [1] [Acquisire il controllo dei televisori con la porta a infrarossi di Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
