# FZ - Infrarosso

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Per maggiori informazioni sul funzionamento dell'infrarosso, consulta:


{{#ref}}
../infrared.md
{{#endref}}

## Ricevitore di segnali IR in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero usa un ricevitore IR demodulante per acquisire i segnali dei comuni telecomandi IR. Alcuni telefoni, inclusi determinati modelli Xiaomi, hanno un trasmettitore IR, ma la maggior parte non è in grado di ricevere e decodificare i segnali dei telecomandi.<sup>[[1]](#references)</sup>

Il **ricevitore** a infrarossi di Flipper è **piuttosto sensibile**. Puoi persino **intercettare il segnale** restando **in un punto intermedio** tra il telecomando e la TV. Non è necessario puntare il telecomando direttamente verso la porta IR di Flipper. Questo è utile quando qualcuno cambia canale vicino alla TV e sia tu sia Flipper siete a una certa distanza.

La decodifica del protocollo avviene via software. I protocolli riconosciuti possono essere memorizzati come comandi decodificati; quelli non supportati possono essere acquisiti e riprodotti come dati temporali grezzi, nel rispetto dei limiti di frequenza portante e temporizzazione dell'hardware.<sup>[[1]](#references)</sup>

## Azioni

### Telecomandi universali

La modalità telecomando universale di Flipper Zero scorre i comandi noti del suo database a infrarossi per TV, apparecchiature audio, proiettori e condizionatori supportati. Non è garantito che controlli ogni dispositivo e va usata solo su apparecchiature di tua proprietà o che sei autorizzato a testare.<sup>[[1]](#references)</sup>

È sufficiente premere il pulsante di accensione in modalità telecomando universale: Flipper invierà **in sequenza i comandi "Power Off"** per tutte le TV che conosce: Sony, Samsung, Panasonic... e così via. Quando la TV riceve il segnale, reagirà e si spegnerà.

Questo tipo di brute-force richiede tempo. Più ampio è il dizionario, più tempo ci vorrà per completare l'operazione. Non è possibile sapere quale segnale abbia riconosciuto esattamente la TV, poiché non c'è alcun feedback da parte sua.

### Acquisire un nuovo telecomando

Flipper Zero può **acquisire un segnale a infrarossi**. Se riconosce il protocollo e il comando, ne memorizza una rappresentazione decodificata; altrimenti, può memorizzare i dati temporali grezzi per riprodurli in seguito.<sup>[[1]](#references)</sup>

## References

- [1] [Prendere il controllo delle TV con la porta a infrarossi di Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
