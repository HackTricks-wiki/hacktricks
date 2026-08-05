# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

iButton è un nome generico per una chiave elettronica di identificazione racchiusa in un **contenitore metallico a forma di moneta**. È anche chiamata Memory Dallas Touch o contact memory. Sebbene venga spesso definita erroneamente una chiave “magnetica”, al suo interno **non c'è nulla di magnetico**. In realtà, al suo interno è nascosto un vero e proprio **microchip** che opera tramite un protocollo digitale.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Cos'è iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Di solito, iButton indica la forma fisica della chiave e del lettore: una moneta rotonda con due contatti. Per la struttura che la circonda esistono numerose varianti, dal più comune supporto in plastica con un foro a anelli, pendenti, ecc.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando la chiave raggiunge il lettore, i **contatti entrano in contatto** e la chiave viene alimentata per **trasmettere** il proprio ID. A volte la chiave **non viene letta** immediatamente perché il **PSD dei contatti di un intercom è più grande** del dovuto. Di conseguenza, i contorni esterni della chiave e del lettore potrebbero non entrare in contatto. In tal caso, sarà necessario premere la chiave contro una delle pareti del lettore.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocollo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Le chiavi Dallas scambiano dati utilizzando il protocollo 1-wire, con un solo contatto per il trasferimento dei dati (!!) in entrambe le direzioni: dal master allo slave e viceversa. Il protocollo 1-wire funziona secondo il modello Master-Slave. In questa topologia, il Master avvia sempre la comunicazione e lo Slave segue le sue istruzioni.

Quando la chiave (Slave) entra in contatto con l'intercom (Master), il chip all'interno della chiave si accende, alimentato dall'intercom, e la chiave viene inizializzata. Dopodiché, l'intercom richiede l'ID della chiave. Di seguito analizzeremo questo processo in maggiore dettaglio.

Flipper può funzionare sia in modalità Master sia in modalità Slave. In modalità di lettura delle chiavi, Flipper agisce come un lettore, ovvero funziona come Master. In modalità di emulazione della chiave, Flipper finge di essere una chiave e opera in modalità Slave.

### Chiavi Dallas, Cyfral e Metakom

Per informazioni sul funzionamento di queste chiavi, consulta la pagina [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attacchi

Gli iButton possono essere attaccati con Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Riferimenti

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
