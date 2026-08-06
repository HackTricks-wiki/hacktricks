# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

iButton è un nome generico per una chiave di identificazione elettronica racchiusa in un **contenitore metallico a forma di moneta**. È anche chiamata memoria **Dallas Touch** o memoria a contatto. Sebbene venga spesso indicata erroneamente come chiave “magnetica”, al suo interno **non c'è nulla di magnetico**. Infatti, al suo interno è nascosto un vero e proprio **microchip** che opera tramite un protocollo digitale.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Cos'è iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Di solito, iButton indica la forma fisica della chiave e del lettore: una moneta rotonda con due contatti. Per quanto riguarda la struttura che la circonda, esistono numerose varianti, dal più comune supporto in plastica con un foro fino ad anelli, pendenti, ecc.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando la chiave raggiunge il lettore, i **contatti entrano in contatto** e la chiave viene alimentata per **trasmettere** il proprio ID. A volte la chiave **non viene letta** immediatamente perché il **PSD dei contatti di un citofono è più grande** del dovuto. Di conseguenza, i contorni esterni della chiave e del lettore potrebbero non entrare in contatto. In tal caso, sarà necessario premere la chiave contro una delle pareti del lettore.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocollo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Le chiavi Dallas scambiano dati utilizzando il protocollo 1-wire, con un solo contatto per il trasferimento dei dati (!!) in entrambe le direzioni, dal master allo slave e viceversa. Il protocollo 1-wire funziona secondo il modello Master-Slave. In questa topologia, il Master avvia sempre la comunicazione e lo Slave segue le sue istruzioni.

Quando la chiave (Slave) entra in contatto con il citofono (Master), il chip all'interno della chiave si accende, alimentato dal citofono, e la chiave viene inizializzata. Successivamente, il citofono richiede l'ID della chiave. Esamineremo ora questo processo più nel dettaglio.

Flipper può funzionare sia in modalità Master che Slave. In modalità di lettura della chiave, Flipper agisce come un lettore, ovvero funziona come Master. In modalità di emulazione della chiave, Flipper finge di essere una chiave e si trova in modalità Slave.<sup>[[1]](#references)</sup>

### Chiavi Dallas, Cyfral e Metakom

Per informazioni sul funzionamento di queste chiavi, consulta la pagina [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attacchi

Gli iButton possono essere attaccati con Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Riferimenti

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
