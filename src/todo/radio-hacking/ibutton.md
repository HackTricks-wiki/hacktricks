# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButton è un nome generico per una chiave di identificazione elettronica racchiusa in un **contenitore metallico a forma di moneta**. È anche chiamata **Dallas Touch** Memory o memoria a contatto. Anche se spesso viene erroneamente definita come una chiave “magnetica”, non c'è **nulla di magnetico** in essa. Infatti, un **microchip** a tutti gli effetti che opera su un protocollo digitale è nascosto all'interno.

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Di solito, iButton implica la forma fisica della chiave e del lettore - una moneta rotonda con due contatti. Per il telaio che la circonda, ci sono molte variazioni, dal supporto in plastica più comune con un foro a anelli, pendenti, ecc.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando la chiave raggiunge il lettore, i **contatti si toccano** e la chiave viene alimentata per **trasmettere** il suo ID. A volte la chiave **non viene letta** immediatamente perché il **PSD di contatto di un citofono è più grande** di quanto dovrebbe essere. Quindi i contorni esterni della chiave e del lettore non possono toccarsi. Se è questo il caso, dovrai premere la chiave su una delle pareti del lettore.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Le chiavi Dallas scambiano dati utilizzando il protocollo 1-wire. Con solo un contatto per il trasferimento dei dati (!!) in entrambe le direzioni, dal master allo slave e viceversa. Il protocollo 1-wire funziona secondo il modello Master-Slave. In questa topologia, il Master inizia sempre la comunicazione e lo Slave segue le sue istruzioni.

Quando la chiave (Slave) contatta il citofono (Master), il chip all'interno della chiave si accende, alimentato dal citofono, e la chiave viene inizializzata. Successivamente, il citofono richiede l'ID della chiave. Ora esamineremo questo processo in modo più dettagliato.

Flipper può funzionare sia in modalità Master che Slave. In modalità lettura della chiave, Flipper agisce come un lettore, cioè funziona come un Master. E in modalità emulazione della chiave, il flipper finge di essere una chiave, è in modalità Slave.

### Dallas, Cyfral & Metakom keys

Per informazioni su come funzionano queste chiavi, controlla la pagina [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacks

Gli iButton possono essere attaccati con Flipper Zero:

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
