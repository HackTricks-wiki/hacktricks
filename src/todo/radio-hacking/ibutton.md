# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

iButton è un nome generico per una chiave elettronica di identificazione racchiusa in un **contenitore metallico a forma di moneta**. È anche chiamata memoria **Dallas Touch** o memoria a contatto. Sebbene venga spesso definita erroneamente una chiave “magnetica”, al suo interno non c'è **nulla di magnetico**. Infatti, al suo interno è nascosto un vero e proprio **microchip** che opera tramite un protocollo digitale.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Che cos'è iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Il nome iButton descrive il contenitore resistente a forma di moneta e la disposizione dei contatti. I supporti includono portachiavi in plastica, anelli e pendenti.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando entrambi i contatti toccano il lettore, il dispositivo riceve alimentazione e scambia dati. Se la geometria incassata dei contatti impedisce ai contatti esterni di massa di toccarsi, inclinare la chiave contro la parete del lettore può ripristinare il contatto.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocollo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Le chiavi Dallas/Maxim utilizzano il protocollo 1-Wire: un contatto dati trasporta il traffico bidirezionale e può anche fornire alimentazione parassita, mentre il contenitore metallico funge da contatto di ritorno. Il controller avvia le transazioni e il dispositivo risponde.<sup>[[2]](#references)</sup>

Quando la chiave (Slave) entra in contatto con il citofono (Master), il chip all'interno della chiave si accende, alimentato dal citofono, e la chiave viene inizializzata. Dopodiché, il citofono richiede l'ID della chiave. Analizzeremo questo processo più nel dettaglio.

Flipper può agire come controller durante la lettura di una chiave e come dispositivo emulato quando presenta a un lettore un identificatore memorizzato.<sup>[[1]](#references)</sup>

### Chiavi Dallas, Cyfral e Metakom

Per informazioni sul funzionamento di queste chiavi, consulta la pagina [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attacchi

Gli iButton possono essere attaccati con Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Comunicazione 1-Wire tramite software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
