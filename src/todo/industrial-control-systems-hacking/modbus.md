# Il protocollo Modbus

{{#include ../../banners/hacktricks-training.md}}

## Introduzione al protocollo Modbus

Il protocollo Modbus è ampiamente utilizzato nei sistemi di automazione e controllo industriale. Modbus consente la comunicazione tra diversi dispositivi, come programmable logic controllers (PLC), sensori, attuatori e altri dispositivi industriali. Comprendere il protocollo Modbus è essenziale, poiché è il protocollo di comunicazione più utilizzato negli ICS e presenta un'ampia attack surface per lo sniffing e persino per l'iniezione di comandi nei PLC.

Qui i concetti sono presentati punto per punto, fornendo il contesto del protocollo e della sua modalità operativa. La sfida più grande nella sicurezza dei sistemi ICS è il costo dell'implementazione e dell'aggiornamento. Questi protocolli e standard sono stati progettati negli anni '80 e '90 e sono ancora ampiamente utilizzati. Poiché un'industria dispone di numerosi dispositivi e connessioni, l'aggiornamento dei dispositivi è molto difficile, offrendo agli hacker il vantaggio di avere a che fare con protocolli obsoleti. Gli attacchi a Modbus sono praticamente inevitabili, poiché continuerà a essere utilizzato senza aggiornamenti se il suo funzionamento è critico per l'industria.

## L'architettura Client-Server

Il protocollo Modbus viene generalmente utilizzato in un'architettura Client-Server, dove un dispositivo master (client) avvia la comunicazione con uno o più dispositivi slave (server). Questa viene anche chiamata architettura Master-Slave ed è ampiamente utilizzata nell'elettronica e nell'IoT con SPI, I2C, ecc.

## Versioni Seriali ed Ethernet

Il protocollo Modbus è progettato sia per la comunicazione seriale sia per le comunicazioni Ethernet. La comunicazione seriale è ampiamente utilizzata nei sistemi legacy, mentre i dispositivi moderni supportano Ethernet, che offre velocità di trasmissione dei dati elevate ed è più adatta alle reti industriali moderne.

## Rappresentazione dei dati

Nel protocollo Modbus i dati vengono trasmessi in formato ASCII o binario, sebbene il formato binario sia utilizzato per la sua compattezza con i dispositivi più vecchi.

## Codici funzione

Il protocollo ModBus funziona trasmettendo specifici codici funzione utilizzati per controllare i PLC e diversi dispositivi di controllo. Questa parte è importante da comprendere, poiché è possibile effettuare replay attacks ritrasmettendo i codici funzione. I dispositivi legacy non supportano alcuna crittografia per la trasmissione dei dati e generalmente utilizzano cavi lunghi che li collegano, il che consente la manomissione di questi cavi e la cattura o l'iniezione dei dati.

## Indirizzamento di Modbus

Ogni dispositivo nella rete dispone di un indirizzo univoco, essenziale per la comunicazione tra i dispositivi. Protocolli come Modbus RTU, Modbus TCP, ecc. vengono utilizzati per implementare l'indirizzamento e fungono da transport layer per la trasmissione dei dati. I dati trasferiti sono nel formato del protocollo Modbus e contengono il messaggio.

Inoltre, Modbus implementa anche controlli degli errori per garantire l'integrità dei dati trasmessi. Ma soprattutto, Modbus è un Open Standard e chiunque può implementarlo nei propri dispositivi. Questo ha permesso al protocollo di diventare uno standard globale e di diffondersi ampiamente nel settore dell'automazione industriale.

A causa del suo utilizzo su larga scala e della mancanza di aggiornamenti, attaccare Modbus offre un vantaggio significativo grazie alla sua attack surface. Gli ICS dipendono fortemente dalla comunicazione tra i dispositivi e qualsiasi attacco contro di essi può essere pericoloso per il funzionamento dei sistemi industriali. Attacchi come replay, data injection, data sniffing e leaking, Denial of Service, data forgery, ecc. possono essere eseguiti se il mezzo di trasmissione viene identificato dall'attaccante.

{{#include ../../banners/hacktricks-training.md}}
