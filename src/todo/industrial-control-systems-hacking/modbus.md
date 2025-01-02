# Il Protocollo Modbus

## Introduzione al Protocollo Modbus

Il protocollo Modbus è un protocollo ampiamente utilizzato nell'Automazione Industriale e nei Sistemi di Controllo. Modbus consente la comunicazione tra vari dispositivi come controllori logici programmabili (PLC), sensori, attuatori e altri dispositivi industriali. Comprendere il Protocollo Modbus è essenziale poiché è il protocollo di comunicazione più utilizzato negli ICS e presenta una grande superficie di attacco potenziale per il sniffing e persino l'iniezione di comandi nei PLC.

Qui, i concetti sono espressi in modo puntuale fornendo il contesto del protocollo e la sua natura operativa. La maggiore sfida nella sicurezza dei sistemi ICS è il costo di implementazione e aggiornamento. Questi protocolli e standard sono stati progettati all'inizio degli anni '80 e '90 e sono ancora ampiamente utilizzati. Poiché un'industria ha molti dispositivi e connessioni, aggiornare i dispositivi è molto difficile, il che fornisce ai hacker un vantaggio nel trattare protocolli obsoleti. Gli attacchi a Modbus sono praticamente inevitabili poiché verrà utilizzato senza aggiornamenti, essendo la sua operazione critica per l'industria.

## L'Architettura Client-Server

Il Protocollo Modbus è tipicamente utilizzato in un'Architettura Client-Server in cui un dispositivo master (client) avvia la comunicazione con uno o più dispositivi slave (server). Questo è anche noto come architettura Master-Slave, ampiamente utilizzata in elettronica e IoT con SPI, I2C, ecc.

## Versioni Seriali ed Ethernet

Il Protocollo Modbus è progettato sia per la Comunicazione Seriale che per le Comunicazioni Ethernet. La Comunicazione Seriale è ampiamente utilizzata nei sistemi legacy, mentre i dispositivi moderni supportano Ethernet, che offre alte velocità di trasmissione dati ed è più adatto per le reti industriali moderne.

## Rappresentazione dei Dati

I dati vengono trasmessi nel protocollo Modbus come ASCII o Binario, sebbene il formato binario sia utilizzato per la sua compatibilità con i dispositivi più vecchi.

## Codici Funzione

Il Protocollo ModBus funziona con la trasmissione di codici funzione specifici che vengono utilizzati per operare i PLC e vari dispositivi di controllo. Questa parte è importante da comprendere poiché gli attacchi di replay possono essere effettuati ritrasmettendo i codici funzione. I dispositivi legacy non supportano alcuna crittografia per la trasmissione dei dati e di solito hanno cavi lunghi che li collegano, il che porta a manomissioni di questi cavi e alla cattura/iniezione di dati.

## Indirizzamento di Modbus

Ogni dispositivo nella rete ha un indirizzo unico che è essenziale per la comunicazione tra i dispositivi. Protocolli come Modbus RTU, Modbus TCP, ecc. vengono utilizzati per implementare l'indirizzamento e fungono da livello di trasporto per la trasmissione dei dati. I dati trasferiti sono nel formato del protocollo Modbus che contiene il messaggio.

Inoltre, Modbus implementa anche controlli di errore per garantire l'integrità dei dati trasmessi. Ma soprattutto, Modbus è uno Standard Aperto e chiunque può implementarlo nei propri dispositivi. Questo ha reso questo protocollo uno standard globale ed è ampiamente diffuso nell'industria dell'automazione industriale.

A causa del suo ampio utilizzo e della mancanza di aggiornamenti, attaccare Modbus fornisce un vantaggio significativo con la sua superficie di attacco. Gli ICS dipendono fortemente dalla comunicazione tra i dispositivi e qualsiasi attacco effettuato su di essi può essere pericoloso per il funzionamento dei sistemi industriali. Attacchi come replay, iniezione di dati, sniffing di dati e leaking, Denial of Service, falsificazione di dati, ecc. possono essere effettuati se il mezzo di trasmissione è identificato dall'attaccante.
