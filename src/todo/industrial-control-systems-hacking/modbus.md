# Il protocollo Modbus

{{#include ../../banners/hacktricks-training.md}}

## Introduzione a Modbus

Modbus è un protocollo open a livello applicativo ampiamente implementato da PLC, sensori, attuatori e altri dispositivi industriali. Il suo modello richiesta/risposta espone coil e registri tramite function code. I security test si concentrano quindi su letture/scritture non autorizzate, osservazione del traffico, replay e comportamento non sicuro dei dispositivi, non semplicemente sulla ricerca della porta TCP 502.<sup>[[1]](#references)</sup>

Molte implementazioni mantengono apparecchiature seriali legacy perché gli aggiornamenti richiedono downtime, ricertificazione o la sostituzione dei dispositivi sul campo. Il Modbus tradizionale non fornisce né riservatezza né autenticazione tra peer; Modbus Security è un profilo separato basato su TLS che utilizza certificati X.509 e la porta TCP 802. Poiché la specifica è pubblica e può essere implementata indipendentemente, il comportamento dei vendor e il supporto alle funzioni opzionali variano e devono essere sottoposti a fingerprinting anziché essere dati per scontati.<sup>[[1]](#references)[[2]](#references)</sup>

## L'architettura Client-Server

Nella terminologia attuale, un **client** avvia una transazione e un **server** restituisce una risposta. La documentazione precedente utilizza **master/slave**. Non bisogna confondere questa relazione a livello applicativo con SPI o I2C: si tratta di bus protocol differenti.<sup>[[1]](#references)</sup>

## Trasporti seriali ed Ethernet

Gli stessi dati applicativi Modbus possono essere trasportati dalle varianti seriali (framing RTU o ASCII) e da Modbus TCP. Modbus TCP aggiunge un header MBAP e normalmente utilizza la porta TCP 502; l'RTU seriale utilizza un framing binario compatto e un CRC, mentre l'ASCII seriale rappresenta i byte come caratteri esadecimali e utilizza un LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Rappresentazione dei dati

Il modello dati è costituito da coil/input discreti a singolo bit e registri di input/holding a 16 bit. I valori distribuiti su più registri, l'ordine dei byte, lo scaling e il significato semantico dipendono dal dispositivo e devono essere verificati sulla register map del vendor.<sup>[[1]](#references)</sup>

## Function code

I function code selezionano operazioni come la lettura dei coil (`0x01`), la lettura dei registri holding (`0x03`), la scrittura di un singolo coil/registro (`0x05`/`0x06`) e la scrittura di coil/registri multipli (`0x0F`/`0x10`). Una richiesta di scrittura catturata può essere riproducibile tramite replay quando l'implementazione non dispone di autenticazione compensativa o di controlli sullo stato del processo. Con accesso fisico autorizzato a lunghi tratti seriali, un assessor può inoltre catturare o iniettare frame direttamente sul cablaggio dopo aver identificato l'interfaccia elettrica, la terminazione e il metodo di connessione sicuro. Entrambe le azioni possono influire sul processo fisico, quindi è necessario utilizzare un lab o disporre di un'autorizzazione operativa esplicita.<sup>[[1]](#references)[[3]](#references)</sup>

## Indirizzamento

I dispositivi seriali utilizzano un indirizzo unità. Modbus TCP utilizza l'indirizzamento IP insieme a un Unit Identifier nell'header MBAP, un aspetto particolarmente rilevante quando un gateway da TCP a seriale instrada le richieste verso unità downstream. I riferimenti ai registri mostrati dalla documentazione del prodotto possono essere one-based (`40001`), mentre gli indirizzi del protocollo sono zero-based: ciò costituisce una fonte comune di errori off-by-one.<sup>[[1]](#references)[[3]](#references)</sup>

Il framing seriale include controlli degli errori di trasmissione (CRC per RTU e LRC per ASCII), mentre TCP fornisce il normale checksum del trasporto. Questi controlli rilevano la corruzione accidentale; non costituiscono integrità crittografica né autenticazione dell'origine.<sup>[[3]](#references)</sup>

Durante un assessment autorizzato, verificare l'esposizione, i function code consentiti, gli intervalli di indirizzi scrivibili, la gestione delle eccezioni, i rate limit e se la segmentazione di rete o un firewall consapevole di Modbus limitano i client. Le minacce rilevanti includono divulgazione passiva, command injection non autorizzata, replay, falsificazione dei dati e denial of service. Coordinare tutti i test attivi con i responsabili del processo, poiché modifiche apparentemente minime ai registri possono alterare un processo fisico.

## References

- [1] [Modbus Organization — Specifica del protocollo applicativo Modbus V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Protocollo Modbus Security e guide all'implementazione](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Specifica e guida all'implementazione di Modbus su linea seriale V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
