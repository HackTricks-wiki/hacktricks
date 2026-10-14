# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

I telecomandi per garage utilizzano allocazioni sub-GHz specifiche per regione e prodotto. Si incontrano frequenze come 300, 310, 315, 390 e 433.92 MHz, ma non esiste una banda universale per i garage di “300–190 MHz”. Prima di trasmettere, identifica l'etichetta del dispositivo bersaglio, la regione normativa e il segnale osservato.<sup>[[1]](#references)</sup>

## Car Doors

Molti telecomandi per auto utilizzano **315 MHz o 433.92 MHz**; la scelta dipende dalle normative regionali e dalla progettazione del veicolo. La frequenza da sola non rende 433 MHz più potente di 315 MHz in termini di portata: contano anche la potenza di trasmissione, l'efficienza dell'antenna, la modulazione, la sensibilità del ricevitore, la propagazione e le normative locali. In Europa è comunemente utilizzata la frequenza di 433.92 MHz, mentre in Nord America e in Giappone è comune quella di 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Nel sistema a codice fisso mostrato, inviare ogni codice una sola volta invece di cinque riduce il tempo stimato a sei minuti:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Rimuovendo l'attesa di 2 ms tra i segnali, la dimostrazione si riduce a circa tre minuti.

L'uso di una sequenza di De Bruijn per sovrapporre stringhe di bit candidate riduce l'attacco mostrato a circa otto secondi, se il ricevitore accetta la sequenza continua senza richiedere un preambolo o il reset del frame.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementa questo attacco contro sistemi a codice fisso compatibili.<sup>[[5]](#references)</sup>

La richiesta di **un preambolo evita l'ottimizzazione con la sequenza di De Bruijn** e i **rolling code impediscono questo attacco** (supponendo che il codice sia abbastanza lungo da non poter essere violato con un brute force).

## Sub-GHz Attack

Per attaccare questi segnali con Flipper Zero, consulta:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Gli apriporta automatici per garage utilizzano in genere un telecomando wireless per aprire e chiudere la porta. Il telecomando **invia un segnale a radiofrequenza (RF)** all'apriporta, che attiva il motore per aprire o chiudere la porta.

È possibile utilizzare un dispositivo noto come code grabber per intercettare il segnale RF e registrarlo per usarlo in seguito. Questo è noto come **replay attack**. Per prevenire questo tipo di attacco, molti apriporta moderni utilizzano un metodo di cifratura più sicuro, noto come sistema a **rolling code**.

Il **segnale RF viene generalmente trasmesso utilizzando un rolling code**, il che significa che il codice cambia a ogni utilizzo. Questo rende **difficile** per qualcuno **intercettare** il segnale e **usarlo** per ottenere un accesso **non autorizzato** al garage.

In un sistema a rolling code, il telecomando e l'apriporta del garage condividono un **algoritmo** che **genera un nuovo codice** ogni volta che si usa il telecomando. L'apriporta risponde solo al **codice corretto**, rendendo molto più difficile ottenere un accesso non autorizzato al garage semplicemente catturando un codice.

### **Missing Link Attack**

In pratica, si ascolta la pressione del pulsante e si **cattura il segnale mentre il telecomando è fuori portata** del dispositivo (ad esempio, dell'auto o del garage). Poi ci si avvicina al dispositivo e si **usa il codice catturato per aprirlo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> L'interferenza RF intenzionale è illegale in molte giurisdizioni e può compromettere sistemi rilevanti per la sicurezza. Esegui test di jamming solo in un laboratorio schermato e autorizzato, nel rispetto delle normative radio applicabili.<sup>[[6]](#references)</sup>

Un attacker potrebbe **disturbare il segnale vicino al veicolo o al ricevitore** affinché quest'ultimo non riesca a decodificare il codice, catturare separatamente la trasmissione bloccata, interrompere il jamming e poi riprodurre il codice catturato.<sup>[[2]](#references)</sup>

A un certo punto, la vittima userà le **chiavi per chiudere l'auto**, ma l'attacco avrà **registrato abbastanza codici di “chiusura”** da poterli, si spera, ritrasmettere per aprire la portiera (potrebbe essere necessario **cambiare frequenza**, perché alcune auto usano gli stessi codici per aprire e chiudere, ma ricevono i due comandi su frequenze diverse).

> [!WARNING]
> **Il jamming funziona**, ma è evidente: se la **persona che chiude l'auto controlla semplicemente le portiere** per assicurarsi che siano bloccate, si accorgerà che l'auto è rimasta aperta. Inoltre, se fosse a conoscenza di attacchi di questo tipo, potrebbe anche accorgersi che le portiere non hanno mai emesso il **suono** di chiusura o che le **luci** dell'auto non hanno mai lampeggiato quando ha premuto il pulsante di chiusura.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Questa è una tecnica di **jamming più furtiva**. L'attacker disturba il segnale, così quando la vittima prova a chiudere la portiera il comando non funziona, ma l'attacker **registra questo codice**. Poi, la vittima **prova di nuovo a chiudere l'auto**, premendo il pulsante, e l'auto **registra questo secondo codice**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Subito dopo, l'**attacker può inviare il primo codice** e l'**auto si chiude** (la vittima penserà che sia stato il secondo tentativo a chiuderla). L'attacker potrà quindi **inviare il secondo codice sottratto per aprire** l'auto (supponendo che un codice di **“chiusura dell'auto” possa essere usato anche per aprirla**). Potrebbe essere necessario cambiare frequenza (alcune auto usano gli stessi codici per aprire e chiudere, ma ricevono i due comandi su frequenze diverse).

Un'implementazione di RollJam sfrutta la larghezza di banda del ricevitore: il jammer trasmette a una frequenza abbastanza vicina alla portante del telecomando da desensibilizzare il ricevitore più ampio del veicolo, mentre il ricevitore più selettivo dell'attacker resta sintonizzato sulla frequenza del telecomando e può continuare a registrare il segnale. Lo scostamento e la larghezza di banda esatti dipendono dall'hardware bersaglio.<sup>[[2]](#references)</sup>

> [!WARNING]
> Altre implementazioni descritte nelle specifiche mostrano che il **rolling code è solo una parte** del codice totale trasmesso. Per esempio, il codice inviato è una **chiave a 24 bit**, di cui i primi **12 sono il rolling code**, gli **8 successivi sono il comando** (ad esempio, chiudi o apri) e gli ultimi 4 sono il **checksum**. Anche i veicoli di questo tipo sono naturalmente vulnerabili, perché all'attacker basta sostituire la parte del rolling code per poter **usare qualsiasi rolling code su entrambe le frequenze**.

> [!CAUTION]
> Se la vittima invia un terzo codice mentre l'attacker sta inviando il primo, il primo e il secondo codice verranno invalidati.

### Alarm Sounding Jamming Attack

Durante i test su un sistema aftermarket a rolling code installato su un'auto, **l'invio dello stesso codice due volte** ha **attivato immediatamente l'allarme** e l'immobilizer, offrendo un'opportunità unica di **denial of service**. Ironia della sorte, per **disattivare l'allarme** e l'immobilizer bastava **premere** il **telecomando**, dando così all'attacker la possibilità di **eseguire continuamente attacchi DoS**. In alternativa, si può combinare questo attacco con il **precedente per ottenere altri codici**, dato che la vittima vorrà interrompere l'attacco il prima possibile.<sup>[[2]](#references)</sup>

## References

- [1] [Documentazione Flipper Zero - frequenze Sub-GHz regionali](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Eludere i sistemi a rolling code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Come hackerare un'auto - ricreazione di RollJam con YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Codice sorgente di OpenSesame](https://github.com/samyk/opensesame)
- [6] [Avviso di applicazione della FCC - contrasto ai jammer](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
