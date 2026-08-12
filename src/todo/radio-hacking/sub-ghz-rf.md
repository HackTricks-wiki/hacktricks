# RF Sub-GHz

{{#include ../../banners/hacktricks-training.md}}

## Porte da garage

I telecomandi delle porte da garage utilizzano diverse allocazioni Sub-GHz specifiche per regione e prodotto. Sono frequenze comuni 300, 310, 315, 390 e 433,92 MHz, ma non esiste una banda universale “300–190 MHz” per le porte da garage. Identifica l'etichetta del target, la regione normativa e il segnale osservato prima di trasmettere.<sup>[[1]](#references)</sup>

## Porte delle auto

Molti portachiavi delle auto utilizzano **315 MHz o 433,92 MHz**, con le normative regionali e la progettazione del veicolo che influenzano la scelta. La frequenza da sola non fa sì che 433 MHz abbia una portata maggiore rispetto a 315 MHz: potenza di trasmissione, efficienza dell'antenna, modulazione, sensibilità del ricevitore, propagazione e normative locali sono tutti fattori importanti. In Europa viene comunemente utilizzata la frequenza 433,92 MHz, mentre 315 MHz è comune in Nord America e Giappone.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Nel sistema a codice fisso dimostrato, l'invio di ogni codice una sola volta invece di cinque riduce il tempo stimato a sei minuti:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Rimuovere l'attesa di 2 ms tra i segnali riduce la durata di questa dimostrazione a circa tre minuti.

L'utilizzo di una sequenza di De Bruijn per sovrapporre le stringhe di bit candidate riduce l'attacco dimostrato a circa otto secondi quando il ricevitore accetta la sequenza continua senza richiedere un preambolo o un reset del frame.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementa questo attacco contro sistemi a codice fisso compatibili.<sup>[[5]](#references)</sup>

La richiesta di **un preambolo eviterà** l'ottimizzazione della **sequenza di De Bruijn** e i **rolling code impediranno questo attacco** (supponendo che il codice sia sufficientemente lungo da non poter essere sottoposto a brute-force).

## Attacco Sub-GHz

Per attaccare questi segnali con Flipper Zero, consulta:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protezione con rolling code

I dispositivi automatici per l'apertura delle porte da garage utilizzano generalmente un telecomando wireless per aprire e chiudere la porta del garage. Il telecomando **invia un segnale a radiofrequenza (RF)** al dispositivo di apertura della porta, che attiva il motore per aprire o chiudere la porta.

È possibile utilizzare un dispositivo noto come code grabber per intercettare il segnale RF e registrarlo per utilizzarlo in seguito. Questo è noto come **replay attack**. Per prevenire questo tipo di attacco, molti dispositivi moderni per l'apertura delle porte da garage utilizzano un metodo di cifratura più sicuro, noto come sistema a **rolling code**.

Il **segnale RF viene generalmente trasmesso utilizzando un rolling code**, il che significa che il codice cambia a ogni utilizzo. Questo rende **difficile** per qualcuno **intercettare** il segnale e **utilizzarlo** per ottenere un accesso **non autorizzato** al garage.

In un sistema a rolling code, il telecomando e il dispositivo di apertura della porta del garage condividono un **algoritmo** che **genera un nuovo codice** ogni volta che viene utilizzato il telecomando. Il dispositivo di apertura della porta risponderà solo al **codice corretto**, rendendo molto più difficile ottenere un accesso non autorizzato al garage semplicemente catturando un codice.

### **Missing Link Attack**

In sostanza, si ascolta la pressione del pulsante e si **cattura il segnale mentre il telecomando si trova fuori dalla portata** del dispositivo (ad esempio l'auto o il garage). Successivamente ci si sposta vicino al dispositivo e si **utilizza il codice catturato per aprirlo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> L'interferenza RF intenzionale è illegale in molte giurisdizioni e può disturbare sistemi rilevanti per la sicurezza. Esegui i test di jamming solo in un laboratorio schermato e autorizzato e nel rispetto delle normative radio applicabili.<sup>[[6]](#references)</sup>

Un attacker potrebbe **bloccare il segnale vicino al veicolo o al ricevitore**, in modo che il ricevitore non possa decodificare il codice, catturare separatamente la trasmissione bloccata, interrompere il jamming e quindi riprodurre il codice catturato.<sup>[[2]](#references)</sup>

A un certo punto la vittima utilizzerà le **chiavi per chiudere l'auto**, ma l'attacco avrà **registrato abbastanza codici di "chiusura della porta"** da poterli eventualmente ritrasmettere per aprire la porta (potrebbe essere necessario **cambiare frequenza**, poiché alcune auto utilizzano gli stessi codici per aprire e chiudere, ma ascoltano entrambi i comandi su frequenze diverse).

> [!WARNING]
> Il **jamming funziona**, ma è evidente: se la **persona che chiude l'auto controlla semplicemente le porte** per assicurarsi che siano chiuse, si accorgerebbe che l'auto è rimasta aperta. Inoltre, se fosse a conoscenza di questo tipo di attacchi, potrebbe persino notare che le porte non hanno mai emesso il **suono** di chiusura o che le **luci dell'auto** non hanno lampeggiato quando ha premuto il pulsante di ‘lock’.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Questa è una tecnica di **jamming più furtiva**. L'attacker blocca il segnale, così quando la vittima prova a chiudere la porta l'operazione non riesce, ma l'attacker **registra questo codice**. La vittima proverà quindi a **chiudere nuovamente l'auto**, premendo il pulsante, e l'auto **registrerà questo secondo codice**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Subito dopo, l'**attacker può inviare il primo codice** e l'**auto si chiuderà** (la vittima penserà che sia stata la seconda pressione a chiuderla). L'attacker potrà quindi **inviare il secondo codice rubato per aprire** l'auto (supponendo che un codice di **"chiusura dell'auto" possa essere utilizzato anche per aprirla**). Potrebbe essere necessario cambiare frequenza (poiché alcune auto utilizzano gli stessi codici per aprire e chiudere, ma ascoltano entrambi i comandi su frequenze diverse).

Un'implementazione di RollJam sfrutta la larghezza di banda del ricevitore: il jammer trasmette abbastanza vicino alla portante del telecomando da desensibilizzare il ricevitore più ampio del veicolo, mentre il ricevitore più stretto dell'attacker rimane centrato sul telecomando e può continuare a registrare il segnale. L'offset e la larghezza di banda esatti dipendono dall'hardware target.<sup>[[2]](#references)</sup>

> [!WARNING]
> Altre implementazioni presenti nelle specifiche mostrano che il **rolling code costituisce una parte** del codice totale inviato. Ad esempio, il codice inviato è una **chiave di 24 bit**, dove i primi **12 bit sono il rolling code**, i successivi **8 bit sono il comando** (come lock o unlock) e gli ultimi 4 bit sono il **checksum**. I veicoli che implementano questo tipo di sistema sono naturalmente vulnerabili, poiché l'attacker deve semplicemente sostituire il segmento del rolling code per poter **utilizzare qualsiasi rolling code su entrambe le frequenze**.

> [!CAUTION]
> Nota che se la vittima invia un terzo codice mentre l'attacker sta inviando il primo, il primo e il secondo codice verranno invalidati.

### Alarm Sounding Jamming Attack

Durante i test su un sistema a rolling code aftermarket installato su un'auto, **l'invio dello stesso codice due volte** ha **attivato immediatamente l'allarme** e l'immobilizer, offrendo un'opportunità unica di **denial of service**. Ironia della sorte, il metodo per **disabilitare l'allarme** e l'immobilizer consisteva nel **premere** il **telecomando**, offrendo a un attacker la possibilità di eseguire continuamente un **DoS attack**. Oppure si può combinare questo attacco con il **precedente per ottenere più codici**, poiché la vittima vorrà interrompere l'attacco il prima possibile.<sup>[[2]](#references)</sup>

## References

- [1] [Documentazione di Flipper Zero - frequenze Sub-GHz regionali](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Elusione dei sistemi a rolling code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Come hackerare un'auto - ricostruzione di RollJam con YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Codice sorgente di OpenSesame](https://github.com/samyk/opensesame)
- [6] [Avviso di applicazione FCC - applicazione contro i jammer](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
