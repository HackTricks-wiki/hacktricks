# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

I telecomandi per porte da garage operano tipicamente a frequenze nell'intervallo di 300-190 MHz, con le frequenze più comuni che sono 300 MHz, 310 MHz, 315 MHz e 390 MHz. Questo intervallo di frequenze è comunemente utilizzato per i telecomandi delle porte da garage perché è meno affollato rispetto ad altre bande di frequenza ed è meno probabile che subisca interferenze da altri dispositivi.

## Car Doors

La maggior parte dei telecomandi delle auto opera su **315 MHz o 433 MHz**. Queste sono entrambe frequenze radio e vengono utilizzate in una varietà di applicazioni diverse. La principale differenza tra le due frequenze è che 433 MHz ha una portata maggiore rispetto a 315 MHz. Ciò significa che 433 MHz è migliore per applicazioni che richiedono una portata più lunga, come l'ingresso senza chiave a distanza.\
In Europa 433.92MHz è comunemente usato e negli Stati Uniti e in Giappone è il 315MHz.

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Se invece di inviare ogni codice 5 volte (inviato in questo modo per assicurarsi che il ricevitore lo riceva) si invia solo una volta, il tempo si riduce a 6 minuti:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

e se **rimuovi il periodo di attesa di 2 ms** tra i segnali puoi **ridurre il tempo a 3 minuti.**

Inoltre, utilizzando la Sequenza di De Bruijn (un modo per ridurre il numero di bit necessari per inviare tutti i potenziali numeri binari da bruteforce) questo **tempo si riduce a soli 8 secondi**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Un esempio di questo attacco è stato implementato in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Richiedere **un preambolo eviterà l'ottimizzazione della Sequenza di De Bruijn** e **i codici rotolanti impediranno questo attacco** (supponendo che il codice sia abbastanza lungo da non essere bruteforcabile).

## Sub-GHz Attack

Per attaccare questi segnali con Flipper Zero controlla:

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

I telecomandi automatici per porte da garage utilizzano tipicamente un telecomando wireless per aprire e chiudere la porta del garage. Il telecomando **invia un segnale a radiofrequenza (RF)** al telecomando della porta del garage, che attiva il motore per aprire o chiudere la porta.

È possibile che qualcuno utilizzi un dispositivo noto come code grabber per intercettare il segnale RF e registrarlo per un uso successivo. Questo è noto come un **attacco di replay**. Per prevenire questo tipo di attacco, molti moderni telecomandi per porte da garage utilizzano un metodo di crittografia più sicuro noto come sistema di **codice rotolante**.

Il **segnale RF viene tipicamente trasmesso utilizzando un codice rotolante**, il che significa che il codice cambia ad ogni utilizzo. Questo rende **difficile** per qualcuno **intercettare** il segnale e **utilizzarlo** per ottenere accesso **non autorizzato** al garage.

In un sistema di codice rotolante, il telecomando e il telecomando della porta del garage hanno un **algoritmo condiviso** che **genera un nuovo codice** ogni volta che il telecomando viene utilizzato. Il telecomando della porta del garage risponderà solo al **codice corretto**, rendendo molto più difficile per qualcuno ottenere accesso non autorizzato al garage semplicemente catturando un codice.

### **Missing Link Attack**

Fondamentalmente, ascolti il pulsante e **catturi il segnale mentre il telecomando è fuori portata** del dispositivo (ad esempio l'auto o il garage). Poi ti sposti verso il dispositivo e **usi il codice catturato per aprirlo**.

### Full Link Jamming Attack

Un attaccante potrebbe **disturbare il segnale vicino al veicolo o al ricevitore** in modo che il **ricevitore non possa effettivamente 'sentire' il codice**, e una volta che ciò accade puoi semplicemente **catturare e riprodurre** il codice quando hai smesso di disturbare.

La vittima a un certo punto utilizzerà le **chiavi per chiudere l'auto**, ma poi l'attacco avrà **registrato abbastanza "codici di chiusura della porta"** che sperabilmente potrebbero essere inviati per aprire la porta (potrebbe essere necessaria **una modifica di frequenza** poiché ci sono auto che utilizzano gli stessi codici per aprire e chiudere ma ascoltano entrambi i comandi a frequenze diverse).

> [!WARNING]
> **Il disturbo funziona**, ma è evidente poiché se la **persona che chiude l'auto semplicemente testa le porte** per assicurarsi che siano chiuse, noterebbe che l'auto è sbloccata. Inoltre, se fossero a conoscenza di tali attacchi, potrebbero anche ascoltare il fatto che le porte non hanno mai emesso il **suono** di chiusura o che le **luci** dell'auto non hanno mai lampeggiato quando hanno premuto il pulsante 'chiudi'.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Questa è una **tecnica di disturbo più furtiva**. L'attaccante disturberà il segnale, quindi quando la vittima prova a chiudere la porta non funzionerà, ma l'attaccante **registrerà questo codice**. Poi, la vittima **proverà a chiudere di nuovo l'auto** premendo il pulsante e l'auto **registrerà questo secondo codice**.\
Immediatamente dopo, l'**attaccante può inviare il primo codice** e l'**auto si chiuderà** (la vittima penserà che la seconda pressione l'abbia chiusa). Poi, l'attaccante sarà in grado di **inviare il secondo codice rubato per aprire** l'auto (supponendo che un **codice "chiudi auto" possa essere utilizzato anche per aprirla**). Potrebbe essere necessaria una modifica di frequenza (poiché ci sono auto che utilizzano gli stessi codici per aprire e chiudere ma ascoltano entrambi i comandi a frequenze diverse).

L'attaccante può **disturbare il ricevitore dell'auto e non il suo ricevitore** perché se il ricevitore dell'auto sta ascoltando, ad esempio, una larghezza di banda di 1MHz, l'attaccante non **disturberà** la frequenza esatta utilizzata dal telecomando ma **una vicina in quello spettro** mentre il **ricevitore dell'attaccante ascolterà in un intervallo più ristretto** dove può ascoltare il segnale del telecomando **senza il segnale di disturbo**.

> [!WARNING]
> Altre implementazioni viste nelle specifiche mostrano che il **codice rotolante è una porzione** del codice totale inviato. Ad esempio, il codice inviato è una **chiave a 24 bit** dove i primi **12 sono il codice rotolante**, gli **ultimi 8 sono il comando** (come chiudere o aprire) e gli ultimi 4 sono il **checksum**. I veicoli che implementano questo tipo sono anche naturalmente suscettibili poiché l'attaccante deve semplicemente sostituire il segmento del codice rotolante per poter **utilizzare qualsiasi codice rotolante su entrambe le frequenze**.

> [!CAUTION]
> Nota che se la vittima invia un terzo codice mentre l'attaccante sta inviando il primo, il primo e il secondo codice saranno invalidati.

### Alarm Sounding Jamming Attack

Testando contro un sistema di codice rotolante aftermarket installato su un'auto, **inviare lo stesso codice due volte** ha immediatamente **attivato l'allarme** e l'immobilizzatore fornendo un'unica opportunità di **negazione del servizio**. Ironia della sorte, il modo per **disattivare l'allarme** e l'immobilizzatore era **premere** il **telecomando**, fornendo a un attaccante la possibilità di **eseguire continuamente un attacco DoS**. Oppure mescolare questo attacco con il **precedente per ottenere più codici** poiché la vittima vorrebbe fermare l'attacco il prima possibile.

## References

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
