# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Porte dei garage

Gli apriporta dei garage operano tipicamente su frequenze comprese tra 190 e 300 MHz, con le frequenze più comuni a 300 MHz, 310 MHz, 315 MHz e 390 MHz. Questa gamma di frequenze viene comunemente utilizzata per gli apriporta dei garage perché è meno affollata rispetto ad altre bande di frequenza ed è meno soggetta a interferenze da parte di altri dispositivi.

## Portiere delle auto

La maggior parte dei key fob delle auto opera a **315 MHz o 433 MHz**. Queste sono entrambe radiofrequenze utilizzate in diverse applicazioni. La differenza principale tra le due frequenze è che 433 MHz ha una portata maggiore rispetto a 315 MHz. Ciò significa che 433 MHz è più adatta alle applicazioni che richiedono una portata maggiore, come il remote keyless entry.\
In Europa viene comunemente utilizzata la frequenza 433,92 MHz, mentre negli Stati Uniti e in Giappone viene utilizzata quella a 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Se invece di inviare ogni codice 5 volte (viene inviato in questo modo per assicurarsi che il ricevitore lo riceva) lo si inviasse una sola volta, il tempo si ridurrebbe a 6 minuti:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

e se si **rimuovesse il periodo di attesa di 2 ms** tra i segnali, si potrebbe **ridurre il tempo a 3 minuti.**

Inoltre, utilizzando la De Bruijn Sequence (un modo per ridurre il numero di bit necessari per inviare tutti i potenziali numeri binari da sottoporre a bruteforce), questo **tempo si riduce ad appena 8 secondi**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Un esempio di questo attack è stato implementato in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

La richiesta di **un preambolo eviterà l'ottimizzazione della De Bruijn Sequence**, mentre i **rolling codes impediranno questo attack** (supponendo che il codice sia abbastanza lungo da non poter essere sottoposto a bruteforce).

## Sub-GHz Attack

Per attaccare questi segnali con Flipper Zero, consulta:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protezione con Rolling Codes

Gli apriporta automatici dei garage utilizzano tipicamente un telecomando wireless per aprire e chiudere la porta del garage. Il telecomando **invia un segnale a radiofrequenza (RF)** all'apriporta del garage, che attiva il motore per aprire o chiudere la porta.

È possibile utilizzare un dispositivo noto come code grabber per intercettare il segnale RF e registrarlo per utilizzarlo in seguito. Questo è noto come **replay attack**. Per prevenire questo tipo di attack, molti apriporta moderni utilizzano un metodo di cifratura più sicuro, noto come sistema a **rolling code**.

Il **segnale RF viene generalmente trasmesso utilizzando un rolling code**, il che significa che il codice cambia a ogni utilizzo. Questo rende **difficile** per qualcuno **intercettare** il segnale e **utilizzarlo** per ottenere un accesso **non autorizzato** al garage.

In un sistema a rolling code, il telecomando e l'apriporta del garage dispongono di un **algoritmo condiviso** che **genera un nuovo codice** ogni volta che viene utilizzato il telecomando. L'apriporta del garage risponderà solo al **codice corretto**, rendendo molto più difficile ottenere un accesso non autorizzato al garage semplicemente catturando un codice.

### **Missing Link Attack**

In pratica, si ascolta la pressione del pulsante e si **cattura il segnale mentre il telecomando si trova fuori dalla portata** del dispositivo (ad esempio dell'auto o del garage). Dopodiché ci si sposta vicino al dispositivo e si **utilizza il codice catturato per aprirlo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Un attacker potrebbe **disturbare il segnale vicino al veicolo o al ricevitore**, in modo che il **ricevitore non possa effettivamente "sentire" il codice**, e una volta fatto ciò si può semplicemente **catturare e riprodurre** il codice dopo aver interrotto il jamming.<sup>[[2]](#references)</sup>

A un certo punto la vittima utilizzerà le **chiavi per chiudere l'auto**, ma l'attack avrà **registrato abbastanza codici di "chiusura della porta"** da poterli eventualmente ritrasmettere per aprire la porta (potrebbe essere necessario **cambiare frequenza**, poiché alcune auto utilizzano gli stessi codici per aprire e chiudere, ma ascoltano entrambi i comandi su frequenze diverse).

> [!WARNING]
> Il **jamming funziona**, ma è evidente: se la **persona che chiude l'auto controlla semplicemente le portiere** per assicurarsi che siano chiuse, si accorgerebbe che l'auto è ancora aperta. Inoltre, se fosse a conoscenza di questo tipo di attack, potrebbe persino notare che le portiere non hanno mai emesso il **suono** di chiusura o che le **luci dell'auto** non hanno lampeggiato quando ha premuto il pulsante di chiusura.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Questa è una tecnica di jamming più **stealth**. L'attacker disturberà il segnale, quindi quando la vittima tenterà di chiudere la portiera, l'operazione non funzionerà, ma l'attacker **registrerà questo codice**. Dopodiché, la vittima **tenterà nuovamente di chiudere l'auto**, premendo il pulsante, e l'auto **registrerà questo secondo codice**.<sup>[[2]](#references)[[4]](#references)</sup>\
Subito dopo, l'**attacker potrà inviare il primo codice** e l'**auto si chiuderà** (la vittima penserà che sia stata la seconda pressione a chiuderla). L'attacker potrà quindi **inviare il secondo codice rubato per aprire** l'auto (supponendo che un codice di **"chiusura dell'auto" possa essere utilizzato anche per aprirla**). Potrebbe essere necessario cambiare frequenza (poiché alcune auto utilizzano gli stessi codici per aprire e chiudere, ma ascoltano entrambi i comandi su frequenze diverse).

L'attacker può **disturbare il ricevitore dell'auto ma non il proprio ricevitore**, perché se il ricevitore dell'auto ascolta, ad esempio, una banda larga di 1 MHz, l'attacker non farà **jamming** sulla frequenza esatta utilizzata dal telecomando, ma su **una frequenza vicina all'interno di quello spettro**, mentre il ricevitore dell'**attacker ascolterà su un intervallo più ristretto**, nel quale potrà ascoltare il segnale del telecomando **senza il segnale di jamming**.

> [!WARNING]
> Altre implementazioni osservate nelle specifiche mostrano che il **rolling code è solo una parte** del codice totale inviato. Ad esempio, il codice inviato è una **chiave di 24 bit**, dove i primi **12 bit sono il rolling code**, i successivi **8 bit sono il comando** (come chiusura o apertura) e gli ultimi 4 sono il **checksum**. I veicoli che implementano questo tipo di sistema sono anch'essi naturalmente vulnerabili, poiché all'attacker basta sostituire il segmento del rolling code per poter **utilizzare qualsiasi rolling code su entrambe le frequenze**.

> [!CAUTION]
> Nota: se la vittima invia un terzo codice mentre l'attacker sta inviando il primo, il primo e il secondo codice verranno invalidati.

### Alarm Sounding Jamming Attack

Durante i test su un sistema aftermarket a rolling code installato su un'auto, **l'invio immediato dello stesso codice due volte** ha **attivato l'allarme** e l'immobiliser, offrendo un'opportunità unica di **denial of service**. Ironia della sorte, il metodo per **disabilitare l'allarme** e l'immobiliser consisteva nel **premere** il **telecomando**, offrendo a un attacker la possibilità di eseguire continuamente un **DoS attack**. In alternativa, è possibile combinare questo attack con quello **precedente per ottenere più codici**, poiché la vittima vorrà interrompere l'attack il prima possibile.<sup>[[2]](#references)</sup>

## References

- [1] [Su quale radiofrequenza operano i key fob delle auto?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
