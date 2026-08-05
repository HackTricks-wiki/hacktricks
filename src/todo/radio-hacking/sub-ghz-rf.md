# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Porte del garage

Gli apriporta per garage operano generalmente nell'intervallo di frequenze 300-190 MHz, con le frequenze più comuni di 300 MHz, 310 MHz, 315 MHz e 390 MHz. Questo intervallo di frequenze viene comunemente utilizzato dagli apriporta per garage perché è meno congestionato rispetto ad altre bande di frequenza e ha meno probabilità di subire interferenze da parte di altri dispositivi.

## Porte delle automobili

La maggior parte dei telecomandi delle automobili opera a **315 MHz o 433 MHz**. Si tratta entrambe di radiofrequenze utilizzate in diverse applicazioni. La differenza principale tra le due frequenze è che 433 MHz ha una portata maggiore rispetto a 315 MHz. Ciò significa che 433 MHz è più adatta alle applicazioni che richiedono una portata maggiore, come l'accesso remoto senza chiave.\
In Europa viene comunemente utilizzata la frequenza 433,92 MHz, mentre negli Stati Uniti e in Giappone viene utilizzata quella a 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Se invece di inviare ogni codice 5 volte (viene inviato in questo modo per assicurarsi che il ricevitore lo riceva) lo si inviasse una sola volta, il tempo si ridurrebbe a 6 minuti:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

e se si **rimuovesse il periodo di attesa di 2 ms** tra i segnali si potrebbe **ridurre il tempo a 3 minuti.**

Inoltre, utilizzando la De Bruijn Sequence (un metodo per ridurre il numero di bit necessari a inviare tutti i potenziali numeri binari da sottoporre a brute-force), questo **tempo si riduce a soli 8 secondi**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Un esempio di questo attacco è stato implementato in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup>

La necessità di un **preamble impedirà l'ottimizzazione della De Bruijn Sequence**, mentre i **rolling codes impediranno questo attacco** (supponendo che il codice sia sufficientemente lungo da non poter essere sottoposto a brute-force).

## Sub-GHz Attack

Per attaccare questi segnali con Flipper Zero, consulta:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Gli apriporta automatici per garage utilizzano generalmente un telecomando wireless per aprire e chiudere la porta del garage. Il telecomando **invia un segnale a radiofrequenza (RF)** all'apriporta del garage, che attiva il motore per aprire o chiudere la porta.

È possibile utilizzare un dispositivo noto come code grabber per intercettare il segnale RF e registrarlo per un uso successivo. Questa tecnica è nota come **replay attack**. Per impedire questo tipo di attacco, molti apriporta moderni utilizzano un metodo di cifratura più sicuro, noto come sistema a **rolling code**.

Il **segnale RF viene generalmente trasmesso utilizzando un rolling code**, il che significa che il codice cambia a ogni utilizzo. Questo rende **difficile** per qualcuno **intercettare** il segnale e **utilizzarlo** per ottenere un accesso **non autorizzato** al garage.

In un sistema a rolling code, il telecomando e l'apriporta del garage dispongono di un **algoritmo condiviso** che **genera un nuovo codice** ogni volta che viene utilizzato il telecomando. L'apriporta risponderà solo al **codice corretto**, rendendo molto più difficile ottenere un accesso non autorizzato al garage semplicemente catturando un codice.

### **Missing Link Attack**

In pratica, si ascolta la pressione del pulsante e si **cattura il segnale mentre il telecomando si trova fuori dalla portata** del dispositivo (ad esempio l'automobile o il garage). Successivamente ci si sposta vicino al dispositivo e si **utilizza il codice catturato per aprirlo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Un attaccante potrebbe **bloccare il segnale vicino al veicolo o al ricevitore**, in modo che il **ricevitore non possa effettivamente "sentire" il codice**; una volta fatto ciò, è sufficiente **catturare e riprodurre** il codice dopo aver interrotto il jamming.

A un certo punto la vittima utilizzerà le **chiavi per chiudere l'automobile**, ma l'attacco avrà **registrato un numero sufficiente di codici "chiudi porta"** che potranno essere ritrasmessi per aprire la porta (potrebbe essere necessario **cambiare frequenza**, poiché alcune automobili utilizzano gli stessi codici per aprire e chiudere, ma ascoltano i due comandi su frequenze diverse).

> [!WARNING]
> Il **jamming funziona**, ma è rilevabile: se la **persona che chiude l'automobile verifica semplicemente le portiere** per assicurarsi che siano chiuse, si accorgerebbe che l'automobile è ancora aperta. Inoltre, se fosse a conoscenza di questo tipo di attacchi, potrebbe persino notare che le portiere non hanno mai emesso il **suono** della chiusura o che le **luci dell'automobile** non hanno lampeggiato quando ha premuto il pulsante "chiudi".

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Si tratta di una tecnica di **jamming più furtiva**. L'attaccante blocca il segnale, così quando la vittima prova a chiudere la portiera l'operazione non riesce, ma l'attaccante **registra questo codice**. Poi la vittima **prova nuovamente a chiudere l'automobile**, premendo il pulsante, e l'automobile **registra questo secondo codice**.\
Subito dopo, l'**attaccante può inviare il primo codice** e l'**automobile si chiuderà** (la vittima penserà che sia stata la seconda pressione a chiuderla). A quel punto l'attaccante potrà **inviare il secondo codice rubato per aprire** l'automobile (supponendo che un codice **"chiudi automobile" possa essere utilizzato anche per aprirla**). Potrebbe essere necessario cambiare frequenza (poiché alcune automobili utilizzano gli stessi codici per aprire e chiudere, ma ascoltano i due comandi su frequenze diverse).<sup>[[3]](#references)[[2]](#references)</sup>

L'attaccante può **bloccare il ricevitore dell'automobile, ma non il proprio ricevitore**, perché se il ricevitore dell'automobile ascolta, ad esempio, una banda larga di 1 MHz, l'attaccante non bloccherà **la frequenza esatta** utilizzata dal telecomando, ma **una frequenza vicina all'interno di quello spettro**, mentre il ricevitore dell'attaccante ascolterà un intervallo più ristretto, nel quale potrà ascoltare il segnale del telecomando **senza il segnale di jamming**.

> [!WARNING]
> Altre implementazioni osservate nelle specifiche mostrano che il **rolling code costituisce una parte** del codice totale inviato. Ad esempio, il codice inviato è una **chiave di 24 bit**, in cui i primi **12 bit sono il rolling code**, i successivi **8 bit sono il comando** (come chiudi o apri) e gli ultimi 4 bit sono il **checksum**. Anche i veicoli che implementano questo tipo di sistema sono naturalmente vulnerabili, poiché all'attaccante basta sostituire il segmento del rolling code per poter **utilizzare qualsiasi rolling code su entrambe le frequenze**.

> [!CAUTION]
> Nota che se la vittima invia un terzo codice mentre l'attaccante sta inviando il primo, il primo e il secondo codice verranno invalidati.

### Alarm Sounding Jamming Attack

Durante i test su un sistema a rolling code aftermarket installato su un'automobile, **l'invio immediato dello stesso codice due volte** **attivava l'allarme** e l'immobilizer, offrendo un'opportunità unica di **denial of service**. Ironicamente, il metodo per **disabilitare l'allarme** e l'immobilizer consisteva nel **premere** il **telecomando**, fornendo a un attaccante la possibilità di **eseguire continuamente un attacco DoS**. In alternativa, è possibile combinare questo attacco con il **precedente per ottenere più codici**, poiché la vittima cercherebbe di interrompere l'attacco il prima possibile.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
