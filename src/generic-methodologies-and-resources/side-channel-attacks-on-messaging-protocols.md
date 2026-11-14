# Attacchi side-channel basati sulle ricevute di consegna nei messenger E2EE

{{#include ../banners/hacktricks-training.md}}

Le ricevute di consegna sono obbligatorie nei moderni messenger con crittografia end-to-end (E2EE), perché i client devono sapere quando un ciphertext è stato decifrato, così da poter eliminare lo stato di ratcheting e le chiavi effimere. Il server inoltra blob opachi, quindi le conferme dei dispositivi (doppie spunte) vengono inviate dal destinatario dopo la decifratura riuscita. Misurare il tempo di andata e ritorno (RTT) tra un’azione attivata dall’attaccante e la corrispondente ricevuta di consegna espone un canale temporale ad alta risoluzione che leak lo stato del dispositivo e la presenza online, e può essere sfruttato per un DoS covert. Le implementazioni multi-dispositivo con architettura "client-fanout" amplificano il leak perché ogni dispositivo registrato decifra la probe e invia la propria ricevuta.<sup>[[1]](#references)</sup>

## Fonti delle ricevute di consegna e segnali visibili all’utente

Scegli tipi di messaggio che generino sempre una ricevuta di consegna, ma non mostrino elementi dell’interfaccia alla vittima. La tabella seguente riassume i comportamenti confermati empiricamente:<sup>[[1]](#references)</sup>

| Messenger | Azione | Ricevuta di consegna | Notifica alla vittima | Note |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Messaggio di testo | ● | ● | Sempre rumoroso → utile solo per inizializzare lo stato. |
| | Reazione | ● | ◐ (solo se applicata a un messaggio della vittima) | Le reazioni ai propri messaggi e le rimozioni restano silenziose. |
| | Modifica | ● | Push silenziosa, a seconda della piattaforma | Finestra di modifica ≈20 min; la ricevuta viene comunque inviata anche dopo la scadenza. |
| | Elimina per tutti | ● | ○ | L’interfaccia consente ~60 h, ma i pacchetti successivi ricevono comunque una conferma. |
| **Signal** | Messaggio di testo | ● | ● | Stesse limitazioni di WhatsApp. |
| | Reazione | ● | ◐ | Le reazioni ai propri messaggi sono invisibili alla vittima. |
| | Modifica/Eliminazione | ● | ○ | Il server impone una finestra di ~48 h e consente fino a 10 modifiche, ma i pacchetti tardivi ricevono comunque una conferma. |
| **Threema** | Messaggio di testo | ● | ● | Le ricevute multi-dispositivo sono aggregate, quindi per ogni probe è visibile un solo RTT. |

Legenda: ● = sempre, ◐ = condizionale, ○ = mai. I comportamenti dell’interfaccia che dipendono dalla piattaforma sono indicati nelle note. Se necessario, disattiva le ricevute di lettura, ma le ricevute di consegna non possono essere disattivate in WhatsApp o Signal.<sup>[[1]](#references)</sup>

## Obiettivi e modelli dell’attaccante

* **G1 – Fingerprinting dei dispositivi:** conta quante ricevute arrivano per ogni probe, raggruppa gli RTT per dedurre il sistema operativo/client (Android vs iOS vs desktop) e osserva le transizioni online/offline.
* **G2 – Monitoraggio comportamentale:** considera la serie di RTT ad alta frequenza (≈1 Hz è stabile) come una serie temporale e deduci se lo schermo è acceso/spento, se l’app è in primo piano/in background, gli orari degli spostamenti rispetto a quelli di lavoro, ecc.
* **G3 – Esaurimento delle risorse:** mantiene attive le radio/CPU di ogni dispositivo della vittima inviando probe silenziose senza interruzione, consumando batteria/dati e degradando la qualità delle videochiamate.<sup>[[1]](#references)</sup>

Due attori malevoli bastano per descrivere la superficie di abuso:<sup>[[1]](#references)</sup>

1. **Compagno inquietante:** ha già una chat in comune con la vittima e abusa delle reazioni ai propri messaggi, della rimozione delle reazioni o di modifiche/eliminazioni ripetute associate a ID di messaggi esistenti.
2. **Estraneo inquietante:** registra un account usa e getta e invia reazioni che fanno riferimento a ID di messaggi mai esistiti nella conversazione locale; WhatsApp e Signal li decifrano e inviano comunque una conferma, anche se l’interfaccia scarta la modifica dello stato, quindi non è necessaria alcuna conversazione precedente.

## Strumenti per l’accesso al protocollo raw

Affidati a client che espongono una parte sufficiente del protocollo E2EE sottostante per creare pacchetti supportati al di fuori dei vincoli dell’interfaccia e registrare timestamp precisi; l’uso di ID di messaggio arbitrari va verificato per ogni implementazione:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multi-dispositivo di WhatsApp Web) documenta l’invio e la ricezione delle ricevute di consegna; [Cobalt](https://github.com/Auties00/Cobalt) (API non ufficiale Java/Kotlin per Web e dispositivi mobili) documenta operazioni sui messaggi come reagire, modificare ed eliminare. Usa le API documentate invece di presumere che ogni frame interno sia esposto.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) espone interfacce CLI, JSON-RPC e D-Bus, mentre [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) è una libreria Java per comunicare con Signal.<sup>[[5]](#references)[[7]](#references)</sup> La sintassi attuale di `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; lascia `receive` o `daemon` in esecuzione affinché gli aggiornamenti del protocollo continuino a essere elaborati.<sup>[[6]](#references)</sup> Esempio di attivazione/disattivazione di una reazione al proprio messaggio:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Le misurazioni riportate nel paper Careless Whisper hanno rilevato che le conferme di consegna sono sincronizzate tra i dispositivi, quindi viene esposta una sola conferma per messaggio anche in una configurazione multi-dispositivo.<sup>[[1]](#references)</sup>
* **PoC pronti all'uso:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) include backend per WhatsApp/Signal, usa per impostazione predefinita sonde di eliminazione silenziosa e distingue `active` da `standby` con una soglia basata sulla mediana mobile (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) è una CLI più leggera, pensata principalmente per WhatsApp, con `--delay`, `--concurrent`, esportatori CSV/Prometheus e output compatibile con Grafana.<sup>[[9]](#references)</sup> Considerali entrambi strumenti di ricognizione, non riferimenti per il protocollo; il punto importante è quanto poco codice serva una volta ottenuto l'accesso diretto al client.

Quando non sono disponibili strumenti personalizzati, i client ufficiali o gli strumenti per sviluppatori del browser possono comunque attivare azioni silenziose e rivelare i tempi del traffico cifrato; le API raw eliminano i ritardi dell'interfaccia e consentono operazioni non valide.<sup>[[1]](#references)</sup>

## Compagno inquietante: ciclo di campionamento silenzioso

1. Scegli un qualsiasi messaggio storico che hai scritto nella chat, così la vittima non vedrà mai cambiare le "reazioni".
2. Alterna tra un'emoji visibile e un payload di reazione vuoto (codificato come `""` nei protobuf di WhatsApp o come `--remove` in signal-cli). Ogni trasmissione genera un ack del dispositivo anche se per la vittima non cambia nulla nell'interfaccia.
3. Registra l'ora di invio e l'arrivo di ogni conferma di consegna. Un ciclo a 1 Hz come il seguente fornisce indefinitamente tracce RTT per dispositivo:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Poiché WhatsApp/Signal accettano aggiornamenti delle reazioni senza limiti, l'attaccante non deve mai pubblicare nuovi contenuti in chat né preoccuparsi delle finestre temporali per le modifiche.<sup>[[1]](#references)</sup>

## Sconosciuto inquietante: sondare numeri di telefono arbitrari

1. Registra un nuovo account WhatsApp/Signal e recupera le chiavi di identità pubbliche del numero target (operazione eseguita automaticamente durante la configurazione della sessione).
2. Crea un pacchetto di reazione che faccia riferimento a un `message_id` casuale, mai visto da nessuna delle due parti; lo studio riferisce che WhatsApp e Signal accettano queste reazioni e generano comunque ricevute di consegna.<sup>[[1]](#references)</sup>
3. Invia il pacchetto anche se non esiste alcuna conversazione. I dispositivi della vittima lo decifrano, non riescono a trovare il messaggio di base e scartano la modifica di stato, ma confermano comunque la ricezione del testo cifrato in arrivo, inviando all'attaccante ricevute del dispositivo.
4. Ripeti continuamente per creare serie di RTT senza una conversazione precedente né notifiche visibili.<sup>[[1]](#references)</sup>

Se prima devi scoprire quali numeri sono registrati o vuoi precaricare gli inventari dei dispositivi su larga scala, combina questa tecnica con gli [oracoli di contact-discovery / registrazione](../pentesting-web/registration-vulnerabilities.md) invece di indovinare manualmente intervalli E.164 casuali.

Le ricerche pubblicate sul contact-discovery hanno mostrato perché questo è importante sul piano operativo: usando tabelle accurate dei prefissi telefonici e risorse modeste, i ricercatori sono riusciti a interrogare circa il `10%` dei numeri di cellulare statunitensi su WhatsApp e il `100%` su Signal, prima di passare ai test mirati.<sup>[[11]](#references)</sup> In pratica, filtrare prima gli account attivi permette di concentrare il budget dei probe silenziosi sui numeri che decifreranno effettivamente i pacchetti.

Le versioni recenti di WhatsApp espongono anche l'opzione `Impostazioni -> Privacy -> Avanzate -> Blocca i messaggi provenienti da account sconosciuti`.<sup>[[10]](#references)</sup> Considerala un limite alla velocità: la documentazione del tracker dice che WhatsApp blocca i messaggi ad alto volume provenienti da account sconosciuti, ma non rivela la soglia, quindi non impedisce del tutto le reazioni usate come probe.<sup>[[8]](#references)</sup>

## Riciclare modifiche ed eliminazioni come trigger covert

* **Eliminazioni ripetute:** dopo che un messaggio è stato eliminato per tutti, ulteriori pacchetti di eliminazione che fanno riferimento allo stesso `message_id` non producono effetti nell'interfaccia, ma ogni dispositivo li decifra e li conferma comunque.
* **Operazioni fuori dalla finestra temporale:** WhatsApp applica nell'interfaccia finestre di circa 60 h per l'eliminazione e 20 min per la modifica; Signal applica una finestra di circa 48 h. I messaggi di protocollo creati al di fuori di queste finestre vengono ignorati silenziosamente sul dispositivo della vittima, ma le ricevute vengono comunque trasmesse: gli attaccanti possono quindi sondare a tempo indeterminato anche molto tempo dopo la fine della conversazione.
* **Payload non validi:** lo studio riferisce che i messaggi non validi possono comunque essere confermati; il comportamento esatto per i corpi malformati o gli ID eliminati dipende dall'implementazione, quindi verifica prima di farvi affidamento.<sup>[[1]](#references)</sup>

## Amplificazione e fingerprinting multi-dispositivo

* Su WhatsApp e Signal, ogni dispositivo associato (telefono, app desktop, browser companion) decifra il probe in modo indipendente e restituisce il proprio ack. Contando le ricevute per ogni probe si può rilevare il numero esatto di dispositivi.<sup>[[1]](#references)</sup>
* Se un dispositivo è offline, la sua ricevuta viene messa in coda e inviata alla riconnessione. Le interruzioni rivelano quindi i cicli online/offline e persino gli orari degli spostamenti (ad esempio, le ricevute desktop cessano durante i viaggi).
* Le distribuzioni RTT variano in base alla piattaforma e all'ambiente, perché sistema operativo, modello, client e condizioni di rete influiscono sui tempi. Raggruppa gli RTT (ad esempio, con k-means su caratteristiche di mediana/varianza) per classificare dispositivi come «telefono Android», «telefono iOS», «desktop Electron» e così via.
* Poiché il mittente deve recuperare l'inventario delle chiavi del destinatario prima di cifrare, l'attaccante può anche osservare quando vengono associati nuovi dispositivi; un aumento improvviso del numero di dispositivi o un nuovo cluster RTT è un forte indicatore.<sup>[[1]](#references)</sup>

**Fingerprinting tramite ricevute in coda:** invia diversi probe con ID messaggio distinti mentre il dispositivo target è offline. Quando si riconnette, correla gli ID nelle ricevute di consegna restituite e verifica se sono separate o raggruppate in un'unica ricevuta, e se gli ID raggruppati mantengono o invertono l'ordine di invio. Nei client testati, WhatsApp per Android/iOS restituiva ricevute di consegna separate, mentre Web, Windows e macOS le raggruppavano; macOS invertiva l'ordine degli ID raggruppati. Signal Desktop raggruppava le ricevute, a differenza dei client mobili. Questo permette di classificare un client che si riconnette anche quando le distribuzioni RTT si sovrappongono. Non confondere le ricevute di consegna con quelle di lettura, che seguono regole di raggruppamento diverse.<sup>[[1]](#references)</sup>

Per un probe WhatsApp distinto che legge le **ricariche delle prekey lato server** senza consegnare messaggi, vedi [Side channel di esaurimento e ricarica del bundle di prekey](whatsapp-prekey-bundle-side-channel.md).

## Frequenza di campionamento, accodamento e ricevute raggruppate

* **Tolleranza di WhatsApp ai burst:** le misurazioni pubblicate riferiscono che WhatsApp accettava burst di reazioni silenziose fino a un probe ogni `50 ms` senza un evidente accodamento lato server. Questo è utile per brevi burst di calibrazione, conteggi rapidi dei dispositivi o per aumentare rapidamente il ritmo di un drain attack.
* **Accodamento prolungato di Signal:** Signal tollerava brevi burst, ma iniziava ad accodare il traffico sostenuto di più probe al secondo. Per il monitoraggio a lungo termine, mantieni la frequenza intorno a `1 Hz` (o meno), così ogni ricevuta riflette ancora lo stato attuale del dispositivo anziché lo svuotamento della coda.
* **Artefatti alla riconnessione:** quando un dispositivo torna online, alcuni client raggruppano o inviano rapidamente più ricevute ritardate. Considera questi burst di ricevute come indicatori di una transizione di stato, non come campioni RTT indipendenti, altrimenti il clustering / classificatore `attivo` vs `inattivo` si adatterà eccessivamente al rumore della riconnessione.<sup>[[1]](#references)</sup>

## Inferire il comportamento dalle tracce RTT

1. Campiona a ≥1 Hz per acquisire gli effetti della pianificazione del sistema operativo. Con WhatsApp su iOS, RTT <1 s è fortemente correlato allo schermo acceso/app in primo piano, mentre RTT >1 s è correlato allo schermo spento/limitazioni in background.
2. Crea classificatori semplici (con soglie o k-means a due cluster) che etichettino ogni RTT come «attivo» o «inattivo». Aggrega le etichette in sequenze per dedurre orari di sonno, spostamenti, orari di lavoro o i momenti in cui è attivo il companion desktop.
3. Correlaziona i probe simultanei verso ogni dispositivo per vedere quando gli utenti passano dal mobile al desktop, quando i companion vanno offline e se l'app è soggetta a rate limiting tramite push o socket persistente.
4. Nelle reti reali, evita una singola soglia rigida di `1 s`. Inizializza ogni dispositivo con una breve finestra di warm-up e mantieni una baseline mobile (ad esempio, la PoC device-activity-tracker usa `threshold = 0.9 * median RTT`) per evitare che le variazioni tra Wi-Fi e rete cellulare compromettano il classificatore.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferire la posizione dagli RTT di consegna

La stessa primitiva temporale può essere riutilizzata per inferire dove si trova il destinatario, non solo se è attivo. Lo studio `Hope of Delivery` ha mostrato che, addestrando un modello sulle distribuzioni RTT di posizioni note dei destinatari, un attaccante può poi classificare la posizione della vittima basandosi sulle sole conferme di consegna:<sup>[[2]](#references)</sup>

* Crea una baseline per lo stesso target mentre si trova in diversi luoghi noti (casa, ufficio, campus, paese A rispetto al paese B e così via).
* Per ogni posizione, raccogli molti RTT di messaggi normali ed estrai caratteristiche semplici, come mediana, varianza o fasce di percentili.
* Durante l'attacco vero e proprio, confronta la nuova serie di probe con i cluster addestrati. Lo studio riferisce che spesso si possono distinguere persino località nella stessa città, con un'accuratezza `>80%` in uno scenario con 3 posizioni.
* Il metodo funziona meglio quando l'attaccante controlla l'ambiente del mittente e invia probe in condizioni di rete simili, perché il percorso misurato include la rete di accesso del destinatario, la latenza di riattivazione e l'infrastruttura del messenger.<sup>[[2]](#references)</sup>

A differenza degli attacchi silenziosi basati su reazioni/modifiche/eliminazioni descritti sopra, l'inferenza della posizione non richiede ID messaggio non validi né pacchetti furtivi che modificano lo stato. Sono sufficienti messaggi normali con normali conferme di consegna, quindi il compromesso è una minore furtività ma un'applicabilità più ampia tra i messenger.

## Esaurimento furtivo delle risorse

Poiché ogni probe silenzioso deve essere decifrato e confermato, inviare continuamente toggle di reazione, modifiche non valide o pacchetti di eliminazione per tutti crea un DoS a livello applicativo:<sup>[[1]](#references)</sup>

* Costringe la radio/modem a trasmettere/ricevere ogni secondo → consumo della batteria evidente, soprattutto sui telefoni inattivi.
* Genera traffico in entrata e in uscita che consuma i piani dati mobili e può competere con funzionalità sensibili alla latenza, come le videochiamate.<sup>[[1]](#references)</sup>
* I payload non validi di grandi dimensioni aumentano il carico di elaborazione, ma lo studio riferisce che la crittografia incide in modo trascurabile sul consumo della batteria.<sup>[[1]](#references)</sup>
* Su WhatsApp, le reazioni non valide accettano molti più dati di quanto farebbe pensare una normale emoji: misurazioni pubblicate hanno rilevato un'accettazione lato server fino a circa `1 MB` per reazione.
* Le reazioni sovradimensionate smettono di produrre ricevute di consegna affidabili quando il corpo supera circa `30 bytes`, ma vengono comunque inoltrate ed elaborate prima di essere scartate. Mantieni i corpi delle reazioni molto piccoli quando servono gli ACK; aumentali solo quando l'obiettivo è il puro drain o un trasporto covert unidirezionale.
* Le misurazioni pubbliche hanno raggiunto circa `3.7 MB/s` (`~13.3 GB/h`) di traffico sulla vittima con questa modalità.



## References

- [1] [Sussurro incauto: sfruttare le ricevute di consegna silenziose per monitorare gli utenti sui messenger mobili](https://arxiv.org/html/2411.11194v4)
- [2] [La speranza di una consegna: estrarre la posizione degli utenti dai messenger mobili](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [pagina man di signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Come bloccare grandi volumi di messaggi sconosciuti | Centro assistenza WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Tutti i numeri sono statunitensi: abuso su larga scala del contact-discovery nei messenger mobili](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
