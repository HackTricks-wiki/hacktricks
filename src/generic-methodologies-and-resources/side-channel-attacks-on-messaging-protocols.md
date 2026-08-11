# Attacchi side-channel tramite ricevute di consegna nei messenger E2EE

{{#include ../banners/hacktricks-training.md}}

Le ricevute di consegna sono obbligatorie nei moderni messenger end-to-end encrypted (E2EE), perché i client devono sapere quando un ciphertext è stato decrittato, così da poter eliminare lo stato del ratchet e le chiavi effimere. Il server inoltra blob opachi, quindi gli acknowledgement dei dispositivi (doppie spunte) vengono emessi dal destinatario dopo una decrittazione riuscita. Misurare il round-trip time (RTT) tra un'azione attivata dall'attaccante e la ricevuta di consegna corrispondente espone un canale temporale ad alta risoluzione che fa leak dello stato del dispositivo e della presenza online, e può essere usato per un covert DoS. Le implementazioni multi-device con "client-fanout" amplificano il leak, perché ogni dispositivo registrato decritta la probe e restituisce la propria ricevuta.<sup>[[1]](#references)</sup>

## Sorgenti delle ricevute di consegna vs. segnali visibili all'utente

Scegliere tipi di messaggio che emettano sempre una ricevuta di consegna, ma che non mostrino artefatti UI sulla vittima. La tabella seguente riassume il comportamento confermato empiricamente:<sup>[[1]](#references)</sup>

| Messenger | Azione | Ricevuta di consegna | Notifica alla vittima | Note |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Messaggio di testo | ● | ● | Sempre rumoroso → utile solo per fare bootstrap dello stato. |
| | Reazione | ● | ◐ (solo se si reagisce al messaggio della vittima) | Le auto-reazioni e le rimozioni restano silenziose. |
| | Modifica | ● | Silent push dipendente dalla piattaforma | Finestra di modifica ≈20 min; riceve comunque l'ack dopo la scadenza. |
| | Elimina per tutti | ● | ○ | La UI consente ~60 h, ma i pacchetti successivi ricevono comunque l'ack. |
| **Signal** | Messaggio di testo | ● | ● | Stesse limitazioni di WhatsApp. |
| | Reazione | ● | ◐ | Le auto-reazioni sono invisibili alla vittima. |
| | Modifica/Eliminazione | ● | ○ | Il server impone una finestra di ~48 h e consente fino a 10 modifiche, ma i pacchetti tardivi ricevono comunque l'ack. |
| **Threema** | Messaggio di testo | ● | ● | Le ricevute multi-device sono aggregate, quindi per ogni probe diventa visibile un solo RTT. |

Legenda: ● = sempre, ◐ = condizionale, ○ = mai. Il comportamento UI dipendente dalla piattaforma è indicato inline. Disabilitare le read receipts se necessario, ma le delivery receipts non possono essere disattivate in WhatsApp o Signal.<sup>[[1]](#references)</sup>

## Obiettivi e modelli dell'attaccante

* **G1 – Fingerprinting dei dispositivi:** contare quante ricevute arrivano per ogni probe, raggruppare gli RTT per dedurre OS/client (Android vs iOS vs desktop) e osservare le transizioni online/offline.
* **G2 – Monitoraggio comportamentale:** trattare la serie di RTT ad alta frequenza (≈1 Hz è stabile) come una serie temporale e dedurre schermo acceso/spento, app in foreground/background, orari di spostamento rispetto agli orari di lavoro, ecc.
* **G3 – Esaurimento delle risorse:** mantenere attive radio/CPU di ogni dispositivo della vittima inviando probe silenziose senza fine, consumando batteria/dati e degradando la qualità delle videochiamate.<sup>[[1]](#references)</sup>

Due threat actor sono sufficienti per descrivere la superficie di abuso:<sup>[[1]](#references)</sup>

1. **Creepy companion:** condivide già una chat con la vittima e abusa di auto-reazioni, rimozioni di reazioni o modifiche/eliminazioni ripetute associate a message ID esistenti.
2. **Spooky stranger:** registra un burner account e invia reazioni che fanno riferimento a message ID mai esistiti nella conversazione locale; WhatsApp e Signal li decrittano e inviano comunque l'ack anche se la UI scarta il cambiamento di stato, quindi non è necessaria una conversazione precedente.

## Tooling per l'accesso al protocollo raw

Usare client che espongano una parte sufficiente del protocollo E2EE sottostante per creare pacchetti supportati al di fuori dei vincoli della UI e registrare timestamp precisi; per i message ID arbitrari è necessario verificare ogni implementazione:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API WhatsApp Web multidevice) documenta l'invio e la ricezione delle delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (API Web e mobile Java/Kotlin non ufficiale) documenta operazioni sui messaggi come reazioni, modifiche ed eliminazioni. Usare le API documentate invece di presumere che ogni frame interno sia esposto.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) espone interfacce CLI, JSON-RPC e D-Bus, mentre [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) è una libreria Java per comunicare con Signal.<sup>[[5]](#references)[[7]](#references)</sup> La sintassi attuale di `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantenere in esecuzione `receive` o `daemon` affinché gli aggiornamenti del protocollo continuino a essere elaborati.<sup>[[6]](#references)</sup> Esempio di toggle di un'auto-reazione:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** le misurazioni del paper Careless Whisper hanno rilevato che le delivery receipts sono sincronizzate tra i dispositivi, quindi viene esposta una sola ricevuta per messaggio anche in una configurazione multi-device.<sup>[[1]](#references)</sup>
* **PoC turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) include backend WhatsApp/Signal, usa per impostazione predefinita probe di eliminazione silenziose e contrassegna `active` rispetto a `standby` con una soglia basata sulla mediana mobile (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) è una CLI più leggera orientata prima di tutto a WhatsApp, con `--delay`, `--concurrent`, exporter CSV/Prometheus e output adatto a Grafana.<sup>[[9]](#references)</sup> Considerarli entrambi strumenti di ricognizione, non riferimenti al protocollo; l'aspetto importante è quanto poco codice sia necessario una volta disponibile l'accesso raw al client.

Quando il tooling custom non è disponibile, i client ufficiali o gli strumenti per sviluppatori del browser possono comunque attivare azioni silenziose ed esporre il timing del traffico cifrato; le API raw eliminano i ritardi della UI e consentono operazioni non valide.<sup>[[1]](#references)</sup>

## Creepy companion: loop di sampling silenzioso

1. Scegliere un qualsiasi messaggio storico scritto dall'attaccante nella chat, così la vittima non vedrà cambiare i balloon delle "reazioni".
2. Alternare tra un'emoji visibile e un payload di reazione vuoto (codificato come `""` nei protobuf di WhatsApp o come `--remove` in signal-cli). Ogni trasmissione produce un device ack nonostante l'assenza di variazioni UI per la vittima.
3. Registrare il momento dell'invio e l'arrivo di ogni delivery receipt. Un loop a 1 Hz come il seguente fornisce indefinitamente tracce RTT per dispositivo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Poiché WhatsApp/Signal accettano aggiornamenti illimitati delle reazioni, l'attaccante non deve mai pubblicare nuovi contenuti nella chat né preoccuparsi delle finestre di modifica.<sup>[[1]](#references)</sup>

## Spooky stranger: probing di numeri di telefono arbitrari

1. Registrare un nuovo account WhatsApp/Signal e recuperare le chiavi di identità pubbliche del numero target (operazione eseguita automaticamente durante il session setup).
2. Creare un pacchetto di reazione che faccia riferimento a un `message_id` casuale mai visto da nessuna delle due parti; il paper riporta che sia WhatsApp sia Signal accettano tali reazioni e generano comunque delivery receipts.<sup>[[1]](#references)</sup>
3. Inviare il pacchetto anche se non esiste alcun thread. I dispositivi della vittima lo decrittano, non riescono ad associare il messaggio base, scartano il cambiamento di stato, ma inviano comunque l'ack del ciphertext in ingresso, restituendo le ricevute del dispositivo all'attaccante.
4. Ripetere continuamente per creare serie di RTT senza una conversazione precedente o una notifica visibile.<sup>[[1]](#references)</sup>

Se prima è necessario scoprire quali numeri sono registrati o si vogliono pre-seminare inventari dei dispositivi su larga scala, concatenare questa procedura con gli [oracle di contact-discovery / registrazione](../pentesting-web/registration-vulnerabilities.md) invece di indovinare manualmente intervalli E.164 casuali.

Il lavoro pubblicato sul contact-discovery ha mostrato perché questo è importante a livello operativo: usando tabelle accurate dei prefissi telefonici e risorse moderate, i ricercatori sono riusciti a interrogare circa il `10%` dei numeri mobili statunitensi su WhatsApp e il `100%` su Signal prima di passare al probing mirato.<sup>[[11]](#references)</sup> Nella pratica, filtrare prima gli account attivi mantiene il budget per le silent probe concentrato sui numeri che decritteranno effettivamente i pacchetti.

Le build recenti di WhatsApp espongono anche `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Considerarlo un limitatore di throughput: la documentazione del tracker afferma che WhatsApp blocca i messaggi ad alto volume provenienti da account sconosciuti, ma non divulga la soglia, quindi non impedisce completamente le probe reaction.<sup>[[8]](#references)</sup>

## Riciclare modifiche ed eliminazioni come trigger covert

* **Eliminazioni ripetute:** dopo che un messaggio è stato eliminato per tutti una volta, ulteriori pacchetti di eliminazione che fanno riferimento allo stesso `message_id` non hanno alcun effetto sulla UI, ma ogni dispositivo continua a decrittarli e a inviare l'ack.
* **Operazioni fuori finestra:** WhatsApp impone nella UI finestre di ~60 h per l'eliminazione e ~20 min per la modifica; Signal impone ~48 h. I messaggi di protocollo creati al di fuori di queste finestre vengono ignorati silenziosamente sul dispositivo della vittima, ma le ricevute vengono trasmesse, consentendo agli attaccanti di eseguire probe indefinitamente anche molto tempo dopo la fine della conversazione.
* **Payload non validi:** il paper riporta che i messaggi non validi possono comunque ricevere un ack; il comportamento esatto per body malformati o ID eliminati dipende dall'implementazione, quindi è necessario testarlo prima di farvi affidamento.<sup>[[1]](#references)</sup>

## Amplificazione e fingerprinting multi-device

* Su WhatsApp e Signal, ogni dispositivo associato (telefono, app desktop, browser companion) decritta la probe in modo indipendente e restituisce il proprio ack. Contare le ricevute per probe rivela il numero esatto di dispositivi.<sup>[[1]](#references)</sup>
* Se un dispositivo è offline, la sua ricevuta viene accodata e inviata alla riconnessione. Le interruzioni fanno quindi leak dei cicli online/offline e persino degli orari di spostamento (ad esempio, le ricevute desktop smettono di arrivare durante gli spostamenti).
* Le distribuzioni RTT differiscono in base alla piattaforma e all'ambiente, perché OS, modello, client e condizioni di rete influenzano il timing. Raggruppare gli RTT (ad esempio con k-means sulle feature di mediana/varianza) per classificare "telefono Android", "telefono iOS", "desktop Electron", ecc.
* Poiché il mittente deve recuperare l'inventario delle chiavi del destinatario prima di cifrare, l'attaccante può anche osservare quando vengono associati nuovi dispositivi; un improvviso aumento del numero di dispositivi o un nuovo cluster RTT è un forte indicatore.<sup>[[1]](#references)</sup>

## Cadenza di sampling, accodamento e ricevute sovrapposte

* **Tolleranza ai burst di WhatsApp:** le misurazioni pubblicate hanno riportato che WhatsApp accettava burst di silent reaction fino a una probe ogni `50 ms` senza un evidente accodamento lato server. Ciò è utile per brevi burst di calibrazione, per contare rapidamente i dispositivi o per aumentare rapidamente un drain attack.
* **Accodamento a lungo termine di Signal:** Signal tollerava burst brevi, ma iniziava ad accodare traffico sostenuto di diverse probe al secondo. Per il monitoraggio a lungo termine, mantenere la cadenza intorno a `1 Hz` (o inferiore), così ogni ricevuta riflette ancora lo stato attuale del dispositivo invece di svuotare una coda arretrata.
* **Artefatti di riconnessione:** quando un dispositivo torna online, alcuni client raggruppano o scaricano rapidamente più ricevute ritardate. Trattare questi burst di ricevute come indicatori di transizione di stato, non come campioni RTT indipendenti; in caso contrario il clustering / classificatore `active` rispetto a `idle` farà overfit sul rumore della riconnessione.<sup>[[1]](#references)</sup>

## Inferenza del comportamento dalle tracce RTT

1. Eseguire il sampling a ≥1 Hz per catturare gli effetti dello scheduling dell'OS. Con WhatsApp su iOS, RTT <1 s è fortemente correlato a schermo acceso/foreground, mentre RTT >1 s è correlato a schermo spento/background throttling.
2. Creare classificatori semplici (thresholding o k-means a due cluster) che etichettino ogni RTT come "active" o "idle". Aggregare le etichette in sequenze per dedurre orari di sonno, spostamenti, orari di lavoro o i periodi di attività del desktop companion.
3. Correlare probe simultanee verso ogni dispositivo per osservare quando gli utenti passano dal mobile al desktop, quando i companion vanno offline e se l'app è rate limited da push o persistent socket.
4. Nelle reti reali, evitare una singola soglia hardcoded di `1 s`. Eseguire il bootstrap di ogni dispositivo con una breve finestra di warm-up e mantenere una baseline mobile (ad esempio, la PoC device-activity-tracker usa `threshold = 0.9 * median RTT`), così la variazione Wi-Fi/cellulare non compromette il classificatore.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferenza della posizione dal delivery RTT

La stessa primitiva temporale può essere riutilizzata per dedurre dove si trova il destinatario, non solo se è attivo. Il lavoro `Hope of Delivery` ha mostrato che il training sulle distribuzioni RTT per posizioni note del ricevitore consente in seguito a un attaccante di classificare la posizione della vittima usando soltanto le delivery confirmations:<sup>[[2]](#references)</sup>

* Creare una baseline per lo stesso target mentre si trova in diverse posizioni note (casa, ufficio, campus, paese A rispetto al paese B, ecc.).
* Per ogni posizione, raccogliere molti RTT di messaggi normali ed estrarre feature semplici come mediana, varianza o bucket percentili.
* Durante l'attacco reale, confrontare la nuova serie di probe con i cluster addestrati. Il paper riporta che spesso è possibile distinguere persino posizioni nella stessa città, con accuratezza `>80%` in uno scenario con 3 posizioni.
* Questo funziona meglio quando l'attaccante controlla l'ambiente del mittente e invia le probe in condizioni di rete simili, perché il percorso misurato include la rete di accesso del destinatario, la latenza di riattivazione e l'infrastruttura del messenger.<sup>[[2]](#references)</sup>

A differenza degli attacchi tramite reazioni/modifiche/eliminazioni silenziose descritti sopra, l'inferenza della posizione non richiede message ID non validi o pacchetti stealth che cambiano lo stato. Sono sufficienti messaggi normali con normali delivery confirmations, quindi il compromesso consiste in una minore stealth ma in una più ampia applicabilità tra i messenger.

## Esaurimento stealth delle risorse

Poiché ogni probe silenziosa deve essere decrittata e ricevere un ack, l'invio continuo di toggle delle reazioni, modifiche non valide o pacchetti di eliminazione per tutti crea un DoS a livello applicativo:<sup>[[1]](#references)</sup>

* Costringe radio/modem a trasmettere/ricevere ogni secondo → consumo della batteria evidente, soprattutto sui telefoni inattivi.
* Genera traffico upstream/downstream che consuma i piani dati mobili e può competere con funzionalità sensibili alla latenza, come le videochiamate.<sup>[[1]](#references)</sup>
* I payload non validi di grandi dimensioni aggiungono lavoro di elaborazione, ma il paper riporta che la crittografia stessa costituisce una parte trascurabile del consumo della batteria.<sup>[[1]](#references)</sup>
* Su WhatsApp, le reazioni non valide accettano molti più dati di quanto suggerisca una normale emoji: le misurazioni pubblicate hanno rilevato un'accettazione lato server fino a circa `1 MB` per reazione.
* Le reazioni sovradimensionate smettono di produrre delivery receipts affidabili quando il body supera circa `30 bytes`, ma vengono comunque inoltrate ed elaborate prima di essere scartate. Mantenere i body delle reazioni piccoli quando servono ACK; aumentarne le dimensioni solo quando l'obiettivo è il puro drain o un covert one-way transport.
* Le misurazioni pubbliche hanno raggiunto circa `3.7 MB/s` (`~13.3 GB/h`) di traffico della vittima in questa modalità.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
