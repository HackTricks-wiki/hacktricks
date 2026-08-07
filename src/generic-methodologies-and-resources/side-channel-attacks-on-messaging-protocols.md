# Side-Channel Attacks sulle ricevute di consegna nei messenger E2EE

{{#include ../banners/hacktricks-training.md}}

Le ricevute di consegna sono obbligatorie nei moderni messenger end-to-end encrypted (E2EE), perché i client devono sapere quando un ciphertext è stato decrittato, così da poter scartare lo stato del ratchet e le chiavi effimere. Il server inoltra blob opachi, quindi gli acknowledgement dei dispositivi (doppie spunte) vengono emessi dal destinatario dopo una decrittazione riuscita. Misurare il round-trip time (RTT) tra un'azione attivata dall'attacker e la relativa ricevuta di consegna espone un canale temporale ad alta risoluzione che fa leak dello stato del dispositivo e della presenza online, e può essere abusato per un DoS covert. Le implementazioni multi-device con "client-fanout" amplificano il leak, perché ogni dispositivo registrato decritta il probe e restituisce la propria ricevuta.<sup>[[1]](#references)</sup>

## Fonti delle ricevute di consegna vs. segnali visibili all'utente

Scegliere tipi di messaggio che emettano sempre una ricevuta di consegna, ma che non mostrino artefatti nella UI della vittima. La tabella seguente riassume il comportamento confermato empiricamente:<sup>[[1]](#references)</sup>

| Messenger | Azione | Ricevuta di consegna | Notifica alla vittima | Note |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Messaggio di testo | ● | ● | Sempre rumoroso → utile solo per bootstrap dello stato. |
| | Reazione | ● | ◐ (solo reagendo al messaggio della vittima) | Le auto-reazioni e le rimozioni restano silenziose. |
| | Modifica | ● | Silent push dipendente dalla piattaforma | Finestra di modifica ≈20 min; riceve comunque l'ack dopo la scadenza. |
| | Elimina per tutti | ● | ○ | La UI consente ~60 h, ma i pacchetti successivi ricevono comunque l'ack. |
| **Signal** | Messaggio di testo | ● | ● | Stesse limitazioni di WhatsApp. |
| | Reazione | ● | ◐ | Le auto-reazioni sono invisibili alla vittima. |
| | Modifica/Elimina | ● | ○ | Il server impone una finestra di ~48 h e consente fino a 10 modifiche, ma i pacchetti tardivi ricevono comunque l'ack. |
| **Threema** | Messaggio di testo | ● | ● | Le ricevute multi-device vengono aggregate, quindi per ogni probe diventa visibile un solo RTT. |

Legenda: ● = sempre, ◐ = condizionale, ○ = mai. Il comportamento della UI dipendente dalla piattaforma è indicato nelle note. Disabilitare le read receipts se necessario, ma le ricevute di consegna non possono essere disattivate in WhatsApp o Signal.<sup>[[1]](#references)</sup>

## Obiettivi e modelli dell'attacker

* **G1 – Fingerprinting dei dispositivi:** contare quante ricevute arrivano per ogni probe, raggruppare gli RTT per inferire OS/client (Android vs iOS vs desktop) e osservare le transizioni online/offline.
* **G2 – Monitoraggio comportamentale:** trattare la serie di RTT ad alta frequenza (≈1 Hz è stabile) come una serie temporale e inferire schermo acceso/spento, app in foreground/background, orari di spostamento rispetto a quelli di lavoro, ecc.
* **G3 – Esaurimento delle risorse:** mantenere attive radio/CPU di ogni dispositivo della vittima inviando probe silenziosi senza fine, consumando batteria/dati e degradando la qualità di VoIP/RTC.<sup>[[1]](#references)</sup>

Due threat actor sono sufficienti per descrivere la superficie d'abuso:<sup>[[1]](#references)</sup>

1. **Creepy companion:** condivide già una chat con la vittima e abusa di auto-reazioni, rimozioni di reazioni o modifiche/eliminazioni ripetute associate a message ID esistenti.
2. **Spooky stranger:** registra un burner account e invia reazioni che fanno riferimento a message ID mai esistiti nella conversazione locale; WhatsApp e Signal li decrittano e li riconoscono comunque, anche se la UI scarta il cambiamento di stato, quindi non è necessaria una conversazione precedente.

## Tooling per l'accesso al protocollo raw

Usare client che espongono il protocollo E2EE sottostante, così da poter creare pacchetti al di fuori dei vincoli della UI, specificare `message_id` arbitrari e registrare timestamp precisi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocollo WhatsApp Web) o [Cobalt](https://github.com/Auties00/Cobalt) (orientato al mobile) consentono di emettere frame raw `ReactionMessage`, `ProtocolMessage` (edit/delete) e `Receipt`, mantenendo sincronizzato lo stato del double-ratchet.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinato con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) espone ogni tipo di messaggio tramite CLI/API.<sup>[[5]](#references)[[7]](#references)</sup> La sintassi attuale di `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantenere in esecuzione `receive` o `daemon` per raccogliere effettivamente le ricevute di consegna.<sup>[[6]](#references)</sup> Esempio di toggle di un'auto-reazione:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** il codice sorgente del client Android documenta come le ricevute di consegna vengano consolidate prima di lasciare il dispositivo, spiegando perché il side channel abbia una bandwidth trascurabile.
* **PoC turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) include backend WhatsApp/Signal, usa come impostazione predefinita probe di eliminazione silenziosi e classifica `active` rispetto a `standby` con una soglia basata sulla mediana mobile (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) è una CLI più leggera, orientata innanzitutto a WhatsApp, con `--delay`, `--concurrent`, exporter CSV/Prometheus e output compatibile con Grafana.<sup>[[9]](#references)</sup> Considerarli entrambi strumenti di reconnaissance, non riferimenti del protocollo; il punto importante è quanto poco codice serva una volta ottenuto l'accesso a un client raw.

Quando il tooling custom non è disponibile, è comunque possibile attivare azioni silenziose da WhatsApp Web o Signal Desktop e sniffare il canale websocket/WebRTC cifrato, ma le raw API rimuovono i ritardi della UI e consentono operazioni non valide.

## Creepy companion: loop di campionamento silenzioso

1. Scegliere un qualsiasi messaggio storico scritto dall'attacker nella chat, così la vittima non vedrà cambiare i palloncini delle "reazioni".
2. Alternare tra un'emoji visibile e un payload di reazione vuoto (codificato come `""` nei protobuf di WhatsApp o come `--remove` in signal-cli). Ogni trasmissione produce un ack del dispositivo nonostante l'assenza di variazioni nella UI della vittima.
3. Registrare il momento dell'invio e l'arrivo di ogni ricevuta di consegna. Un loop a 1 Hz come il seguente fornisce indefinitamente tracce RTT per dispositivo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Poiché WhatsApp/Signal accettano aggiornamenti illimitati delle reazioni, l'attacker non deve mai pubblicare nuovi contenuti nella chat né preoccuparsi delle finestre di modifica.<sup>[[1]](#references)</sup>

## Spooky stranger: probing di numeri di telefono arbitrari

1. Registrare un nuovo account WhatsApp/Signal e recuperare le chiavi di identità pubbliche del numero target (operazione eseguita automaticamente durante il session setup).
2. Creare un pacchetto di reazione/modifica/eliminazione che faccia riferimento a un `message_id` casuale mai visto da nessuna delle due parti (WhatsApp accetta GUID arbitrari per `key.id`; Signal usa timestamp in millisecondi).
3. Inviare il pacchetto anche se non esiste alcun thread. I dispositivi della vittima lo decrittano, non riescono ad associare il messaggio di base, scartano il cambiamento di stato, ma riconoscono comunque il ciphertext in ingresso e inviano le ricevute del dispositivo all'attacker.
4. Ripetere continuamente per costruire serie RTT senza comparire nell'elenco chat della vittima.<sup>[[1]](#references)</sup>

Se prima è necessario scoprire quali numeri sono registrati o si desidera pre-popolare gli inventari dei dispositivi su larga scala, concatenare questa attività con [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) invece di indovinare manualmente intervalli E.164 casuali.

I lavori pubblicati sul contact-discovery hanno mostrato perché questo sia importante dal punto di vista operativo: con tabelle accurate dei prefissi telefonici e risorse moderate, i ricercatori hanno potuto interrogare circa il `10%` dei numeri mobili statunitensi su WhatsApp e il `100%` su Signal prima di passare al probing mirato.<sup>[[11]](#references)</sup> In pratica, filtrare prima gli account attivi mantiene il budget per i silent probe concentrato sui numeri che decritteranno effettivamente i pacchetti.

Le versioni recenti di WhatsApp espongono anche `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Considerarla un limite al throughput, non una soluzione: ostacola soprattutto il flooding prolungato da parte di stranger e non è rilevante quando l'attacker è già un contatto noto.

## Riutilizzo di modifiche ed eliminazioni come trigger covert

* **Eliminazioni ripetute:** dopo che un messaggio è stato eliminato per tutti una volta, ulteriori pacchetti di eliminazione che fanno riferimento allo stesso `message_id` non producono effetti nella UI, ma ogni dispositivo li decritta e li riconosce comunque.
* **Operazioni fuori finestra:** WhatsApp impone nella UI finestre di ~60 h per l'eliminazione e ~20 min per la modifica; Signal impone ~48 h. I messaggi di protocollo creati al di fuori di queste finestre vengono ignorati silenziosamente sul dispositivo della vittima, ma le ricevute vengono trasmesse, consentendo agli attacker di effettuare probe indefinitamente anche molto tempo dopo la fine della conversazione.
* **Payload non validi:** corpi di modifica malformati o eliminazioni che fanno riferimento a messaggi già eliminati producono lo stesso comportamento: decrittazione più ricevuta, senza artefatti visibili all'utente.<sup>[[1]](#references)</sup>

## Amplificazione e fingerprinting multi-device

* Ogni dispositivo associato (telefono, app desktop, browser companion) decritta il probe indipendentemente e restituisce il proprio ack. Contare le ricevute per probe rivela il numero esatto di dispositivi.
* Se un dispositivo è offline, la sua ricevuta viene accodata ed emessa alla riconnessione. Le lacune fanno quindi leak dei cicli online/offline e persino degli orari degli spostamenti (ad esempio, le ricevute desktop si interrompono durante i viaggi).
* Le distribuzioni RTT differiscono in base alla piattaforma a causa del power management dell'OS e dei push wakeup. Raggruppare gli RTT (ad esempio con k-means su feature di mediana/varianza) per classificare “Android handset", “iOS handset", “Electron desktop", ecc.
* Poiché il mittente deve recuperare l'inventario delle chiavi del destinatario prima di cifrare, l'attacker può anche osservare quando vengono associati nuovi dispositivi; un aumento improvviso del numero di dispositivi o un nuovo cluster RTT è un indicatore forte.<sup>[[1]](#references)</sup>

## Cadenza di campionamento, accodamento e ricevute sovrapposte

* **Tolleranza ai burst di WhatsApp:** le misurazioni pubblicate hanno riportato che WhatsApp accettava burst di reazioni silenziose fino a un probe ogni `50 ms` senza un evidente accodamento lato server. Ciò è utile per brevi burst di calibrazione, per contare rapidamente i dispositivi o per aumentare velocemente un drain attack.
* **Accodamento a lungo termine di Signal:** Signal tollerava brevi burst, ma iniziava ad accodare traffico sostenuto di più probe al secondo. Per il monitoraggio a lungo termine, mantenere la cadenza intorno a `1 Hz` (o inferiore), così ogni ricevuta rifletta ancora lo stato corrente del dispositivo invece dello svuotamento di una coda arretrata.
* **Artefatti di riconnessione:** quando un dispositivo torna online, alcuni client raggruppano o scaricano rapidamente più ricevute ritardate. Trattare questi burst di ricevute come indicatori di transizione di stato, non come campioni RTT indipendenti; altrimenti il classificatore per il clustering / `active` vs `idle` farà overfitting sul rumore di riconnessione.<sup>[[1]](#references)</sup>

## Inferenza del comportamento dalle tracce RTT

1. Campionare a ≥1 Hz per catturare gli effetti dello scheduling dell'OS. Con WhatsApp su iOS, RTT inferiori a 1 s correlano fortemente con schermo acceso/foreground, mentre RTT superiori a 1 s correlano con throttling a schermo spento/in background.
2. Creare classificatori semplici (thresholding o k-means a due cluster) che etichettino ogni RTT come "active" o "idle". Aggregare le etichette in sequenze per ricavare orari di sonno, spostamenti, orari di lavoro o i periodi di attività del companion desktop.
3. Correlare probe simultanei verso ogni dispositivo per osservare quando gli utenti passano dal mobile al desktop, quando i companion vanno offline e se l'app è rate limited da push o da socket persistente.
4. Nelle reti reali, evitare una singola soglia hardcoded di `1 s`. Eseguire il bootstrap di ogni dispositivo con una breve finestra di warm-up e mantenere una baseline mobile (ad esempio, `threshold = 0.9 * median RTT`), così il drift tra Wi-Fi e rete cellulare non faccia collassare il classificatore.<sup>[[1]](#references)</sup>

## Inferenza della posizione dal RTT di consegna

La stessa primitiva temporale può essere riutilizzata per inferire dove si trovi il destinatario, non solo se sia attivo. Il lavoro `Hope of Delivery` ha mostrato che il training sulle distribuzioni RTT relative a posizioni note del ricevitore consente a un attacker di classificare in seguito la posizione della vittima usando soltanto le conferme di consegna:<sup>[[2]](#references)</sup>

* Creare una baseline per lo stesso target mentre si trova in diversi luoghi noti (casa, ufficio, campus, paese A rispetto al paese B, ecc.).
* Per ogni posizione, raccogliere molti RTT di messaggi normali ed estrarre feature semplici come mediana, varianza o bucket di percentile.
* Durante l'attacco reale, confrontare la nuova serie di probe con i cluster sottoposti a training. Il paper riporta che spesso è possibile distinguere persino posizioni nella stessa città, con un'accuratezza `>80%` in uno scenario con 3 posizioni.
* Il metodo funziona meglio quando l'attacker controlla l'ambiente del mittente ed esegue i probe in condizioni di rete simili, perché il percorso misurato include la rete di accesso del destinatario, la latenza del wake-up e l'infrastruttura del messenger.<sup>[[2]](#references)</sup>

A differenza degli attacchi basati su reazioni/modifiche/eliminazioni silenziose descritti sopra, l'inferenza della posizione non richiede message ID non validi né pacchetti stealth che cambino lo stato. Sono sufficienti messaggi normali con conferme di consegna standard, quindi il compromesso è una stealthiness inferiore ma un'applicabilità più ampia tra i messenger.

## Esaurimento stealth delle risorse

Poiché ogni probe silenzioso deve essere decrittato e riconosciuto, l'invio continuo di toggle di reazioni, modifiche non valide o pacchetti di eliminazione per tutti crea un DoS a livello applicativo:<sup>[[1]](#references)</sup>

* Forza radio/modem a trasmettere e ricevere ogni secondo → consumo evidente della batteria, soprattutto sui telefoni inattivi.
* Genera traffico upstream/downstream non conteggiato che consuma i piani dati mobili mimetizzandosi nel rumore TLS/WebSocket.
* Occupa i thread crittografici e introduce jitter nelle funzionalità sensibili alla latenza (VoIP, videochiamate), anche se l'utente non visualizza notifiche.
* Su WhatsApp, le reazioni non valide accettano molti più dati di quanto suggerisca una normale emoji: le misurazioni pubblicate hanno rilevato un'accettazione lato server fino a circa `1 MB` per reazione.
* Le reazioni sovradimensionate smettono di produrre ricevute di consegna affidabili quando il corpo supera circa `30 bytes`, ma vengono comunque inoltrate ed elaborate prima di essere scartate. Mantenere piccoli i corpi delle reazioni quando servono gli ACK; aumentarne le dimensioni solo quando l'obiettivo è un puro drain o un trasporto covert unidirezionale.
* Le misurazioni pubbliche hanno raggiunto circa `3.7 MB/s` (`~13.3 GB/h`) di traffico della vittima in questa modalità.

## Riferimenti

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
