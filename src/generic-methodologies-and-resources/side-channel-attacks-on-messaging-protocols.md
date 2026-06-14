# Side-Channel Attack sui delivery receipt in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

I delivery receipt sono obbligatori nei moderni messengers end-to-end encrypted (E2EE) perché i client devono sapere quando un ciphertext è stato decriptato, così possono scartare lo stato di ratcheting e le chiavi effimere. Il server inoltra blob opachi, quindi gli acknowledgements del device (doppie spunte) vengono emessi dal destinatario dopo la decrittazione riuscita. Misurare il round-trip time (RTT) tra un’azione innescata dall’attaccante e il corrispondente delivery receipt espone un canale temporale ad alta risoluzione che leak lo stato del device, la presenza online e può essere abusato per covert DoS. Le implementazioni multi-device "client-fanout" amplificano il leak perché ogni device registrato decripta il probe e restituisce il proprio receipt.

## Delivery receipt sources vs. segnali visibili all’utente

Scegli tipi di messaggio che emettono sempre un delivery receipt ma non mostrano artefatti UI sulla vittima. La tabella seguente riassume il comportamento confermato empiricamente:

| Messenger | Azione | Delivery receipt | Notifica alla vittima | Note |
|-----------|--------|------------------|-----------------------|-------|
| **WhatsApp** | Messaggio di testo | ● | ● | Sempre rumoroso → utile solo per bootstrap dello stato. |
| | Reaction | ● | ◐ (solo se reagisce a un messaggio della vittima) | Le self-reaction e le rimozioni restano silenziose. |
| | Edit | ● | Push silenzioso dipendente dalla piattaforma | Finestra di edit ≈20 min; comunque ack’d dopo la scadenza. |
| | Delete for everyone | ● | ○ | L’interfaccia consente ~60 h, ma i pacchetti successivi restano comunque ack’d. |
| **Signal** | Messaggio di testo | ● | ● | Stesse limitazioni di WhatsApp. |
| | Reaction | ● | ◐ | Le self-reaction sono invisibili alla vittima. |
| | Edit/Delete | ● | ○ | Il server impone una finestra di ~48 h, consente fino a 10 edit, ma i pacchetti tardivi restano comunque ack’d. |
| **Threema** | Messaggio di testo | ● | ● | I receipt multi-device sono aggregati, quindi per ogni probe diventa visibile solo un RTT. |

Legenda: ● = sempre, ◐ = condizionale, ○ = mai. Il comportamento UI dipendente dalla piattaforma è indicato inline. Disabilita i read receipts se necessario, ma i delivery receipt non possono essere disattivati in WhatsApp o Signal.

## Obiettivi e modelli dell’attaccante

* **G1 – Device fingerprinting:** Conta quanti receipt arrivano per ogni probe, clusterizza gli RTT per inferire OS/client (Android vs iOS vs desktop) e osserva le transizioni online/offline.
* **G2 – Behavioural monitoring:** Tratta la serie RTT ad alta frequenza (≈1 Hz è stabile) come una serie temporale e inferisci screen on/off, app in foreground/background, orari di spostamento vs lavoro, ecc.
* **G3 – Resource exhaustion:** Mantieni svegli radio/CPU di ogni device della vittima inviando probe silenziosi senza fine, scaricando batteria/dati e degradando la qualità VoIP/RTC.

Sono sufficienti due threat actor per descrivere la superficie di abuso:

1. **Creepy companion:** condivide già una chat con la vittima e abusa di self-reaction, rimozioni di reaction o edit/delete ripetuti legati a message ID già esistenti.
2. **Spooky stranger:** registra un account burner e invia reaction che fanno riferimento a message ID che non sono mai esistiti nella conversazione locale; WhatsApp e Signal li decriptano e li riconoscono comunque anche se la UI scarta il cambiamento di stato, quindi non serve una conversazione precedente.

## Tooling per l’accesso grezzo al protocollo

Affidati a client che espongono il protocollo E2EE sottostante, così puoi costruire pacchetti fuori dai vincoli della UI, specificare `message_id` arbitrari e registrare timestamp precisi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocollo WhatsApp Web) o [Cobalt](https://github.com/Auties00/Cobalt) (orientato al mobile) permettono di emettere frame grezzi `ReactionMessage`, `ProtocolMessage` (edit/delete) e `Receipt` mantenendo sincronizzato lo stato double-ratchet.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinato con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) espone ogni tipo di messaggio via CLI/API. La sintassi attuale di `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; tieni `receive` o `daemon` in esecuzione così i delivery receipt vengono davvero raccolti. Esempio di toggle self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Il codice sorgente del client Android documenta come i delivery receipt vengono consolidati prima di lasciare il device, spiegando perché lì il side channel ha banda trascurabile.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) include backend WhatsApp/Signal, usa di default silent delete probes e etichetta `active` vs `standby` con una soglia rolling-median (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) è un CLI più leggero, prima di WhatsApp, con `--delay`, `--concurrent`, exporter CSV/Prometheus e output compatibile con Grafana. Considera entrambi come helper di reconnaissance e non come riferimenti di protocollo; il punto importante è quanto poco codice serva una volta ottenuto l’accesso raw al client.

Quando non è disponibile tooling custom, puoi comunque attivare azioni silenziose da WhatsApp Web o Signal Desktop e sniffare il canale websocket/WebRTC cifrato, ma le API raw rimuovono i ritardi della UI e consentono operazioni non valide.

## Creepy companion: silent sampling loop

1. Scegli un qualunque messaggio storico che hai scritto nella chat, così la vittima non vede mai cambiare i balloon di "reaction".
2. Alterna tra un emoji visibile e un payload di reaction vuoto (codificato come `""` nei protobuf di WhatsApp o `--remove` in signal-cli). Ogni trasmissione genera un device ack nonostante nessun delta UI per la vittima.
3. Timestampa l’orario di invio e ogni arrivo dei delivery receipt. Un loop a 1 Hz come il seguente produce trace RTT per device in modo indefinito:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Poiché WhatsApp/Signal accettano aggiornamenti di reaction illimitati, l’attaccante non deve mai pubblicare nuovo contenuto nella chat né preoccuparsi delle finestre di edit.

## Spooky stranger: probing di numeri di telefono arbitrari

1. Registra un account WhatsApp/Signal nuovo e recupera le public identity keys per il numero target (fatto automaticamente durante il setup della sessione).
2. Costruisci un pacchetto reaction/edit/delete che faccia riferimento a un `message_id` casuale mai visto da nessuna delle due parti (WhatsApp accetta GUID arbitrari `key.id`; Signal usa timestamp in millisecondi).
3. Invia il pacchetto anche se non esiste alcun thread. I device della vittima lo decriptano, non riescono a matchare il messaggio base, scartano il cambiamento di stato, ma riconoscono comunque il ciphertext in arrivo, rimandando i delivery receipt all’attaccante.
4. Ripeti in modo continuo per costruire serie RTT senza mai comparire nella lista chat della vittima.

Se prima devi scoprire quali numeri sono registrati o vuoi pre-seed di inventari device su larga scala, collega questa tecnica con [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) invece di indovinare a mano range E.164 casuali.

Il lavoro pubblicato sul contact-discovery ha mostrato perché questo è operativo: con tabelle accurate dei prefissi telefonici e risorse modeste, i ricercatori sono riusciti a interrogare circa `10%` dei numeri mobili US su WhatsApp e `100%` su Signal prima di passare a probing mirato. In pratica, filtrare prima gli account attivi mantiene il budget dei silent probe focalizzato sui numeri che decriptano davvero i pacchetti.

Le build recenti di WhatsApp espongono anche `Settings -> Privacy -> Advanced -> Block unknown account messages`. Trattalo come un limitatore di throughput, non come una fix: colpisce soprattutto il flooding sostenuto solo da estranei ed è irrilevante una volta che sei già un contatto noto.

## Riutilizzare edit e delete come trigger covert

* **Repeated deletes:** Dopo che un messaggio è stato deleted-for-everyone una volta, ulteriori pacchetti delete che fanno riferimento allo stesso `message_id` non hanno effetto UI ma ogni device li decripta e li acknowledges comunque.
* **Out-of-window operations:** WhatsApp applica finestre di delete ~60 h / edit ~20 min nella UI; Signal applica ~48 h. I messaggi di protocollo costruiti fuori da queste finestre vengono ignorati silenziosamente sul device della vittima, ma i receipt vengono comunque trasmessi, quindi gli attaccanti possono fare probing per tempi molto lunghi dopo la fine della conversazione.
* **Invalid payloads:** Body di edit malformati o delete che fanno riferimento a messaggi già purgati generano lo stesso comportamento: decrittazione più receipt, zero artefatti visibili all’utente.

## Amplificazione multi-device e fingerprinting

* Ogni device associato (telefono, app desktop, companion browser) decripta il probe in modo indipendente e restituisce il proprio ack. Contare i receipt per probe rivela il numero esatto di device.
* Se un device è offline, il suo receipt viene accodato ed emesso alla riconnessione. Le lacune quindi leak cicli online/offline e persino gli orari di spostamento (per esempio, i receipt desktop si fermano durante il viaggio).
* Le distribuzioni RTT differiscono per piattaforma a causa del power management del sistema operativo e dei wakeup push. Clusterizza gli RTT (per esempio, k-means su feature mediana/varianza) per etichettare “Android handset", “iOS handset", “Electron desktop", ecc.
* Poiché il sender deve recuperare l’inventario chiavi del destinatario prima di cifrare, l’attaccante può anche osservare quando vengono associati nuovi device; un aumento improvviso del numero di device o un nuovo cluster RTT è un forte indicatore.

## Sampling cadence, queueing, e stacked receipts

* **WhatsApp burst tolerance:** Misurazioni pubblicate hanno riportato che WhatsApp accettava burst di silent-reaction fino a un probe ogni `50 ms` senza un’ovvia queueing lato server. È utile per burst di calibrazione brevi, conteggio rapido dei device o per aumentare rapidamente un drain attack.
* **Signal long-run queueing:** Signal tollerava burst brevi ma iniziava a mettere in coda traffico sostenuto di più probe al secondo. Per monitoraggio di lunga durata, mantieni la cadenza intorno a `1 Hz` (o inferiore) così ogni receipt riflette ancora lo stato corrente del device invece del drenaggio della backlog.
* **Reconnect artefacts:** Quando un device torna online, alcuni client raggruppano o svuotano rapidamente più receipt ritardati. Tratta questi burst di receipt come marker di transizione di stato e non come campioni RTT indipendenti, altrimenti il tuo clustering / classificatore `active` vs `idle` overfit-tera il rumore di reconnessione.

## Inferenza del comportamento dai trace RTT

1. Campiona a ≥1 Hz per catturare gli effetti di scheduling dell’OS. Con WhatsApp su iOS, RTT < 1 s correlano fortemente con screen-on/foreground, RTT > 1 s con screen-off/background throttling.
2. Costruisci classificatori semplici (thresholding o k-means a due cluster) che etichettano ogni RTT come "active" o "idle". Aggrega le etichette in streak per ricavare bedtime, spostamenti, orari di lavoro o quando il companion desktop è attivo.
3. Correlate probe simultanei verso ogni device per vedere quando gli utenti passano da mobile a desktop, quando i companion vanno offline e se l’app è rate limited da push o socket persistente.
4. Nelle reti reali, evita una singola soglia hardcoded `1 s`. Bootstrap ogni device con una breve finestra di warm-up e mantieni una baseline rolling (per esempio, `threshold = 0.9 * median RTT`) così il drift Wi-Fi/cellular non fa collassare il classificatore.

## Inferenza della location dai delivery RTT

La stessa primitive temporale può essere riutilizzata per inferire dove si trova il destinatario, non solo se è attivo. Il lavoro `Hope of Delivery` ha mostrato che addestrare su distribuzioni RTT per location note del ricevente permette a un attaccante di classificare in seguito la location della vittima usando solo le delivery confirmations:

* Costruisci una baseline per lo stesso target mentre si trova in diversi posti noti (casa, ufficio, campus, paese A vs paese B, ecc.).
* Per ogni location, raccogli molti RTT di messaggi normali ed estrai feature semplici come mediana, varianza o bucket di percentile.
* Durante l’attacco reale, confronta la nuova serie di probe con i cluster addestrati. Il paper riporta che anche location nella stessa città possono spesso essere separate, con accuratezza `>80%` in un setting a 3 location.
* Funziona meglio quando l’attaccante controlla l’ambiente del sender e fa probing in condizioni di rete simili, perché il path misurato include la rete di accesso del destinatario, la wake-up latency e l’infrastruttura del messenger.

A differenza degli attacchi silenziosi di reaction/edit/delete sopra, l’inferenza della location non richiede message ID invalidi o pacchetti stealth che cambiano stato. Bastano messaggi normali con conferme di delivery standard, quindi il tradeoff è meno stealth ma maggiore applicabilità tra i messenger.

## Stealthy resource exhaustion

Poiché ogni silent probe deve essere decriptato e riconosciuto, inviare continuamente toggle di reaction, edit invalidi o pacchetti delete-for-everyone crea un DoS a livello applicativo:

* Forza radio/modem a trasmettere/ricevere ogni secondo → scarica la batteria in modo evidente, soprattutto su handset inattivi.
* Genera traffico upstream/downstream non a consumo, che usa i piani dati mobili mentre si confonde nel rumore TLS/WebSocket.
* Occupa i thread crypto e introduce jitter nelle funzionalità sensibili alla latenza (VoIP, video call) anche se l’utente non vede mai notifiche.
* Su WhatsApp, le reaction non valide accettano molti più dati di quanto suggerisca un emoji normale: misurazioni pubblicate hanno trovato accettazione lato server fino a circa `1 MB` per reaction.
* Le reaction oversize smettono di produrre delivery receipt affidabili una volta che il body cresce oltre circa `30 bytes`, ma vengono comunque inoltrate e processate prima dello scarto. Mantieni i body delle reaction piccoli quando ti servono ACK; ingrandiscili solo quando l’obiettivo è puro drain o trasporto covert one-way.
* Misurazioni pubbliche hanno raggiunto circa `3.7 MB/s` (`~13.3 GB/h`) di traffico della vittima in questa modalità.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
