# Attacchi side-channel sui delivery receipt in messenger E2EE

{{#include ../banners/hacktricks-training.md}}

I delivery receipt sono obbligatori nei moderni messenger end-to-end encrypted (E2EE) perché i client devono sapere quando un ciphertext è stato decriptato, così possono scartare lo stato di ratcheting e le chiavi effimere. Il server inoltra blob opachi, quindi gli acknowledgement del dispositivo (doppie spunte) vengono emessi dal destinatario dopo la decrittazione riuscita. Misurare il round-trip time (RTT) tra un'azione indotta dall'attaccante e il corrispondente delivery receipt espone un canale temporale ad alta risoluzione che leak lo stato del dispositivo, la presenza online, e può essere abusato per DoS covert. Le implementazioni multi-device "client-fanout" amplificano la leak perché ogni dispositivo registrato decripta la probe e restituisce il proprio receipt.

## Delivery receipt sources vs. segnali visibili all'utente

Scegli tipi di messaggio che emettono sempre un delivery receipt ma non mostrano artefatti UI sulla vittima. La tabella seguente riassume il comportamento confermato empiricamente:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Sempre rumoroso → utile solo per avviare lo stato. |
| | Reaction | ● | ◐ (solo se si reagisce a un messaggio della vittima) | Le self-reactions e le rimozioni restano silenziose. |
| | Edit | ● | Silent push dipendente dalla piattaforma | Finestra di edit ≈20 min; comunque ack’d dopo la scadenza. |
| | Delete for everyone | ● | ○ | La UI consente ~60 h, ma i pacchetti successivi vengono comunque ack’d. |
| **Signal** | Text message | ● | ● | Stesse limitazioni di WhatsApp. |
| | Reaction | ● | ◐ | Le self-reactions sono invisibili alla vittima. |
| | Edit/Delete | ● | ○ | Il server impone una finestra di ~48 h, consente fino a 10 edit, ma i pacchetti tardivi vengono comunque ack’d. |
| **Threema** | Text message | ● | ● | I delivery receipt multi-device sono aggregati, quindi per ogni probe è visibile solo un RTT. |

Legenda: ● = sempre, ◐ = condizionale, ○ = mai. Il comportamento UI dipendente dalla piattaforma è annotato inline. Disabilita i read receipts se necessario, ma i delivery receipt non possono essere disattivati in WhatsApp o Signal.

## Obiettivi e modelli dell'attaccante

* **G1 – Device fingerprinting:** Contare quanti receipt arrivano per probe, raggruppare gli RTT per inferire OS/client (Android vs iOS vs desktop), e osservare le transizioni online/offline.
* **G2 – Behavioural monitoring:** Trattare la serie RTT ad alta frequenza (≈1 Hz è stabile) come una serie temporale e inferire screen on/off, app foreground/background, commuting vs working hours, ecc.
* **G3 – Resource exhaustion:** Tenere svegli radio/CPU di ogni device della vittima inviando probe silenziose infinite, scaricando batteria/dati e degradando la qualità VoIP/RTC.

Due threat actor sono sufficienti per descrivere la superficie di abuso:

1. **Creepy companion:** condivide già una chat con la vittima e abusa di self-reactions, rimozioni di reaction o edit/delete ripetuti legati a message ID già esistenti.
2. **Spooky stranger:** registra un account burner e invia reaction che riferiscono message ID mai esistiti nella conversazione locale; WhatsApp e Signal li decriptano e li acknowledge comunque anche se la UI scarta il cambio di stato, quindi non serve una conversazione precedente.

## Tooling per accesso raw al protocollo

Affidati a client che espongono il protocollo E2EE sottostante così puoi costruire pacchetti fuori dai vincoli della UI, specificare `message_id` arbitrari e registrare timestamp precisi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocollo WhatsApp Web) o [Cobalt](https://github.com/Auties00/Cobalt) (orientato al mobile) permettono di emettere frame raw `ReactionMessage`, `ProtocolMessage` (edit/delete) e `Receipt` mantenendo sincronizzato lo stato double-ratchet.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinato con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) espone ogni tipo di messaggio via CLI/API. Esempio di toggle di self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Il source del client Android documenta come i delivery receipt vengono consolidati prima di lasciare il device, spiegando perché lì il side channel ha banda trascurabile.
* **Turnkey PoCs:** progetti pubblici come `device-activity-tracker` e `careless-whisper-python` automatizzano già probe di silent delete/reaction e classificazione RTT. Considerali helper di reconnaissance pronti all'uso invece che riferimenti di protocollo; la parte interessante è che confermano che l'attacco è operativamente semplice una volta che esiste accesso raw al client.

Quando non è disponibile tooling custom, puoi comunque attivare azioni silenziose da WhatsApp Web o Signal Desktop e sniffare il canale websocket/WebRTC cifrato, ma le API raw rimuovono i ritardi della UI e consentono operazioni non valide.

## Creepy companion: silent sampling loop

1. Scegli un qualsiasi messaggio storico che hai scritto nella chat così la vittima non vede mai cambiare i balloon di "reaction".
2. Alterna tra un emoji visibile e un payload di reaction vuoto (codificato come `""` nei protobuf di WhatsApp o `--remove` in signal-cli). Ogni trasmissione genera un device ack nonostante nessuna delta UI per la vittima.
3. Registra il send time e ogni arrivo del delivery receipt. Un loop a 1 Hz come il seguente fornisce trace RTT per dispositivo in modo indefinito:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Poiché WhatsApp/Signal accettano aggiornamenti di reaction illimitati, l'attaccante non deve mai pubblicare nuovo contenuto in chat né preoccuparsi delle edit window.

## Spooky stranger: probing di numeri di telefono arbitrari

1. Registra un account WhatsApp/Signal nuovo e recupera le public identity keys per il numero target (fatto automaticamente durante il setup della sessione).
2. Costruisci un pacchetto reaction/edit/delete che riferisce un `message_id` casuale mai visto da nessuna delle due parti (WhatsApp accetta GUID arbitrari `key.id`; Signal usa timestamp in millisecondi).
3. Invia il pacchetto anche se non esiste alcun thread. I device della vittima lo decriptano, non riescono a matchare il messaggio base, scartano il cambio di stato, ma comunque acknowledge il ciphertext in ingresso, rimandando i device receipt all'attaccante.
4. Ripeti continuamente per costruire serie RTT senza mai comparire nella chat list della vittima.

## Riutilizzare edit e delete come trigger covert

* **Delete ripetuti:** Dopo che un messaggio è stato deleted-for-everyone una volta, ulteriori pacchetti delete che riferiscono lo stesso `message_id` non hanno effetto UI ma ogni device continua a decriptarli e ad ackarli.
* **Operazioni fuori finestra:** WhatsApp impone finestre di delete di ~60 h / edit di ~20 min nella UI; Signal impone ~48 h. I messaggi di protocollo costruiti fuori da queste finestre vengono ignorati silenziosamente sul device della vittima, ma i receipt vengono comunque trasmessi, quindi gli attaccanti possono fare probe molto tempo dopo la fine della conversazione.
* **Payload non validi:** Corpi di edit malformati o delete che riferiscono messaggi già purgati producono lo stesso comportamento—decryption più receipt, zero artefatti visibili all'utente.

## Amplificazione multi-device & fingerprinting

* Ogni device associato (phone, desktop app, browser companion) decripta la probe in modo indipendente e restituisce il proprio ack. Contare i receipt per probe rivela il numero esatto di device.
* Se un device è offline, il suo receipt viene accodato ed emesso alla riconnessione. I gap quindi leak cicli online/offline e persino orari di commuting (ad es. i receipt desktop si fermano durante il viaggio).
* Le distribuzioni degli RTT differiscono per piattaforma a causa del power management dell'OS e dei wakeup push. Raggruppa gli RTT (ad es. k-means su feature di mediana/varianza) per etichettare "Android handset", "iOS handset", "Electron desktop", ecc.
* Poiché il sender deve recuperare l'inventario delle chiavi del destinatario prima di cifrare, l'attaccante può anche osservare quando vengono associati nuovi device; un aumento improvviso del conteggio device o un nuovo cluster RTT è un forte indicatore.

## Inferenza comportamentale dalle trace RTT

1. Campiona a ≥1 Hz per catturare gli effetti di scheduling dell'OS. Con WhatsApp su iOS, RTT <1 s correlano fortemente con screen-on/foreground, RTT >1 s con throttling screen-off/background.
2. Costruisci classificatori semplici (thresholding o k-means a due cluster) che etichettano ogni RTT come "active" o "idle". Aggrega le etichette in streaks per ricavare orari di sonno, commuting, lavoro, o quando il companion desktop è attivo.
3. Correlate probe simultanee verso ogni device per vedere quando gli utenti passano da mobile a desktop, quando i companion vanno offline, e se l'app è rate limited da push o da socket persistente.

## Inferenza della location dal delivery RTT

Lo stesso primitive temporale può essere riusato per inferire dove si trova il destinatario, non solo se è attivo. Il lavoro `Hope of Delivery` ha mostrato che addestrare su distribuzioni RTT per location note del receiver consente poi all'attaccante di classificare la location della vittima usando solo le delivery confirmation:

* Costruisci una baseline per lo stesso target mentre si trova in più posti noti (casa, ufficio, campus, country A vs country B, ecc.).
* Per ogni location, raccogli molti RTT di messaggi normali ed estrai feature semplici come mediana, varianza o bucket di percentile.
* Durante l'attacco reale, confronta la nuova serie di probe contro i cluster addestrati. Il paper riporta che anche location nella stessa città possono spesso essere separate, con accuratezza `>80%` in uno scenario a 3 location.
* Funziona meglio quando l'attaccante controlla l'ambiente di invio e fa probe in condizioni di rete simili, perché il path misurato include la access network del destinatario, la wake-up latency e l'infrastruttura del messenger.

A differenza degli attacchi silent reaction/edit/delete sopra, l'inferenza della location non richiede message ID non validi o pacchetti stealth che cambiano stato. Bastano messaggi normali con conferme di delivery normali, quindi il tradeoff è meno stealth ma maggiore applicabilità tra i messenger.

## Stealthy resource exhaustion

Poiché ogni probe silenziosa deve essere decriptata e ackata, inviare continuamente toggle di reaction, edit non validi o pacchetti delete-for-everyone crea un DoS a livello applicativo:

* Forza la radio/modem a trasmettere/ricevere ogni secondo → drenaggio batteria evidente, soprattutto su handset idle.
* Genera traffico upstream/downstream non metered che consuma piani dati mobili mescolandosi al rumore TLS/WebSocket.
* Occupa i thread crypto e introduce jitter in funzionalità sensibili alla latenza (VoIP, video call) anche se l'utente non vede mai notifiche.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
