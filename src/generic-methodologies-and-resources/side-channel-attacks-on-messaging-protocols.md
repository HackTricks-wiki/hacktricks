# Attacchi Side-Channel sui Delivery Receipt in Messaggeri E2EE

{{#include ../banners/hacktricks-training.md}}

I delivery receipt sono obbligatori nei moderni messaggeri end-to-end encrypted (E2EE) perché i client devono sapere quando un ciphertext è stato decifrato, così possono scartare lo stato di ratcheting e le chiavi effimere. Il server inoltra blob opachi, quindi gli acknowledgement del dispositivo (doppia spunta) vengono emessi dal destinatario dopo la decifrazione riuscita. Misurare il round-trip time (RTT) tra un'azione attivata dall'attaccante e il corrispondente delivery receipt espone un canale temporale ad alta risoluzione che leak stato del dispositivo, presenza online e può essere abusato per covert DoS. Le distribuzioni multi-device "client-fanout" amplificano il leak perché ogni device registrato decifra il probe e restituisce il proprio receipt.

## Delivery receipt sources vs. segnali visibili all'utente

Scegli tipi di messaggio che emettono sempre un delivery receipt ma non mostrano artefatti UI sulla vittima. La tabella seguente riassume il comportamento confermato empiricamente:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Sempre rumoroso -> utile solo per inizializzare lo stato. |
| | Reaction | ● | ◐ (solo se la reaction riguarda un messaggio della vittima) | Le self-reaction e le rimozioni restano silenziose. |
| | Edit | ● | silent push dipendente dalla piattaforma | Finestra di edit ≈20 min; ancora ack'd dopo la scadenza. |
| | Delete for everyone | ● | ○ | La UI consente ~60 h, ma i pacchetti successivi sono ancora ack'd. |
| **Signal** | Text message | ● | ● | Stesse limitazioni di WhatsApp. |
| | Reaction | ● | ◐ | Le self-reaction sono invisibili per la vittima. |
| | Edit/Delete | ● | ○ | Il server impone una finestra di ~48 h, consente fino a 10 edit, ma i pacchetti tardivi sono ancora ack'd. |
| **Threema** | Text message | ● | ● | I receipt multi-device sono aggregati, quindi per ogni probe diventa visibile solo un RTT. |

Legenda: ● = sempre, ◐ = condizionale, ○ = mai. Il comportamento UI dipendente dalla piattaforma è indicato inline. Disabilita i read receipts se necessario, ma i delivery receipt non possono essere disattivati in WhatsApp o Signal.

## Obiettivi e modelli dell'attaccante

* **G1 - Device fingerprinting:** Conta quanti receipt arrivano per ogni probe, raggruppa gli RTT per inferire OS/client (Android vs iOS vs desktop) e osserva le transizioni online/offline.
* **G2 - Behavioral monitoring:** Tratta la serie RTT ad alta frequenza (≈1 Hz è stabile) come una time-series e inferisci screen on/off, app foreground/background, commuting vs working hours, ecc.
* **G3 - Resource exhaustion:** Tieni radios/CPU di ogni device vittima svegli inviando probe silenziosi senza fine, consumando batteria/dati e degradando la qualità VoIP/RTC.

Due attori di minaccia sono sufficienti per descrivere la superficie di abuso:

1. **Creepy companion:** condivide già una chat con la vittima e abusa di self-reaction, rimozioni di reaction o edit/delete ripetuti legati a ID di messaggi esistenti.
2. **Spooky stranger:** registra un account burner e invia reaction che riferiscono message ID mai esistiti nella conversazione locale; WhatsApp e Signal li decifrano e li acknowledge ancora anche se la UI scarta il cambio di stato, quindi non serve una conversazione precedente.

## Tooling per accesso raw al protocollo

Affidati a client che espongono il protocollo E2EE sottostante, così puoi creare pacchetti fuori dai vincoli della UI, specificare `message_id` arbitrari e registrare timestamp precisi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocollo WhatsApp Web) o [Cobalt](https://github.com/Auties00/Cobalt) (orientato al mobile) permettono di emettere frame raw `ReactionMessage`, `ProtocolMessage` (edit/delete) e `Receipt` mantenendo sincronizzato lo stato double-ratchet.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinato con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) espone ogni tipo di messaggio via CLI/API. La sintassi attuale di `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; tieni `receive` o `daemon` in esecuzione così i delivery receipt vengono davvero raccolti. Esempio di toggle self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Il sorgente del client Android documenta come i delivery receipt vengono consolidati prima di uscire dal device, spiegando perché il side channel lì ha banda trascurabile.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) include backend WhatsApp/Signal, usa di default silent delete probe e etichetta `active` vs `standby` con una soglia a rolling median (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) è un CLI più leggero, prima WhatsApp, con `--delay`, `--concurrent`, exporter CSV/Prometheus e output adatto a Grafana. Considerali entrambi helper di reconnaissance più che riferimenti di protocollo; il punto chiave è quanta poca code serve una volta che esiste accesso raw al client.

Quando non hai tooling custom, puoi comunque attivare azioni silenziose da WhatsApp Web o Signal Desktop e sniffare il canale websocket/WebRTC cifrato, ma le API raw rimuovono i delay della UI e permettono operazioni invalid.

## Creepy companion: ciclo di sampling silenzioso

1. Scegli qualsiasi messaggio storico che hai scritto nella chat, così la vittima non vede mai cambiare i balloon di "reaction".
2. Alterna tra un emoji visibile e un payload di reaction vuoto (codificato come `""` in WhatsApp protobufs o `--remove` in signal-cli). Ogni trasmissione produce un device ack nonostante nessun delta UI per la vittima.
3. Timbra il send time e ogni arrivo di delivery receipt. Un loop a 1 Hz come il seguente produce tracce RTT per-device all'infinito:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Poiché WhatsApp/Signal accettano aggiornamenti di reaction illimitati, l'attaccante non deve mai pubblicare nuovo contenuto in chat né preoccuparsi delle finestre di edit.

## Spooky stranger: probing di numeri di telefono arbitrari

1. Registra un account WhatsApp/Signal nuovo e recupera le public identity keys per il numero target (fatto automaticamente durante la session setup).
2. Crea un pacchetto reaction/edit/delete che riferisce un `message_id` casuale mai visto da entrambe le parti (WhatsApp accetta GUID arbitrari `key.id`; Signal usa timestamp in millisecondi).
3. Invia il pacchetto anche se non esiste alcun thread. I device della vittima lo decifrano, falliscono il match con il messaggio base, scartano il cambio di stato, ma ack'ano comunque il ciphertext in arrivo, inviando delivery receipt all'attaccante.
4. Ripeti continuamente per costruire serie RTT senza mai apparire nella chat list della vittima.

Se prima devi scoprire quali numeri sono registrati o vuoi pre-seed device inventories su larga scala, concatenalo con [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) invece di indovinare a mano range E.164 casuali.

Le build recenti di WhatsApp espongono anche `Settings -> Privacy -> Advanced -> Block unknown account messages`. Trattalo come limiter di throughput, non come fix: danneggia soprattutto flooding sostenuto solo da sconosciuti ed è irrilevante una volta che sei già un contatto noto.

## Riciclo di edit e delete come trigger covert

* **Repeated deletes:** Dopo che un messaggio è stato deleted-for-everyone una volta, ulteriori pacchetti delete che riferiscono lo stesso `message_id` non hanno effetto UI ma ogni device li decifra e li acknowledge ancora.
* **Out-of-window operations:** WhatsApp impone nella UI finestre di ~60 h per delete / ~20 min per edit; Signal impone ~48 h. I messaggi di protocollo creati fuori da queste finestre vengono ignorati silenziosamente sul device vittima ma i receipt vengono trasmessi, quindi gli attaccanti possono probing per tempi indefiniti anche molto dopo la fine della conversazione.
* **Invalid payloads:** Corpi edit malformati o delete che riferiscono messaggi già rimossi provocano lo stesso comportamento - decifrazione più receipt, zero artefatti visibili all'utente.

## Amplificazione multi-device e fingerprinting

* Ogni device associato (telefono, desktop app, browser companion) decifra il probe in modo indipendente e restituisce il proprio ack. Contare i receipt per probe rivela il numero esatto di device.
* Se un device è offline, il suo receipt viene accodato ed emesso alla riconnessione. I gap quindi leak cicli online/offline e perfino schedule di commuting (per esempio, i receipt desktop si fermano durante il viaggio).
* Le distribuzioni RTT differiscono per piattaforma a causa del power management dell'OS e dei wakeup push. Raggruppa gli RTT (per esempio, k-means su feature di mediana/varianza) per etichettare "Android handset", "iOS handset", "Electron desktop", ecc.
* Poiché il mittente deve recuperare l'inventory chiavi del destinatario prima di cifrare, l'attaccante può anche osservare quando vengono associati nuovi device; un aumento improvviso del numero di device o un nuovo cluster RTT è un forte indicatore.

## Inference comportamentale dalle tracce RTT

1. Campiona a ≥1 Hz per catturare gli effetti di scheduling dell'OS. Con WhatsApp su iOS, RTT <1 s correlano fortemente con screen-on/foreground, >1 s con throttling screen-off/background.
2. Costruisci classificatori semplici (thresholding o k-means a due cluster) che etichettano ogni RTT come "active" o "idle". Aggrega le etichette in streaks per derivare orari di sonno, commuting, lavoro o quando il companion desktop è attivo.
3. Correlate probe simultanee verso ogni device per vedere quando gli utenti passano da mobile a desktop, quando i companion vanno offline e se l'app è rate limited da push o da socket persistente.
4. In reti reali, evita una singola soglia hardcoded `1 s`. Fai bootstrap di ogni device con una breve finestra di warm-up e mantieni una baseline rolling (per esempio, `threshold = 0.9 * median RTT`) così il drift Wi-Fi/cellular non manda in crisi il classificatore.

## Inferenza di location dal delivery RTT

Lo stesso primitive temporale può essere riutilizzato per inferire dove si trova il destinatario, non solo se è attivo. Il lavoro `Hope of Delivery` ha mostrato che addestrare su distribuzioni RTT per location note del receiver permette a un attaccante di classificare poi la location della vittima basandosi solo sui delivery confirmation:

* Costruisci una baseline per lo stesso target mentre si trova in più luoghi noti (casa, ufficio, campus, paese A vs paese B, ecc.).
* Per ogni location, raccogli molti RTT di messaggi normali ed estrai feature semplici come mediana, varianza o bucket di percentile.
* Durante l'attacco reale, confronta la nuova serie di probe con i cluster addestrati. Il paper riporta che anche location nella stessa città spesso si possono separare, con accuratezza `>80%` in un setting a 3 location.
* Funziona meglio quando l'attaccante controlla l'ambiente del sender e fa probe in condizioni di rete simili, perché il path misurato include la rete di accesso del destinatario, la wake-up latency e l'infrastruttura del messenger.

A differenza degli attacchi silenziosi di reaction/edit/delete sopra, l'inferenza di location non richiede message ID invalid o pacchetti stealth che cambiano stato. Bastano messaggi normali con normali delivery confirmation, quindi il tradeoff è meno stealth ma maggiore applicabilità tra messenger.

## Resource exhaustion stealthy

Poiché ogni silent probe deve essere decifrato e acknowledged, inviare continuamente toggle di reaction, edit invalidi o pacchetti delete-for-everyone crea un DoS a livello application-layer:

* Forza radio/modem a trasmettere/ricevere ogni secondo -> battery drain evidente, specialmente su handset idle.
* Genera traffico upstream/downstream non misurato che consuma piani dati mobili fondendosi nel rumore TLS/WebSocket.
* Occupa thread crypto e introduce jitter in funzioni latency-sensitive (VoIP, video call) anche se l'utente non vede notifiche.
* Su WhatsApp, reaction invalide accettano molti più dati di quanto suggerisca un emoji normale: misurazioni pubblicate hanno trovato acceptance lato server fino a circa `1 MB` per reaction.
* Le reaction oversized smettono di produrre delivery receipt affidabili una volta che il body supera circa `30 bytes`, ma vengono comunque inoltrate e processate prima dello scarto. Tieni piccoli i body delle reaction quando ti servono ACK; ingrandiscili solo quando l'obiettivo è puro drain o covert one-way transport.
* Le misurazioni pubbliche hanno raggiunto circa `3.7 MB/s` (`~13.3 GB/h`) di traffico vittima in questa modalità.

## Riferimenti

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
