# Attacchi Side-Channel sui Delivery Receipt in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

I delivery receipt sono obbligatori nei moderni messaggeri end-to-end encrypted (E2EE) perché i client devono sapere quando un ciphertext è stato decriptato per poter scartare lo stato del ratchet e le chiavi effimere. Il server inoltra blob opachi, quindi gli acknowledgement dei device (double checkmarks) vengono emessi dal destinatario dopo la decriptazione riuscita. Misurare il round-trip time (RTT) tra un'azione triggerata dall'attaccante e il corrispondente delivery receipt espone un canale di timing ad alta risoluzione che leaks lo stato del dispositivo, la presenza online, e può essere abusato per covert DoS. Le distribuzioni multi-device a "client-fanout" amplificano la leakage perché ogni device registrato decripta la probe e ritorna il proprio receipt.

## Delivery receipt sources vs. user-visible signals

Scegli tipi di messaggio che emettono sempre un delivery receipt ma che non producono artefatti UI visibili alla vittima. La tabella sotto riassume il comportamento empiricamente confermato:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Always noisy → only useful to bootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI allows ~60 h, but later packets still ack’d. |
| **Signal** | Text message | ● | ● | Same limitations as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Server enforces ~48 h window, allows up to 10 edits, but late packets still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts are aggregated, so only one RTT per probe becomes visible. |

Legenda: ● = sempre, ◐ = condizionale, ○ = mai. Il comportamento UI dipendente dalla piattaforma è annotato inline. Disabilita read receipts se necessario, ma i delivery receipts non possono essere disattivati in WhatsApp o Signal.

## Attacker goals and models

* **G1 – Device fingerprinting:** Conta quanti receipts arrivano per probe, clusterizza gli RTT per inferire OS/client (Android vs iOS vs desktop), e monitora transizioni online/offline.
* **G2 – Behavioural monitoring:** Tratta la serie di RTT ad alta frequenza (≈1 Hz è stabile) come una time-series e inferisci screen on/off, app foreground/background, ore di pendolarismo vs di lavoro, ecc.
* **G3 – Resource exhaustion:** Mantieni radio/CPU di ogni device vittima svegli inviando probe silent senza fine, consumando batteria/dati e degradando la qualità di VoIP/RTC.

Due threat actor sono sufficienti per descrivere la superficie di abuso:

1. **Creepy companion:** già condivide una chat con la vittima e abusa di self-reactions, reaction removals, o ripetute edit/delete legate a message ID esistenti.
2. **Spooky stranger:** registra un account burner e invia reaction che fanno riferimento a message ID che non sono mai esistiti nella conversazione locale; WhatsApp e Signal comunque li decriptano e li acknowledgeano anche se la UI scarta il cambio di stato, quindi non è necessaria una conversazione pregressa.

## Tooling for raw protocol access

Affidati a client che espongono il protocollo E2EE sottostante così puoi craftare pacchetti al di fuori dei vincoli UI, specificare arbitrari `message_id`s, e loggare timestamp precisi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) o [Cobalt](https://github.com/Auties00/Cobalt) (orientato mobile) ti permettono di emettere raw `ReactionMessage`, `ProtocolMessage` (edit/delete), e `Receipt` frames mantenendo lo stato del double-ratchet sincronizzato.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinato con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) espone ogni tipo di messaggio via CLI/API. Esempio toggle self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Il sorgente del client Android documenta come i delivery receipts siano consolidati prima di lasciare il device, spiegando perché lo side channel ha banda trascurabile lì.

Quando custom tooling non è disponibile, puoi comunque triggerare azioni silent da WhatsApp Web o Signal Desktop e sniffare il websocket/WebRTC cifrato, ma le raw API rimuovono ritardi UI e permettono operazioni invalide.

## Creepy companion: silent sampling loop

1. Scegli un qualsiasi messaggio storico che hai inviato nella chat così la vittima non vede cambiare i balloon delle "reaction".
2. Alterna tra un'emoji visibile e un payload di reaction vuoto (codificato come `""` nei protobuf WhatsApp o `--remove` in signal-cli). Ogni trasmissione genera un ack di dispositivo nonostante nessuna delta UI per la vittima.
3. Timestampa il tempo di invio e ogni arrivo di delivery receipt. Un loop a 1 Hz come il seguente fornisce tracce RTT per-device indefinitamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Poiché WhatsApp/Signal accettano aggiornamenti illimitati delle reaction, l'attaccante non ha mai bisogno di postare nuovo contenuto in chat o preoccuparsi delle finestre di edit.

## Spooky stranger: probing arbitrary phone numbers

1. Registra un nuovo account WhatsApp/Signal e recupera le identity keys pubbliche per il numero target (fatto automaticamente durante il setup della sessione).
2. Crea un pacchetto reaction/edit/delete che faccia riferimento a un `message_id` random mai visto da nessuna delle due parti (WhatsApp accetta GUID arbitrari in `key.id`; Signal usa timestamp in millisecondi).
3. Invia il pacchetto anche se non esiste alcun thread. I device della vittima lo decriptano, non riescono a matchare il messaggio di base, scartano il cambio di stato, ma acknowledgeano comunque il ciphertext in arrivo, inviando device receipts all'attaccante.
4. Ripeti continuamente per costruire serie di RTT senza mai apparire nella lista chat della vittima.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Dopo che un messaggio è stato delete-for-everyone una volta, ulteriori pacchetti delete che fanno riferimento allo stesso `message_id` non hanno effetto UI ma ogni device continua a decriptarli e acknowledgerli.
* **Out-of-window operations:** WhatsApp impone ~60 h per delete / ~20 min per edit nella UI; Signal impone ~48 h. Messaggi di protocollo craftati fuori da queste finestre vengono silenziosamente ignorati sul device della vittima ma i receipts vengono trasmessi, quindi gli attaccanti possono probeare indefinitamente molto dopo la fine della conversazione.
* **Invalid payloads:** Corpi edit malformati o delete che fanno riferimento a messaggi già purgeati elicitano lo stesso comportamento — decryption più receipt, zero artefatti visibili all'utente.

## Multi-device amplification & fingerprinting

* Ogni device associato (telefono, app desktop, companion browser) decripta la probe indipendentemente e ritorna il proprio ack. Contare i receipts per probe rivela il conteggio esatto dei dispositivi.
* Se un device è offline, il suo receipt viene messo in coda ed emesso al riconnettersi. I gap quindi leak online/offline cycles e persino schedule di commuting (es. i receipt desktop cessano durante i viaggi).
* Le distribuzioni di RTT differiscono per piattaforma a causa di power management degli OS e wakeup push. Clusterizza gli RTT (es. k-means su median/variance features) per etichettare “Android handset”, “iOS handset”, “Electron desktop”, ecc.
* Poiché il sender deve recuperare l'inventory delle chiavi del destinatario prima di cifrare, l'attaccante può anche osservare quando nuovi device vengono appaiati; un improvviso aumento del conteggio device o un nuovo cluster RTT è un forte indicatore.

## Behaviour inference from RTT traces

1. Campiona a ≥1 Hz per catturare effetti di scheduling dell'OS. Con WhatsApp su iOS, RTT <1 s si correlano fortemente con screen-on/foreground, >1 s con throttling da screen-off/background.
2. Costruisci classifier semplici (thresholding o k-means a due cluster) che etichettino ogni RTT come "active" o "idle". Aggrega le etichette in streaks per ricavare orari di sonno, pendolarismo, ore di lavoro, o quando il companion desktop è attivo.
3. Correlare probe simultanei verso ogni device per vedere quando gli utenti passano da mobile a desktop, quando i companion vanno offline, e se l'app è rate-limited da push vs socket persistente.

## Stealthy resource exhaustion

Poiché ogni probe silent deve essere decriptata e acknowledgeata, l'invio continuo di toggle di reaction, edit invalidi, o pacchetti delete-for-everyone crea un DoS a livello applicazione:

* Costringe la radio/modem a trasmettere/ricevere ogni secondo → drain di batteria evidente, soprattutto su handset inattivi.
* Genera traffico upstream/downstream che consuma piani dati mobili pur mascherandosi nel rumore TLS/WebSocket.
* Occupia thread crypto e introduce jitter in funzionalità sensibili alla latenza (VoIP, videochiamate) anche se l'utente non vede mai notifiche.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
