# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts sind in modernen end-to-end verschlüsselten (E2EE) Messengern obligatorisch, weil Clients wissen müssen, wann ein ciphertext entschlüsselt wurde, damit sie den ratcheting state und ephemeral keys verwerfen können. Der Server leitet opaque blobs weiter, sodass Gerätebestätigungen (double checkmarks) vom Empfänger nach erfolgreicher Entschlüsselung ausgegeben werden. Das Messen der round-trip time (RTT) zwischen einer vom Angreifer ausgelösten Aktion und der entsprechenden delivery receipt offenbart einen hochauflösenden Timing-Kanal, der device state und online presence leak und für covert DoS missbraucht werden kann. Multi-device "client-fanout"-Deployments verstärken das leak, weil jedes registrierte Gerät die Probe entschlüsselt und seine eigene receipt zurücksendet.

## Delivery receipt sources vs. user-visible signals

Wähle Nachrichtentypen, die immer eine delivery receipt senden, aber beim Opfer keine UI-Artefakte anzeigen. Die folgende Tabelle fasst das empirisch bestätigte Verhalten zusammen:

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

Legend: ● = always, ◐ = conditional, ○ = never. Plattformabhängiges UI-Verhalten ist inline vermerkt. Disable read receipts falls nötig, aber delivery receipts lassen sich in WhatsApp oder Signal nicht ausschalten.

## Attacker goals and models

* **G1 – Device fingerprinting:** Zähle, wie viele receipts pro Probe ankommen, clustere RTTs, um OS/client (Android vs iOS vs desktop) abzuleiten, und beobachte online/offline-Übergänge.
* **G2 – Behavioural monitoring:** Behandle die hochfrequente RTT-Serie (≈1 Hz ist stabil) als Zeitreihe und leite screen on/off, app foreground/background, Pendel- vs. Arbeitszeiten etc. ab.
* **G3 – Resource exhaustion:** Halte Radios/CPUs aller Opfergeräte wach, indem du nie endende stille Probes sendest, wodurch Akku/Datennutzung sinkt und VoIP/RTC-Qualität leidet.

Zwei Bedrohungsakteure genügen, um die Angriffsfläche zu beschreiben:

1. **Creepy companion:** Teilt bereits einen Chat mit dem Opfer und missbraucht self-reactions, reaction removals oder wiederholte edits/deletes, die an bestehende message IDs gebunden sind.
2. **Spooky stranger:** Registriert einen Burner-Account und sendet Reactions, die sich auf message IDs beziehen, die in der lokalen Konversation nie existierten; WhatsApp und Signal entschlüsseln und bestätigen diese trotzdem, obwohl die UI die Zustandsänderung verwirft — es ist also keine vorherige Unterhaltung erforderlich.

## Tooling for raw protocol access

Verwende Clients, die das zugrundeliegende E2EE-Protokoll offenlegen, damit du Pakete außerhalb der UI-Einschränkungen konstruieren, beliebige `message_id`s angeben und präzise Zeitstempel protokollieren kannst:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) oder [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) erlauben das Senden von rohen `ReactionMessage`, `ProtocolMessage` (edit/delete) und `Receipt` Frames, während der double-ratchet state synchron gehalten wird.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) kombiniert mit [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) macht jeden Nachrichtentyp über CLI/API zugänglich. Beispiel für Self-Reaction-Toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Der Quellcode des Android-Clients dokumentiert, wie delivery receipts konsolidiert werden, bevor sie das Gerät verlassen, was erklärt, warum der Side Channel dort vernachlässigbare Bandbreite hat.

Wenn kein Custom-Tooling verfügbar ist, kannst du stille Aktionen über WhatsApp Web oder Signal Desktop auslösen und den verschlüsselten websocket/WebRTC-Kanal mitschneiden; rohe APIs eliminieren jedoch UI-Verzögerungen und erlauben ungültige Operationen.

## Creepy companion: silent sampling loop

1. Wähle eine beliebige historische Nachricht, die du im Chat gesendet hast, sodass das Opfer niemals sichtbare "reaction"-Bubbles sieht.
2. Wechsle ab zwischen einem sichtbaren Emoji und einer leeren reaction-Payload (kodiert als `""` in WhatsApp protobufs oder `--remove` in signal-cli). Jede Übertragung erzeugt eine Geräte-Ack, obwohl für das Opfer kein UI-Delta entsteht.
3. Zeitstemple den Sendezeitpunkt und jede Ankunft einer delivery receipt. Eine 1‑Hz-Schleife wie die folgende liefert dauerhaft per-Gerät RTT-Traces:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Da WhatsApp/Signal unbegrenzte Reaction-Updates akzeptieren, muss der Angreifer nie neuen Chatinhalt posten oder sich um Edit-Fenster sorgen.

## Spooky stranger: probing arbitrary phone numbers

1. Registriere einen frischen WhatsApp/Signal-Account und hole automatisch die öffentlichen Identity-Keys für die Zielnummer (geschieht bei der Session-Initialisierung).
2. Konstruiere ein Reaction/Edit/Delete-Paket, das sich auf eine zufällige `message_id` bezieht, die von keiner Partei gesehen wurde (WhatsApp akzeptiert beliebige `key.id` GUIDs; Signal verwendet Millisekunden-Timestamps).
3. Sende das Paket, obwohl kein Thread existiert. Die Geräte des Opfers entschlüsseln es, finden keine passende Basisnachricht, verwerfen die Zustandsänderung, bestätigen aber trotzdem den eingehenden ciphertext und senden device receipts an den Angreifer zurück.
4. Wiederhole kontinuierlich, um RTT-Serien aufzubauen, ohne jemals in der Chatliste des Opfers aufzutauchen.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Nachdem eine Nachricht einmal "delete-for-everyone" ausgeführt wurde, haben weitere Delete-Pakete für dieselbe `message_id` keinen UI-Effekt, aber jedes Gerät entschlüsselt und bestätigt sie weiterhin.
* **Out-of-window operations:** WhatsApp erzwingt ~60 h Delete- / ~20 min Edit-Fenster in der UI; Signal erzwingt ~48 h. Konstruktierte Protokollnachrichten außerhalb dieser Fenster werden auf dem Gerät des Opfers still ignoriert, dennoch werden receipts übertragen, sodass Angreifer unbegrenzt lange danach probeen können.
* **Invalid payloads:** Fehlerhafte Edit-Bodies oder Deletes, die sich auf bereits gelöschte Nachrichten beziehen, zeigen dasselbe Verhalten—Entschlüsselung plus receipt, null nutzerseitige Artefakte.

## Multi-device amplification & fingerprinting

* Jedes zugeordnete Gerät (Telefon, Desktop-App, Browser-Companion) entschlüsselt die Probe unabhängig und sendet seine eigene Ack. Das Zählen der receipts pro Probe offenbart die exakte Anzahl der Geräte.
* Ist ein Gerät offline, wird seine receipt in die Queue gestellt und bei Wiederverbindung gesendet. Lücken geben daher online/offline-Zyklen und sogar Pendelpläne preis (z. B. fehlen Desktop-Receipts während Reisen).
* RTT-Verteilungen unterscheiden sich plattformbedingt aufgrund von OS-Power-Management und Push-Wakeups. Cluster RTTs (z. B. k-means über Median/Varianz-Features), um Labels wie “Android handset”, “iOS handset”, “Electron desktop” etc. zu vergeben.
* Da der Sender vor dem Verschlüsseln das Key-Inventory des Empfängers abrufen muss, kann der Angreifer auch beobachten, wann neue Geräte gekoppelt werden; ein plötzlicher Anstieg der Geräteanzahl oder ein neues RTT-Cluster ist ein starker Indikator.

## Behaviour inference from RTT traces

1. Sampel mit ≥1 Hz, um OS-Scheduling-Effekte zu erfassen. Bei WhatsApp auf iOS korrelieren <1 s RTTs stark mit screen-on/foreground, >1 s mit screen-off/background-Throttling.
2. Baue einfache Klassifizierer (Thresholding oder Zwei-Cluster k-means), die jede RTT als "active" oder "idle" labeln. Aggregiere Labels zu Streaks, um Schlafzeiten, Pendelzeiten, Arbeitszeiten oder die Aktivität des Desktop-Companions abzuleiten.
3. Korrelieren simultane Probes an alle Geräte, um zu sehen, wann Nutzer von Mobile zu Desktop wechseln, wann Begleitgeräte offline gehen und ob die App durch Push vs. persistent socket rate-limitiert ist.

## Stealthy resource exhaustion

Da jede stille Probe entschlüsselt und bestätigt werden muss, erzeugt kontinuierliches Senden von Reaction-Toggles, invalid edits oder Delete-for-everyone-Paketen einen Application-Layer DoS:

* Hält das Radio/Modem jede Sekunde aktiv → spürbarer Batterieverschleiß, besonders bei idle Handsets.
* Erzeugt unmetered Upstream/Downstream-Traffic, der mobile Datentarife aufbrauchen kann, während er sich in TLS/WebSocket-Noise einfügt.
* Belegt Crypto-Threads und führt zu Jitter in Latenz-sensitiven Features (VoIP, Video), obwohl der Nutzer niemals Benachrichtigungen sieht.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
