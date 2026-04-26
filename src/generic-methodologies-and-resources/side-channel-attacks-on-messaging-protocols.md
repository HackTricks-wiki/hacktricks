# Side-Channel-Angriffe auf Delivery Receipts in E2EE Messengern

{{#include ../banners/hacktricks-training.md}}

Delivery receipts sind in modernen End-to-End-encrypted (E2EE) Messengern Pflicht, weil Clients wissen müssen, wann ein Ciphertext entschlüsselt wurde, damit sie Ratcheting-State und Ephemeral Keys verwerfen können. Der Server leitet opaque Blobs weiter, daher werden Gerätebestätigungen (doppelte Häkchen) vom Empfänger nach erfolgreicher Entschlüsselung gesendet. Das Messen der Round-Trip-Time (RTT) zwischen einer vom Angreifer ausgelösten Aktion und dem entsprechenden Delivery Receipt offenbart einen hochauflösenden Timing-Kanal, der Gerätezustand, Online-Präsenz leakt und für covert DoS missbraucht werden kann. Multi-Device-„client-fanout“-Deployments verstärken das leak, weil jedes registrierte Gerät die Probe entschlüsselt und sein eigenes Receipt zurücksendet.

## Delivery-receipt-Quellen vs. für den Nutzer sichtbare Signale

Wähle Nachrichtentypen, die immer ein Delivery Receipt auslösen, aber auf dem Opfer keine UI-Artefakte anzeigen. Die folgende Tabelle fasst das empirisch bestätigte Verhalten zusammen:

| Messenger | Aktion | Delivery receipt | Opferbenachrichtigung | Hinweise |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Textnachricht | ● | ● | Immer laut → nur nützlich, um State zu bootstrappen. |
| | Reaktion | ● | ◐ (nur wenn auf Opfernachricht reagiert wird) | Selbstreaktionen und Entfernen bleiben still. |
| | Edit | ● | Plattformabhängiger stiller Push | Edit-Fenster ≈20 min; nach Ablauf weiterhin ack’d. |
| | Delete for everyone | ● | ○ | UI erlaubt ~60 h, aber spätere Pakete werden weiterhin ack’d. |
| **Signal** | Textnachricht | ● | ● | Gleiche Einschränkungen wie WhatsApp. |
| | Reaktion | ● | ◐ | Selbstreaktionen sind für das Opfer unsichtbar. |
| | Edit/Delete | ● | ○ | Server erzwingt ein ~48 h-Fenster, erlaubt bis zu 10 Edits, aber späte Pakete werden weiterhin ack’d. |
| **Threema** | Textnachricht | ● | ● | Multi-Device-Receipts werden aggregiert, daher wird pro Probe nur ein RTT sichtbar. |

Legende: ● = immer, ◐ = bedingt, ○ = nie. Plattformabhängiges UI-Verhalten ist inline vermerkt. Deaktiviere Read Receipts bei Bedarf, aber Delivery Receipts können in WhatsApp oder Signal nicht ausgeschaltet werden.

## Angreiferziele und Modelle

* **G1 – Device Fingerprinting:** Zähle, wie viele Receipts pro Probe eintreffen, clustere RTTs, um OS/Client zu inferieren (Android vs iOS vs Desktop), und beobachte Online/Offline-Übergänge.
* **G2 – Verhaltensüberwachung:** Behandle die hochfrequente RTT-Serie (≈1 Hz ist stabil) als Zeitreihe und inferiere Bildschirm an/aus, App foreground/background, Pendeln vs Arbeitszeiten usw.
* **G3 – Resource Exhaustion:** Halte Radios/CPUs jedes Opfergeräts wach, indem du endlose stille Probes sendest, wodurch Akku/Daten verbraucht und VoIP/RTC-Qualität verschlechtert wird.

Zwei Threat Actors reichen aus, um die Angriffsfläche zu beschreiben:

1. **Creepy companion:** teilt bereits einen Chat mit dem Opfer und missbraucht Selbstreaktionen, das Entfernen von Reaktionen oder wiederholte Edits/Deletes, die an bestehende message IDs gebunden sind.
2. **Spooky stranger:** registriert ein Burner-Konto und sendet Reaktionen, die sich auf message IDs beziehen, die in der lokalen Unterhaltung nie existiert haben; WhatsApp und Signal entschlüsseln und bestätigen sie trotzdem, obwohl die UI den State-Change verwirft, sodass keine vorherige Unterhaltung erforderlich ist.

## Tooling für Rohprotokoll-Zugriff

Verlasse dich auf Clients, die das zugrunde liegende E2EE-Protokoll offenlegen, damit du Pakete außerhalb von UI-Einschränkungen bauen, beliebige `message_id`s angeben und präzise Zeitstempel loggen kannst:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp-Web-Protokoll) oder [Cobalt](https://github.com/Auties00/Cobalt) (mobile-orientiert) erlauben das Senden roher `ReactionMessage`, `ProtocolMessage` (edit/delete) und `Receipt`-Frames, während der double-ratchet-State synchron bleibt.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) zusammen mit [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) stellt jeden Nachrichtentyp über CLI/API bereit. Beispiel für ein Selbstreaktions-Toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Die Quelle des Android-Clients dokumentiert, wie Delivery Receipts konsolidiert werden, bevor sie das Gerät verlassen, was erklärt, warum der side channel dort praktisch keine Bandbreite hat.
* **Turnkey PoCs:** öffentliche Projekte wie `device-activity-tracker` und `careless-whisper-python` automatisieren bereits stille Delete/Reaction-Probes und RTT-Klassifizierung. Behandle sie als fertige Reconnaissance-Helfer statt als Protokollreferenzen; interessant ist, dass sie bestätigen, wie operativ einfach der Angriff ist, sobald Rohzugriff auf den Client vorhanden ist.

Wenn benutzerdefiniertes Tooling nicht verfügbar ist, kannst du stille Aktionen trotzdem aus WhatsApp Web oder Signal Desktop auslösen und den verschlüsselten websocket/WebRTC-Kanal sniffen, aber rohe APIs entfernen UI-Verzögerungen und erlauben ungültige Operationen.

## Creepy companion: silent sampling loop

1. Wähle eine beliebige historische Nachricht, die du im Chat verfasst hast, damit das Opfer nie sieht, dass sich „reaction“-Balloons ändern.
2. Wechsle zwischen einem sichtbaren Emoji und einem leeren Reaction-Payload (kodiert als `""` in WhatsApp-Protobufs oder `--remove` in signal-cli). Jede Übertragung erzeugt ein Device Ack, obwohl es für das Opfer keine UI-Änderung gibt.
3. Time den Sendezeitpunkt und jede Ankunft eines Delivery Receipts. Eine 1-Hz-Schleife wie die folgende liefert unbegrenzt RTT-Traces pro Gerät:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Weil WhatsApp/Signal unbegrenzte Reaction-Updates akzeptieren, muss der Angreifer nie neue Chat-Inhalte posten oder sich um Edit-Fenster sorgen.

## Spooky stranger: beliebige Telefonnummern probieren

1. Registriere ein frisches WhatsApp/Signal-Konto und hole die öffentlichen Identity Keys für die Zielnummer (geschieht automatisch während des Session-Setups).
2. Baue ein Reaction/Edit/Delete-Paket, das sich auf eine zufällige `message_id` bezieht, die von keiner Seite je gesehen wurde (WhatsApp akzeptiert beliebige `key.id` GUIDs; Signal verwendet Millisekunden-Zeitstempel).
3. Sende das Paket, obwohl kein Thread existiert. Die Opfergeräte entschlüsseln es, finden die Basisnachricht nicht, verwerfen den State-Change, bestätigen aber trotzdem den eingehenden Ciphertext und senden Device Receipts an den Angreifer zurück.
4. Wiederhole das fortlaufend, um RTT-Serien aufzubauen, ohne jemals in der Chatliste des Opfers aufzutauchen.

## Edits und Deletes als covert Trigger wiederverwenden

* **Wiederholte Deletes:** Nachdem eine Nachricht einmal delete-for-everyone wurde, haben weitere Delete-Pakete mit derselben `message_id` keinen UI-Effekt, aber jedes Gerät entschlüsselt und bestätigt sie weiterhin.
* **Operationen außerhalb des Fensters:** WhatsApp erzwingt im UI ein ~60-h-Delete- und ~20-min-Edit-Fenster; Signal erzwingt ~48 h. Konstruierte Protokollnachrichten außerhalb dieser Fenster werden auf dem Opfergerät still ignoriert, doch Receipts werden trotzdem übertragen, sodass Angreifer noch lange nach Ende der Unterhaltung Probes senden können.
* **Ungültige Payloads:** Fehlerhafte Edit-Bodies oder Deletes, die auf bereits bereinigte Nachrichten verweisen, erzeugen dasselbe Verhalten — Entschlüsselung plus Receipt, keine für den Nutzer sichtbaren Artefakte.

## Multi-Device-Verstärkung & Fingerprinting

* Jedes zugeordnete Gerät (Telefon, Desktop-App, Browser-Companion) entschlüsselt die Probe unabhängig und sendet sein eigenes Ack zurück. Das Zählen der Receipts pro Probe offenbart die exakte Geräteanzahl.
* Wenn ein Gerät offline ist, wird sein Receipt in eine Queue gestellt und bei Reconnect gesendet. Lücken leaken daher Online/Offline-Zyklen und sogar Pendelzeiten (z. B. Desktop-Receipts stoppen während der Fahrt).
* RTT-Verteilungen unterscheiden sich je nach Plattform aufgrund von OS-Power-Management und Push-Wakeups. Clustere RTTs (z. B. k-means auf Median/Varianz-Features), um „Android handset“, „iOS handset“, „Electron desktop“ usw. zu labeln.
* Weil der Sender vor dem Verschlüsseln das Key-Inventar des Empfängers abrufen muss, kann der Angreifer auch beobachten, wann neue Geräte gekoppelt werden; ein plötzlicher Anstieg der Geräteanzahl oder ein neuer RTT-Cluster ist ein starkes Indiz.

## Verhalten aus RTT-Traces inferieren

1. Mit ≥1 Hz sampeln, um OS-Scheduling-Effekte zu erfassen. Mit WhatsApp auf iOS korrelieren <1 s RTTs stark mit screen-on/foreground, >1 s mit screen-off/background throttling.
2. Einfache Klassifikatoren bauen (Thresholding oder zwei-Cluster-k-means), die jede RTT als „active“ oder „idle“ labeln. Labels zu Streaks aggregieren, um Schlafenszeiten, Pendeln, Arbeitszeiten oder die Aktivität des Desktop-Companions abzuleiten.
3. Simultane Probes an jedes Gerät korrelieren, um zu sehen, wann Nutzer von Mobile zu Desktop wechseln, wann Companions offline gehen und ob die App durch Push oder einen persistent socket rate-limited wird.

## Standortinferenzen aus Delivery RTT

Derselbe Timing-Primitive kann umfunktioniert werden, um zu inferieren, wo sich der Empfänger befindet, nicht nur, ob er aktiv ist. Die Arbeit `Hope of Delivery` zeigte, dass Training auf RTT-Verteilungen für bekannte Empfängerstandorte es einem Angreifer später erlaubt, den Standort des Opfers allein aus Delivery Confirmations zu klassifizieren:

* Baue eine Baseline für dasselbe Ziel, während es sich an mehreren bekannten Orten befindet (Zuhause, Büro, Campus, Land A vs. Land B usw.).
* Sammle für jeden Standort viele normale Message-RTTs und extrahiere einfache Features wie Median, Varianz oder Perzentil-Buckets.
* Vergleiche während des realen Angriffs die neue Probe-Serie mit den trainierten Clustern. Das Paper berichtet, dass selbst Standorte innerhalb derselben Stadt oft getrennt werden können, mit `>80%` Genauigkeit in einem 3-Standorte-Setting.
* Das funktioniert am besten, wenn der Angreifer die Senderumgebung kontrolliert und unter ähnlichen Netzwerkbedingungen probt, weil der gemessene Pfad das Zugangsnetz des Empfängers, Wake-up-Latenz und Messenger-Infrastruktur einschließt.

Im Gegensatz zu den oben beschriebenen stillen Reaction/Edit/Delete-Angriffen erfordert Standortinferierung keine ungültigen message IDs oder stealthy state-changing packets. Einfache Nachrichten mit normalen Delivery Confirmations reichen aus, also ist der Trade-off weniger Stealth, aber breitere Anwendbarkeit über Messenger hinweg.

## Stealthy resource exhaustion

Da jede stille Probe entschlüsselt und bestätigt werden muss, erzeugt das kontinuierliche Senden von Reaction-Toggles, ungültigen Edits oder delete-for-everyone-Paketen einen Application-Layer-DoS:

* Erzwingt, dass Radio/Modem jede Sekunde sendet/empfängt → spürbarer Akkuverbrauch, besonders auf im Leerlauf befindlichen Handsets.
* Erzeugt unmetered Upstream-/Downstream-Traffic, der mobile Datenpläne verbraucht und dabei im TLS/WebSocket-Rauschen untergeht.
* Belegt Crypto-Threads und führt zu Jitter in latenzsensitiven Funktionen (VoIP, Videoanrufe), obwohl der Nutzer nie Benachrichtigungen sieht.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
