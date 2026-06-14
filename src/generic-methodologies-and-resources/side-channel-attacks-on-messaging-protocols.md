# Side-Channel-Angriffe auf Delivery Receipts in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts sind in modernen Ende-zu-Ende-verschlüsselten (E2EE) Messengers Pflicht, weil Clients wissen müssen, wann ein Ciphertext entschlüsselt wurde, damit sie Ratcheting-State und ephemere Keys verwerfen können. Der Server leitet opaque blobs weiter, daher werden Gerätebestätigungen (double checkmarks) vom Empfänger nach erfolgreicher Entschlüsselung gesendet. Die Messung der Round-Trip-Time (RTT) zwischen einer vom Angreifer ausgelösten Aktion und dem entsprechenden Delivery Receipt legt einen hochauflösenden Timing-Channel offen, der Gerätestatus, Online-Präsenz leakt und für covert DoS missbraucht werden kann. Multi-Device-„client-fanout“-Deployments verstärken den leak, weil jedes registrierte Gerät die Probe entschlüsselt und seine eigene Bestätigung zurücksendet.

## Delivery-receipt-Quellen vs. für Nutzer sichtbare Signale

Wähle Nachrichtentypen, die immer ein Delivery Receipt auslösen, aber auf dem Opfer keine UI-Artefakte anzeigen. Die folgende Tabelle fasst das empirisch bestätigte Verhalten zusammen:

| Messenger | Aktion | Delivery receipt | Opfer-Benachrichtigung | Notizen |
|-----------|--------|------------------|------------------------|-------|
| **WhatsApp** | Text message | ● | ● | Immer laut → nur zum Bootstrap des Zustands nützlich. |
| | Reaction | ● | ◐ (nur wenn auf eine Nachricht des Opfers reagiert wird) | Selbst-Reaktionen und Entfernen bleiben still. |
| | Edit | ● | Plattformabhängige stille push | Edit-Fenster ≈20 min; nach Ablauf trotzdem ack’d. |
| | Delete for everyone | ● | ○ | UI erlaubt ~60 h, aber spätere Pakete werden trotzdem ack’d. |
| **Signal** | Text message | ● | ● | Gleiche Einschränkungen wie WhatsApp. |
| | Reaction | ● | ◐ | Selbst-Reaktionen für das Opfer unsichtbar. |
| | Edit/Delete | ● | ○ | Server erzwingt ~48 h Fenster, erlaubt bis zu 10 edits, aber späte Pakete werden trotzdem ack’d. |
| **Threema** | Text message | ● | ● | Multi-Device-Receipts werden aggregiert, daher wird pro Probe nur eine RTT sichtbar. |

Legende: ● = immer, ◐ = bedingt, ○ = nie. Plattformabhängiges UI-Verhalten ist direkt im Text vermerkt. Read Receipts bei Bedarf deaktivieren, aber Delivery Receipts lassen sich in WhatsApp oder Signal nicht abschalten.

## Ziele und Modelle des Angreifers

* **G1 – Device fingerprinting:** Zähle, wie viele Receipts pro Probe eintreffen, clustere RTTs, um OS/Client (Android vs iOS vs desktop) abzuleiten, und beobachte Online/Offline-Übergänge.
* **G2 – Verhaltensüberwachung:** Behandle die hochfrequente RTT-Serie (≈1 Hz ist stabil) als Zeitreihe und leite screen on/off, app foreground/background, Pendelzeiten vs Arbeitszeiten usw. ab.
* **G3 – Ressourcenerschöpfung:** Halte Radios/CPUs jedes Opfergeräts wach, indem du endlose stille Probes sendest, Batterie/Daten leerst und VoIP/RTC-Qualität verschlechterst.

Zwei Threat Actors reichen aus, um die Missbrauchsfläche zu beschreiben:

1. **Creepy companion:** teilt bereits einen Chat mit dem Opfer und missbraucht Selbst-Reaktionen, das Entfernen von Reaktionen oder wiederholte edits/deletes, die an bestehende message IDs gebunden sind.
2. **Spooky stranger:** registriert ein Burner-Account und sendet Reaktionen, die sich auf message IDs beziehen, die lokal nie in der Konversation existierten; WhatsApp und Signal entschlüsseln und bestätigen sie trotzdem, obwohl das UI die Zustandsänderung verwirft, also ist keine vorherige Konversation nötig.

## Tooling für rohen Protokollzugriff

Verlasse dich auf Clients, die das zugrunde liegende E2EE-Protokoll offenlegen, damit du Pakete außerhalb der UI-Beschränkungen bauen, beliebige `message_id`s angeben und genaue Zeitstempel loggen kannst:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) oder [Cobalt](https://github.com/Auties00/Cobalt) (mobile-orientiert) erlauben das Senden von rohen `ReactionMessage`, `ProtocolMessage` (edit/delete) und `Receipt`-Frames, während der double-ratchet-State synchron bleibt.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) zusammen mit [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) legt jeden Nachrichtentyp via CLI/API offen. Die aktuelle `signal-cli`-Syntax nutzt `sendReaction RECIPIENT --target-author --target-timestamp`; `receive` oder `daemon` müssen laufen, damit Delivery Receipts tatsächlich gesammelt werden. Beispiel für einen Self-Reaction-Toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Der Source-Code des Android-Clients dokumentiert, wie Delivery Receipts vor dem Verlassen des Geräts konsolidiert werden, was erklärt, warum der Side Channel dort nur eine vernachlässigbare Bandbreite hat.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) liefert WhatsApp/Signal-Backends, nutzt standardmäßig stille delete-Probes und labelt `active` vs `standby` mit einem rolling-median threshold (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ist ein leichter WhatsApp-first-CLI mit `--delay`, `--concurrent`, CSV/Prometheus-Exportern und Grafana-freundlichem Output. Behandle beide als Reconnaissance-Helfer statt als Protokollreferenzen; die wichtige Erkenntnis ist, wie wenig Code nötig ist, sobald roher Clientzugriff existiert.

Wenn eigenes Tooling nicht verfügbar ist, kannst du trotzdem stille Aktionen über WhatsApp Web oder Signal Desktop auslösen und den verschlüsselten websocket/WebRTC-Channel sniffen, aber rohe APIs entfernen UI-Verzögerungen und erlauben ungültige Operationen.

## Creepy companion: stille Sampling-Schleife

1. Wähle irgendeine historische Nachricht, die du im Chat verfasst hast, damit das Opfer nie sieht, wie sich „reaction“-Ballons ändern.
2. Wechsle zwischen einem sichtbaren Emoji und einem leeren reaction payload (kodiert als `""` in WhatsApp protobufs oder `--remove` in signal-cli). Jede Übertragung erzeugt eine device ack, obwohl es für das Opfer keine UI-Änderung gibt.
3. Zeitstemple die Sendezeit und das Eintreffen jedes Delivery Receipts. Eine 1-Hz-Schleife wie die folgende liefert unbegrenzt pro-Gerät RTT-Traces:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Weil WhatsApp/Signal unbegrenzte Reaction-Updates akzeptieren, muss der Angreifer nie neuen Chat-Content posten oder sich um edit windows kümmern.

## Spooky stranger: beliebige Telefonnummern prüfen

1. Registriere einen frischen WhatsApp/Signal-Account und hole die öffentlichen Identity Keys für die Zielnummer (automatisch während des Session-Setup erledigt).
2. Baue ein reaction/edit/delete-Paket, das sich auf eine zufällige `message_id` bezieht, die von keiner Seite je gesehen wurde (WhatsApp akzeptiert beliebige `key.id` GUIDs; Signal verwendet Millisekunden-Timestamps).
3. Sende das Paket, obwohl kein Thread existiert. Die Opfergeräte entschlüsseln es, finden die Basisnachricht nicht, verwerfen die Zustandsänderung, bestätigen den eingehenden Ciphertext aber trotzdem und senden device receipts an den Angreifer zurück.
4. Wiederhole das kontinuierlich, um RTT-Serien aufzubauen, ohne jemals in der Chatliste des Opfers aufzutauchen.

Wenn du zuerst herausfinden musst, welche Nummern registriert sind, oder Device-Inventare in großem Maßstab vorbefüllen willst, verknüpfe dies mit [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) statt zufällige E.164-Bereiche von Hand zu raten.

Veröffentlichte Arbeiten zu contact-discovery zeigten, warum das operativ wichtig ist: Mit genauen Telefonvorwahlen und moderaten Ressourcen konnten Forscher bei WhatsApp etwa `10%` der US-Mobilnummern und bei Signal `100%` abfragen, bevor sie zu gezieltem probing übergingen. In der Praxis hält das Vorfiltern aktiver Accounts das Budget für stille Probes auf Nummern fokussiert, die Pakete tatsächlich entschlüsseln.

Neuere WhatsApp-Builds bieten außerdem `Settings -> Privacy -> Advanced -> Block unknown account messages`. Behandle das als Durchsatzbegrenzer, nicht als Fix: Es schadet vor allem dauerhaftem Flooding durch Unbekannte und ist irrelevant, sobald du bereits ein bekannter Kontakt bist.

## Edits und Deletes als covert Trigger recyceln

* **Wiederholte Deletes:** Nachdem eine Nachricht einmal für alle gelöscht wurde, haben weitere delete-Pakete mit derselben `message_id` keine UI-Wirkung, aber jedes Gerät entschlüsselt und bestätigt sie weiterhin.
* **Operationen außerhalb des Fensters:** WhatsApp erzwingt in der UI ~60 h Delete- / ~20 min Edit-Fenster; Signal erzwingt ~48 h. Gekünstelte Protokollnachrichten außerhalb dieser Fenster werden auf dem Opfergerät lautlos ignoriert, aber Receipts werden trotzdem übertragen, sodass Angreifer noch lange nach Gesprächsende unbegrenzt probe können.
* **Ungültige Payloads:** Fehlformatierte edit bodies oder Deletes, die bereits bereinigte Nachrichten referenzieren, lösen dasselbe Verhalten aus — Entschlüsselung plus Receipt, keine für Nutzer sichtbaren Artefakte.

## Multi-Device-Amplifikation & Fingerprinting

* Jedes verknüpfte Gerät (Telefon, Desktop-App, Browser-Companion) entschlüsselt die Probe unabhängig und sendet seine eigene ack zurück. Das Zählen der Receipts pro Probe offenbart die exakte Geräteanzahl.
* Wenn ein Gerät offline ist, wird sein Receipt gequeued und bei Reconnect ausgelöst. Lücken leaken daher Online/Offline-Zyklen und sogar Pendelzeiten (z. B. stoppen Desktop-Receipts während der Fahrt).
* RTT-Verteilungen unterscheiden sich je nach Plattform wegen OS-Power-Management und push wakeups. Clustere RTTs (z. B. k-means auf Median/Varianz-Features), um „Android handset“, „iOS handset“, „Electron desktop“ usw. zu labeln.
* Weil der Sender vor dem Encrypting das Key-Inventar des Empfängers abrufen muss, kann der Angreifer auch beobachten, wann neue Geräte gepaart werden; ein plötzlicher Anstieg der Geräteanzahl oder ein neuer RTT-Cluster ist ein starkes Indiz.

## Sampling-Cadence, Queueing und gestapelte Receipts

* **WhatsApp burst tolerance:** Veröffentlichte Messungen berichteten, dass WhatsApp stille Reaction-Bursts mit bis zu einer Probe alle `50 ms` ohne offensichtliches Server-Queueing akzeptierte. Das ist nützlich für kurze Kalibrierungs-Bursts, schnelles Device Counting oder ein schnelles Hochfahren eines Drain-Angriffs.
* **Signal long-run queueing:** Signal tolerierte kurze Bursts, begann aber bei dauerhaftem Traffic mit mehreren Probes pro Sekunde zu queueing. Für langfristiges Monitoring halte die Kadenz bei etwa `1 Hz` (oder darunter), damit jedes Receipt weiterhin den aktuellen Gerätezustand widerspiegelt statt Backlog-Drain.
* **Reconnect-Artefakte:** Wenn ein Gerät wieder online kommt, bündeln manche Clients mehrere verzögerte Receipts oder flushen sie schnell. Behandle solche Receipt-Bursts als Zustandsübergangsmarker und nicht als unabhängige RTT-Samples, sonst overfittet dein Clustering / `active` vs `idle`-Classifier auf Reconnect-Rauschen.

## Verhaltensableitung aus RTT-Traces

1. Sample mit ≥1 Hz, um OS-Scheduling-Effekte zu erfassen. Bei WhatsApp auf iOS korrelieren RTTs unter 1 s stark mit screen-on/foreground, über 1 s mit screen-off/background throttling.
2. Baue einfache Klassifikatoren (Thresholding oder Zwei-Cluster-k-means), die jede RTT als "active" oder "idle" labeln. Aggregiere Labels zu Streaks, um Schlafenszeiten, Pendelstrecken, Arbeitszeiten oder die Aktivität des Desktop-Companions abzuleiten.
3. Korrelation simultaner Probes an jedes Gerät zeigt, wann Nutzer von Mobile zu Desktop wechseln, wann Companions offline gehen und ob die App durch push oder einen persistenten Socket rate-limited wird.
4. Vermeide in realen Netzwerken einen einzelnen hart codierten `1 s`-Threshold. Bootstrappe jedes Gerät mit einem kurzen Warm-up-Fenster und halte eine rollende Baseline fest (z. B. `threshold = 0.9 * median RTT`), damit Wi-Fi-/Cellular-Drift deinen Classifier nicht zerstört.

## Standortableitung aus Delivery RTT

Dasselbe Timing-Primitive kann auch dafür verwendet werden, nicht nur Aktivität, sondern den Aufenthaltsort des Empfängers abzuleiten. Die Arbeit `Hope of Delivery` zeigte, dass das Training auf RTT-Verteilungen bekannter Empfängerorte einem Angreifer später erlaubt, den Standort des Opfers allein aus Delivery Confirmations zu klassifizieren:

* Baue eine Baseline für dasselbe Ziel auf, während es sich an mehreren bekannten Orten befindet (Zuhause, Büro, Campus, Land A vs Land B usw.).
* Sammle für jeden Ort viele normale Message-RTTs und extrahiere einfache Features wie Median, Varianz oder Perzentil-Buckets.
* Vergleiche während des echten Angriffs die neue Probe-Serie mit den trainierten Clustern. Das Paper berichtet, dass selbst Orte innerhalb derselben Stadt oft getrennt werden können, mit `>80%` Genauigkeit in einem 3-Orte-Setting.
* Das funktioniert am besten, wenn der Angreifer die Sender-Umgebung kontrolliert und unter ähnlichen Netzwerkbedingungen probt, weil der gemessene Pfad das Zugangsnetz des Empfängers, Wake-up-Latenz und die Messenger-Infrastruktur umfasst.

Im Gegensatz zu den stillen Reaction/Edit/Delete-Angriffen oben erfordert die Standortableitung keine ungültigen message IDs oder stealthy state-changing packets. Normale Nachrichten mit regulären Delivery Confirmations genügen, daher ist der Trade-off geringere Stealth, aber breitere Anwendbarkeit über Messenger hinweg.

## Stealthy Ressourcenerschöpfung

Weil jede stille Probe entschlüsselt und bestätigt werden muss, erzeugt das kontinuierliche Senden von Reaction-Toggles, ungültigen edits oder delete-for-everyone-Paketen einen Application-Layer-DoS:

* Erzwingt, dass Radio/Modem jede Sekunde sendet/empfängt → merklicher Batterieverbrauch, besonders auf inaktiven Handsets.
* Erzeugt unmetered upstream/downstream traffic, der mobile Datenpläne verbraucht und sich gleichzeitig in TLS/WebSocket-Rauschen einfügt.
* Belegt Kryptothreads und führt zu Jitter bei latenzsensitiven Features (VoIP, Videoanrufe), obwohl der Nutzer nie Benachrichtigungen sieht.
* In WhatsApp akzeptieren ungültige Reaktionen viel mehr Daten, als ein normales Emoji vermuten lässt: Veröffentlichte Messungen fanden serverseitige Akzeptanz von bis zu ungefähr `1 MB` pro Reaktion.
* Übergroße Reaktionen liefern keine zuverlässigen Delivery Receipts mehr, sobald der Body über ungefähr `30 bytes` wächst, werden aber trotzdem weitergeleitet und verarbeitet, bevor sie verworfen werden. Halte reaction bodies klein, wenn du ACKs brauchst; vergrößere sie nur, wenn das Ziel reiner Drain oder covert one-way transport ist.
* Öffentliche Messungen erreichten in diesem Modus etwa `3.7 MB/s` (`~13.3 GB/h`) an Opfertraffic.

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
