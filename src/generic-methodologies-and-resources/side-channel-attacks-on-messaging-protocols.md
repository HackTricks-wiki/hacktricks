# Side-Channel-Angriffe auf Delivery Receipts in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts sind in modernen End-to-End-encrypted (E2EE) Messengers Pflicht, weil Clients wissen müssen, wann ein ciphertext entschlüsselt wurde, damit sie ratcheting state und ephemeral keys verwerfen können. Der Server leitet opaque blobs weiter, daher werden device acknowledgements (double checkmarks) vom Empfänger nach erfolgreicher Entschlüsselung gesendet. Das Messen der round-trip time (RTT) zwischen einer vom Angreifer ausgelösten Aktion und dem entsprechenden delivery receipt offenbart einen hochauflösenden Timing-Kanal, der device state und online presence leak und für covert DoS missbraucht werden kann. Multi-device "client-fanout"-Deployments verstärken das leak, weil jedes registrierte Gerät die Probe entschlüsselt und sein eigenes receipt zurücksendet.

## Delivery receipt sources vs. user-visible signals

Wähle Nachrichtentypen, die immer ein delivery receipt auslösen, aber auf dem Opfer keine UI-Artefakte anzeigen. Die folgende Tabelle fasst das empirisch bestätigte Verhalten zusammen:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Immer lautstark → nur nützlich, um den State zu bootstrappen. |
| | Reaction | ● | ◐ (nur wenn auf die Opfernachricht reagiert wird) | Self-reactions und removals bleiben lautlos. |
| | Edit | ● | Plattformabhängige stille push | Edit-Fenster ≈20 min; auch nach Ablauf noch ack’d. |
| | Delete for everyone | ● | ○ | UI erlaubt ~60 h, aber spätere Pakete werden weiter ack’d. |
| **Signal** | Text message | ● | ● | Gleiche Einschränkungen wie bei WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions für das Opfer unsichtbar. |
| | Edit/Delete | ● | ○ | Der Server erzwingt ein Fenster von ~48 h, erlaubt bis zu 10 edits, aber späte Pakete werden weiter ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts werden aggregiert, daher wird pro Probe nur eine RTT sichtbar. |

Legende: ● = immer, ◐ = bedingt, ○ = nie. Plattformabhängiges UI-Verhalten ist direkt im Text vermerkt. Deaktiviere read receipts bei Bedarf, aber delivery receipts lassen sich in WhatsApp oder Signal nicht abschalten.

## Ziele und Modelle des Angreifers

* **G1 – Device fingerprinting:** Zähle, wie viele receipts pro Probe eintreffen, cluster RTTs, um OS/client (Android vs iOS vs desktop) zu inferieren, und beobachte online/offline-Übergänge.
* **G2 – Verhaltensmonitoring:** Behandle die hochfrequente RTT-Serie (≈1 Hz ist stabil) als Zeitreihe und inferiere screen on/off, app foreground/background, Pendeln vs Arbeitszeiten usw.
* **G3 – Ressourcenauslastung:** Halte Radios/CPUs jedes Opfergeräts wach, indem du endlose stille Probes sendest, Akku/Daten drainst und die VoIP/RTC-Qualität verschlechterst.

Zwei Threat Actor reichen aus, um die Abuse-Fläche zu beschreiben:

1. **Creepy companion:** teilt bereits einen Chat mit dem Opfer und missbraucht self-reactions, reaction removals oder wiederholte edits/deletes, die an bestehende message IDs gebunden sind.
2. **Spooky stranger:** registriert ein Burner-Konto und sendet reactions mit Verweisen auf message IDs, die lokal in der Konversation nie existiert haben; WhatsApp und Signal entschlüsseln und bestätigen sie trotzdem, obwohl das UI die Zustandsänderung verwirft, sodass keine vorherige Konversation erforderlich ist.

## Tooling für direkten Protokollzugriff

Nutze Clients, die das zugrunde liegende E2EE-Protokoll exponieren, damit du Pakete außerhalb der UI-Beschränkungen bauen, beliebige `message_id`s angeben und exakte Zeitstempel protokollieren kannst:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) oder [Cobalt](https://github.com/Auties00/Cobalt) (mobile-orientiert) erlauben das Senden von rohen `ReactionMessage`, `ProtocolMessage` (edit/delete) und `Receipt`-Frames, während der double-ratchet state synchron bleibt.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) kombiniert mit [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) exponiert jeden Nachrichtentyp per CLI/API. Die aktuelle `signal-cli`-Syntax verwendet `sendReaction RECIPIENT --target-author --target-timestamp`; lasse `receive` oder `daemon` laufen, damit delivery receipts tatsächlich gesammelt werden. Beispiel für einen Self-Reaction-Toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Die Source des Android-Clients dokumentiert, wie delivery receipts vor dem Verlassen des Geräts konsolidiert werden, was erklärt, warum der Side Channel dort eine vernachlässigbare Bandbreite hat.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) bringt WhatsApp/Signal-Backends mit, nutzt standardmäßig stille delete probes und labelt `active` vs `standby` mit einem Rolling-Median-Threshold (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ist ein leichter WhatsApp-first-CLI mit `--delay`, `--concurrent`, CSV/Prometheus-Exportern und Grafana-freundlicher Ausgabe. Behandle beide als Reconnaissance-Helper statt als Protokollreferenzen; die wichtige Erkenntnis ist, wie wenig Code nötig ist, sobald Raw Client Access vorhanden ist.

Wenn eigenes Tooling nicht verfügbar ist, kannst du trotzdem stille Aktionen über WhatsApp Web oder Signal Desktop auslösen und den verschlüsselten websocket/WebRTC-Kanal sniffen, aber raw APIs entfernen UI-Verzögerungen und erlauben ungültige Operationen.

## Creepy companion: silent sampling loop

1. Wähle irgendeine historische Nachricht, die du im Chat selbst verfasst hast, damit das Opfer nie sieht, dass sich "reaction"-Bubbles verändern.
2. Wechsle zwischen einem sichtbaren Emoji und einem leeren reaction payload (kodiert als `""` in WhatsApp protobufs oder `--remove` in signal-cli). Jede Übertragung erzeugt einen device ack, obwohl es für das Opfer keine UI-Änderung gibt.
3. Zeitstempel für die Sendezeit und jeden delivery-receipt-Eingang. Ein 1 Hz-Loop wie der folgende liefert unbegrenzt per-device RTT-Traces:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Da WhatsApp/Signal unbegrenzte reaction updates akzeptieren, muss der Angreifer nie neue Chat-Inhalte posten oder sich um edit windows kümmern.

## Spooky stranger: Probing beliebiger Telefonnummern

1. Registriere ein frisches WhatsApp/Signal-Konto und hole die öffentlichen identity keys für die Zielnummer (geschieht automatisch während der Session-Einrichtung).
2. Baue ein reaction/edit/delete-Paket, das sich auf eine zufällige `message_id` bezieht, die von keiner Seite je gesehen wurde (WhatsApp akzeptiert beliebige `key.id` GUIDs; Signal verwendet Millisecond-Timestamps).
3. Sende das Paket, obwohl kein Thread existiert. Die Opfergeräte entschlüsseln es, können die Basisnachricht nicht zuordnen, verwerfen die Zustandsänderung, bestätigen aber trotzdem den eingehenden ciphertext und senden device receipts zurück an den Angreifer.
4. Wiederhole dies kontinuierlich, um RTT-Serien aufzubauen, ohne je in der Chat-Liste des Opfers aufzutauchen.

Wenn du zuerst herausfinden musst, welche Nummern registriert sind, oder device inventories in großem Maßstab vorab befüllen willst, verknüpfe das mit [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) statt zufällige E.164-Bereiche von Hand zu raten.

Neuere WhatsApp-Builds bieten außerdem `Settings -> Privacy -> Advanced -> Block unknown account messages`. Betrachte das als Durchsatzbegrenzer, nicht als Fix: Es erschwert vor allem anhaltendes Flooding nur mit Fremden und ist irrelevant, sobald du bereits ein bekannter Kontakt bist.

## Edits und Deletes als covert triggers wiederverwenden

* **Repeated deletes:** Nachdem eine Nachricht einmal für alle gelöscht wurde, haben weitere delete-Pakete mit derselben `message_id` keine UI-Wirkung, aber jedes Gerät entschlüsselt und bestätigt sie weiterhin.
* **Out-of-window operations:** WhatsApp erzwingt in der UI ein Delete-Fenster von ~60 h / ein Edit-Fenster von ~20 min; Signal erzwingt ~48 h. Außerhalb dieser Fenster werden konstruierte Protokollnachrichten auf dem Opfergerät lautlos ignoriert, dennoch werden receipts übertragen, sodass Angreifer noch lange nach Gesprächsende weiter proben können.
* **Invalid payloads:** Fehlformatierte edit bodies oder Deletes, die auf bereits bereinigte Nachrichten verweisen, erzeugen dasselbe Verhalten — Entschlüsselung plus receipt, keine sichtbaren Artefakte für den Benutzer.

## Multi-device amplification & fingerprinting

* Jedes verbundene Gerät (Telefon, Desktop-App, Browser-Companion) entschlüsselt die Probe unabhängig und sendet seinen eigenen ack zurück. Das Zählen der receipts pro Probe offenbart die exakte Geräteanzahl.
* Ist ein Gerät offline, wird sein Receipt queued und bei Wiederverbindung gesendet. Lücken leak daher online/offline-Zyklen und sogar Pendelzeiten (z. B. stoppen Desktop-Receipts während der Fahrt).
* RTT-Verteilungen unterscheiden sich je nach Plattform aufgrund von OS-Energieverwaltung und Push-Wakeups. Clustere RTTs (z. B. k-means auf Median/Varianz-Features), um „Android handset“, „iOS handset“, „Electron desktop“ usw. zu labeln.
* Da der Sender vor dem Verschlüsseln das Key-Inventar des Empfängers abrufen muss, kann der Angreifer auch beobachten, wann neue Geräte gepaart werden; ein plötzlicher Anstieg der Geräteanzahl oder ein neuer RTT-Cluster ist ein starkes Indiz.

## Verhalten aus RTT-Traces inferieren

1. Sample mit ≥1 Hz, um OS-Scheduling-Effekte zu erfassen. Mit WhatsApp auf iOS korrelieren RTTs <1 s stark mit screen-on/foreground, >1 s mit screen-off/background throttling.
2. Baue einfache Klassifikatoren (Thresholding oder Zwei-Cluster-k-means), die jede RTT als "active" oder "idle" labeln. Aggregiere die Labels zu Streaks, um Schlafenszeiten, Pendeln, Arbeitszeiten oder Aktivität des Desktop-Companions abzuleiten.
3. Korreliere gleichzeitige Probes an jedes Gerät, um zu sehen, wann Nutzer vom Mobilgerät zum Desktop wechseln, wann Companions offline gehen und ob die App durch Push oder persistent socket rate-limited wird.
4. Vermeide in realen Netzen einen einzigen hart codierten `1 s`-Threshold. Boote jedes Gerät mit einem kurzen Warm-up-Fenster und halte eine Rolling-Baseline (z. B. `threshold = 0.9 * median RTT`) vor, damit Wi-Fi-/Mobilfunk-Drift deinen Klassifikator nicht kollabieren lässt.

## Location inference aus delivery RTT

Dasselbe Timing-Primitive kann auch genutzt werden, um zu inferieren, wo sich der Empfänger befindet, nicht nur ob er aktiv ist. Die Arbeit `Hope of Delivery` zeigte, dass das Training auf RTT-Verteilungen für bekannte Empfängerstandorte es einem Angreifer ermöglicht, später den Standort des Opfers allein aus delivery confirmations zu klassifizieren:

* Erstelle eine Baseline für dasselbe Ziel, während es sich an mehreren bekannten Orten befindet (home, office, campus, country A vs country B usw.).
* Sammle für jeden Ort viele normale message RTTs und extrahiere einfache Features wie Median, Varianz oder Perzentil-Buckets.
* Vergleiche während des echten Angriffs die neue Probe-Serie mit den trainierten Clustern. Das Paper berichtet, dass selbst Standorte innerhalb derselben Stadt oft getrennt werden können, mit `>80%` accuracy in einem 3-Location-Setting.
* Das funktioniert am besten, wenn der Angreifer die Senderumgebung kontrolliert und unter ähnlichen Netzwerkbedingungen probt, weil der gemessene Pfad das Zugangsnetz des Empfängers, Wake-up-Latenz und die Messenger-Infrastruktur umfasst.

Anders als die stillen reaction/edit/delete-Angriffe oben erfordert location inference keine ungültigen message IDs oder stealthy state-changing packets. Normale Nachrichten mit üblichen delivery confirmations reichen aus, daher ist der Trade-off geringere Stealth, aber breitere Anwendbarkeit über Messenger hinweg.

## Stealthy resource exhaustion

Da jede stille Probe entschlüsselt und bestätigt werden muss, erzeugt das kontinuierliche Senden von reaction toggles, invalid edits oder delete-for-everyone-Paketen ein Application-Layer-DoS:

* Erzwingt, dass Funk/Modem jede Sekunde sendet/empfängt → spürbarer Akkuverbrauch, besonders auf Idle-Handsets.
* Erzeugt unmetered Upstream-/Downstream-Traffic, der mobile Datenpläne verbraucht und sich dennoch in TLS/WebSocket-Rauschen tarnt.
* Belegt Crypto-Threads und erzeugt Jitter bei latency-sensitiven Features (VoIP, Videoanrufe), obwohl der Benutzer nie Benachrichtigungen sieht.
* In WhatsApp akzeptieren ungültige reactions deutlich mehr Daten, als ein normales Emoji vermuten lässt: Veröffentlichte Messungen fanden serverseitige Akzeptanz von bis zu ungefähr `1 MB` pro reaction.
* Überdimensionierte reactions liefern keine zuverlässigen delivery receipts mehr, sobald der Body etwa über `30 bytes` wächst, werden aber weiterhin weitergeleitet und verarbeitet, bevor sie verworfen werden. Halte reaction bodies klein, wenn du ACKs brauchst; bläh sie nur auf, wenn das Ziel reiner Drain oder covert one-way transport ist.
* Öffentliche Messungen erreichten in diesem Modus etwa `3.7 MB/s` (`~13.3 GB/h`) an Opfertraffic.

## References

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
