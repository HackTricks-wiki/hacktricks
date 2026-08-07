# Side-Channel-Angriffe auf Zustellbestätigungen in E2EE-Messengern

{{#include ../banners/hacktricks-training.md}}

Zustellbestätigungen sind in modernen Ende-zu-Ende-verschlüsselten (E2EE) Messengern obligatorisch, da Clients wissen müssen, wann ein Ciphertext entschlüsselt wurde, damit sie Ratchet-Zustände und ephemere Schlüssel verwerfen können. Der Server leitet undurchsichtige Blobs weiter, sodass Gerätebestätigungen (doppelte Häkchen) vom Empfänger nach erfolgreicher Entschlüsselung gesendet werden. Die Messung der Round-Trip-Time (RTT) zwischen einer vom Angreifer ausgelösten Aktion und der entsprechenden Zustellbestätigung legt einen hochauflösenden Timing-Kanal offen, der Gerätezustand und Online-Präsenz leakt und für verdecktes DoS missbraucht werden kann. Multi-Device-"Client-Fanout"-Bereitstellungen verstärken den Leak, da jedes registrierte Gerät den Probe entschlüsselt und seine eigene Bestätigung zurücksendet.<sup>[[1]](#references)</sup>

## Quellen von Zustellbestätigungen vs. für Benutzer sichtbare Signale

Wähle Nachrichtentypen, die immer eine Zustellbestätigung auslösen, aber beim Opfer keine UI-Artefakte anzeigen. Die folgende Tabelle fasst das empirisch bestätigte Verhalten zusammen:<sup>[[1]](#references)</sup>

| Messenger | Aktion | Zustellbestätigung | Benachrichtigung des Opfers | Hinweise |
|-----------|--------|------------------|-----------------------------|-------|
| **WhatsApp** | Textnachricht | ● | ● | Immer auffällig → nur zum Initialisieren des Zustands nützlich. |
| | Reaktion | ● | ◐ (nur bei Reaktion auf eine Nachricht des Opfers) | Selbstreaktionen und Entfernungen bleiben unauffällig. |
| | Bearbeiten | ● | Plattformabhängiger stiller Push | Bearbeitungsfenster ≈20 Min.; auch nach Ablauf wird weiterhin bestätigt. |
| | Für alle löschen | ● | ○ | Die UI erlaubt ~60 h, spätere Pakete werden jedoch weiterhin bestätigt. |
| **Signal** | Textnachricht | ● | ● | Dieselben Einschränkungen wie bei WhatsApp. |
| | Reaktion | ● | ◐ | Selbstreaktionen sind für das Opfer unsichtbar. |
| | Bearbeiten/Löschen | ● | ○ | Der Server erzwingt ein Fenster von ~48 h und erlaubt bis zu 10 Bearbeitungen, spätere Pakete werden jedoch weiterhin bestätigt. |
| **Threema** | Textnachricht | ● | ● | Multi-Device-Bestätigungen werden aggregiert, sodass pro Probe nur eine RTT sichtbar wird. |

Legende: ● = immer, ◐ = bedingt, ○ = nie. Plattformabhängiges UI-Verhalten wird inline angegeben. Deaktiviere bei Bedarf Lesebestätigungen, Zustellbestätigungen können in WhatsApp oder Signal jedoch nicht deaktiviert werden.<sup>[[1]](#references)</sup>

## Ziele und Modelle des Angreifers

* **G1 – Geräte-Fingerprinting:** Zähle, wie viele Bestätigungen pro Probe eintreffen, gruppiere RTTs, um OS/Client zu ermitteln (Android vs. iOS vs. Desktop), und beobachte Online-/Offline-Übergänge.
* **G2 – Verhaltensüberwachung:** Behandle die hochfrequente RTT-Serie (≈1 Hz ist stabil) als Zeitreihe und leite Bildschirm ein/aus, App im Vorder-/Hintergrund, Pendelzeiten vs. Arbeitszeiten usw. ab.
* **G3 – Ressourcenerschöpfung:** Halte Funkmodule/CPUs aller Geräte des Opfers durch das Senden endloser stiller Probes aktiv, entlade Akku und Datenvolumen und verschlechtere die VoIP/RTC-Qualität.<sup>[[1]](#references)</sup>

Zwei Angreiferprofile reichen aus, um die Missbrauchsfläche zu beschreiben:<sup>[[1]](#references)</sup>

1. **Creepy companion:** teilt bereits einen Chat mit dem Opfer und missbraucht Selbstreaktionen, das Entfernen von Reaktionen oder wiederholte Bearbeitungen/Löschungen, die an vorhandene Nachrichten-IDs gebunden sind.
2. **Spooky stranger:** registriert einen Burner-Account und sendet Reaktionen, die auf Nachrichten-IDs verweisen, die in der lokalen Unterhaltung nie existierten; WhatsApp und Signal entschlüsseln und bestätigen sie trotzdem, obwohl die UI die Zustandsänderung verwirft, sodass keine vorherige Unterhaltung erforderlich ist.

## Tooling für den direkten Zugriff auf das Protokoll

Verwende Clients, die das zugrunde liegende E2EE-Protokoll offenlegen, damit du Pakete außerhalb von UI-Einschränkungen erstellen, beliebige `message_id`s angeben und präzise Zeitstempel protokollieren kannst:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) oder [Cobalt](https://github.com/Auties00/Cobalt) (für Mobilgeräte ausgelegt) ermöglichen das Senden roher `ReactionMessage`-, `ProtocolMessage`- (Bearbeiten/Löschen) und `Receipt`-Frames, während der Double-Ratchet-Zustand synchron bleibt.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) in Kombination mit [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) stellt jeden Nachrichtentyp über CLI/API bereit.<sup>[[5]](#references)[[7]](#references)</sup> Die aktuelle `signal-cli`-Syntax verwendet `sendReaction RECIPIENT --target-author --target-timestamp`; lasse `receive` oder `daemon` laufen, damit Zustellbestätigungen tatsächlich gesammelt werden.<sup>[[6]](#references)</sup> Beispiel für das Umschalten einer Selbstreaktion:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Der Quellcode des Android-Clients dokumentiert, wie Zustellbestätigungen vor dem Verlassen des Geräts zusammengeführt werden, und erklärt, warum der Side-Channel dort nur eine vernachlässigbare Bandbreite besitzt.<sup>[[1]](#references)</sup>
* **Turnkey-PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) enthält WhatsApp-/Signal-Backends, verwendet standardmäßig stille Lösch-Probes und kennzeichnet `active` vs. `standby` mit einem gleitenden Median-Schwellenwert (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ist eine schlankere, primär auf WhatsApp ausgerichtete CLI mit `--delay`, `--concurrent`, CSV-/Prometheus-Exportern und Grafana-kompatibler Ausgabe.<sup>[[9]](#references)</sup> Betrachte beide eher als Reconnaissance-Helfer denn als Protokollreferenzen; entscheidend ist, wie wenig Code nach vorhandenem Zugriff auf den Raw Client erforderlich ist.

Wenn kein eigenes Tooling verfügbar ist, kannst du stille Aktionen weiterhin über WhatsApp Web oder Signal Desktop auslösen und den verschlüsselten Websocket-/WebRTC-Kanal sniffen. Raw APIs entfernen jedoch UI-Verzögerungen und erlauben ungültige Operationen.

## Creepy companion: stiller Sampling-Loop

1. Wähle eine beliebige historische Nachricht, die du im Chat verfasst hast, damit das Opfer keine Änderung von "Reaktions"-Bannern sieht.
2. Wechsle zwischen einem sichtbaren Emoji und einem leeren Reaktions-Payload (in WhatsApp-Protobufs als `""` oder in signal-cli als `--remove` kodiert). Jede Übertragung erzeugt trotz fehlender UI-Änderung für das Opfer einen Geräte-Ack.
3. Erfasse den Sendezeitpunkt und den Eingang jeder Zustellbestätigung. Ein 1-Hz-Loop wie der folgende liefert unbegrenzt RTT-Spuren pro Gerät:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Da WhatsApp/Signal unbegrenzte Reaktionsaktualisierungen akzeptieren, muss der Angreifer keine neuen Chat-Inhalte posten und sich keine Gedanken über Bearbeitungsfenster machen.<sup>[[1]](#references)</sup>

## Spooky stranger: Beliebige Telefonnummern sondieren

1. Registriere ein neues WhatsApp-/Signal-Konto und rufe die öffentlichen Identitätsschlüssel der Zielnummer ab (dies geschieht automatisch während der Sitzungseinrichtung).
2. Erstelle ein Reaktions-/Bearbeitungs-/Löschpaket, das auf eine zufällige `message_id` verweist, die keine der beiden Parteien jemals gesehen hat (WhatsApp akzeptiert beliebige `key.id`-GUIDs; Signal verwendet Zeitstempel in Millisekunden).
3. Sende das Paket, obwohl kein Thread existiert. Die Geräte des Opfers entschlüsseln es, finden keine passende Basismeldung, verwerfen die Zustandsänderung, bestätigen jedoch weiterhin den eingehenden Ciphertext und senden Gerätebestätigungen an den Angreifer zurück.
4. Wiederhole dies kontinuierlich, um RTT-Serien zu erstellen, ohne jemals in der Chatliste des Opfers zu erscheinen.<sup>[[1]](#references)</sup>

Wenn du zunächst herausfinden musst, welche Nummern registriert sind, oder Gerätebestände in großem Maßstab vorab erfassen möchtest, kombiniere dies mit [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), anstatt zufällige E.164-Bereiche von Hand zu erraten.

Veröffentlichte Arbeiten zu Contact Discovery zeigten, warum dies praktisch relevant ist: Mit genauen Telefonpräfix-Tabellen und moderaten Ressourcen konnten Forscher ungefähr `10%` der US-Mobilfunknummern auf WhatsApp und `100%` auf Signal abfragen, bevor sie mit gezieltem Probing fortfuhren.<sup>[[11]](#references)</sup> In der Praxis hält eine Vorfilterung aktiver Konten das Budget für Silent Probes auf Nummern konzentriert, die Pakete tatsächlich entschlüsseln werden.

Aktuelle WhatsApp-Builds stellen außerdem `Settings -> Privacy -> Advanced -> Block unknown account messages` bereit.<sup>[[10]](#references)</sup> Betrachte dies als Durchsatzbegrenzer, nicht als Lösung: Es beeinträchtigt hauptsächlich anhaltendes Flooding ausschließlich durch Fremde und ist irrelevant, sobald du bereits ein bekannter Kontakt bist.

## Wiederverwendung von Bearbeitungen und Löschungen als verdeckte Trigger

* **Wiederholte Löschungen:** Nachdem eine Nachricht einmal für alle gelöscht wurde, haben weitere Löschpakete mit derselben `message_id` keinen UI-Effekt, aber jedes Gerät entschlüsselt und bestätigt sie weiterhin.
* **Operationen außerhalb des Zeitfensters:** WhatsApp erzwingt in der UI ein Löschfenster von ~60 h und ein Bearbeitungsfenster von ~20 min.; Signal erzwingt ~48 h. Erstellte Protokollnachrichten außerhalb dieser Fenster werden auf dem Gerät des Opfers stillschweigend ignoriert, Bestätigungen werden jedoch übertragen, sodass Angreifer noch lange nach dem Ende der Unterhaltung unbegrenzt sondieren können.
* **Ungültige Payloads:** Fehlerhafte Bearbeitungstexte oder Löschungen, die auf bereits bereinigte Nachrichten verweisen, zeigen dasselbe Verhalten – Entschlüsselung plus Bestätigung, ohne für Benutzer sichtbare Artefakte.<sup>[[1]](#references)</sup>

## Multi-Device-Verstärkung und Fingerprinting

* Jedes verbundene Gerät (Telefon, Desktop-App, Browser-Begleiter) entschlüsselt den Probe unabhängig und sendet seinen eigenen Ack zurück. Das Zählen der Bestätigungen pro Probe zeigt die genaue Geräteanzahl.
* Ist ein Gerät offline, wird seine Bestätigung in die Warteschlange gestellt und bei der erneuten Verbindung gesendet. Lücken leaken daher Online-/Offline-Zyklen und sogar Pendelzeiten (z. B. Desktop-Bestätigungen bleiben während der Reise aus).
* RTT-Verteilungen unterscheiden sich aufgrund von OS-Energiemanagement und Push-Wakeups je nach Plattform. Gruppiere RTTs (z. B. mit k-means anhand von Median-/Varianzmerkmalen), um sie als „Android handset“, „iOS handset“, „Electron desktop“ usw. zu kennzeichnen.
* Da der Sender vor der Verschlüsselung das Schlüsselverzeichnis des Empfängers abrufen muss, kann der Angreifer auch beobachten, wann neue Geräte gekoppelt werden. Ein plötzlicher Anstieg der Geräteanzahl oder ein neuer RTT-Cluster ist ein starkes Indiz.<sup>[[1]](#references)</sup>

## Sampling-Takt, Warteschlangen und gestapelte Bestätigungen

* **WhatsApp-Burst-Toleranz:** Veröffentlichte Messungen ergaben, dass WhatsApp stille Reaktions-Bursts mit bis zu einer Probe alle `50 ms` ohne offensichtliche serverseitige Warteschlangenbildung akzeptierte. Das ist für kurze Kalibrierungs-Bursts, schnelles Zählen von Geräten oder ein schnelles Hochfahren eines Drain-Angriffs nützlich.
* **Signal-Warteschlangenbildung im Langzeitbetrieb:** Signal tolerierte kurze Bursts, begann aber bei anhaltendem Traffic mit mehreren Probes pro Sekunde mit dem Einreihen in Warteschlangen. Für langfristiges Monitoring sollte der Takt bei etwa `1 Hz` (oder darunter) gehalten werden, damit jede Bestätigung weiterhin den aktuellen Gerätezustand und nicht den Abbau eines Rückstaus widerspiegelt.
* **Reconnect-Artefakte:** Wenn ein Gerät wieder online kommt, bündeln manche Clients mehrere verzögerte Bestätigungen oder senden sie schnell hintereinander. Behandle solche Bestätigungs-Bursts als Marker eines Zustandsübergangs und nicht als unabhängige RTT-Samples, da dein Clustering bzw. dein `active`-vs.-`idle`-Classifier sonst auf Reconnect-Rauschen überfitten würde.<sup>[[1]](#references)</sup>

## Verhaltensinferenz aus RTT-Spuren

1. Sample mit ≥1 Hz, um OS-Scheduling-Effekte zu erfassen. Bei WhatsApp unter iOS korrelieren RTTs von <1 s stark mit eingeschaltetem Bildschirm bzw. Vordergrundbetrieb, während >1 s mit ausgeschaltetem Bildschirm bzw. Drosselung im Hintergrund korrelieren.
2. Erstelle einfache Classifier (Schwellwertverfahren oder Zwei-Cluster-k-means), die jede RTT als "active" oder "idle" kennzeichnen. Fasse die Kennzeichnungen zu Sequenzen zusammen, um Schlafenszeiten, Pendelzeiten, Arbeitszeiten oder die Aktivität des Desktop-Begleiters abzuleiten.
3. Korrelieren simultane Probes zu jedem Gerät, um zu erkennen, wann Benutzer vom Mobilgerät auf den Desktop wechseln, wann Begleiter offline gehen und ob die App durch Push oder einen persistenten Socket rate-limited wird.
4. Vermeide in realen Netzwerken einen einzigen fest codierten Schwellenwert von `1 s`. Initialisiere jedes Gerät mit einem kurzen Warm-up-Fenster und verwende eine gleitende Baseline (zum Beispiel `threshold = 0.9 * median RTT`), damit Wi-Fi-/Mobilfunk-Schwankungen deinen Classifier nicht unbrauchbar machen.<sup>[[1]](#references)</sup>

## Standortinferenz anhand der Zustell-RTT

Dasselbe Timing-Primitiv kann verwendet werden, um zu ermitteln, wo sich der Empfänger befindet, nicht nur, ob er aktiv ist. Die Arbeit `Hope of Delivery` zeigte, dass das Training mit RTT-Verteilungen für bekannte Empfängerstandorte es einem Angreifer später ermöglicht, den Standort des Opfers allein anhand von Zustellbestätigungen zu klassifizieren:<sup>[[2]](#references)</sup>

* Erstelle eine Baseline für dasselbe Ziel, während es sich an mehreren bekannten Orten befindet (zu Hause, im Büro, auf dem Campus, Land A vs. Land B usw.).
* Sammle für jeden Standort viele normale Nachrichten-RTTs und extrahiere einfache Merkmale wie Median, Varianz oder Perzentil-Buckets.
* Vergleiche während des eigentlichen Angriffs die neue Probeserie mit den trainierten Clustern. Das Paper berichtet, dass sich selbst Orte innerhalb derselben Stadt häufig unterscheiden lassen, mit einer Genauigkeit von `>80%` bei drei Standorten.
* Dies funktioniert am besten, wenn der Angreifer die Senderumgebung kontrolliert und unter ähnlichen Netzwerkbedingungen sondiert, da der gemessene Pfad das Zugangsnetz des Empfängers, die Wake-up-Latenz und die Messenger-Infrastruktur umfasst.<sup>[[2]](#references)</sup>

Im Gegensatz zu den oben beschriebenen Angriffen mit stillen Reaktionen/Bearbeitungen/Löschungen erfordert die Standortinferenz keine ungültigen Nachrichten-IDs oder verdeckten zustandsändernden Pakete. Normale Nachrichten mit gewöhnlichen Zustellbestätigungen reichen aus. Der Nachteil ist daher eine geringere Tarnung, dafür eine breitere Anwendbarkeit über verschiedene Messenger hinweg.

## Verdeckte Ressourcenerschöpfung

Da jeder stille Probe entschlüsselt und bestätigt werden muss, erzeugt das kontinuierliche Senden von Reaktionsumschaltungen, ungültigen Bearbeitungen oder "für alle löschen"-Paketen ein DoS auf Anwendungsebene:<sup>[[1]](#references)</sup>

* Zwingt Funkmodul/Modem dazu, jede Sekunde zu senden/empfangen → bemerkbarer Akkuverbrauch, insbesondere bei inaktiven Mobilgeräten.
* Erzeugt nicht abgerechneten Upstream-/Downstream-Traffic, der mobile Datenvolumen verbraucht und sich dabei in TLS-/WebSocket-Rauschen einfügt.
* Belegt Crypto-Threads und führt zu Jitter bei latenzempfindlichen Funktionen (VoIP, Videoanrufe), obwohl der Benutzer nie Benachrichtigungen sieht.
* Bei WhatsApp akzeptieren ungültige Reaktionen deutlich mehr Daten, als ein normales Emoji vermuten lässt: Veröffentlichte Messungen ergaben eine serverseitige Annahme von bis zu ungefähr `1 MB` pro Reaktion.
* Übergroße Reaktionen erzeugen keine zuverlässigen Zustellbestätigungen mehr, sobald der Body ungefähr `30 Bytes` überschreitet. Sie werden jedoch weiterhin weitergeleitet und verarbeitet, bevor sie verworfen werden. Halte Reaktions-Bodies klein, wenn du ACKs benötigst; vergrößere sie nur, wenn das Ziel reines Drain oder verdeckter unidirektionaler Transport ist.
* Öffentliche Messungen erreichten in diesem Modus ungefähr `3.7 MB/s` (`~13.3 GB/h`) Traffic auf Seiten des Opfers.

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
