# Side-Channel-Angriffe auf Zustellbestätigungen in E2EE-Messengern

{{#include ../banners/hacktricks-training.md}}

Zustellbestätigungen sind in modernen Ende-zu-Ende-verschlüsselten (E2EE) Messengern obligatorisch, da Clients wissen müssen, wann ein Ciphertext entschlüsselt wurde, damit sie den Ratchet-Zustand und ephemere Schlüssel verwerfen können. Der Server leitet undurchsichtige Blobs weiter, daher werden Gerätebestätigungen (doppelte Häkchen) vom Empfänger nach erfolgreicher Entschlüsselung gesendet. Die Messung der Round-Trip-Time (RTT) zwischen einer vom Angreifer ausgelösten Aktion und der zugehörigen Zustellbestätigung legt einen hochauflösenden Timing-Kanal offen, der Gerätezustand und Online-Präsenz leakt und für verdecktes DoS missbraucht werden kann. Multi-Device-Deployments mit „Client-Fanout“ verstärken den leak, da jedes registrierte Gerät die Probe entschlüsselt und seine eigene Bestätigung zurücksendet.<sup>[[1]](#references)</sup>

## Quellen von Zustellbestätigungen vs. für Benutzer sichtbare Signale

Wähle Nachrichtentypen, die immer eine Zustellbestätigung auslösen, aber beim Opfer keine UI-Artefakte anzeigen. Die folgende Tabelle fasst das empirisch bestätigte Verhalten zusammen:<sup>[[1]](#references)</sup>

| Messenger | Aktion | Zustellbestätigung | Benachrichtigung des Opfers | Hinweise |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Textnachricht | ● | ● | Immer auffällig → nur zum Bootstrapping des Zustands nützlich. |
| | Reaktion | ● | ◐ (nur bei Reaktion auf eine Nachricht des Opfers) | Selbstreaktionen und Entfernungen bleiben unauffällig. |
| | Bearbeiten | ● | Plattformabhängiger stiller Push | Bearbeitungsfenster ≈20 Min.; Bestätigung erfolgt auch nach Ablauf. |
| | Für alle löschen | ● | ○ | Die UI erlaubt etwa 60 h, spätere Pakete werden jedoch weiterhin bestätigt. |
| **Signal** | Textnachricht | ● | ● | Dieselben Einschränkungen wie bei WhatsApp. |
| | Reaktion | ● | ◐ | Selbstreaktionen sind für das Opfer unsichtbar. |
| | Bearbeiten/Löschen | ● | ○ | Der Server erzwingt ein Fenster von etwa 48 h und erlaubt bis zu 10 Bearbeitungen, spätere Pakete werden jedoch weiterhin bestätigt. |
| **Threema** | Textnachricht | ● | ● | Multi-Device-Bestätigungen werden aggregiert, daher wird pro Probe nur eine RTT sichtbar. |

Legende: ● = immer, ◐ = bedingt, ○ = nie. Plattformabhängiges UI-Verhalten wird inline vermerkt. Deaktiviere bei Bedarf Lesebestätigungen, Zustellbestätigungen können in WhatsApp oder Signal jedoch nicht deaktiviert werden.<sup>[[1]](#references)</sup>

## Ziele und Modelle des Angreifers

* **G1 – Device-Fingerprinting:** Zähle, wie viele Bestätigungen pro Probe eintreffen, gruppiere RTTs, um OS/Client zu bestimmen (Android vs. iOS vs. Desktop), und beobachte Online-/Offline-Übergänge.
* **G2 – Verhaltensüberwachung:** Behandle die hochfrequente RTT-Serie (≈1 Hz ist stabil) als Zeitreihe und leite Bildschirm an/aus, App im Vorder-/Hintergrund, Pendelzeiten vs. Arbeitszeiten usw. ab.
* **G3 – Ressourcenerschöpfung:** Halte die Funkmodule/CPUs jedes Opfergeräts durch das Senden endloser stiller Probes wach, entlade Akku und Datenvolumen und verschlechtere die Qualität von Videoanrufen.<sup>[[1]](#references)</sup>

Zwei Threat Actors reichen aus, um die Angriffsfläche zu beschreiben:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Teilt bereits einen Chat mit dem Opfer und missbraucht Selbstreaktionen, das Entfernen von Reaktionen oder wiederholte Bearbeitungen/Löschungen, die an bestehende Nachrichten-IDs gebunden sind.
2. **Spooky stranger:** Registriert ein Burner-Konto und sendet Reaktionen, die auf Nachrichten-IDs verweisen, die in der lokalen Unterhaltung nie existiert haben; WhatsApp und Signal entschlüsseln und bestätigen sie trotzdem, obwohl die UI die Zustandsänderung verwirft. Daher ist keine vorherige Unterhaltung erforderlich.

## Tooling für den Zugriff auf Rohprotokolle

Verwende Clients, die ausreichend Zugriff auf das zugrunde liegende E2EE-Protokoll bieten, um unterstützte Pakete außerhalb von UI-Einschränkungen zu erstellen und präzise Zeitstempel zu protokollieren; beliebige Nachrichten-IDs müssen für jede Implementierung geprüft werden:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp-Web-Multi-Device-API) dokumentiert das Senden und Empfangen von Zustellbestätigungen; [Cobalt](https://github.com/Auties00/Cobalt) (inoffizielle Java/Kotlin-Web- und Mobile-API) dokumentiert Nachrichtenoperationen wie Reagieren, Bearbeiten und Löschen. Verwende die dokumentierten APIs, anstatt davon auszugehen, dass jeder interne Frame offengelegt wird.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) stellt CLI-, JSON-RPC- und D-Bus-Schnittstellen bereit, während [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) eine Java-Bibliothek für die Kommunikation mit Signal ist.<sup>[[5]](#references)[[7]](#references)</sup> Die aktuelle Syntax von `signal-cli` verwendet `sendReaction RECIPIENT --target-author --target-timestamp`; lasse `receive` oder `daemon` laufen, damit Protokollupdates weiterhin verarbeitet werden.<sup>[[6]](#references)</sup> Beispiel für das Umschalten einer Selbstreaktion:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Messungen aus dem Paper Careless Whisper ergaben, dass Zustellbestätigungen geräteübergreifend synchronisiert werden, sodass selbst bei einem Multi-Device-Setup nur eine Bestätigung pro Nachricht offengelegt wird.<sup>[[1]](#references)</sup>
* **Turnkey-PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) enthält WhatsApp-/Signal-Backends, verwendet standardmäßig stille Löschprobes und kennzeichnet `active` vs. `standby` mit einem gleitenden Median-Schwellenwert (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ist eine schlankere, auf WhatsApp ausgerichtete CLI mit `--delay`, `--concurrent`, CSV-/Prometheus-Exportern und Grafana-kompatibler Ausgabe.<sup>[[9]](#references)</sup> Betrachte beide eher als Reconnaissance-Hilfsmittel denn als Protokollreferenzen; entscheidend ist, wie wenig Code erforderlich ist, sobald Zugriff auf den Roh-Client besteht.

Wenn kein eigenes Tooling verfügbar ist, können offizielle Clients oder Browser-Developer-Tools weiterhin stille Aktionen auslösen und das Timing des verschlüsselten Datenverkehrs offenlegen; Raw APIs entfernen UI-Verzögerungen und ermöglichen ungültige Operationen.<sup>[[1]](#references)</sup>

## Creepy companion: stille Sampling-Schleife

1. Wähle eine beliebige historische Nachricht, die du im Chat verfasst hast, damit das Opfer keine Änderung von „Reaktions“-Ballons sieht.
2. Wechsle zwischen einem sichtbaren Emoji und einem leeren Reaktions-Payload (in WhatsApp-Protobufs als `""` oder in signal-cli als `--remove` codiert). Jede Übertragung erzeugt trotz fehlender UI-Änderung für das Opfer eine Gerätebestätigung.
3. Erfasse den Sendezeitpunkt und den Eingang jeder Zustellbestätigung mit Zeitstempel. Eine 1-Hz-Schleife wie die folgende liefert unbegrenzt RTT-Traces pro Gerät:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Da WhatsApp/Signal unbegrenzte Aktualisierungen von Reaktionen akzeptieren, muss der Angreifer weder neue Chat-Inhalte posten noch sich um Bearbeitungsfenster sorgen.<sup>[[1]](#references)</sup>

## Spooky stranger: beliebige Telefonnummern prüfen

1. Registriere ein neues WhatsApp-/Signal-Konto und rufe die öffentlichen Identitätsschlüssel für die Zielnummer ab (dies geschieht automatisch während des Session-Setups).
2. Erstelle ein Reaktionspaket, das auf eine zufällige `message_id` verweist, die keine der beiden Parteien jemals gesehen hat; das Paper berichtet, dass sowohl WhatsApp als auch Signal solche Reaktionen akzeptieren und weiterhin Zustellbestätigungen erzeugen.<sup>[[1]](#references)</sup>
3. Sende das Paket, obwohl kein Thread existiert. Die Geräte des Opfers entschlüsseln es, finden keine passende Basismeldung, verwerfen die Zustandsänderung, bestätigen den eingehenden Ciphertext jedoch weiterhin und senden Gerätebestätigungen an den Angreifer zurück.
4. Wiederhole dies kontinuierlich, um RTT-Serien ohne vorherige Unterhaltung oder sichtbare Benachrichtigung aufzubauen.<sup>[[1]](#references)</sup>

Wenn du zuerst herausfinden musst, welche Nummern registriert sind, oder Gerätebestände in großem Maßstab vorbereiten möchtest, kombiniere dies mit [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), anstatt zufällige E.164-Bereiche manuell zu erraten.

Veröffentlichte Arbeiten zu Contact Discovery zeigten, warum dies operativ relevant ist: Mit genauen Telefonpräfix-Tabellen und moderaten Ressourcen konnten Forscher etwa `10%` der US-Mobilfunknummern auf WhatsApp und `100%` auf Signal abfragen, bevor sie zu gezielten Probes übergingen.<sup>[[11]](#references)</sup> In der Praxis hält das Vorfiltern aktiver Konten das Budget für stille Probes auf Nummern konzentriert, die Pakete tatsächlich entschlüsseln werden.

Aktuelle WhatsApp-Builds stellen außerdem `Settings -> Privacy -> Advanced -> Block unknown account messages` bereit.<sup>[[10]](#references)</sup> Betrachte dies als Durchsatzbegrenzer: Die Dokumentation des Trackers besagt, dass WhatsApp Nachrichten von unbekannten Konten bei hohem Volumen blockiert, den Schwellenwert jedoch nicht offenlegt; Reaktionsprobes werden dadurch also nicht vollständig verhindert.<sup>[[8]](#references)</sup>

## Wiederverwendung von Bearbeitungen und Löschungen als verdeckte Trigger

* **Wiederholte Löschungen:** Nachdem eine Nachricht einmal für alle gelöscht wurde, haben weitere Löschpakete mit derselben `message_id` keinen UI-Effekt, doch jedes Gerät entschlüsselt und bestätigt sie weiterhin.
* **Operationen außerhalb des Zeitfensters:** WhatsApp erzwingt in der UI ein Fenster von etwa 60 h zum Löschen bzw. 20 min zum Bearbeiten; Signal erzwingt etwa 48 h. Erstellte Protokollnachrichten außerhalb dieser Zeitfenster werden auf dem Gerät des Opfers still ignoriert, ihre Bestätigungen werden jedoch übertragen. Angreifer können daher noch lange nach Ende der Unterhaltung unbegrenzt prüfen.
* **Ungültige Payloads:** Das Paper berichtet, dass ungültige Nachrichten weiterhin bestätigt werden können; das genaue Verhalten bei fehlerhaften Bodies oder bereinigten IDs hängt von der Implementierung ab und sollte vor einer Nutzung getestet werden.<sup>[[1]](#references)</sup>

## Multi-Device-Verstärkung und Fingerprinting

* Auf WhatsApp und Signal entschlüsselt jedes verbundene Gerät (Telefon, Desktop-App, Browser-Begleiter) die Probe unabhängig und sendet seine eigene Bestätigung zurück. Das Zählen der Bestätigungen pro Probe legt die genaue Geräteanzahl offen.<sup>[[1]](#references)</sup>
* Wenn ein Gerät offline ist, wird seine Bestätigung in eine Warteschlange gestellt und bei der Wiederverbindung gesendet. Lücken leaken daher Online-/Offline-Zyklen und sogar Pendelzeiten (z. B. bleiben Desktop-Bestätigungen während einer Reise aus).
* RTT-Verteilungen unterscheiden sich je nach Plattform und Umgebung, da OS, Modell, Client und Netzwerkbedingungen das Timing beeinflussen. Gruppiere RTTs (z. B. per k-means anhand von Median-/Varianzmerkmalen), um sie als „Android handset“, „iOS handset“, „Electron desktop“ usw. zu kennzeichnen.
* Da der Sender vor der Verschlüsselung das Schlüsselverzeichnis des Empfängers abrufen muss, kann der Angreifer auch beobachten, wann neue Geräte gekoppelt werden; ein plötzlicher Anstieg der Geräteanzahl oder ein neuer RTT-Cluster ist ein starkes Indiz.<sup>[[1]](#references)</sup>

## Sampling-Taktung, Queueing und gebündelte Bestätigungen

* **WhatsApp-Burst-Toleranz:** Veröffentlichte Messungen ergaben, dass WhatsApp stille Reaktions-Bursts mit bis zu einer Probe alle `50 ms` ohne offensichtliches serverseitiges Queueing akzeptierte. Das ist für kurze Kalibrierungs-Bursts, schnelles Zählen von Geräten oder das schnelle Hochfahren eines Drain-Angriffs nützlich.
* **Signal-Queueing im Langzeitbetrieb:** Signal tolerierte kurze Bursts, begann jedoch bei dauerhaftem Datenverkehr mit mehreren Probes pro Sekunde, Pakete einzureihen. Für langfristiges Monitoring sollte die Taktung bei etwa `1 Hz` (oder niedriger) liegen, damit jede Bestätigung weiterhin den aktuellen Gerätezustand und nicht das Abarbeiten eines Rückstaus widerspiegelt.
* **Reconnect-Artefakte:** Wenn ein Gerät wieder online kommt, bündeln einige Clients mehrere verzögerte Bestätigungen oder senden sie schnell nacheinander. Behandle solche Bestätigungs-Bursts als Marker für einen Zustandswechsel und nicht als unabhängige RTT-Samples, da dein Clustering bzw. dein `active`-vs.-`idle`-Classifier sonst auf Reconnect-Rauschen überangepasst wird.<sup>[[1]](#references)</sup>

## Verhaltensinferenz aus RTT-Traces

1. Sample mit ≥1 Hz, um OS-Scheduling-Effekte zu erfassen. Bei WhatsApp auf iOS korrelieren RTTs <1 s stark mit aktivem Bildschirm bzw. Vordergrund, RTTs >1 s mit ausgeschaltetem Bildschirm bzw. Hintergrund-Drosselung.
2. Erstelle einfache Classifier (Schwellwert oder Zwei-Cluster-k-means), die jede RTT als „active“ oder „idle“ kennzeichnen. Aggregiere die Kennzeichnungen zu Sequenzen, um Schlafenszeiten, Pendelzeiten, Arbeitszeiten oder die Aktivität des Desktop-Begleiters abzuleiten.
3. Korreliere gleichzeitige Probes für jedes Gerät, um zu erkennen, wann Benutzer vom Mobilgerät zum Desktop wechseln, wann Begleitgeräte offline gehen und ob die App durch Push oder einen persistenten Socket rate-limited wird.
4. Vermeide in realen Netzwerken einen einzelnen fest codierten `1 s`-Schwellwert. Initialisiere jedes Gerät mit einem kurzen Warm-up-Fenster und führe eine gleitende Baseline, beispielsweise verwendet der device-activity-tracker-PoC `threshold = 0.9 * median RTT`, damit Wi-Fi-/Mobilfunk-Schwankungen deinen Classifier nicht unbrauchbar machen.<sup>[[1]](#references)[[8]](#references)</sup>

## Standortinferenz aus der Zustellungs-RTT

Dieselbe Timing-Primitiv kann verwendet werden, um abzuleiten, wo sich der Empfänger befindet, und nicht nur, ob er aktiv ist. Die Arbeit `Hope of Delivery` zeigte, dass das Training mit RTT-Verteilungen für bekannte Empfängerstandorte es einem Angreifer ermöglicht, den Standort des Opfers später allein anhand von Zustellbestätigungen zu klassifizieren:<sup>[[2]](#references)</sup>

* Erstelle eine Baseline für dasselbe Ziel, während es sich an mehreren bekannten Orten befindet (zu Hause, im Büro, auf dem Campus, Land A vs. Land B usw.).
* Sammle für jeden Standort viele normale Nachrichten-RTTs und extrahiere einfache Merkmale wie Median, Varianz oder Perzentil-Buckets.
* Vergleiche während des eigentlichen Angriffs die neue Probe-Serie mit den trainierten Clustern. Das Paper berichtet, dass sich sogar Orte innerhalb derselben Stadt häufig unterscheiden lassen, mit einer Genauigkeit von `>80%` bei drei Standorten.
* Dies funktioniert am besten, wenn der Angreifer die Senderumgebung kontrolliert und unter ähnlichen Netzwerkbedingungen Probes sendet, da der gemessene Pfad das Zugangsnetz des Empfängers, die Wake-up-Latenz und die Messenger-Infrastruktur umfasst.<sup>[[2]](#references)</sup>

Im Gegensatz zu den oben beschriebenen Angriffen über stille Reaktionen/Bearbeitungen/Löschungen benötigt die Standortinferenz weder ungültige Nachrichten-IDs noch verdeckte zustandsändernde Pakete. Normale Nachrichten mit regulären Zustellbestätigungen reichen aus; der Nachteil ist daher eine geringere Tarnung, aber eine breitere Anwendbarkeit über verschiedene Messenger hinweg.

## Unauffällige Ressourcenerschöpfung

Da jede stille Probe entschlüsselt und bestätigt werden muss, erzeugt das kontinuierliche Senden von Reaktionsumschaltungen, ungültigen Bearbeitungen oder „für alle löschen“-Paketen ein DoS auf Anwendungsebene:<sup>[[1]](#references)</sup>

* Zwingt Funkmodul/Modem, jede Sekunde zu senden/zu empfangen → spürbarer Akkuverbrauch, insbesondere bei inaktiven Mobilgeräten.
* Erzeugt Upstream-/Downstream-Datenverkehr, der mobile Datentarife verbraucht und mit latenzempfindlichen Funktionen wie Videoanrufen konkurrieren kann.<sup>[[1]](#references)</sup>
* Große ungültige Payloads erhöhen den Verarbeitungsaufwand, das Paper berichtet jedoch, dass die Kryptografie selbst nur einen vernachlässigbaren Anteil der Akkukosten ausmacht.<sup>[[1]](#references)</sup>
* Auf WhatsApp akzeptieren ungültige Reaktionen deutlich mehr Daten, als ein normales Emoji vermuten lässt: Veröffentlichte Messungen stellten eine serverseitige Akzeptanz von bis zu etwa `1 MB` pro Reaktion fest.
* Übergroße Reaktionen erzeugen keine zuverlässigen Zustellbestätigungen mehr, sobald der Body etwa `30 bytes` überschreitet; sie werden jedoch weiterhin weitergeleitet und vor dem Verwerfen verarbeitet. Halte Reaktions-Bodies klein, wenn du ACKs benötigst; vergrößere sie nur, wenn das Ziel reiner Drain oder ein verdeckter unidirektionaler Transport ist.
* Öffentliche Messungen erreichten in diesem Modus etwa `3.7 MB/s` (`~13.3 GB/h`) Datenverkehr beim Opfer.

## References

- [1] [Careless Whisper: Ausnutzung stiller Zustellbestätigungen zur Überwachung von Benutzern in mobilen Instant-Messengern](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extrahieren von Benutzerstandorten aus mobilen Instant-Messengern](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli-Handbuchseite](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [So blockierst du große Mengen unbekannter Nachrichten | WhatsApp-Hilfebereich](https://faq.whatsapp.com/3379690015658337)
- [11] [Alle Nummern sind US-Nummern: groß angelegter Missbrauch von Contact Discovery in mobilen Messengern](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
