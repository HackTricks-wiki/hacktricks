# Side-Channel-Angriffe über Zustellbestätigungen in E2EE-Messengern

Zustellbestätigungen sind in modernen Ende-zu-Ende-verschlüsselten (E2EE) Messengern obligatorisch, da Clients wissen müssen, wann ein Ciphertext entschlüsselt wurde, damit sie den Ratchet-Zustand und ephemere Schlüssel verwerfen können. Der Server leitet undurchsichtige Blobs weiter, daher werden Gerätebestätigungen (doppelte Häkchen) vom Empfänger nach erfolgreicher Entschlüsselung ausgegeben. Die Messung der Round-Trip-Time (RTT) zwischen einer vom Angreifer ausgelösten Aktion und der entsprechenden Zustellbestätigung legt einen hochauflösenden Timing-Kanal offen, der Gerätezustand und Online-Präsenz leakt und für verdeckte DoS-Angriffe missbraucht werden kann. Multi-Device-Deployments mit „Client-Fanout“ verstärken den leak, da jedes registrierte Gerät den Probe entschlüsselt und seine eigene Bestätigung zurückgibt.<sup>[[1]](#references)</sup>

## Quellen für Zustellbestätigungen vs. für Benutzer sichtbare Signale

Wähle Nachrichtentypen, die immer eine Zustellbestätigung ausgeben, aber beim Opfer keine UI-Artefakte anzeigen. Die folgende Tabelle fasst das empirisch bestätigte Verhalten zusammen:<sup>[[1]](#references)</sup>

| Messenger | Aktion | Zustellbestätigung | Benachrichtigung des Opfers | Hinweise |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Textnachricht | ● | ● | Immer auffällig → nur zum Initialisieren des Zustands nützlich. |
| | Reaktion | ● | ◐ (nur bei Reaktion auf eine Nachricht des Opfers) | Selbstreaktionen und Entfernungen bleiben unbemerkt. |
| | Bearbeiten | ● | Plattformabhängiger stiller Push | Bearbeitungsfenster ≈20 Min.; wird auch nach Ablauf bestätigt. |
| | Für alle löschen | ● | ○ | Die UI erlaubt ~60 h, spätere Pakete werden jedoch weiterhin bestätigt. |
| **Signal** | Textnachricht | ● | ● | Dieselben Einschränkungen wie bei WhatsApp. |
| | Reaktion | ● | ◐ | Selbstreaktionen sind für das Opfer unsichtbar. |
| | Bearbeiten/Löschen | ● | ○ | Der Server erzwingt ein Fenster von ~48 h und erlaubt bis zu 10 Bearbeitungen, bestätigt jedoch auch verspätete Pakete. |
| **Threema** | Textnachricht | ● | ● | Multi-Device-Bestätigungen werden aggregiert, daher wird pro Probe nur eine RTT sichtbar. |

Legende: ● = immer, ◐ = bedingt, ○ = nie. Plattformabhängiges UI-Verhalten ist inline angegeben. Deaktiviere bei Bedarf Lesebestätigungen, Zustellbestätigungen können in WhatsApp oder Signal jedoch nicht deaktiviert werden.<sup>[[1]](#references)</sup>

## Ziele und Modelle des Angreifers

* **G1 – Geräte-Fingerprinting:** Zähle, wie viele Bestätigungen pro Probe eintreffen, gruppiere RTTs, um Betriebssystem/Client zu erkennen (Android vs. iOS vs. Desktop), und beobachte Online-/Offline-Übergänge.
* **G2 – Verhaltensüberwachung:** Behandle die hochfrequente RTT-Serie (≈1 Hz ist stabil) als Zeitreihe und leite daraus Bildschirm ein/aus, App im Vorder-/Hintergrund, Pendelzeiten vs. Arbeitszeiten usw. ab.
* **G3 – Ressourcenerschöpfung:** Halte die Funkmodule/CPUs jedes Opfergeräts durch das Senden endloser stiller Probes wach, entlade Akku und verbrauche Datenvolumen und verschlechtere die Qualität von Videoanrufen.<sup>[[1]](#references)</sup>

Zwei Angreiferprofile reichen aus, um die Missbrauchsfläche zu beschreiben:<sup>[[1]](#references)</sup>

1. **Creepy Companion:** Teilt bereits einen Chat mit dem Opfer und missbraucht Selbstreaktionen, das Entfernen von Reaktionen oder wiederholtes Bearbeiten/Löschen, die an vorhandene Nachrichten-IDs gebunden sind.
2. **Spooky Stranger:** Registriert ein Burner-Konto und sendet Reaktionen, die auf Nachrichten-IDs verweisen, die in der lokalen Unterhaltung nie existierten; WhatsApp und Signal entschlüsseln und bestätigen diese dennoch, obwohl die UI die Zustandsänderung verwirft. Eine vorherige Unterhaltung ist daher nicht erforderlich.

## Tooling für den direkten Zugriff auf das Protokoll

Verlasse dich auf Clients, die genügend Zugriff auf das zugrunde liegende E2EE-Protokoll bieten, um unterstützte Pakete außerhalb von UI-Einschränkungen zu erstellen und präzise Zeitstempel zu protokollieren. Bei beliebigen Nachrichten-IDs muss jede Implementierung geprüft werden:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp-Web-Multidevice-API) dokumentiert das Senden und Empfangen von Zustellbestätigungen; [Cobalt](https://github.com/Auties00/Cobalt) (inoffizielle Java/Kotlin-Web- und Mobile-API) dokumentiert Nachrichtenoperationen wie Reagieren, Bearbeiten und Löschen. Verwende die dokumentierten APIs, statt anzunehmen, dass jeder interne Frame verfügbar ist.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) stellt CLI-, JSON-RPC- und D-Bus-Schnittstellen bereit, während [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) eine Java-Bibliothek für die Kommunikation mit Signal ist.<sup>[[5]](#references)[[7]](#references)</sup> Die aktuelle Syntax von `signal-cli` verwendet `sendReaction RECIPIENT --target-author --target-timestamp`; lasse `receive` oder `daemon` laufen, damit Protokollaktualisierungen weiterhin verarbeitet werden.<sup>[[6]](#references)</sup> Beispiel für das Umschalten einer Selbstreaktion:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Messungen im Paper Careless Whisper ergaben, dass Zustellbestätigungen geräteübergreifend synchronisiert werden, sodass selbst in einem Multi-Device-Setup nur eine Bestätigung pro Nachricht offengelegt wird.<sup>[[1]](#references)</sup>
* **Turnkey-PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) enthält WhatsApp-/Signal-Backends, verwendet standardmäßig stille Lösch-Probes und kennzeichnet `active` vs. `standby` mit einem gleitenden Median-Schwellenwert (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ist eine schlankere, auf WhatsApp ausgerichtete CLI mit `--delay`, `--concurrent`, CSV-/Prometheus-Exportern und Grafana-freundlicher Ausgabe.<sup>[[9]](#references)</sup> Betrachte beide eher als Reconnaissance-Hilfsmittel denn als Protokollreferenzen. Entscheidend ist, wie wenig Code erforderlich ist, sobald direkter Client-Zugriff besteht.

Wenn kein eigenes Tooling verfügbar ist, können offizielle Clients oder Browser-Entwicklertools weiterhin stille Aktionen auslösen und das Timing des verschlüsselten Datenverkehrs offenlegen. Raw APIs entfernen UI-Verzögerungen und ermöglichen ungültige Operationen.<sup>[[1]](#references)</sup>

## Creepy Companion: stille Sampling-Schleife

1. Wähle eine beliebige historische Nachricht, die du im Chat verfasst hast, damit das Opfer keine Änderung von „Reaktions“-Bubbles sieht.
2. Wechsle zwischen einem sichtbaren Emoji und einem leeren Reaktions-Payload (in WhatsApp-Protobufs als `""` oder in signal-cli als `--remove` kodiert). Jede Übertragung erzeugt eine Gerätebestätigung, obwohl sich für das Opfer keine UI-Änderung ergibt.
3. Setze den Sendezeitpunkt und den Eingang jeder Zustellbestätigung mit einem Zeitstempel. Eine 1-Hz-Schleife wie die folgende liefert unbegrenzt RTT-Traces pro Gerät:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Da WhatsApp/Signal unbegrenzte Reaktionsaktualisierungen akzeptieren, muss der Angreifer weder neue Chat-Inhalte veröffentlichen noch Bearbeitungsfenster beachten.<sup>[[1]](#references)</sup>

## Spooky Stranger: beliebige Telefonnummern prüfen

1. Registriere ein neues WhatsApp-/Signal-Konto und rufe die öffentlichen Identitätsschlüssel der Zielnummer ab (dies geschieht automatisch während der Sitzungseinrichtung).
2. Erstelle ein Reaktionspaket, das auf eine zufällige `message_id` verweist, die keine der beiden Parteien je gesehen hat. Das Paper berichtet, dass sowohl WhatsApp als auch Signal solche Reaktionen akzeptieren und weiterhin Zustellbestätigungen erzeugen.<sup>[[1]](#references)</sup>
3. Sende das Paket, obwohl kein Thread existiert. Die Geräte des Opfers entschlüsseln es, können die Basisnachricht nicht zuordnen, verwerfen die Zustandsänderung, bestätigen jedoch weiterhin den eingehenden Ciphertext und senden Gerätebestätigungen an den Angreifer zurück.
4. Wiederhole den Vorgang kontinuierlich, um RTT-Serien ohne vorherige Unterhaltung oder sichtbare Benachrichtigung aufzubauen.<sup>[[1]](#references)</sup>

Wenn du zunächst herausfinden musst, welche Nummern registriert sind, oder Geräteinventare in großem Maßstab vorab erfassen möchtest, kombiniere dies mit [Kontaktentdeckung / Registrierungs-Oracles](../pentesting-web/registration-vulnerabilities.md), statt zufällige E.164-Bereiche manuell zu erraten.

Veröffentlichte Arbeiten zur Kontaktentdeckung zeigen, warum dies operativ relevant ist: Mit genauen Telefonvorwahltabellen und moderaten Ressourcen konnten Forscher ungefähr `10%` der US-Mobilfunknummern auf WhatsApp und `100%` auf Signal abfragen, bevor sie mit gezielten Probes fortfuhren.<sup>[[11]](#references)</sup> In der Praxis hält die Vorfilterung aktiver Konten das Budget für stille Probes auf Nummern konzentriert, die Pakete tatsächlich entschlüsseln werden.

Aktuelle WhatsApp-Builds bieten außerdem `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Betrachte dies als Durchsatzbegrenzer: Die Dokumentation des Trackers besagt, dass WhatsApp Nachrichten von unbekannten Konten in hoher Anzahl blockiert, den Schwellenwert jedoch nicht offenlegt. Dadurch werden Reaktions-Probes nicht vollständig verhindert.<sup>[[8]](#references)</sup>

## Wiederverwendung von Bearbeitungen und Löschungen als verdeckte Auslöser

* **Wiederholtes Löschen:** Nachdem eine Nachricht einmal für alle gelöscht wurde, haben weitere Löschpakete mit derselben `message_id` keinen UI-Effekt, werden von jedem Gerät jedoch weiterhin entschlüsselt und bestätigt.
* **Operationen außerhalb des Zeitfensters:** WhatsApp erzwingt in der UI ein Löschfenster von ~60 h und ein Bearbeitungsfenster von ~20 min.; Signal erzwingt ~48 h. Erstellte Protokollnachrichten außerhalb dieser Fenster werden auf dem Gerät des Opfers stillschweigend ignoriert, Zustellbestätigungen werden jedoch übertragen. Angreifer können daher noch lange nach Ende der Unterhaltung unbegrenzt prüfen.
* **Ungültige Payloads:** Das Paper berichtet, dass ungültige Nachrichten weiterhin bestätigt werden können. Das genaue Verhalten bei fehlerhaften Bodies oder bereinigten IDs hängt von der Implementierung ab; teste dies, bevor du dich darauf verlässt.<sup>[[1]](#references)</sup>

## Multi-Device-Verstärkung & Fingerprinting

* Auf WhatsApp und Signal entschlüsselt jedes verknüpfte Gerät (Telefon, Desktop-App, Browser-Begleiter) die Probe unabhängig und gibt eine eigene Bestätigung zurück. Das Zählen der Bestätigungen pro Probe legt die exakte Geräteanzahl offen.<sup>[[1]](#references)</sup>
* Wenn ein Gerät offline ist, wird seine Bestätigung in eine Warteschlange eingereiht und bei der Wiederverbindung ausgegeben. Lücken leaken daher Online-/Offline-Zyklen und sogar Pendelpläne (z. B. stoppen Desktop-Bestätigungen während der Reise).
* RTT-Verteilungen unterscheiden sich je nach Plattform und Umgebung, da Betriebssystem, Modell, Client und Netzwerkbedingungen das Timing beeinflussen. Gruppiere RTTs (z. B. mit k-Means auf Median-/Varianzmerkmalen), um sie als „Android-Handset“, „iOS-Handset“, „Electron-Desktop“ usw. zu kennzeichnen.
* Da der Sender vor der Verschlüsselung das Schlüsselverzeichnis des Empfängers abrufen muss, kann der Angreifer auch beobachten, wann neue Geräte gekoppelt werden. Ein plötzlicher Anstieg der Geräteanzahl oder ein neuer RTT-Cluster ist ein starkes Indiz.<sup>[[1]](#references)</sup>

## Sampling-Taktung, Warteschlangen und gebündelte Bestätigungen

* **Burst-Toleranz von WhatsApp:** Veröffentlichte Messungen ergaben, dass WhatsApp stille Reaktions-Bursts mit bis zu einer Probe alle `50 ms` ohne offensichtliche serverseitige Warteschlangen akzeptierte. Dies ist für kurze Kalibrierungs-Bursts, schnelles Zählen von Geräten oder das schnelle Hochfahren eines Drain-Angriffs nützlich.
* **Langzeit-Warteschlangen bei Signal:** Signal tolerierte kurze Bursts, begann jedoch bei dauerhaftem Datenverkehr mit mehreren Probes pro Sekunde, Pakete in eine Warteschlange einzureihen. Halte die Taktung bei langfristiger Überwachung bei etwa `1 Hz` (oder niedriger), damit jede Bestätigung weiterhin den aktuellen Gerätezustand und nicht das Leeren eines Rückstaus widerspiegelt.
* **Artefakte bei der Wiederverbindung:** Wenn ein Gerät wieder online kommt, bündeln manche Clients mehrere verzögerte Bestätigungen oder geben sie schnell nacheinander aus. Behandle diese Bestätigungs-Bursts als Marker für einen Zustandsübergang und nicht als unabhängige RTT-Samples, da dein Clustering bzw. dein `active`-vs.-`idle`-Classifier sonst auf Wiederverbindungsrauschen überangepasst wird.<sup>[[1]](#references)</sup>

## Verhaltensinferenz aus RTT-Traces

1. Sample mit ≥1 Hz, um Effekte der OS-Scheduling-Mechanismen zu erfassen. Bei WhatsApp unter iOS korrelieren RTTs von <1 s stark mit eingeschaltetem Bildschirm bzw. Vordergrundbetrieb, RTTs von >1 s mit ausgeschaltetem Bildschirm bzw. Hintergrund-Drosselung.
2. Erstelle einfache Classifier (Schwellwertverfahren oder Zwei-Cluster-k-Means), die jede RTT als „active“ oder „idle“ kennzeichnen. Aggregiere die Kennzeichnungen zu Sequenzen, um Schlafenszeiten, Pendelzeiten, Arbeitszeiten oder die Aktivität des Desktop-Begleiters abzuleiten.
3. Korreliere simultane Probes an jedes Gerät, um zu erkennen, wann Benutzer vom Mobilgerät auf den Desktop wechseln, wann Begleitgeräte offline gehen und ob die App durch Push oder einen persistenten Socket rate-limitiert wird.
4. Vermeide in realen Netzwerken einen einzelnen fest codierten Schwellwert von `1 s`. Initialisiere jedes Gerät mit einem kurzen Aufwärmfenster und führe eine gleitende Baseline (beispielsweise verwendet der device-activity-tracker-PoC `threshold = 0.9 * median RTT`), damit WLAN-/Mobilfunk-Schwankungen deinen Classifier nicht unbrauchbar machen.<sup>[[1]](#references)[[8]](#references)</sup>

## Standortinferenz aus Zustellungs-RTT

Dieselbe Timing-Grundlage kann verwendet werden, um den Aufenthaltsort des Empfängers abzuleiten, nicht nur dessen Aktivität. Die Arbeit `Hope of Delivery` zeigte, dass ein Training mit RTT-Verteilungen für bekannte Empfängerstandorte es einem Angreifer ermöglicht, den Standort des Opfers später allein anhand von Zustellbestätigungen zu klassifizieren:<sup>[[2]](#references)</sup>

* Erstelle eine Baseline für dasselbe Ziel, während es sich an mehreren bekannten Orten befindet (zu Hause, im Büro, auf dem Campus, Land A vs. Land B usw.).
* Sammle für jeden Standort viele normale Nachrichten-RTTs und extrahiere einfache Merkmale wie Median, Varianz oder Perzentil-Buckets.
* Vergleiche während des eigentlichen Angriffs die neue Probe-Serie mit den trainierten Clustern. Das Paper berichtet, dass sich sogar Orte innerhalb derselben Stadt häufig unterscheiden lassen, mit einer Genauigkeit von `>80%` bei einem Szenario mit drei Standorten.
* Dies funktioniert am besten, wenn der Angreifer die Senderumgebung kontrolliert und unter ähnlichen Netzwerkbedingungen Probes sendet, da der gemessene Pfad das Zugangsnetz des Empfängers, die Aufwecklatenz und die Messenger-Infrastruktur umfasst.<sup>[[2]](#references)</sup>

Im Gegensatz zu den oben beschriebenen Angriffen mit stillen Reaktionen/Bearbeitungen/Löschungen erfordert die Standortinferenz weder ungültige Nachrichten-IDs noch unauffällige zustandsverändernde Pakete. Normale Nachrichten mit regulären Zustellbestätigungen reichen aus. Der Kompromiss besteht daher in geringerer Tarnung, aber breiterer Anwendbarkeit über verschiedene Messenger hinweg.

## Unauffällige Ressourcenerschöpfung

Da jede stille Probe entschlüsselt und bestätigt werden muss, erzeugt das kontinuierliche Senden von Reaktionsumschaltungen, ungültigen Bearbeitungen oder „Für alle löschen“-Paketen einen DoS auf Anwendungsebene:<sup>[[1]](#references)</sup>

* Zwingt das Funkmodem dazu, jede Sekunde zu senden/empfangen → spürbarer Akkuverbrauch, insbesondere bei inaktiven Handsets.
* Erzeugt Upstream-/Downstream-Datenverkehr, der mobile Datenvolumen verbraucht und mit latenzempfindlichen Funktionen wie Videoanrufen konkurrieren kann.<sup>[[1]](#references)</sup>
* Große ungültige Payloads erhöhen den Verarbeitungsaufwand, das Paper berichtet jedoch, dass die Kryptografie selbst nur einen vernachlässigbaren Teil der Akkukosten ausmacht.<sup>[[1]](#references)</sup>
* Unter WhatsApp akzeptieren ungültige Reaktionen deutlich mehr Daten, als ein normales Emoji vermuten lässt: Veröffentlichte Messungen ergaben eine serverseitige Akzeptanz von bis zu ungefähr `1 MB` pro Reaktion.
* Übergroße Reaktionen erzeugen keine zuverlässigen Zustellbestätigungen mehr, sobald der Body ungefähr `30 Bytes` überschreitet. Sie werden jedoch weiterhin weitergeleitet und vor dem Verwerfen verarbeitet. Halte Reaktions-Bodies klein, wenn du ACKs benötigst; vergrößere sie nur, wenn das Ziel reiner Drain oder ein verdeckter unidirektionaler Transport ist.
* Öffentliche Messungen erreichten in diesem Modus ungefähr `3.7 MB/s` (`~13.3 GB/h`) Datenverkehr beim Opfer.

## References

- [1] [Careless Whisper: Ausnutzung stiller Zustellbestätigungen zur Überwachung von Benutzern in mobilen Instant Messengern](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extrahieren von Benutzerstandorten aus mobilen Instant Messengern](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli-Handbuchseite](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [So blockieren Sie eine hohe Anzahl unbekannter Nachrichten | WhatsApp-Hilfezentrum](https://faq.whatsapp.com/3379690015658337)
- [11] [Alle Nummern sind US-Nummern: groß angelegter Missbrauch der Kontaktentdeckung in mobilen Messengern](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
