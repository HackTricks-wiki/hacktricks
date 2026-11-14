# Side-Channel-Angriffe über Zustellbestätigungen in E2EE-Messengern

{{#include ../banners/hacktricks-training.md}}

Zustellbestätigungen sind in modernen Ende-zu-Ende-verschlüsselten (E2EE) Messengern obligatorisch, da Clients wissen müssen, wann ein Ciphertext entschlüsselt wurde, damit sie den Ratchet-Zustand und kurzlebige Schlüssel verwerfen können. Der Server leitet undurchsichtige Blobs weiter, sodass Gerätebestätigungen (Doppelhäkchen) vom Empfänger nach erfolgreicher Entschlüsselung gesendet werden. Die Messung der Round-Trip-Zeit (RTT) zwischen einer durch den Angreifer ausgelösten Aktion und der entsprechenden Zustellbestätigung legt einen hochauflösenden Timing-Kanal offen, der den Gerätezustand und die Online-Präsenz leakt und für verdeckte DoS-Angriffe missbraucht werden kann. Multi-Device-Bereitstellungen mit „Client-Fanout“ verstärken den Leak, da jedes registrierte Gerät den Probe entschlüsselt und eine eigene Bestätigung zurücksendet.<sup>[[1]](#references)</sup>

## Quellen für Zustellbestätigungen vs. für Benutzer sichtbare Signale

Wähle Nachrichtentypen, die immer eine Zustellbestätigung auslösen, aber beim Opfer keine UI-Artefakte anzeigen. Die folgende Tabelle fasst das empirisch bestätigte Verhalten zusammen:<sup>[[1]](#references)</sup>

| Messenger | Aktion | Zustellbestätigung | Benachrichtigung des Opfers | Hinweise |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Textnachricht | ● | ● | Immer auffällig → nur zum Ermitteln des Ausgangszustands nützlich. |
| | Reaktion | ● | ◐ (nur bei Reaktion auf eine Nachricht des Opfers) | Selbstreaktionen und deren Entfernen bleiben unbemerkt. |
| | Bearbeiten | ● | Plattformabhängiger Silent Push | Bearbeitungsfenster ≈20 Min.; Bestätigungen werden auch nach Ablauf gesendet. |
| | Für alle löschen | ● | ○ | Die UI erlaubt dies für etwa 60 h, spätere Pakete werden jedoch weiterhin bestätigt. |
| **Signal** | Textnachricht | ● | ● | Dieselben Einschränkungen wie bei WhatsApp. |
| | Reaktion | ● | ◐ | Selbstreaktionen sind für das Opfer unsichtbar. |
| | Bearbeiten/Löschen | ● | ○ | Der Server setzt ein Zeitfenster von etwa 48 h durch und erlaubt bis zu 10 Bearbeitungen, bestätigt aber auch verspätete Pakete. |
| **Threema** | Textnachricht | ● | ● | Multi-Device-Zustellbestätigungen werden zusammengefasst, sodass pro Probe nur eine RTT sichtbar wird. |

Legende: ● = immer, ◐ = bedingt, ○ = nie. Plattformabhängiges UI-Verhalten ist inline angegeben. Deaktiviere bei Bedarf Lesebestätigungen. Zustellbestätigungen lassen sich in WhatsApp oder Signal jedoch nicht deaktivieren.<sup>[[1]](#references)</sup>

## Ziele und Modelle des Angreifers

* **G1 – Geräte-Fingerprinting:** Zähle, wie viele Zustellbestätigungen pro Probe eintreffen, gruppiere RTTs, um auf Betriebssystem/Client zu schließen (Android vs. iOS vs. Desktop), und beobachte Übergänge zwischen online und offline.
* **G2 – Verhaltensüberwachung:** Behandle die hochfrequente RTT-Reihe (≈1 Hz ist stabil) als Zeitreihe und leite daraus ab, ob der Bildschirm ein- oder ausgeschaltet ist, ob die App im Vorder- oder Hintergrund läuft, ob die Person pendelt oder arbeitet usw.
* **G3 – Ressourcenerschöpfung:** Halte die Funkmodule/CPUs aller Geräte des Opfers durch endlose stille Probes aktiv, wodurch Akku und Datenvolumen verbraucht und die Qualität von Videoanrufen beeinträchtigt wird.<sup>[[1]](#references)</sup>

Zwei Bedrohungsakteure reichen aus, um die Angriffsfläche zu beschreiben:<sup>[[1]](#references)</sup>

1. **Unheimlicher Chatpartner:** Hat bereits einen Chat mit dem Opfer und missbraucht Selbstreaktionen, das Entfernen von Reaktionen oder wiederholte Bearbeitungen/Löschungen, die an bestehende Nachrichten-IDs gebunden sind.
2. **Unheimlicher Fremder:** Registriert ein Wegwerf-Konto und sendet Reaktionen, die auf Nachrichten-IDs verweisen, die in der lokalen Unterhaltung nie existiert haben. WhatsApp und Signal entschlüsseln und bestätigen diese trotzdem, obwohl die UI die Zustandsänderung verwirft; eine vorherige Unterhaltung ist daher nicht erforderlich.

## Tools für den Zugriff auf Rohprotokolle

Nutze Clients, die genügend Einblick in das zugrunde liegende E2EE-Protokoll bieten, um unterstützte Pakete außerhalb der Einschränkungen der UI zu erstellen und präzise Zeitstempel zu protokollieren. Bei beliebigen Nachrichten-IDs muss jede Implementierung einzeln geprüft werden:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp-Web-Multi-Device-API) dokumentiert das Senden und Empfangen von Zustellbestätigungen; [Cobalt](https://github.com/Auties00/Cobalt) (inoffizielle Java/Kotlin-Web- und Mobile-API) dokumentiert Nachrichtenaktionen wie Reagieren, Bearbeiten und Löschen. Nutze die dokumentierten APIs, statt davon auszugehen, dass jeder interne Frame verfügbar ist.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) bietet CLI-, JSON-RPC- und D-Bus-Schnittstellen, während [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) eine Java-Bibliothek zur Kommunikation mit Signal ist.<sup>[[5]](#references)[[7]](#references)</sup> Die aktuelle Syntax von `signal-cli` verwendet `sendReaction RECIPIENT --target-author --target-timestamp`. Lasse `receive` oder `daemon` laufen, damit Protokollaktualisierungen weiterhin verarbeitet werden.<sup>[[6]](#references)</sup> Beispiel für das Umschalten einer Selbstreaktion:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Messungen im Paper Careless Whisper ergaben, dass Zustellbestätigungen geräteübergreifend synchronisiert werden, sodass selbst bei einer Konfiguration mit mehreren Geräten nur eine Bestätigung pro Nachricht offengelegt wird.<sup>[[1]](#references)</sup>
* **Turnkey-PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) enthält WhatsApp-/Signal-Backends, verwendet standardmäßig stille Delete-Probes und kennzeichnet Geräte anhand eines rollierenden Median-Schwellenwerts (`RTT < 0.9 * median`) als `active` oder `standby`.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ist eine schlankere, primär auf WhatsApp ausgerichtete CLI mit `--delay`, `--concurrent`, CSV-/Prometheus-Exportern und Grafana-kompatibler Ausgabe.<sup>[[9]](#references)</sup> Betrachte beide als Reconnaissance-Helfer und nicht als Protokollreferenzen; entscheidend ist, wie wenig Code nötig ist, sobald direkter Clientzugriff besteht.

Wenn keine eigenen Tools verfügbar sind, können offizielle Clients oder Browser-Entwicklertools weiterhin stille Aktionen auslösen und das Timing verschlüsselten Datenverkehrs offenlegen; Raw-APIs beseitigen UI-Verzögerungen und ermöglichen ungültige Operationen.<sup>[[1]](#references)</sup>

## Unheimlicher Begleiter: stille Sampling-Schleife

1. Wähle eine beliebige ältere Nachricht, die du im Chat verfasst hast, damit das Opfer keine sich ändernden „Reaktions“-Sprechblasen sieht.
2. Wechsle zwischen einem sichtbaren Emoji und einem leeren Reaktions-Payload (in WhatsApp-Protobufs als `""` codiert oder in signal-cli mit `--remove`). Jede Übertragung führt zu einem Geräte-ACK, obwohl sich die UI für das Opfer nicht ändert.
3. Zeichne den Sendezeitpunkt und den Eingang jeder Zustellbestätigung mit einem Zeitstempel auf. Eine 1-Hz-Schleife wie die folgende liefert unbegrenzt RTT-Verläufe pro Gerät:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Da WhatsApp/Signal unbegrenzte Reaktionsaktualisierungen akzeptieren, muss der Angreifer weder neue Chat-Inhalte posten noch sich um Bearbeitungsfristen sorgen.<sup>[[1]](#references)</sup>

## Unbekannter Spuk: beliebige Telefonnummern abfragen

1. Ein neues WhatsApp-/Signal-Konto registrieren und die öffentlichen Identitätsschlüssel für die Zielnummer abrufen (geschieht automatisch während der Sitzungseinrichtung).
2. Ein Reaktionspaket erstellen, das auf eine zufällige `message_id` verweist, die keiner der beiden Beteiligten je gesehen hat. Laut dem Paper akzeptieren sowohl WhatsApp als auch Signal solche Reaktionen und erstellen trotzdem Zustellbestätigungen.<sup>[[1]](#references)</sup>
3. Das Paket senden, obwohl kein Chatverlauf existiert. Die Geräte des Opfers entschlüsseln es, finden keine passende Basisnachricht, verwerfen die Zustandsänderung, bestätigen aber trotzdem den Empfang des Chiffretexts und senden Gerätebestätigungen an den Angreifer zurück.
4. Dies kontinuierlich wiederholen, um RTT-Reihen ohne vorherige Unterhaltung oder sichtbare Benachrichtigung aufzubauen.<sup>[[1]](#references)</sup>

Wenn du zuerst herausfinden musst, welche Nummern registriert sind, oder Geräteinventare in großem Umfang vorab erfassen möchtest, kombiniere dies mit [Kontakt-Erkennung / Registrierungs-Orakeln](../pentesting-web/registration-vulnerabilities.md), statt von Hand zufällige E.164-Bereiche zu erraten.

Veröffentlichte Arbeiten zur Kontakt-Erkennung zeigten, warum dies in der Praxis wichtig ist: Mit genauen Tabellen zu Telefonvorwahlen und moderaten Ressourcen konnten Forschende ungefähr `10%` der US-Mobilnummern auf WhatsApp und `100%` auf Signal abfragen, bevor sie zu gezielten Abfragen übergingen.<sup>[[11]](#references)</sup> In der Praxis sorgt das Vorfiltern aktiver Konten dafür, dass dein Budget für stille Probes auf Nummern konzentriert bleibt, die Pakete tatsächlich entschlüsseln.

Aktuelle WhatsApp-Versionen bieten außerdem `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Betrachte dies als Durchsatzbegrenzer: Laut der Dokumentation des Trackers blockiert WhatsApp eine hohe Anzahl von Nachrichten unbekannter Konten, legt den Schwellenwert aber nicht offen. Reaktions-Probes werden dadurch also nicht vollständig verhindert.<sup>[[8]](#references)</sup>

## Bearbeitungen und Löschungen als verdeckte Auslöser wiederverwenden

* **Wiederholte Löschungen:** Nachdem eine Nachricht einmal für alle gelöscht wurde, haben weitere Löschpakete mit derselben `message_id` keine sichtbare Auswirkung, aber jedes Gerät entschlüsselt und bestätigt sie weiterhin.
* **Operationen außerhalb des Zeitfensters:** WhatsApp setzt in der UI Zeitfenster von etwa 60 Stunden für Löschungen und etwa 20 Minuten für Bearbeitungen durch; bei Signal sind es etwa 48 Stunden. Erstellte Protokollnachrichten außerhalb dieser Zeitfenster werden auf dem Gerät des Opfers stillschweigend ignoriert, aber Bestätigungen werden trotzdem gesendet. Angreifer können daher noch lange nach Ende der Unterhaltung unbegrenzt Probes durchführen.
* **Ungültige Payloads:** Laut dem Paper können ungültige Nachrichten trotzdem bestätigt werden. Das genaue Verhalten bei fehlerhaften Inhalten oder bereinigten IDs hängt von der Implementierung ab; teste es daher, bevor du dich darauf verlässt.<sup>[[1]](#references)</sup>

## Verstärkung durch mehrere Geräte und Fingerprinting

* Auf WhatsApp und Signal entschlüsselt jedes verknüpfte Gerät (Telefon, Desktop-App, Browser-Begleitgerät) den Probe unabhängig und sendet eine eigene Bestätigung zurück. Die Anzahl der Bestätigungen pro Probe verrät die genaue Anzahl der Geräte.<sup>[[1]](#references)</sup>
* Ist ein Gerät offline, wird seine Bestätigung in eine Warteschlange gestellt und beim Wiederverbinden gesendet. Lücken leaken daher Online-/Offline-Zyklen und sogar Pendelzeiten (z. B. bleiben Desktop-Bestätigungen während einer Reise aus).
* Die RTT-Verteilungen unterscheiden sich je nach Plattform und Umgebung, da Betriebssystem, Modell, Client und Netzwerkbedingungen das Timing beeinflussen. Gruppiere RTTs (z. B. mit k-means auf Median-/Varianzmerkmalen), um „Android-Mobilgerät“, „iOS-Mobilgerät“, „Electron-Desktop“ usw. zuzuordnen.
* Da der Absender vor der Verschlüsselung das Schlüsselverzeichnis des Empfängers abrufen muss, kann der Angreifer auch beobachten, wann neue Geräte verknüpft werden. Ein plötzlicher Anstieg der Geräteanzahl oder ein neuer RTT-Cluster ist ein deutlicher Hinweis.<sup>[[1]](#references)</sup>

**Fingerabdruck anhand aufgestauter Bestätigungen:** Sende mehrere Probes mit unterschiedlichen Nachrichten-IDs, während das Zielgerät offline ist. Wenn es sich wieder verbindet, korreliere die IDs in den zurückgesendeten Zustellbestätigungen und prüfe, ob sie einzeln oder gebündelt in einer Bestätigung erscheinen und ob die gebündelten IDs die Sendereihenfolge beibehalten oder umkehren. In den getesteten Clients sendeten WhatsApp für Android/iOS separate Zustellbestätigungen, während Web, Windows und macOS sie bündelten; macOS kehrte die Reihenfolge der gebündelten IDs um. Signal Desktop bündelte Bestätigungen, anders als die mobilen Clients. So lässt sich ein sich wieder verbindender Client klassifizieren, selbst wenn sich die RTT-Verteilungen überschneiden. Verwechsle Zustellbestätigungen nicht mit Lesebestätigungen, für die andere Bündelungsregeln gelten.<sup>[[1]](#references)</sup>

Eine separate WhatsApp-Probe, die **serverseitige Prekey-Auffüllungen** erfasst, ohne Nachrichten zuzustellen, findest du unter [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md).

## Abtastrate, Warteschlangen und gebündelte Bestätigungen

* **Burst-Toleranz von WhatsApp:** Veröffentlichte Messungen ergaben, dass WhatsApp Bursts stiller Reaktionen mit bis zu einer Probe alle `50 ms` ohne offensichtliche serverseitige Warteschlangenbildung akzeptierte. Das ist nützlich für kurze Kalibrierungs-Bursts, schnelles Zählen von Geräten oder das rasche Hochfahren eines Drain-Angriffs.
* **Langfristige Warteschlangenbildung bei Signal:** Signal tolerierte kurze Bursts, begann aber bei anhaltendem Datenverkehr mit mehreren Probes pro Sekunde, Nachrichten in Warteschlangen zu stellen. Für langfristige Überwachung solltest du eine Rate von etwa `1 Hz` (oder weniger) einhalten, damit jede Bestätigung weiterhin den aktuellen Gerätezustand statt den Abbau eines Rückstands widerspiegelt.
* **Artefakte beim Wiederverbinden:** Wenn ein Gerät wieder online kommt, bündeln einige Clients mehrere verzögerte Bestätigungen oder senden sie schnell nacheinander. Behandle solche Bestätigungs-Bursts als Marker für einen Zustandswechsel und nicht als unabhängige RTT-Messwerte, sonst passt sich dein Clustering bzw. dein Klassifikator für `active` vs `idle` zu stark an das Rauschen beim Wiederverbinden an.<sup>[[1]](#references)</sup>

## Verhalten aus RTT-Verläufen ableiten

1. Mit ≥1 Hz abtasten, um Effekte der Betriebssystemplanung zu erfassen. Bei WhatsApp auf iOS korrelieren RTTs unter 1 s stark mit eingeschaltetem Bildschirm/Vordergrund, RTTs über 1 s mit ausgeschaltetem Bildschirm/Drosselung im Hintergrund.
2. Einfache Klassifikatoren erstellen (Schwellenwert oder Zwei-Cluster-k-means), die jede RTT als „aktiv“ oder „inaktiv“ kennzeichnen. Die Kennzeichnungen zu Abschnitten zusammenfassen, um Schlafenszeiten, Pendelzeiten, Arbeitszeiten oder Aktivitätszeiten des Desktop-Begleitgeräts abzuleiten.
3. Gleichzeitige Probes an jedes Gerät richten, um zu erkennen, wann Nutzer vom Mobilgerät zum Desktop wechseln, wann Begleitgeräte offline gehen und ob die App durch Push-Nachrichten oder persistente Sockets begrenzt wird.
4. Verwende in realen Netzwerken keinen einzigen fest kodierten Schwellenwert von `1 s`. Kalibriere jedes Gerät zunächst in einem kurzen Aufwärmzeitraum und halte einen rollierenden Ausgangswert vor (der PoC device-activity-tracker verwendet beispielsweise `threshold = 0.9 * median RTT`), damit Schwankungen zwischen WLAN und Mobilfunk deinen Klassifikator nicht unbrauchbar machen.<sup>[[1]](#references)[[8]](#references)</sup>

## Standort aus der Zustellungs-RTT ableiten

Dieselbe Timing-Methode lässt sich nutzen, um den Standort des Empfängers abzuleiten, nicht nur dessen Aktivität. Die Arbeit `Hope of Delivery` zeigte, dass ein Angreifer anhand von RTT-Verteilungen bekannter Empfängerstandorte trainieren und später den Standort des Opfers allein aus Zustellbestätigungen klassifizieren kann:<sup>[[2]](#references)</sup>

* Eine Basislinie für dasselbe Ziel an mehreren bekannten Orten erstellen (zu Hause, im Büro, auf dem Campus, in Land A gegenüber Land B usw.).
* Für jeden Standort viele normale Nachrichten-RTTs erfassen und einfache Merkmale wie Median, Varianz oder Perzentilbereiche extrahieren.
* Während des eigentlichen Angriffs die neue Probe-Serie mit den trainierten Clustern vergleichen. Laut dem Paper lassen sich oft sogar Standorte innerhalb derselben Stadt unterscheiden; in einem Szenario mit drei Standorten wurde eine Genauigkeit von `>80%` erreicht.
* Dies funktioniert am besten, wenn der Angreifer die Absenderumgebung kontrolliert und unter ähnlichen Netzwerkbedingungen Probes sendet, da der gemessene Pfad das Zugangsnetz des Empfängers, die Aufwecklatenz und die Messenger-Infrastruktur umfasst.<sup>[[2]](#references)</sup>

Anders als die oben beschriebenen stillen Reaktions-/Bearbeitungs-/Löschangriffe erfordert die Standortableitung keine ungültigen Nachrichten-IDs oder verdeckten Pakete, die den Zustand ändern. Normale Nachrichten mit regulären Zustellbestätigungen reichen aus. Der Kompromiss ist geringere Tarnung, dafür eine breitere Anwendbarkeit über verschiedene Messenger hinweg.

## Unauffällige Erschöpfung von Ressourcen

Da jeder stille Probe entschlüsselt und bestätigt werden muss, führt das kontinuierliche Senden von Reaktionsumschaltungen, ungültigen Bearbeitungen oder „Für alle löschen“-Paketen zu einem DoS auf Anwendungsebene:<sup>[[1]](#references)</sup>

* Erzwingt jede Sekunde das Senden/Empfangen über Funk/Modem → merklicher Akkuverbrauch, insbesondere bei ungenutzten Mobilgeräten.
* Erzeugt Upstream-/Downstream-Datenverkehr, der mobile Datentarife belastet und mit latenzempfindlichen Funktionen wie Videoanrufen konkurrieren kann.<sup>[[1]](#references)</sup>
* Große ungültige Payloads verursachen zusätzliche Verarbeitung, aber laut dem Paper ist die Kryptografie selbst nur für einen vernachlässigbaren Teil des Akkuverbrauchs verantwortlich.<sup>[[1]](#references)</sup>
* Auf WhatsApp akzeptieren ungültige Reaktionen weit mehr Daten, als ein normales Emoji vermuten lässt: Veröffentlichte Messungen ergaben eine serverseitige Akzeptanz von bis zu etwa `1 MB` pro Reaktion.
* Übergroße Reaktionen erzeugen keine zuverlässigen Zustellbestätigungen mehr, sobald der Inhalt etwa `30 bytes` überschreitet. Sie werden jedoch weiterhin weitergeleitet und vor dem Verwerfen verarbeitet. Halte Reaktionsinhalte klein, wenn du ACKs benötigst; vergrößere sie nur, wenn es ausschließlich um Ressourcenerschöpfung oder verdeckten unidirektionalen Transport geht.
* Öffentliche Messungen erreichten in diesem Modus etwa `3.7 MB/s` (`~13.3 GB/h`) an Datenverkehr auf dem Gerät des Opfers.



## References

- [1] [Sorgloses Flüstern: Stille Zustellbestätigungen ausnutzen, um Nutzer mobiler Instant Messenger zu überwachen](https://arxiv.org/html/2411.11194v4)
- [2] [Hoffnung auf Zustellung: Nutzerstandorte aus mobilen Instant Messengern extrahieren](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [So blockierst du eine große Anzahl unbekannter Nachrichten | WhatsApp-Hilfebereich](https://faq.whatsapp.com/3379690015658337)
- [11] [Alle Nummern sind US-Nummern: Missbrauch der Kontakterkennung in mobilen Messengern in großem Maßstab](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
