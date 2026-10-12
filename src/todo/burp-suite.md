# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder-Payload-Typen

Burp Intruder enthält die folgenden integrierten Payload-Generatoren und -Transformationen:<sup>[[1]](#references)</sup>

- **Simple list:** Verwendet eine konfigurierte Liste von Zeichenfolgen als Payloads.
- **Runtime file:** Liest zur Laufzeit eine Payload pro Zeile. Dies ist bei großen Listen hilfreich, da Burp nicht die gesamte Datei in den Arbeitsspeicher lädt.
- **Case modification:** Erzeugt den unveränderten Wert, Klein- und Großbuchstaben, `Propername` (erster Buchstabe groß, die übrigen klein) oder `ProperName` (erster Buchstabe groß, die übrigen unverändert). Burp verwirft doppelte Ergebnisse.
- **Numbers:** Erzeugt fortlaufende oder zufällige Zahlen innerhalb eines konfigurierten Bereichs.
- **Brute forcer:** Erzeugt alle Permutationen für einen ausgewählten Zeichensatz und eine minimale und maximale Länge.

## Erweiterungen und Begleittools

- **Collabfiltrator** erzeugt Payloads, die Befehle ausführen und deren Ausgabe über DNS-Abfragen an Burp Collaborator exfiltrieren.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exportiert Burp-Ergebnisse zur Verwendung in anderen Reporting-Workflows.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** wandelt HTTP-Anfragen in Skripte in mehreren Sprachen um.<sup>[[4]](#references)</sup>

## Autorisierungstests mit mehreren Sitzungen mit Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) ist eine Java-Erweiterung für Burp Suite `2025.5+`, die Cookies und ungewöhnliche Header als benannte Credential-Profile speichert. Wird in einem bearbeitbaren Anfrage-Editor, etwa Repeater oder einer abgefangenen Proxy-Anfrage, ein Profil ausgewählt, ersetzt es die Authentifizierungsdaten der Anfrage. Dies dient der erneuten Übermittlung, ist **kein Authorization Bypass**: Verwenden Sie die Erweiterung, um dieselbe Anfrage als verschiedene Accounts zu senden und so horizontale Zugriffsrechte, vertikale Rollengrenzen, Tenant-Isolation und [IDOR/BOLA](../pentesting-web/idor.md) im Rahmen der [Web-Testmethodik](../pentesting-web/web-vulnerabilities-methodology.md) zu prüfen.<sup>[[5]](#references)[[8]](#references)</sup>

### Wiederholbarer Workflow zum Vergleich unterschiedlicher Identitäten

Der folgende Workflow behandelt Ressource/Aktion und handelnde Identität als getrennte Testvariablen. So lassen sich falsche Ergebnisse aufgrund veralteter Tokens oder der falschen Browser-Sitzung reduzieren.<sup>[[5]](#references)[[8]](#references)</sup>

1. Authentifizieren Sie Test-Accounts, die die relevanten Benutzer, Rollen und Tenants repräsentieren, in separaten Browser-Profilen oder Containern.
2. Öffnen Sie eine Anfrage mit den Cookies und Headern einer Identität, wählen Sie **Sessions > New** und vergeben Sie einen eindeutigen Profilnamen wie `tenant-a-user` oder `tenant-b-admin`. Wiederholen Sie dies für jede Testidentität.
3. Senden Sie eine mögliche Anfrage an Repeater und übermitteln Sie sie erneut, ohne Methode, Endpunkt, Parameter oder Objektkennung zu ändern; wechseln Sie nur die ausgewählte Sitzung. Vergleichen Sie Antwortdaten und beobachtbare Zustandsänderungen, nicht nur Statuscodes.
4. Prüfen Sie auf Objektebene eine Anfrage für ein Objekt, das bekanntermaßen zu Account A gehört, während Sie das Profil von Account B auswählen. Prüfen Sie auf Funktionsebene dieselbe privilegierte Aktion mit Profilen mit geringeren Berechtigungen.
5. Verwenden Sie nach einer erneuten Authentifizierung oder Token-Rotation **Update** für eine aktuelle Browser-Anfrage oder konfigurieren Sie eine Auto Update-Regel, bevor Sie den Vergleich wiederholen.

### Semantik von Erfassung und Injektion

Prüfen Sie vor dem Testen die Aktualisierungs- und Injektionsmodi, da eine hybride Anfrage mit Zugangsdaten zweier Identitäten den Vergleich ungültig machen kann. Die aktuellen Standardeinstellungen übernehmen alle Anfrage-Cookies in ein Profil, aktualisieren nur bereits gespeicherte ungewöhnliche Header, übernehmen die Cookies des ausgewählten Profils in die Zielanfrage (und entfernen deren vorhandene Cookies) und fügen die Header des Profils hinzu. Die Auswahl lässt sich auf eine exakte Subdomain, die Top-Level-Anwendungsdomain (Standard) oder alle gespeicherten Profile beschränken.<sup>[[7]](#references)</sup>

- **Mirror** ist hilfreich, wenn der vollständige Cookie-Satz eine Identität definiert und veraltete Cookies der Zielanfrage entfernt werden müssen.
- **Update existing** übernimmt rotierende Werte, ohne nicht zugehörige Cookies oder Header aus dem Browser-Traffic zu speichern.
- **Add all** behält zusätzliche Werte bei, die bereits im Profil oder in der Anfrage gespeichert sind. Prüfen Sie, dass dadurch keine identitätsbezogenen Daten der vorherigen Sitzung verbleiben.
- **Do nothing** schließt Cookies oder Header von Profilaktualisierungen aus, wenn die jeweilige Zugangsdatenklasse irrelevant ist.

### Sitzungsabgleich über Proxy

Auto Update-Regeln ordnen Proxy-Traffic einem gespeicherten Profil zu und aktualisieren dessen Cookies/Header. Verwenden Sie bevorzugt ein stabiles Unterscheidungsmerkmal wie einen dedizierten Anfrage-Header, einen profilspezifischen `User-Agent`-Marker, ein identifizierendes Cookie, `X-PwnFox-Color` oder einen JWT-Claim. Kombinieren Sie es mit Bedingungen für Scope/Domain/Pfad, damit nicht zugehörige Anwendungen das Profil nicht aktualisieren können. Alle Bedingungen innerhalb einer Regel werden der Reihe nach mit logischem `AND` ausgewertet. Setzen Sie daher restriktive Prüfungen an den Anfang; für `OR` erstellen Sie mehrere Regeln, die auf dasselbe Profil verweisen. Auch negative Übereinstimmungen werden unterstützt.<sup>[[6]](#references)</sup>

Wählen Sie für jede passende Regel unabhängig für Cookies und Header **Mirror request**, **Add all**, **Update existing** oder **Do nothing**. Regeln, die nur Anfragen berücksichtigen, werden ausgeführt, wenn Proxy die Anfrage empfängt. Wird eine Bedingung für Antwortstatus, Antwort-Header oder Antwort-Body hinzugefügt, wird die Auswertung bis zum Eintreffen der Antwort verzögert. Eine Hervorhebungsfarbe kann passenden Traffic markieren und so dabei helfen zu überprüfen, ob jede Browser-Identität nur ihr vorgesehenes Profil aktualisiert.<sup>[[6]](#references)</sup>

Gespeicherte Profile befinden sich im Burp-Projekt. JSON-Exporte der Projektdaten enthalten die Sitzungen und damit auch ihre Cookies und Header. Behandeln Sie beide Dateien als aktive Zugangsdaten, beschränken Sie den Zugriff darauf und löschen Sie die gespeicherten Erweiterungsdaten nach dem Engagement.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger-Dokumentation – Burp-Intruder-Payload-Typen](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub – 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC – Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub – h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec – Quellcode und Nutzungsdokumentation von Session Switcher](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec – Auto Update-Regeln von Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec – Einstellungen von Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec – Session Switcher: Vereinfachung von Autorisierungstests mit mehreren Sitzungen in Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
