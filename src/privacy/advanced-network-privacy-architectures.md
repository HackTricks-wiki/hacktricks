# Erweiterte Architekturen für Netzwerk-Privatsphäre

Komplexität ist nur dann sinnvoll, wenn sie einen bestimmten Beobachter oder Fehlermodus entfernt. Ein einzigartiger Tunnel-Stack, eine benutzerdefinierte Paketstruktur, ein seltener User-Agent oder eine häufig rotierende Infrastruktur kann zu einem stärkeren Fingerprint werden als eine Standardkonfiguration, die von Tausenden verwendet wird.

Der [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) stellt das übliche Schema `Pros`/`Cons`/`Procedure`/`Detection` bereit. Diese Seite erweitert die komplexeren Architekturen und Vertrauensgrenzen.

Das fortgeschrittene Ziel ist daher die **Trennung von Wissen**: Keine gewöhnliche Komponente sollte gleichzeitig die Benutzeridentität, das Ziel, den Klartext und den langfristigen Aktivitätsverlauf besitzen. Dies bedeutet keine Unsichtbarkeit, und Kollusion, rechtliche Maßnahmen, eine Kompromittierung des Endpunkts oder eine Ende-zu-Ende-Verkehrskorrelation können den Pfad weiterhin rekonstruieren.

## Architekturauswahl

| Muster | Gewonnene Eigenschaft | Neues Vertrauen/neuer Fehlermodus | Geeignete Verwendung |
|---|---|---|---|
| Standard-Tor Browser | Gemeinsamer Browser-Fingerprint und Pfad über mehrere Relays | Geringe Latenz ermöglicht Verkehrskorrelation | Allgemeines anonymes Web-Browsing |
| Tor bridge + pluggable transport | Erschwert direktes Tor-Blocking und die Klassifizierung | Bridge/Transport kann weiterhin erkannt werden; die Bridge erfährt die Quelle | Zensierte Netzwerke |
| Onion service | Verbirgt die Service-IP; vermeidet den Exit; authentifiziert die Onion-Identität | Onion-Key und Server-Endpunkt werden zu kritischen Ressourcen | Private Veröffentlichungen, Annahme oder Administration |
| Unabhängige Ingress- und Egress-Relays | Kein einzelnes Relay sieht normalerweise Quelle und Ziel | Betreiber können kolludieren; das Timing erstreckt sich über beide | Unterstützte Anwendungen mit hoher Performance |
| Oblivious HTTP | Trennt die Quell-IP von einer verschlüsselten zustandslosen HTTP-Anfrage | Erfordert Unterstützung durch Anwendung, Relay und Gateway | Telemetrie, Abfragen und Übermittlungen ohne Sitzungsstatus |
| Nur-VPN-Workload-Namespace | Kernel-erzwungenes Fehlen einer Route in ein unverschlüsseltes Netzwerk | Das VPN sieht weiterhin beide Enden; Host/Root bleibt vertrauenswürdig | Autorisierte Engagement-Tools und fester Egress |
| Wegwerfbarer Remote-Browser | Das Ziel wird vom lokalen Browser/Endpunkt isoliert | Der Workspace-Provider sieht Aktivität und Login-Identität | Nicht vertrauenswürdige Websites/Dateien und kontrollierte Recherche |
| I2P-interner Service | Getrennte eingehende/ausgehende Overlay-Tunnel; keine offiziellen Exits | Kleineres/anderes Ökosystem; Verhalten langfristig laufender Peers | Für I2P native Services, nicht als gewöhnlicher Web-Ersatz |
| Mixnet/asynchrone Zustellung | Verzögerung, Bündelung und Cover-Traffic widerstehen der Timing-Analyse | Hohe Latenz, begrenzte Anwendungen und geringere Reife | Nachrichten/Tasks, die keine Interaktion benötigen |

## Split-Knowledge-Relays

Ein Relay-Muster mit zwei Betreibern kann ein einzelnes VPN für eine eng umrissene Anwendung übertreffen:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay ist ein eingesetztes Beispiel: Apple betreibt den Ingress, während ein anderer Content-Provider den Egress betreibt, sodass normalerweise keiner von beiden sowohl die Client-IP als auch das Browsing-Ziel sieht.<sup>[[1]](#references)</sup> Dies ist ein produktspezifischer Safari-/DNS-Privacy-Service und kein geräteweites Anonymitätsnetzwerk; außerdem bewahrt er absichtlich eine grobe Region.

Oblivious HTTP (OHTTP) standardisiert ein enger gefasstes Anwendungsmuster. Der Relay sieht den Client und den verschlüsselten Gateway-Datenverkehr; der Gateway entschlüsselt die HTTP-Nachricht, sieht jedoch den Relay und nicht den Client. RFC 9458 weist darauf hin, dass dafür die Unterstützung durch Relay und Gateway erforderlich ist, dass es sich am besten für Requests ohne Cookies, Authentifizierung oder Session-Status eignet und dass Traffic Analysis nicht durch die Garantien abgedeckt ist.<sup>[[2]](#references)</sup>

### Design-Checkliste

1. Definiere die genauen Anwendungnachrichten, die geschützt werden sollen; proxy keine beliebigen authentifizierten Web-Sessions stillschweigend.
2. Verwende nach Möglichkeit unabhängig betriebene Ingress- und Egress-Organisationen mit getrennter Administration, getrennten Zugangsdaten, getrenntem Logging und getrennter rechtlicher Kontrolle.
3. Verschlüssele den Application-Request für den Gateway, damit der Ingress ihn nicht lesen kann.
4. Entferne Client-abgeleitete Forwarding-Header, TLS-Identifier und stabile benutzerbezogene Tokens auf der geeigneten Schicht.
5. Vermeide eindeutige Schlüssel, Cookies oder Payload-Felder, durch die der Gateway Requests trotz der Transporttrennung wieder verknüpfen kann.
6. Aggregiere, minimiere und lösche Logs auf beiden Seiten nach Ablauf der Frist; dokumentiere das Kollusions- und das Risiko erzwungener Offenlegung.
7. Führe Padding oder Batching nur gemäß einem überprüften Protokoll durch. Selbst entwickeltes Traffic Shaping kann eine eindeutige Signatur erzeugen, ohne die Korrelation zu verhindern.
8. Teste mit kontrollierten Canary-Requests und vergleiche, was Client, Ingress, Gateway und Ziel jeweils protokollieren.

Für gewöhnliches interaktives Browsing solltest du Tor Browser verwenden, statt einen privaten OHTTP-Proxy zu entwickeln. OHTTP schützt eine unterstützte Anwendungstransaktion, nicht die vollständige Browser-Identität.

## Die Route pro Workload erzwingen

Ein Kill Switch, der ausschließlich auf veränderlichen Host-Routen basiert, kann während einer DHCP-Erneuerung, beim Wechsel zwischen Ruhezustand und Aktivität, bei IPv6-Änderungen oder nach einem Tunnel-Crash versagen. Ein stärkeres Linux-Muster weist einem Container oder Network Namespace nur ein Loopback-Interface und ein Tunnel-Interface zu. WireGuard dokumentiert, dass ein Interface in einem physischen Namespace erstellt, in einen Workload-Namespace verschoben werden und seinen verschlüsselten UDP-Socket im ursprünglichen Namespace behalten kann.<sup>[[3]](#references)</sup>

### Deployment-Muster

1. Baue dies zuerst auf einem verworfenen Host mit lokalem Konsolenzugriff auf; Fehler bei Namespaces können den Remote-Zugriff entfernen.
2. Platziere das physische Ethernet-/Wi-Fi-Interface sowie DHCP/Supplicant in einem **physischen** Namespace.
3. Erstelle dort das WireGuard-Interface, damit sein verschlüsselter Transport-Socket Zugriff auf das physische Netzwerk hat.
4. Verschiebe nur das WireGuard-Interface in den **Workload**-Namespace und mache es zur einzigen Default-Route.
5. Weise dem Workload einen Namespace-spezifischen Resolver zu, der nur über den Tunnel erreichbar ist. Berücksichtige IPv6 ausdrücklich.
6. Starte den Browser-/Tool-Container in diesem Namespace ohne Host-Networking, privilegierte Capabilities, gemeinsam genutztes Browser-Verzeichnis oder persönlichen Credential-Agent.
7. Stoppe den Tunnel und überprüfe, dass der Workload keinen kontrollierten IPv4- oder IPv6-Endpunkt auflösen oder verbinden kann.
8. Teste Endpoint-Roaming, DHCP-Erneuerung, Suspend/Resume und Captive-Portal-Verhalten außerhalb des Workload-Namespaces.
9. Protokolliere den Hash der Namespace-/Tunnel-Konfiguration und die genehmigte Egress-Adresse zur Nachvollziehbarkeit des Engagements.

Dies bietet **Routen-Erzwingung**, jedoch keine Anonymität gegenüber dem VPN oder dem Engagement-Bastion-Host. Ein kompromittierter Host bzw. Root kann Namespaces inspizieren oder ändern.

## Tor Bridges und Pluggable Transports

Bridges sind nicht öffentliche Tor-Entry-Relays. Pluggable Transports verändern den Traffic des ersten Hops, sodass einfaches Blocking oder eine Protokollklassifizierung erschwert wird. Sie fügen nach dem Entry keine anonymen Relay-Schichten hinzu und können einen Beobachter, der zu umfassenderer Timing-Korrelation fähig ist, nicht ausschalten.

| Transport | Ansatz für den ersten Hop | Praktischer Kompromiss |
|---|---|---|
| **obfs4** | Lässt den Traffic zufällig aussehen und widersteht aktivem Probing | Eine bekannte Bridge-Adresse kann weiterhin blockiert werden |
| **Snowflake** | Verwendet kurzlebige freiwillige WebRTC-Proxies, um eine Bridge zu erreichen | Die Performance variiert; Broker-/STUN-/WebRTC-Muster existieren |
| **WebTunnel** | Überträgt Bridge-Traffic in einem HTTPS-ähnlichen WebSocket-Tunnel | Hängt von einem erreichbaren Web-Front ab und kann weiterhin klassifiziert werden |

Das Tor Project beschreibt Snowflake und WebTunnel als Transporte zur Zensurumgehung, nicht als perfekte Ununterscheidbarkeit.<sup>[[4]](#references)</sup>

### Sicherer Ablauf

1. Beginne mit der direkten Verbindung von Tor Browser. Füge eine Bridge nur hinzu, wenn Blocking oder Sichtbarkeit im lokalen Beobachtermodell dies rechtfertigt.
2. Verwende integrierte Transporte oder Bridge-Zeilen, die über Kanäle des Tor Project bezogen wurden. Lade keine zufälligen Transport-Binaries oder öffentlichen Bridge-Listen aus Foren herunter.
3. Probiere die am wenigsten komplexe unterstützte Option, die zuverlässig verbindet, und dokumentiere den Grund für ihre Auswahl.
4. Belasse Tor Browser ansonsten im Standardzustand. Eine Bridge macht benutzerdefinierte Extensions, Account-Logins oder ungewöhnliche Browsereinstellungen nicht sicher.
5. Teste Reconnect und die korrekte Uhrzeit. Wechsle Transporte nicht wiederholt auf eine Weise, die für denselben lokalen Beobachter eine charakteristische Sequenz erzeugt.
6. Bewerte die Situation neu, wenn sich Zensur oder Netzwerkregeln ändern; die Nutzung kann an manchen Orten selbst sensibel oder eingeschränkt sein.

## Onion Services als privater Rendezvous-Punkt

Ein Onion Service baut ausgehende Tor-Circuits zu Introduction Points und Rendezvous-Relays auf. Daher benötigt er keinen öffentlichen eingehenden Port und legt seine Server-IP nicht über das Onion-Protokoll offen. Der Traffic zwischen Client und Service bleibt innerhalb von Tor, und die Onion-Adresse authentifiziert den Service-Schlüssel.<sup>[[5]](#references)</sup>

Für ein rechtmäßiges Intake-Portal, ein privates Repository, ein administratives Interface oder einen Ablageort für Engagement-Beweise:

1. Betreibe die Anwendung auf einem dedizierten Host bzw. einer dedizierten VM und binde sie an Loopback oder einen isolierten Unix-Socket.
2. Installiere Tor aus dem offiziellen Repository und befolge die offizielle Einrichtung für v3-Onion-Services; verwende niemals veraltete v2-Anleitungen.
3. Schütze den privaten Schlüssel des Onion Service wie einen TLS-/Signing-Schlüssel. Sichere ihn nur, wenn eine stabile Identität erforderlich ist.
4. Füge eine Client-Autorisierung für Onion Services für eine geschlossene Gruppe hinzu und übermittle die Zugangsdaten über einen unabhängig authentifizierten Kanal.<sup>[[6]](#references)</sup>
5. Verhindere, dass der Origin Drittanbieter-Fonts, Analytics, Updates oder Webhooks abruft, die seine öffentliche IP oder das Account des Operators offenlegen.
6. Implementiere Authentifizierung und Autorisierung zusätzlich in der Anwendung; der Besitz der Onion-Adresse ist keine Zugriffskontrolle.
7. Spiele Patches ein, begrenze die Rate und überwache den Service, ohne Telemetrie von Drittanbietern einzubetten.
8. Bestätige aus einem separaten Testkontext, dass DNS, E-Mail, Fehlerseiten, Datei-Metadaten und Response-Header den Origin nicht offenlegen.
9. Führe den Service bei Red-Team-Nutzung mit Service, Eigentümer, Zweck und Abschaltzeit im ROE auf. Verwende ihn nicht, um C2 außerhalb des Scopes zu verbergen.

## Remote-Browser und verworfener Workspace

Ein Remote-Browser verlagert Rendering und riskante Inhalte vom lokalen Endpunkt weg und kann einen engagement-spezifischen Cloud-Egress bereitstellen. Er schützt das lokale Gerät vor bestimmten Inhalten und Persistenz; gegenüber dem Workspace-Provider macht er den Operator jedoch nicht anonym. AWS dokumentiert beispielsweise die Erfassung von Portal-, Identitäts-, Richtlinien-, Präferenz- und Session-Log-Daten, obwohl die verworfene Browser-Instanz am Ende der Session gelöscht wird.<sup>[[7]](#references)</sup>

Verwende pro Engagement einen von der Organisation kontrollierten Workspace, beschränke Downloads, Uploads und Clipboard, deaktiviere persönliche Identity Provider, leite seinen festen Egress über den genehmigten Bastion-Host und lösche den Workspace nach dem Export der Beweise. Betrachte die Provider-Konsole, den IdP und den Administrator als Beobachter.

## I2P und interne Overlays

I2P erstellt getrennte unidirektionale Inbound- und Outbound-Tunnel und besitzt keine offiziellen Exits auf Netzwerkebene; es ist hauptsächlich für Services innerhalb von I2P gedacht.<sup>[[8]](#references)</sup> Es ist kein schnellerer Drop-in-Ersatz für das Browsen im öffentlichen Internet. Outproxies führen einen Trust Point ein, und das offizielle Threat Model fordert ausdrücklich weitere Forschung und beansprucht keine perfekte Anonymität.

Verwende I2P nur, wenn beide Seiten es absichtlich unterstützen, isoliere seinen langlebigen Router von persönlichen Anwendungen und berücksichtige, dass Peers und lokale Netzwerke die I2P-Teilnahme beobachten können. Erhöhe die Hop-Anzahl nicht und optimiere die Peer-Auswahl nicht ohne Belege: Ungewöhnliche Einstellungen können die Performance und die Anonymity Set reduzieren.

## Korrelationresistente Abläufe

- Bevorzuge eine gemeinsame, unterstützte Client-Konfiguration gegenüber einem individuellen Build.
- Trenne Identitäten am Endpunkt; keine Routing-Topologie repariert die Wiederverwendung von Accounts, Zahlungen, Recovery-Informationen oder Inhalten.
- Für nicht interaktive Aufgaben solltest du ein überprüftes asynchrones Protokoll bzw. Mixnet gegenüber dem manuellen Einfügen von Wartezeiten oder Fake-Traffic bevorzugen.
- Vermeide es, vermeintlich getrennte Identitäten aus demselben physischen Kontext in einem synchronisierten Muster zu betreiben.
- Verwende ein einseitiges Export-Gate: Nicht vertrauenswürdige Inhalte gelangen in einen verworfenen Renderer; nur ein überprüftes, bereinigtes Ergebnis verlässt ihn.
- Halte Uhren für die Protokollsicherheit korrekt, entferne jedoch unnötig präzise Zeitstempel aus veröffentlichten Artefakten.
- Minimiere die Session-Dauer und veraltete Infrastruktur, ohne eine schnelle „Fast-Flux“-Rotation einzusetzen, die auffällig ist und die Nachvollziehbarkeit beeinträchtigt.

## Techniken, die keine unbeteiligten Dritten verwenden dürfen

Dies sind echte Adversary-Techniken, keine imaginären oder unwichtigen. Ihre Funktionsweise und Erkennung werden in [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) und den [APT case studies](government-and-apt-case-studies.md) behandelt. Reproduziere während einer autorisierten Übung ihr beobachtbares Verhalten mit eigenen Ersatzsystemen:

- simuliere die Rotation von Residential-/Mobile-Exits mit kontrollierten Relay-Pools, niemals mit Märkten unklarer Zustimmung;
- simuliere Open Proxies, kompromittierte Router und Botnets mit eigenen VMs/Routern;
- simuliere gestohlene Cloud-Accounts mit einem dafür vorgesehenen Exercise-Tenant und einer synthetischen Opferidentität;
- simuliere Domain Fronting auf einem eigenen Reverse Proxy statt auf einem nicht willigen CDN;
- simuliere Drittanbieter-Wi-Fi mit zwei isolierten, dem Labor gehörenden APs;
- behandle benutzerdefinierte Verschlüsselung, Multi-VPN-Ketten und Identifier-Rotation als Test-Hypothesen, deren Flow-, Account- und Endpunkt-Artefakte weiterhin erkennbar bleiben.

Bei einem autorisierten Red Team muss jeder Versuch, Traffic weniger erkennbar zu machen, ein ausdrücklich im ROE festgelegtes Detection-Ziel sein, über eine vom Controller verwaltete Attribution Map verfügen und einen Stop-/Deconfliction-Mechanismus enthalten.

## Verifikationsmatrix

| Test | Erwartetes Ergebnis | Fehler bedeutet |
|---|---|---|
| Tunnel/Bridge gestoppt | Der Workload hat keinen direkten IPv4-/IPv6-/DNS-Pfad | Die Routen-Erzwingung ist unvollständig |
| Target-Log geprüft | Es erscheint nur die geplante Egress-/Application-Identität | Header-, Routen- oder Account-Leak |
| Ingress-Log geprüft | Quelle vorhanden; klares Ziel bzw. klarer Request nicht vorhanden | Trust Split am Ingress fehlgeschlagen |
| Egress-Log geprüft | Relay/Request vorhanden; Quellidentität nicht vorhanden | Trust Split am Egress fehlgeschlagen |
| Onion-Origin extern gescannt | Kein öffentlicher Origin-Service ist erreichbar oder verknüpft | Origin geleakt oder dual-homed |
| Verwerfbare Session beendet | Instanzstatus verschwunden; genehmigte Beweise separat erhalten | Persistenzgrenze fehlgeschlagen |
| Controller-Lookup durchgeführt | Aktivität wird zeitnah Engagement/Operator zugeordnet | Red-Team-Nachvollziehbarkeit fehlgeschlagen |

## References

- [1] [Apple Platform Security — Sicherheit von iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing und Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake und Pluggable Transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Funktionsweise von Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Erweiterte Einstellungen für Onion Services und Client-Autorisierung](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Datenverschlüsselung in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
