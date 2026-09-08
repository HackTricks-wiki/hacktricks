# Erweiterte Architekturen für Netzwerk-Privatsphäre

{{#include ../banners/hacktricks-training.md}}

Komplexität ist nur dann sinnvoll, wenn sie einen bestimmten Beobachter oder Fehlermodus ausschaltet. Ein einzigartiger Tunnel-Stack, eine benutzerdefinierte Paketstruktur, ein seltener User-Agent oder eine häufig wechselnde Infrastruktur kann zu einem stärkeren Fingerabdruck werden als eine Standardkonfiguration, die von Tausenden Menschen verwendet wird.

Der [Katalog für Techniken zum anonymen Internetzugang](anonymous-internet-access-techniques.md) stellt das gängige Schema `Pros`/`Cons`/`Procedure`/`Detection` bereit. Diese Seite erweitert die komplexeren Architekturen und Vertrauensgrenzen.

Das fortgeschrittene Ziel ist daher die **Trennung von Wissen**: Keine gewöhnliche Komponente sollte gleichzeitig über die Benutzeridentität, das Ziel, den Klartext und den langfristigen Aktivitätsverlauf verfügen. Dies bedeutet keine Unsichtbarkeit, und durch Kollusion, rechtliche Verfahren, eine Kompromittierung des Endpunkts oder eine Ende-zu-Ende-Korrelation des Datenverkehrs kann der Pfad weiterhin rekonstruiert werden.

## Auswahl der Architektur

| Muster | Gewonnene Eigenschaft | Neues Vertrauen/Fehlerrisiko | Geeignete Verwendung |
|---|---|---|---|
| Standard Tor Browser | Gemeinsamer Browser-Fingerabdruck und Pfad über mehrere Relays | Geringe Latenz ermöglicht eine Korrelation des Datenverkehrs | Allgemeines anonymes Web-Browsing |
| Tor bridge + pluggable transport | Erschwert die direkte Blockierung/Klassifizierung von Tor | Bridge/Transport kann weiterhin erkannt werden; die Bridge erfährt die Quelle | Zensierte Netzwerke |
| Onion service | Verbirgt die Service-IP, vermeidet den Exit und authentifiziert die Onion-Identität | Onion-Schlüssel und Server-Endpunkt werden zu kritischen Assets | Privates Veröffentlichen, Entgegennahme von Inhalten oder Administration |
| Unabhängige Ingress- und Egress-Relays | Normalerweise sieht kein einzelnes Relay Quelle und Ziel | Betreiber können kolludieren; das Timing durchläuft beide | Unterstützte Anwendungen mit hoher Leistung |
| Oblivious HTTP | Trennt die Quell-IP von der verschlüsselten zustandslosen HTTP-Anfrage | Erfordert Unterstützung durch Anwendung, Relay und Gateway | Telemetrie, Abfragen und Übermittlungen ohne Sitzungsstatus |
| Nur-VPN-Workload-Namespace | Durch den Kernel erzwungenes Fehlen einer Route zum Klartextnetz | Das VPN sieht weiterhin beide Enden; Host/Root bleibt vertrauenswürdig | Autorisierte Engagement-Tools und fester Egress |
| Wegwerfbarer Remote-Browser | Das Ziel wird vom lokalen Browser/Endpunkt isoliert | Der Workspace-Anbieter sieht Aktivität und Login-Identität | Nicht vertrauenswürdige Websites/Dateien und kontrollierte Recherche |
| I2P-interner Service | Getrennte eingehende/ausgehende Overlay-Tunnel; keine offiziellen Exits | Kleineres/anderes Ökosystem; Verhalten langfristig laufender Peers | Für I2P native Services, kein Ersatz für das gewöhnliche Web |
| Mixnet/asynchrone Zustellung | Verzögerung, Bündelung und Cover Traffic widerstehen der Timing-Analyse | Hohe Latenz, begrenzte Anwendungen und geringere Reife | Nachrichten/Tasks, die keine Interaktion benötigen |

## Relays mit geteiltem Wissen

Ein Relay-Muster mit zwei Betreibern kann ein einzelnes VPN für eine eng begrenzte Anwendung übertreffen:
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
Apple Private Relay ist ein eingesetztes Beispiel: Apple betreibt den Ingress, während ein anderer Content Provider den Egress betreibt, sodass normalerweise keine der beiden Seiten sowohl die Client-IP als auch das Browsing-Ziel sieht.<sup>[[1]](#references)</sup> Dies ist ein produktspezifischer Safari/DNS-Privacy-Service und kein geräteübergreifendes Anonymitätsnetzwerk; außerdem bewahrt er absichtlich eine grobe Region.

Oblivious HTTP (OHTTP) standardisiert ein enger gefasstes Anwendungsmuster. Der Relay sieht den Client und den verschlüsselten Gateway-Datenverkehr; der Gateway entschlüsselt die HTTP-Nachricht, sieht jedoch den Relay und nicht den Client. RFC 9458 weist darauf hin, dass dafür die Unterstützung durch Relay und Gateway erforderlich ist, dass es sich am besten für Requests ohne Cookies/Authentifizierung/Session-State eignet und dass Traffic Analysis nicht durch die Garantien abgedeckt ist.<sup>[[2]](#references)</sup>

### Design-Checkliste

1. Definiere die exakten Anwendungsnachrichten, die geschützt werden sollen; proxy nicht stillschweigend beliebige authentifizierte Web-Sessions.
2. Verwende nach Möglichkeit unabhängig betriebene Ingress- und Egress-Organisationen mit getrennter Administration, getrennten Credentials, getrenntem Logging und getrennter rechtlicher Kontrolle.
3. Verschlüssele den Application Request für den Gateway, damit der Ingress ihn nicht lesen kann.
4. Entferne Client-abgeleitete Forwarding-Header, TLS-Identifier und stabile per-user Tokens auf der jeweils geeigneten Schicht.
5. Vermeide eindeutige Keys, Cookies oder Payload-Felder, durch die der Gateway Requests trotz Transporttrennung erneut verknüpfen kann.
6. Aggregiere, minimiere und lasse Logs auf beiden Seiten ablaufen; dokumentiere das Kollusions- und das Risiko erzwungener Offenlegung.
7. Padde oder batch nur entsprechend einem geprüften Protokoll. Selbst entwickelte Traffic Shaping kann eine eindeutige Signatur erzeugen, ohne die Korrelation zu verhindern.
8. Teste mit kontrollierten Canary-Requests und vergleiche, was Client, Ingress, Gateway und Target jeweils protokollieren.

Für gewöhnliches interaktives Browsing solltest du Tor Browser verwenden, statt einen privaten OHTTP-Proxy zu erfinden. OHTTP schützt eine unterstützte Application-Transaktion, nicht eine vollständige Browser-Identität.

## Route pro Workload erzwingen

Ein Kill Switch, der nur auf veränderlichen Host-Routen basiert, kann bei DHCP-Erneuerung, Sleep/Wake, IPv6-Änderungen oder einem Tunnel-Crash versagen. Ein stärkeres Linux-Muster gibt einem Container oder Network Namespace nur ein Loopback-Interface und ein Tunnel-Interface. WireGuard dokumentiert, dass ein Interface in einem physischen Namespace erstellt, in einen Workload Namespace verschoben und sein verschlüsselter UDP-Socket im ursprünglichen Namespace behalten werden kann.<sup>[[3]](#references)</sup>

### Deployment-Muster

1. Baue dies zuerst auf einem Disposable-/Local-Console-Host auf; Fehler im Namespace können den Remote-Zugriff entfernen.
2. Lege das physische Ethernet-/Wi-Fi-Interface sowie DHCP/Supplicant in einen **physischen** Namespace.
3. Erstelle dort das WireGuard-Interface, damit sein verschlüsselter Transport-Socket Zugriff auf das physische Netzwerk hat.
4. Verschiebe nur das WireGuard-Interface in den **Workload** Namespace und mache es zur einzigen Default-Route.
5. Gib dem Workload einen Namespace-spezifischen Resolver, der nur über den Tunnel erreichbar ist. Berücksichtige IPv6 ausdrücklich.
6. Führe den Browser-/Tool-Container in diesem Namespace aus, ohne Host-Networking, privilegierte Capabilities, ein gemeinsam genutztes Browser-Verzeichnis oder einen persönlichen Credential-Agent.
7. Stoppe den Tunnel und überprüfe, dass der Workload weder einen kontrollierten IPv4- oder IPv6-Endpunkt auflösen noch sich mit ihm verbinden kann.
8. Teste Endpoint-Roaming, DHCP-Erneuerung, Suspend/Resume und Captive-Portal-Verhalten außerhalb des Workload Namespace.
9. Protokolliere den Hash der Namespace-/Tunnel-Konfiguration und die genehmigte Egress-Adresse zur Nachvollziehbarkeit des Engagements.

Dies bietet **Route Enforcement**, jedoch keine Anonymität gegenüber dem VPN oder dem Engagement-Bastion. Ein kompromittierter Host/Root kann Namespaces inspizieren oder ändern.

## Tor Bridges und Pluggable Transports

Bridges sind nicht öffentliche Tor-Entry-Relays. Pluggable Transports verändern den Traffic des ersten Hops, sodass einfaches Blocking oder eine Protokollklassifizierung erschwert wird. Sie fügen nach dem Entry keine anonymen Relay-Schichten hinzu und können einen Beobachter, der zu umfassenderer Timing-Korrelation fähig ist, nicht ausschalten.

| Transport | First-Hop-Ansatz | Praktischer Kompromiss |
|---|---|---|
| **obfs4** | Lässt den Traffic zufällig aussehen und widersteht aktivem Probing | Eine bekannte Bridge-Adresse kann weiterhin geblockt werden |
| **Snowflake** | Verwendet kurzlebige freiwillige WebRTC-Proxies, um eine Bridge zu erreichen | Die Performance variiert; Broker-/STUN-/WebRTC-Muster existieren |
| **WebTunnel** | Überträgt Bridge-Traffic in einem HTTPS-ähnlichen WebSocket-Tunnel | Abhängig von einem erreichbaren Web-Front und weiterhin klassifizierbar |

Das Tor Project beschreibt Snowflake und WebTunnel als Transports zur Umgehung von Zensur, nicht als perfekte Ununterscheidbarkeit.<sup>[[4]](#references)</sup>

### Sicherer Workflow

1. Beginne mit der direkten Verbindung von Tor Browser. Füge eine Bridge nur hinzu, wenn Blocking oder Sichtbarkeit im lokalen Beobachtermodell dies rechtfertigen.
2. Verwende integrierte Transports oder Bridge-Lines, die über Tor-Project-Kanäle bezogen wurden. Lade keine zufälligen Transport-Binaries oder öffentlichen Bridge-Listen aus Foren herunter.
3. Verwende die am wenigsten komplexe unterstützte Option, die zuverlässig verbindet, und dokumentiere den Auswahlgrund.
4. Halte Tor Browser ansonsten standardmäßig. Eine Bridge macht Custom Extensions, Account-Logins oder ungewöhnliche Browser-Einstellungen nicht sicher.
5. Teste Reconnect und die Korrektheit der Uhrzeit. Wechsle Transports nicht wiederholt auf eine Weise, die demselben lokalen Beobachter eine eindeutige Sequenz sendet.
6. Bewerte neu, wenn sich der Zensor oder die Network Policy ändert; die Nutzung selbst kann an manchen Orten sensibel oder eingeschränkt sein.

## Onion Services als privater Rendezvous-Punkt

Ein Onion Service baut ausgehende Tor-Circuits zu Introduction Points und Rendezvous-Relays auf. Daher benötigt er keinen öffentlichen Inbound-Port und legt seine Server-IP nicht über das Onion-Protokoll offen. Der Traffic zwischen Client und Service bleibt innerhalb von Tor, und die Onion-Adresse authentifiziert den Service-Key.<sup>[[5]](#references)</sup>

Für ein rechtmäßiges Intake-Portal, privates Repository, administratives Interface oder einen Engagement-Evidence-Drop:

1. Betreibe die Anwendung auf einem dedizierten Host/VM und binde sie an Loopback oder einen isolierten Unix-Socket.
2. Installiere Tor aus seinem offiziellen Repository und befolge das offizielle Setup für v3 Onion Services; verwende niemals veraltete v2-Anleitungen.
3. Schütze den privaten Key des Onion Service wie einen TLS-/Signing-Key. Erstelle nur dann ein Backup, wenn eine stabile Identität erforderlich ist.
4. Füge eine Client-Authorisierung des Onion Service für eine geschlossene Gruppe hinzu und übermittle Credentials über einen unabhängig authentifizierten Kanal.<sup>[[6]](#references)</sup>
5. Verhindere, dass der Origin Third-Party-Fonts, Analytics, Updates oder Webhooks abruft, die seine öffentliche IP oder das Operator-Konto offenlegen.
6. Implementiere Authentication und Authorization auch in der Anwendung; der Besitz der Onion-Adresse ist keine Access Control.
7. Patche, rate-limitiere und überwache den Service, ohne Third-Party-Telemetrie einzubetten.
8. Überprüfe aus einem separaten Testkontext, dass DNS, E-Mail, Error Pages, File Metadata und Response Headers den Origin nicht offenlegen.
9. Liste für Red-Team-Nutzung den Service, den Owner, den Zweck und den Abschaltzeitpunkt im ROE auf. Verwende ihn nicht, um Out-of-Scope-C2 zu verbergen.

## Remote Browser und Disposable Workspace

Ein Remote Browser verlagert Rendering und riskanten Content vom lokalen Endpoint weg und kann einen engagement-spezifischen Cloud-Egress bereitstellen. Er schützt das lokale Gerät vor bestimmten Inhalten und Persistenz, macht den Operator gegenüber dem Workspace Provider jedoch nicht anonym. AWS dokumentiert beispielsweise die Erfassung von Portal-, Identitäts-, Policy-, Präferenz- und Session-Log-Daten, obwohl die Disposable-Browser-Instanz am Ende der Session verworfen wird.<sup>[[7]](#references)</sup>

Verwende einen organisationskontrollierten Workspace pro Engagement, beschränke Downloads/Uploads/Clipboard, deaktiviere persönliche Identity Provider, leite seinen festen Egress über die genehmigte Bastion und lasse den Workspace nach dem Evidence-Export ablaufen. Behandle die Provider Console, den IdP und den Administrator als Beobachter.

## I2P und interne Overlays

I2P erstellt separate unidirektionale Inbound- und Outbound-Tunnel und verfügt über keine offiziellen Network-Layer-Exits; es ist hauptsächlich für Services innerhalb von I2P gedacht.<sup>[[8]](#references)</sup> Es ist kein schnellerer Drop-in-Ersatz für das Browsing im öffentlichen Internet. Outproxies führen einen Trust Point ein, und das offizielle Threat Model fordert ausdrücklich weitere Forschung und behauptet keine perfekte Anonymität.

Verwende I2P nur, wenn beide Seiten es absichtlich unterstützen, isoliere seinen langlebigen Router von persönlichen Anwendungen und verstehe, dass Peers/lokale Netzwerke die I2P-Teilnahme beobachten können. Erhöhe die Hop-Anzahl nicht und passe die Peer-Auswahl nicht ohne Belege an: Ungewöhnliche Einstellungen können die Performance verringern und die Anonymity Set verkleinern.

## Korrelation-resistente Operationen

- Bevorzuge eine übliche, unterstützte Client-Konfiguration gegenüber einem einzigartigen Build.
- Trenne Identitäten am Endpoint; keine Routing-Topologie repariert Account-, Zahlungs-, Recovery- oder Content-Wiederverwendung.
- Bevorzuge für nicht-interaktive Aufgaben ein geprüftes asynchrones Protokoll/Mixnet gegenüber dem manuellen Hinzufügen von Sleeps oder Fake Traffic.
- Vermeide es, vermeintlich getrennte Identitäten aus demselben physischen Kontext in einem synchronisierten Muster zu betreiben.
- Verwende ein One-Way-Export-Gate: Untrusted Content gelangt in einen Disposable Renderer; nur ein geprüfter, bereinigter Output verlässt ihn.
- Halte Uhren für die Protokollsicherheit korrekt, entferne jedoch unnötig präzise Zeitstempel aus veröffentlichten Artefakten.
- Minimiere die Session-Dauer und veraltete Infrastruktur, ohne eine schnelle „Fast-Flux“-Rotation einzusetzen, die auffällig ist und die Nachvollziehbarkeit beeinträchtigt.

## Techniken, die keine unbeteiligten Dritten verwenden dürfen

Dies sind echte Adversary-Techniken, keine imaginären oder unwichtigen. Ihre Funktionsweise und Erkennung werden in [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) und den [APT case studies](government-and-apt-case-studies.md) behandelt. Reproduziere während einer autorisierten Übung ihr beobachtbares Verhalten mit eigenen Ersatzsystemen:

- simuliere Residential-/Mobile-Egress-Churn mit kontrollierten Relay-Pools, niemals mit Märkten unklarer Zustimmung;
- simuliere Open Proxies, kompromittierte Router und Botnets mit eigenen VMs/Routern;
- simuliere gestohlene Cloud-Accounts mit einem dafür vorgesehenen Exercise-Tenant und einer synthetischen Opferidentität;
- simuliere Domain Fronting auf einem eigenen Reverse Proxy statt auf einem unfreiwillig genutzten CDN;
- simuliere Third-Party-Wi-Fi mit zwei isolierten, dem Lab gehörenden APs;
- behandle Custom Encryption, Multi-VPN-Chains und Identifier Rotation als Test-Hypothesen, deren Flow-, Account- und Endpoint-Artefakte weiterhin erkennbar bleiben.

Für ein autorisiertes Red Team muss jeder Versuch, Traffic weniger erkennbar zu machen, ein ausdrückliches Detection Objective im ROE sein, über eine vom Controller verwahrte Attribution Map verfügen und einen Stop-/Deconfliction-Mechanismus enthalten.

## Verifikationsmatrix

| Test | Erwartetes Ergebnis | Fehler bedeutet |
|---|---|---|
| Tunnel/Bridge gestoppt | Workload hat keinen direkten IPv4-/IPv6-/DNS-Pfad | Route Enforcement ist unvollständig |
| Target-Log inspiziert | Nur der geplante Egress/die Application-Identity erscheint | Header-, Routen- oder Account-leak |
| Ingress-Log inspiziert | Source vorhanden; klares Target/Request fehlt | Trust Split am Ingress fehlgeschlagen |
| Egress-Log inspiziert | Relay/Request vorhanden; Source-Identity fehlt | Trust Split am Egress fehlgeschlagen |
| Onion-Origin extern gescannt | Kein öffentlicher Origin-Service ist erreichbar/verknüpft | Origin geleakt oder dual-homed |
| Disposable-Session beendet | Instanzstatus verschwunden; genehmigte Evidence separat erhalten | Persistenzgrenze fehlgeschlagen |
| Controller-Lookup durchgeführt | Aktivität wird zeitnah Engagement/Operator zugeordnet | Red-Team-Accountability fehlgeschlagen |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
