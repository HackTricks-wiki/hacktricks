# Offensive Infrastruktur und Umgehung der Zuordnung

{{#include ../banners/hacktricks-training.md}}

Ein Operator erlangt nur selten durch einen einzelnen Proxy eine echte Anonymität. Reale Kampagnen bauen einen **Trennungsgraphen** auf: Der Operator erreicht einen access node, Traversal Nodes verbergen diesen Node vor dem Exit, Redirectors schützen das echte C2, und Wegwerfnamen verweisen auf den öffentlich sichtbaren Rand.

Verwende den [Katalog für Techniken des anonymen Internetzugangs](anonymous-internet-access-techniques.md) für eine standardisierte Übersicht über Vor- und Nachteile, Bereitstellung und Erkennung jedes Pfads. Diese Seite geht ausführlicher auf die Zusammensetzung adversärer Infrastruktur ein.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Die letzte von einem Ziel beobachtete Adresse ist daher ein Beleg für einen Pfad, nicht der Beweis dafür, wer die Tastatur kontrolliert hat. MITRE ordnet die wesentlichen Komponenten den Techniken Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) und Web Service (T1102) zu.<sup>[[1]](#references)</sup>

## Infrastrukturklassen

| Klasse | Warum ein Akteur sie verwendet | Dauerhafte Spuren | Bester Ansatzpunkt für Defender |
|---|---|---|---|
| Gemietete VPS/cloud | Schnell, vorhersehbar, routbar und einfach neu aufzusetzen | Tenant-, Abrechnungs-, Konsolen-, Source-Login- und Image-Verlauf | Account-/Control-Plane-Ereignisse und wiederkehrender Server-Fingerprint |
| Kommerzielles VPN/Tor | Großer gemeinsamer Egress-Pool; keine Serveradministration | Provider-/Guard-Sichtbarkeit und Ende-zu-Ende-Timing | Zielverhalten, Endpoint-Beweise und Flow-Korrelation |
| Residential-/Mobile-Proxy | Consumer-ASN und geografische Plausibilität | Broker-/Kundendaten; Proxyware- oder infiziertes Host-Verhalten | Unmögliche Ortswechsel, Proxy-Protokolle und adressbasierte Session-Rotation |
| Kompromittierter Server/Router/IoT | Nutzt Reputation und Jurisdiktion des Opfers | Implantat, Management-Flow und wiederkehrender Upstream-Controller | Geräte-Telemetrie und ORB-Topologie, nicht eine einzelne Exit-IP |
| CDN/Redirector | Trennt den öffentlichen Edge vom Back-End-C2 | TLS-/HTTP-Grammatik, Zertifikat, Routing- und Cloud-Account-Artefakte | Korrelation zwischen Edge und Origin sowie Clustering der Request-Form |
| Legitimer Web Service | Fügt sich in erlaubten GitHub-/Cloud-/Social-Traffic ein | API-Token, Tenant-/Objekt-IDs und ungewöhnliche Prozessabstammung | Endpoint-Prozess plus Service-/API-Semantik |
| Physischer/zellularer/satellitengestützter Pfad | Verändert den scheinbaren physischen Ursprung | RF-, Carrier-, Teilnehmer-, Geräte- und Standortdaten | Kombinierte Funk-/physische und Netzwerkbeweise |

## Netzwerke mit operativen Relay-Boxen

Ein **ORB network** ist eine verwaltete Proxy-Flotte, die als zwischengeschalteter Service verwendet wird. Mandiant unterteilt sie in provisionierte Netzwerke aus geleasten Servern, nicht provisionierte Netzwerke aus kompromittierten Routern/IoT-Geräten und hybride Netzwerke. Eine ausgereifte Topologie besitzt vier logische Rollen:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** Verwaltet Inventar, Zugangsdaten, Zustand und Routing-Richtlinien.
2. **Access/relay node:** Authentifiziert Kunden oder Operatoren; dies ist der stabile Einstieg in ein sich veränderndes Mesh.
3. **Traversal nodes:** Ein oder mehrere geleaste oder kompromittierte Systeme leiten undurchsichtige Verbindungen weiter.
4. **Exit/staging node:** Präsentiert Reconnaissance-, Exploitation- oder C2-Zielen die endgültige Quelladresse.

Das Mesh kann Exits nach Land, ASN, Latenz oder Verfügbarkeit auswählen und fehlerhafte Nodes rotieren. Mehrere Threat Groups können dasselbe Netzwerk mieten. Mandiant beobachtete, dass eine IPv4-Adresse nur 31 Tage lang mit einigen ORBs verbunden blieb; daher empfiehlt Mandiant, das **Netzwerk als eine sich entwickelnde, einem Akteur ähnelnde Entität** zu behandeln, statt eine veraltete Liste von IPs zu blockieren.<sup>[[2]](#references)</sup>

### Was dies ermöglicht – und was es leakt

- Das Ziel sieht einen Exit, der geografisch nahe und scheinbar einem Residential-Anschluss zugeordnet sein kann.
- Der Exit sieht das Ziel und den vorherigen Hop, nicht unbedingt den Operator.
- Der Access-Service sieht den Kunden und die Routenanforderung. Ein unabhängig verwaltetes Mesh kann den Kunden von den Exits trennen, erzeugt jedoch einen aussagekräftigen Datensatz beim jeweiligen Gegenüber.
- Wiederkehrende Ports, Handshake-Reihenfolge, Server-Banner, Zertifikate, Betriebszeitfenster und Controller-Beziehungen können die Flotte offenlegen, selbst wenn die IPs rotieren.
- Ein kompromittierter Router verfügt häufig über keine Endpoint-Telemetrie, doch sein ISP besitzt weiterhin Teilnehmer- und Flow-Daten; eine Beschlagnahmung legt Implantat-/Konfigurationsartefakte offen.

{% hint style="info" %}
Für eine autorisierte Übung sollte die Topologie mit organisations-eigenen VMs oder Routern nachgebildet und die Attribution-Map des Controllers aufbewahrt werden. Keine offenen Proxies oder Geräte Dritter rekrutieren. Der [Lab-Leitfaden](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) erstellt dieselbe für Defender sichtbare Hop-Struktur, ohne einen Vermittler zum Opfer zu machen.
{% endhint %}

## Residential- und Mobile-Proxy-Netzwerke

Residential-Proxy-Services weisen Sessions Consumer-Breitbandadressen zu; Mobile-Proxies verlassen das Netzwerk über Carrier-NAT-Pools. Die Versorgung kann von ausdrücklich registrierten Geräten, in Consumer-Anwendungen gebündelter SDK-/Proxyware, Resellern oder Malware stammen. Diese Ursprünge sind nicht gleichwertig: Fehlende informierte Einwilligung macht aus einem Privacy-Service kompromittierte Infrastruktur.

Rotationsmodi beeinflussen die Erkennung:

- **Rotation pro Request** erzeugt schnelle Diskontinuitäten bei IP, ASN und Geografie, während die Identität auf höheren Protokollebenen stabil bleibt;
- **Sticky Sessions** behalten einen Exit für Minuten oder Stunden bei und ähneln dadurch einem gewöhnlichen Teilnehmer;
- **Backconnect-Gateways** stellen dem Kunden einen einzigen Broker-Endpunkt bereit und wählen die Exits intern aus;
- **Mobile Pools** platzieren viele echte Teilnehmer hinter einer kleinen Anzahl von Carrier-NAT-Adressen, wodurch ein IP-Block kostspielig wird.

Defender sollten die IP mit der authentifizierten Session, dem TLS-/Client-Fingerprint, der HTTP-Reihenfolge, dem Geräte-Cookie und dem Verhalten korrelieren. Ein angeblich lokaler Residential-Login, auf den ein Login aus einem anderen Land folgt, während alle Merkmale auf höheren Protokollebenen identisch bleiben, ist aussagekräftiger als Reputation allein. Umgekehrt erzeugen Adressfreigabe und Mobile-Handoffs legitime Wechsel, weshalb die Einstufung als Residential-/Proxy-Adresse niemals als endgültiges Urteil behandelt werden sollte.

## Multi-Hop-Proxy-Ketten

MITRE unterscheidet externe Proxies von **Multi-Hop-Proxies (T1090.003)**. Die entscheidende Eigenschaft ist nicht die Anzahl der Hops, sondern die Trennung von Wissen und Administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Wenn eine Partei A und B betreibt, können gemeinsam genutzte Logs oder der zeitliche Ablauf des Datenverkehrs den Circuit rekonstruieren. Das Hinzufügen aufeinanderfolgender kommerzieller VPNs vom selben Endpunkt/Account kann die Latenz erhöhen, während gemeinsame Identitäts-, Zahlungs- und Timing-Daten bestehen bleiben. Tor reduziert dieses Problem durch unabhängig ausgewählte Relays und ein gemeinsames Client-Design, aber ein interaktives Netzwerk mit geringer Latenz kann keine Resistenz gegenüber einem Beobachter versprechen, der beide Enden misst.

Häufige Fehler sind DNS- oder IPv6-Bypass, Anwendungen, die eigene Sockets öffnen, Management-Datenverkehr, der Relays direkt erreicht, synchronisierte Aktivitäten, wiederverwendete SSH-Keys und das Einloggen in identifizierende Accounts. Die korrekte Verifizierung ist ein Ausfalltest: Stoppe jedes Relay nacheinander und zeige, dass die Workload nicht auf einen direkten Pfad zurückfallen kann.

## Redirector tiers und Traffic shaping

Ein öffentlicher **Redirector** akzeptiert Datenverkehr, der einer operationsspezifischen Grammatik entspricht, und leitet ihn an einen geschützten Teamserver weiter. Alles andere kann abgelehnt oder mit harmlosen Inhalten beantwortet werden.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Mehrere Ebenen begrenzen die Sichtbarkeit: Das Aufgeben einer öffentlichen Domain muss den Teamserver nicht offenlegen. CDNs bieten Anycast-Kapazität und eine seriöse äußere Domain, doch das CDN-Konto und die Edge-Logs werden zu Zuordnungspunkten. TLS-Fingerprints, Zertifikatshistorien, charakteristische Pfade/Header-Reihenfolgen, Antwortgrößen, Redirect-Verhalten und Origin-Allowlisten können angeblich unabhängige Fronts clustern.

Für die Erkennung sollten Reverse-Proxy-Felder vor der Normalisierung aufgezeichnet, SNI/Host/Authority verglichen, seltene Header-Kombinationen untersucht, Response-Bodies und TLS-Fingerprints gruppiert und Cloud-/CDN-Audit-Logs nach Konfigurationsüberschneidungen durchsucht werden. Bei autorisierten Red Teams sollte vermieden werden, eine echte Marke zu kopieren oder Credential Collection hinter einem nicht verwandten Drittanbieter zu platzieren.

## Domain fronting und domainless fronting

Beim klassischen **domain fronting (T1090.004)** bewirbt die TLS-Verbindung eine erlaubte Front-Domain in SNI, während der verschlüsselte HTTP-`Host`- oder HTTP/2-`:authority`-Wert eine andere Back-End-Domain anfordert. Ein kooperierendes CDN routet anhand des inneren Werts. Ein Netzwerkbeobachter ohne TLS-Entschlüsselung sieht die Front; das CDN sieht beide Werte und den Origin. Bei domainless-Varianten kann SNI leer sein, während ein anderes Routing-Feld das Ziel auswählt.<sup>[[4]](#references)</sup>

Das ist keine magische Identitätsvortäuschung: Es funktioniert nur, wenn der Vermittler die Abweichung absichtlich oder versehentlich zulässt und weiß, wie der innere Name geroutet werden soll. Große Anbieter haben accountübergreifendes Fronting eingeschränkt. Encrypted ClientHello (ECH) verändert, was ein Beobachter auf dem Übertragungsweg sehen kann, löscht jedoch keine CDN-, Endpoint- oder Application-Aufzeichnungen.

Erkennungspunkte umfassen:

- Prozessabstammung am Endpoint und ein Ziel, das für diese Application nicht erwartet wird;
- Abweichung zwischen SNI und HTTP Authority, sofern TLS Inspection rechtmäßig und verfügbar ist;
- CDN-Logs, die zeigen, dass ein Tenant/Front zu einer anderen Authority/einem anderen Origin routet;
- ungewöhnliche langlebige oder periodische Sessions zu einem normalerweise interaktiven Service;
- stabile verschlüsselte Flow-Größen und -Taktung über wechselnde Front-Domains hinweg.

Das sichere Lab simuliert die Routing-Abweichung auf einem eigenen Reverse Proxy; es missbraucht kein öffentliches CDN.

## Dynamic resolution: DDNS, DGA und fast flux

Dynamic resolution entkoppelt einen logischen Service von fester Infrastruktur:

- **DDNS:** Ein authentifizierter Client aktualisiert einen stabilen Namen, nachdem sich seine Adresse geändert hat.
- **DGA:** Sowohl Endpoint als auch Controller leiten aus einem Zeit-/Key-Seed mögliche Domainnamen ab; der Operator registriert eine kleine Teilmenge.
- **Fast flux:** Ein Name liefert eine sich schnell ändernde Menge kompromittierter/als Proxy eingesetzter Adressen zurück, oft mit niedrigen TTLs.
- **Double flux:** Sowohl Serviceadressen als auch autoritative Nameserver-Adressen rotieren, wodurch zusätzlich die Control Layer verborgen wird.

Fast flux ist ein adversarial verwendetes Load-Distribution-Muster und nicht einfach nur „viele DNS-Antworten“. Stärkere Belege kombinieren niedrige TTLs, eine hohe Anzahl eindeutiger Adressen, breite ASN-/Geografie-Streuung, kurze Node-Lebensdauer, wiederholtes Application-Verhalten und verdächtige Registrierungshistorie. CDNs weisen legitimerweise mehrere dieser Eigenschaften auf. MITRE empfiehlt, DNS-Verhalten mit dem Prozess und nachfolgenden Verbindungen zu korrelieren.<sup>[[5]](#references)</sup>

Eine DGA kann anhand lexikalischer Entropie, Konsonanten-/Ziffernmustern, NXDOMAIN-Schüben, synchronisierten First-Seen-Domains und Prozesskontext erkannt werden. Wordlist-DGAs und generative Modelle umgehen einfache Entropieregeln, wodurch zeitliches Clustering über die gesamte Flotte und die Endpoint-Lineage wichtiger werden.

## Kompromittierte Domains und Domain Shadowing

Ein Akteur kann ein Registrar-/DNS-Konto hijacken, eine verwaiste Subdomain übernehmen oder Records unterhalb einer ansonsten seriösen Domain hinzufügen. **Domain Shadowing** erhält den legitimen Apex, während eine große Anzahl vom Angreifer kontrollierter Subdomains auf wechselnde Delivery- oder C2-Hosts zeigt. Dadurch werden Alter und Reputation übernommen, und ein domainweites Blocking kann umgangen werden.<sup>[[6]](#references)</sup>

Verteidiger benötigen Registrar- und autoritative-DNS-Audit-Logs, MFA, Registry-/Registrar-Locks, Alerts für neue Delegations/API-Tokens/Nameserver, Certificate-Transparency-Monitoring sowie ein Inventar der von DNS referenzierten Cloud-Ressourcen. Die Auflösung und Zertifikatshistorie einer Subdomain sollte unabhängig von der Reputation des Apex untersucht werden.

## Web services und dead-drop resolvers

Ein **dead-drop resolver (T1102.001)** speichert einen codierten Pointer auf das aktuelle C2 in einem legitimen Post, Profil, Dokument, Repository, Cloud-Objekt oder Blockchain-Feld. Malware ruft das öffentliche Objekt ab, decodiert eine Domain/IP und kontaktiert die nächste Stage. Bidirektionale Varianten tauschen Commands oder Files über Service-APIs aus.<sup>[[7]](#references)</sup>

Dies bietet Resilienz und verbirgt das Back-End-C2 vor statischer Binary-Analyse. Gleichzeitig entstehen stabile Objekt-, Tenant-, Repository-, API- und Zugriffsmuster-Identifier. Verteidiger sollten Folgendes zusammenführen:

1. den Prozess, der den Service kontaktiert hat;
2. den exakten API-Pfad/das Objekt und den Response-Hash;
3. Decoding- oder String-Processing-Aktivität;
4. die kurz darauf erfolgende neue Outbound-Verbindung; und
5. identisches Verhalten an anderer Stelle in der Flotte.

Das Blockieren sämtlicher GitHub-, Cloud-Storage- oder Social-Media-Dienste ist selten praktikabel. Service-bewusste Egress-Policy und Korrelation auf Prozessebene sind Domain-only-Blocking überlegen.

## Personas, Accounts und Procurement-Kompartimente

Die Anonymität der Infrastruktur scheitert, wenn eine Persona, Recovery-E-Mail, Telefonnummer, Zahlung, Browser- oder Admin-IP Kompartimente miteinander verbindet. State-linked Operations haben Social Profiles, E-Mail-Identitäten und Cloud-Accounts lange vor ihrer Nutzung aufgebaut; ATT&CK erfasst dies als Establish Accounts (T1585), einschließlich Social-, E-Mail- und Cloud-Subtechniques.<sup>[[8]](#references)</sup>

Ein Verteidiger oder Ermittler erstellt einen Graphen aus:

- Erstellungs- und First-Login-Zeit, Locale, Zeitzone und Arbeitszeitplan;
- Recovery-Feldern, MFA-Geräten, Identitätsdokumenten und Zahlungsmitteln;
- Browser-/TLS-Fingerprints und Verlauf der Quellnetzwerke;
- wiederverwendeten Avataren, Bildherkunft, Schreibstil und Wachstum des Social Graphs;
- gemeinsamem Domain-Registrant, Nameserver, Zertifikat, Analytics-ID oder Repository-Commit;
- Management-Plane-Aktionen, die die öffentliche Relay-Architektur umgehen.

Bei einem autorisierten Red Team sollten synthetische Personas gegenüber dem Exercise Controller dokumentiert werden, organisations-eigene Recovery-/Payment-Kanäle verwenden, die Imitation realer unbeteiligter Personen vermeiden und eine geplante Stilllegung besitzen. Das SOC kann weiterhin blind bleiben; die Operation darf nicht unaccountable werden.

## Aufkommende zusammengesetzte Muster für das Threat Modeling

Die folgenden Beispiele sind **defender-driven compositions** und keine Behauptungen, dass ein genannter Akteur jedes exakte Design eingesetzt hat. Sie kombinieren bereits beobachtete Primitives und sind nützliche Purple-Team-Hypothesen.

### Asymmetric one-way tasking

Commands treffen über eine öffentliche, broadcast- oder append-only-Quelle ein, während Results nach einer Verzögerung über einen nicht verwandten Kanal abfließen. Beispiele für das Primitive sind Web-Service-One-Way-Communication und Dead Drops. Die Trennung verhindert, dass ein einzelner Flow bidirektional wirkt, und erschwert einfache Request-/Response-Korrelation.<sup>[[9]](#references)</sup>

**Detection:** Objektbezogene Reads beibehalten und anschließend Prozesszustandsänderungen sowie spätere Outbound-Transfers über ein größeres Zeitfenster korrelieren. Nach einem seltenen Prozess suchen, der dasselbe öffentliche Objekt liest, auch wenn keine unmittelbare Antwort folgt.

### Multi-stage channel promotion

Eine ruhige First Stage führt Inventarisierung durch und befördert nur ausgewählte Systeme zu einem nicht verwandten Second-Stage-Kanal. Der zweite Endpoint, das Protocol und der Prozess teilen möglicherweise keine Infrastruktur mit der ersten Stage. Dies begrenzt die Sichtbarkeit leistungsfähiger Infrastruktur und wird in ATT&CK ausdrücklich als T1104 modelliert.<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` zusammenführen; den Incident nicht nach dem Blockieren der ersten Domain schließen.

### Cross-protocol relay translation

Unterschiedliche Hops übersetzen HTTPS, QUIC, WebSocket, DNS, SSH oder eine Message-Queue-API, anstatt Pakete transparent weiterzuleiten. Die Übersetzung entfernt einen einzelnen End-to-End-Protocol-Fingerprint, erzeugt jedoch Gateways mit charakteristischem Timing, Buffering und semantischer Konvertierung. Protocol Tunneling (T1572) kann mit Proxies und Service Impersonation kombiniert werden.<sup>[[11]](#references)</sup>

**Detection:** Nach Gateway-Hosts suchen, die ein Protocol empfangen und ein anderes initiieren, mit eng gekoppeltem Byte-/Zeitverhalten; die Absicht des Endpoints mit dem tatsächlich übertragenen Protocol vergleichen.

### Passive activation on edge devices

Statt zu beaconen überwacht ein Implant Traffic, der bereits einen Router/VPN erreicht, und aktiviert sich nur bei einem Magic Value, Source-Port-Muster oder authentifizierten Token. Normaler Traffic wird weiterhin an den echten Service geleitet. ATT&CK bezeichnet dies als Traffic Signaling (T1205), mit dokumentierten Network-Device- und APT-Beispielen.<sup>[[12]](#references)</sup>

**Detection:** Firmware-/File-Integrität, Raw-Packet-Capture während eines autorisierten Hunts, unerwartete Socket-Filter und differentiales Service-Verhalten. Das Fehlen eines periodischen Beacons beweist nicht, dass ein Edge Device sauber ist.

### Serverless and ephemeral origin rotation

Eine Front behält eine stabile logische Identität, während kurzlebige Functions/Container einzelne Stages in mehreren Regionen/Accounts verarbeiten. Dies reduziert die Lebensdauer auf der Festplatte und feste Origin-IPs, doch Control-Plane-Erstellung, Image/Layer, Role, Secret, Request-ID und Billing-Telemetrie werden zum dauerhaften Graphen.

**Detection:** Cloud-Audit- und Invocation-Logs außerhalb des Workloads aufbewahren; Deployment-Templates, Roles, Environment Keys und Front-to-Origin-Beziehungen clustern.

### Privacy-layer diversity

Eine Operation kann absichtlich eine einzige homogene Chain vermeiden: Beispielsweise verwendet ein Kanal ein gemietetes Relay, Tasking ein öffentliches Objekt, ein Exit einen eigenen Cellular-Link im Lab und die Administration ein separates Organisationsnetzwerk. Dies verringert den Nutzen der Kompromittierung eines einzelnen Providers, erhöht jedoch das Risiko durchschlagender Timing- und Operational-Error-Korrelationen über mehrere Ebenen.

**Detection:** Kampagnen-Timelines über Identity-, DNS-, SaaS-, Network- und Cloud-Sensoren erstellen. Nach synchronisierten Zustandsübergängen statt nach identischen Indicators suchen.

### Decentralized or transparency-log dead drops

Ein Akteur kann einen kleinen verschlüsselten Pointer in jedem dauerhaften öffentlichen Append-only-System, Content-addressed Store oder Transparency-ähnlichen Feed platzieren. Das öffentliche Objekt ist resilient, doch sein exakter Index/Content-Hash und das Polling-Verhalten des Clients werden zu stabilen Identifiers.

**Detection:** Vollständige API-/Objekt-Identifier und Response-Hashes aufzeichnen; bei nicht standardmäßigen Prozessen alarmieren, die unveränderliche Objekte pollen und anschließend Decoding oder neue Connections durchführen.

### Delayed store-and-forward operations

Interactive C2 erzeugt eine starke zeitliche Korrelation. Ein Store-and-forward-Design bündelt verschlüsselte Jobs und liefert Results Minuten oder Stunden später über eine andere Queue oder einen physischen Transfer zurück. Es opfert Reaktionsfähigkeit für eine schwächere End-to-End-Timing-Korrelation.

**Detection:** Korrelationsfenster verlängern, periodischen Queue-Zugriff modellieren und Endpoint-Staging untersuchen. Batching verlagert das Signal vom Packet-Timing auf geplantes Prozess-/File-Verhalten; es beseitigt es nicht.

## Design Review: in Observers denken

Für jeden Pfad sollte diese Tabelle vor der Bereitstellung und nach der Sammlung ausgefüllt werden:

| Layer | Sieht Source? | Sieht Destination? | Sieht Content? | Stabile Identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| lokales Netzwerk/Carrier | | | | | |
| Entry-/Access-Service | | | | | |
| Traversal Operator(s) | | | | | |
| Exit/Redirector/CDN | | | | | |
| autoritativer DNS/Registrar | | | | | |
| Target | | | | | |
| Account-/Payment-Provider | | | | | |

Wenn ein gewöhnlicher Provider jede Spalte ausfüllen kann, bietet die Architektur dem Target zwar Concealment, aber keine robuste Trennung. Wenn kein interner Controller Aktivitäten auf ein Engagement zurückführen kann, ist die Architektur für professionelles Red Teaming ungeeignet.

## References

- [1] [MITRE ATT&CK — Infrastruktur beschaffen (T1583), Infrastruktur kompromittieren (T1584) und Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus-Spionageakteure nutzen ORB-Netzwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastruktur kompromittieren: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Accounts einrichten (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
