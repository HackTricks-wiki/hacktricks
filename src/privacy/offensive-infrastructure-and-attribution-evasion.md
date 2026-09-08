# Offensive Infrastruktur und Attribution-Evasion

Ein Operator erlangt nur selten durch einen einzelnen Proxy eine nennenswerte Anonymität. Reale Kampagnen erstellen einen **Separation Graph**: Der Operator erreicht einen Access Node, Traversal Nodes verbergen diesen Node vor dem Exit, Redirectors schützen das tatsächliche C2, und kurzlebige Namen verweisen auf den öffentlichen Edge.

Verwende den [Katalog für Techniken des anonymen Internetzugangs](anonymous-internet-access-techniques.md) für eine normalisierte Übersicht über Vor- und Nachteile, Deployment und Detection jedes Pfads. Diese Seite geht tiefer auf die Zusammensetzung adversarialer Infrastruktur ein.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Die letzte von einem Ziel gesehene Adresse ist daher ein Beleg für einen Pfad, nicht der Beweis dafür, wer die Tastatur kontrolliert hat. MITRE ordnet die wichtigsten Komponenten den Bereichen Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) und Web Service (T1102) zu.<sup>[[1]](#references)</sup>

## Infrastructure-Klassen

| Klasse | Warum ein Akteur sie verwendet | Dauerhafte Spuren | Bester Ansatzpunkt für Defender |
|---|---|---|---|
| Gemietete VPS/cloud | Schnell, vorhersehbar, routbar und einfach neu aufzusetzen | Tenant-, Abrechnungs-, Konsolen-, Source-Login- und Image-Historie | Account-/Control-Plane-Ereignisse und wiederkehrender Server-Fingerprint |
| Kommerzielles VPN/Tor | Große gemeinsame Egress-Menge; keine Serveradministration | Provider-/Guard-Sichtbarkeit und Ende-zu-Ende-Timing | Zielverhalten, Endpoint-Belege und Flow-Korrelation |
| Residential-/Mobile-Proxy | Consumer-ASN und geografische Plausibilität | Broker-/Kundendaten; Proxyware- oder infizierten-Host-Verhalten | Impossible Travel, Proxy-Protokolle und Adresswechsel pro Session |
| Kompromittierter Server/Router/IoT | Nutzt die Reputation und Jurisdiktion des Opfers | Implant, Management-Flow und wiederkehrender Upstream-Controller | Geräte-Telemetrie und ORB-Topologie, nicht eine einzelne Exit-IP |
| CDN/Redirector | Trennt den öffentlichen Edge vom Backend-C2 | TLS-/HTTP-Grammatik, Zertifikat, Routing- und Cloud-Account-Artefakte | Edge-to-Origin-Korrelation und Clustering der Request-Struktur |
| Legitimater Web Service | Verschmilzt mit erlaubtem GitHub-/Cloud-/Social-Traffic | API-Token, Tenant-/Objekt-Identifier und ungewöhnliche Process-Lineage | Endpoint-Prozess plus Service-/API-Semantik |
| Physischer/mobiler/satellitengestützter Pfad | Verändert den scheinbaren physischen Ursprung | RF-, Carrier-, Teilnehmer-, Geräte- und Standortdaten | Kombinierte Funk-/physische und Netzwerkbelege |

## Netzwerke aus operativen Relay-Boxen

Ein **ORB-Netzwerk** ist eine verwaltete Proxy-Flotte, die als Zwischenservice verwendet wird. Mandiant unterteilt sie in provisionierte Netzwerke aus geleasten Servern, nicht provisionierte Netzwerke aus kompromittierten Routern/IoT-Geräten sowie Hybride. Eine ausgereifte Topologie besitzt vier logische Rollen:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** Verwaltet Inventar, Zugangsdaten, Zustand und Routing-Policy.
2. **Access/relay node:** Authentifiziert Kunden oder Operatoren; er ist der stabile Einstieg in ein sich veränderndes Mesh.
3. **Traversal nodes:** Ein oder mehrere geleaste oder kompromittierte Systeme leiten undurchsichtige Verbindungen weiter.
4. **Exit/staging node:** Präsentiert Reconnaissance-, Exploitation- oder C2-Zielen die endgültige Quelladresse.

Das Mesh kann Exits nach Land, ASN, Latenz oder Verfügbarkeit auswählen und ausgefallene Nodes austauschen. Mehrere Threat Groups können dasselbe Netzwerk mieten. Mandiant beobachtete, dass eine IPv4-Adresse nur 31 Tage lang mit bestimmten ORBs verbunden blieb; daher empfiehlt Mandiant, das **Netzwerk als eine sich weiterentwickelnde, akteursähnliche Einheit** zu behandeln, anstatt eine veraltete IP-Liste zu blockieren.<sup>[[2]](#references)</sup>

### Was dies ermöglicht – und was es leakt

- Das Ziel sieht einen Exit, der geografisch nahegelegen und scheinbar residential sein kann.
- Der Exit sieht das Ziel und den vorherigen Hop, jedoch nicht zwangsläufig den Operator.
- Der Access-Service sieht den Kunden und die Routenanfrage. Ein unabhängig verwaltetes Mesh kann den Kunden von den Exits trennen, erzeugt jedoch einen aussagekräftigen Datensatz beim Gegenüber.
- Wiederkehrende Ports, Handshake-Reihenfolge, Server-Banner, Zertifikate, Uptime-Zeitfenster und Controller-Beziehungen können die Flotte offenlegen, selbst wenn sich die IPs ändern.
- Ein kompromittierter Router verfügt häufig über keine Endpoint-Telemetrie, sein ISP besitzt jedoch weiterhin Teilnehmer- und Flow-Daten; eine Beschlagnahmung legt Implant-/Konfigurationsartefakte offen.

{% hint style="info" %}
Für eine autorisierte Übung kann die Topologie mit organisations­eigenen VMs oder Routern nachgebildet werden; die Attributionskarte des Controllers ist aufzubewahren. Keine offenen Proxies oder Geräte Dritter rekrutieren. Der [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) erstellt dieselbe für Defender sichtbare Hop-Struktur, ohne einen Vermittler zum Opfer zu machen.
{% endhint %}

## Residential- und Mobile-Proxy-Netzwerke

Residential-Proxy-Services weisen Sessions Consumer-Breitbandadressen zu; Mobile-Proxies nutzen für ihren Egress Carrier-NAT-Pools. Das Angebot kann aus ausdrücklich registrierten Geräten, in Consumer-Anwendungen gebündelter SDK-/Proxyware, Resellern oder Malware stammen. Diese Ursprünge sind nicht gleichwertig: Fehlende informierte Einwilligung macht aus einem Privacy-Service kompromittierte Infrastruktur.

Rotationsmodi beeinflussen die Detection:

- **per-request rotation** erzeugt schnelle Diskontinuitäten bei IP, ASN und Geografie, während die Identität auf höheren Schichten stabil bleibt;
- **sticky sessions** halten einen Exit Minuten oder Stunden lang aufrecht und ähneln einem gewöhnlichen Teilnehmer;
- **backconnect gateways** stellen dem Kunden einen einzelnen Broker-Endpunkt bereit und wählen die Exits intern aus;
- **mobile pools** platzieren viele echte Teilnehmer hinter einer kleinen Anzahl von Carrier-NAT-Adressen, wodurch ein IP-Block kostspielig wird.

Defender sollten die IP mit der authentifizierten Session, dem TLS-/Client-Fingerprint, der HTTP-Reihenfolge, dem Device-Cookie und dem Verhalten korrelieren. Ein angeblich lokaler Residential-Login, auf den ein weiteres Land folgt, während alle Merkmale auf höheren Schichten identisch bleiben, ist aussagekräftiger als Reputation allein. Umgekehrt erzeugen Adress-Sharing und Mobile-Handoffs legitime Wechsel; daher darf die Einstufung als Residential-/Proxy-Adresse niemals als endgültiges Urteil behandelt werden.

## Multi-Hop-Proxy-Ketten

MITRE unterscheidet externe Proxies von **Multi-Hop-Proxies (T1090.003)**. Entscheidend ist nicht die Anzahl der Hops, sondern die Trennung von Wissen und Administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Wenn eine Partei A und B betreibt, können gemeinsame Logs oder das Timing des Datenflusses den Circuit rekonstruieren. Das Hinzufügen aufeinanderfolgender kommerzieller VPNs vom selben Endpunkt/Account kann zwar Latenz hinzufügen, aber gemeinsame Identitäts-, Zahlungs- und Timing-Nachweise bestehen lassen. Tor reduziert dieses Problem durch unabhängig ausgewählte Relays und ein gemeinsames Client-Design, aber ein interaktives Netzwerk mit niedriger Latenz kann keine Resistenz gegen einen Beobachter versprechen, der beide Enden misst.

Häufige Fehler sind DNS- oder IPv6-Bypass, Anwendungen, die eigene Sockets öffnen, Management-Traffic, der Relays direkt erreicht, synchronisierte Aktivitäten, wiederverwendete SSH-Schlüssel und das Einloggen in identifizierende Accounts. Die korrekte Verifizierung ist ein Ausfalltest: Stoppe jedes Relay nacheinander und zeige, dass die Workload nicht auf einen direkten Pfad zurückfallen kann.

## Redirector-Tiers und Traffic Shaping

Ein öffentlicher **Redirector** akzeptiert Traffic, der einer operationsspezifischen Grammatik entspricht, und leitet ihn an einen geschützten Teamserver weiter. Alles andere kann abgelehnt oder mit unauffälligem Inhalt bedient werden.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Mehrere Ebenen begrenzen die Offenlegung: Das Aufgeben einer öffentlichen Domain muss den Teamserver nicht offenlegen. CDNs bieten Anycast-Kapazität und eine seriös wirkende äußere Domain, doch das CDN-Konto und die Edge-Logs werden zu Attributionspunkten. TLS-Fingerprints, Zertifikatshistorien, charakteristische Pfade/Header-Reihenfolgen, Antwortgrößen, Redirect-Verhalten und Origin-Allowlists können vermeintlich unabhängige Fronts gruppieren.

Für die Erkennung sollten Reverse-Proxy-Felder vor der Normalisierung aufgezeichnet, SNI/Host/Authority verglichen, seltene Header-Kombinationen untersucht, Antwort-Bodies und TLS-Fingerprints gruppiert sowie Cloud-/CDN-Audit-Logs nach Konfigurationsüberschneidungen durchsucht werden. Bei autorisierten Red Teams sollte nicht die Identität einer realen Marke kopiert und keine Credential-Sammlung hinter einem unabhängigen Drittanbieter platziert werden.

## Domain fronting and domainless fronting

Beim klassischen **domain fronting (T1090.004)** kündigt die TLS-Verbindung eine erlaubte Front-Domain in SNI an, während der verschlüsselte HTTP-`Host`- oder HTTP/2-`:authority`-Wert eine andere Back-End-Domain anfordert. Ein kooperierendes CDN routet anhand des inneren Werts. Ein Netzwerkbeobachter ohne TLS-Entschlüsselung sieht die Front; das CDN sieht beide Werte und den Origin. Bei domainless-Varianten kann SNI leer sein, während ein anderes Routing-Feld das Ziel auswählt.<sup>[[4]](#references)</sup>

Dies ist keine magische Identitätsvortäuschung: Es funktioniert nur, wenn der Intermediär die Abweichung absichtlich oder versehentlich zulässt und weiß, wie der innere Name geroutet werden soll. Große Anbieter haben accountübergreifendes Fronting eingeschränkt. Encrypted ClientHello (ECH) verändert, was ein Beobachter auf dem Übertragungsweg sehen kann, beseitigt jedoch keine CDN-, Endpoint- oder Anwendungsaufzeichnungen.

Zu den Erkennungspunkten gehören:

- Prozessabstammung des Endpoints und ein für die Anwendung unerwartetes Ziel;
- Abweichung zwischen SNI und HTTP-Authority, sofern TLS-Inspektion rechtmäßig und verfügbar ist;
- CDN-Logs, die zeigen, dass ein Tenant/Front zu einer anderen Authority/einem anderen Origin routet;
- ungewöhnliche langlebige oder periodische Sessions zu einem normalerweise interaktiven Service;
- stabile Größen und Taktung verschlüsselter Datenströme über wechselnde Front-Domains hinweg.

Das sichere Lab simuliert die Routing-Abweichung auf einem eigenen Reverse Proxy und missbraucht kein öffentliches CDN.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic Resolution entkoppelt einen logischen Service von einer festen Infrastruktur:

- **DDNS:** Ein authentifizierter Client aktualisiert einen stabilen Namen, nachdem sich seine Adresse geändert hat.
- **DGA:** Endpoint und Controller leiten aus einem Zeit-/Key-Seed beide mögliche Domainnamen ab; der Operator registriert eine kleine Teilmenge.
- **Fast flux:** Ein Name liefert eine sich schnell ändernde Menge kompromittierter/als Proxy eingesetzter Adressen zurück, häufig mit niedrigen TTLs.
- **Double flux:** Sowohl Service-Adressen als auch autoritative Nameserver-Adressen rotieren, wodurch zusätzlich die Control-Ebene verborgen wird.

Fast flux ist ein adversariales Muster zur Lastverteilung und nicht lediglich „viele DNS-Antworten“. Stärkere Belege kombinieren niedrige TTLs, eine hohe Anzahl eindeutiger Adressen, große ASN-/geografische Streuung, kurze Lebensdauer der Nodes, wiederholtes Anwendungsverhalten und eine verdächtige Registrierungshistorie. CDNs weisen legitimerweise mehrere dieser Eigenschaften auf. MITRE empfiehlt, DNS-Verhalten mit dem Prozess und nachfolgenden Verbindungen zu korrelieren.<sup>[[5]](#references)</sup>

Eine DGA kann durch lexikalische Entropie, Konsonanten-/Ziffernmuster, NXDOMAIN-Ausbrüche, synchronisierte First-Seen-Domains und Prozesskontext erkannt werden. Wordlist-DGAs und generative Modelle umgehen einfache Entropieregeln, wodurch temporales Clustering über die gesamte Flotte und die Endpoint-Abstammung wichtiger werden.

## Compromised domains and domain shadowing

Ein Akteur kann ein Registrar-/DNS-Konto hijacken, eine verwaiste Subdomain übernehmen oder Records unterhalb einer ansonsten seriösen Domain hinzufügen. **Domain shadowing** bewahrt den legitimen Apex, während eine große Zahl vom Angreifer kontrollierter Subdomains auf wechselnde Delivery- oder C2-Hosts zeigt. Dadurch werden Alter und Reputation übernommen, und eine Domain-weite Blockierung kann umgangen werden.<sup>[[6]](#references)</sup>

Verteidiger benötigen Audit-Logs von Registrar und autoritativem DNS, MFA, Registry-/Registrar-Locks, Warnungen für neue Delegationen/API-Tokens/Nameserver, Certificate-Transparency-Monitoring sowie ein Inventar der von DNS referenzierten Cloud-Ressourcen. Die Auflösung und Zertifikatshistorie einer Subdomain sollte unabhängig von der Reputation des Apex untersucht werden.

## Web services and dead-drop resolvers

Ein **dead-drop resolver (T1102.001)** speichert einen codierten Zeiger auf das aktuelle C2 in einem legitimen Post, Profil, Dokument, Repository, Cloud-Objekt oder Blockchain-Feld. Malware ruft das öffentliche Objekt ab, decodiert eine Domain/IP und kontaktiert die nächste Stufe. Bidirektionale Varianten tauschen Befehle oder Dateien über Service-APIs aus.<sup>[[7]](#references)</sup>

Dies bietet Resilienz und verbirgt das Back-End-C2 vor statischer Binary-Analyse. Gleichzeitig entstehen stabile Identifikatoren für Objekte, Tenants, Repositories, APIs und Zugriffsmuster. Verteidiger sollten Folgendes zusammenführen:

1. den Prozess, der den Service kontaktiert hat;
2. den exakten API-Pfad/das Objekt und den Response-Hash;
3. Decoding- oder String-Verarbeitungsaktivitäten;
4. die neue ausgehende Verbindung kurze Zeit später; und
5. identisches Verhalten an anderen Stellen der Flotte.

Das Blockieren von ganz GitHub, Cloud Storage oder Social Media ist selten praktikabel. Service-bewusste Egress-Policy und Korrelation auf Prozessebene sind einer Blockierung nur anhand von Domains überlegen.

## Personas, accounts and procurement compartments

Die Anonymität der Infrastruktur scheitert, wenn eine Persona, Recovery-E-Mail, Telefonnummer, Zahlung, ein Browser oder eine Admin-IP Compartments miteinander verbindet. Staatlich verbundene Operationen haben Social-Profile, E-Mail-Identitäten und Cloud-Konten lange vor ihrer Nutzung aufgebaut; ATT&CK erfasst dies als Establish Accounts (T1585), einschließlich Social-, E-Mail- und Cloud-Subtechniken.<sup>[[8]](#references)</sup>

Ein Verteidiger oder Ermittler erstellt einen Graphen aus:

- Erstellungs- und Erstlogin-Zeit, Locale, Zeitzone und Arbeitszeitplan;
- Recovery-Feldern, MFA-Geräten, Identitätsdokumenten und Zahlungsmitteln;
- Browser-/TLS-Fingerprints und Verlauf der Quellnetzwerke;
- Wiederverwendung von Avataren, Bildherkunft, Schreibstil und Wachstum des sozialen Graphen;
- gemeinsamem Domain-Registrant, Nameserver, Zertifikat, Analytics-ID oder Repository-Commit;
- Aktionen auf der Management-Ebene, die die öffentliche Relay-Architektur umgehen.

Bei einem autorisierten Red Team sollten synthetische Personas gegenüber dem Übungsleiter dokumentiert werden, organisations­eigene Recovery-/Zahlungskanäle verwenden, die Imitation realer unbeteiligter Personen vermeiden und einen geplanten Rückzug besitzen. Das SOC darf weiterhin blind bleiben; die Operation darf jedoch nicht unverantwortlich werden.

## Emerging compound patterns to threat-model

Die folgenden Muster sind **verteidigerorientierte Kombinationen** und keine Behauptungen, dass ein genannter Akteur jedes exakt beschriebene Design eingesetzt hat. Sie kombinieren bereits beobachtete Primitive und eignen sich als Purple-Team-Hypothesen.

### Asymmetric one-way tasking

Befehle treffen über eine öffentliche, broadcastende oder nur anhängende Quelle ein, während Ergebnisse nach einer Verzögerung über einen unabhängigen Kanal abfließen. Beispiele für das Primitive sind Web-Service-One-Way-Communication und Dead Drops. Die Trennung verhindert, dass ein einzelner Datenstrom bidirektional wirkt, und erschwert eine einfache Request-/Response-Korrelation.<sup>[[9]](#references)</sup>

**Detection:** Objektbezogene Lesevorgänge bewahren und anschließend Prozesszustandsänderungen sowie spätere ausgehende Transfers über ein größeres Zeitfenster korrelieren. Nach einem seltenen Prozess suchen, der dasselbe öffentliche Objekt liest, selbst wenn keine unmittelbare Antwort folgt.

### Multi-stage channel promotion

Eine unauffällige erste Stufe führt Inventarisierung durch und befördert nur ausgewählte Systeme zu einem unabhängigen zweiten Stufenkanal. Der zweite Endpoint, das Protokoll und der Prozess können keinerlei Infrastruktur mit der ersten Stufe gemeinsam haben. Dies begrenzt die Offenlegung leistungsfähiger Infrastruktur und wird ausdrücklich als ATT&CK T1104 modelliert.<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` zusammenführen; den Incident nicht beenden, nachdem die erste Domain blockiert wurde.

### Cross-protocol relay translation

Verschiedene Hops übersetzen HTTPS, QUIC, WebSocket, DNS, SSH oder eine Message-Queue-API, anstatt Pakete transparent weiterzuleiten. Die Übersetzung entfernt einen einzelnen durchgängigen Protokoll-Fingerprint, erzeugt jedoch Gateways mit charakteristischem Timing, Buffering und semantischer Konvertierung. Protocol Tunneling (T1572) kann mit Proxies und Service Impersonation kombiniert werden.<sup>[[11]](#references)</sup>

**Detection:** Nach Gateway-Hosts suchen, die ein Protokoll empfangen und ein anderes mit eng gekoppeltem Byte-/Zeitverhalten initiieren; die Absicht des Endpoints mit dem tatsächlich übertragenen Protokoll vergleichen.

### Passive activation on edge devices

Statt zu beaconen überwacht ein Implant den Datenverkehr, der bereits einen Router/VPN erreicht, und aktiviert sich nur bei einem Magic Value, Source-Port-Muster oder authentifizierten Token. Normaler Datenverkehr wird weiterhin an den echten Service geleitet. ATT&CK bezeichnet dies als Traffic Signaling (T1205), mit dokumentierten Beispielen für Netzwerkgeräte und APTs.<sup>[[12]](#references)</sup>

**Detection:** Firmware-/Dateiintegrität, Raw-Packet-Capture während eines autorisierten Hunts, unerwartete Socket-Filter und differentiales Service-Verhalten. Das Fehlen eines periodischen Beacons beweist nicht, dass ein Edge-Gerät sauber ist.

### Serverless and ephemeral origin rotation

Eine Front bewahrt eine stabile logische Identität, während kurzlebige Functions/Container einzelne Stufen in mehreren Regionen/Accounts verarbeiten. Dies reduziert die Lebensdauer auf dem Datenträger und feste Origin-IPs, doch die Erstellung auf der Control-Ebene, Image-/Layer-, Rollen-, Secret-, Request-ID- und Billing-Telemetrie werden zum dauerhaften Graphen.

**Detection:** Cloud-Audit- und Invocation-Logs außerhalb der Workload aufbewahren; Deployment-Templates, Rollen, Environment Keys und Front-to-Origin-Beziehungen gruppieren.

### Privacy-layer diversity

Eine Operation kann eine homogene Kette bewusst vermeiden: Beispielsweise nutzt ein Kanal ein gemietetes Relay, Tasking ein öffentliches Objekt, ein Exit einen eigenen Labor-Mobilfunklink und die Administration ein separates Organisationsnetzwerk. Dies reduziert den Nutzen einer Kompromittierung eines einzelnen Anbieters, erhöht jedoch das Risiko von Timing- und Betriebsfehlern über mehrere Ebenen hinweg.

**Detection:** Kampagnen-Zeitlinien über Identity-, DNS-, SaaS-, Netzwerk- und Cloud-Sensoren erstellen. Nach synchronisierten Zustandsübergängen statt nach identischen Indikatoren suchen.

### Decentralized or transparency-log dead drops

Ein Akteur kann einen kleinen verschlüsselten Zeiger in jedem dauerhaften öffentlichen Append-only-System, content-addressed Store oder Transparency-ähnlichen Feed platzieren. Das öffentliche Objekt ist resilient, doch sein exakter Index/Content-Hash und das Polling-Verhalten des Clients werden zu stabilen Identifikatoren.

**Detection:** Vollständige API-/Objekt-Identifikatoren und Response-Hashes aufzeichnen; auf nichtstandardmäßige Prozesse hinweisen, die unveränderliche Objekte abfragen, gefolgt von Decoding oder neuen Verbindungen.

### Delayed store-and-forward operations

Interaktives C2 erzeugt eine starke zeitliche Korrelation. Ein Store-and-forward-Design bündelt verschlüsselte Jobs und liefert Ergebnisse Minuten oder Stunden später über eine andere Queue oder physische Übertragung zurück. Es opfert Reaktionsfähigkeit zugunsten einer schwächeren End-to-End-Zeitkorrelation.

**Detection:** Korrelationsfenster verlängern, periodischen Queue-Zugriff modellieren und Endpoint-Staging untersuchen. Batching verlagert das Signal vom Packet-Timing auf geplantes Prozess-/Dateiverhalten; es beseitigt es nicht.

## Design review: think in observers

Für jeden Pfad diese Tabelle vor der Bereitstellung und nach der Datenerfassung ausfüllen:

| Ebene | Sieht die Quelle? | Sieht das Ziel? | Sieht den Inhalt? | Stabile Identifikatoren | Aufbewahrung/rechtlich Verantwortlicher |
|---|---:|---:|---:|---|---|
| lokales Netzwerk/Carrier | | | | | |
| Entry-/Access-Service | | | | | |
| Traversal-Operator(en) | | | | | |
| Exit/Redirector/CDN | | | | | |
| autoritativer DNS/Registrar | | | | | |
| Ziel | | | | | |
| Account-/Zahlungsanbieter | | | | | |

Wenn ein gewöhnlicher Anbieter jede Spalte ausfüllen kann, bietet die Architektur zwar Verschleierung gegenüber dem Ziel, jedoch keine robuste Trennung. Wenn kein interner Controller Aktivitäten einem Engagement zuordnen kann, ist die Architektur für professionelles Red Teaming ungeeignet.

## References

- [1] [MITRE ATT&CK — Infrastruktur beschaffen (T1583), Infrastruktur kompromittieren (T1584) und Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nahe Spionageakteure nutzen ORB-Netzwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
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
