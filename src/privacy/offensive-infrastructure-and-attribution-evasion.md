# Offensive Infrastruktur und Verschleierung der Zuordnung

{{#include ../banners/hacktricks-training.md}}

Ein Operator erlangt durch einen einzelnen Proxy nur selten echte Anonymität. Reale Kampagnen bauen einen **Trennungsgraphen** auf: Der Operator erreicht einen Zugangsknoten, Traversal-Knoten verbergen diesen Knoten vor dem Exit, Redirectors schützen das echte C2, und kurzlebige Namen verweisen auf den öffentlichen Rand.

Verwende den [Katalog für Techniken des anonymen Internetzugangs](anonymous-internet-access-techniques.md) für eine standardisierte Übersicht über Vor- und Nachteile, Bereitstellung und Erkennung jedes Pfads. Diese Seite geht tiefer auf die Zusammensetzung gegnerischer Infrastruktur ein.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Die letzte von einem Ziel gesehene Adresse ist daher ein Beleg für einen Pfad, nicht der Beweis dafür, wer die Tastatur bedient hat. MITRE ordnet die wesentlichen Komponenten den Bereichen Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) und Web Service (T1102) zu.<sup>[[1]](#references)</sup>

## Infrastrukturklassen

| Klasse | Warum ein Akteur sie nutzt | Dauerhafte Spuren | Bester Ansatzpunkt für Defender |
|---|---|---|---|
| Gemietete VPS/Cloud | Schnell, vorhersehbar, routbar und leicht neu aufzusetzen | Mandant, Abrechnung, Konsole, Quell-Login und Image-Verlauf | Account-/Control-Plane-Ereignisse und wiederkehrender Server-Fingerprint |
| Kommerzielle VPN/Tor | Großer gemeinsamer Egress-Pool; keine Serververwaltung | Sichtbarkeit des Anbieters/Guards und Ende-zu-Ende-Timing | Zielverhalten, Endpoint-Belege und Flow-Korrelation |
| Residential-/Mobile-Proxy | Consumer-ASN und geografische Plausibilität | Broker-/Kundendaten; Proxyware- oder infiziertes Host-Verhalten | Unmögliche Ortswechsel, Proxy-Protokolle und Adresswechsel pro Sitzung |
| Kompromittierter Server/Router/IoT | Leiht sich Reputation und Rechtsraum des Opfers | Implant, Management-Flow und wiederkehrender Upstream-Controller | Geräte-Telemetrie und ORB-Topologie, nicht eine einzelne Exit-IP |
| CDN/Redirector | Trennt den öffentlichen Edge vom Back-end-C2 | TLS-/HTTP-Grammatik, Zertifikat, Routing- und Cloud-Account-Artefakte | Korrelation zwischen Edge und Origin sowie Clustering der Request-Struktur |
| Legitimater Web-Service | Mischt sich in erlaubten GitHub-/Cloud-/Social-Traffic | API-Token, Tenant-/Objektbezeichner und ungewöhnliche Prozessabstammung | Endpoint-Prozess plus Service-/API-Semantik |
| Physischer/mobiler/satellitengestützter Pfad | Verändert den scheinbaren physischen Ursprung | Funk-, Provider-, Teilnehmer-, Geräte- und Standortdaten | Funk-/physische und Netzwerkbelege kombiniert |

## Netzwerke aus operativen Relay-Boxen

Ein **ORB network** ist eine verwaltete Proxy-Flotte, die als Zwischendienst eingesetzt wird. Mandiant unterteilt sie in provisionierte Netzwerke aus geleasten Servern, nicht provisionierte Netzwerke aus kompromittierten Routern/IoT-Geräten und Hybride. Eine ausgereifte Topologie besitzt vier logische Rollen:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** Verwaltet Inventar, Zugangsdaten, Zustand und Routing-Richtlinien.
2. **Access/relay node:** Authentifiziert Kunden oder Operatoren; er ist der stabile Einstieg in ein sich veränderndes Mesh.
3. **Traversal nodes:** Ein oder mehrere geleaste oder kompromittierte Systeme leiten undurchsichtige Verbindungen weiter.
4. **Exit/staging node:** Präsentiert Reconnaissance-, Exploitation- oder C2-Zielen die endgültige Quelladresse.

Das Mesh kann Exits nach Land, ASN, Latenz oder Verfügbarkeit auswählen und fehlerhafte Nodes rotieren. Mehrere Threat Groups können dasselbe Netzwerk mieten. Mandiant beobachtete, dass eine IPv4-Adresse nur 31 Tage lang mit einigen ORBs verbunden blieb; daher empfiehlt das Unternehmen, das **Netzwerk als eine sich entwickelnde, einem Akteur ähnelnde Einheit** zu behandeln, anstatt eine veraltete IP-Liste zu blockieren.<sup>[[2]](#references)</sup>

### Was dies ermöglicht – und was es leakt

- Das Ziel sieht einen Exit, der geografisch nahe liegen und scheinbar zu einem Residential-Anschluss gehören kann.
- Der Exit sieht das Ziel und den vorherigen Hop, aber nicht unbedingt den Operator.
- Der Access-Service sieht den Kunden und die Routenanfrage. Ein unabhängig verwaltetes Mesh kann den Kunden von den Exits getrennt halten, erzeugt jedoch einen aussagekräftigen Gegenparteien-Datensatz.
- Wiederkehrende Ports, Handshake-Reihenfolge, Server-Banner, Zertifikate, Verfügbarkeitsfenster und Controller-Beziehungen können die Flotte offenlegen, selbst wenn die IPs rotieren.
- Ein kompromittierter Router verfügt häufig nicht über Endpoint-Telemetrie, aber sein ISP besitzt weiterhin Teilnehmer- und Flow-Daten; eine Beschlagnahmung legt Implant-/Konfigurationsartefakte offen.

{% hint style="info" %}
Für eine autorisierte Übung reproduzieren Sie die Topologie mit organisations eigenen VMs oder Routern und bewahren Sie die Attribution-Map des Controllers auf. Rekrutieren Sie keine offenen Proxies oder Geräte Dritter. Der [Lab-Leitfaden](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) erstellt dieselbe für Defender sichtbare Hop-Struktur, ohne einen Vermittler zum Opfer zu machen.
{% endhint %}

## Residential- und Mobile-Proxy-Netzwerke

Residential-Proxy-Dienste weisen Sitzungen Consumer-Breitbandadressen zu; Mobile-Proxies verlassen das Netzwerk über Carrier-NAT-Pools. Die Versorgung kann aus ausdrücklich registrierten Geräten, in Consumer-Anwendungen gebündelten SDKs/Proxyware, Resellern oder Malware stammen. Diese Ursprünge sind nicht gleichwertig: Das Fehlen einer informierten Einwilligung macht aus einem Privacy-Service kompromittierte Infrastruktur.

Rotationsmodi beeinflussen die Erkennung:

- **per-request rotation** erzeugt schnelle Diskontinuitäten bei IP, ASN und Geografie, während die Identität auf höheren Ebenen stabil bleibt;
- **sticky sessions** behalten einen Exit minuten- oder stundenlang bei und ähneln dadurch einem gewöhnlichen Teilnehmer;
- **backconnect gateways** stellen dem Kunden einen Broker-Endpunkt bereit und wählen die Exits intern aus;
- **mobile pools** platzieren viele echte Teilnehmer hinter einer kleinen Anzahl von Carrier-NAT-Adressen, wodurch ein IP-Block kostspielig wird.

Defender sollten die IP mit authentifizierter Sitzung, TLS-/Client-Fingerprint, HTTP-Reihenfolge, Geräte-Cookie und Verhalten korrelieren. Ein vermeintlich lokales Residential-Login, auf das ein weiteres Land folgt, während alle Merkmale auf höheren Ebenen identisch bleiben, ist aussagekräftiger als Reputation allein. Umgekehrt erzeugen gemeinsam genutzte Adressen und der Wechsel zwischen Mobilfunkzellen legitime Wechsel, weshalb die Einstufung als Residential-/Proxy-Adresse niemals als Urteil behandelt werden sollte.

### Proxyware-Control-Planes und Überschneidungen bei Resellern

Modellieren Sie einen Residential-Pool nicht als flache Liste von Exits. Die Analyse des IPIDEA-Ökosystems legte eine wiederverwendbare **zwei-stufige Control-Plane** offen: Ein eingebettetes SDK meldet Geräte-/Registrierungsmetadaten zunächst an eine Tier-One-Domain und erhält Scheduling sowie Tier-Two-`connect`-/`proxy`-IP:Port-Paare. Der Node fragt den Tier-Two-connect-Port regelmäßig nach einer codierten Aufgabe ab, öffnet eine zweite Verbindung zum zugeordneten Proxy-Port und leitet die bereitgestellten Bytes an das angeforderte Ziel weiter. Nominell unterschiedliche SDKs und Proxy-Marken besaßen separate Discovery-Domains, liefen jedoch über gemeinsame Tier-Two-Infrastruktur und sich überschneidende Exit-Pools zusammen, was auf gemeinsame Eigentums- und Reseller-Beziehungen zurückging.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Dies erzeugt dauerhaftere Hunting-Pivots als ein Residential-IP-Block:<sup>[[13]](#references)</sup>

- ein unerwarteter Prozess eines Utility-, VPN-, Game- oder Embedded-Device-Programms sendet eine stabile Geräte-ID bzw. einen Kunden-Schlüssel und empfängt eine sich ändernde Serverliste;
- der Endpunkt fragt eine direkte IP an einem ungewöhnlichen Port ab und verbindet sich anschließend sofort mit einem anderen Port auf derselben Adresse, bevor er einen neuen Destination-Socket öffnet;
- mehrere scheinbare Brands teilen sich Tier-Two-Adressen, Protocol-Grammar, SDK-Code oder eine Überschneidung bei Exit-Nodes;
- verschiedene Anwendungen, die unterschiedliche Tier-One-Domains kontaktieren, erhalten Adressen aus demselben Tier-Two-Pool.

Die Überschneidung schränkt auch die Attribution ein: Das Erkennen einer IP im beworbenen Pool eines Vendors belegt nicht, welcher Reseller, Kunde oder Threat Actor sie zum relevanten Zeitpunkt verwendet hat. Bewahre Flow-Zeitstempel, Prozessherkunft, Tier-One-Response-Bodies und Tier-Two-Task-Identifier auf.<sup>[[13]](#references)</sup> Emuliere diese Hierarchie in einem autorisierten Exercise ausschließlich mit organisations­eigenen Endpunkten; registriere niemals Consumer-Geräte oder Proxyware von Drittanbietern.

## Multi-hop proxy chains

MITRE unterscheidet externe Proxies von **Multi-hop proxies (T1090.003)**. Die entscheidende Eigenschaft ist nicht die Anzahl der Hops, sondern die Trennung von Wissen und Administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Wenn eine Partei A und B betreibt, können gemeinsam ausgewertete Logs oder das Timing des Datenflusses den Circuit rekonstruieren. Das Hinzufügen sequenzieller kommerzieller VPNs vom selben Endpoint/Account kann zwar Latenz verursachen, aber gemeinsame Identitäts-, Zahlungs- und Timing-Daten bestehen lassen. Tor reduziert dieses Problem durch unabhängig ausgewählte Relays und ein gemeinsames Client-Design, aber ein interaktives Netzwerk mit geringer Latenz kann einem Beobachter, der beide Enden misst, keine Resistenz versprechen.

Häufige Fehler sind DNS- oder IPv6-Bypass, Anwendungen, die eigene Sockets öffnen, Management-Traffic, der Relays direkt erreicht, synchronisierte Aktivitäten, wiederverwendete SSH-Keys und das Einloggen in identifizierende Accounts. Die korrekte Verifizierung ist ein Ausfalltest: Jedes Relay wird nacheinander gestoppt, und es wird gezeigt, dass die Workload nicht auf einen Klartextpfad zurückfallen kann.

### Tunnelzusammenbruch und Upstream-Leakage

Eine Relay-Architektur ist oft am besten zuzuordnen, wenn sie ausfällt. Unit 42 dokumentierte einen mehrstufigen Spionagepfad mit opferseitigen VPSs, Relay-VPSs, Residential Proxies, Tor und anderen Proxy-Diensten. Wenn ein Tunnel fehlte oder zusammenbrach, verband sich die verborgene Upstream-Infrastruktur direkt mit Relay- und opferseitigen Systemen. Dieselbe Untersuchung nutzte außerdem ein X.509-Zertifikat, das kurzzeitig auf der Upstream-Infrastruktur offengelegt war, als Pivot über mehrere Tiers hinweg.<sup>[[14]](#references)</sup>

Halte die **Datenebene** (`victim <-> exit`) von der **Steuerungsebene** (`operator/upstream -> relay administration`) getrennt. Bewahre Ingress- und Authentifizierungs-Logs auf jeder eigenen Tier, Zertifikatshistorien und kurze fehlgeschlagene Verbindungen auf – nicht nur erfolgreiche C2-Sessions. Eine Quelle, die nur während Relay-Ausfällen erscheint oder mehrere opferseitige Nodes direkt administriert, ist ein stärkerer Upstream-Kandidat als ein gewöhnlicher Exit. Ihre ASN/Geolokalisierung bleibt jedoch eine Hypothese und ist kein Beweis für die Identität eines Operators.

Ein autorisiertes Labor sollte die Workload bei Fehlern geschlossen ausfallen lassen. Bei einer Workload, die in einem Linux-Netzwerk-Namespace isoliert ist, muss die erste Route den Tunnel verwenden. Nach dessen Entfernung müssen sowohl die Anfrage als auch die Routenabfrage fehlschlagen, statt den physischen Uplink auszuwählen:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Wiederhole den Test für DNS und IPv6 sowie an jeder Relay-Grenze. Wenn eine Probe erfolgreich ist, zeichne die tatsächliche Schnittstelle/Quelladresse auf, bevor du Policy Routing oder die Firewall reparierst; diese Beobachtung ist der Attribution Leak, den ein Ermittler sehen würde.

## Redirector tiers und Traffic Shaping

Ein öffentlicher **Redirector** akzeptiert Traffic, der einer operationsspezifischen Grammatik entspricht, und leitet ihn an einen geschützten Team Server weiter. Alles andere kann abgelehnt oder mit harmlosen Inhalten beantwortet werden.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Mehrere Ebenen begrenzen die Sichtbarkeit: Das Aufgeben einer öffentlichen Domain muss den Teamserver nicht offenlegen. CDNs fügen Anycast-Kapazität und eine seriöse äußere Domain hinzu, aber das CDN-Konto und die Edge-Logs werden zu Zuordnungspunkten. TLS-Fingerprints, Zertifikatshistorien, charakteristische Pfade/Header-Reihenfolgen, Antwortgrößen, Redirect-Verhalten und Origin-Allowlisten können vermeintlich unabhängige Fronts gruppieren.

Zur Erkennung sollten Reverse-Proxy-Felder vor der Normalisierung aufgezeichnet, SNI/Host/Authority verglichen, seltene Header-Kombinationen untersucht, Antwort-Bodies und TLS-Fingerprints gruppiert sowie Cloud-/CDN-Audit-Logs auf Konfigurationsüberschneidungen durchsucht werden. Bei autorisierten Red Teams sollte das Kopieren einer echten Marke oder das Platzieren einer Credential-Sammlung hinter einem unabhängigen Drittanbieter vermieden werden.

## Domain fronting und domainless fronting

Beim klassischen **domain fronting (T1090.004)** kündigt die TLS-Verbindung eine zulässige Front-Domain in SNI an, während der verschlüsselte HTTP-`Host`- oder HTTP/2-`:authority`-Wert eine andere Back-End-Domain anfordert. Ein kooperierendes CDN routet anhand des inneren Werts. Ein Netzwerkbeobachter ohne TLS-Entschlüsselung sieht die Front; das CDN sieht beide Werte und den Origin. Bei domainless-Varianten kann SNI leer sein, während ein anderes Routing-Feld das Ziel auswählt.<sup>[[4]](#references)</sup>

Das ist keine magische Identitätsvortäuschung: Es funktioniert nur, wenn der Intermediär die Abweichung absichtlich oder versehentlich zulässt und weiß, wie der innere Name geroutet werden soll. Große Anbieter haben accountübergreifendes fronting eingeschränkt. Encrypted ClientHello (ECH) verändert, was ein Beobachter auf dem Übertragungsweg sehen kann, beseitigt aber keine CDN-, Endpoint- oder Application-Aufzeichnungen.

Zu den Erkennungspunkten gehören:

- Prozessabstammung des Endpoints und ein für diese Anwendung unerwartetes Ziel;
- Abweichung zwischen SNI und HTTP-Authority, sofern TLS-Inspection rechtmäßig und verfügbar ist;
- CDN-Logs, die zeigen, dass ein Tenant/eine Front zu einer anderen Authority/einem anderen Origin routet;
- ungewöhnliche langlebige oder periodische Sessions zu einem normalerweise interaktiven Service;
- stabile verschlüsselte Flow-Größen und ein konstantes Timing über wechselnde Front-Domains hinweg.

Das sichere Lab simuliert die Routing-Abweichung auf einem eigenen Reverse Proxy; es missbraucht kein öffentliches CDN.

## Dynamic resolution: DDNS, DGA und fast flux

Dynamic resolution entkoppelt einen logischen Service von einer festen Infrastruktur:

- **DDNS:** Ein authentifizierter Client aktualisiert einen stabilen Namen, nachdem sich seine Adresse geändert hat.
- **DGA:** Endpoint und Controller leiten aus einem Zeit-/Key-Seed beide eine Reihe möglicher Domainnamen ab; der Betreiber registriert eine kleine Teilmenge.
- **Fast flux:** Ein Name liefert eine sich schnell ändernde Gruppe kompromittierter/Proxy-Adressen zurück, oft mit niedrigen TTLs.
- **Double flux:** Sowohl Service-Adressen als auch autoritative Nameserver-Adressen rotieren, wodurch auch die Control Layer verborgen wird.

Fast flux ist ein adversariales Muster zur Lastverteilung, nicht einfach nur „viele DNS-Antworten“. Stärkere Belege kombinieren niedrige TTLs, eine hohe Anzahl eindeutiger Adressen, große ASN-/Geografie-Streuung, kurze Node-Lebensdauer, wiederholtes Application-Verhalten und eine verdächtige Registrierungshistorie. CDNs weisen legitimerweise mehrere dieser Eigenschaften auf. MITRE empfiehlt, DNS-Verhalten mit dem Prozess und nachfolgenden Verbindungen zu korrelieren.<sup>[[5]](#references)</sup>

Eine DGA kann anhand lexikalischer Entropie, Konsonanten-/Ziffernmustern, NXDOMAIN-Schüben, synchronisierten First-Seen-Domains und Prozesskontext erkannt werden. Wordlist-DGAs und generative Modelle umgehen einfache Entropieregeln, wodurch zeitliches Clustering über die gesamte Flotte und die Endpoint-Abstammung wichtiger werden.

## Kompromittierte Domains und Domain Shadowing

Ein Akteur kann ein Registrar-/DNS-Konto kapern, eine verwaiste Subdomain übernehmen oder Records unter einer ansonsten seriösen Domain hinzufügen. **Domain shadowing** bewahrt den legitimen Apex, während große Mengen von angreiferkontrollierten Subdomains auf wechselnde Delivery- oder C2-Hosts zeigen. Dadurch werden Alter und Reputation übernommen, und eine domainweite Blockierung kann umgangen werden.<sup>[[6]](#references)</sup>

Verteidiger benötigen Registrar- und autoritative-DNS-Audit-Logs, MFA, Registry-/Registrar-Sperren, Warnungen für neue Delegations, API-Tokens und Nameserver, Certificate-Transparency-Monitoring sowie ein Inventar der von DNS referenzierten Cloud-Ressourcen. Die Auflösung und Zertifikatshistorie einer Subdomain sollte unabhängig von der Reputation des Apex untersucht werden.

## Web services und Dead-Drop-Resolver

Ein **dead-drop resolver (T1102.001)** speichert einen codierten Zeiger auf aktuelles C2 in einem legitimen Post, Profil, Dokument, Repository, Cloud-Objekt oder Blockchain-Feld. Malware ruft das öffentliche Objekt ab, decodiert eine Domain/IP und kontaktiert die nächste Stufe. Bidirektionale Varianten tauschen Commands oder Dateien über Service-APIs aus.<sup>[[7]](#references)</sup>

Dies bietet Resilienz und verbirgt das Back-End-C2 vor statischer Binary-Analyse. Gleichzeitig entstehen stabile Objekt-, Tenant-, Repository-, API- und Zugriffsmuster-Identifikatoren. Verteidiger sollten Folgendes miteinander verknüpfen:

1. den Prozess, der den Service kontaktiert hat;
2. den exakten API-Pfad/das Objekt und den Response-Hash;
3. Decoding- oder String-Processing-Aktivitäten;
4. die neue ausgehende Verbindung kurz danach; und
5. identisches Verhalten an anderer Stelle in der Flotte.

Das Blockieren von ganz GitHub, Cloud Storage oder Social Media ist selten praktikabel. Service-bewusste Egress-Policies und Korrelation auf Prozessebene sind einer rein domainbasierten Blockierung überlegen.

## Personas, Accounts und Beschaffungskompartimente

Die Anonymität der Infrastruktur scheitert, wenn eine Persona, Recovery-E-Mail, Telefonnummer, Zahlung, ein Browser oder eine Admin-IP Kompartimente miteinander verbindet. Mit Staaten verbundene Operationen haben Social Profiles, E-Mail-Identitäten und Cloud-Accounts lange vor ihrer Nutzung aufgebaut; ATT&CK führt dies als Establish Accounts (T1585), einschließlich Social-, E-Mail- und Cloud-Subtechniken.<sup>[[8]](#references)</sup>

Ein Verteidiger oder Ermittler erstellt einen Graphen aus:

- Erstellungs- und First-Login-Zeit, Locale, Zeitzone und Arbeitszeitplan;
- Recovery-Feldern, MFA-Geräten, Identitätsdokumenten und Zahlungsinstrumenten;
- Browser-/TLS-Fingerprints und Verlauf der Quellnetzwerke;
- Wiederverwendung von Avataren, Bildherkunft, Schreibstil und Wachstum des Social Graphs;
- gemeinsamem Domain-Registrant, Nameserver, Zertifikat, Analytics-ID oder Repository-Commit;
- Aktionen auf der Management Plane, die die öffentliche Relay-Architektur umgehen.

Für ein autorisiertes Red Team sollten synthetische Personas gegenüber dem Exercise Controller dokumentiert werden, organisationsinterne Recovery-/Zahlungskanäle verwenden, die Identitätsvortäuschung realer unbeteiligter Personen vermeiden und einen geplanten Rückzug haben. Das SOC kann weiterhin blind bleiben; die Operation darf jedoch nicht unaccountable werden.

## Neue zusammengesetzte Muster für das Threat Modeling

Die folgenden Muster sind **defender-driven compositions** und keine Behauptungen, dass ein namentlich genannter Akteur jedes exakt beschriebene Design eingesetzt hat. Sie kombinieren bereits beobachtete Primitives und eignen sich als Purple-Team-Hypothesen.

### Asymmetric one-way tasking

Commands treffen über eine öffentliche, broadcast- oder append-only-Quelle ein, während Ergebnisse nach einer Verzögerung über einen unabhängigen Kanal abfließen. Beispiele für das Primitive sind Web-Service-One-Way-Communication und Dead Drops. Die Trennung verhindert, dass ein einzelner Flow bidirektional aussieht, und erschwert eine einfache Request-/Response-Korrelation.<sup>[[9]](#references)</sup>

**Erkennung:** Objektbezogene Reads bewahren und anschließend Prozesszustandsänderungen sowie spätere ausgehende Transfers über ein größeres Zeitfenster korrelieren. Nach einem seltenen Prozess suchen, der dasselbe öffentliche Objekt liest, selbst wenn keine unmittelbare Antwort folgt.

### Multi-stage channel promotion

Eine unauffällige erste Stufe führt ein Inventory durch und befördert nur ausgewählte Systeme zu einem unabhängigen Second-Stage-Kanal. Der zweite Endpoint, das Protokoll und der Prozess können keinerlei Infrastruktur mit der ersten Stufe teilen. Dies begrenzt die Sichtbarkeit leistungsfähiger Infrastruktur und wird in ATT&CK ausdrücklich als T1104 modelliert.<sup>[[10]](#references)</sup>

**Erkennung:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` verknüpfen; den Vorfall nicht nach dem Blockieren der ersten Domain schließen.

### Cross-protocol relay translation

Verschiedene Hops übersetzen HTTPS, QUIC, WebSocket, DNS, SSH oder eine Message-Queue-API, statt Pakete transparent weiterzuleiten. Die Übersetzung beseitigt einen einzelnen End-to-End-Protokoll-Fingerprint, erzeugt jedoch Gateways mit charakteristischem Timing, Buffering und semantischer Konvertierung. Protocol Tunneling (T1572) kann mit Proxies und Service Impersonation kombiniert werden.<sup>[[11]](#references)</sup>

**Erkennung:** Nach Gateway-Hosts suchen, die ein Protokoll empfangen und ein anderes initiieren, mit eng gekoppeltem Byte-/Zeitverhalten; die Absicht des Endpoints mit dem tatsächlich übertragenen Protokoll vergleichen.

### Passive activation on edge devices

Statt zu beaconen überwacht ein Implant Traffic, der bereits einen Router/VPN erreicht, und aktiviert sich nur bei einem Magic Value, Source-Port-Muster oder authentifizierten Token. Normaler Traffic wird weiterhin an den echten Service geleitet. ATT&CK nennt dies Traffic Signaling (T1205), mit dokumentierten Network-Device- und APT-Beispielen.<sup>[[12]](#references)</sup>

**Erkennung:** Firmware-/File-Integrity, Raw-Packet-Capture während eines autorisierten Hunts, unerwartete Socket-Filter und differenzielles Service-Verhalten. Das Fehlen eines periodischen Beacons beweist nicht, dass ein Edge Device sauber ist.

### Serverless and ephemeral origin rotation

Eine Front bewahrt eine stabile logische Identität, während kurzlebige Functions/Container einzelne Stufen in mehreren Regionen/Accounts verarbeiten. Dies reduziert die Lebensdauer auf dem Datenträger und feste Origin-IPs, aber Control-Plane-Erstellung, Image/Layer, Role, Secret, Request-ID und Billing-Telemetrie werden zum dauerhaften Graphen.

**Erkennung:** Cloud-Audit- und Invocation-Logs außerhalb der Workload aufbewahren; Deployment-Templates, Roles, Environment Keys und Front-to-Origin-Beziehungen gruppieren.

### Privacy-layer diversity

Eine Operation kann absichtlich eine homogene Chain vermeiden: Ein Kanal verwendet beispielsweise ein gemietetes Relay, Tasking ein öffentliches Objekt, ein Exit eine eigene Labor-Mobilfunkverbindung und die Administration ein separates Organisationsnetzwerk. Dies reduziert den Nutzen der Kompromittierung eines einzelnen Providers, erhöht jedoch das Risiko von Timing- und Operationsfehlern über mehrere Ebenen hinweg.

**Erkennung:** Campaign-Timelines über Identity-, DNS-, SaaS-, Network- und Cloud-Sensoren erstellen. Nach synchronisierten Zustandsübergängen statt nach identischen Indicators suchen.

### Decentralized or transparency-log dead drops

Ein Akteur kann einen kleinen verschlüsselten Zeiger in jedem dauerhaften öffentlichen append-only-System, content-addressed Store oder transparency-artigen Feed platzieren. Das öffentliche Objekt ist resilient, aber sein exakter Index/Content-Hash und das Polling-Verhalten des Clients werden zu stabilen Identifikatoren.

**Erkennung:** Vollständige API-/Objekt-Identifikatoren und Response-Hashes aufzeichnen; bei ungewöhnlichen Prozessen alarmieren, die unveränderliche Objekte pollen, gefolgt von Decoding oder neuen Verbindungen.

### Delayed store-and-forward operations

Interaktives C2 erzeugt eine starke Timing-Korrelation. Ein Store-and-Forward-Design bündelt verschlüsselte Jobs und liefert Ergebnisse Minuten oder Stunden später über eine andere Queue oder einen physischen Transfer zurück. Es opfert Reaktionsfähigkeit zugunsten eines schwächeren End-to-End-Timings.

**Erkennung:** Korrelationsfenster verlängern, periodischen Queue-Zugriff modellieren und Endpoint-Staging untersuchen. Batching verlagert das Signal vom Packet-Timing auf geplantes Process-/File-Verhalten; es beseitigt das Signal nicht.

## Design Review: in Beobachtern denken

Für jeden Pfad diese Tabelle vor dem Deployment und nach der Collection ausfüllen:

| Layer | Sieht die Quelle? | Sieht das Ziel? | Sieht den Inhalt? | Stabile Identifikatoren | Aufbewahrung/rechtlich Verantwortlicher |
|---|---:|---:|---:|---|---|
| lokales Netzwerk/Carrier | | | | | |
| Entry-/Access-Service | | | | | |
| Traversal Operator(s) | | | | | |
| Exit/Redirector/CDN | | | | | |
| autoritativer DNS/Registrar | | | | | |
| Target | | | | | |
| Account-/Zahlungsanbieter | | | | | |

Wenn ein gewöhnlicher Provider jede Spalte ausfüllen kann, bietet die Architektur zwar Verdeckung gegenüber dem Target, aber keine robuste Trennung. Wenn kein interner Controller Aktivitäten einem Engagement zuordnen kann, ist die Architektur für professionelles Red Teaming ungeeignet.

## References

- [1] [MITRE ATT&CK — Infrastruktur beschaffen (T1583), Infrastruktur kompromittieren (T1584) und Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus-Spionageakteure verwenden ORB-Netzwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
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
- [13] [Google Threat Intelligence Group — Das weltweit größte Residential-Proxy-Netzwerk stören](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Die Shadow Campaigns: Globale Spionage aufdecken](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
