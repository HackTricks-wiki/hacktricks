# Attribution, Detection und Gegenmaßnahmen

Die Infrastruktur zur Umgehung der Attribution ist darauf ausgelegt, einzelne Indikatoren austauschbar zu machen. Verteidiger sollten Rohdaten sichern, Beziehungen modellieren und nach Verhalten suchen, das einen Wechsel von IP, Domain oder Persona überdauert.

## Beweishierarchie

| Beweis | Nützlich für | Wichtigster Vorbehalt |
|---|---|---|
| Quell-IP/ASN/Geolokalisierung | den sichtbaren Ausgang und den Provider lokalisieren | Der Ausgang kann ein Relay, NAT oder Opfer sein; die Geolokalisierung ist nur ungefähr |
| Passives DNS/Registrierung | Infrastrukturverlauf und Co-Hosting | Datenschutz/Redaktion und Shared Hosting erzeugen Lücken |
| Zertifikat/TLS/HTTP-Fingerprint | wiederholte Deployments clustern | Standardsoftware und Nachahmung erzeugen False Positives |
| Flow-Timing und Byte-Struktur | Relay-Stufen und wiederkehrende Beacons verknüpfen | CDNs/NAT und eingeschränkte Sichtbarkeit reduzieren die Sicherheit |
| Endpoint-Prozess/Identität | erklären, warum eine Verbindung zustande kam | Auf Edge-/IoT-Geräten nicht vorhanden; Angreifer können native Tools verwenden |
| Cloud/CDN/API-Audit | Tenant und Kontrolle über die Infrastruktur identifizieren | Aufbewahrung und Zugriff durch Provider/Behörden variieren |
| Zahlung/Konto/Gerät | Beschaffung mit einer Person/Entität verknüpfen | Strohpersonen, Kompromittierung und gemeinsam genutzte Geräte müssen berücksichtigt werden |
| Sichergestelltes Implantat/Configuration | Schlüssel, Peers, Controller und Build-Verknüpfungen offenlegen | Integrität der Erfassung und Zeitpunkt der Sicherstellung sind relevant |
| Menschliche/physische Beweise | digitales Ereignis mit Ort/Operator verknüpfen | Eingriffsintensiv, von der Jurisdiktion abhängig und erfordert strenge Handhabung |

Keine einzelne Zeile sollte eine Attribution auf staatlicher Ebene mit hoher Sicherheit begründen. Verwende konkurrierende Hypothesen und benenne, welche Beobachtung jede einzelne falsifizieren würde.

## Minimale Telemetrie

1. **DNS:** Client, Anfrage, Typ, Antworten, TTL, Antwortcode, Resolver und Zeitstempel.
2. **Network Flow:** Quelle/Ziel/Port, Beginn/Ende, Pakete/Bytes, TCP-Flags und Sensorstandort.
3. **TLS/HTTP:** SNI, sofern sichtbar, Zertifikat, ausgehandeltes Protokoll, Client-/Server-Fingerprint, Methode, Kategorie von Authority/Pfad, Status und Byte-Anzahl. Schütze vertrauliche vollständige URLs.
4. **Identität:** Authentifizierungsergebnis, Faktor/Zertifikat/Gerät, Quelle, Anwendung, Sitzungs-ID und Risikoentscheidung.
5. **Endpoint:** auslösender Prozess, übergeordneter Prozess, Benutzer, Binärsignatur/-Hash und Ziel.
6. **Edge-/Netzwerkgerät:** Konfigurationsdifferenz, Admin-Login, Prozess-/Datei-/Firmware-Integrität, Interface- und Flow-Logs.
7. **Cloud/SaaS/CDN:** Akteur, Tenant/Projekt, API-Aktion, Quelle, Objekt/Ressource, Token und Ergebnis.
8. **Wireless/NAC:** Station, Randomized-MAC-Flag, AP, Signal, EAP-Identität/Zertifikat, zugewiesenes VLAN/IP und Sicherheitsstatus.

Synchronisiere die Uhren, bewahre die ursprünglichen Zeitzonen auf, dokumentiere NAT-/Proxy-Grenzen und speichere ausreichend Historie, um einen ORB-Knoten 31 Tage zu überdauern.

## Einen Attribution-Graphen erstellen

Stelle Beobachtungen als typisierte Knoten und Kanten dar:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Nützliche Knoten umfassen IP, Präfix, ASN, Domain, DNS account, Zertifikat/Schlüssel, einen JA3/JA4-ähnlichen Fingerprint, HTTP-Grammatik, Datei-/Config-Hash, Cloud-Tenant, API token, E-Mail, Persona, Zahlungsinstrument und physisches Gerät. Jede Kante benötigt `first_seen`, `last_seen`, Sensor/Quelle, Konfidenz sowie die Angabe, ob sie beobachtet oder abgeleitet wurde.

Die Graphdichte allein ist irreführend: Ein CDN oder eine Certificate Authority verbindet viele voneinander unabhängige Akteure. Seltene, vom Betreiber kontrollierte Beziehungen—derselbe API account, SSH-Schlüssel, Origin-Allowlist, eindeutig konstruierter Response-Body oder ein Control-Protokoll—sollten stärker gewichtet werden als gewöhnliches Hosting.

## ORB und die Suche nach kompromittierten Routern

### Von einem beobachteten Exit aus

1. Bestimme, ob die Adresse Hosting, einem privaten, mobilen, Bildungs- oder Geschäftsnetzwerk zuzuordnen ist; verwirf Quellen aus privaten Netzwerken nicht.
2. Rufe historische DNS-Daten, Services/Zertifikate, offene Ports und beobachtetes Scan-/Exploitation-Verhalten für einen begrenzten Zeitraum ab.
3. Suche nach Peers mit seltenen Service-Fingerprints, Controller-Zielen, Zertifikatsmaterial oder ähnlichem Rotationstiming.
4. Klassifiziere wahrscheinliche Rollen: Zugriff, Traversierung, Exit/Staging oder Administration.
5. Prüfe, ob mehrere voneinander unabhängige Intrusion-Cluster denselben Pool verwendet haben; Multi-Tenancy schwächt die direkte Akteursattribution, stärkt jedoch die ORB-Hypothese.
6. Verfolge neue Knoten, die dem Rollenprofil entsprechen, nachdem alte IPs verschwunden sind.

### Beim Betreiber des Netzwerks

- Erzeuge Alerts für neu aus dem Internet erreichbare Managementschnittstellen sowie für Standard-/Legacy-Authentifizierung.
- Sende Router-/Firewall-/VPN-Konfigurationsänderungen und Admin-Authentifizierung vom Gerät weg.
- Erstelle eine Baseline für ausgehende Verbindungen von Infrastrukturen, die normalerweise nur wenige Sessions initiieren.
- Erkenne neue Proxy-/Listener-Prozesse, Tunnel, geplante Tasks, Firmwareänderungen und unerwartetes DNS.
- Ersetze Geräte am Ende ihres Lebenszyklus; ein Neustart, der flüchtige Malware entfernt, behebt die Schwachstelle nicht.
- Beschränke das Management auf eine authentifizierte Administrationsebene und bekannte Quellen.

Mandiant empfiehlt, ORB-Infrastruktur als sich weiterentwickelnde Einheit zu verfolgen, da eine kurzzeitige Sperrung von IPs Topologie und Lebenszyklus nicht erfasst.<sup>[[1]](#references)</sup>

## Fast-flux- und Dynamic-DNS-Analysen

Aggregiere nach registrierter Domain und einem gleitenden Zeitfenster. Ein praxisnaher Score kann Folgendes kombinieren:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Untersuchen Sie Domains anhand mehrerer unabhängiger Merkmale, nicht anhand eines einzelnen Schwellenwerts. Vergleichen Sie sie mit einem CDN-/Anti-DDoS-Allow-Modell und prüfen Sie die Rotation der autoritativen Name-Server, um Single Flux von Double Flux zu unterscheiden. Fügen Sie bei DGAs clientbezogene NXDOMAIN-Spitzen, die Längen-/Zeichenverteilung, synchronisierte Abfragen über mehrere Hosts hinweg und den Prozess hinzu, der sie erzeugt. Auch die aktuelle Anleitung von MITRE betont häufige Änderungen, niedrige TTL-Werte sowie die Korrelation von Prozessen und Netzwerkaktivität.<sup>[[2]](#references)</sup>

## Erkennung von Domain-Fronting

Wenn der Enterprise-Endpunkt oder ein autorisierter Inspektionspunkt über beide Identitäten verfügt, vergleichen Sie:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Erhöhe das Vertrauen, wenn SNI und Authority zu nicht miteinander verbundenen Tenants gehören, der Prozess kein genehmigter Client ist, die Sitzung periodisch/lang andauernd ist und der innere Ursprung selten ist. Leeres SNI ist ein zu erfassendes Merkmal und nicht automatisch bösartig. ECH kann SNI im Netzwerk verbergen, daher werden Endpoint-, DNS- und Provider/CDN-Logs wichtiger. MITRE dokumentiert sowohl Varianten mit nicht übereinstimmendem als auch mit leerem SNI.<sup>[[3]](#references)</sup>

## Erkennung von Dead-drop-Resolver-Sequenzen

Das Verhalten mit hoher Aussagekraft ist eine Sequenz und keine blockierte Domain:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Durchsuche die gesamte Flotte nach identischen Objektpfaden, Response-Hashes, API-Kennungen und Anschlusszielen. Bewahre abgerufene Inhalte auf, da der Akteur sie bearbeiten oder löschen kann. Schränke nicht benötigte Service-APIs ein und verlange, dass genehmigte Anwendungen Enterprise-Proxies verwenden, berücksichtige dabei jedoch Entwickler-Tools und Automatisierung. MITRE führt GitHub, Foren, Dokumente und Social-/Web-Services in realen Verfahren auf.<sup>[[4]](#references)</sup>

## Clustering von Redirectors und wiederverwendbaren Deployments

Selbst wenn sich Domains und Adressen ändern, setzen Betreiber häufig dieselbe Automatisierung erneut ein. Bilde Cluster anhand von Kombinationen aus:

- Zertifikatsfeldern/Key-Wiederverwendung und dem Zeitpunkt der Ausstellung;
- TLS-Version/Cipher/Erweiterungsreihenfolge und Serververhalten;
- identischem HTTP-Status, Header-Reihenfolge, Cache-Verhalten, Icon/Body und Fehlerseite;
- ungewöhnlichen Portpaaren und Redirect-Ketten;
- DNS-Provider-/Nameserver-Muster und TTL-Zeitplan;
- Deployment-Zeitpunkt, Uptime und Wartungsfenster;
- offengelegtem Back-End-Ursprung oder identischen Allowlists.

Eine einzelne generische Nginx-Seite ist ein schwaches Indiz. Mehrere seltene, unabhängige Übereinstimmungen plus zeitliche Kontinuität können eine Hypothese zu einem Infrastruktur-Cluster rechtfertigen.

## Erkennung von Residential-Proxies und unmöglichen Sitzungen

Halte die Sitzungsidentität über die IP-Ebene hinaus aufrecht. Markiere Kombinationen wie:

- ein Sitzungs-/Geräte-Fingerprint wechselt schneller zwischen Ländern/ASNs, als es die Reisegeschwindigkeit erlaubt;
- eine Consumer-IP ändert sich bei jeder Anfrage, während Cookies und TLS-/Browser-Identität unverändert bleiben;
- das angeblich lokale Gerät weist Latenz/Zeitzone/Sprache auf, die nicht mit dem Exit übereinstimmen;
- eine Adresse wechselt zwischen nicht zusammengehörigen Account-Populationen oder zeigt Backconnect-Proxy-Verhalten;
- eine privilegierte Sitzung erscheint über Residential Access ohne das Geräte-Zertifikat der Organisation.

Carrier-NAT, Accessibility-Tools, Corporate-VPNs und Reisen erzeugen gutartige Anomalien. Fordere Step-up-Authentifizierung oder eine Untersuchung statt einer irreversiblen Sperrung, die allein auf Labels wie „Residential Proxy“ basiert.

## Erkennung von Wireless- und verdeckten Geräten

Führe RADIUS/NAC mit AP- und physischem Kontext zusammen:

1. finde erstmals beobachtete Kombinationen aus Account, Gerät und AP;
2. identifiziere Credentials, die ohne verwaltetes EAP-Zertifikat bzw. ohne verwaltete Posture verwendet wurden;
3. vergleiche gleichzeitig aktive Sitzungen und Badge-/Gebäudepräsenz;
4. untersuche ungewöhnlich schwache bzw. grenzwertige Signalstärke und Bewegungen zwischen APs;
5. suche auf nahegelegenen verwalteten Endpunkten nach Wireless-Scanning, einer neu aktivierten Interface-Bridge/NAT, virtuellen Adaptern oder Tunneln;
6. erfasse neue Switchports sowie DHCP-, USB-Netzwerk- und PoE-Aktivität;
7. führe einen autorisierten RF-/physischen Sweep durch, wenn die Beweislage dies unterstützt.

Dies erkennt sowohl einen APT28-ähnlichen Pfad über den nächsten Nachbarn als auch einen im Rahmen einer Übung platzierten Drop. MAC-Randomisierung darf nicht als Identität oder Schuldnachweis behandelt werden.

## Erkennung finanzieller Attribution

- Bewahre die exakte Kette sowie Token-, Adress-, Transaktions- und Block-Kennungen auf.
- Verfolge Werte über Change, Peel-Chains, Fan-out/-in, Mixer, Bridges und Service-Einzahlungen und kennzeichne dabei Heuristiken.
- Korrelieren Zeit, Betrag abzüglich Gebühren, Contract-Event, Liquidität und Auszahlung auf der Ziel-Chain.
- Beschaffe oder bewahre rechtmäßig Exchange-, Bridge-, Händler-, Account-, Geräte- und Lieferaufzeichnungen auf.
- Prüfe aktuelle sanktionierte Entitäten/Adressen und Derivate gemäß dem anwendbaren Programm; verlasse dich nicht auf eine alte statische Liste.
- Behandle die Nutzung von Privacy-Protokollen als Input für den Risikokontext, nicht als Beweis für Fehlverhalten.

Die Red Flags der FATF sind ausdrücklich kontextbezogen: Ungewöhnliches Muster, Betrag/Häufigkeit, Geografie, Herkunft der Mittel und Services zur Anonymitätssteigerung werden gemeinsam aussagekräftig.<sup>[[5]](#references)</sup>

## Täuschung und Canaries

Verteidiger können Signale mit hoher Sicherheit erzeugen, ohne gewöhnliche Nutzer deanonymisieren zu wollen:

- eindeutige Credentials oder Dokumente, die niemals ein System verlassen sollten;
- gefälschte administrative Endpunkte und Decoy-Shares;
- instrumentierte DNS-Namen, die nur in kontrollierte Artefakte eingebettet sind;
- Canary-Cloud-Keys ohne legitime Verwendung;
- eine Decoy-Wi-Fi-Identität, die kein verwaltetes Gerät besitzt.

Plane und steuere Täuschungsmaßnahmen sorgfältig. Ein Canary sollte den Missbrauch eines eigenen Assets des Verteidigers erkennen, nicht unabhängigen Datenverkehr Dritter erfassen.

## Prioritäten bei Gegenmaßnahmen

1. Entferne nicht unterstützte, aus dem Internet erreichbare Router, VPNs und Appliances.
2. Fordere phishing-resistente MFA und gerätegebundene Zertifikate, einschließlich internem/Wireless-Zugriff.
3. Zentralisiere hinreichend unveränderliche Identity-, Endpoint-, DNS-, Flow-, Proxy-, Cloud- und Netzwerkgeräte-Logs.
4. Beschränke Management und Egress; erfasse jeden extern erreichbaren Service.
5. Überwache DNS, Certificate Transparency und Cloud-Konfiguration auf nicht autorisierte Assets.
6. Stelle Process-to-Network- und Object-Level-SaaS-Visibility sicher.
7. Übe Untersuchungen über mehrere Ebenen und die Koordination mit benachbarten Providern.
8. Verfolge Infrastruktur-Cluster und Verhaltensweisen, nicht nur IP-Blocklists.

## Analytische Disziplin

Verwende Konfidenzaussagen:

- **Beobachtet:** Ein Sensor-/Provider-Datensatz zeigt die Beziehung direkt.
- **Stark gestützt:** Mehrere unabhängige Beobachtungen sprechen stärker dafür als für Alternativen.
- **Bewertet:** Schlussfolgerung auf Grundlage ausdrücklich genannter Annahmen und Belege.
- **Unbekannt:** Fehlende Sichtbarkeit verhindert eine Schlussfolgerung.

Behalte immer mindestens zwei Hypothesen bei: vom Akteur betriebene Infrastruktur gegenüber einem kompromittierten/geteilten Vermittler; ein Akteur gegenüber einem Multi-Tenant-Service; absichtliche Umgehung gegenüber legitimem Privacy-/CDN-Verhalten. Unsicherheit erklären zu können, ist Teil einer korrekten Erkennung.

## References

- [1] [Google Cloud/Mandiant — Spionageakteure mit China-Bezug nutzen ORB-Netzwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast-Flux-DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead-Drop-Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Red-Flag-Indikatoren für virtuelle Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Akteure aus der VR China kompromittieren kritische Infrastruktur der USA und erhalten dauerhaften Zugriff aufrecht](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Leitfaden für verbesserte Sichtbarkeit und Härtung der Kommunikationsinfrastruktur](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
