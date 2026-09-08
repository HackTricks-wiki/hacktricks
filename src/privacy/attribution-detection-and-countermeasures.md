# Zuordnung, Erkennung und Gegenmaßnahmen

{{#include ../banners/hacktricks-training.md}}

Infrastruktur zur Umgehung der Zuordnung ist darauf ausgelegt, einzelne Indikatoren austauschbar zu machen. Die Verteidigung sollte Rohdaten sichern, Beziehungen modellieren und nach Verhalten suchen, das eine Änderung von IP, Domain oder Persona überdauert.

## Beweishierarchie

| Beweis | Nützlich für | Wichtigster Vorbehalt |
|---|---|---|
| Quell-IP/ASN/Geolokalisierung | den sichtbaren Ausgang und den Provider lokalisieren | der Ausgang kann ein Relay, NAT oder Opfer sein; die Geolokalisierung ist ungenau |
| Passives DNS/Registrierung | Infrastrukturhistorie und gemeinsames Hosting | Datenschutz/Redaktion und Shared Hosting erzeugen Lücken |
| Zertifikat/TLS/HTTP-Fingerprint | wiederholte Deployments clustern | verbreitete Software und Nachahmung erzeugen False Positives |
| Flow-Timing und Byte-Struktur | Relay-Stufen und wiederkehrende Beacons verknüpfen | CDNs/NAT und eingeschränkte Sichtbarkeit verringern die Sicherheit |
| Endpoint-Prozess/Identität | erklären, warum eine Verbindung hergestellt wurde | auf Edge-/IoT-Geräten nicht vorhanden; der Angreifer kann native Tools verwenden |
| Cloud/CDN/API-Audit | Tenant und Infrastrukturkontrolle identifizieren | Aufbewahrungsfristen und Zugriff durch Provider/Behörden variieren |
| Zahlung/Account/Gerät | Beschaffung mit einer Person/Organisation verknüpfen | Strohmänner, Kompromittierung und gemeinsam genutzte Geräte müssen berücksichtigt werden |
| Sichergestelltes Implantat/Configuration | Schlüssel, Peers, Controller und Build-Verbindungen offenlegen | Integrität der Sammlung und Zeitpunkt der Sicherstellung sind entscheidend |
| Menschliche/physische Beweise | digitales Ereignis mit Ort/Operator verknüpfen | eingriffsintensiv, jurisdiktionsabhängig und erfordert strikte Handhabung |

Keine einzelne Zeile sollte eine Zuordnung zu einem Staat mit hoher Sicherheit tragen. Verwende konkurrierende Hypothesen und benenne, welche Beobachtung jede einzelne falsifizieren würde.

## Minimale Telemetrie

1. **DNS:** Client, Anfrage, Typ, Antworten, TTL, Antwortcode, Resolver und Zeitstempel.
2. **Netzwerk-Flow:** Quelle/Ziel/Port, Start/Ende, Pakete/Bytes, TCP-Flags und Sensorstandort.
3. **TLS/HTTP:** SNI, sofern sichtbar, Zertifikat, ausgehandeltes Protokoll, Client-/Server-Fingerprint, Methode, Kategorie von Authority/Pfad, Status und Byte-Anzahl. Schütze vollständige URLs, sofern sie sensibel sind.
4. **Identität:** Authentifizierungsergebnis, Faktor/Zertifikat/Gerät, Quelle, Anwendung, Sitzungs-ID und Risikoentscheidung.
5. **Endpoint:** initiierender Prozess, übergeordneter Prozess, Benutzer, Binärsignatur/-Hash und Ziel.
6. **Edge-/Netzwerkgerät:** Konfigurationsdifferenz, Admin-Login, Prozess-/Datei-/Firmware-Integrität, Interface- und Flow-Logs.
7. **Cloud/SaaS/CDN:** Akteur, Tenant/Projekt, API-Aktion, Quelle, Objekt/Ressource, Token und Ergebnis.
8. **Wireless/NAC:** Station, Randomized-MAC-Flag, AP, Signal, EAP-Identität/Zertifikat, zugewiesene VLAN/IP und Sicherheitsstatus.

Synchronisiere die Uhren, bewahre die ursprünglichen Zeitzonen auf, dokumentiere NAT-/Proxy-Grenzen und speichere genügend Historie, um einen ORB-Knoten 31 Tage zu überdauern.

## Einen Zuordnungsgraphen erstellen

Stelle Beobachtungen als typisierte Knoten und Kanten dar:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Nützliche Knoten umfassen IP, Präfix, ASN, Domain, DNS-Konto, Zertifikat/Schlüssel, JA3/JA4-ähnlichen Fingerabdruck, HTTP-Grammatik, Datei-/Konfigurations-Hash, Cloud-Tenant, API-Token, E-Mail, Persona, Zahlungsmittel und physisches Gerät. Jede Kante benötigt `first_seen`, `last_seen`, Sensor/Quelle, Konfidenz sowie die Angabe, ob sie beobachtet oder abgeleitet wurde.

Die Graphdichte allein ist irreführend: Ein CDN oder eine Zertifizierungsstelle verbindet viele voneinander unabhängige Akteure. Seltene, vom Operator kontrollierte Beziehungen sollten stärker gewichtet werden – etwa dasselbe API-Konto, derselbe SSH-Schlüssel, dieselbe Origin-Allowlist, ein eindeutiger Response-Body oder dasselbe Kontrollprotokoll – als allgemeines Hosting.

## ORB und die Suche nach kompromittierten Routern

### Von einem beobachteten Exit aus

1. Bestimmen Sie, ob die Adresse Hosting, privat, mobil, im Bildungsbereich oder geschäftlich genutzt wird; private Quellen dürfen nicht verworfen werden.
2. Rufen Sie für einen begrenzten Zeitraum historische DNS-Daten, Services/Zertifikate, offene Ports sowie beobachtetes Scan-/Exploitation-Verhalten ab.
3. Suchen Sie nach Peers mit seltenen Service-Fingerprints, Controller-Zielen, Zertifikatsmaterial oder demselben Rotationszeitpunkt.
4. Klassifizieren Sie wahrscheinliche Rollen: Zugang, Traversierung, Exit/Staging oder Administration.
5. Prüfen Sie, ob mehrere voneinander unabhängige Intrusion-Cluster denselben Pool verwendet haben; Multi-Tenancy schwächt die direkte Actor-Attribution, stärkt jedoch die ORB-Hypothese.
6. Verfolgen Sie neue Knoten, die dem Rollenprofil entsprechen, nachdem alte IPs verschwunden sind.

### Beim Netzwerkbetreiber

- Alarmieren Sie bei neuen aus dem Internet erreichbaren Management-Schnittstellen sowie bei Standard-/Legacy-Authentifizierung.
- Senden Sie Router-/Firewall-/VPN-Konfigurationsänderungen und Admin-Authentifizierungen außerhalb des Geräts.
- Erstellen Sie eine Baseline für ausgehende Verbindungen von Infrastrukturen, die normalerweise nur wenige Sessions initiieren.
- Erkennen Sie neue Proxy-/Listener-Prozesse, Tunnel, geplante Tasks, Firmware-Änderungen und unerwartete DNS-Aktivität.
- Ersetzen Sie Geräte am Ende ihres Lebenszyklus; ein Neustart, der flüchtige Malware entfernt, behebt die Schwachstelle nicht.
- Beschränken Sie das Management auf eine authentifizierte Administrationsebene und bekannte Quellen.

Mandiant empfiehlt, ORB-Infrastruktur als sich entwickelnde Entität zu verfolgen, da das kurzzeitige Blockieren von IPs Topologie und Lebenszyklus nicht erfasst.<sup>[[1]](#references)</sup>

## Fast-flux- und Dynamic-DNS-Analysen

Aggregieren Sie nach registrierter Domain und einem gleitenden Zeitfenster. Ein praktischer Score kann Folgendes kombinieren:
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
Untersuchen Sie Domains anhand mehrerer unabhängiger Merkmale statt anhand eines einzelnen Schwellenwerts. Vergleichen Sie sie mit einem Allow-Modell für CDN/Anti-DDoS und prüfen Sie die Rotation autoritativer Name-Server, um Single Flux von Double Flux zu unterscheiden. Fügen Sie bei DGAs NXDOMAIN-Ausbrüche pro Client, die Längen-/Zeichenverteilung, synchronisierte Abfragen über mehrere Hosts hinweg sowie den Prozess hinzu, der sie erzeugt. Auch die aktuelle Anleitung von MITRE betont häufige Änderungen, eine niedrige TTL sowie die Korrelation von Prozess und Netzwerk.<sup>[[2]](#references)</sup>

## Erkennung von Domain-Fronting

Wenn der Enterprise-Endpunkt oder ein autorisierter Prüfpunkt über beide Identitäten verfügt, vergleichen Sie:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Erhöhen Sie die Konfidenz, wenn SNI und authority zu nicht miteinander verbundenen Tenants gehören, der Prozess kein freigegebener Client ist, die Sitzung periodisch oder langlebig ist und der innere Origin selten vorkommt. Ein leeres SNI ist ein zu erfassendes Merkmal und nicht automatisch bösartig. ECH kann das SNI im Netzwerkverkehr verbergen, wodurch Logs von Endpunkt, DNS und Provider/CDN wichtiger werden. MITRE dokumentiert sowohl Varianten mit nicht übereinstimmendem als auch mit leerem SNI.<sup>[[3]](#references)</sup>

## Erkennung von Dead-Drop-Resolver-Sequenzen

Das Verhalten mit hoher Aussagekraft ist eine Sequenz und nicht eine blockierte Domain:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Suche im gesamten Bestand nach identischen Objektpfaden, Response-Hashes, API-Identifiern und nachgelagerten Zielen. Bewahre abgerufene Inhalte auf, da der Akteur sie bearbeiten oder löschen kann. Schränke nicht benötigte Service-APIs ein und verlange, dass genehmigte Anwendungen Enterprise-Proxies verwenden, berücksichtige dabei jedoch Developer-Tools und Automation. MITRE führt GitHub, Foren, Dokumente und Social-/Web-Services in realen Verfahren auf.<sup>[[4]](#references)</sup>

## Clustering von Redirectors und wiederverwendbaren Deployments

Selbst wenn sich Domains und Adressen ändern, deployen Operatoren häufig dieselbe Automation erneut. Bilde Cluster anhand von Kombinationen aus:

- Zertifikatsfeldern/Schlüsselwiederverwendung und dem Zeitpunkt der Ausstellung;
- TLS-Version/Cipher/Erweiterungsreihenfolge und Serververhalten;
- identischem HTTP-Status, Header-Reihenfolge, Cache-Verhalten, Icon/Body und Fehlerseite;
- ungewöhnlichen Portpaaren und Redirect-Ketten;
- Muster des DNS-Providers/Name-Servers und TTL-Zeitplan;
- Deployment-Zeitpunkt, Uptime und Wartungsfenster;
- Offenlegung des Back-End-Ursprungs oder identischen Allowlists.

Eine einzelne generische Nginx-Seite ist ein schwaches Indiz. Mehrere seltene, unabhängige Übereinstimmungen plus zeitliche Kontinuität können die Hypothese eines Infrastruktur-Clusters rechtfertigen.

## Erkennung von Residential-Proxies und unmöglichen Sessions

Halte die Session-Identität oberhalb der IP-Ebene aufrecht. Kennzeichne Kombinationen wie:

- ein Session-/Geräte-Fingerprint wechselt schneller zwischen Ländern/ASNs, als es die Reisegeschwindigkeit erlaubt;
- eine Consumer-IP ändert sich bei jeder Anfrage, während Cookies und TLS-/Browser-Identität unverändert bleiben;
- das angeblich lokale Gerät weist Latenz, Zeitzone oder Sprache auf, die nicht zum Exit passen;
- eine Adresse wechselt zwischen nicht zusammengehörigen Account-Populationen oder zeigt Backconnect-Proxy-Verhalten;
- eine privilegierte Session erscheint über einen Residential-Zugang ohne Geräte-Zertifikat der Organisation.

Carrier-NAT, Accessibility-Tools, Corporate-VPNs und Reisen erzeugen gutartige Anomalien. Verlange eine Step-up-Authentifizierung oder Untersuchung, statt ausschließlich aufgrund von Labels wie „Residential Proxy“ irreversibel zu blockieren.

## Erkennung von Wireless- und verdeckten Geräten

Führe RADIUS/NAC mit AP- und physischem Kontext zusammen:

1. Finde erstmals beobachtete Account–Gerät–AP-Kombinationen.
2. Identifiziere Credentials, die ohne verwaltetes EAP-Zertifikat/verwaltete Posture verwendet werden.
3. Vergleiche gleichzeitig aktive Sessions und Badge-/Gebäudeanwesenheit.
4. Untersuche ungewöhnlich schwache/grenzwertige Signale und Bewegungen zwischen APs.
5. Suche auf nahegelegenen verwalteten Endpoints nach Wireless-Scanning, einer neu aktivierten Interface-Bridge/NAT, virtuellen Adaptern oder Tunneln.
6. Erfasse neue Switchports, DHCP-, USB-Netzwerk- und PoE-Aktivität.
7. Führe eine autorisierte RF-/physische Untersuchung durch, wenn die Indizien dies stützen.

Dies erkennt sowohl einen APT28-ähnlichen Pfad über den nächstgelegenen Nachbarn als auch einen bei einer Übung platzierten Drop. MAC-Randomisierung darf weder als Identität noch als Schuldbeweis behandelt werden.

## Erkennung finanzieller Attribution

- Bewahre die exakte Kette sowie Token-, Adress-, Transaktions- und Block-Identifier auf.
- Verfolge den Wert durch Change, Peel-Chains, Fan-out/in, Mixer, Bridges und Service-Einzahlungen, und kennzeichne dabei Heuristiken.
- Kor­reliere Zeitpunkt, Betrag abzüglich Gebühren, Contract-Event, Liquidität und Auszahlung auf die Ziel-Chain.
- Beschaffe oder bewahre rechtmäßig Exchange-, Bridge-, Händler-, Account-, Geräte- und Lieferdaten auf.
- Prüfe aktuelle sanktionierte Entitäten/Adressen und Derivate im Rahmen des geltenden Programms; verlasse dich nicht auf eine alte statische Liste.
- Behandle die Nutzung von Privacy-Protokollen als Input für den Risikokontext, nicht als Beweis für Fehlverhalten.

Die Red Flags der FATF sind ausdrücklich kontextabhängig: Ungewöhnliches Muster, Betrag/Häufigkeit, Geografie, Herkunft der Gelder und anonymitätssteigernde Services werden erst gemeinsam aussagekräftig.<sup>[[5]](#references)</sup>

## Täuschung und Canaries

Defender können Signale mit hoher Aussagekraft erzeugen, ohne zu versuchen, gewöhnliche Nutzer zu deanonymisieren:

- eindeutige Credentials oder Dokumente, die niemals ein System verlassen sollten;
- gefälschte administrative Endpoints und Decoy-Shares;
- instrumentierte DNS-Namen, die nur in kontrollierte Artefakte eingebettet sind;
- Canary-Cloud-Keys ohne legitime Verwendung;
- eine Decoy-Wi-Fi-Identität, die kein verwaltetes Gerät besitzt.

Lege den Umfang von Täuschungsmaßnahmen sorgfältig fest und verwalte sie entsprechend. Ein Canary sollte die missbräuchliche Nutzung eines eigenen Assets durch den Defender erkennen, nicht unabhängigen Traffic Dritter erfassen.

## Prioritäten für Gegenmaßnahmen

1. Entferne nicht unterstützte, aus dem Internet erreichbare Router, VPNs und Appliances.
2. Verlange phishing-resistente MFA und gerätegebundene Zertifikate, einschließlich internem/Wireless-Zugriff.
3. Zentralisiere ausreichend unveränderliche Identity-, Endpoint-, DNS-, Flow-, Proxy-, Cloud- und Netzwerkgeräte-Logs.
4. Beschränke Management und Egress; erfasse jeden extern erreichbaren Service.
5. Überwache DNS, Certificate Transparency und die Cloud-Konfiguration auf nicht autorisierte Assets.
6. Bewahre Prozess-zu-Netzwerk- und objektbezogene SaaS-Transparenz auf.
7. Übe Untersuchungen über mehrere Ebenen hinweg und die Koordination mit benachbarten Providern.
8. Verfolge Infrastruktur-Cluster und Verhaltensweisen, nicht nur IP-Blocklists.

## Analytische Disziplin

Verwende Formulierungen zur Konfidenz:

- **Beobachtet:** Ein Sensor-/Provider-Datensatz zeigt die Beziehung direkt.
- **Stark gestützt:** Mehrere unabhängige Beobachtungen sprechen eher dafür als für Alternativen.
- **Bewertet:** Schlussfolgerung auf Grundlage ausdrücklich genannter Annahmen und Belege.
- **Unbekannt:** Fehlende Transparenz verhindert eine Schlussfolgerung.

Behalte immer mindestens zwei Hypothesen bei: vom Akteur betriebene Infrastruktur gegenüber einem kompromittierten/geteilten Intermediär; ein Akteur gegenüber einem Multi-Tenant-Service; absichtliche Umgehung gegenüber legitimem Privacy-/CDN-Verhalten. Die Fähigkeit, Unsicherheit zu erklären, ist Bestandteil einer korrekten Erkennung.

## References

- [1] [Google Cloud/Mandiant — Spionageakteure mit China-Bezug nutzen ORB-Netzwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast-Flux-DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead-Drop-Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Red-Flag-Indikatoren für virtuelle Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Akteure aus der VR China kompromittieren kritische Infrastruktur und erhalten dauerhaften Zugriff](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Leitlinien für erweiterte Transparenz und Härtung von Kommunikationsinfrastruktur](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
