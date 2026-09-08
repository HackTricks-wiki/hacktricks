# Katalog der Techniken für anonymen Internetzugang

Dies ist das maßgebliche Inventar der Zugriffspfade. Es umfasst protokoll- und betriebstechnische **Familien**, nicht jeden Anbieternamen. Kein Internetpfad garantiert Anonymität: Konto-, Browser-, Endpunkt-, Timing-, Zahlungs-, Cloud-Control-Plane- und physische Beweise können eine perfekt wirkende Route entkräften.

Jeder Eintrag verwendet dieselben Felder. „Verfahren“ bedeutet eine rechtmäßige Bereitstellung oder eine Emulation in einem eigenen Labor. Wenn die reale Technik vom Kompromittieren eines Routers, dem Diebstahl von Zugangsdaten oder dem Missbrauch eines unwilligen Vermittlers abhängt, ersetzt die Reproduktion diese durch Systeme, die der Übung gehören.

## Abdeckungsmatrix

| Familie | Was das Ziel sieht | Stärkste Eigenschaft | Geschwindigkeit | Behandlung |
|---|---|---|---|---|
| Shared NAT/CGNAT | gemeinsame öffentliche Adresse | Mehrdeutigkeit zwischen Teilnehmern | hoch | einsetzbar |
| VPN, VPS, SOCKS/HTTP/SSH proxy | Relay-Adresse | schnelle Trennung der Quelladresse | hoch | einsetzbar |
| Multi-Hop/Split-Relay, MASQUE | letzter proxy | Wissensteilung oder vollständiger IP-Tunnel | hoch/moderat | mit vertrauenswürdigen Relays einsetzbar |
| Tor, Bridge, Onion Service | Exit- oder Onion-Identität | Pfad über mehrere Parteien und gemeinsamer Browser | moderat | einsetzbar |
| I2P, GNUnet, Mixnet | Overlay-Peer/Gateway | Overlay- oder Timing-Resistenz | niedrig/variabel | anwendungsspezifisch |
| OHTTP/ODoH, Private Relay | Gateway/Egress | Aufteilung von Quelle und Anfrage | hoch | nur unterstützte Anwendungen |
| Öffentliches WLAN, Travel Router | Venue-/Tunnel-Adresse | Änderung von Standort/Zugriffspfad | hoch | Zustimmung erforderlich |
| Mobilfunk/eSIM, Satellit | Carrier-/Provider-Adresse | unabhängiger physischer Uplink | hoch/variabel | Subscription/Provider beobachtet |
| Remote Browser/Jump Host | Remote Workspace | Trennung von Endpunkt und Egress | hoch | einsetzbar |
| Residential/Mobile Proxy | Consumer-/Carrier-Adresse | Erscheinungsbild eines Consumer-Netzes | hoch | Zustimmung/Herkunft entscheidend |
| ORB/kompromittiertes Relay | Adresse eines anderen Opfers | Verschleierung der Herkunft und geliehene Reputation | hoch | nur Reproduktion im eigenen Labor |
| CDN/Fronting/Redirector | CDN-/Front-Adresse | Schutz der Back-End-Infrastruktur | hoch | Zustimmung von Provider/Eigentümer erforderlich |
| Fast Flux/DGA/Dead Drop | rotierender Node/Service | Resistenz gegen Infrastrukturermittlung | variabel | nur Reproduktion im eigenen Labor |
| Drop/Nearest Neighbor | lokale zielnahe Adresse | Überquerung geografischer/Netzwerkgrenzen | hoch | nur Labor am eigenen Standort |
| Store-and-Forward/offline | Gateway oder physischer Empfänger | weniger interaktive Timing-Verknüpfung | niedrig | anwendungsspezifisch |
| Pluggable/Refraction Transport | Tor-Einstieg oder kooperierender Diversion-Proxy | zensurresistenter Zugriff | variabel | unterstützter Client oder Forschungslabor |
| IPFS Gateway/PIR/Remote Fetcher | Gateway oder Anwendungsservice | Trennung von Publisher, Query und Request | variabel | nur begrenzte Anwendung |
| Anycast/QUIC/MPTCP | stabiler Broker oder mehrere Subflows | Rendezvous und Session-Kontinuität | hoch | Verfügbarkeit, nicht Anonymität |
| CI/CD-Automation-Runner | Adresse des Hosted Runners | kurzlebiger, nachvollziehbarer Egress | hoch | nur eigener Workflow |
| Nicht-IP-basierter lokaler erster Hop | Organisations-Gateway | Entfernen des Internet-Stacks vom Sensor | niedrig | vom Eigentümer genehmigte Bereitstellung |

## Direktes Shared NAT und Carrier-Grade NAT

**Mechanik:** Mehrere Nutzer teilen sich eine öffentliche Adresse; der Access-Provider ordnet Teilnehmeradressen und Ports dem öffentlichen Tupel zu.

**Vorteile:** schnell; kein spezieller Client; die IP allein auf der Zielseite identifiziert möglicherweise nur einen Haushalt, Veranstaltungsort oder Carrier-Pool.

**Nachteile:** Der Provider kann Teilnehmer-/Port-/Zeitzuordnungen speichern; Konten und Fingerprints bleiben bestehen; andere Nutzer können die Reputation der Adresse beschädigen.

**Verfahren:** (1) Bestätigen, ob der autorisierte Zugriff NAT/CGNAT verwendet; (2) die exakte öffentliche IP und den Quellport an einem eigenen Endpunkt aufzeichnen; (3) Anwendungsidentitäten getrennt halten; (4) Shared Addressing nicht als Privacy-Control behandeln; (5) einen stärkeren Pfad verwenden, wenn der ISP Ziele nicht kennen darf.

**Erkennung:** Ziele sollten Quellport und genaue Zeit, nicht nur die IP speichern. Provider korrelieren NAT-Zuweisungslogs; Ermittler verknüpfen Konto-, Geräte- und Browserbeweise.

## Kommerzielles VPN

**Mechanik:** Eine verschlüsselte Full-Tunnel-Verbindung endet beim VPN; Ziele sehen dessen Egress. Das VPN kann Quelle, Timing und Ziele normalerweise einander zuordnen.

**Vorteile:** schnell; einfach; schützt vor lokaler passiver Beobachtung; stabile oder gemeinsam genutzte Exits; gut für kontrollierten Red-Team-Egress.

**Nachteile:** konzentriertes Vertrauen; Billing-/Login-Telemetrie; Kill-Switch-/DNS-/IPv6-Fehler; Shared Exits werden häufig wegen ihrer Reputation blockiert.

**Verfahren:** (1) Provider, Eigentümer, Gerichtsbarkeit, Aufbewahrung und Assessment-Policy bestimmen; (2) den signierten offiziellen Client installieren; (3) Full Tunnel, Always-on und Fail-closed-Verhalten aktivieren; (4) DNS und IPv6 bewusst routen; (5) beobachtete IPv4-/IPv6-/DNS-Werte an einem eigenen Endpunkt prüfen; (6) Tunnel stoppen/neu verbinden und bestätigen, dass kein unverschlüsselter Fallback möglich ist.<sup>[[1]](#references)</sup>

**Erkennung:** Lokale Netzwerke sehen einen langen verschlüsselten Datenstrom zur VPN-Infrastruktur; Provider besitzen Authentifizierungs-/Verbindungsdaten; Ziele verwenden ASN-/Reputation- sowie Konto-, TLS-/Browser- und Verhaltenskorrelation.

## Selbst gehosteter VPN- oder gemieteter VPS-Egress

**Mechanik:** Der Betreiber kontrolliert ein WireGuard-/OpenVPN-Gateway oder leitet Datenverkehr über einen gemieteten Server weiter.

**Vorteile:** vorhersehbare hohe Geschwindigkeit; feste, in Allowlists aufnehmbare Adresse; individuelles Logging/Firewalling; gute Incident-Kontrolle.

**Nachteile:** kleine Anonymitätsmenge; Cloud-Tenant, Zahlung, Quell-Login, API- und Image-Historie verknüpfen den Betreiber; ein neuer, charakteristischer Server lässt sich leicht clustern.

**Verfahren:** (1) ein engagementbezogenes Organisationsprojekt erstellen; (2) ein unterstütztes Image und eine feste Adresse bereitstellen; (3) Management auf MFA-/schlüsselbasierte Administration beschränken; (4) Full-Tunnel-Egress und DNS konfigurieren; (5) Ziele nach Möglichkeit auf den vorgesehenen Umfang beschränken; (6) Leak-/Fehlerverhalten testen; (7) Controller-Auditdaten aufbewahren; (8) Credentials und Ressourcen beim Abbau löschen.

**Erkennung:** Hosting-ASN, erstmals beobachtete Adresse, Zertifikats-/Service-Fingerprint und Scanverhalten korrelieren; Cloud-Eigentümer verwenden Control-Plane-, Console-, Billing- und Flow-Logs.

## HTTP CONNECT, SOCKS und SSH Forwarding

**Mechanik:** Eine Anwendung fordert einen Proxy auf, einen TCP-Datenstrom zu öffnen; SOCKS kann je nach Version auch Namensauflösung und UDP übertragen; SSH leitet Datenströme innerhalb einer verschlüsselten Sitzung weiter.

**Vorteile:** leichtgewichtig; pro Anwendung; schnell; nützlich für Chaining und segmentierte Netzwerke.

**Nachteile:** Anwendungen können ihn umgehen; DNS kann leaken; der Proxy sieht benachbarte Endpunkte; Browserstatus bleibt erhalten; offene Proxies können Fallen oder kompromittierte Systeme sein.

**Verfahren:** (1) den Proxy auf einem eigenen Host bereitstellen; (2) Authentifizierung verlangen und Quelle/Ziel beschränken; (3) ein verfügbares Anwendungsprofil konfigurieren; (4) bei Bedarf Remote-DNS-Auflösung sicherstellen; (5) mit einem eigenen DNS-/HTTP-Endpunkt prüfen; (6) direkten Egress für die Workload blockieren; (7) Proxy-Credentials prüfen und rotieren.

**Erkennung:** tunnel-fähige Prozesse, CONNECT-/SOCKS-Verhandlung, lange SSH-Sitzungen und mit der Anwendung unvereinbare Ziele identifizieren; Proxy-Logs rekonstruieren die Datenströme.

## URL-umschreibender Web-Proxy und Browser-Proxy-Extension

**Mechanik:** Eine Website ruft ein Ziel ab und schreibt Links/Formulare über ihren eigenen Origin um, oder eine Extension leitet Browseranfragen an einen Proxy. Das Ziel sieht den Service, während der Service nach der TLS-Terminierung Klartext lesen sowie Inhalte einschleusen oder speichern kann.

**Vorteile:** kein systemweiter Client; schnell für einfaches Browsing; funktioniert, wenn VPN-Installation unmöglich ist.

**Nachteile:** Der Proxy kann Credentials/Inhalte lesen, Downloads umschreiben und Nutzer fingerprinten; Scripts/WebSockets/Downloads können ihn umgehen; die Browser-Extension besitzt weitreichende Rechte; kleine Anonymitätsmenge und häufige Blockierung.

**Verfahren:** (1) nur einen organisationsbetriebenen Proxy für autorisierte Tests verwenden; (2) ihn in einem verfügbaren Browser ohne persönliche Konten isolieren; (3) Passworteingabe und sensible Downloads verbieten; (4) auf einer eigenen Seite prüfen, dass jede Subresource über den Proxy aufgelöst wird; (5) WebSocket-, Download- und Formularverhalten testen; (6) Extension/Profil danach entfernen.

**Erkennung:** Das Ziel protokolliert den Proxy; Enterprise-Proxy/DNS und Extension-Inventar identifizieren den Service; Content-Security-/Reporting- oder eigene Canary-Subresources zeigen direkten Bypass; Proxy-Logs ordnen Benutzersitzungen den Zielen zu.

## Multi-Hop-Proxy oder Multi-Hop-VPN eines Providers

**Mechanik:** Ein Einstieg sieht die Quelle, während ein oder mehrere Traversal-Relays sie von einem Exit trennen, der das Ziel sieht.

**Vorteile:** Kein gewöhnliches Relay benötigt beide Enden; Ausfall/Beschlagnahme eines Knotens offenbart weniger; flexible Geografie.

**Nachteile:** Gemeinsame Administration/Logs beseitigen die Trennung; Latenz; Timing-Korrelation; mehr Fehler- und DNS-Pfade; dasselbe Konto/dieselbe Zahlung kann alle Hops verbinden.

**Verfahren:** (1) festlegen, welchen Beobachter jeder Hop entfernt; (2) bei erforderlicher Trennung unabhängig verwaltete eigene/genehmigte Relays verwenden; (3) nur Entry-Zugriff aus der Workload erzwingen; (4) sicherstellen, dass jedes Relay nur den nächsten Hop erreicht; (5) Logs auf jeder Ebene prüfen; (6) jeden Hop stoppen und Fail-closed-Verhalten bestätigen. Mit [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) reproduzieren.

**Erkennung:** Benachbarte NetFlow-Zeitpunkte/-Volumina, wiederholte Proxy-Handshakes und gemeinsame Controller-Infrastruktur korrelieren; die Betreibergeografie nicht aus dem Exit ableiten.

## Anwendungssplit-Relay und OHTTP

**Mechanik:** Der Client verschlüsselt eine zustandslose HTTP-Nachricht für ein Gateway und sendet sie über ein Relay. Das Relay sieht die Client-IP, aber nicht die Anfrage; das Gateway sieht die Anfrage, normalerweise jedoch nur die Relay-IP.

**Vorteile:** starke, auditierbare Privacy-Trennung für unterstützte Requests; geringerer Overhead als allgemeine Anonymitätsnetzwerke.

**Nachteile:** kein beliebiges Browsing; Cookies/Authentifizierung können erneut verknüpfen; Kollusion von Relay/Gateway und Traffic-Analyse bleiben möglich; die Anwendung muss dies implementieren.

**Verfahren:** (1) eine Anwendung auswählen, die RFC 9458 ausdrücklich unterstützt; (2) Gateway-Schlüssel über den offiziellen Konfigurationspfad prüfen; (3) stabile benutzerbezogene Felder vermeiden; (4) nur den unterstützten zustandslosen Request senden; (5) Relay-, Gateway- und Ziellogs vergleichen; (6) Schlüsselrotation/-fehler ohne direkten Fallback testen.<sup>[[2]](#references)</sup>

**Erkennung:** Enterprise-Endpunkte zeigen den initiierenden Prozess und das OHTTP-Relay; Gateways erkennen fehlerhafte/wiederholte Daten; Timing sowie stabile Payload-/Kontofelder können Requests korrelieren.

## MASQUE CONNECT-UDP/CONNECT-IP und HTTP-Privacy-Proxies

**Mechanik:** HTTP Extended CONNECT über TLS/QUIC transportiert UDP- oder IP-Pakete durch einen Proxy. Dies kann einen modernen VPN-ähnlichen Tunnel implementieren und den Transport mit HTTP/3 vermischen, der Proxy bleibt jedoch Beobachter.<sup>[[3]](#references)</sup>

**Vorteile:** effizientes Multiplexing/Roaming; unterstützt UDP oder vollständiges IP; Bereitstellung über moderne HTTP-Infrastruktur.

**Nachteile:** kein Anonymitätsnetzwerk; Proxy/Konto sehen Quelle und Ziele; QUIC-/HTTP-Fingerprints und bekannte Pfade sind für Endpunkte/Provider sichtbar.

**Verfahren:** (1) einen Client/Service mit dokumentierter RFC-9298-/9484-Unterstützung verwenden; (2) Proxy-Zertifikat/-Konfiguration authentifizieren; (3) erlaubte Zielrouten definieren; (4) verschlüsseltes DNS innerhalb des Pfads aktivieren; (5) UDP, TCP, IPv6 und Failover an eigenen Endpunkten prüfen; (6) Proxy-Request- und Flow-Logs untersuchen.

**Erkennung:** Endpunkte sehen den Clientprozess und das virtuelle Interface; Netzwerke können anhaltendes QUIC/TLS zu einem Proxy klassifizieren; Proxy-Logs legen CONNECT-Ziel/-Pfad und zugewiesene Routen offen.

## Tor Browser

**Mechanik:** Tor wählt Guard-, Middle- und Exit-Relays; mehrschichtige Verschlüsselung begrenzt die Sicht jedes Relays. Tor Browser fügt einen standardisierten Browser hinzu, der Fingerprinting erschweren soll.

**Vorteile:** große öffentliche Anonymitätsmenge; kein gewöhnliches Relay kennt beide Enden; Ziel-Unlinkability ohne eigene Server.

**Nachteile:** langsamer; TCP-orientiert; Exit-Reputation/-Blockierung; Logins und Offenlegungen identifizieren den Nutzer; Low-Latency-Timing-Korrelation bleibt möglich.

**Verfahren:** (1) Tor Browser vom Projekt herunterladen und prüfen; (2) Standardeinstellungen beibehalten und Extensions vermeiden; (3) geeignete Sicherheitsstufe auswählen; (4) separate Identität/Sitzung erstellen; (5) identifizierende Konten und externe aktive Dokumente vermeiden; (6) HTTPS oder authentifizierte Onion Services verwenden; (7) Exit nur mit einem eigenen Endpunkt prüfen.<sup>[[4]](#references)</sup>

**Erkennung:** Lokale Netzwerke können bekannten Guard-Datenverkehr identifizieren, sofern keine Bridge/kein Transport verwendet wird; Ziele sehen Exits und Tor-Browser-Verhalten; Ende-zu-Ende-Beobachter korrelieren Timing/Volumen.

## Tor Bridges und Pluggable Transports

**Mechanik:** Eine nicht öffentliche Bridge ersetzt den öffentlichen Guard; obfs4, Snowflake oder WebTunnel verändern den First-Hop-Transport, um einfache Blockierung/Probing zu erschweren.

**Vorteile:** umgeht Zensur und verbirgt offensichtliche Ziele öffentlicher Relays; behält den Tor-Circuit nach dem Einstieg bei.

**Nachteile:** Transportmuster/Bridge-Ermittlung bleiben möglich; variable Leistung; kein zusätzlicher Schutz vor Konten oder globalem Timing.

**Verfahren:** (1) zuerst direktes Tor versuchen; (2) in den Tor-Browser-Connection-Einstellungen einen integrierten unterstützten Transport auswählen oder eine offizielle Bridge anfordern; (3) keine zufälligen Binärdateien/Listen verwenden; (4) verbinden und einen harmlosen Test durchführen; (5) Reconnect und Uhrzeit testen; (6) alle anderen Browsereinstellungen standardmäßig belassen.<sup>[[5]](#references)</sup>

**Erkennung:** Zensoren verwenden Zielermittlung, Protokoll-/Flow-Klassifizierung und aktives Probing; Verteidiger sollten Umgehungsnutzung von Kompromittierung unterscheiden und sich auf Endpunktprozess/-kontext stützen.

## VPN vor Tor und Tor vor VPN

**Mechanik:** VPN-before-Tor verbirgt die direkte Tor-Nutzung vor dem Access-ISP, gibt die Quelle jedoch dem VPN preis. Tor-before-VPN gibt dem VPN Datenverkehr nach Tor und oft eine stabile Kunden-/Tunnelidentität.

**Vorteile:** entfernt bei korrektem Design einen bestimmten Beobachter; kann Netze erreichen, die eine Ebene blockieren.

**Nachteile:** Komplexität, ungewöhnlicher Fingerprint, Leaks, kleinere Anonymitätsmenge und falsches Vertrauen; das Tor Project betrachtet Kombinationen als fortgeschritten.<sup>[[6]](#references)</sup>

**Verfahren:** (1) den entfernten und den neu eingeführten Beobachter dokumentieren; (2) eine verfügbare Umgebung verwenden; (3) nur den vorgesehenen äußeren Pfad aufbauen; (4) Firewall-Routen erzwingen; (5) DNS/IPv4/IPv6 und jede Fehlerreihenfolge prüfen; (6) Sichtbarkeit beider Provider vergleichen; (7) den Stack verwerfen, wenn kein messbarer Vorteil besteht.

**Erkennung:** Lokale/VPN-/Tor-Beobachter sehen unterschiedliche benachbarte Ebenen; Timing bleibt Ende-zu-Ende; ungewöhnliche verschachtelte Tunnel-Fingerprints und Providerkonten können Sitzungen verknüpfen.

## Onion Service

**Mechanik:** Client und Service bauen Tor-Circuits zu einem Rendezvous auf, wodurch die Service-IP verborgen und ein Exit vermieden wird.

**Vorteile:** Schutz von Quelle und Service-Standort; Ende-zu-Ende-Onion-Authentifizierung; kein öffentlicher Inbound-Port; optionale Client-Autorisierung.

**Nachteile:** Origin-Leaks durch Updates/Analytics/Fehler; der Onion-Schlüssel ist kritisch; Anwendungsidentität/Timing und Host-Kompromittierung bleiben bestehen.

**Verfahren:** (1) Anwendung isolieren und nur an Loopback/Socket binden; (2) unterstütztes Tor installieren; (3) einen v3-Onion-Service nach offiziellen Anweisungen konfigurieren; (4) Schlüssel nur schützen/sichern, wenn eine stabile Identität erforderlich ist; (5) für geschlossene Nutzung Client-Autorisierung hinzufügen; (6) Drittanbieterabrufe entfernen; (7) extern prüfen, dass der Origin nicht erreichbar ist.<sup>[[7]](#references)</sup>

**Erkennung:** Host-/Netzwerkverteidiger finden Tor-Prozess/-Konfiguration und ausgehende Circuits; Anwendungsfehler, DNS, Zertifikate oder Drittanbieterressourcen können den Origin offenlegen.

## I2P-interne Services

**Mechanik:** I2P verwendet getrennte unidirektionale Inbound-/Outbound-Tunnel für Ziele innerhalb des Overlays; Public-Internet-Outproxies bilden einen Vertrauenspunkt.

**Vorteile:** dezentrale interne Veröffentlichung; keine Abhängigkeit von einem offiziellen Exit; getrennte Ein- und Ausgangspfade.

**Nachteile:** kein allgemeiner Webersatz; kleineres Ökosystem; lang laufendes Peer-Verhalten; Outproxy kann öffentliches Browsing beobachten.

**Verfahren:** (1) aus offizieller Quelle installieren; (2) einen dedizierten Kontext verwenden; (3) Integration/Bandbreitenstabilisierung erlauben; (4) einen eigenen I2P-nativen Service aufrufen; (5) Outproxies vermeiden, sofern nicht ausdrücklich erforderlich; (6) prüfen, dass das Beenden keinen direkten Fallback erzeugt; (7) lokale Peer- und Service-Logs untersuchen.<sup>[[8]](#references)</sup>

**Erkennung:** Lokale Netzwerke sehen langlebigen Peer-Datenverkehr und Bootstrap-Verhalten; Endpunkte legen Router-/Anwendungsprozesse offen; Outproxies protokollieren Exits.

## Mixnets

**Mechanik:** Pakete fester Größe, Batching, Verzögerung, Neuordnung und Cover Traffic reduzieren Timing-Korrelation; Gateways verbinden Anwendungen.

**Vorteile:** besserer Schutz gegen Timing-Analyse als Low-Latency-Proxies; nützlich für asynchrone Nachrichten/Transaktionen.

**Nachteile:** Latenz, Bandbreiten-Overhead, kleinere Bereitstellung und Anwendungsgrenzen; Gateway-/Kontometadaten können bestehen bleiben.

**Verfahren:** (1) einen gepflegten Client und eine unterstützte Anwendung auswählen; (2) das tatsächliche Threat Model lesen; (3) in einem separaten Compartment installieren; (4) harmlose Daten an einen eigenen Endpunkt senden; (5) Latenz/Zuverlässigkeit und Antwortpfad messen; (6) Gateway-Ausfall testen; (7) Verzögerungen/Cover Traffic niemals nur für Geschwindigkeit deaktivieren.<sup>[[9]](#references)</sup>

**Erkennung:** Endpunkte identifizieren den Client; Zugangsnetze können Gateways/Paketkadenz klassifizieren; Gateways und Exits sehen benachbarte Rollen, während umfassendere Korrelation längere statistische Zeitfenster erfordert.

## GNUnet Anonymous File Sharing

**Mechanik:** GNUnet kann Publish-/Search-/Download-Requests über Peers routen und abhängig von einer Anonymitätsstufe Cover Traffic hinzufügen. Die eigene Dokumentation warnt, dass Standardstufe 1 keinen Cover Traffic verlangt und leistungsfähige Traffic-Analyse den Ursprung identifizieren kann.<sup>[[10]](#references)</sup>

**Vorteile:** dezentrales, anwendungsnahes anonymes Sharing; einstellbare Anforderungen an Cover Traffic.

**Nachteile:** kein gewöhnlicher anonymer Webzugriff; Performance-/Speicherkosten; Peer- und Traffic-Analyse-Limits; die GNUnet-VPN-Dokumentation erklärt, dass das IP-Overlay keine gute Anonymität bietet.

**Verfahren:** (1) einen gepflegten offiziellen Build installieren; (2) einen Test-Peer isolieren; (3) Bandbreite/Speicher begrenzen; (4) eine harmlose eindeutige Testdatei mit gewählter Anonymitätsstufe veröffentlichen; (5) sie von einem anderen eigenen Peer abrufen; (6) Cover Traffic und Latenz aufzeichnen; (7) nicht behaupten, die IP-VPN-Komponente biete gleichwertige Anonymität.

**Erkennung:** Peer-Bootstrap, Overlay-Datenverkehr, lokaler Datastore/Prozess und Datei-Identifier; ein umfassender Beobachter kann Datenvolumen gegen Cover Traffic analysieren.

## Verschlüsseltes DNS, ODoH und ECH

**Mechanik:** DoH/DoT/DoQ verschlüsseln zum Resolver; ODoH teilt Clientadresse und Query zwischen Proxy und Resolver; ECH verschlüsselt den inneren TLS ClientHello/Servernamen.

**Vorteile:** entfernt Plaintext-DNS/SNI von einigen lokalen Beobachtern; ODoH teilt die Kenntnis von Quelle und Query.

**Nachteile:** kein IP-Anonymitätspfad; Resolver/Proxy/Server behalten ihre Rollen; Ziel-IP, Timing, Volumen und Endpunkt bleiben sichtbar; Fallback kann leaken.

**Verfahren:** (1) festlegen, ob OS, Anwendung oder Tunnel DNS kontrolliert; (2) strikten verschlüsselten Modus oder unterstütztes ODoH aktivieren; (3) eine eigene eindeutige Domain testen; (4) lokal mitschneiden und fehlende Klartext-Queries bestätigen; (5) Resolverausfall herbeiführen und gewünschtes Verhalten prüfen; (6) bei ECH bestätigen, dass Serverdiagnosen die Annahme des inneren ClientHello anzeigen.<sup>[[11]](#references)</sup>

**Erkennung:** Endpunkt-/Resolver-Logs legen Queries offen; Netzwerke identifizieren verschlüsselte Resolver-Endpunkte und Ziel-Flows; ECH-Zustand ist an Endpunkten/CDN sichtbar, auch wenn er im Pfad verborgen ist.

## Split-Provider Privacy Relay

**Mechanik:** Produkte wie iCloud Private Relay verwenden einen Ingress, der den Client kennt, und einen unabhängig betriebenen Egress, der das Ziel kennt, mit grober Regionsbehandlung.

**Vorteile:** reibungsarme Wissensteilung; schnell; integrierter DNS-/Webschutz für unterstützten Datenverkehr.

**Nachteile:** Produkt-/Anwendungsumfang ist begrenzt; Konto-/Plattformprovider identifiziert weiterhin den Kunden; keine beliebige Systemanonymität; Kollusions-/Rechts- und Timing-Risiken.

**Verfahren:** (1) exakt unterstützte Anwendungen und Datentypen bestätigen; (2) die Funktion gegebenenfalls in einem dedizierten Plattformkontext aktivieren; (3) Regionsverhalten auswählen; (4) Safari/DNS und nicht unterstützte Anwendungen getrennt testen; (5) Zieladresse untersuchen; (6) Netzwerkwechsel/-ausfall testen.<sup>[[12]](#references)</sup>

**Erkennung:** Der Zugriff sieht den Ingress; das Ziel sieht den Egress; Plattform-/Relay-Logs und Kontodaten umfassen jeweils ihre Ebene; nicht unterstützte Anwendungen legen normale Pfade offen.

## Remote Browser, VDI, RDP oder organisatorischer Jump Host

**Mechanik:** Browsing/Tool-Ausführung findet auf einem Remote-System statt; das Ziel sieht dessen Egress, während der Workspace-Provider die Betreiberverbindung und Control Plane sieht.

**Vorteile:** schnell; isoliert riskante Inhalte; stabiler kontrollierter Egress; verfügbarer Zustand und starke Organisationsprüfung.

**Nachteile:** Provider/Admin kann Sitzung/Konto beobachten; Bildschirm-/Clipboard-/Dateikanäle leaken; Remote-Browser-Fingerprint kann eindeutig sein; gegenüber dem Workspace-Eigentümer nicht anonym.

**Verfahren:** (1) pro Engagement einen organisations-eigenen Workspace erstellen; (2) MFA verlangen und Administration beschränken; (3) Clipboard/Upload/Download deaktivieren oder begrenzen; (4) über genehmigten festen Egress routen; (5) keine persönliche IdP-/Sync-Nutzung; (6) nur geprüfte Beweise exportieren; (7) Workspace und Credentials planmäßig vernichten.

**Erkennung:** Provider- und IdP-Logs ordnen Nutzer Sitzungen zu; Ziele clustern Workspace-Egress/Browser; Enterprise-Verteidiger erkennen Remote-Control-Protokolle und ungewöhnliche Cloud-Sitzungen.

## Öffentliches oder Gäste-WLAN

**Mechanik:** Datenverkehr verlässt das Netzwerk über Venue-NAT oder einen dort gestarteten Tunnel.

**Vorteile:** hohe Geschwindigkeit und gemeinsam genutzte Nicht-Heimadresse; keine eigene Infrastruktur.

**Nachteile:** Venue-Zuordnung/DHCP/Portal, Kameras, Kauf- und Standortbeweise; feindliche Peers/APs; Nutzungsbedingungen; physisches Risiko.

**Verfahren:** (1) Gästen angebotenen Zugang verwenden und SSID beim Personal bestätigen; (2) ein gepatchtes Gerät mit geringem Vertrauensniveau verwenden; (3) Sharing/Auto-Join deaktivieren und private MAC aktivieren; (4) Portal ohne wiederverwendete Identität abschließen; (5) Fail-closed-VPN-/Tor-Pfad starten; (6) Tethering-Datenverkehr prüfen; (7) Netzwerk vergessen.

**Erkennung:** Venue korreliert AP, MAC, DHCP, Portal und Zeit; Ziel sieht Venue/Tunnel; Ermittler kombinieren physische und Gerätebeweise. Zugriffskontrollen niemals umgehen.

## Travel Router

**Mechanik:** Ein eigener Router verbindet sich mit Venue-WLAN/Ethernet und stellt ein isoliertes internes Netzwerk mit erzwungener Tunnel-Policy bereit.

**Vorteile:** isoliert Workstations; zentraler Kill Switch/DNS; konsistentes Client-Netzwerk; schützt privilegierte Endpunkte vor lokalen Broadcasts.

**Nachteile:** Router wird zu einem stabilen Funk-/DHCP-Fingerprint; zusätzliche Angriffsfläche; Captive Portals und Tethering können den Tunnel umgehen.

**Verfahren:** (1) unterstützte Firmware aktualisieren; (2) eindeutige Management-Credentials setzen und WAN-Admin/WPS/UPnP deaktivieren; (3) erlaubten privaten Upstream-MAC konfigurieren; (4) separate interne SSID erstellen; (5) Full-Tunnel-DNS-/IPv6-Firewall-Policy erzwingen; (6) Portal, Reconnect und Tunnelausfall testen.

**Erkennung:** Venue sieht Routerassoziation und Traffic-Form; lokale RF-/DHCP-Fingerprinting identifiziert ihn; VPN-Provider sieht die Venue-Quelle.

## Mobilfunk, Prepaid-SIM und eSIM

**Mechanik:** Ein Modem verwendet Carrier-Funkzugang und üblicherweise Carrier-NAT; eine VPN-/Tor-Schicht kann den für das Ziel sichtbaren Exit ändern.

**Vorteile:** unabhängig vom lokalen kabelgebundenen/WLAN-Netz; mobil; hohe Geschwindigkeit; nützlicher Backhaul für autorisierte Drops.

**Nachteile:** Carrier kennt Subscriber/eSIM, IMSI, IMEI, Zellen, Zeit und zugewiesene Ports; Registrierungsgesetze variieren; gemeinsame Nutzung mit dem persönlichen Telefon verbindet Geräte.

**Verfahren:** (1) Dienst rechtmäßig und mit den erforderlichen korrekten Angaben beziehen; (2) separates Organisationsmodem/-gerät verwenden; (3) beim Übungscontroller registrieren; (4) nicht zugehörige Funkmodule/Konten deaktivieren; (5) genehmigten Tunnel aufbauen; (6) prüfen, ob verbundene Clients ihm tatsächlich folgen; (7) Provider- und Aufbewahrungsannahmen vor Reisen prüfen.<sup>[[13]](#references)</sup>

**Erkennung:** Carrierdaten und RF-Standort; Enterprise-USB-/PCI-/MDM-Inventar und Rogue-Hotspot-Prüfungen; Ziel-/Tunnel-Timing.

## Satelliteninternet und Missbrauch von Satelliten-Downlinks

**Mechanik:** Normaler Dienst verwendet ein registriertes Terminal/einen Provider. Älterer einseitiger DVB-S-Missbrauch erlaubte es einem Empfänger innerhalb eines Beams, unverschlüsselten Downlink-Datenverkehr für einen legitimen Teilnehmer zu beobachten, während ein anderer Pfad für ausgehende Requests verwendet wurde.

**Vorteile:** große Reichweite; unabhängige letzte Meile; historischer einseitiger Missbrauch konnte C2 fälschlich der Geografie eines Teilnehmers zuordnen.

**Nachteile:** Geräte-/RF-/Providerdaten; Latenz und Abdeckung; moderne bidirektionale Systeme unterscheiden sich; Outbound-Pfad und asymmetrisches Routing bleiben Beweise.

**Verfahren:** Für rechtmäßigen Zugriff ein eigenes Terminal registrieren und Datenverkehr nach Bedarf tunneln. Zur Emulation historischen Turla-Verhaltens synthetische One-Way-Packet-Captures in einem RF-freien Labor abspielen und prüfen, ob Analysten eine Antwort an einen Host erkennen, der keine Anfrage gestellt hat; keinen Live-Satellitendatenverkehr abfangen.<sup>[[14]](#references)</sup>

**Erkennung:** Provider-/Terminaltelemetrie, RF-Richtungsermittlung, unmöglicher/asymmetrischer Flow, RTT-/Routing-Inkonsistenz und Malware-Konfiguration.

## Residential-/Mobile-Proxy oder Proxyware mit Zustimmung

**Mechanik:** Ein Backconnect-Gateway weist Consumer-Breitband-/Mobilfunk-Exits zu, entweder dauerhaft oder rotierend. Das Angebot kann einvernehmlich, täuschend gebündelt oder bösartig sein.

**Vorteile:** hohe Geschwindigkeit; geografische Auswahl; Consumer-ASN umgeht einige Hosting-Blockierungen; große Pools.

**Nachteile:** Herkunfts-/Zustimmungs- und Rechtsrisiko; Broker sieht Kunden; infizierte Exits schädigen Opfer; Rotation erzeugt Anomalien; teuer und unzuverlässig.

**Verfahren:** Für Emulation nur dokumentierte Agents mit informierter Zustimmung und Organisationsbesitz verwenden: (1) Testendpunkte registrieren; (2) Eigentümer/IPs inventarisieren; (3) Gateway konfigurieren; (4) Sticky-/Per-Request-Modi rotieren; (5) nur an ein eigenes Ziel senden; (6) Gateway-/Exit-/Ziellogs vergleichen; (7) jeden Agent entfernen.

**Erkennung:** Unmögliche Reisen, stabiler Browser/Account über schnelle IP-/ASN-Wechsel, Backconnect-Protokolle, Proxyware-Prozess-/Netzwerkartefakte und Broker-/Controller-Beziehungen.

## ORB-, Botnet- und kompromittierte Edge-Device-Relays

**Mechanik:** Gemietete oder kompromittierte Router/IoT-Geräte/Server bilden von einer Flotte verwaltete Zugangs-, Traversal- und Exit-Rollen. Mehrere APT-Kunden können sie gemeinsam nutzen.

**Vorteile:** geliehene Reputation/Geografie; kurzlebige Exits; ausfallsicheres Multi-Hop-Mesh; schwache direkte Akteur-IP-Verknüpfung.

**Nachteile:** Kriminalität gegen Opfer; Implant-/Controller- und Flottenmuster; Beschlagnahme von Vermittlern; inkonsistente Leistung; Betreiber-/Kundenunterlagen.

**Verfahren:** Niemals reale Geräte kompromittieren. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) verwenden: (1) isolierte Entry-/Transit-/Target-Netze erstellen; (2) eigene dual-homed Relay-Container anbinden; (3) nur einen Testport weiterleiten; (4) harmlose Anfrage senden; (5) prüfen, dass das Ziel nur den Exit sieht; (6) Exit rotieren; (7) alle benannten Assets abbauen.<sup>[[15]](#references)</sup>

**Erkennung:** Topologie, Ports/Services, Controllerbeziehungen, Implant-Fingerprints und Node-Lebenszyklus verfolgen; Edge-Konfiguration/Flow-/Integritätstelemetrie zentralisieren; Exit-IP nicht mit dem Akteur gleichsetzen.

## CDN-Redirector, Domain Fronting und domainless Fronting

**Mechanik:** Ein öffentlicher Edge leitet nur Datenverkehr weiter, der einer Grammatik entspricht; Fronting verwendet ein harmloses äußeres SNI und eine andere innere HTTP-Authority oder leeres SNI, sofern der Vermittler dies erlaubt.

**Vorteile:** verbirgt/schützt das Back-End; schneller globaler Edge; vermischt das Ziel mit einem Shared Service; schnelles Umschalten.

**Nachteile:** CDN sieht gesamtes Routing und Tenant; viele Provider verbieten Cross-Tenant-Fronting; SNI/Host/Prozess/Flow und Kontenartefakte; wiederverwendete Konfigurationen clustern Kampagnen.

**Verfahren:** Nur auf einem eigenen Reverse Proxy mit [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) reproduzieren: lokalen Zertifikats-/Edge-Dienst erstellen, einen abweichenden Host an ein eigenes Ziel routen, SNI und Host protokollieren, normale/abweichende Requests senden und anschließend Container entfernen.<sup>[[16]](#references)</sup>

**Erkennung:** SNI/ECH/Host/`:authority` am Endpunkt oder terminierenden Edge vergleichen; initiierenden Prozess, Tenant/Origin, Request-Grammatik und Flow-Kadenz verknüpfen.

## Dynamic DNS, DGA, Fast Flux und Double Flux

**Mechanik:** DDNS aktualisiert einen stabilen Namen; DGA erzeugt wechselnde Kandidatennamen; Fast Flux rotiert Serviceadressen mit niedriger TTL; Double Flux rotiert zusätzlich Nameserver.

**Vorteile:** robuste Ermittlung; schneller Infrastrukturersatz; verbirgt Controller hinter vielen Nodes.

**Nachteile:** DNS erzeugt zentrale Telemetrie; Entropie/NXDOMAIN/Churn; niedrige TTL und breite ASN-Muster; Registrierung und autoritative Infrastruktur bleiben.

**Verfahren:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry) verwenden: eine eigene Zone bereitstellen, die RFC-5737-Adressen mit fünf Sekunden TTL zurückgibt, wiederholt abfragen, die synthetische Epoche ändern und Analytics validieren. Testrecords niemals auf Dritte verweisen.<sup>[[17]](#references)</sup>

**Erkennung:** einzigartige Antworten/ASNs im Sliding Window, Median-TTL, Geografie, autoritativer Churn, DGA-NXDOMAIN-/lexikalische/zeitliche Cluster und nachfolgende Prozesse; legitime CDNs kontextbezogen ausschließen.

## Legitimer Webservice, Dead-Drop-Resolver und One-Way-Tasking

**Mechanik:** Ein öffentlicher Post, ein Repository, Dokument, Objekt oder Feed enthält einen codierten aktuellen Endpunkt oder Task. Der Client kann Ergebnisse über einen anderen Kanal zurückgeben.

**Vorteile:** erlaubter Service mit hoher Reputation; TLS; Endpunktrotation ohne Binäränderung; asymmetrisches Tasking erschwert einfache Flow-Korrelation.

**Nachteile:** stabile Objekt-/Konto-/API-Identifier; Providerdaten; Endpunkt-Decoding/Folgezugriff; Inhalte können beschlagnahmt oder geändert werden.

**Verfahren:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence) verwenden: einen codierten Pointer in einem eigenen Container hosten, ihn von einem kurzlebigen Client abrufen/dekodieren, einen zweiten eigenen Service kontaktieren, beide Logs aufbewahren und anschließend abbauen.

**Erkennung:** ungewöhnlichen Prozess → Lesen eines stabilen Objekts → Decoding → neues Ziel korrelieren; Inhalte hashen/aufbewahren und vollständige Objektpfade, nicht nur Domains, speichern.

## Serverless-, kurzlebiger Container- und Cloud-NAT-Egress

**Mechanik:** Functions/kurzlebige Jobs laufen hinter Provider-NAT oder einem Front; der logische Service bleibt stabil, während Instanzen und Adressen rotieren.

**Vorteile:** schnelle Bereitstellung/Zerstörung; geteilter Egress im Providermaßstab; wenig lokaler Datenträger; elastisches regionales Routing.

**Nachteile:** Tenant, Rolle, API, Image, Secret, Invocation, Billing und Front-to-Origin-Logs sind dauerhaft; Cold-Start- und Plattform-Fingerprints; Provider-Policy.

**Verfahren:** (1) eigenen Organisations-Übungstenant verwenden; (2) harmlose Function bereitstellen, die nur einen eigenen Endpunkt anfragt; (3) Projekt/Rolle/Image/Konfiguration aufzeichnen; (4) über mehrere Instanzen ausführen; (5) Ziel-IPs mit Audit-/Request-IDs vergleichen; (6) Logaufbewahrung testen; (7) Function, Rollen und Secrets entfernen.

**Erkennung:** Cloud-Audit-/Invocation-Logs, ungewöhnliche Rollenerstellung, geteilter Egress mit stabiler Request-Grammatik, wiederverwendete Images/Layers/Secrets und Front-Origin-Korrelation.

## Autorisierter On-Site-Drop

**Mechanik:** Ein inventarisierter Kleincomputer verwendet lokales Wired/Wi-Fi und einen ausgehenden VPN-/Mobilfunk-Rendezvous und präsentiert eine lokale Quelle.

**Vorteile:** realistischer Test interner Herkunft; hohe Geschwindigkeit; testet NAC, physisches Inventar und Egress-Kontrollen.

**Nachteile:** physische Entdeckung/Diebstahl; Serial/MAC/USB/DHCP/PoE/RF- und Kamera-Beweise; Verlust kann Credentials offenlegen.

**Verfahren:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) befolgen: (1) exakt schriftliche Platzierungsgenehmigung einholen; (2) Seriennummer, MAC, Foto, Standort und Abholzeit erfassen; (3) signiertes Minimal-Image und kurzlebige gegenseitige Credentials verwenden; (4) ausgehende Ziele/Fähigkeiten beschränken; (5) serverseitige Quarantäne und Bandbreitenlimits hinzufügen; (6) SOC-Sichtbarkeit und Verlustreaktion testen; (7) abrufen, erforderliche Beweise sichern und anschließend gemäß vereinbarter Lifecycle-Policy bereinigen. Niemals an einem nicht zustimmenden Ort verstecken.

**Erkennung:** NAC/802.1X, Switchport/PoE/DHCP, USB-Inventar, RF-Survey, wiederkehrender Tunnel, Empfang/Kamera und physische Inspektion.

## Nearest-Neighbor-Wireless-Pivot

**Mechanik:** Ein Akteur kontrolliert einen Host in Funkreichweite des Ziels und verwendet anschließend Ziel-WLAN-Credentials, um die Grenze remote zu überqueren. APT28 nutzte nahegelegene kompromittierte Organisationen auf diese Weise.<sup>[[18]](#references)</sup>

**Vorteile:** keine Anreise des Betreibers; Ziel sieht eine lokale Funkquelle; Kontrollen, die nur den Internetzugang schützen, werden umgangen.

**Nachteile:** nahegelegener kompromittierter/eigener Dual-Radio-Host und gültiger Zugriff erforderlich; RADIUS/NAC/AP- und Nachbarendpunktbeweise; Signal-/Geräteanomalien.

**Verfahren:** Nur mit dem [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduzieren: einen eigenen Pivot mit Nachbar- und Ziel-Labor-SSID verbinden, nur einen Service weiterleiten, beide AP-/Pivot-Logs erfassen, anschließend EAP-TLS/Gerätehaltung aktivieren und bestätigen, dass der zweite Versuch scheitert.

**Erkennung:** RADIUS-Identität, verwaltetes Zertifikat/Device Posture, erstmals erkanntes Gerät, AP-Rand/Signal, parallelen Login und physische Präsenz korrelieren; nahe Endpunkte auf gleichzeitige Funkmodule, Forwarding und Tunnel untersuchen.

## Community Mesh, Delay-Tolerant und Offline Store-and-Forward

**Mechanik:** Datenverkehr durchläuft lokale Peers, asynchrone Gateways, Wechselmedien oder geplante Queues statt einer interaktiven Internet-Sitzung.

**Vorteile:** funktioniert bei Störung/Zensur; verzögerte/gebündelte Zustellung schwächt einfache Timing-Analyse; kein zentraler letzter Hop für lokale Kommunikation.

**Nachteile:** hohe Latenz; kleine Anonymitätsmenge; Übergabe-/physische Metadaten; bösartige Peers; Daten erreichen schließlich ein Gateway, das sie beobachtet.

**Verfahren:** (1) isoliertes eigenes Drei-Knoten-Mesh oder eine File-Queue aufbauen; (2) Inhalte Ende-zu-Ende verschlüsseln/authentifizieren; (3) direkte Internet-Routen vom Ursprung entfernen; (4) harmlose Datei nach kontrollierter Verzögerung weiterleiten; (5) prüfen, dass nur das Gateway das eigene Ziel kontaktiert; (6) Übergabe-/Zeitstempel vergleichen; (7) erforderliche Beweise sichern und temporäre Medien/Queues beim genehmigten Abschluss bereinigen.

**Erkennung:** Endpunkt-Datei-/Prozessaktivität, Peer-Funkverbindungen, Wechselmedien-Audit, Queue-/Gateway-Periodizität und Content-Identifier. Längere Korrelationsfenster ersetzen die interaktive Flow-Analyse.

## TURN Relay und erzwungenes Relay in WebRTC

**Mechanik:** Traversal Using Relays around NAT (TURN) weist eine öffentliche Relay-Adresse zu und überträgt UDP-, TCP- oder TLS-Daten zwischen Client und Peers. Eine ICE-Policy kann Relay-Nutzung erzwingen, statt einen direkten Candidate offenzulegen. TURN löst Erreichbarkeit, nicht allgemeine Anonymität: Der Server authentifiziert den Client und beobachtet Allocations, Peers, Zeit und Volumen.<sup>[[19]](#references)</sup>

**Vorteile:** weit verbreitet implementiert; bewältigt restriktives NAT; unterstützt mobiles WebRTC; der Peer erhält bei korrekt erzwungener Relay-only-Policy nicht die direkte Transportadresse des Clients.

**Nachteile:** TURN-Betreiber sieht beide benachbarten Seiten; Anwendungsidentität, Medien-Fingerprint und Signaling bleiben; Relay-only kostet Bandbreite/Latenz; Fehlkonfiguration kann weiterhin Host- oder serverreflexive Candidates sammeln.

**Verfahren:** (1) eigenen TURN-Service mit TLS und kurzlebigen Credentials bereitstellen; (2) Realms, Peers, Ports, Quotas und Ablauf beschränken; (3) Testanwendung auf Relay-only ICE setzen; (4) eigenen Peer anrufen; (5) `getStats()` und Packet Capture prüfen und bestätigen, dass nur Relay-Candidates Medien übertragen; (6) Relay ausfallen lassen und direkten Fallback ausschließen; (7) Allocation-Logs für das Engagement aufbewahren.

**Erkennung:** Signaling, Browserprozess und TURN-Allocations verbinden Sitzung und Relay; Netzwerke beobachten anhaltende Flows zu TURN-Ports oder TLS-Endpunkten; der Peer sieht das zugewiesene Relay. **Erfasster Node:** Anwendungszustand und kurzlebige TURN-Credentials können Realm und Rendezvous-Service offenlegen. Exposition durch gerätebezogene, kurzlebige Credentials minimieren und Betreiber-Authentifizierung ausschließlich am Controller halten.

## Outbound-Only-Rendezvous oder Reverse Overlay

**Mechanik:** Ein Node hinter NAT initiiert eine authentifizierte Verbindung zu einem organisationskontrollierten Broker. Der Betreiber authentifiziert sich separat am Broker, der einen engen Managementkanal autorisiert; weder Inbound-Port-Forwarding noch direkte Betreiber-zu-Node-Route ist erforderlich.

**Vorteile:** stabil hinter NAT und Captive Last Miles; zentrale Sperrung und Auditierung; wechselnde Field-Node-Adressen erfordern keine Betreiberermittlung; Betreiberidentität und Node-Credential werden sauber getrennt.

**Nachteile:** Broker wird zu einem wertvollen Korrelationspunkt; regelmäßige Keepalives sind erkennbar; ein breiter Tunnel kann zu einem unsicheren Pivot werden; Verlust des Brokers beendet Management.

**Verfahren:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous) befolgen: eine begrenzte Geräteidentität ausstellen, nur eigenen Broker und genehmigten Management-Service erlauben, authentifizierte Keepalives verwenden, Fail-closed-Routing erzwingen, Adresswechsel und Neustartwiederherstellung testen und die Identität während der Verlustübung widerrufen. WireGuard dokumentiert ein persistentes Keepalive von 25 Sekunden als allgemein nützliches NAT-Intervall, wenn es tatsächlich benötigt wird.<sup>[[20]](#references)</sup>

**Erkennung:** Broker- und IdP-Logs ordnen beide Seiten zu; das Zugangsnetz sieht ein wiederholtes verschlüsseltes Ziel/eine Kadenz; Endpunktinventar zeigt den Overlay-Agent. **Erfasster Node:** davon ausgehen, dass Geräteschlüssel, Brokername, Tunneladressen und gecachte Taskdaten offengelegt sind. Er darf keinen privaten Betreiberschlüssel, kein persönliches Konto und kein wiederverwendbares Controller-Token enthalten.

## Pull-Mailbox, Message Queue oder Object-Store-Rendezvous

**Mechanik:** Eine Field-Workload fragt eine authentifizierte Mailbox nach signierten, vorab genehmigten Jobs ab und sendet begrenzte Ergebnisse. Der Betreiber schreibt über eine separate Control Plane in die Queue; zwischen ihnen besteht kein interaktiver Socket.

**Vorteile:** toleriert unterbrochene Verbindungen; entkoppelt Timing und Adressierung; Quotas und Schemas begrenzen Fähigkeiten; einfache zentrale Auditierung und Sperrung.

**Nachteile:** Polling-Kadenz und stabile Objekt-/Queue-Namen fingerprinten das System; Provider-Logs verbinden Producer und Consumer; verzögerte Steuerung; erfasste Queue-Daten können die Übung offenlegen.

**Verfahren:** (1) eine Engagement-Queue und eine Geräteidentität erstellen; (2) signiertes Schema harmloser, ausdrücklich begrenzter Jobs definieren; (3) Nachrichten-TTL, maximale Ergebnisgröße und Rate setzen; (4) Node nur seine Queue lesen und nur in sein Ergebnispräfix schreiben lassen; (5) Offline-Akkumulation, doppelte Zustellung und Widerruf testen; (6) unveränderliche Zugriffslogs zentralisieren; (7) Queue nach Erfüllung der Aufbewahrungspflichten löschen.

**Erkennung:** periodische API-Aufrufe eines ungewöhnlichen Prozesses, stabile Bucket-/Objekt-/Queue-Pfade, identisches User-Agent-/TLS-Verhalten und Fetch-then-new-connection-Sequenzen suchen. **Erfasster Node:** lokaler Cache kann ausstehende Jobs und Objektnamen offenlegen; Cache verschlüsselt, begrenzt und löschbar halten, autoritative Controller-Logs jedoch bewahren.

## Dual-Uplink-Failover und Connection Migration

**Mechanik:** Ein genehmigter Field Node besitzt zwei unabhängige Uplinks, etwa Venue-Ethernet/Wi-Fi und Organisationsmobilfunk, und hält seine Control Session über ein Overlay oder einen Message Broker aufrecht, während sich Routen ändern. Dies ist Verfügbarkeits-, nicht Anonymitätsengineering.

**Vorteile:** übersteht Ausfall eines Providers, APs oder Captive Portals; unterstützt geplante Wartung; ermöglicht schnelle Isolierung eines verdächtigen Pfads.

**Nachteile:** Zwei Provider erzeugen zwei Standort-/Kontodaten; gleichzeitige Nutzung erleichtert Korrelation; Routen-/DNS-Leaks beim Failover; Mobilfunk-Co-Location bleibt ein Beweis.

**Verfahren:** (1) beide organisations-eigenen Interfaces und Provider registrieren; (2) deterministische Routenprioritäten und Health Checks zu eigenen Endpunkten zuweisen; (3) DNS und Management an das Overlay binden; (4) verhindern, dass der sekundäre Pfad Inbound-Verkehr annimmt; (5) jeden Pfad trennen und Session-Wiederherstellung, Quellpolicy sowie fehlenden direkten Zielzugriff prüfen; (6) ungeplanten Pfadwechsel alarmieren; (7) Datennutzung und Roaming-Limits dokumentieren.

**Erkennung:** dasselbe Gerätezertifikat, dieselbe Request-Grammatik und dasselbe Timing über ASNs korrelieren; lokales Inventar sieht beide Funkmodule; Carrier/Venues behalten eigene Daten. **Erfasster Node:** beide SIM-/Geräte-Identifier und bekannte SSIDs können sichtbar sein; Organisationsressourcen verwenden und Node niemals mit persönlichen Geräten zusammenbringen.

## Organisations-eigener APN oder verwalteter Mobilfunktunnel

**Mechanik:** Ein privater Carrier-APN platziert eingeschriebene SIMs in einer privaten gerouteten Domain oder tunnelt Datenverkehr zu einem Enterprise-Gateway. Er trennt das Gerät vom öffentlichen Mobilinternet, verbirgt es jedoch nicht vor Carrier oder beauftragter Organisation.

**Vorteile:** stabile private Adressierung; Carrier-Enrollment und Traffic-Policy; kein öffentlicher Inbound; nützlich für autorisierte Remote-Appliances.

**Nachteile:** Subscriber-, IMSI-/IMEI-, Zell- und Billing-Zuordnung sind stark; Vorlaufzeit und Kosten; Carrier-/Gateway-Ausfall; gegenüber dem Betreiber nicht anonym.

**Verfahren:** (1) APN im Namen der Assessment-Organisation beauftragen; (2) nur registrierte SIMs und Gateway-Präfixe allowlisten; (3) gegenseitige Authentifizierung auf Anwendungsebene hinzufügen; (4) APN-Route auf Rendezvous- und Update-Services beschränken; (5) SIM-Entfernung, Roaming, Public-Internet-Breakout und Widerruf testen; (6) Carrier- und Gateway-Daten überwachen; (7) jede SIM beim Abschluss kündigen oder unter Quarantäne stellen.

**Erkennung:** Carrierinventar und Zelltelemetrie, APN-Gateway-Flows, SIM-/IMEI-Abweichung und Enterprise-Asset-Daten. **Erfasster Node:** SIM und Modem identifizieren den Vertrag auch bei verschlüsseltem Speicher; Capture-Resilience bedeutet daher schnelle Sperrung und enge Autorisierung, nicht Abstreitbarkeit.

## Drahtlose Langstrecken-Punkt-zu-Punkt-Brücke

**Mechanik:** Richtfunk-Wi-Fi oder ein anderes lizenziertes/nicht lizenziertes Point-to-Point-Radio verbindet zwei genehmigte Standorte; der Internet-Egress liegt am entfernten Standort. Die scheinbare IP-Position kann ohne kommerziellen Proxy verlagert werden.

**Vorteile:** hoher Durchsatz; unabhängig von zwischengeschalteten Carriern; kontrollierbares RF und Routing; nützlich zum Testen von Segmentierung und Remote-Site-Monitoring.

**Nachteile:** Sichtlinie, Frequenz, Vermieter- und Regulierungsanforderungen; charakteristische RF-Emissionen und Hardware; beide Endpunkte sind physischer Beweis; Wetter/Strom/Ausrichtung beeinflussen Stabilität.

**Verfahren:** (1) schriftliche Genehmigung für beide Standorte einholen und Frequenz-/Leistungsregeln prüfen; (2) Pfad ohne Senden außerhalb genehmigter Parameter untersuchen; (3) authentifizierte Verschlüsselung und Management-VLAN verwenden; (4) Bridge auf eigenes Rendezvous oder Testsubnetz beschränken; (5) Failover, Ausrichtung, Stromwiederherstellung und RF-Eindämmung testen; (6) beide Funkgeräte kennzeichnen/inventarisieren; (7) entfernen und nach der Übung Konfigurationsreset prüfen.

**Erkennung:** RF-Surveys, Spektrumanalyse, Dach-/Standortinspektion, Bridge-MAC/OUI, Managementdaten und Remote-Site-Egress-Logs. **Erfasster Node:** Konfiguration offenbart Peer und Managementdomain; eindeutige Übungs-Credentials, keine persönlichen Managementkonten und schnelle Peer-Key-Sperrung verwenden.

## Einvernehmlicher kooperativer oder Community-Exit

**Mechanik:** Freiwillige oder Partnerorganisationen betreiben wissentlich Relays nach veröffentlichter Policy. Datenverkehr verlässt das Netz aus einem gemeinsamen Community-Pool, während die Koordination Missbrauch und Sperrungen verwaltet.

**Vorteile:** vielfältige Nicht-Cloud-Netze; ausdrückliche Zustimmung ist sicherer als Proxyware; gemeinsame Governance kann Vertrauen verteilen; nützlich für Forschung und Zensurresilienz.

**Nachteile:** kleine Pools und Mitgliederdaten reduzieren Anonymität; Exit-Betreiber erhalten Beschwerden und sehen Traffic-Metadaten; bösartige Teilnehmer, variable Verfügbarkeit und unterschiedliche Gerichtsbarkeiten.

**Verfahren:** (1) Acceptable-Use- und Logging-Policy veröffentlichen; (2) informierte Opt-ins jedes Betreibers einholen; (3) eindeutige Relay-Identität ausstellen und Ziele/Raten beschränken; (4) Abuse-Handling und sofortige Sperrung bereitstellen; (5) während Tests nur autorisierten Datenverkehr zu eigenen Endpunkten senden; (6) Churn und Korrelationsexposition messen; (7) Relay sauber entfernen, wenn Zustimmung endet.

**Erkennung:** Mitgliedschafts-/Control-Plane-Daten, Relay-Zertifikate, gemeinsamer Software-Fingerprint und Exit-Verhalten identifizieren den Pool. **Erfasster Node:** Relay-Konfiguration kann die Kooperation identifizieren, darf jedoch keine Clientidentitäten enthalten; Client-to-Session-Accountability am autorisierten Controller zugriffskontrolliert speichern.

## IPv6 Temporary Addresses und Präfixrotation

**Mechanik:** IPv6 Privacy Extensions erzeugen temporäre Interface-Identifier, sodass eine stabile Adresse nicht für jede ausgehende Verbindung wiederverwendet wird. Provider-Präfixwechsel können zusätzliche Rotation erzeugen, Präfix, Teilnehmerdaten und Fingerprint höherer Schichten bleiben jedoch.<sup>[[21]](#references)</sup>

**Vorteile:** reduziert passives langfristiges Tracking durch einen stabilen Interface-Identifier; in gängigen Betriebssystemen integriert; kein Relay-Overhead.

**Nachteile:** keine Quellenanonymität; ISP und lokales Netzwerk kennen Präfix/Gerät weiterhin; DNS, Konten und Browserstatus verknüpfen Sitzungen; Adresswechsel erschwert Allowlists und Logging.

**Verfahren:** (1) aktuelle stabile und temporäre Adressen eines eigenen Clients prüfen; (2) vom OS unterstützten Privacy-Address-Standard statt Spoofing durch Drittanbieter aktivieren; (3) wiederholt einen eigenen IPv6-Endpunkt über die Lebensdauer der Adressen anfragen; (4) bestätigen, dass Inbound-Services nur an vorgesehene stabile Adressen gebunden sind; (5) DHCPv6-/RA-/Neighbor- und genaue Endpunktlogs aufbewahren; (6) VPN-/Firewall-Verhalten für jede IPv6-Adresse testen.

**Erkennung:** delegiertes Präfix, Layer-2-Identität, Neighbor Discovery, Konto- und Endpunkttelemetrie korrelieren, statt eine Adresse als ein Gerät zu behandeln. **Erfasster Node:** Netzwerkprofile und Interface-Identifier bleiben; temporäre Adressen verhindern einen passiven Identifier, nicht forensische Zuordnung.

## Tor Pluggable Transports: Snowflake, WebTunnel, obfs4 und meek

**Mechanik:** Ein Pluggable Transport verändert das Erscheinungsbild der ersten Tor-Verbindung oder deren Weg zu einer Bridge. Snowflake verwendet kurzlebige freiwillige WebRTC-Proxies, WebTunnel ähnelt gewöhnlichem HTTPS, obfs4 widersteht einfacher Protokollerkennung und aktivem Probing, und meek leitet über unterstützte Web-Infrastruktur. Dies sind Zensurumgehungstransporte in Tor, keine zusätzlichen Ende-zu-Ende-Anonymitätsschichten.<sup>[[22]](#references)</sup>

**Vorteile:** nützlich, wenn direktes Tor oder bekannte Relays blockiert werden; Snowflake vermeidet eine stabile öffentliche Bridge-Adresse; in gepflegte Tor-Clients integriert; das Ziel erhält weiterhin gewöhnliche Tor-Eigenschaften.

**Nachteile:** geringere oder variable Leistung; Broker/Front/Bridge und lokales Netzwerk sehen unterschiedliche Metadaten; Transport-Fingerprints und Blockierung bleiben möglich; freiwillige Proxies ersetzen Tor nicht und sollten keinen Klartext der Anwendung erhalten.

**Verfahren:** (1) offiziellen Tor Browser oder unterstützten Tor Client installieren und prüfen; (2) integrierten Transport in Connection/Bridges auswählen; (3) nur eine eigene Diagnose-Seite aufrufen; (4) bestätigen, dass die Seite einen Tor-Exit, nicht den Snowflake-/WebTunnel-Peer sieht; (5) Bootstrap und Leistung vergleichen; (6) Transport ausfallen lassen und bestätigen, dass der Client nicht stillschweigend direkt verbindet; (7) nach dem Test zur standardmäßig unterstützten Konfiguration zurückkehren.

**Erkennung:** Ein Zensor kann Ziel-Allowlists, TLS-/WebRTC-Verhalten, Brokerermittlung und Flow-Analyse kombinieren; Endpunkte legen Tor- und Transportkonfiguration offen. **Capture-resilient OPSEC:** Standardclient verwenden, niemals persönlichen Browserstatus hineinkopieren und davon ausgehen, dass Bridge-/Broker-Historie wiederherstellbar ist. **Monitoring:** Tor-Bootstrap-Logs, unerwartete direkte DNS-/Verbindungsversuche und Beobachtungen eigener Seiten am Controller überwachen; Transportausfall ist kein Beweis für Entdeckung.

## Refraction Networking oder Decoy Routing

**Mechanik:** Ein kooperierender Netzwerkbetreiber erkennt ein verdecktes Signal in Datenverkehr, der scheinbar an ein erlaubtes Decoy adressiert ist, und leitet den Flow an einen Circumvention-Proxy um. Die Bereitstellung erfordert Infrastruktur im Netzwerkpfad; ein Client kann dies nicht allein durch Auswahl einer harmlosen Website erzeugen.<sup>[[23]](#references)</sup>

**Vorteile:** Das scheinbare Ziel kann für einen Zensor schwer blockierbar sein, ohne Kollateralschäden zu verursachen; keine öffentliche Bridge-Adresse muss verteilt werden; nützliches Forschungsmodell für pfadunterstützte Umgehung.

**Nachteile:** spezialisierte ISP-/Transitbeteiligung; Bereitstellbarkeit und Performance hängen vom Routing ab; Client-to-Decoy-Flow und Proxyaktivität bleiben; ein globaler oder kooperierender Beobachter kann Timing korrelieren.

**Verfahren:** Nicht über unbeteiligte Netzwerke signalisieren. Architektur nur in einem isolierten Labor reproduzieren: (1) eigene Client-, Router-, Decoy- und Proxy-Namespaces erstellen; (2) harmlose markierte Testanfrage verwenden; (3) eigenen Router nur dieses Tag an den Proxy umleiten lassen; (4) Pre-/Post-Routing-Tupel und Request-IDs protokollieren; (5) normale und signalisierte Flows vergleichen; (6) False Positives und Entfernung testen; (7) Laborrouten zerstören.

**Erkennung:** Autorisierte Netzwerkbetreiber können Routingabweichung, ungewöhnliches ClientHello-/Tag-Verhalten und Diskrepanzen zwischen Decoy- und Back-End-Flows untersuchen. **Capture-resilient OPSEC:** Ein Forschungsclient sollte nur Testschlüssel und Dokumentationsadressen besitzen. **Monitoring:** signierte Entscheidungen des Laborrouters mit Proxyankünften vergleichen; keine Produktions-Transitprovider sondieren, um deren Erkennung zu bestimmen.

## Content-Addressed Gateway oder Cached Peer Retrieval

**Mechanik:** Ein HTTP-Gateway ruft einen IPFS Content Identifier (CID) ab, gegebenenfalls aus Cache oder von Peers, und gibt den verifizierbaren Inhalt an den Client zurück. Der ursprüngliche Publisher kann das Gateway oder andere Peers statt des endgültigen Lesers sehen; das Gateway sieht Leser-IP und angeforderten CID. Native Peer-to-Peer-Abrufe setzen den Client Peers und DHT-/Routingteilnehmern aus.<sup>[[24]](#references)</sup>

**Vorteile:** Publisher und Leser können durch Caches getrennt werden; unveränderliche Inhalte sind hash-verifizierbar; replizierte Daten überleben den Ausfall eines Hosts; HTTP-Clients benötigen keinen nativen Peer-Stack.

**Nachteile:** öffentliche CIDs und Gateway-Logs zeigen Interessen; Timing des ersten Abrufs kann Publisher und Leser korrelieren; bösartige Webinhalte und Path-Style-Same-Origin-Risiken; öffentliche Gateways sind Best Effort und verbieten Missbrauch.

**Verfahren:** (1) harmlose Testdatei in einem eigenen privaten IPFS-Swarm oder eigenen Gateway veröffentlichen; (2) CID aufzeichnen; (3) über ein separates eigenes HTTP-Gateway mit Subdomain-Isolation abrufen; (4) Bytes gegen CID verifizieren; (5) nach dem Caching wiederholen; (6) Publisher-, Peer- und Gateway-Logs vergleichen; (7) Testinhalt nach Ende der Aufbewahrung entpinnen und entfernen.

**Erkennung:** Gateways protokollieren Quelle/CID; DHT- und Peer-Verbindungen zeigen Abruf; Endpunkthistorie und Dateihashes identifizieren Inhalt. **Capture-resilient OPSEC:** keinen privaten Publishing-Schlüssel auf einem schreibgeschützten Field Client speichern und sensible Inhalte vor der Content-Adressierung verschlüsseln. **Monitoring:** unerwartetes Pinning, Peer-Set-Änderung, CID-Anfragen außerhalb der Allowlist oder Gateway-Kontohinweise alarmieren.

## Private Information Retrieval Service

**Mechanik:** Private Information Retrieval (PIR) ermöglicht es einem Client, einen Datensatz aus einer Datenbank abzurufen, während der ausgewählte Index gegenüber dem Server kryptografisch verborgen bleibt, gemäß einem festgelegten Single- oder Multi-Server-Threat-Model. Es schützt die Query-Auswahl für einen begrenzten Datensatz, ist jedoch kein allgemeiner Webzugriff oder IP-Anonymität.<sup>[[25]](#references)</sup>

**Vorteile:** starke anwendungsspezifische Query-Privacy; messbares Leckagemodell; nützlich für Schlüsselverzeichnisse, Blocklists oder kleine öffentliche Datenbanken; kann die Offenlegung exakter Suchbegriffe vermeiden.

**Nachteile:** Rechen-/Bandbreiten-Overhead; Server erfährt Verbindungszeit/IP, sofern kein Relay verwendet wird; Dataset-Version, Antwortgröße und Anwendungszustand können Nutzer trennen; Reife der Implementierung variiert.

**Verfahren:** (1) auditierte PIR-Implementierung gegen synthetische eigene Datenbank bereitstellen; (2) Dataset-Version und Parameter veröffentlichen; (3) mehrere Indizes mit identischen Request-Größen abrufen; (4) Korrektheit lokal prüfen; (5) Server-Logs vergleichen und bestätigen, dass der Index fehlt; (6) bösartige/gekürzte Antworten und Versionsabweichung testen; (7) die genaue Privacy-Annahme dokumentieren, statt von anonymem Browsing zu sprechen.

**Erkennung:** Netzwerke sehen Service-Nutzung und Volumen; Endpunkttelemetrie legt Client und endgültige Datensatznutzung offen; ein kompromittierter Server kann Datensätze oder Timing manipulieren. **Capture-resilient OPSEC:** nur öffentliche Datenbankparameter und einen begrenzten Cache auf dem Client speichern. **Monitoring:** signierte Dataset-Roots, feste Request-Formen, Änderungen der Fehlerrate und Server-Key-Rotationen validieren.

## Begrenzter serverseitiger Fetcher, Preview- oder Rendering-Service

**Mechanik:** Ein Remote-Service ruft eine URL ab oder rendert sie und gibt Screenshot, Metadaten oder bereinigten Inhalt zurück. Das Ziel sieht die Fetcher-Adresse; der Service sieht Requester, URL und Ergebnis. Der Missbrauch von Link-Preview-Bots, Security-Scannern oder URL-Fetchern Dritter ist keine autorisierte Proxy-Nutzung.

**Vorteile:** isoliert aktive Inhalte von der Workstation; Ziel erhält einen kontrollierten Fetcher-Fingerprint; Dateiart, Größe, Ziel und Rendering-Limits können erzwungen werden; verfügbare Ausführungsumgebung.

**Nachteile:** Service besitzt vollständige Requestkenntnis; Konto-/API-/Billing-Daten; SSRF- und Datenexfiltrationsrisiko; Scripts, Authentifizierung und interaktive Websites können nicht funktionieren; eindeutige URLs korrelieren Requester und Fetch.

**Verfahren:** (1) eigenen Fetcher mit strikter Allowlist eigener Testdomains bereitstellen; (2) private, link-local, Metadaten- und Redirect-to-unapproved-Adressen blockieren; (3) Methoden, Redirects, Bytes und Renderzeit begrenzen; (4) Credentials/Cookies entfernen; (5) eigene URL übermitteln; (6) Requester-, Fetcher- und Ziellogs vergleichen; (7) Renderinstanz zerstören und zentrales Audit gemäß Policy aufbewahren.

**Erkennung:** Ziel sieht Service-ASN/Fingerprint; Provider- und Controller-Logs ordnen Requester der URL zu; Endpunktprozess/API-Aufrufe zeigen die Übermittlung. **Capture-resilient OPSEC:** ein kurzlebiges Projekttoken ohne beliebige Zielberechtigung verwenden. **Monitoring:** Allowlist-Ablehnungen, Redirect-Verstöße, Fetches ohne Controller-Job-ID und Provider-Abuse-Hinweise alarmieren.

## Anycast-Rendezvous-Pool

**Mechanik:** Mehrere organisationskontrollierte Nodes announcen oder fronten eine stabile Serviceadresse; Routing wählt eine nahe Instanz. Anycast verbessert Verfügbarkeit und verbirgt ein einzelnes Back-End vor dem Client, der Betreiber kontrolliert jedoch alle Instanzen und die Serviceadresse bleibt stabil.<sup>[[26]](#references)</sup>

**Vorteile:** resiliente regionale Ingresses; keine Field-Node-Neukonfiguration bei Ausfall einer Instanz; DDoS-/Lastverteilung; zentrale Policy kann Sitzungen zwischen bekannten Nodes verschieben.

**Nachteile:** BGP-/CDN- und Providerdaten identifizieren die Organisation; Pfadwechsel können zustandsbehaftete Sitzungen abbrechen; Monitoring unterscheidet sich je nach Clientstandort; eine stabile Adresse ist leicht blockier- oder reputationsclusterbar.

**Verfahren:** Provider-gestütztes eigenes Organisationsprojekt oder isoliertes Routing-Labor verwenden: (1) zwei identische authentifizierte Health-Endpunkte bereitstellen; (2) eine dokumentierte Serviceadresse veröffentlichen; (3) Sitzungszustand am Broker statt am Edge halten; (4) einen Node zurückziehen und Reconnect prüfen; (5) Zertifikat, Policy und Logkonsistenz testen; (6) nicht autorisierten Origin/Region alarmieren; (7) Announcements und Credentials beim Abschluss entfernen.

**Erkennung:** BGP/RPKI/Historie, Provider-Tenant, Zertifikate und identisches Serviceverhalten identifizieren den Pool. **Capture-resilient OPSEC:** Ein Edge hält nur regionale Serviceidentität und keinen Operator- oder Flotten-Enrollment-Key. **Monitoring:** jede Region von autorisierten Monitoren prüfen, Route Origin und Konfigurationsdigest vergleichen und unerwarteten Origin als Incident behandeln.

## QUIC-Migration und Multipath-TCP-Kontinuität

**Mechanik:** QUIC Connection IDs können eine Client-Sitzung über NAT-Rebinding oder Adresswechsel hinweg erhalten; Multipath TCP kann einen zuverlässigen Bytestrom über mehrere Subflows übertragen. Beide verbessern Kontinuität bei WLAN-/Mobilfunkwechseln, legen dem gemeinsamen Peer jedoch alte und neue Pfade offen und können Cross-Path-Korrelation erleichtern.<sup>[[27]](#references)</sup>

**Vorteile:** schnellere Wiederherstellung bei Uplink-Wechseln; Anwendungssitzung muss nicht neu starten; MPTCP kann Resilienz und Durchsatz kombinieren; wertvoll für genehmigte Field Nodes.

**Nachteile:** keine Anonymität; Peer sieht Migration/Subflows; Connection IDs und paralleler Datenverkehr verbinden Pfade; Unterstützung durch Middleboxes/Carrier variiert; zusätzliche Providerdaten erhöhen die Exposition.

**Verfahren:** (1) unterstützten Transport nur zwischen eigenem Field Client und Rendezvous aktivieren; (2) Anwendung unabhängig von IP authentifizieren; (3) begrenzten Transfer über genehmigtes WLAN beginnen; (4) auf Organisationsmobilfunk wechseln; (5) Pfadvalidierung, Datenintegrität und fehlenden Klartext-/Direkt-Fallback bestätigen; (6) Idle Timeout und Rückkehr testen; (7) Brokerdaten jedes Pfadwechsels aufbewahren.

**Erkennung:** Peer beobachtet Adressmigration oder MPTCP-Subflows direkt; Access-Provider sehen ihren Anteil; Connection IDs, TLS-Identität und Timing verbinden beide. **Capture-resilient OPSEC:** nur gerätebezogenes Sitzungsmaterial speichern und wiederaufnehmbaren Zustand schnell ablaufen lassen. **Monitoring:** unmögliche Pfadwechsel, gleichzeitige nicht genehmigte Netze, Migrationsstürme und Resumption nach Quarantäne alarmieren.

## Verwalteter CI/CD- oder kurzlebiger Automation-Runner-Egress

**Mechanik:** Ein organisations-eigener Workflow führt auf einem Hosted Runner eine begrenzte Netzwerkprüfung aus. Das Ziel sieht eine Cloud-Runner-Adresse, während die Plattform Repository, Akteur, Workflow, Token, Logs und Billing zuordnet. Dies ist Remote Execution mit nachvollziehbarem Egress, keine Anonymität gegenüber dem Provider.<sup>[[28]](#references)</sup>

**Vorteile:** verfügbare saubere Umgebung; reproduzierbare Jobdefinition; keine eingehende Verbindung; nützlich für geografisch verteilte Verfügbarkeitsprüfungen; starkes Controller-Audit.

**Nachteile:** Plattform und Organisation identifizieren Initiator; breite Workflow-Tokens und nicht vertrauenswürdige Pull Requests sind gefährlich; gemeinsame IP-Reputation; Logs/Artefakte können Secrets oder Zieldaten speichern.

**Verfahren:** (1) privates Organisationsrepository und Assessment-Environment erstellen; (2) nur manuell genehmigte, feste harmlose Jobs gegen eigene Endpunkte erlauben; (3) minimale schreibgeschützte Workflow-Berechtigungen und keine Produktionssecrets verwenden; (4) Prüfung ausführen; (5) Workflow-, Provider- und Zielaufzeichnungen vergleichen; (6) Artefakte auf Credentials prüfen; (7) Environment-Token löschen und erforderliches Audit aufbewahren.

**Erkennung:** Provider-Audit und Workflow-Logs liefern direkte Zuordnung; Ziele identifizieren Runner-ASNs/-Bereiche und stabile Request-Grammatik. **Capture-resilient OPSEC:** niemals Secrets von Field Devices, Signing, Wallets oder Cloud-Administratoren in Runner-Variablen speichern. **Monitoring:** Branch-/Environment-Genehmigung verlangen und Workflowänderungen, Fork-Ausführung, Secret-Lesen und unerwartete Ziele alarmieren.

## Nicht-IP-basierter lokaler erster Hop zu einem eigenen Gateway

**Mechanik:** Bluetooth-Mesh, Wi-Fi Aware/Direct, Low-Power-Funk oder serielle/optische Verbindung übertragen begrenzte Nachrichten von einem nahen Sensor zu einem genehmigten Internet-Gateway. Das Field Device selbst hat keine Internetroute; das Gateway ist der einzige Egress. Reichweite und Protokollgrenzen machen dies zu Telemetrie/Store-and-Forward, nicht zu interaktivem anonymem Internet.

**Vorteile:** entfernt Internet-Stack und Credentials vom kleinsten Field Device; geringer Stromverbrauch; Gateway zentralisiert Policy; kann temporäre Funklöcher überbrücken.

**Nachteile:** RF-/physische Entdeckung, Pairing und Geräte-Identifier; geringe Bandbreite/Reichweite; Gateway verknüpft weiterhin alle Nachrichten; Frequenz- und Verschlüsselungsbeschränkungen variieren; Erfassung kann Warteschlangendaten offenlegen.

**Verfahren:** (1) Standort- und Frequenzgenehmigung einholen; (2) einen eigenen Sensor mit einem eigenen Gateway über eindeutige Schlüssel koppeln; (3) signierte Nachrichtenarten fester Größe, TTL und Rate definieren; (4) dem Sensor keine Standard-IP-Route geben; (5) Gateway nur an einen eigenen Collector weiterleiten lassen; (6) Replay, Reichweitenverlust und Gatewayausfall testen; (7) beide Geräte inventarisieren und zurückholen.

**Erkennung:** RF-Survey, Pairing-Datenbank, physische Inspektion sowie Gateway-Prozess-/Flow-Logs legen den Pfad offen. **Capture-resilient OPSEC:** Sensor hält nur seinen Pairwise-Key und eine begrenzte verschlüsselte Queue, niemals Operator-, WLAN-, Mobilfunk- oder Controller-Credentials. **Monitoring:** neue Peers, Sequenz-Rollback, Schlüsselfehler, ungewöhnliche RF-Rate und Nachrichten über nicht registrierte Gateways alarmieren.

## Exposure-Matrix für Erfassung/Kompromittierung

Diese Tabelle wendet auf jede oben genannte Familie eine Capture-Resilience-Prüfung an. „Minimieren“ bedeutet, Secrets und Blast Radius auf autorisierten Assets zu reduzieren; es bedeutet niemals, Beweise zu löschen oder sich einer Untersuchung zu entziehen.

| Technologiefamilie | Ein erfasster Endpunkt/ein Relay kann offenlegen | Minimale autorisierte Kontrolle |
|---|---|---|
| NAT/CGNAT, öffentliches WLAN, Travel Router | bekannte Netze, DHCP-/Portalhistorie, MACs, Tunnel-Peer | separates Organisationsgerät; private MAC, sofern unterstützt; keine persönlichen Konten; Controller-Inventar |
| VPN, VPS, HTTP/SOCKS/SSH, Multi-Hop | Provider/Hostnamen, Schlüssel, Routen, Logs und benachbarter Hop | eine Identität pro Engagement; kurze TTL; enge Routen; Broker-seitiger Widerruf; keine Master Keys |
| OHTTP/ODoH, MASQUE, Split-Provider-Relay | Relay-/Gateway-Konfiguration, Anwendungs-Identifier und gecachte Requests | Payload-Identifier minimieren; genehmigte Konfiguration pinnen; begrenzter Cache; strikter kein-direkter-Fallback |
| Tor, Bridge, Onion Service, I2P, Mixnet, GNUnet | installierte Software, Bridge-/Onion-Material, lokalen Zustand und Peer-Historie | Standardclient; separate Service-Schlüssel; verschlüsselter Minimalzustand; kompromittierte Serviceidentität rotieren |
| Remote Browser/VDI/Jump Host | Workspace-Token, Clipboard/Dateien und Remote-Tenant | phishing-resistentes MFA am Gateway; Transferkanäle deaktivieren; schnelle Sitzungswiderrufung |
| Mobilfunk, Satellit, privater APN | SIM/eSIM, IMEI/Terminalidentität, Provider und ungefähren Standort | Organisationsvertrag; keine persönliche Co-Location; enge APN-/Overlay-Policy; Provider-Sperr-Runbook |
| Residential-/kooperativer Proxy, ORB-Labor | Agentidentität, Controller/nächsten Hop, gecachten Datenverkehr | nur zugestimmte/eigene Nodes; signierter Agent; Credential pro Node; Teilnehmerzuordnung beim Controller |
| CDN/Fronting, Fast Flux, Serverless | Tenant/Origin/Konfiguration, API-Tokens, Deployment- und Billingreferenzen | dediziertes Projekt; Least-Privilege-Rolle; kurzlebiges Deployment-Token; Provider-Audit zentral aufbewahren |
| Dead Drop, Pull-Mailbox, Store-and-Forward | Objektnamen, Queue, gecachte Jobs/Ergebnisse und Übergabedaten | signierte begrenzte Jobs; TTL; verschlüsselter Cache; getrennte Producer-Identität; unveränderliche Server-Logs |
| Drop, Nearest Neighbor, Long-Range Bridge | Serial/RF/SSID/Peer, Geräteschlüssel, physische Platzierungsartefakte | schriftliche Platzierung; eindeutige Geräteidentität; kein Operatorschlüssel; Manipulations-/Zustandstelemetrie; widerrufen und zurückholen |
| TURN, Reverse Overlay, Dual-Uplink | Realm/Broker, Geräte-Credential, Peer/Route und Uplink-Profile | enger Outbound-only-Service; kurzlebiges Geräte-Credential; unabhängiger Operator-Login; Fail-closed-Pfade |
| IPv6 Temporary Addresses | Profile, Präfixhistorie und Endpunkt-/Anwendungszustand | nur als Anti-Tracking behandeln; Netzwerklogs bewahren; mit Endpunkt-Compartmentation kombinieren |
| Pluggable Transport/Refraction-Labor | Bridge-/Broker-/Decoy-Einstellungen, Tor-Zustand und Forschungsschlüssel | Standardclient oder isoliertes Labor; kein persönlicher Browserstatus; kein Production Signaling |
| IPFS/PIR/Fetcher | angeforderten CID/Query-Client, gecachten Inhalt, Gateway- oder Service-Token | verschlüsselter begrenzter Cache; nur öffentliche Parameter; kurzlebiges allowlistiertes Service-Token |
| Anycast/QUIC/MPTCP | Servicenodes, Connection IDs, wiederaufnehmbaren Zustand und bekannte Pfade | nur regionale Identität; kurze Resumption-Lebensdauer; zentrale Route-/Sitzungswiderrufung |
| Verwalteter CI/CD-Runner | Repository, Workflow, Provider-Token, Logs und Artefakte | Least-Privilege-Workflow; keine Produktions-/Field-/Wallet-Secrets; Environment-Genehmigung |
| Nicht-IP-lokaler Hop | Funkpeer, Pairwise-Key, Warteschlangennachrichten und Gatewayidentität | eindeutiger Pairwise-Key; festes Nachrichtenschema; keine WLAN-/Mobilfunk-/Operator-Credentials |

## Monitoring möglicher Entdeckung für jede Zugriffsfamilie

Kein clientseitiger Test beweist, dass ein Ermittler oder Verteidiger zusieht. Änderungen in Systemen überwachen, die dem Engagement gehören, mit Controller/Client abgleichen und statt Beobachter zu sondieren stoppen. Die folgenden Zeilen decken alle oben genannten Techniken ab; mit den [Alert-Zuständen und dem Response-Runbook für Field Nodes](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise) kombinieren.

| Abgedeckte Techniken | Sichere Signale auf Controllerseite | Quarantäne-/Stoppbedingung |
|---|---|---|
| NAT/CGNAT, öffentliches/Gäste-WLAN, Travel Router, Mobilfunk/eSIM, Satellit, privater APN | Lease/Portal/Carrier-Sitzung, öffentliches Tupel, BSSID-/Zell-/Pfadwechsel, Providerhinweis | nicht genehmigtes Netzwerk/SIM/Gerät, unerklärliche Verlagerung oder Provider-/SOC-Eskalation |
| VPN/VPS, HTTP/SOCKS/SSH, Multi-Hop, Residential-/kooperativer Proxy | Peer-Authentifizierung, Tunnelstatus, Routen-/DNS-Leaks, neues Admin-/API-Ereignis, Beschwerde | doppeltes/gestohlenes Credential, unbekannter Administrator, direkter Fallback oder Egress außerhalb des Umfangs |
| OHTTP/ODoH/ECH, MASQUE, Split-Provider-Relay, TURN | Relay-/Gateway-Allocation, Schlüssel-/Konfigurationsversion, nicht unterstützte Direktverbindung, Fehler-/Replay-Rate | Schlüsselabweichung, direkter Fallback, unbekannter Realm/Peer oder Provider-Abuse-Hinweis |
| Tor Browser, Bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, Onion Service | Bootstrap-Zustand, Circuit-Ausfall, Onion-Descriptor-/Servicezustand und eigene Canary-Seite | Übernahme persönlicher Konten, unerwartete Nicht-Tor-Verbindung oder kompromittierter Serviceschlüssel |
| I2P, Mixnet, GNUnet, Mesh/Store-and-Forward, Nicht-IP-lokaler Hop | Peer-Set, Queue-Alter/Sequenz, Gateway-Ankunft, Funkassoziation und Content-Hash | unbekannter Peer/Gateway, Sequenz-Rollback, nicht autorisierter Inhalt oder fehlender Übergabenachweis |
| Remote Browser/VDI/Jump Host, CI/CD-Runner, Serverless | IdP-Sitzung, Workflow-/Image-/Konfigurationsänderung, neues Token, Artefakt/Export und Cloud-Audit | unbekannter Login/Workflow-Edit, Secret-Lesen, unerwartetes Ziel oder Projektrolleneskalation |
| ORB-Labor, Fast Flux/DGA, CDN/Fronting, Dead Drop/Pull-Mailbox | eigene Node-Inventardaten, DNS-/Edge-/Objektzugriff, Controllergraph, Jobsignatur und TTL | unbekannter Node/Origin/Objekt-Writer, unsignierter/wiederholter Job, Topologieausbruch aus dem Labor |
| Drop/Nearest Neighbor/Long-Range Bridge/Outbound Overlay/Dual Uplink | signierter Heartbeat, Boot-/Konfigurationshash, Gehäusezustand, AP-/Switchkontext, doppelte Identität | verschobener/geöffneter Node, unerwarteter Boot/Hash/Pfad, Sentinel-Nutzung oder Standortmeldung |
| IPv6 Temporary Addresses, QUIC Migration, MPTCP | delegiertes Präfix, Connection ID/Subflows, Pfadvalidierung und Broker-Sitzung | unmögliche Migration, gleichzeitige nicht genehmigte Pfade oder Sitzungsfortsetzung nach Widerruf |
| IPFS/Cache, PIR, begrenzter Fetcher | CID-/Query-Form, Root-Version, Peer-/Gatewaywechsel, Redirect-/Allowlist-Ablehnung | unerwartetes Pinning/Query/Ziel, unsignierte Dataset-Root oder Provider-Abuse-Hinweis |
| Refraction-/Decoy-Routing-Labor, Anycast-Rendezvous | eigene Umleitungsentscheidung, Proxy-Ankunft, BGP/RPKI-Origin, regionaler Konfigurationsdigest | Signal im Produktionspfad, unbekannter Route Origin, Regions-/Konfigurationsabweichung |

## Auswahl und Test eines Pfads

1. Den zu entfernenden Beobachter und die zu verbergenden Daten benennen.
2. Die am wenigsten komplexe Familie auswählen, die ihn entfernt.
3. Beobachter für Quelle, Einstieg, Traversal, Exit, DNS, Konto und Zahlung einzeichnen.
4. Eine separate Endpunkt-/Anwendungsidentität verwenden.
5. IPv4, IPv6, DNS, WebRTC-/Anwendungs-Bypass und Zielansicht prüfen.
6. Jeden Hop unterbrechen und bestätigen, dass der Ausfall geschlossen ist.
7. Logs jeder kontrollierten Komponente vergleichen.
8. Verbleibende Timing-, Provider-, Endpunkt- und physische Verknüpfungen dokumentieren.

## References

- [1] [EFF — Das richtige VPN für Sie auswählen](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor entsperren](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Tor Browser mit einem VPN verwenden](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Überblick über Onion Services](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous File Sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Obligatorische SIM-Registrierung](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
