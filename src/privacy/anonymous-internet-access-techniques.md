# Katalog für anonyme Internetzugriffstechniken

{{#include ../banners/hacktricks-training.md}}

Dies ist das kanonische Inventar der Zugriffspfade. Es behandelt protokollbezogene und operative **Familien**, nicht jeden Anbieternamen. Kein Internetpfad garantiert Anonymität: Konto-, Browser-, Endpunkt-, Zeit-, Zahlungs-, Cloud-Control-Plane- und physische Beweise können selbst eine perfekt wirkende Route entkräften.

Jeder Eintrag verwendet dieselben Felder. „Verfahren“ bedeutet eine rechtmäßige Bereitstellung oder eine Emulation in einem eigenen Labor. Wenn die echte Technik die Kompromittierung eines Routers, den Diebstahl eines Zugangs oder den Missbrauch eines unwilligen Vermittlers erfordert, ersetzt die Reproduktion diese Systeme durch Systeme, die dem Übungsteilnehmer gehören.

## Abdeckungsmatrix

| Familie | Ziel sieht | Stärkste Eigenschaft | Geschwindigkeit | Behandlung |
|---|---|---|---|---|
| Shared NAT/CGNAT | gemeinsame öffentliche Adresse | Mehrdeutigkeit unter Teilnehmern | hoch | bereitstellbar |
| VPN, VPS, SOCKS/HTTP/SSH proxy | Relay-Adresse | schnelle Trennung der Quelladresse | hoch | bereitstellbar |
| Multi-Hop/Split-Relay, MASQUE | finalen Proxy | Wissensaufteilung oder vollständiger IP-Tunnel | hoch/mittel | mit vertrauenswürdigen Relays bereitstellbar |
| Tor, Bridge, onion service | Exit oder Onion-Identität | Mehrparteienpfad und einheitlicher Browser | mittel | bereitstellbar |
| I2P, GNUnet, mixnet | Overlay-Peer/Gateway | Overlay- oder Timing-Resistenz | niedrig/variabel | anwendungsspezifisch |
| OHTTP/ODoH, Private Relay | Gateway/Egress | Aufteilung von Quelle und Anfrage | hoch | nur unterstützte Anwendungen |
| Öffentliches Wi-Fi, travel router | Venue-/Tunnel-Adresse | Änderung von Standort/Zugriffspfad | hoch | Genehmigung erforderlich |
| Mobilfunk/eSIM, Satellit | Carrier-/Provider-Adresse | unabhängiger physischer Uplink | hoch/variabel | Subscription-/Provider-Beobachtung |
| Remote-Browser/jump host | Remote-Workspace | Trennung von Endpunkt und Egress | hoch | bereitstellbar |
| Residential-/Mobile-Proxy | Consumer-/Carrier-Adresse | Erscheinungsbild eines Consumer-Netzes | hoch | Einwilligung/Herkunft entscheidend |
| ORB/kompromittiertes Relay | Adresse eines anderen Opfers | Verbergen des Ursprungs und geliehene Reputation | hoch | nur eigene Laborreproduktion |
| CDN/fronting/redirector | CDN-/Front-Adresse | Schutz der Back-End-Infrastruktur | hoch | Genehmigung von Provider/Eigentümer erforderlich |
| Fast Flux/DGA/dead drop | rotierender Knoten/Dienst | Resistenz gegen Infrastrukturaufklärung | variabel | nur eigene Laborreproduktion |
| Drop/Nearest Neighbor | lokale, zielnahe Adresse | Überquerung geografischer/Netzwerkgrenzen | hoch | nur Labor am eigenen Standort |
| Store-and-forward/offline | Gateway oder physischer Empfänger | geringere interaktive Timing-Verknüpfung | niedrig | anwendungsspezifisch |
| Pluggable/Refraction Transport | Tor-Einstieg oder kooperierender Diversionsproxy | zensurresistente Erreichbarkeit | variabel | unterstützter Client oder Forschungslabor |
| IPFS gateway/PIR/remote fetcher | Gateway oder Anwendungsdienst | Trennung von Publisher, Query und Request | variabel | nur begrenzte Anwendung |
| Anycast/QUIC/MPTCP | stabiler Broker oder mehrere Subflows | Rendezvous und Sessionkontinuität | hoch | Verfügbarkeit, keine Anonymität |
| CI/CD-Automation-Runner | Adresse des gehosteten Runners | verworfener, nachvollziehbarer Egress | hoch | nur eigener Workflow |
| Nicht-IP-lokaler erster Hop | Organisations-Gateway | entfernt den Internet-Stack vom Sensor | niedrig | vom Eigentümer genehmigte Bereitstellung |

## Direktes Shared NAT und Carrier-Grade NAT

**Mechanik:** Mehrere Nutzer teilen eine öffentliche Adresse; der Access-Provider ordnet Teilnehmeradressen und Ports dem öffentlichen Tupel zu.

**Vorteile:** schnell; kein spezieller Client; die IP am Ziel kann möglicherweise nur einen Haushalt, ein Venue oder einen Carrier-Pool identifizieren.

**Nachteile:** Der Provider kann Teilnehmer-/Port-/Zeit-Zuordnungen speichern; Konten und Fingerprints bleiben bestehen; andere Nutzer können die Reputation der Adresse schädigen.

**Verfahren:** (1) Bestätigen, ob der autorisierte Zugang NAT/CGNAT verwendet; (2) die exakte öffentliche IP und den Quellport an einem eigenen Endpunkt erfassen; (3) Anwendungsidentitäten trennen; (4) Shared Addressing nicht als Datenschutzkontrolle behandeln; (5) einen stärkeren Pfad verwenden, wenn der ISP Ziele nicht erfahren darf.

**Erkennung:** Ziele sollten Quellport und präzise Zeit, nicht nur die IP speichern. Provider korrelieren NAT-Zuweisungslogs; Ermittler verknüpfen Konto-, Geräte- und Browserbeweise.

## Kommerzielles VPN

**Mechanik:** Eine verschlüsselte Full-Tunnel-Verbindung endet beim VPN; Ziele sehen dessen Egress. Das VPN kann Quelle, Timing und Ziele normalerweise miteinander verknüpfen.

**Vorteile:** schnell; einfach; schützt vor lokaler passiver Beobachtung; stabile oder geteilte Exits; gut für kontrollierten Red-Team-Egress.

**Nachteile:** konzentriertes Vertrauen; Billing-/Login-Telemetrie; Kill-Switch-/DNS-/IPv6-Fehler; Shared Exits werden häufig wegen ihrer Reputation blockiert.

**Verfahren:** (1) Provider, Eigentümer, Rechtsraum, Aufbewahrung und Assessment-Richtlinie bestimmen; (2) den signierten offiziellen Client installieren; (3) Full Tunnel, Always-on und Fail-closed aktivieren; (4) DNS und IPv6 bewusst routen; (5) beobachtete IPv4/IPv6/DNS-Werte an einem eigenen Endpunkt prüfen; (6) Tunnel stoppen/neu verbinden und bestätigen, dass kein Klartext-Fallback besteht.<sup>[[1]](#references)</sup>

**Erkennung:** Lokale Netzwerke sehen einen langen verschlüsselten Flow zur VPN-Infrastruktur; Provider besitzen Authentifizierungs-/Verbindungsdaten; Ziele verwenden ASN-/Reputation-Daten sowie Konto-, TLS-/Browser- und Verhaltenskorrelation.

## Selbst gehosteter VPN- oder gemieteter VPS-Egress

**Mechanik:** Der Betreiber kontrolliert ein WireGuard/OpenVPN-Gateway oder leitet Daten über einen gemieteten Server weiter.

**Vorteile:** vorhersehbare hohe Geschwindigkeit; feste, allowlistbare Adresse; individuelle Logs/Firewall; gute Incident-Kontrolle.

**Nachteile:** kleine Anonymitätsmenge; Cloud-Tenant, Zahlung, Source-Login, API und Image-Historie verknüpfen den Betreiber; ein unverwechselbarer neuer Server lässt sich leicht clustern.

**Verfahren:** (1) ein engagement-spezifisches Organisationsprojekt erstellen; (2) ein unterstütztes Image und eine feste Adresse bereitstellen; (3) Management auf MFA-/schlüsselbasierte Administration beschränken; (4) Full-Tunnel-Egress und DNS konfigurieren; (5) Ziele, soweit praktikabel, auf den Scope beschränken; (6) Leak-/Fehlerverhalten testen; (7) Controller-Audit-Logs aufbewahren; (8) Credentials und Ressourcen beim Abbau zerstören.

**Erkennung:** Hosting-ASN, erstmals beobachtete Adresse, Zertifikats-/Service-Fingerprint und Scanverhalten korrelieren; Cloud-Eigentümer verwenden Control-Plane-, Console-, Billing- und Flow-Logs.

## HTTP CONNECT, SOCKS und SSH-Forwarding

**Mechanik:** Eine Anwendung bittet einen Proxy, einen TCP-Stream zu öffnen; SOCKS kann je nach Version auch Namensauflösung und UDP übertragen; SSH leitet Streams innerhalb einer verschlüsselten Session weiter.

**Vorteile:** leichtgewichtig; pro Anwendung; schnell; nützlich für Verkettungen und segmentierte Netzwerke.

**Nachteile:** Anwendungen können den Proxy umgehen; DNS kann leaken; der Proxy sieht benachbarte Endpunkte; Browserstatus bleibt bestehen; offene Proxies können Fallen oder kompromittierte Systeme sein.

**Verfahren:** (1) Proxy auf einem eigenen Host bereitstellen; (2) Authentifizierung verlangen und Quelle/Ziel beschränken; (3) ein einzelnes verworfenes Anwendungsprofil konfigurieren; (4) bei Bedarf entfernte DNS-Auflösung sicherstellen; (5) mit einem eigenen DNS-/HTTP-Endpunkt prüfen; (6) direkten Egress für die Workload blockieren; (7) Proxy-Credentials prüfen und rotieren.

**Erkennung:** tunnel-fähige Prozesse, CONNECT-/SOCKS-Verhandlung, lange SSH-Sessions und anwendungsinkonsistente Ziele identifizieren; Proxy-Logs rekonstruieren die Streams.

## URL-rewriting-Webproxy und Browser-Proxy-Extension

**Mechanik:** Eine Website ruft ein Ziel ab und schreibt Links/Formulare über ihren eigenen Origin um, oder eine Extension leitet Browseranfragen an einen Proxy. Das Ziel sieht den Dienst; der Dienst kann nach TLS-Terminierung Klartext lesen sowie Inhalte einschleusen oder speichern.

**Vorteile:** kein systemweiter Client; schnell für einfaches Browsing; funktioniert, wenn eine VPN-Installation unmöglich ist.

**Nachteile:** Der Proxy kann Credentials/Inhalte lesen, Downloads umschreiben und Nutzer fingerprinten; Scripts/WebSockets/Downloads können ihn umgehen; eine Browser-Extension besitzt weitreichende Rechte; kleine Anonymitätsmenge und häufige Blockierung.

**Verfahren:** (1) nur einen organisationsbetriebenen Proxy für autorisierte Tests verwenden; (2) ihn in einem verworfenen Browser ohne persönliche Konten isolieren; (3) Passworteingabe und sensible Downloads verbieten; (4) auf einer eigenen Seite prüfen, dass jedes Subresource über den Proxy aufgelöst wird; (5) WebSocket-, Download- und Formularverhalten testen; (6) Extension/Profil nach der Nutzung entfernen.

**Erkennung:** Das Ziel protokolliert den Proxy; Enterprise-Proxy/DNS und Extension-Inventar identifizieren den Dienst; Content-Security-/Reporting- oder eigene Canary-Subresources zeigen direkte Umgehungen; Proxy-Logs ordnen Benutzersessions den Zielen zu.

## Multi-Hop-Proxy oder Multi-Hop-VPN eines Providers

**Mechanik:** Ein Entry sieht die Quelle, während ein oder mehrere Traversal-Relays sie von einem Exit trennen, der das Ziel sieht.

**Vorteile:** Kein gewöhnliches Relay benötigt beide Enden; Ausfall/Beschlagnahmung eines Knotens enthüllt weniger; flexible Geografie.

**Nachteile:** Gemeinsame Administration/Logs zerstören die Trennung; Latenz; Timing-Korrelation; mehr Ausfälle und DNS-Routen; dasselbe Konto/dieselbe Zahlung kann alle Hops verbinden.

**Verfahren:** (1) festlegen, welchen Beobachter jeder Hop entfernt; (2) bei notwendiger Trennung unabhängig verwaltete eigene/genehmigte Relays verwenden; (3) nur Entry-Zugriff von der Workload erzwingen; (4) jeden Relay auf den jeweils nächsten Hop beschränken; (5) Logs auf jeder Ebene prüfen; (6) jeden Hop stoppen und Fail-closed-Verhalten bestätigen. Mit [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) reproduzieren.

**Erkennung:** Benachbarte NetFlow-Zeit/Volumen, wiederholte Proxy-Handshakes und gemeinsame Controller-Infrastruktur korrelieren; aus dem Exit keine Geografie des Betreibers ableiten.

## Split-Knowledge-Application-Relay und OHTTP

**Mechanik:** Der Client verschlüsselt eine zustandslose HTTP-Nachricht für ein Gateway und sendet sie über ein Relay. Das Relay sieht die Client-IP, aber nicht die Anfrage; das Gateway sieht die Anfrage, normalerweise jedoch nur die Relay-IP.

**Vorteile:** starke, auditierbare Datenschutztrennung für unterstützte Requests; geringerer Overhead als allgemeine Anonymitätsnetzwerke.

**Nachteile:** kein beliebiges Browsing; Cookies/Authentifizierung können erneut verknüpfen; Kollusion und Traffic-Analyse zwischen Relay/Gateway bleiben möglich; die Anwendung muss dies implementieren.

**Verfahren:** (1) eine Anwendung auswählen, die RFC 9458 ausdrücklich unterstützt; (2) Gateway-Schlüssel über den offiziellen Konfigurationsweg prüfen; (3) stabile benutzerspezifische Felder vermeiden; (4) nur den unterstützten zustandslosen Request senden; (5) Relay-, Gateway- und Ziel-Logs vergleichen; (6) Schlüsselrotation/-ausfall ohne direkten Fallback testen.<sup>[[2]](#references)</sup>

**Erkennung:** Enterprise-Endpunkte zeigen den auslösenden Prozess und das OHTTP-Relay; Gateways erkennen fehlerhafte/wiederholte Daten; Timing sowie stabile Payload-/Kontofelder können Requests korrelieren.

## MASQUE CONNECT-UDP/CONNECT-IP und HTTP-Datenschutz-Proxies

**Mechanik:** HTTP Extended CONNECT über TLS/QUIC transportiert UDP- oder IP-Pakete durch einen Proxy. Dies kann einen modernen VPN-ähnlichen Tunnel implementieren und den Transport mit HTTP/3 vermischen; der Proxy bleibt jedoch Beobachter.<sup>[[3]](#references)</sup>

**Vorteile:** effizientes Multiplexing/Roaming; unterstützt UDP oder vollständiges IP; Bereitstellung über moderne HTTP-Infrastruktur.

**Nachteile:** kein Anonymitätsnetzwerk; Proxy/Konto sieht Quelle und Ziele; QUIC-/HTTP-Fingerprints und bekannte Pfade sind für Endpunkte/Provider sichtbar.

**Verfahren:** (1) Client/Dienst mit dokumentierter RFC-9298/9484-Unterstützung verwenden; (2) Proxy-Zertifikat/-Konfiguration authentifizieren; (3) erlaubte Zielrouten definieren; (4) verschlüsseltes DNS innerhalb des Pfades aktivieren; (5) UDP, TCP, IPv6 und Failover an eigenen Endpunkten prüfen; (6) Proxy-Request- und Flow-Logs untersuchen.

**Erkennung:** Endpunkte sehen Clientprozess und virtuelles Interface; Netzwerke können anhaltendes QUIC/TLS zu einem Proxy klassifizieren; Proxy-Logs zeigen CONNECT-Ziel/Pfad und zugewiesene Routen.

## Tor Browser

**Mechanik:** Tor wählt Guard-, Middle- und Exit-Relays; mehrschichtige Verschlüsselung begrenzt die Sicht jedes Relays. Tor Browser ergänzt einen standardisierten Browser, der Fingerprinting widerstehen soll.

**Vorteile:** große öffentliche Anonymitätsmenge; kein gewöhnliches Relay kennt beide Enden; Ziel-Unlinkability ohne eigene Server.

**Nachteile:** langsamer; TCP-orientiert; Exit-Reputation/-Blockaden; Logins und Preisgaben identifizieren den Nutzer; Korrelation durch Low-Latency-Timing bleibt möglich.

**Verfahren:** (1) Tor Browser aus dem Projekt herunterladen und verifizieren; (2) Standardeinstellungen beibehalten und Extensions vermeiden; (3) angemessenes Sicherheitsniveau wählen; (4) separate Identität/Session erstellen; (5) identifizierende Konten und externe aktive Dokumente vermeiden; (6) HTTPS oder authentifizierte Onion-Services verwenden; (7) Exit nur an einem eigenen Endpunkt prüfen.<sup>[[4]](#references)</sup>

**Erkennung:** Lokale Netzwerke können bekannten Guard-Traffic erkennen, sofern keine Bridge/kein Transport verwendet wird; Ziele sehen Exits und das Verhalten von Tor Browser; Ende-zu-Ende-Beobachter korrelieren Timing/Volumen.

## Tor Bridges und Pluggable Transports

**Mechanik:** Eine nicht öffentliche Bridge ersetzt den öffentlichen Guard; obfs4, Snowflake oder WebTunnel verändern den First-Hop-Transport, um einfache Blockierung/Probing zu erschweren.

**Vorteile:** umgeht Zensur und verbirgt offensichtliche Ziele öffentlicher Relays; behält den Tor-Circuit nach dem Einstieg bei.

**Nachteile:** Transportmuster/Bridge-Erkennung bleiben möglich; variable Performance; kein zusätzlicher Schutz vor Konten oder globalem Timing.

**Verfahren:** (1) zuerst direktes Tor versuchen; (2) in den Verbindungseinstellungen von Tor Browser einen integrierten unterstützten Transport auswählen oder eine offizielle Bridge anfordern; (3) keine zufälligen Binärdateien/Listen verwenden; (4) verbinden und einen harmlosen Test ausführen; (5) Reconnect und Uhr prüfen; (6) alle übrigen Browsereinstellungen standardmäßig belassen.<sup>[[5]](#references)</sup>

**Erkennung:** Zensoren verwenden Zielerkennung, Protokoll-/Flow-Klassifizierung und aktives Probing; Verteidiger sollten Umgehungsnutzung von Kompromittierung unterscheiden und sich auf Endpunktprozess/-kontext stützen.

## VPN vor Tor und Tor vor VPN

**Mechanik:** VPN-vor-Tor verbirgt direkte Tor-Nutzung vor dem Access-ISP, enthüllt die Quelle jedoch gegenüber dem VPN. Tor-vor-VPN gibt dem VPN Tor-Nachverkehr und häufig eine stabile Kunden-/Tunnelidentität.

**Vorteile:** entfernt bei korrekter Planung einen bestimmten Beobachter; kann Netze erreichen, die eine Ebene blockieren.

**Nachteile:** Komplexität, ungewöhnlicher Fingerprint, Leaks, kleinere Anonymitätsmenge und falsches Vertrauen; Tor Project behandelt Kombinationen als fortgeschritten.<sup>[[6]](#references)</sup>

**Verfahren:** (1) den entfernten und den neu eingeführten Beobachter notieren; (2) verworfene Umgebung verwenden; (3) nur den beabsichtigten äußeren Pfad herstellen; (4) Firewall-Routen erzwingen; (5) DNS/IPv4/IPv6 und jede Fehlerreihenfolge prüfen; (6) Sichtbarkeit beider Provider vergleichen; (7) Stack verwerfen, wenn kein messbarer Vorteil besteht.

**Erkennung:** Lokale/VPN-/Tor-Beobachter sehen unterschiedliche benachbarte Ebenen; Timing bleibt Ende-zu-Ende; ungewöhnliche verschachtelte Tunnel-Fingerprints und Providerkonten können Sessions verbinden.

## Onion Service

**Mechanik:** Client und Service erstellen Tor-Circuits zu einem Rendezvous, verbergen die Service-IP und vermeiden einen Exit.

**Vorteile:** Schutz von Quelle und Service-Standort; Ende-zu-Ende-Onion-Authentifizierung; kein öffentlicher Inbound-Port; optionale Client-Autorisierung.

**Nachteile:** Origin-Leaks durch Updates/Analytics/Fehler; Onion-Schlüssel ist kritisch; Anwendungsidentität, Timing und Host-Kompromittierung bleiben bestehen.

**Verfahren:** (1) Anwendung isolieren und nur an Loopback/Socket binden; (2) unterstütztes Tor installieren; (3) v3-Onion-Service nach offiziellen Anweisungen konfigurieren; (4) Schlüssel nur sichern/backupen, wenn eine stabile Identität benötigt wird; (5) Client-Autorisierung für geschlossene Nutzung hinzufügen; (6) Third-Party-Fetches entfernen; (7) extern prüfen, dass der Origin nicht erreichbar ist.<sup>[[7]](#references)</sup>

**Erkennung:** Host-/Netzwerkverteidiger finden Tor-Prozess/Konfiguration und ausgehende Circuits; Anwendungsfehler, DNS, Zertifikate oder Third-Party-Ressourcen können den Origin offenlegen.

## I2P-interne Services

**Mechanik:** I2P verwendet getrennte unidirektionale Inbound-/Outbound-Tunnel für Ziele innerhalb des Overlays; Outproxies zum öffentlichen Internet bilden einen Vertrauenspunkt.

**Vorteile:** dezentrale interne Veröffentlichung; keine Abhängigkeit von einem offiziellen Exit; getrennte Inbound-/Outbound-Pfade.

**Nachteile:** kein allgemeiner Webersatz; kleineres Ökosystem; langfristiges Peer-Verhalten; Outproxy kann öffentliches Browsing beobachten.

**Verfahren:** (1) aus offizieller Quelle installieren; (2) dedizierten Kontext verwenden; (3) Integration/Bandbreitenstabilisierung zulassen; (4) eigenen I2P-Service aufrufen; (5) Outproxies vermeiden, sofern nicht ausdrücklich erforderlich; (6) prüfen, dass das Herunterfahren keinen direkten Fallback ermöglicht; (7) lokale Peer- und Service-Logs untersuchen.<sup>[[8]](#references)</sup>

**Erkennung:** Lokale Netzwerke sehen langlebigen Peer-Traffic und Bootstrap-Verhalten; Endpunkte legen Router-/Anwendungsprozesse offen; Outproxies protokollieren Exits.

## Mixnets

**Mechanik:** Pakete fester Größe, Batching, Verzögerung, Umordnung und Cover Traffic reduzieren Timing-Korrelation; Gateways verbinden Anwendungen.

**Vorteile:** höhere Resistenz gegen Timing-Analyse als Low-Latency-Proxies; nützlich für asynchrone Nachrichten/Transaktionen.

**Nachteile:** Latenz, Bandbreiten-Overhead, kleinere Bereitstellung und Anwendungsgrenzen; Gateway-/Kontometadaten können bestehen bleiben.

**Verfahren:** (1) gepflegten Client und unterstützte Anwendung auswählen; (2) tatsächliches Threat Model lesen; (3) in separater Umgebung installieren; (4) harmlose Daten an eigenen Endpunkt senden; (5) Latenz/Zuverlässigkeit und Antwortpfad messen; (6) Gateway-Ausfall testen; (7) Verzögerungen/Cover Traffic niemals nur aus Geschwindigkeitsgründen deaktivieren.<sup>[[9]](#references)</sup>

**Erkennung:** Endpunkte identifizieren den Client; Access-Netzwerke können Gateways/Paketkadenz klassifizieren; Gateways und Exits sehen benachbarte Rollen, während umfassendere Korrelation längere statistische Zeitfenster erfordert.

## GNUnet Anonymous File Sharing

**Mechanik:** GNUnet kann Publish-/Search-/Download-Anfragen über Peers routen und entsprechend einem Anonymitätslevel Cover Traffic hinzufügen. Die eigene Dokumentation warnt, dass Level 1 standardmäßig keinen Cover Traffic verlangt und leistungsfähige Traffic-Analyse den Ursprung identifizieren kann.<sup>[[10]](#references)</sup>

**Vorteile:** dezentrales, anwendungsnahes anonymes Sharing; einstellbare Cover-Traffic-Anforderung.

**Nachteile:** kein gewöhnlicher anonymer Webzugang; Performance-/Speicherkosten; Peer- und Traffic-Analyse-Grenzen; GNUnet-VPN-Dokumentation zufolge bietet sein IP-Overlay keine gute Anonymität.

**Verfahren:** (1) gepflegten offiziellen Build installieren; (2) Test-Peer isolieren; (3) Bandbreite/Speicher begrenzen; (4) harmlose eindeutige Testdatei mit gewähltem Anonymitätslevel veröffentlichen; (5) von einem anderen eigenen Peer abrufen; (6) Cover Traffic und Latenz erfassen; (7) nicht behaupten, dass die IP-VPN-Komponente gleichwertige Anonymität bietet.

**Erkennung:** Peer-Bootstrap, Overlay-Traffic, lokaler Datastore/Prozess und Dateikennungen; ein umfassender Beobachter kann Traffic-Volumen gegen Cover Traffic analysieren.

## Verschlüsseltes DNS, ODoH und ECH

**Mechanik:** DoH/DoT/DoQ verschlüsseln zum Resolver; ODoH teilt Clientadresse und Query zwischen Proxy und Resolver; ECH verschlüsselt den inneren TLS ClientHello/Servernamen.

**Vorteile:** entfernt für manche lokalen Beobachter Klartext-DNS/SNI; ODoH teilt die Kenntnis von Quelle und Query.

**Nachteile:** kein IP-Anonymitätspfad; Resolver/Proxy/Server behalten ihre Rollen; Ziel-IP, Timing, Volumen und Endpunkt bleiben sichtbar; Fallback kann leaken.

**Verfahren:** (1) bestimmen, ob OS, Anwendung oder Tunnel DNS kontrolliert; (2) Strict Encrypted Mode oder unterstütztes ODoH aktivieren; (3) eigene eindeutige Domain testen; (4) lokal mitschneiden und fehlenden Klartext-Query bestätigen; (5) Resolver ausfallen lassen und erwartetes Verhalten prüfen; (6) bei ECH bestätigen, dass Serverdiagnosen die Annahme des inneren ClientHello zeigen.<sup>[[11]](#references)</sup>

**Erkennung:** Endpunkt-/Resolver-Logs zeigen Queries; Netzwerke erkennen verschlüsselte Resolver-Endpunkte und Zielflows; ECH-Zustand ist an Endpunkten/CDN sichtbar, auch wenn er auf dem Pfad verborgen ist.

## Split-Provider-Privacy-Relay

**Mechanik:** Produkte wie iCloud Private Relay verwenden einen Ingress, der den Client kennt, und einen unabhängig betriebenen Egress, der das Ziel kennt, mit grober Regionsbehandlung.

**Vorteile:** reibungsarme Wissensaufteilung; schnell; integrierter DNS-/Webschutz für unterstützten Traffic.

**Nachteile:** begrenzter Produkt-/Anwendungsumfang; Konto-/Plattformprovider identifiziert den Kunden weiterhin; keine beliebige Systemanonymität; Kollusions-, Rechts- und Timingrisiken.

**Verfahren:** (1) exakt unterstützte Anwendungen und Traffic-Typen bestätigen; (2) Funktion gegebenenfalls unter dediziertem Plattformkontext aktivieren; (3) Regionsverhalten wählen; (4) Safari/DNS und nicht unterstützte Anwendungen getrennt testen; (5) Zieladresse untersuchen; (6) Netzwerkwechsel/-ausfall testen.<sup>[[12]](#references)</sup>

**Erkennung:** Access sieht den Ingress; Ziel sieht den Egress; Plattform-/Relay-Logs und Kontodaten decken jeweils ihre Ebene ab; nicht unterstützte Anwendungen legen normale Pfade offen.

## Remote-Browser, VDI, RDP oder Organisations-Jump-Host

**Mechanik:** Browsing/Toolausführung erfolgt auf einem Remote-System; das Ziel sieht dessen Egress, während der Workspace-Provider die Operatorverbindung und Control Plane sieht.

**Vorteile:** schnell; isoliert riskante Inhalte; stabiler kontrollierter Egress; verworfener Zustand und starke Organisationsprüfung.

**Nachteile:** Provider/Admin kann Session/Konto beobachten; Bildschirm-/Clipboard-/Dateikanäle leaken; Remote-Browser-Fingerprint kann einzigartig sein; keine Anonymität gegenüber dem Workspace-Eigentümer.

**Verfahren:** (1) pro Engagement einen organisations-eigenen Workspace erstellen; (2) MFA verlangen und Administration beschränken; (3) Clipboard/Upload/Download deaktivieren oder begrenzen; (4) über genehmigten festen Egress routen; (5) keine persönliche IdP-/Sync-Nutzung; (6) nur geprüfte Beweise exportieren; (7) Workspace und Credentials planmäßig zerstören.

**Erkennung:** Provider- und IdP-Logs ordnen Nutzer Sessions zu; Ziele clustern Workspace-Egress/Browser; Enterprise-Verteidiger erkennen Remote-Control-Protokolle und anomale Cloud-Sessions.

## Öffentliches oder Gast-Wi-Fi

**Mechanik:** Traffic verlässt das Netzwerk über Venue-NAT oder einen dort gestarteten Tunnel.

**Vorteile:** hohe Geschwindigkeit und gemeinsame Nicht-Heimadresse; keine dedizierte Infrastruktur.

**Nachteile:** Venue-Zuordnung/DHCP/Portal, Kamera-, Kauf- und Standortbeweise; feindliche Peers/APs; Nutzungsbedingungen; physisches Risiko.

**Verfahren:** (1) Gästen angebotenen Zugang verwenden und SSID mit Personal bestätigen; (2) gepatchtes Gerät mit geringem Vertrauen einsetzen; (3) Sharing/Auto-Join deaktivieren und private MAC aktivieren; (4) Portal ohne wiederverwendete Identität abschließen; (5) Fail-closed-VPN/Tor starten; (6) getetherte Verbindungen prüfen; (7) Netzwerk vergessen.

**Erkennung:** Venue korreliert AP, MAC, DHCP, Portal und Zeit; Ziel sieht Venue/Tunnel; Ermittler verbinden physische und Gerätebeweise. Zugriffskontrollen niemals umgehen.

## Travel Router

**Mechanik:** Ein eigener Router verbindet sich mit Venue-Wi-Fi/Ethernet und stellt ein isoliertes internes Netz mit erzwungener Tunnelrichtlinie bereit.

**Vorteile:** isoliert Workstations; zentraler Kill Switch/DNS; konsistentes Client-Netz; schützt privilegierte Endpunkte vor lokalen Broadcasts.

**Nachteile:** Router wird zu einem stabilen Radio-/DHCP-Fingerprint; zusätzliche Angriffsfläche; Captive Portals und Tethering können den Tunnel umgehen.

**Verfahren:** (1) unterstützte Firmware aktualisieren; (2) eindeutige Management-Credentials setzen und WAN-Admin/WPS/UPnP deaktivieren; (3) privaten Upstream-MAC verwenden, sofern zulässig; (4) separate interne SSID erstellen; (5) Full-Tunnel-DNS-/IPv6-Firewallrichtlinie erzwingen; (6) Portal, Reconnect und Tunnelausfall testen.

**Erkennung:** Venue sieht Routerassoziation und Traffic-Form; lokale RF-/DHCP-Fingerprinting identifiziert ihn; VPN-Provider sieht die Venue-Quelle.

## Mobilfunk, Prepaid-SIM und eSIM

**Mechanik:** Ein Modem verwendet Carrier-Funkzugang und normalerweise Carrier-NAT; eine VPN-/Tor-Schicht kann den am Ziel sichtbaren Exit ändern.

**Vorteile:** unabhängig vom lokalen kabelgebundenen/Wi-Fi-Netz; mobil; hohe Geschwindigkeit; nützlich als Backhaul für autorisierte Drops.

**Nachteile:** Carrier kennt Teilnehmer/eSIM, IMSI, IMEI, Zellen, Zeit und zugewiesene Ports; Registrierungsgesetze variieren; gemeinsame Nutzung mit einem persönlichen Telefon verbindet Geräte.

**Verfahren:** (1) Dienst rechtmäßig und mit erforderlichen korrekten Angaben beziehen; (2) separates organisations-eigenes Modem/Gerät verwenden; (3) beim Übungscontroller registrieren; (4) nicht relevante Funkgeräte/Konten deaktivieren; (5) genehmigten Tunnel herstellen; (6) prüfen, ob getetherte Clients tatsächlich darüber laufen; (7) Provider- und Aufbewahrungsannahmen vor Reisen prüfen.<sup>[[13]](#references)</sup>

**Erkennung:** Carrierdaten und RF-Standort; Enterprise-USB-/PCI-/MDM-Inventar und Rogue-Hotspot-Suchen; Ziel-/Tunnel-Timing.

## Satelliteninternet und Missbrauch von Satellite Downlinks

**Mechanik:** Normaler Dienst verwendet registriertes Terminal/Provider. Älterer einseitiger DVB-S-Missbrauch erlaubte einem Empfänger innerhalb eines Beams, unverschlüsselten Downlink-Traffic für einen legitimen Teilnehmer zu beobachten, während ein anderer Pfad für ausgehende Anfragen verwendet wurde.

**Vorteile:** große Reichweite; unabhängige letzte Meile; historischer einseitiger Missbrauch konnte C2 fälschlich einer Teilnehmergeografie zuordnen.

**Nachteile:** Geräte-/RF-/Providerdaten; Latenz und Abdeckung; moderne bidirektionale Systeme unterscheiden sich; Outbound-Pfad und asymmetrisches Routing bleiben Beweise.

**Verfahren:** Für rechtmäßigen Zugang ein eigenes Terminal registrieren und Traffic nach Bedarf tunneln. Zur Emulation historischen Turla-Verhaltens synthetische One-Way-Paketmitschnitte in einem RF-freien Labor wiedergeben und prüfen, ob Analysten eine Antwort an einen Host erkennen, der keine Anfrage gestellt hat; keinen Live-Satellitentraffic abfangen.<sup>[[14]](#references)</sup>

**Erkennung:** Provider-/Terminal-Telemetrie, RF-Richtungsbestimmung, unmöglicher/asymmetrischer Flow, RTT-/Routing-Widerspruch und Malware-Konfiguration.

## Residential-/Mobile-Proxy oder Proxyware mit Einwilligung

**Mechanik:** Ein Backconnect-Gateway weist Consumer-Breitband-/Mobilfunk-Exits zu, dauerhaft oder rotierend. Die Bereitstellung kann einvernehmlich, täuschend gebündelt oder bösartig sein.

**Vorteile:** hohe Geschwindigkeit; geografische Auswahl; Consumer-ASN umgeht manche Hosting-Blockaden; große Pools.

**Nachteile:** Herkunfts-/Einwilligungs- und Rechtsrisiko; Broker sieht Kunden; infizierte Exits schädigen Opfer; Rotation erzeugt Anomalien; teuer und unzuverlässig.

**Verfahren:** Nur dokumentierte, informierte, organisations-eigene Agents für Emulation verwenden: (1) Testendpunkte registrieren; (2) Eigentümer/IPs inventarisieren; (3) Gateway konfigurieren; (4) Sticky-/Per-Request-Modi rotieren; (5) nur an eigenes Ziel senden; (6) Gateway-/Exit-/Ziel-Logs vergleichen; (7) jeden Agent entfernen.

**Erkennung:** Unmögliche Reisen, stabiler Browser/Account über schnelle IP-/ASN-Wechsel, Backconnect-Protokolle, Proxyware-Prozess-/Netzwerkartefakte und Broker-/Controller-Beziehungen.

## ORB-, Botnet- und kompromittierte Edge-Device-Relays

**Mechanik:** Gemietete oder kompromittierte Router/IoT-Geräte/Server bilden von einer Flotte verwaltete Access-, Traversal- und Exit-Rollen. Mehrere APT-Kunden können sie gemeinsam nutzen.

**Vorteile:** geliehene Reputation/Geografie; kurzlebige Exits; widerstandsfähiges Multi-Hop-Mesh; schwache direkte Akteur-IP-Verknüpfung.

**Nachteile:** Kriminalität gegen Opfer; Implantat-/Controller- und Flottenmuster; Beschlagnahmung von Vermittlern; inkonsistente Performance; Operator-/Kundenunterlagen.

**Verfahren:** Niemals echte Geräte kompromittieren. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) verwenden: (1) isolierte Entry-/Transit-/Zielnetze erstellen; (2) eigene Dual-Homed-Relay-Container verbinden; (3) nur einen Testport weiterleiten; (4) harmlose Anfrage senden; (5) prüfen, dass das Ziel nur den Exit sieht; (6) Exit rotieren; (7) alle benannten Ressourcen abbauen.<sup>[[15]](#references)</sup>

**Erkennung:** Topologie, Ports/Services, Controller-Beziehungen, Implantat-Fingerprints und Knotenlebenszyklus verfolgen; Edge-Konfiguration/Flow/Integrität zentral telemetrieren; Exit-IP nicht mit dem Akteur gleichsetzen.

## CDN-Redirector, Domain Fronting und Domainless Fronting

**Mechanik:** Ein öffentlicher Edge leitet nur Traffic weiter, der einer Grammatik entspricht; Fronting verwendet einen harmlosen äußeren SNI und eine andere innere HTTP Authority oder leeres SNI, sofern der Vermittler dies zulässt.

**Vorteile:** verbirgt/schützt Back-End; schneller globaler Edge; vermischt das Ziel mit einem Shared Service; schneller Wechsel.

**Nachteile:** CDN sieht sämtliches Routing und den Tenant; viele Provider verbieten Cross-Tenant-Fronting; SNI/Host/Prozess/Flow und Kontenartefakte; wiederverwendete Konfiguration clustert Kampagnen.

**Verfahren:** Nur auf einem eigenen Reverse Proxy mit [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) reproduzieren: lokalen Certificate/Edge erstellen, einen abweichenden Host zu einem eigenen Ziel routen, SNI und Host loggen, normale/abweichende Requests senden und Container entfernen.<sup>[[16]](#references)</sup>

**Erkennung:** SNI/ECH/Host/`:authority` an Endpunkt oder terminierendem Edge vergleichen; auslösenden Prozess, Tenant/Origin, Request-Grammatik und Flow-Kadenz verbinden.

## Dynamic DNS, DGA, Fast Flux und Double Flux

**Mechanik:** DDNS aktualisiert einen stabilen Namen; DGA erzeugt wechselnde Kandidatennamen; Fast Flux rotiert Serviceadressen mit niedriger TTL; Double Flux rotiert zusätzlich Nameserver.

**Vorteile:** widerstandsfähige Auffindbarkeit; schneller Infrastrukturwechsel; verbirgt Controller hinter vielen Knoten.

**Nachteile:** DNS erzeugt zentrale Telemetrie; Entropie/NXDOMAIN/Wechsel; niedrige TTL und breite ASN-Muster; Registrierung und autoritative Infrastruktur bleiben.

**Verfahren:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry) verwenden: eigene Zone mit RFC-5737-Adressen und fünf Sekunden TTL bereitstellen, wiederholt abfragen, synthetische Epoche ändern und Analytics validieren. Testrecords niemals auf Dritte zeigen lassen.<sup>[[17]](#references)</sup>

**Erkennung:** Eindeutige Antworten/ASNs im Sliding Window, mediane TTL, Geografie, autoritativer Wechsel, DGA-NXDOMAIN-/lexikalische/zeitliche Cluster und nachfolgende Prozesse; legitime CDNs mit Kontext ausschließen.

## Legitime Webdienste, Dead-Drop-Resolver und One-Way-Tasking

**Mechanik:** Ein öffentlicher Post, ein Repository, ein Dokument, Objekt oder Feed enthält einen codierten aktuellen Endpunkt oder Task. Der Client kann Ergebnisse über einen anderen Kanal zurückgeben.

**Vorteile:** erlaubter Dienst mit hoher Reputation; TLS; Endpunktrotation ohne Binäränderung; asymmetrisches Tasking erschwert einfache Flow-Korrelation.

**Nachteile:** stabile Objekt-/Konto-/API-Kennungen; Providerdaten; Endpunkt-Decode-/Follow-on-Sequenz; Inhalt kann beschlagnahmt oder verändert werden.

**Verfahren:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence) verwenden: codierten Pointer auf einem eigenen Container hosten, von einem kurzlebigen Client abrufen/decodieren, zweiten eigenen Dienst kontaktieren, beide Logs aufbewahren und anschließend abbauen.

**Erkennung:** ungewöhnlichen Prozess → stabiles Objektlesen → Decode → neues Ziel korrelieren; Inhalte hashen/aufbewahren und vollständige Objektpfade, nicht nur Domains, speichern.

## Serverless-, kurzlebiger Container- und Cloud-NAT-Egress

**Mechanik:** Functions/kurzlebige Jobs laufen hinter Provider-NAT oder einem Front; der logische Dienst bleibt stabil, während Instanzen/Adressen rotieren.

**Vorteile:** schnelle Bereitstellung/Zerstörung; geteilter Egress auf Providermaßstab; wenig lokale Festplatte; elastisches regionales Routing.

**Nachteile:** Tenant, Rolle, API, Image, Secret, Invocation, Billing und Front-to-Origin-Logs sind dauerhaft; Cold-Start-/Plattform-Fingerprints; Provider-Richtlinie.

**Verfahren:** (1) eigenen Organisations-Tenant verwenden; (2) harmlose Function bereitstellen, die nur einen eigenen Endpunkt anfragt; (3) Projekt/Rolle/Image/Konfiguration erfassen; (4) über mehrere Instanzen aufrufen; (5) Ziel-IPs mit Audit-/Request-IDs vergleichen; (6) Log-Aufbewahrung testen; (7) Function, Rollen und Secrets entfernen.

**Erkennung:** Cloud-Audit-/Invocation-Logs, ungewöhnliche Rollenerstellung, geteilter Egress mit stabiler Request-Grammatik, Image-/Layer-/Secret-Wiederverwendung und Front-Origin-Korrelation.

## Autorisierter On-Site-Drop

**Mechanik:** Ein inventarisierter Kleincomputer verwendet lokales Kabel/Wi-Fi sowie ausgehendes VPN-/Mobilfunk-Rendezvous und präsentiert eine lokale Quelle.

**Vorteile:** realistischer Test interner Herkunft; hohe Geschwindigkeit; kann NAC, physisches Inventar und Egress-Kontrollen prüfen.

**Nachteile:** physische Entdeckung/Diebstahl; Seriennummer/MAC/USB/DHCP/PoE/RF- und Kamerabeweise; Verlust kann Credentials offenlegen.

**Verfahren:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) befolgen: (1) exakte schriftliche Platzierungsgenehmigung einholen; (2) Seriennummer, MAC, Foto, Standort und Abholzeit erfassen; (3) signiertes minimales Image und kurzlebige Mutual-Credentials verwenden; (4) ausgehende Ziele/Fähigkeiten beschränken; (5) serverseitige Quarantäne und Bandbreitenlimits hinzufügen; (6) SOC-Sichtbarkeit und Verlustreaktion testen; (7) abholen, erforderliche Beweise sichern und gemäß vereinbarter Lifecycle-Richtlinie bereinigen. Niemals in einem nicht einwilligenden Venue verstecken.

**Erkennung:** NAC/802.1X, Switchport/PoE/DHCP, USB-Inventar, RF-Survey, wiederkehrender Tunnel, Empfang/Kamera und physische Prüfung.

## Nearest-Neighbor-Wireless-Pivot

**Mechanik:** Ein Akteur kontrolliert einen Host in Funkreichweite des Ziels und verwendet anschließend Ziel-Wi-Fi-Credentials, um die Grenze aus der Ferne zu überschreiten. APT28 nutzte dies über nahe kompromittierte Organisationen.<sup>[[18]](#references)</sup>

**Vorteile:** keine Reise des Operators; Ziel sieht lokale Funkquelle; umgeht Kontrollen, die nur auf den Internetzugang angewendet werden.

**Nachteile:** nahegelegener kompromittierter/eigener Dual-Radio-Host und gültiger Zugang erforderlich; RADIUS/NAC/AP- und Nachbarendpunktbeweise; Signal-/Geräteanomalien.

**Verfahren:** Nur mit dem [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduzieren: eigenen Pivot in benachbarte und Ziel-Lab-SSIDs einbinden, nur einen Dienst weiterleiten, beide AP-/Pivot-Logs erfassen, anschließend EAP-TLS/Gerätehaltung aktivieren und bestätigen, dass der zweite Versuch scheitert.

**Erkennung:** RADIUS-Identität, verwaltetes Zertifikat/Haltung, erstmals beobachtetes Gerät, AP-Rand/Signal, gleichzeitiges Login und physische Präsenz korrelieren; nahe Endpunkte auf gleichzeitige Funkgeräte, Forwarding und Tunnel untersuchen.

## Community-Mesh, Delay-Tolerant und Offline Store-and-Forward

**Mechanik:** Traffic durchläuft lokale Peers, asynchrone Gateways, Wechselmedien oder geplante Queues statt einer interaktiven Internet-Session.

**Vorteile:** funktioniert bei Störungen/Zensur; verzögerte/gebündelte Zustellung schwächt einfache Timing-Analyse; kein zentraler Last Mile für lokale Kommunikation.

**Nachteile:** hohe Latenz; kleine Anonymitätsmenge; Verwahrungs-/physische Metadaten; bösartige Peers; Daten erreichen letztlich ein Gateway, das sie beobachtet.

**Verfahren:** (1) isoliertes eigenes Drei-Knoten-Mesh oder eine File-Queue erstellen; (2) Inhalte Ende-zu-Ende verschlüsseln/authentifizieren; (3) direkte Internet-Routen vom Ursprung entfernen; (4) harmlose Datei nach kontrollierter Verzögerung weiterleiten; (5) prüfen, dass nur das Gateway das eigene Ziel kontaktiert; (6) Verwahrung/Zeitstempel vergleichen; (7) erforderliche Beweise sichern und temporäre Medien/Queues beim genehmigten Abschluss bereinigen.

**Erkennung:** Endpunkt-Datei-/Prozessaktivität, Peer-Funkverbindungen, Wechselmedien-Audit, Queue-/Gateway-Periodizität und Inhaltskennungen. Längere Korrelationsfenster ersetzen interaktive Flow-Analyse.

## TURN-Relay und erzwungenes WebRTC-Relay

**Mechanik:** Traversal Using Relays around NAT (TURN) weist eine öffentliche Relay-Adresse zu und transportiert UDP-, TCP- oder TLS-Traffic zwischen Client und Peers. Eine ICE-Richtlinie kann Relay-Nutzung erzwingen, statt einen direkten Kandidaten offenzulegen. TURN löst Erreichbarkeit, keine allgemeine Anonymität: Der Server authentifiziert den Client und sieht Allocations, Peers, Zeit und Volumen.<sup>[[19]](#references)</sup>

**Vorteile:** weit verbreitet; funktioniert bei restriktivem NAT; unterstützt mobiles WebRTC; der Peer erhält bei korrekter Relay-only-Richtlinie nicht die direkte Transportadresse des Clients.

**Nachteile:** TURN-Betreiber sieht beide benachbarten Seiten; Anwendungsidentität, Media-Fingerprint und Signaling bleiben; Relay-only kostet Bandbreite/Latenz; Fehlkonfiguration kann weiterhin Host- oder serverreflexive Kandidaten sammeln.

**Verfahren:** (1) organisations-eigenen TURN-Dienst mit TLS und kurzlebigen Credentials bereitstellen; (2) Realms, Peers, Ports, Quoten und Ablauf beschränken; (3) Testanwendung auf Relay-only ICE setzen; (4) eigenen Peer anrufen; (5) `getStats()` und Paketmitschnitt prüfen, um zu bestätigen, dass nur Relay-Kandidaten Medien transportieren; (6) Relay ausfallen lassen und direkten Fallback ausschließen; (7) Allocation-Logs für das Engagement aufbewahren.

**Erkennung:** Signaling, Browserprozess und TURN-Allocations verbinden Session und Relay; Netzwerke sehen dauerhafte Flows zu TURN-Ports oder TLS-Endpunkten; Peer sieht das zugewiesene Relay. **Erfasster Knoten:** Anwendungszustand und kurzlebige TURN-Credentials können Realm und Rendezvous-Dienst offenlegen. Exposition mit gerätebezogenen, kurzlebigen Credentials minimieren und Operatorauthentifizierung nur beim Controller aufbewahren.

## Nur ausgehendes Rendezvous oder Reverse Overlay

**Mechanik:** Ein Knoten hinter NAT initiiert eine authentifizierte Verbindung zu einem organisationskontrollierten Broker. Der Operator authentifiziert sich separat beim Broker, der einen engen Managementkanal autorisiert; weder Inbound-Portforwarding noch direkte Operator-zu-Knoten-Route ist erforderlich.

**Vorteile:** stabil hinter NAT und Captive Last Miles; zentrale Sperrung und Auditierung; wechselnde Feldknotenadresse erfordert keine Operator-Suche; trennt Operatoridentität sauber vom Knotenschlüssel.

**Nachteile:** Broker wird zu einem wertvollen Korrelationspunkt; periodische Keepalives sind erkennbar; ein breiter Tunnel kann zu einem unsicheren Pivot werden; Brokerverlust beendet Management.

**Verfahren:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous) befolgen: eine begrenzte Geräteidentität ausgeben, nur eigenen Broker und genehmigten Managementdienst erlauben, authentifizierte Keepalives verwenden, Fail-closed-Routing erzwingen, Adresswechsel und Reboot-Recovery testen und die Identität während der Verlustübung widerrufen. WireGuard dokumentiert ein 25-sekündiges Persistent Keepalive als allgemein nützliches NAT-Intervall, wenn es tatsächlich benötigt wird.<sup>[[20]](#references)</sup>

**Erkennung:** Broker- und IdP-Logs verbinden beide Seiten; Access-Netz sieht wiederholtes verschlüsseltes Ziel/Kadenz; Endpunktinventar zeigt den Overlay-Agent. **Erfasster Knoten:** Annehmen, dass Geräteschlüssel, Brokername, Tunneladressen und gecachte Taskdaten offengelegt sind. Er darf keinen privaten Operatorschlüssel, kein persönliches Konto und kein wiederverwendbares Controller-Token enthalten.

## Pull-Mailbox, Message Queue oder Object-Store-Rendezvous

**Mechanik:** Eine Feld-Workload fragt eine authentifizierte Mailbox nach signierten, vorab genehmigten Jobs ab und veröffentlicht begrenzte Ergebnisse. Der Operator schreibt über eine separate Control Plane in die Queue; es gibt keinen interaktiven Socket zwischen beiden.

**Vorteile:** toleriert unterbrochene Verbindungen; entkoppelt Timing und Adressierung; Quoten und Schemas begrenzen Fähigkeiten; einfache zentrale Prüfung und Sperrung.

**Nachteile:** Polling-Kadenz und stabile Objekt-/Queue-Namen fingerprinten das System; Provider-Logs verbinden Producer und Consumer; verzögerte Steuerung; erfasste Queue-Daten können die Übung offenlegen.

**Verfahren:** (1) eine Engagement-Queue und Geräteidentität erstellen; (2) signiertes Schema harmloser, ausdrücklich begrenzter Jobs definieren; (3) Message-TTL, maximale Ergebnisgröße und Rate festlegen; (4) Node nur seine Queue lesen und nur in sein Ergebnispräfix schreiben lassen; (5) Offline-Aufstau, doppelte Zustellung und Sperrung testen; (6) unveränderliche Zugriffslogs zentralisieren; (7) Queue nach Ablauf der Aufbewahrung löschen.

**Erkennung:** periodische API-Aufrufe eines ungewöhnlichen Prozesses, stabile Bucket-/Objekt-/Queue-Pfade, identischer User-Agent oder TLS-Verhalten und Fetch-then-new-connection-Sequenzen suchen. **Erfasster Knoten:** lokaler Cache kann offene Jobs und Objektnamen offenlegen; Cache verschlüsselt, begrenzt und verwwerfbar halten, während autoritative Controller-Logs erhalten bleiben.

## Dual-Uplink-Failover und Connection Migration

**Mechanik:** Ein genehmigter Feldknoten hat zwei unabhängige Uplinks, etwa Venue-Ethernet/Wi-Fi und Organisationsmobilfunk, und hält seine Control Session über ein Overlay oder einen Message Broker aufrecht, während sich Routen ändern. Dies ist Verfügbarkeits-Engineering, keine Anonymität.

**Vorteile:** übersteht Ausfall eines Providers, APs oder Captive Portals; unterstützt geplante Wartung; erlaubt schnelle Isolation eines verdächtigen Pfades.

**Nachteile:** zwei Provider erzeugen zwei Standort-/Kontodaten; gleichzeitige Nutzung erleichtert Korrelation; Routen-/DNS-Leaks beim Failover; Mobilfunk-Co-Location bleibt beweiskräftig.

**Verfahren:** (1) beide organisations-eigenen Interfaces/Provider registrieren; (2) deterministische Routenprioritäten und Health Checks zu eigenen Endpunkten festlegen; (3) DNS und Management an Overlay binden; (4) sekundären Pfad daran hindern, Inbound-Traffic anzunehmen; (5) jeden Pfad trennen und Session-Recovery, Source Policy und fehlenden direkten Zielzugriff prüfen; (6) ungeplanten Pfadwechsel alarmieren; (7) Datennutzung/Roaming-Grenzen dokumentieren.

**Erkennung:** dasselbe Geräte-Zertifikat, Request-Grammatik und Timing über ASNs korrelieren; lokales Inventar sieht beide Funkgeräte; Carrier/Venues behalten eigene Daten. **Erfasster Knoten:** beide SIM-/Gerätekennungen und bekannte SSIDs können sichtbar sein; Organisationsressourcen verwenden und den Node niemals mit persönlichen Geräten koppeln.

## Organisations-Private-APN oder verwalteter Mobilfunktunnel

**Mechanik:** Ein privater Carrier-APN platziert registrierte SIMs in einer privaten gerouteten Domäne oder tunnelt Traffic zu einem Enterprise-Gateway. Er trennt das Gerät vom öffentlichen mobilen Internet, verbirgt es jedoch nicht vor Carrier oder beauftragter Organisation.

**Vorteile:** stabile private Adressierung; Carrier-Enrollment und Traffic-Richtlinie; keine öffentliche Inbound-Exposition; nützlich für autorisierte Remote-Appliances.

**Nachteile:** Teilnehmer, IMSI/IMEI, Zelle und Billing ermöglichen starke Zuordnung; Vorlaufzeit und Kosten; Carrier-/Gateway-Ausfall; keine Anonymität gegenüber dem Betreiber.

**Verfahren:** (1) APN im Namen der Assessment-Organisation beauftragen; (2) nur registrierte SIMs und Gateway-Präfixe allowlisten; (3) Mutual Authentication auf Anwendungsebene hinzufügen; (4) APN-Route auf Rendezvous-/Update-Dienste beschränken; (5) SIM-Entfernung, Roaming, Public-Internet-Breakout und Widerruf testen; (6) Carrier-/Gatewaydaten überwachen; (7) jede SIM beim Abschluss kündigen oder in Quarantäne setzen.

**Erkennung:** Carrierinventar und Zelltelemetrie, APN-Gateway-Flows, SIM-/IMEI-Abweichung und Enterprise-Assetdaten. **Erfasster Knoten:** SIM und Modem identifizieren den Vertrag, auch wenn der Speicher verschlüsselt ist; Capture-Resilience bedeutet daher schnelle Sperrung und enge Autorisierung, nicht Abstreitbarkeit.

## Langreichweiten-Punkt-zu-Punkt-Wireless-Bridge

**Mechanik:** Richtfunk-Wi-Fi oder ein anderes lizenzierter/nicht lizenzierter Point-to-Point-Funk verbindet zwei genehmigte Eigentümerstandorte, mit Internet-Egress am entfernten Standort. Die scheinbare IP-Position kann ohne kommerziellen Proxy verlagert werden.

**Vorteile:** hoher Durchsatz; unabhängig von Zwischen-Carriern; kontrollierbare RF und Routing; nützlich zum Testen von Segmentierung und Remote-Site-Monitoring.

**Nachteile:** Sichtverbindung, Frequenz-, Vermieter- und Regulierungsanforderungen; eindeutige RF-Emissionen und Hardware; beide Endpunkte sind physische Beweise; Wetter/Strom/Ausrichtung beeinflussen Stabilität.

**Verfahren:** (1) schriftliche Genehmigung für beide Standorte und Frequenz-/Leistungsregeln einholen; (2) Pfad ohne Senden außerhalb genehmigter Parameter vermessen; (3) authentifizierte Verschlüsselung und Management-VLAN verwenden; (4) Bridge auf eigenes Rendezvous/Testsubnetz beschränken; (5) Failover, Ausrichtung, Stromwiederherstellung und RF-Eindämmung testen; (6) beide Funkgeräte markieren/inventarisieren; (7) entfernen und nach der Übung Konfigurationsreset prüfen.

**Erkennung:** RF-Surveys, Spektrumanalyse, Dach-/Standortprüfung, Bridge-MAC/OUI, Management-Traffic und Remote-Site-Egress-Logs. **Erfasster Knoten:** Konfiguration offenbart Peer und Managementdomäne; eindeutige Übungs-Credentials, keine persönlichen Managementkonten und schnellen Peer-Key-Widerruf verwenden.

## Einvernehmlicher kooperativer oder Community-Exit

**Mechanik:** Freiwillige oder Partnerorganisationen betreiben wissentlich Relays unter veröffentlichter Richtlinie. Traffic verlässt das Netz aus einem gemeinsamen Community-Pool, während die Koordination Missbrauch und Widerruf verwaltet.

**Vorteile:** vielfältige Nicht-Cloud-Netze; ausdrückliche Einwilligung ist sicherer als Proxyware; gemeinsame Governance kann Vertrauen verteilen; nützlich für Forschung und Zensurresilienz.

**Nachteile:** kleine Pools und Mitgliedsdaten reduzieren Anonymität; Exit-Betreiber erhalten Beschwerden und sehen Traffic-Metadaten; böswillige Teilnehmer, wechselnde Verfügbarkeit und unterschiedliche Rechtsräume.

**Verfahren:** (1) Acceptable-Use- und Logging-Richtlinie veröffentlichen; (2) informierte Einwilligung jedes Betreibers einholen; (3) eindeutige Relay-Identität ausstellen und Ziele/Raten beschränken; (4) Missbrauchsbehandlung und sofortigen Widerruf anbieten; (5) beim Test nur autorisierten Traffic an eigene Endpunkte senden; (6) Wechsel- und Korrelationsrisiko messen; (7) Relay bei Ende der Einwilligung sauber entfernen.

**Erkennung:** Mitglieds-/Control-Plane-Daten, Relay-Zertifikate, gemeinsamer Software-Fingerprint und Exit-Verhalten identifizieren den Pool. **Erfasster Knoten:** Relay-Konfiguration kann die Kooperation identifizieren, sollte aber keine Clientidentitäten enthalten; Client-zu-Session-Verantwortlichkeit beim autorisierten Controller mit Zugriffskontrolle speichern.

## Temporäre IPv6-Adressen und Präfixrotation

**Mechanik:** IPv6-Privacy-Extensions erzeugen temporäre Interface-Identifier, sodass eine stabile Adresse nicht für jede ausgehende Verbindung wiederverwendet wird. Providerpräfixwechsel können zusätzliche Rotation erzeugen, aber delegiertes Präfix, Teilnehmerdaten und Layer-übergreifender Fingerprint bleiben.<sup>[[21]](#references)</sup>

**Vorteile:** reduziert langfristiges passives Tracking durch stabile Interface-ID; in üblichen Betriebssystemen integriert; kein Relay-Overhead.

**Nachteile:** keine Quellenanonymität; ISP und lokales Netz kennen Präfix/Gerät; DNS, Konten und Browserstatus verbinden Sessions; Adresswechsel erschwert Allowlists und Logging.

**Verfahren:** (1) aktuelle stabile und temporäre Adressen eines eigenen Clients prüfen; (2) vom OS unterstützten Privacy-Address-Standard statt Spoofing durch Dritte aktivieren; (3) wiederholt einen eigenen IPv6-Endpunkt über Adresslebensdauern anfragen; (4) bestätigen, dass Inbound-Dienste nur an vorgesehene stabile Adressen gebunden sind; (5) DHCPv6-/RA-/Neighbor- und präzise Endpunktlogs aufbewahren; (6) VPN-/Firewallverhalten für jede IPv6-Adresse testen.

**Erkennung:** delegiertes Präfix, Layer-2-Identität, Neighbor Discovery, Konto- und Endpunkttelemetrie korrelieren, statt eine Adresse als ein Gerät zu behandeln. **Erfasster Knoten:** Netzwerkprofile und Interface-Identifier bleiben; temporäre Adressierung verhindert eine passive Kennung, nicht forensische Zuordnung.

## Tor Pluggable Transports: Snowflake, WebTunnel, obfs4 und meek

**Mechanik:** Ein Pluggable Transport verändert das Erscheinungsbild der ersten Tor-Verbindung oder deren Weg zu einer Bridge. Snowflake verwendet kurzlebige freiwillige WebRTC-Proxies, WebTunnel ähnelt normalem HTTPS, obfs4 widersteht einfacher Protokollerkennung/aktivem Probing und meek leitet über unterstützte Webinfrastruktur. Dies sind Zensurumgehungstransporte in Tor, keine zusätzlichen Ende-zu-Ende-Anonymitätsschichten.<sup>[[22]](#references)</sup>

**Vorteile:** nützlich bei blockiertem direktem Tor oder bekannten Relays; Snowflake vermeidet eine stabile öffentliche Bridge-Adresse; in gepflegte Tor-Clients integriert; das Ziel erhält weiterhin normale Tor-Eigenschaften.

**Nachteile:** geringere/variable Performance; Broker/Front/Bridge und lokales Netz sehen unterschiedliche Metadaten; Transport-Fingerprints und Blockierung bleiben möglich; freiwilliger Proxy ersetzt Tor nicht und sollte keinen Klartext der Anwendung erhalten.

**Verfahren:** (1) offiziellen Tor Browser oder unterstützten Tor-Client installieren/verifizieren; (2) integrierten Transport in Verbindung/Bridges wählen; (3) nur eigene Diagnoseseite kontaktieren; (4) bestätigen, dass die Seite einen Tor-Exit, nicht den Snowflake-/WebTunnel-Peer sieht; (5) Bootstrap und Performance vergleichen; (6) Transport ausfallen lassen und stillen direkten Connect ausschließen; (7) nach dem Test zur standardmäßig unterstützten Konfiguration zurückkehren.

**Erkennung:** Ein Zensor kann Allowlists, TLS-/WebRTC-Verhalten, Broker-Erkennung und Flow-Analyse verbinden; Endpunkte zeigen Tor- und Transportkonfiguration. **Capture-resiliente OPSEC:** Standardclient verwenden, niemals persönlichen Browserstatus kopieren und davon ausgehen, dass Bridge-/Broker-Historie wiederherstellbar ist. **Monitoring:** Tor-Bootstrap-Logs, unerwartete direkte DNS-/Verbindungsversuche und Beobachtungen eigener Controller-Seiten überwachen; Transportfehler sind kein Beweis für Entdeckung.

## Refraction Networking oder Decoy Routing

**Mechanik:** Ein kooperierender Netzwerkbetreiber erkennt ein verdecktes Signal in Traffic, der scheinbar an ein erlaubtes Decoy adressiert ist, und leitet den Flow zu einem Umgehungsproxy um. Die Bereitstellung erfordert Infrastruktur im Netzwerkpfad; ein Client kann dies nicht allein durch Auswahl einer harmlosen Website erzeugen.<sup>[[23]](#references)</sup>

**Vorteile:** das scheinbare Ziel kann für einen Zensor schwer zu blockieren sein, ohne Kollateralschäden zu verursachen; keine öffentliche Bridge-Adresse muss verteilt werden; nützliches Forschungsmodell für pfadunterstützte Umgehung.

**Nachteile:** spezialisierte ISP-/Transitbeteiligung; Bereitstellung/Performance hängen vom Routing ab; Client-to-Decoy-Flow und Proxyaktivität bleiben; globaler/kooperierender Beobachter kann Timing korrelieren.

**Verfahren:** Nicht über unbeteiligte Netze signalisieren. Architektur in isoliertem Labor reproduzieren: (1) eigene Client-, Router-, Decoy- und Proxy-Namespaces erstellen; (2) harmlose markierte Testanfrage verwenden; (3) eigenen Router nur dieses Tag zum Proxy umleiten lassen; (4) Pre-/Post-Routing-Tupel und Request-IDs loggen; (5) normale und signalisierte Flows vergleichen; (6) False Positives und Entfernung testen; (7) Laborrouten zerstören.

**Erkennung:** Autorisierte Netzwerkbetreiber können Routingabweichung, ungewöhnliches ClientHello-/Tag-Verhalten und Diskrepanzen zwischen Decoy- und Back-End-Flow prüfen. **Capture-resiliente OPSEC:** Forschungsclient sollte nur Testschlüssel und Dokumentationsadressen enthalten. **Monitoring:** signierte Entscheidungen des Laborrouters mit Proxyankünften vergleichen; keine Produktions-Transitprovider sondieren, um Erkennung des Signaling festzustellen.

## Content-Addressed Gateway oder Cached-Peer-Retrieval

**Mechanik:** Ein HTTP-Gateway ruft einen IPFS Content Identifier (CID), eventuell aus Cache oder Peers, ab und gibt verifizierbaren Inhalt an den Client zurück. Der ursprüngliche Publisher sieht möglicherweise Gateway oder andere Peers statt des Lesers; das Gateway sieht Leser-IP und angeforderten CID. Native Peer-to-Peer-Abfrage exponiert den Client gegenüber Peers und DHT-/Routing-Teilnehmern.<sup>[[24]](#references)</sup>

**Vorteile:** Publisher und Leser können durch Caches getrennt werden; unveränderlicher Inhalt ist hash-verifizierbar; replizierte Daten überstehen den Ausfall eines Hosts; HTTP-Clients benötigen keinen nativen Peer-Stack.

**Nachteile:** öffentliche CIDs und Gateway-Logs offenbaren Interessen; erstes Abruf-Timing kann Publisher und Leser korrelieren; bösartiger Webinhalt und Same-Origin-Gefahren bei Pfaden; öffentliche Gateways sind Best-Effort und verbieten Missbrauch.

**Verfahren:** (1) harmlose Testdatei in eigenem privaten IPFS-Swarm oder Gateway veröffentlichen; (2) CID erfassen; (3) über separates eigenes HTTP-Gateway mit Subdomain-Isolation abrufen; (4) Bytes gegen CID prüfen; (5) nach Caching wiederholen; (6) Publisher-, Peer- und Gateway-Logs vergleichen; (7) Pins entfernen und Testinhalt nach Ablauf der Aufbewahrung löschen.

**Erkennung:** Gateways loggen Quelle/CID; DHT-/Peer-Verbindungen zeigen Abruf; Endpunkthistorie und Dateihashes identifizieren Inhalt. **Capture-resiliente OPSEC:** keinen privaten Publishing-Key auf einem Read-only-Feldclient speichern und sensible Inhalte vor Content-Addressing verschlüsseln. **Monitoring:** unerwartetes Pinning, Peer-Set-Änderung, nicht erlaubte CID-Anfragen oder Gateway-Kontobenachrichtigungen alarmieren.

## Private-Information-Retrieval-Service

**Mechanik:** Private Information Retrieval (PIR) ermöglicht einem Client, einen Datensatz aus einer Datenbank abzurufen, während der ausgewählte Index gegenüber dem Server unter einem angegebenen Single-/Multi-Server-Threat-Model kryptografisch verborgen bleibt. Es schützt die Query-Auswahl eines begrenzten Datasets, ist aber kein allgemeiner Webzugang und keine IP-Anonymität.<sup>[[25]](#references)</sup>

**Vorteile:** starke anwendungsspezifische Query-Privatsphäre; messbares Leakage-Modell; nützlich für Schlüsselverzeichnisse, Blocklists oder kleine öffentliche Datenbanken; kann die Preisgabe genauer Suchbegriffe vermeiden.

**Nachteile:** Rechen-/Bandbreiten-Overhead; Server kennt Verbindungstime/IP, sofern kein Relay verwendet wird; Dataset-Version, Antwortgröße und Anwendungszustand können Nutzer trennen; unterschiedliche Reifegrade der Implementierungen.

**Verfahren:** (1) auditierte PIR-Implementierung gegen eigene synthetische Datenbank bereitstellen; (2) Dataset-Version und Parameter veröffentlichen; (3) mehrere Indizes mit identischen Request-Größen abrufen; (4) lokal Korrektheit prüfen; (5) Server-Logs vergleichen und Abwesenheit des Index bestätigen; (6) bösartige/abgeschnittene Antworten und Versionskonflikte testen; (7) exakte Datenschutzannahme dokumentieren, statt anonymes Browsing zu behaupten.

**Erkennung:** Netzwerke sehen Dienstnutzung und Volumen; Endpunkttelemetrie zeigt Client und finale Datensatznutzung; kompromittierter Server kann Datenbanken oder Timing manipulieren. **Capture-resiliente OPSEC:** nur öffentliche Datenbankparameter und begrenzten Cache auf dem Client speichern. **Monitoring:** signierte Dataset-Roots, feste Request-Formen, Fehlerquotenänderungen und Server-Key-Rotationen validieren.

## Eingeschränkter serverseitiger Fetcher, Preview- oder Rendering-Service

**Mechanik:** Ein Remote-Dienst ruft eine URL ab oder rendert sie und gibt Screenshot, Metadaten oder bereinigten Inhalt zurück. Das Ziel sieht die Fetcher-Adresse; der Dienst sieht Anforderer, URL und Ergebnis. Der Missbrauch von Link-Preview-Bots, Security-Scannern oder URL-Fetchern Dritter ist keine autorisierte Proxy-Nutzung.

**Vorteile:** isoliert aktive Inhalte von der Workstation; Ziel erhält kontrollierten Fetcher-Fingerprint; Dateiart, Größe, Ziel und Renderinglimits können erzwungen werden; verworfene Ausführungsumgebung.

**Nachteile:** Dienst kennt die vollständige Anfrage; Konto/API-/Billing-Daten; SSRF- und Datenexfiltrationsrisiko; Scripts, Authentifizierung und interaktive Sites funktionieren möglicherweise nicht; eindeutige URLs korrelieren Anforderer und Abruf.

**Verfahren:** (1) eigenen Fetcher mit strikter Allowlist eigener Testdomains bereitstellen; (2) private, link-local, Metadata- und Redirect-to-unapproved-Adressen blockieren; (3) Methoden, Redirects, Bytes und Renderzeit begrenzen; (4) Credentials/Cookies entfernen; (5) eigene URL einreichen; (6) Anforderer-, Fetcher- und Ziel-Logs vergleichen; (7) Renderinstanz zerstören und zentrales Audit gemäß Richtlinie aufbewahren.

**Erkennung:** Ziel sieht Service-ASN/Fingerprint; Provider- und Controller-Logs verbinden Anforderer und URL; Endpunktprozess/API-Aufrufe zeigen Submission. **Capture-resiliente OPSEC:** ein kurzlebiges Projekt-Token ohne beliebige Zielberechtigung verwenden. **Monitoring:** Allowlist-Ablehnungen, Redirect-Verletzungen, Fetches ohne Controller-Job-ID und Provider-Missbrauchshinweise alarmieren.

## Anycast-Rendezvous-Pool

**Mechanik:** Mehrere organisationskontrollierte Knoten bewerben oder fronten eine stabile Serviceadresse; Routing wählt eine nahe Instanz. Anycast verbessert Verfügbarkeit und verbirgt ein einzelnes Backend vor dem Client, aber der Betreiber kontrolliert weiterhin alle Instanzen und die Serviceadresse bleibt stabil.<sup>[[26]](#references)</sup>

**Vorteile:** widerstandsfähiger regionaler Ingress; keine Feldneukonfiguration bei Ausfall einer Instanz; DDoS-/Lastverteilung; zentrale Richtlinie kann Sessions zwischen bekannten Knoten verschieben.

**Nachteile:** BGP/CDN- und Providerdaten identifizieren die Organisation; Pfadwechsel können zustandsbehaftete Sessions unterbrechen; Monitoring unterscheidet sich nach Clientstandort; eine stabile Adresse ist leicht zu blockieren oder zu clustern.

**Verfahren:** Provider-unterstütztes Organisationsprojekt oder isoliertes Routing-Labor verwenden: (1) zwei identische authentifizierte Health-Endpunkte bereitstellen; (2) dokumentierte Serviceadresse veröffentlichen; (3) Sessionzustand beim Broker statt am Edge halten; (4) einen Knoten zurückziehen und Reconnect prüfen; (5) Zertifikat, Richtlinie und Logkonsistenz testen; (6) unautorisierten Origin/Region alarmieren; (7) Advertisements und Credentials beim Abschluss entfernen.

**Erkennung:** BGP/RPKI/Historie, Provider-Tenancy, Zertifikate und identisches Serviceverhalten identifizieren den Pool. **Capture-resiliente OPSEC:** Edge enthält nur regionale Serviceidentität und keinen Operator-/Flottenregistrierungsschlüssel. **Monitoring:** jede Region von autorisierten Monitoren prüfen, Route-Origin und Konfigurationsdigest vergleichen und unerwarteten Origin als Incident behandeln.

## QUIC-Migration und Multipath-TCP-Kontinuität

**Mechanik:** QUIC Connection IDs können eine Client-Session über NAT-Rebinding oder Adresswechsel erhalten; Multipath TCP kann einen zuverlässigen Bytestream über mehrere Subflows transportieren. Beide verbessern Kontinuität bei Wi-Fi-/Mobilfunkwechseln, exponieren alte und neue Pfade jedoch gegenüber dem gemeinsamen Peer und können Cross-Path-Korrelation erleichtern.<sup>[[27]](#references)</sup>

**Vorteile:** schnellere Wiederherstellung bei Uplinkwechsel; Anwendungssession muss nicht neu starten; MPTCP kann Resilienz und Durchsatz verbinden; wertvoll für genehmigte Feldknoten.

**Nachteile:** keine Anonymität; Peer sieht Migration/Subflows; Connection IDs und paralleler Traffic verbinden Pfade; Middlebox-/Carrier-Unterstützung variiert; doppelte Providerdaten erhöhen die Exposition.

**Verfahren:** (1) unterstützten Transport nur zwischen eigenem Feldclient und Rendezvous aktivieren; (2) Anwendung unabhängig von IP authentifizieren; (3) begrenzten Transfer über genehmigtes Wi-Fi starten; (4) auf Organisationsmobilfunk wechseln; (5) Path Validation, Datenintegrität und fehlenden Klartext/direkten Fallback bestätigen; (6) Idle Timeout und Rückkehr testen; (7) Brokerdaten jeder Pfadänderung aufbewahren.

**Erkennung:** Peer beobachtet Adressmigration oder MPTCP-Subflows direkt; Access-Provider sehen ihren Teil; Connection IDs, TLS-Identität und Timing verbinden beide. **Capture-resiliente OPSEC:** nur gerätebezogenes Sessionmaterial speichern und resumierbaren Zustand schnell ablaufen lassen. **Monitoring:** unmögliche Pfadwechsel, gleichzeitige nicht genehmigte Netze, Migrationsstürme und Wiederaufnahme nach Quarantäne alarmieren.

## Verwalteter CI/CD- oder kurzlebiger Automation-Runner-Egress

**Mechanik:** Ein organisations-eigener Workflow führt eine begrenzte Netzwerkprüfung auf einem gehosteten Runner aus. Das Ziel sieht eine Cloud-Runner-Adresse, während die Plattform Repository, Akteur, Workflow, Token, Logs und Billing zuordnet. Dies ist Remote Execution mit nachvollziehbarem Egress, keine Anonymität gegenüber dem Provider.<sup>[[28]](#references)</sup>

**Vorteile:** verworfene saubere Umgebung; reproduzierbare Jobdefinition; keine eingehende Verbindung; nützlich für geografisch verteilte Verfügbarkeitsprüfungen; starkes Controller-Audit.

**Nachteile:** Plattform und Organisation identifizieren Initiator; breite Workflow-Tokens und nicht vertrauenswürdige Pull Requests sind gefährlich; geteilte IP-Reputation; Logs/Artefakte können Secrets oder Zieldaten speichern.

**Verfahren:** (1) privates Organisations-Repository und Assessment-Environment erstellen; (2) nur manuell genehmigte, feste harmlose Jobs zu eigenen Endpunkten erlauben; (3) minimale Read-only-Workflowrechte und keine Produktions-Secrets verwenden; (4) Prüfung ausführen; (5) Workflow-, Provider- und Zielaufzeichnungen vergleichen; (6) Artefakte auf Credentials prüfen; (7) Environment-Token löschen und erforderliches Audit aufbewahren.

**Erkennung:** Provider-Audit und Workflow-Logs liefern direkte Zuordnung; Ziele identifizieren Runner-ASNs/-Ranges und stabile Request-Grammatik. **Capture-resiliente OPSEC:** niemals Feldgeräte-, Signing-, Wallet- oder Cloud-Administrator-Secrets in Runner-Variablen ablegen. **Monitoring:** Branch-/Environment-Genehmigung verlangen und Workflowänderungen, Fork-Ausführung, Secret-Lesevorgänge und unerwartete Ziele alarmieren.

## Nicht-IP-lokaler erster Hop zu einem eigenen Gateway

**Mechanik:** Bluetooth-Mesh, Wi-Fi Aware/Direct, Low-Power-Funk oder serielle/optische Verbindung transportiert begrenzte Nachrichten von einem nahen Sensor zu einem genehmigten Internet-Gateway. Das Feldgerät selbst besitzt keine Internetroute; das Gateway ist der einzige Egress. Funkreichweite und Protokollgrenzen machen dies zu Telemetrie/Store-and-forward, nicht zu interaktivem anonymem Internet.

**Vorteile:** entfernt Internet-Stack und Credentials vom kleinsten Feldgerät; geringer Energieverbrauch; Gateway zentralisiert Richtlinie; kann temporäre Funklöcher überbrücken.

**Nachteile:** RF-/physische Auffindbarkeit, Pairing und Gerätekennungen; geringe Bandbreite/Reichweite; Gateway verbindet alle Nachrichten; Frequenz- und Verschlüsselungsbeschränkungen variieren; Erfassung kann Queue-Daten offenlegen.

**Verfahren:** (1) Standort- und Frequenzgenehmigung einholen; (2) einen eigenen Sensor mit einem eigenen Gateway über eindeutige Schlüssel koppeln; (3) signierte Nachrichtenarten fester Größe, TTL und Rate definieren; (4) dem Sensor keine Standard-IP-Route geben; (5) Gateway nur zu eigenem Collector weiterleiten lassen; (6) Replay, Reichweitenverlust und Gateway-Ausfall testen; (7) beide Geräte inventarisieren und zurückholen.

**Erkennung:** RF-Survey, Pairing-Datenbank, physische Prüfung und Gateway-Prozess-/Flow-Logs zeigen den Pfad. **Capture-resiliente OPSEC:** Sensor enthält nur Pairwise-Key und begrenzte verschlüsselte Queue, niemals Operator-, Wi-Fi-, Mobilfunk- oder Controller-Credentials. **Monitoring:** neue Peers, Sequenz-Rollback, Key-Fehler, ungewöhnliche RF-Rate und Nachrichten über nicht registriertes Gateway alarmieren.

## Matrix zur Exposition bei Erfassung/Kompromittierung

Diese Tabelle wendet eine Capture-Resilience-Prüfung auf jede oben genannte Familie an. „Minimieren“ bedeutet, Secrets und Blast Radius auf autorisierten Assets zu reduzieren; es bedeutet niemals, Beweise zu löschen oder sich vor einer Untersuchung zu verbergen.

| Technikenfamilie | Ein erfasster Endpunkt/Relay kann offenlegen | Minimale autorisierte Kontrolle |
|---|---|---|
| NAT/CGNAT, öffentliches Wi-Fi, travel router | bekannte Netze, DHCP-/Portalhistorie, MACs, Tunnel-Peer | separates Organisationsgerät; private MAC, sofern unterstützt; keine persönlichen Konten; Controller-Inventar |
| VPN, VPS, HTTP/SOCKS/SSH, Multi-Hop | Provider/Hostnamen, Schlüssel, Routen, Logs und benachbarten Hop | eine Identität je Engagement; kurze TTL; enge Routen; Broker-seitiger Widerruf; keine Masterkeys |
| OHTTP/ODoH, MASQUE, Split-Provider-Relay | Relay-/Gateway-Konfiguration, Anwendungskennungen und gecachte Requests | Payload-Kennungen minimieren; genehmigte Konfiguration pinnen; begrenzter Cache; strikter direkter Fallback-Ausschluss |
| Tor, Bridge, Onion Service, I2P, Mixnet, GNUnet | installierte Software, Bridge-/Onion-Material, lokalen Zustand und Peer-Historie | Standardclient; separate Servicekeys; verschlüsselter Minimalzustand; kompromittierte Serviceidentität rotieren |
| Remote-Browser/VDI/Jump-Host | Workspace-Token, Clipboard/Dateien und Remote-Tenant | phishing-resistente MFA am Gateway; Transferkanäle deaktiviert; schnelle Session-Sperrung |
| Mobilfunk, Satellit, Private APN | SIM/eSIM, IMEI/Terminalidentität, Provider und ungefähren Standort | Organisationsvertrag; keine persönliche Co-Location; enge APN-/Overlay-Richtlinie; Provider-Sperrprozess |
| Residential-/kooperativer Proxy, ORB-Labor | Agentidentität, Controller/nächster Hop, gecachten Traffic | nur einwilligende/eigene Nodes; signierter Agent; Node-Credential; Teilnehmerzuordnung beim Controller |
| CDN/Fronting, Fast Flux, Serverless | Tenant/Origin/Konfiguration, API-Tokens, Deployment- und Billingdaten | dediziertes Projekt; Least-Privilege-Rolle; kurzlebiges Deploy-Token; Provider-Audit zentral aufbewahren |
| Dead Drop, Pull-Mailbox, Store-and-forward | Objektnamen, Queue, gecachte Jobs/Ergebnisse und Verwahrungsdaten | signierte begrenzte Jobs; TTL; verschlüsselter Cache; getrennte Produceridentität; unveränderliche Serverlogs |
| Drop, Nearest Neighbor, Long-Range Bridge | Serien-/Funk-/SSID-/Peer-Daten, Geräteschlüssel, physische Platzierungsartefakte | schriftliche Platzierung; eindeutige Geräteidentität; kein Operatorssecret; Manipulations-/Zustandstelemetrie; widerrufen und zurückholen |
| TURN, Reverse Overlay, Dual-Uplink | Realm/Broker, Gerätecredential, Peer/Route und Uplinkprofile | nur ausgehender enger Dienst; kurzlebiges Gerätecredential; unabhängiger Operatorlogin; Fail-closed-Pfade |
| Temporäre IPv6-Adressierung | Profile, Präfixhistorie und Endpunkt-/Anwendungszustand | nur als Anti-Tracking behandeln; Netzwerklogs bewahren; mit Endpunktkompartimentierung kombinieren |
| Pluggable Transport/Refraction-Labor | Bridge-/Broker-/Decoy-Einstellungen, Tor-Zustand und Forschungsschlüssel | Standardclient oder isoliertes Labor; kein persönlicher Browserstatus; kein Production-Signaling |
| IPFS/PIR/Fetcher | angeforderten CID/Query-Client, gecachten Inhalt, Gateway-/Service-Token | verschlüsselter begrenzter Cache; nur öffentliche Parameter; kurzlebiges allowlistiertes Service-Token |
| Anycast/QUIC/MPTCP | Servicenodes, Connection IDs, resumierbaren Zustand und bekannte Pfade | nur regionale Identität; kurze Resume-Lebensdauer; zentrale Routen-/Session-Sperrung |
| Verwalteter CI/CD-Runner | Repository, Workflow, Provider-Token, Logs und Artefakte | Least-Privilege-Workflow; keine Produktions-/Feld-/Wallet-Secrets; Environment-Genehmigung |
| Nicht-IP-lokaler Hop | Funk-Peer, Pairwise-Key, Queued Messages und Gatewayidentität | eindeutiger Pairwise-Key; festes Nachrichtenschema; keine Wi-Fi-/Mobilfunk-/Operator-Credentials |

## Monitoring möglicher Entdeckung für jede Zugriffsfamilie

Kein clientseitiger Test beweist, dass ein Ermittler oder Verteidiger zusieht. Änderungen in Systemen überwachen, die dem Engagement gehören, sie mit Controller/Client corroborieren und statt Beobachter zu sondieren stoppen. Die folgenden Zeilen decken jede oben genannte Technik ab; mit den [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise) kombinieren.

| Abgedeckte Techniken | Sichere controllerseitige Signale | Quarantäne-/Stoppbedingung |
|---|---|---|
| NAT/CGNAT, öffentliches/Gast-Wi-Fi, travel router, Mobilfunk/eSIM, Satellit, private APN | Lease/Portal-/Carrier-Session, öffentliches Tupel, BSSID-/Zellen-/Pfadwechsel, Providerhinweis | nicht genehmigtes Netz/SIM/Gerät, ungeklärte Verlagerung oder Provider-/SOC-Eskalation |
| VPN/VPS, HTTP/SOCKS/SSH, Multi-Hop, Residential-/kooperativer Proxy | Peer-Authentifizierung, Tunnelzustand, Routen-/DNS-Leaks, neues Admin-/API-Ereignis, Beschwerde | doppeltes/gestohlenes Credential, unbekannter Admin, direkter Fallback oder Egress außerhalb des Scopes |
| OHTTP/ODoH/ECH, MASQUE, Split-Provider-Relay, TURN | Relay-/Gateway-Allocation, Schlüssel-/Konfigurationsversion, nicht unterstützte direkte Verbindung, Fehler-/Replay-Rate | Schlüsselabweichung, direkter Fallback, unbekannter Realm/Peer oder Provider-Missbrauchshinweis |
| Tor Browser, Bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, Onion Service | Bootstrapzustand, Circuitausfall, Onion Descriptor/Servicezustand und eigene Canary-Seite | persönlicher Account-Crossover, unerwartete Nicht-Tor-Verbindung oder kompromittierter Servicekey |
| I2P, Mixnet, GNUnet, Mesh/Store-forward, Nicht-IP-lokaler Hop | Peer-Set, Queue-Alter/-Sequenz, Gatewayankunft, Funkassoziation und Content-Hash | unbekannter Peer/Gateway, Sequenz-Rollback, nicht autorisierter Inhalt oder fehlender Verwahrungsnachweis |
| Remote-Browser/VDI/Jump-Host, CI/CD-Runner, Serverless | IdP-Session, Workflow-/Image-/Konfigurationsänderung, neue Token-Nutzung, Artefakt/Export und Cloud-Audit | unbekannter Login/Workflowänderung, Secret-Lesevorgang, unerwartetes Ziel oder Projekt-/Rollenescalation |
| ORB-Labor, Fast Flux/DGA, CDN/Fronting, Dead Drop/Pull-Mailbox | eigenes Node-Inventar, DNS-/Edge-/Objektzugriff, Controllergraph, Jobsignatur und TTL | unbekannter Node/Origin/Objektwriter, unsignierter/wiederholter Job, Topologie verlässt Labor |
| Drop/Nearest Neighbor/Long-Range Bridge/Outbound Overlay/Dual Uplink | signierter Heartbeat, Boot-/Konfigurationshash, Gehäusestatus, AP-/Switchkontext, doppelte Identität | bewegter/geöffneter Node, unerwarteter Boot/Hash/Pfad, Sentinel-Nutzung oder Standortmeldung |
| Temporäres IPv6, QUIC-Migration, MPTCP | delegiertes Präfix, Connection ID/Subflows, Path Validation und Broker-Session | unmögliche Migration, gleichzeitige nicht genehmigte Pfade oder Session-Resume nach Widerruf |
| IPFS/Cache, PIR, eingeschränkter Fetcher | CID-/Query-Form/Root-Version, Peer-/Gatewayänderung, Redirect-/Allowlist-Ablehnung | unerwartetes Pinning/Query/Ziel, unsignierter Dataset-Root oder Provider-Missbrauchshinweis |
| Refraction-/Decoy-Routing-Labor, Anycast-Rendezvous | eigene Diversionsentscheidung, Proxyankunft, BGP/RPKI-Origin, regionaler Konfigurationsdigest | Production-Path-Signal, unbekannter Route-Origin, regionale/Konfigurationsabweichung |

## Auswahl und Test eines Pfades

1. Den zu entfernenden Beobachter und die zu verbergenden Daten benennen.
2. Die am wenigsten komplexe Familie wählen, die ihn entfernt.
3. Quellen-, Entry-, Traversal-, Exit-, DNS-, Konto- und Zahlungsbeobachter einzeichnen.
4. Separate Endpunkt-/Anwendungsidentität verwenden.
5. IPv4, IPv6, DNS, WebRTC-/Anwendungsumgehung und Zielsicht prüfen.
6. Jeden Hop unterbrechen und geschlossenen Fehlerzustand bestätigen.
7. Logs jeder kontrollierten Komponente vergleichen.
8. Verbleibende Timing-, Provider-, Endpunkt- und physische Verknüpfungen dokumentieren.

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
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
{{#include ../banners/hacktricks-training.md}}
