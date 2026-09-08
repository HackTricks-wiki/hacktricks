# Netzwerkdatenschutz & anonyme Konnektivität

{{#include ../banners/hacktricks-training.md}}

Netzwerkdatenschutz ist eine Routing-Entscheidung, keine vollständige Identität. Wähle einen Pfad, indem du fragst, wer **Quelle**, **Ziel**, **Inhalt** und **Zeitablauf** nicht miteinander verbinden können soll.

Beginne für das normalisierte Inventar - `Pros`, `Cons`, schrittweise `Procedure` und `Detection` für jede Familie von Zugriffspfaden - mit dem [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Diese Seite erweitert die gängigen einsetzbaren Optionen.

## Was die einzelnen Beobachter normalerweise sehen können

| Pfad | Lokales Netzwerk / ISP | Vermittler | Ziel | Hauptbeschränkung | Relative Geschwindigkeit |
|---|---|---|---|---|---|
| Direktes HTTPS | Quell- und Zielmetadaten, Zeitablauf/Volumen | Hosting/CDN sieht die Verbindung | Quell-IP, Browser-/App-Daten | Kein Quell-IP-Datenschutz | Am schnellsten |
| Commercial VPN | Quelle mit VPN verbunden; übliche Zielmetadaten nicht sichtbar | VPN sieht Quell- und Zielmetadaten | VPN-Egress-IP | Ein Anbieter wird zum Korrelationspunkt | Normalerweise schnell |
| Self-hosted VPN/VPS | Quelle mit VPS verbunden | Host-/Konto-/Payment-/Control-Plane-Logs | VPS-Egress-IP | Leicht dem gemieteten Server/Konto zuzuordnen | Normalerweise schnell |
| Tor Browser | Quelle mit Tor/Bridge verbunden; Zeitablauf/Volumen | Jedes Relay sieht nur einen begrenzten Teil | Tor-Exit, Browser-Daten | Langsamer; Konto-/Endpoint-/Korrelationsrisiken | Mittel/langsam |
| Tails/Whonix | Ähnlicher Tor-Pfad mit stärkeren Routing-Grenzen | Dieselben Tor-Beschränkungen | Tor-Exit/Anwendungsdaten | Bedienfehler sowie Host/Hardware bleiben relevant | Mittel/langsam |
| Öffentliches Gäste-Wi-Fi + HTTPS | Ort sieht lokales Gerät/Zeitablauf und Ziele | ISP des Ortes sieht Metadaten | Öffentliche Gäste-IP | Physische-/Captive-Portal-/Gerätekorrelation | Schnell/variabel |
| Cellular Hotspot | Carrier sieht Teilnehmer, Gerät, Standort und Ziele | VPN/Tor, falls verwendet | Carrier-, VPN- oder Tor-Egress-IP | Mobilfunkvertrag und Standort sind dauerhafte Identifikatoren | Schnell/variabel |
| Mixnet | Zugriff sieht die Mixnet-Nutzung, Zeitablauf/Volumen | Mehrere Mixing Nodes | Gateway/Egress | Aufkommendes Ökosystem; Kosten durch Latenz und Bandbreite | Am langsamsten |

HTTPS schützt den Inhalt während der Übertragung, aber nicht alle Metadaten. EFF weist darauf hin, dass Domain, Zeitpunkt und Traffic-Größe für Vermittler sichtbar bleiben können, selbst wenn Seitenpfade, Zugangsdaten und Nachrichten verschlüsselt sind.<sup>[[1]](#references)</sup>

## VPNs: schneller Datenschutz mit konzentriertem Vertrauen

Ein VPN ist nützlich, um Zielmetadaten vor dem Zugangs-ISP zu verbergen, den ersten Hop in einem nicht vertrauenswürdigen Netzwerk zu schützen, eine stabile Engagement-Egress-Adresse bereitzustellen oder ein privates Netzwerk zu erreichen. Es macht einen Benutzer **nicht** anonym. Das VPN sieht die Quellverbindung und kann Zielmetadaten beobachten; Konten, Cookies, GPS, Fingerprints und Zahlungsinformationen bleiben bestehen.<sup>[[1]](#references)</sup>

### Checkliste zur Anbieterbewertung

1. **Eigentum und Gerichtsstand:** Ermittle die juristische Einheit, die Muttergesellschaft, die Länder, in denen der Betrieb stattfindet, Infrastruktur-Subunternehmer und anwendbare rechtliche Verfahren.
2. **Erhobene Daten:** Unterscheide zwischen Konto-/Abrechnungsdaten, Quell-IP, Verbindungszeitpunkten, Bandbreite, Crash-Telemetrie, DNS-Abfragen und Ziel-Logs. „Keine Browsing-Logs“ bedeutet nicht „keine Daten“.
3. **Aufbewahrung und Löschung:** Ermittle genaue Zeiträume und ob Backups, Fraud-Systeme und Auftragsverarbeiter denselben Zeitplan einhalten.
4. **Nachweise:** Bevorzuge öffentliche Audits mit Umfang, Datum, Ergebnissen und Behebung; reproduzierbare/Open Clients; Transparenzberichte und dokumentierte Vorfälle.
5. **Protokoll und Client:** Gepflegtes WireGuard, OpenVPN oder ein anderes geprüftes Protokoll; automatische Updates; DNS- und IPv6-Verarbeitung; Kill Switch und Leak-Tests für jede Plattform.
6. **Geschäftsmodell:** Verstehe, wie ein kostenloser oder subventionierter Dienst finanziert wird. Die Präsenz in einem App Store allein ist kein Nachweis für einen vertrauenswürdigen Betrieb.
7. **Payment-Eignung:** Alternative Zahlungsmethoden können die Abrechnungsdaten gegenüber dem VPN reduzieren, löschen jedoch nicht die bei jeder Verbindung beobachtete Quell-IP.

### VPN konfigurieren und verifizieren

1. Installiere den signierten Client des Anbieters/der Organisation aus der offiziellen Quelle.
2. Wähle **full tunnel**, sofern keine dokumentierte Route daran vorbeiführen muss. Split tunneling erzeugt Korrelations- und Leak-Pfade.
3. Aktiviere fail-closed/always-on-Verhalten und blockiere Traffic während der Wiederverbindung.
4. Leite DNS durch den Tunnel und teste IPv4 sowie IPv6. Deaktiviere ein Protokoll nur, wenn es nicht sicher getunnelt werden kann und der Funktionsverlust akzeptiert wird.
5. Teste Standby/Aufwachen, Netzwerkwechsel, Captive-Portal-Login, Tunnelabsturz und Hotspot-Tethering. NCSC warnt, dass Tethered Clients auf einigen Plattformen das VPN eines Telefons umgehen können.<sup>[[2]](#references)</sup>
6. Verwende einen von der Organisation kontrollierten Test-Endpoint, um beobachtete IPv4-, IPv6- und DNS-Resolver-Daten sowie den Verbindungszeitpunkt zu erfassen. Setze kein sensibles Engagement zufälligen „Leak-Test“-Websites aus.
7. Teste nach Änderungen an Client, OS, Netzwerk oder Richtlinien erneut.

## Tor Browser: stärkeres Web-Unlinking

Tor erstellt eine Circuit über mehrere Relays, sodass normalerweise kein einzelnes Relay sowohl Quelle als auch Ziel kennt. Das Ziel sieht einen Tor-Exit statt der IP des Benutzers; das lokale Netzwerk sieht normalerweise eine Tor-Verbindung.<sup>[[3]](#references)</sup> Tor ist für TCP-Anwendungen mit niedriger Latenz ausgelegt, daher ist es langsamer und kann keinen Schutz gegen einen Angreifer garantieren, der beide Enden korrelieren kann.<sup>[[4]](#references)</sup>

### Sicherer Tor-Browser-Workflow

1. Lade Tor Browser ausschließlich vom Tor Project oder einem offiziellen Mirror herunter und verifiziere nach Möglichkeit die Signatur.
2. Verwende **Tor Browser**, nicht einen normalen Browser, der auf einen Tor-SOCKS-Port zeigt. Normale Browser können DNS/WebRTC und identifizierende Zustände leaken.<sup>[[5]](#references)</sup>
3. Behalte Standardgröße, Fonts, Extensions und Privacy-Einstellungen bei. Zusätzliche Add-ons können den Browser einzigartiger machen.<sup>[[6]](#references)</sup>
4. Wähle die Sicherheitsstufe **Safer** oder **Safest**, wenn die dadurch verursachten Funktionseinschränkungen akzeptabel sind.
5. Verwende eine Bridge, wenn direktes Tor blockiert wird oder gewöhnliche Relay-IPs eine nicht akzeptable lokale Sichtbarkeit erzeugen würden. Bridges erschweren die einfache Erkennung, beseitigen jedoch keine Traffic-Analyse.<sup>[[7]](#references)</sup>
6. Melde dich nicht bei einem identifizierenden Konto an, gib keine identifizierenden Informationen an und öffne heruntergeladene aktive Dokumente nicht in einer extern vernetzten Anwendung.
7. Verwende für jede Identität eine separate Session/einen separaten Kontext. „New circuit“ ist nicht dasselbe wie das Löschen der Browser-/Anwendungsidentität; verwende **New Identity** oder starte die isolierte Umgebung gegebenenfalls neu.
8. Bevorzuge authentifiziertes HTTPS oder einen authentifizierten Onion Service. Ein Tor-Exit kann unverschlüsselten HTTP-Traffic beobachten.

### Tor plus VPN

Die Kombination ist nicht automatisch sicherer. Ein VPN vor Tor kann direkte Tor-Relay-Verbindungen vor einem ISP verbergen, während das VPN die Quelle sieht; Tor vor einem VPN gibt dem VPN eine stabile Sicht auf Aktivitäten nach Tor und kann die Anonymity Set verkleinern. Fehlkonfigurationen können Leaks verursachen. Das Tor Project empfiehlt solche Kombinationen nur für fortgeschrittene, ausdrücklich definierte Threat Models.<sup>[[8]](#references)</sup>

## Öffentliches und Gäste-Wi-Fi

Modernes HTTPS bedeutet, dass passive Nachbarn ordnungsgemäß verschlüsselte Webinhalte normalerweise nicht lesen können; Gäste-Wi-Fi ist jedoch keine Anonymität. Der Ort kann Verbindungszeitpunkte, Gerätekennungen, Captive-Portal-Daten, Ziele und DHCP-Details protokollieren; Kameras, Einkäufe, Transportmittel und physische Beobachtung können den Benutzer identifizieren. Ein gefälschter Hotspot mit ähnlichem Namen kann außerdem Portal-Zugangsdaten erfassen oder unverschlüsselten Traffic manipulieren.<sup>[[9]](#references)</sup>

### Rechtmäßiger Gäste-Netzwerk-Workflow

1. Verwende nur ein Netzwerk, das Gästen angeboten wird, oder eines, für das der Eigentümer ausdrücklich die Erlaubnis erteilt hat. Frage das Personal nach der exakten SSID und dem Portalverfahren.
2. Aktualisiere Endpoint und Travel Router vor der Ankunft. Deaktiviere Datei-/Druckerfreigaben, eingehende Erkennung, automatisches Beitreten und die Abfrage gespeicherter Netzwerke.
3. Aktiviere die private/randomisierte Wi-Fi-Adresse des OS. Aktuelle Apple-Systeme können rotierende Adressen in offenen/schwachen Netzwerken verwenden; moderne Android-Randomisierung ist üblicherweise pro SSID dauerhaft. Dies reduziert nur einen lokalen Identifikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Bevorzuge einen von der Organisation kontrollierten Travel Router oder ein Bridge-Gerät mit geringem Vertrauensniveau zwischen privilegierter Workstation und Gäste-Netzwerk. Dies zentralisiert Firewall-/VPN-Richtlinien, verbirgt den Router jedoch nicht vor dem Ort.<sup>[[12]](#references)</sup>
5. Schließe ein Captive Portal nur über das dafür vorgesehene Gerät/den dafür vorgesehenen Browser mit geringem Vertrauensniveau ab. Gib niemals persönliche oder wiederverwendete Zugangsdaten für einen angeblich anonymen Kontext ein. Schließe den Portal-Browser, sobald die Verbindung hergestellt ist.
6. Starte vor sensiblen Aktivitäten ein full-tunnel VPN oder Tor und bestätige das fail-closed-Verhalten.
7. Vergiss das Netzwerk nach der Nutzung und überprüfe die Richtlinien des Portalkontos zur Datenspeicherung.

{% hint style="danger" %}
Das Knacken des Wi-Fi eines Nachbarn, das Umgehen eines Portals, die Verwendung geleakter Gäste-Zugangsdaten, das Klonen des Zugangs eines anderen Gastes oder das Verstecken eines Raspberry Pi in einem Café sind nicht autorisierte Aktivitäten - keine Privacy-Techniken. Sichere Alternativen sind ein rechtmäßiges Gästenetzwerk, ein vom Client genehmigter Standort oder ein dokumentierter Drop Node, der mit der schriftlichen Zustimmung des Eigentümers platziert und wieder entfernt wird.
{% endhint %}

## Travel Router

Ein Travel Router kann eine Workstation von feindlichen lokalen Broadcasts isolieren, eine Firewall erzwingen, eine konsistente interne SSID bereitstellen und ein VPN automatisch wiederverbinden. Er ist **nicht** anonym: Der Upstream sieht seine Funkidentität und den Traffic-Zeitablauf, und der VPN-Anbieter sieht die Tunnelquelle.

- Verwende unterstützte OpenWrt-/Vendor-Firmware und entferne ungenutzte Dienste.
- Verwalte ihn über Ethernet oder eine dedizierte Management-SSID mit einem eindeutigen Passwort.
- Deaktiviere WAN-seitige Administration, UPnP, WPS, Dateifreigaben und unaufgeforderten eingehenden Traffic.
- Verwende eine randomisierte/private WAN-MAC nur, wenn dies unterstützt und erlaubt ist.
- Erzwinge die VPN-Richtlinie auf dem Router, einschließlich DNS und IPv6, und blockiere Egress, wenn der Tunnel ausfällt.
- Gehe nicht davon aus, dass ein Telefon-Hotspot getetherte Geräte durch das VPN des Telefons tunnelt; teste dies.

## Cellular, SIMs und eSIMs

Cellular ist praktisch, aber nicht anonym. Betreiber speichern Teilnehmer-/Gerätekennungen und den aus der Netzwerkanmeldung abgeleiteten Standort; eine eSIM ist weiterhin ein Mobilfunkvertrag. Prepaid bedeutet nicht zuverlässig unregistriert - die Anforderungen unterscheiden sich je nach Land und ändern sich.<sup>[[13]](#references)</sup>

Operativ:

- Verwende ein separates, unterstütztes Gerät, um die Offenlegung persönlicher Daten zu reduzieren, nicht um einen fiktiven Teilnehmer zu erzeugen.
- Trage ein „separates“ Gerät nicht dauerhaft neben einem persönlichen Telefon, wenn sich gemeinsamer Standort im Threat Model befindet.
- Deaktiviere ungenutzte Mobilfunk-, Wi-Fi-, Bluetooth- und Standortzugriffe; das Ausschalten bildet eine stärkere Funkgrenze als UI-Schalter.
- Leite sensiblen Traffic durch den genehmigten VPN-/Tor-Pfad, wobei der Carrier weiterhin den Standort von Vertrag/Gerät sowie den Tunnel-Endpoint kennt.
- Überprüfe aktuelle Registrierungs- und Aufbewahrungsregeln beim nationalen Regulator oder lokalen Rechtsberater; verlasse dich nicht auf Online-Listen „anonymer SIM-Länder“.

## DNS- und TLS-Metadaten

- **DoH/DoT/DoQ** verschlüsseln DNS zwischen Client und Resolver und verhindern einfaches lokales Lesen oder Ändern, aber der Resolver sieht weiterhin Abfragen und Transportkennungen. Sie verlagern Vertrauen, bieten jedoch keine Anonymität.<sup>[[14]](#references)</sup>
- **ODoH** fügt einen Proxy hinzu, sodass der Resolver die Client-IP nicht erfahren muss, sofern Proxy und Ziel nicht kolludieren. Traffic-Analyse ist ausdrücklich außerhalb des Geltungsbereichs.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** kann den inneren Servernamen in einem TLS-Handshake schützen, wenn Client, DNS und Server dies unterstützen. Ziel-IP, Zeitablauf, Volumen und Endpoint bleiben sichtbar.<sup>[[16]](#references)</sup>
- In einer korrekt konfigurierten VPN- oder Tor-Umgebung sollte DNS dem unterstützten Pfad dieser Umgebung folgen. Das Hinzufügen eines separaten Resolvers kann einen neuen Beobachter oder Fingerprint erzeugen.

### Verifizierungs-Workflow für verschlüsseltes DNS/ECH

1. Entscheide, ob DNS durch die VPN-/Tor-Umgebung, das OS oder die Anwendung kontrolliert wird. Konfiguriere es in **einer** vorgesehenen Ebene, statt nicht zusammengehörige Resolver zu stapeln.
2. Wähle einen Resolver anhand seiner veröffentlichten Datenschutz-/Aufbewahrungsrichtlinie und aktiviere den strikten verschlüsselten Modus, sofern die Plattform dies unterstützt. Opportunistischer Fallback kann unbemerkt zu Klartext zurückkehren.
3. Frage eine eindeutige Subdomain unter einer von dir kontrollierten autoritativen Testzone ab; bestätige, dass das autoritative Log den vorgesehenen rekursiven Resolver sieht.
4. Erfasse mit entsprechender Autorisierung ausschließlich den Traffic des Testgeräts. Bestätige, dass das Zugangsnetzwerk kein unverschlüsseltes DNS lesen kann, wobei es den verschlüsselten Resolver-/Tunnel-Endpoint weiterhin sehen kann.
5. Teste einen blockierten/nicht erreichbaren verschlüsselten Resolver. Die Bedingung für Erfolg ist das gewählte fail-closed- oder dokumentierte Fallback-Verhalten - nicht eine versehentliche Klartextabfrage.
6. Verwende für ECH einen kontrollierten ECH-fähigen Host und prüfe Client-/Server-Diagnosen, um zu bestätigen, dass der **innere** ClientHello akzeptiert wurde. Das bloße Anbieten eines HTTPS-Records beweist nicht, dass ECH erfolgreich war.
7. Wiederhole den Test nach Netzwerkänderungen, Captive Portals, Browser-Updates und VPN-Reconnects. Dokumentiere, welche Komponente DNS/ECH kontrolliert, damit spätere Administratoren keinen Bypass erzeugen.

## Mixnets

Mixnets wie Nym oder Katzenpost fügen Pakete fester Größe, Verzögerungen, Umordnung und Cover Traffic hinzu, um Timing-Korrelation zu widerstehen. Diese Eigenschaften kosten Latenz und Bandbreite; unabhängige Nachweise im Maßstab produktiver Deployments sind begrenzt. Behandle aktuelle Consumer-Mixnets als **aufkommende Optionen mit hoher Latenz**, nicht als schnellere oder garantierte Ersatzlösungen für Tor/VPNs.<sup>[[17]](#references)</sup>

### Bewertungs-Workflow

1. Identifiziere einen gepflegten Client und die exakt unterstützte Anwendung; zwinge keinen beliebigen Browser-/System-Traffic durch einen nicht dokumentierten Proxy.
2. Lies das aktuelle Threat Model für Entry, Mix Nodes, Gateway, Ziel und Annahmen zur Kollusion.
3. Installiere aus der offiziellen signierten Quelle in einem separaten Testbereich und verwende ausschließlich einen gutartigen, eigenen Endpoint.
4. Miss Zustelllatenz, Nachrichten-Größenlimits, Zuverlässigkeit, Retransmission und das Verhalten bei Nichtverfügbarkeit des Gateways.
5. Untersuche lokalen Traffic und den eigenen Endpoint, um den vorgesehenen Pfad und die Quelle zu bestätigen. Prüfe, ob Antworten dasselbe Privacy-Design verwenden.
6. Teste das Herunterfahren/Fehlerverhalten: Die Anwendung darf nicht stillschweigend auf direkten Internetzugang zurückfallen.
7. Deaktiviere Cover Traffic nicht, reduziere keine Verzögerungen und wähle keine ungewöhnlichen festen Routen nur zugunsten der Geschwindigkeit; solche Änderungen können das angegebene Anonymity Model ungültig machen.
8. Behandle das System als experimentell, bis das konkrete Deployment, unabhängige Analysen und die operative Zuverlässigkeit dem erforderlichen Konsequenzniveau entsprechen.

## Preflight-Checkliste für Netzwerke

- [ ] Die Autorisierung umfasst Zugangsnetzwerk, Ziel, Zeitraum und Quellinfrastruktur.
- [ ] Der Endpoint enthält keine fremden Identitäten oder aktiven Sync-Sessions.
- [ ] IPv4, IPv6, DNS und Reconnect-Verhalten entsprechen dem Plan.
- [ ] Das Ziel sieht ausschließlich den erwarteten Egress.
- [ ] Captive-Portal- und Hotspot-Verhalten wurden ohne sensiblen Traffic getestet.
- [ ] Lokale Freigaben/Erkennung und automatisches Beitreten zu Netzwerken sind deaktiviert.
- [ ] Die Tabelle der Beobachter und das verbleibende Risiko der Traffic-Korrelation werden akzeptiert.
- [ ] Anbieter-Richtlinie, Aufbewahrung und Notfallkontakt sind aktuell.

Für Split-Knowledge-Relays, route-erzwungene Workloads, Pluggable Transports, Onion Services, I2P und Disposable Remote Browser fahre mit [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) fort.

## References

- [1] [EFF - Auswahl des passenden VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC - Leitfaden zur Gerätesicherheit: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project - Die Datenschutz- und Anonymitätsschutzmaßnahmen von Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications - Eine kurze Einführung in Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project - Tor mit anderen Browsern verwenden](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project - Plugins und Add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project - Tor entsperren](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project - Tor Browser mit einem VPN verwenden](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice - Sind öffentliche Wi-Fi-Netzwerke sicher?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security - Wi-Fi-Datenschutz mit Apple-Geräten](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project - MAC-Randomisierung implementieren](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC - Grundsätze für sichere privilegierte Zugriffsarbeitsstationen](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA - Verpflichtende SIM-Registrierung: politische und regulatorische Perspektiven](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 - Empfehlungen für Betreiber von DNS-Datenschutzdiensten](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 - Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 - TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost - Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
