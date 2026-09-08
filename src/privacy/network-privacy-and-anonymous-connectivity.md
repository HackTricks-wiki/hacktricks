# Netzwerkdatenschutz und anonyme Konnektivität

Netzwerkdatenschutz ist eine Routing-Entscheidung, keine vollständige Identität. Wähle einen Pfad, indem du fragst, wer **Quelle**, **Ziel**, **Inhalt** und **Zeitabläufe** nicht miteinander verbinden können soll.

Für das normalisierte Inventar - `Pros`, `Cons`, die schrittweise `Procedure` und `Detection` für jede Familie von Zugriffspfaden - beginne mit dem [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Diese Seite erweitert die gängigen einsetzbaren Optionen.

## Was die einzelnen Beobachter normalerweise sehen können

| Pfad | Lokales Netzwerk / ISP | Vermittler | Ziel | Hauptbeschränkung | Relative Geschwindigkeit |
|---|---|---|---|---|---|
| Direkte HTTPS-Verbindung | Quell- und Zielmetadaten, Zeitabläufe/Volumen | Hosting/CDN sieht die Verbindung | Quell-IP, Browser-/App-Daten | Kein Schutz der Quell-IP | Am schnellsten |
| Kommerzielles VPN | Quelle ist mit dem VPN verbunden; üblicherweise keine Zielmetadaten | VPN sieht Quell- und Zielmetadaten | VPN-Egress-IP | Ein Anbieter wird zum Korrelationspunkt | Meist schnell |
| Selbst gehostetes VPN/VPS | Quelle ist mit dem VPS verbunden | Host-/Konto-/Zahlungs-/Control-Plane-Logs | VPS-Egress-IP | Einfache Zuordnung zum gemieteten Server/Konto | Meist schnell |
| Tor Browser | Quelle ist mit Tor/Bridge verbunden; Zeitabläufe/Volumen | Relays sehen jeweils nur einen begrenzten Teil | Tor-Exit, Browserdaten | Langsamer; Konto-/Endpoint-/Korrelationsrisiken | Mittel/langsam |
| Tails/Whonix | Ähnlicher Tor-Pfad mit stärkeren Routing-Grenzen | Dieselben Tor-Beschränkungen | Tor-Exit/Anwendungsdaten | Bedienfehler sowie Host/Hardware bleiben | Mittel/langsam |
| Öffentliches Gäste-Wi-Fi + HTTPS | Standort sieht lokales Gerät/Zeitabläufe und Ziele | ISP des Standorts sieht Metadaten | Öffentliche Gäste-IP | Physische-/Captive-Portal-/Gerätekorrelation | Schnell/variabel |
| Mobilfunk-Hotspot | Anbieter sieht Teilnehmer, Gerät, Standort und Ziele | VPN/Tor, falls verwendet | Anbieter-, VPN- oder Tor-Egress-IP | Mobilfunkvertrag und Standort sind dauerhafte Identifikatoren | Schnell/variabel |
| Mixnet | Zugang sieht die Mixnet-Nutzung sowie Zeitabläufe/Volumen | Mehrere Mixing-Nodes | Gateway/Egress | Neues Ökosystem; Kosten bei Latenz und Bandbreite | Am langsamsten |

HTTPS schützt den Inhalt während der Übertragung, aber nicht alle Metadaten. Die EFF weist darauf hin, dass Domain, Zeitpunkt und Traffic-Größe für Vermittler sichtbar bleiben können, selbst wenn Seitenpfade, Zugangsdaten und Nachrichten verschlüsselt sind.<sup>[[1]](#references)</sup>

## VPNs: schneller Datenschutz mit konzentriertem Vertrauen

Ein VPN ist nützlich, um Zielmetadaten vor dem Zugangs-ISP zu verbergen, den ersten Hop in einem nicht vertrauenswürdigen Netzwerk zu schützen, eine stabile Engagement-Egress-Adresse bereitzustellen oder ein privates Netzwerk zu erreichen. Es macht den Benutzer **nicht** anonym. Das VPN sieht die Quellverbindung und kann Zielmetadaten beobachten; Konten, Cookies, GPS, Fingerprints und Zahlungsinformationen bleiben bestehen.<sup>[[1]](#references)</sup>

### Checkliste zur Anbieterbewertung

1. **Eigentum und Zuständigkeit:** Identifiziere die juristische Person, die Muttergesellschaft, die Betriebsländer, Infrastruktur-Subunternehmer und anwendbare rechtliche Verfahren.
2. **Erfasste Daten:** Unterscheide zwischen Konto-/Abrechnungsdaten, Quell-IP, Verbindungszeitstempeln, Bandbreite, Crash-Telemetrie, DNS-Abfragen und Ziellogs. „Keine Browsing-Logs“ bedeutet nicht „keine Daten“.
3. **Aufbewahrung und Löschung:** Ermittle genaue Zeiträume und ob Backups, Betrugssysteme und Auftragsverarbeiter denselben Zeitplan einhalten.
4. **Nachweise:** Bevorzuge öffentliche Audits mit Umfang, Datum, Ergebnissen und Behebung; reproduzierbare/offene Clients; Transparenzberichte und dokumentierte Vorfälle.
5. **Protokoll und Client:** Gepflegtes WireGuard, OpenVPN oder ein anderes geprüftes Protokoll; automatische Updates; DNS- und IPv6-Verarbeitung; Kill Switch und Leak-Tests für jede Plattform.
6. **Geschäftsmodell:** Verstehe, wie ein kostenloser oder subventionierter Dienst finanziert wird. Die Präsenz in einem App-Store allein ist kein Nachweis für vertrauenswürdigen Betrieb.
7. **Zahlung:** Eine alternative Zahlungsmethode kann die Abrechnungsdaten gegenüber dem VPN reduzieren, löscht aber nicht die bei jeder Verbindung beobachtete Quell-IP.

### VPN konfigurieren und überprüfen

1. Installiere den signierten Client des Anbieters/der Organisation aus der offiziellen Quelle.
2. Wähle **Full Tunnel**, sofern eine dokumentierte Route nicht daran vorbeiführen muss. Split Tunneling erzeugt Korrelations- und Leak-Pfade.
3. Aktiviere Fail-Closed-/Always-On-Verhalten und blockiere Traffic während der Wiederherstellung der Verbindung.
4. Leite DNS durch den Tunnel und teste sowohl IPv4 als auch IPv6. Deaktiviere ein Protokoll nur, wenn es nicht sicher getunnelt werden kann und der Funktionsverlust akzeptiert wird.
5. Teste Ruhezustand/Wakeup, Netzwerkwechsel, Captive-Portal-Login, Tunnelabsturz und Hotspot-Tethering. Das NCSC warnt, dass getetherte Clients auf einigen Plattformen das VPN eines Telefons umgehen können.<sup>[[2]](#references)</sup>
6. Verwende einen von der Organisation kontrollierten Test-Endpoint, um beobachtete IPv4-, IPv6- und DNS-Resolver-Daten sowie Verbindungszeitpunkte zu protokollieren. Setze kein sensibles Engagement zufälligen „Leak-Test“-Websites aus.
7. Wiederhole den Test nach Änderungen an Client, Betriebssystem, Netzwerk oder Richtlinien.

## Tor Browser: stärkeres Unlinkability im Web

Tor erstellt eine Verbindung über mehrere Relays, sodass normalerweise kein einzelnes Relay sowohl Quelle als auch Ziel kennt. Das Ziel sieht einen Tor-Exit statt der IP des Benutzers; das lokale Netzwerk sieht normalerweise eine Tor-Verbindung.<sup>[[3]](#references)</sup> Tor ist für TCP-Anwendungen mit niedriger Latenz ausgelegt, daher ist es langsamer und kann keinen Schutz gegen einen Angreifer garantieren, der beide Enden korrelieren kann.<sup>[[4]](#references)</sup>

### Sicherer Tor-Browser-Workflow

1. Lade den Tor Browser nur vom Tor Project oder einem offiziellen Mirror herunter und überprüfe möglichst die Signatur.
2. Verwende den **Tor Browser**, nicht einen normalen Browser, der auf einen Tor-SOCKS-Port zeigt. Gewöhnliche Browser können DNS/WebRTC und identifizierende Zustände leaken.<sup>[[5]](#references)</sup>
3. Behalte die Standardgröße, Schriftarten, Extensions und Datenschutzeinstellungen bei. Zusätzliche Add-ons können den Browser einzigartiger machen.<sup>[[6]](#references)</sup>
4. Wähle die Sicherheitsstufe **Safer** oder **Safest**, wenn die dadurch entstehenden Einschränkungen akzeptabel sind.
5. Verwende eine Bridge, wenn direktes Tor blockiert ist oder gewöhnliche Relay-IPs eine unakzeptable lokale Sichtbarkeit erzeugen würden. Bridges erschweren die einfache Erkennung, beseitigen aber keine Traffic-Analyse.<sup>[[7]](#references)</sup>
6. Melde dich nicht bei einem identifizierenden Konto an, gib keine identifizierenden Informationen an und öffne heruntergeladene aktive Dokumente nicht in einer extern vernetzten Anwendung.
7. Verwende für jede Identität eine separate Sitzung/einen separaten Kontext. „New circuit“ ist nicht dasselbe wie das Löschen der Browser-/Anwendungsidentität; verwende **New Identity** oder starte die isolierte Umgebung je nach Bedarf neu.
8. Bevorzuge authentifiziertes HTTPS oder einen authentifizierten Onion Service. Ein Tor-Exit kann unverschlüsselten HTTP-Traffic beobachten.

### Tor plus VPN

Die Kombination ist nicht automatisch sicherer. Ein VPN vor Tor kann direkte Tor-Relay-Verbindungen vor einem ISP verbergen, während das VPN die Quelle sieht; Tor vor einem VPN gibt dem VPN eine stabile Sicht auf die Aktivitäten nach Tor und kann die Anonymity Set verkleinern. Fehlkonfigurationen können Leaks verursachen. Das Tor Project empfiehlt solche Kombinationen nur für fortgeschrittene, ausdrücklich definierte Threat Models.<sup>[[8]](#references)</sup>

## Öffentliches und Gäste-Wi-Fi

Modernes HTTPS bedeutet, dass passive Nachbarn ordnungsgemäß verschlüsselten Webinhalt normalerweise nicht lesen können; Gäste-Wi-Fi ist jedoch keine Anonymität. Der Standort kann Verbindungszeiten, Gerätekennungen, Captive-Portal-Daten, Ziele und DHCP-Details protokollieren; Kameras, Einkäufe, Transportmittel und physische Beobachtung können den Benutzer identifizieren. Ein gefälschter Hotspot mit ähnlichem Namen kann außerdem Portalzugangsdaten erfassen oder unverschlüsselten Traffic manipulieren.<sup>[[9]](#references)</sup>

### Rechtmäßiger Workflow für Gastnetzwerke

1. Verwende nur ein Netzwerk, das Gästen angeboten wird, oder eines, für das der Eigentümer ausdrücklich die Erlaubnis erteilt hat. Frage das Personal nach der exakten SSID und dem Portalverfahren.
2. Aktualisiere Endpoint und Reise-Router vor der Ankunft. Deaktiviere Datei-/Druckerfreigaben, eingehende Erkennung, automatisches Beitreten und die Suche nach gespeicherten Netzwerken.
3. Aktiviere die private/randomisierte Wi-Fi-Adresse des Betriebssystems. Aktuelle Apple-Systeme können rotierende Adressen in offenen/schwachen Netzwerken verwenden; moderne Android-Randomisierung ist üblicherweise pro SSID dauerhaft. Dies reduziert nur einen lokalen Identifikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Bevorzuge einen von der Organisation kontrollierten Reise-Router oder ein Bridge-Gerät mit geringem Vertrauen zwischen privilegierter Workstation und Gastnetzwerk. Dies zentralisiert Firewall-/VPN-Richtlinien, verbirgt den Router jedoch nicht vor dem Standort.<sup>[[12]](#references)</sup>
5. Schließe ein Captive Portal nur über das vorgesehen Gerät/den vorgesehenen Browser mit geringem Vertrauen ab. Gib für einen vermeintlich anonymen Kontext niemals persönliche oder wiederverwendete Zugangsdaten ein. Schließe den Portal-Browser nach hergestellter Verbindung.
6. Starte vor sensiblen Aktivitäten ein Full-Tunnel-VPN oder Tor und bestätige das Fail-Closed-Verhalten.
7. Vergiss das Netzwerk nach der Nutzung und prüfe die Richtlinie des Portalkontos zur Datenspeicherung.

{% hint style="danger" %}
Das Knacken des Wi-Fi eines Nachbarn, das Umgehen eines Portals, die Verwendung geleakter Gastzugangsdaten, das Klonen des Zugangs eines anderen Gastes oder das Verstecken eines Raspberry Pi in einem Café sind nicht autorisierte Aktivitäten - keine Datenschutztechnik. Sichere Alternativen sind ein rechtmäßiges Gastnetzwerk, ein vom Kunden genehmigter Standort oder ein dokumentierter Drop Node, der mit der schriftlichen Zustimmung des Eigentümers platziert und geborgen wird.
{% endhint %}

## Reise-Router

Ein Reise-Router kann eine Workstation von feindlichen lokalen Broadcasts isolieren, eine Firewall erzwingen, eine konsistente interne SSID bereitstellen und ein VPN automatisch wiederherstellen. Er ist **nicht** anonym: Der Upstream sieht seine Funkidentität und die Traffic-Zeitabläufe, und der VPN-Anbieter sieht die Tunnelquelle.

- Verwende unterstützte OpenWrt-/Hersteller-Firmware und entferne nicht benötigte Dienste.
- Verwalte den Router über Ethernet oder eine dedizierte Management-SSID mit einem einzigartigen Passwort.
- Deaktiviere WAN-seitige Administration, UPnP, WPS, Dateifreigaben und unaufgeforderten eingehenden Traffic.
- Verwende eine randomisierte/private WAN-MAC nur, wenn dies unterstützt und erlaubt ist.
- Erzwinge VPN-Richtlinien auf dem Router, einschließlich DNS und IPv6, und blockiere den Egress bei einem Tunnelausfall.
- Gehe nicht davon aus, dass ein Telefon-Hotspot getetherte Geräte durch das VPN des Telefons tunnelt; teste dies.

## Mobilfunk, SIMs und eSIMs

Mobilfunk ist praktisch, aber nicht anonym. Anbieter verwalten Teilnehmer-/Gerätekennungen und aus der Netzwerkanmeldung abgeleitete Standortdaten; eine eSIM ist weiterhin ein Mobilfunkvertrag. Prepaid bedeutet nicht zuverlässig unregistriert - die Anforderungen unterscheiden sich je nach Land und ändern sich.<sup>[[13]](#references)</sup>

Operativ:

- Verwende ein separates, unterstütztes Gerät, um die Offenlegung persönlicher Daten zu reduzieren, nicht um einen fiktiven Teilnehmer zu erzeugen.
- Trage ein „separates“ Gerät nicht ständig neben einem persönlichen Telefon, wenn der gemeinsame Standort Teil des Threat Models ist.
- Deaktiviere nicht benötigten Mobilfunk, Wi-Fi, Bluetooth und Standortzugriff; das Ausschalten bildet eine stärkere Funkgrenze als UI-Schalter.
- Leite sensiblen Traffic durch den genehmigten VPN-/Tor-Pfad und berücksichtige, dass der Anbieter weiterhin den Standort von Vertrag/Gerät sowie den Tunnel-Endpoint kennt.
- Überprüfe aktuelle Registrierungs- und Aufbewahrungsregeln bei der nationalen Regulierungsbehörde oder lokalem Rechtsbeistand; verlasse dich nicht auf Online-Listen „anonymer SIM-Länder“.

## DNS- und TLS-Metadaten

- **DoH/DoT/DoQ** verschlüsseln DNS zwischen Client und Resolver und verhindern einfaches lokales Lesen oder Ändern, der Resolver sieht jedoch weiterhin Abfragen und Transportidentifikatoren. Sie verlagern Vertrauen, bieten aber keine Anonymität.<sup>[[14]](#references)</sup>
- **ODoH** fügt einen Proxy hinzu, sodass der Resolver die Client-IP nicht kennen muss, sofern Proxy und Ziel nicht kolludieren. Traffic-Analyse ist ausdrücklich außerhalb des Umfangs.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** kann den inneren Servernamen in einem TLS-Handshake schützen, wenn Client, DNS und Server dies unterstützen. Ziel-IP, Zeitabläufe, Volumen und Endpoint bleiben sichtbar.<sup>[[16]](#references)</sup>
- In einer korrekt konfigurierten VPN- oder Tor-Umgebung sollte DNS dem unterstützten Pfad dieser Umgebung folgen. Ein zusätzlicher Resolver kann einen neuen Beobachter oder Fingerprint erzeugen.

### Verifizierungs-Workflow für verschlüsseltes DNS/ECH

1. Entscheide, ob DNS von der VPN-/Tor-Umgebung, dem Betriebssystem oder der Anwendung kontrolliert wird. Konfiguriere es in **einer** vorgesehenen Schicht, statt unabhängige Resolver zu stapeln.
2. Wähle anhand der veröffentlichten Datenschutz-/Aufbewahrungsrichtlinie einen Resolver und aktiviere den strikt verschlüsselten Modus, sofern die Plattform dies unterstützt. Opportunistischer Fallback kann still zu Klartext zurückkehren.
3. Frage eine eindeutige Subdomain unter einer von dir kontrollierten autoritativen Testzone ab; bestätige, dass der autoritative Log den vorgesehenen rekursiven Resolver sieht.
4. Erfasse nur mit Autorisierung den Traffic des Testgeräts. Bestätige, dass das Zugangsnetzwerk kein unverschlüsseltes DNS lesen kann, und berücksichtige, dass es den verschlüsselten Resolver-/Tunnel-Endpoint sehen kann.
5. Teste einen blockierten/nicht erreichbaren verschlüsselten Resolver. Die Bedingung für Erfolg ist das gewählte Fail-Closed- oder dokumentierte Fallback-Verhalten - nicht eine versehentliche Klartextabfrage.
6. Verwende für ECH einen kontrollierten ECH-fähigen Host und prüfe Client-/Server-Diagnosen, um zu bestätigen, dass das **innere** ClientHello akzeptiert wurde. Das bloße Anbieten eines HTTPS-Records beweist keinen erfolgreichen ECH-Einsatz.
7. Wiederhole den Test nach Netzwerkänderungen, Captive Portals, Browser-Updates und VPN-Reconnects. Dokumentiere, welche Komponente DNS/ECH kontrolliert, damit spätere Administratoren keinen Bypass erzeugen.

## Mixnets

Mixnets wie Nym oder Katzenpost fügen Pakete fester Größe, Verzögerung, Umordnung und Cover Traffic hinzu, um Timing-Korrelation zu erschweren. Diese Eigenschaften kosten Latenz und Bandbreite, und unabhängige Nachweise im Einsatzmaßstab sind begrenzt. Betrachte aktuelle Consumer-Mixnets als **neue Optionen mit hoher Latenz**, nicht als schnellere oder garantierte Ersatzlösungen für Tor/VPNs.<sup>[[17]](#references)</sup>

### Bewertungs-Workflow

1. Identifiziere einen gepflegten Client und die exakt unterstützte Anwendung; leite keinen beliebigen Browser-/System-Traffic durch einen undokumentierten Proxy.
2. Lies das aktuelle Threat Model für Entry, Mix Nodes, Gateway, Ziel sowie Annahmen zu Kollusion.
3. Installiere aus der offiziellen signierten Quelle in einem separaten Testbereich und verwende nur einen harmlosen, eigenen Endpoint.
4. Miss Zustelllatenz, Größenlimits für Nachrichten, Zuverlässigkeit, Retransmission und das Verhalten bei nicht verfügbarem Gateway.
5. Untersuche lokalen Traffic und den eigenen Endpoint, um den vorgesehenen Pfad und die Quelle zu bestätigen. Prüfe, ob Antworten dasselbe Datenschutzdesign verwenden.
6. Teste Abschaltung/Fehler: Die Anwendung darf nicht still auf direkten Internetzugang zurückfallen.
7. Deaktiviere Cover Traffic nicht, reduziere Verzögerungen nicht und wähle nicht allein wegen der Geschwindigkeit ungewöhnliche feste Routen; solche Änderungen können das angegebene Anonymitätsmodell ungültig machen.
8. Behalte die Lösung im experimentellen Status, bis die konkrete Bereitstellung, unabhängige Analyse und betriebliche Zuverlässigkeit dem erforderlichen Konsequenzniveau entsprechen.

## Checkliste vor der Netzwerkverbindung

- [ ] Die Autorisierung umfasst Zugangsnetzwerk, Ziel, Zeiträume und Quellinfrastruktur.
- [ ] Der Endpoint enthält keine unabhängigen Identitäten oder aktiven Sync-Sitzungen.
- [ ] IPv4-, IPv6-, DNS- und Reconnect-Verhalten entsprechen dem Plan.
- [ ] Das Ziel sieht nur den erwarteten Egress.
- [ ] Captive-Portal- und Hotspot-Verhalten wurden ohne sensiblen Traffic getestet.
- [ ] Lokale Freigaben/Erkennung und automatisches Beitreten zu Netzwerken sind deaktiviert.
- [ ] Die Beobachtertabelle und das verbleibende Risiko einer Traffic-Korrelation sind akzeptiert.
- [ ] Anbieterrichtlinie, Aufbewahrung und Notfallkontakt sind aktuell.

Für Relays mit geteiltem Wissen, routen-erzwungene Workloads, Pluggable Transports, Onion Services, I2P und kurzlebige Remote-Browser fahre mit [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) fort.

## References

- [1] [EFF - Das richtige VPN für dich auswählen](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC - Leitfaden zur Gerätesicherheit: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project - Datenschutz- und Anonymitätsschutz durch Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications - Eine kurze Einführung in Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project - Tor mit anderen Browsern verwenden](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project - Plugins und Add-ons im Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project - Tor entsperren](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project - Tor Browser mit einem VPN verwenden](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice - Sind öffentliche Wi-Fi-Netzwerke sicher?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security - Wi-Fi-Datenschutz mit Apple-Geräten](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project - MAC-Randomisierung implementieren](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC - Prinzipien für sichere privilegierte Access-Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA - Verpflichtende SIM-Registrierung: politische und regulatorische Perspektiven](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 - Empfehlungen für Betreiber von DNS-Datenschutzdiensten](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 - Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 - TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost - Threat Model](https://katzenpost.network/docs/threat_model/)
