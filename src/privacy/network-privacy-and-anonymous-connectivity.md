# Netzwerkprivatsphäre und anonyme Konnektivität

{{#include ../banners/hacktricks-training.md}}

Netzwerkprivatsphäre ist eine Routing-Entscheidung, keine vollständige Identität. Wähle einen Pfad, indem du fragst, wer **Quelle**, **Ziel**, **Inhalt** und **Zeitabläufe** nicht miteinander verbinden können soll.

Für das standardisierte Inventar – `Pros`, `Cons`, die schrittweise `Procedure` und `Detection` für jede Familie von Zugriffspfaden – beginne mit dem [Katalog anonymer Internetzugriffstechniken](anonymous-internet-access-techniques.md). Diese Seite erweitert die gängigen einsetzbaren Optionen.

## Was die einzelnen Beobachter normalerweise sehen können

| Pfad | Lokales Netzwerk / ISP | Vermittler | Ziel | Hauptbeschränkung | Relative Geschwindigkeit |
|---|---|---|---|---|---|
| Direktes HTTPS | Quellen-, Zielmetadaten, Zeitabläufe/Volumen | Hosting/CDN sieht die Verbindung | Quell-IP, Browser-/App-Daten | Kein Datenschutz für die Quell-IP | Am schnellsten |
| Kommerzielles VPN | Quelle ist mit dem VPN verbunden; übliche Zielmetadaten nicht sichtbar | VPN sieht Quellen- und Zielmetadaten | VPN-Egress-IP | Ein Anbieter wird zu einem Korrelationspunkt | Normalerweise schnell |
| Selbst gehostetes VPN/VPS | Quelle ist mit dem VPS verbunden | Host-/Konto-/Zahlungs-/Control-Plane-Logs | VPS-Egress-IP | Einfach dem gemieteten Server/Konto zuzuordnen | Normalerweise schnell |
| Tor Browser | Quelle ist mit Tor/Bridge verbunden; Zeitabläufe/Volumen | Jedes Relay sieht nur einen begrenzten Teil | Tor-Exit, Browserdaten | Langsamer; Konto-/Endpoint-/Korrelationsrisiken | Mittel/langsam |
| Tails/Whonix | Ähnlicher Tor-Pfad mit stärkeren Routing-Grenzen | Dieselben Tor-Beschränkungen | Tor-Exit/Anwendungsdaten | Bedienungsfehler sowie Host/Hardware bleiben bestehen | Mittel/langsam |
| Öffentliches Gäste-WLAN + HTTPS | Veranstaltungsort sieht lokales Gerät/Zeitabläufe und Ziele | ISP des Veranstaltungsorts sieht Metadaten | Öffentliche Gäste-IP | Physische-/Captive-Portal-/Gerätekorrelation | Schnell/variabel |
| Mobilfunk-Hotspot | Mobilfunkanbieter sieht Teilnehmer/Gerät/Standort und Ziele | Falls verwendet: VPN/Tor | Mobilfunkanbieter-, VPN- oder Tor-Egress-IP | Mobilfunkvertrag und Standort sind dauerhafte Identifikatoren | Schnell/variabel |
| Mixnet | Zugriff sieht die Mixnet-Nutzung sowie Zeitabläufe/Volumen | Mehrere Mixing-Nodes | Gateway/Egress | Aufkommendes Ökosystem; Kosten durch Latenz und Bandbreite | Am langsamsten |

HTTPS schützt den Inhalt während der Übertragung, aber nicht alle Metadaten. Die EFF weist darauf hin, dass Domain, Zeitpunkt und Traffic-Größe für Vermittler sichtbar bleiben können, selbst wenn Seitenpfade, Zugangsdaten und Nachrichten verschlüsselt sind.<sup>[[1]](#references)</sup>

## VPNs: schnelle Privatsphäre mit konzentriertem Vertrauen

Ein VPN ist nützlich, um Zielmetadaten vor dem Zugangs-ISP zu verbergen, den ersten Hop in einem nicht vertrauenswürdigen Netzwerk zu schützen, eine stabile Engagement-Egress-Adresse bereitzustellen oder ein privates Netzwerk zu erreichen. Es macht einen Benutzer **nicht** anonym. Das VPN sieht die Quellverbindung und kann Zielmetadaten beobachten; Konten, Cookies, GPS, Fingerprints und Zahlungsinformationen bleiben bestehen.<sup>[[1]](#references)</sup>

### Checkliste zur Anbieterbewertung

1. **Eigentum und Gerichtsbarkeit:** Identifiziere die juristische Person, die Muttergesellschaft, die Länder, in denen der Betrieb stattfindet, Infrastruktur-Subunternehmer und die geltenden rechtlichen Verfahren.
2. **Erfasste Daten:** Unterscheide zwischen Konto-/Abrechnungsdaten, Quell-IP, Verbindungszeitpunkten, Bandbreite, Crash-Telemetrie, DNS-Abfragen und Ziellogs. „Keine Browsing-Logs“ bedeutet nicht „keine Daten“.
3. **Aufbewahrung und Löschung:** Ermittle genaue Zeiträume und ob Backups, Betrugssysteme und Datenverarbeiter denselben Zeitplan einhalten.
4. **Nachweise:** Bevorzuge öffentliche Audits mit Umfang, Datum, Ergebnissen und Behebung; reproduzierbare/offene Clients; Transparenzberichte und dokumentierte Vorfälle.
5. **Protokoll und Client:** Gepflegtes WireGuard, OpenVPN oder ein anderes geprüftes Protokoll; automatische Updates; DNS- und IPv6-Verarbeitung; Kill Switch sowie Leak-Tests für jede Plattform.
6. **Geschäftsmodell:** Verstehe, wie ein kostenloser oder subventionierter Dienst finanziert wird. Die Präsenz in einem App-Store allein ist kein Beleg für einen vertrauenswürdigen Betrieb.
7. **Geeignete Zahlungsweise:** Eine alternative Zahlungsweise kann die Abrechnungsdaten, die der VPN-Anbieter erhält, reduzieren, löscht aber nicht die bei jeder Verbindung beobachtete Quell-IP.

### VPN konfigurieren und überprüfen

1. Installiere den signierten Client des Anbieters/der Organisation aus der offiziellen Quelle.
2. Wähle **full tunnel**, sofern eine dokumentierte Route nicht daran vorbeiführen muss. Split tunneling erzeugt Korrelations- und Leak-Pfade.
3. Aktiviere Fail-closed-/Always-on-Verhalten und blockiere Traffic während der erneuten Verbindung.
4. Leite DNS durch den Tunnel und teste sowohl IPv4 als auch IPv6. Deaktiviere ein Protokoll nur, wenn es nicht sicher durch den Tunnel geleitet werden kann und der Funktionsverlust akzeptiert wird.
5. Teste Aufwachen aus dem Ruhezustand, Netzwerkwechsel, Captive-Portal-Anmeldung, Tunnelabsturz und Hotspot-Tethering. Das NCSC warnt, dass getetherte Clients auf manchen Plattformen das VPN eines Telefons umgehen können.<sup>[[2]](#references)</sup>
6. Verwende einen von der Organisation kontrollierten Test-Endpoint, um beobachtete IPv4-, IPv6- und DNS-Resolver-Daten sowie den Verbindungszeitpunkt aufzuzeichnen. Setze kein sensibles Engagement zufälligen „Leak-Test“-Websites aus.
7. Teste nach Änderungen am Client, Betriebssystem, Netzwerk oder an Richtlinien erneut.

### Routing-Bypasses in feindlichen LANs

Ein VPN kann weiterhin sichtbar „verbunden“ sein, während ausgewählte Pakete daran vorbeigeleitet werden, weil das Betriebssystem eine Route **vor** der Verschlüsselung des Pakets durch das VPN auswählt. TunnelCrack demonstrierte zwei Möglichkeiten, gängige Routing-Ausnahmen auszunutzen: **LocalNet** lässt ein Internetziel so erscheinen, als befände es sich im direkt verbundenen Subnetz, während **ServerIP** die Auflösung des VPN-Gateways fälscht, sodass eine Zieladresse die für den VPN-Transport erforderliche Ausnahme des Klartextnetzwerks übernimmt. Dabei handelt es sich um Client-/Routing-Fehler und nicht um Brüche in WireGuard, OpenVPN, IPsec oder TLS; HTTPS-Payloads bleiben Ende-zu-Ende-verschlüsselt, aber der lokale Beobachter kann Ziel-/Zeitablauf-Metadaten und Klartextdaten beliebiger unverschlüsselter Protokolle erfassen.<sup>[[18]](#references)</sup>

TunnelVision verwendet dieselbe Primitive vor der Verschlüsselung über DHCP-Option 121. Ein bösartiger oder kompromittierter DHCP-Server kann eine klassenlose Route installieren, die spezifischer ist als die Catch-all-Route des VPNs, und so für einen beliebigen Host oder Bereich das physische Interface auswählen. Der VPN-Control-Channel kann aktiv bleiben. Daher wird ein Kill Switch, der nur durch die Trennung des Tunnels ausgelöst wird, möglicherweise nicht aktiviert, und eine einzelne öffentliche „IP-Leak“-Prüfung kann selektive Bypasses übersehen.<sup>[[19]](#references)</sup>

Ein Packet-Filter-Kill-Switch, der auf dem physischen Interface nur DHCP und den authentifizierten VPN-Transport zulässt, sollte dies in ein Fail-closed-Verhalten umwandeln. Eine gezielte Routeninjektion kann jedoch weiterhin einen selektiven Side-Channel zur Dienstverweigerung erzeugen. Für Linux-Workloads mit hohen Auswirkungen solltest du das stärkere [route-erzwungene Network-Namespace-Muster](advanced-network-privacy-architectures.md#enforce-the-route-per-workload) bevorzugen, bei dem der Application-Namespace weder ein physisches Interface noch eine Default-Route zum Klartextnetzwerk besitzt.<sup>[[19]](#references)</sup>

#### Überprüfung im eigenen Labor

Teste den exakten Client/das exakte Betriebssystem sowie die Version in Verbindung mit einem eigenen AP, DHCP-Server, VPN-Endpoint und Ziel. Aussagen über ein gesamtes Produkt veralten schnell, da Routing- und Packet-Filter-Implementierungen plattformspezifisch sind. Erfasse den Traffic sowohl direkt am Endpoint als auch auf dem Testserver – eine Website zur Prüfung der Egress-IP allein beweist nicht, dass jedes Ziel dem Tunnel folgt.<sup>[[18]](#references)[[19]](#references)</sup>

1. Verbinde das VPN, notiere die Adresse des VPN-Servers und speichere jede IPv4-/IPv6-Routing-Tabelle sowie jede Policy-Routing-Regel. Verwende unter Windows `route print`, unter macOS `netstat -rn` und unter Linux die unten aufgeführten Befehle.
2. Frage die ausgewählte Route für mehrere eigene Ziel-IPs ab. Der nächste Hop bzw. das Interface muss der Tunnel sein, mit Ausnahme des dokumentierten VPN-Transport-Endpoints.
3. Für TunnelVision erneuere das Lease im kontrollierten DHCP-Netzwerk und installiere eine Option-121-Route **nur für ein eigenes Testziel**. Ein erfolgreicher Test bedeutet, dass der Traffic weiterhin durch den Tunnel geleitet oder blockiert wird – er darf niemals als Zieltraffic über das physische Interface übertragen werden.
4. Für LocalNet weise dem Client ein ausschließlich für das Labor bestimmtes öffentliches Dokumentationssubnetz wie `203.0.113.0/24` zu und platziere das eigene Testziel darin. Überprüfe, dass die Aktivierung des LAN-Zugriffs keine Ziele der Internetklasse am Tunnel vorbeileitet.
5. Für ServerIP lasse vor der VPN-Verbindung kontrolliertes DNS den eigenen VPN-Hostnamen zum eigenen Testziel auflösen, während das Lab-Gateway den VPN-Transport an den tatsächlich eigenen VPN-Endpoint weiterleitet. Der Client darf keinen unabhängigen Application-Traffic zur gefälschten Adresse ausnehmen.
6. Wiederhole den Test mit aktiviertem und deaktiviertem „local network access“, nach erneuter Verbindung, Aufwachen aus dem Ruhezustand, Netzwerkwechsel und einem Absturz des VPN-Prozesses. Teste IPv4, IPv6 und DNS unabhängig voneinander.
7. Überprüfe den Mitschnitt des physischen Interfaces. Er sollte DHCP und verschlüsselte Pakete an den VPN-Server enthalten, jedoch keine direkt an das eigene Testziel adressierten Pakete. Bestätige außerdem, dass ein abgelehnter Bypass nach Benutzerabfragen oder einer Verbindungswiederherstellung nicht unbemerkt als Fallback verwendet werden kann.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: stärkere Web-Unlinkability

Tor baut über mehrere Relays einen Circuit auf, sodass normalerweise kein einzelnes Relay sowohl Quelle als auch Ziel kennt. Das Ziel sieht ein Tor-Exit-Relay statt der IP des Benutzers; das lokale Netzwerk sieht normalerweise eine Tor-Verbindung.<sup>[[3]](#references)</sup> Tor ist für TCP-Anwendungen mit geringer Latenz ausgelegt, ist daher langsamer und kann keinen Schutz gegen einen Angreifer garantieren, der beide Enden korrelieren kann.<sup>[[4]](#references)</sup>

### Sicherer Tor Browser-Workflow

1. Lade Tor Browser nur vom Tor Project oder einem offiziellen Mirror herunter und verifiziere nach Möglichkeit die Signatur.
2. Verwende **Tor Browser**, nicht einen normalen Browser, der auf einen Tor-SOCKS-Port zeigt. Gewöhnliche Browser können DNS/WebRTC und identifizierende Zustände leaken.<sup>[[5]](#references)</sup>
3. Behalte die Standardgröße, Fonts, Extensions und Privacy-Einstellungen bei. Zusätzliche Add-ons können den Browser einzigartiger machen.<sup>[[6]](#references)</sup>
4. Wähle die Sicherheitsstufe **Safer** oder **Safest**, wenn die dadurch verursachten Einschränkungen akzeptabel sind.
5. Verwende eine Bridge, wenn direktes Tor blockiert ist oder gewöhnliche Relay-IPs eine nicht akzeptable lokale Sichtbarkeit erzeugen würden. Bridges erschweren die einfache Erkennung, beseitigen Traffic Analysis jedoch nicht.<sup>[[7]](#references)</sup>
6. Melde dich nicht bei einem identifizierenden Account an, gib keine identifizierenden Informationen an und öffne heruntergeladene aktive Dokumente nicht in einer externen vernetzten Anwendung.
7. Verwende für jede Identität eine separate Session bzw. einen separaten Kontext. „New circuit“ ist nicht dasselbe wie das Löschen der Browser-/Application-Identität; verwende **New Identity** oder starte die isolierte Umgebung gegebenenfalls neu.
8. Bevorzuge authentifiziertes HTTPS oder einen authentifizierten Onion Service. Ein Tor-Exit kann unverschlüsselten HTTP-Traffic beobachten.

### Tor plus VPN

Die Kombination ist nicht automatisch sicherer. Ein VPN vor Tor kann direkte Tor-Relay-Verbindungen vor einem ISP verbergen, während das VPN die Quelle sieht; Tor vor einem VPN gibt dem VPN eine stabile Sicht auf Aktivitäten nach Tor und kann die Anonymity Set verkleinern. Eine Fehlkonfiguration kann Leaks verursachen. Das Tor Project empfiehlt solche Kombinationen nur für fortgeschrittene, ausdrücklich definierte Threat Models.<sup>[[8]](#references)</sup>

## Öffentliches und Gäste-WLAN

Modernes HTTPS bedeutet, dass passive Nachbarn normalerweise ordnungsgemäß verschlüsselte Webinhalte nicht lesen können; Gäste-WLAN bietet jedoch keine Anonymität. Der Betreiber kann Verbindungszeiten, Gerätekennungen, Captive-Portal-Daten, Ziele und DHCP-Details aufzeichnen; Kameras, Einkäufe, Transport und physische Beobachtung können den Benutzer identifizieren. Ein gefälschter, ähnlich benannter Hotspot kann außerdem Portal-Zugangsdaten erfassen oder unverschlüsselten Traffic manipulieren.<sup>[[9]](#references)</sup>

### Rechtmäßiger Gäste-Netzwerk-Workflow

1. Verwende nur ein Netzwerk, das Gästen angeboten wird, oder eines, für das der Eigentümer ausdrücklich die Erlaubnis erteilt hat. Frage das Personal nach der exakten SSID und dem Portal-Verfahren.
2. Aktualisiere den Endpoint und den Travel Router vor der Ankunft. Deaktiviere Datei-/Druckerfreigaben, eingehende Discovery, automatisches Beitreten und das Suchen nach gespeicherten Netzwerken.
3. Aktiviere die private/randomisierte WLAN-Adresse des Betriebssystems. Aktuelle Apple-Systeme können auf offenen/schwachen Netzwerken rotierende Adressen verwenden; die Randomisierung moderner Android-Systeme ist üblicherweise pro SSID persistent. Dies reduziert nur eine lokale Kennung.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Bevorzuge einen von der Organisation kontrollierten Travel Router oder ein Bridge-Gerät mit geringem Trust zwischen einer privilegierten Workstation und dem Gäste-Netzwerk. Dies zentralisiert Firewall-/VPN-Richtlinien, verbirgt den Router jedoch nicht vor dem Betreiber.<sup>[[12]](#references)</sup>
5. Schließe ein Captive Portal nur über das dafür vorgesehene Gerät bzw. den dafür vorgesehenen Browser mit geringem Trust ab. Gib niemals persönliche oder wiederverwendete Zugangsdaten für einen vermeintlich anonymen Kontext ein. Schließe den Portal-Browser, sobald die Verbindung hergestellt ist.
6. Starte vor sensiblen Aktivitäten ein Full-Tunnel-VPN oder Tor und bestätige das Fail-closed-Verhalten.
7. Vergiss das Netzwerk nach der Nutzung und prüfe die Richtlinien des Portal-Accounts zur Datenspeicherung.

{% hint style="danger" %}
Das Knacken des WLANs eines Nachbarn, das Umgehen eines Portals, die Verwendung geleakter Zugangsdaten für Gäste, das Klonen des Zugangs eines anderen Gastes oder das Verstecken eines Raspberry Pi in einem Café sind unbefugte Aktivitäten und keine Privacy-Techniken. Sichere Alternativen sind ein rechtmäßiges Gäste-Netzwerk, eine vom Kunden genehmigte Site oder ein dokumentierter Drop Node, der mit der schriftlichen Zustimmung des Eigentümers platziert und wieder abgeholt wird.
{% endhint %}

## Travel Router

Ein Travel Router kann eine Workstation von feindlichen lokalen Broadcasts isolieren, eine Firewall erzwingen, eine konsistente interne SSID bereitstellen und ein VPN automatisch wiederverbinden. Er ist **nicht** anonym: Der Upstream sieht seine Funkidentität und das Timing des Traffics, und der VPN-Provider sieht die Quelle des Tunnels.

- Verwende unterstützte OpenWrt-/Vendor-Firmware und entferne ungenutzte Services.
- Verwalte das Gerät über Ethernet oder eine dedizierte Management-SSID mit einem einzigartigen Passwort.
- Deaktiviere Administration auf der WAN-Seite, UPnP, WPS, File Sharing und nicht angeforderten eingehenden Traffic.
- Verwende eine randomisierte/private WAN-MAC nur, wenn dies unterstützt und erlaubt ist.
- Erzwinge die VPN-Richtlinie auf dem Router einschließlich DNS und IPv6 und blockiere den Egress, wenn der Tunnel ausfällt.
- Gehe nicht davon aus, dass ein Smartphone-Hotspot verbundene Geräte durch das VPN des Smartphones tunnelt; teste dies.

## Mobilfunk, SIMs und eSIMs

Mobilfunk ist praktisch, aber nicht anonym. Betreiber speichern Teilnehmer-/Gerätekennungen und aus der Netzanmeldung abgeleitete Standortdaten; eine eSIM ist weiterhin ein Mobilfunkvertrag. Prepaid bedeutet nicht zuverlässig unregistriert – die Anforderungen unterscheiden sich je nach Land und ändern sich.<sup>[[13]](#references)</sup>

Operativ:

- Verwende ein separates, unterstütztes Gerät, um die Offenlegung persönlicher Daten zu reduzieren, nicht um einen fiktiven Teilnehmer zu erzeugen.
- Trage ein „separates“ Gerät nicht dauerhaft zusammen mit einem persönlichen Telefon bei dir, wenn die gemeinsame Lokalisierung Teil des Threat Models ist.
- Deaktiviere ungenutzten Mobilfunk, WLAN, Bluetooth und Standortzugriff; das Ausschalten bietet eine stärkere Funkgrenze als UI-Schalter.
- Leite sensiblen Traffic durch den genehmigten VPN-/Tor-Pfad und berücksichtige dabei, dass der Carrier weiterhin das Abonnement, den Gerätestandort und den Tunnel-Endpoint kennt.
- Prüfe aktuelle Registrierungs- und Aufbewahrungsregeln bei der nationalen Regulierungsbehörde oder einem lokalen Rechtsberater; verlasse dich nicht auf Online-Listen „anonymer SIM-Länder“.

## DNS- und TLS-Metadaten

- **DoH/DoT/DoQ** verschlüsseln DNS zwischen Client und Resolver und verhindern dadurch einfaches lokales Lesen oder Manipulieren, aber der Resolver sieht weiterhin die Queries und Transportkennungen. Sie verlagern Trust, bieten jedoch keine Anonymität.<sup>[[14]](#references)</sup>
- **ODoH** fügt einen Proxy hinzu, sodass der Resolver die Client-IP nicht kennen muss, sofern Proxy und Ziel nicht kolludieren. Traffic Analysis liegt ausdrücklich außerhalb des Geltungsbereichs.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** kann den inneren Servernamen in einem TLS-Handshake schützen, wenn Client, DNS und Server dies unterstützen. Ziel-IP, Timing, Volumen und der Endpoint bleiben sichtbar.<sup>[[16]](#references)</sup>
- In einer korrekt konfigurierten VPN- oder Tor-Umgebung sollte DNS dem unterstützten Pfad dieser Umgebung folgen. Das Hinzufügen eines separaten Resolvers kann einen neuen Beobachter oder Fingerprint erzeugen.

### Verifizierungs-Workflow für verschlüsseltes DNS/ECH

1. Entscheide, ob DNS von der VPN-/Tor-Umgebung, dem Betriebssystem oder der Anwendung kontrolliert wird. Konfiguriere es in **einer** vorgesehenen Schicht, anstatt nicht zusammengehörige Resolver zu stapeln.
2. Wähle einen Resolver anhand seiner veröffentlichten Privacy-/Retention-Richtlinie und aktiviere den strikt verschlüsselten Modus, sofern die Plattform ihn unterstützt. Opportunistisches Fallback kann unbemerkt zu Klartext zurückkehren.
3. Frage eine einzigartige Subdomain unter einer autoritativen Testzone ab, die du kontrollierst; bestätige, dass das autoritative Log den vorgesehenen rekursiven Resolver sieht.
4. Erfasse nur mit Autorisierung den Traffic des Testgeräts. Bestätige, dass das Zugangsnetzwerk Klartext-DNS nicht lesen kann, und berücksichtige, dass es den verschlüsselten Resolver-/Tunnel-Endpoint sehen kann.
5. Teste einen blockierten/nicht erreichbaren verschlüsselten Resolver. Die erfolgreiche Bedingung ist das ausgewählte Fail-closed- oder dokumentierte Fallback-Verhalten – nicht eine versehentliche Klartext-Query.
6. Verwende für ECH einen kontrollierten ECH-fähigen Host und prüfe Client-/Server-Diagnosedaten, um zu bestätigen, dass der **innere** ClientHello akzeptiert wurde. Das bloße Anbieten eines HTTPS-Records beweist nicht, dass ECH erfolgreich war.
7. Wiederhole den Test nach Netzwerkänderungen, Captive Portals, Browser-Updates und VPN-Reconnects. Dokumentiere, welche Komponente DNS/ECH kontrolliert, damit spätere Administratoren keinen Bypass erzeugen.

## Mixnets

Mixnets wie Nym oder Katzenpost fügen Pakete fester Größe, Verzögerung, Umordnung und Cover Traffic hinzu, um Timing-Korrelation zu erschweren. Diese Eigenschaften kosten Latenz und Bandbreite, und unabhängige Nachweise im Einsatzmaßstab sind begrenzt. Betrachte aktuelle Consumer-Mixnets als **aufkommende Optionen mit hoher Latenz**, nicht als schnellere oder garantierte Ersatzlösungen für Tor/VPNs.<sup>[[17]](#references)</sup>

### Evaluierungs-Workflow

1. Identifiziere einen gepflegten Client und die exakt unterstützte Anwendung; zwinge keinen beliebigen Browser-/System-Traffic durch einen nicht dokumentierten Proxy.
2. Lies das aktuelle Threat Model für Entry, Mix Nodes, Gateway, Ziel und Annahmen zur Kollusion.
3. Installiere aus der offiziellen signierten Quelle in einem separaten Testbereich und verwende ausschließlich einen harmlosen, eigenen Endpoint.
4. Miss Zustelllatenz, Nachrichtengrößenlimits, Zuverlässigkeit, Retransmission und das Verhalten bei nicht verfügbarem Gateway.
5. Prüfe den lokalen Traffic und den eigenen Endpoint, um den vorgesehenen Pfad und die Quelle zu bestätigen. Prüfe, ob Antworten dasselbe Privacy-Design verwenden.
6. Teste das Herunterfahren bzw. den Ausfall: Die Anwendung darf nicht unbemerkt auf direkten Internetzugriff zurückfallen.
7. Deaktiviere Cover Traffic nicht, reduziere Verzögerungen nicht und wähle nicht allein wegen der Geschwindigkeit ungewöhnliche feste Routen; solche Änderungen können das angegebene Anonymity Model ungültig machen.
8. Behandle das System als experimentell, bis der konkrete Einsatz, unabhängige Analysen und die operative Zuverlässigkeit dem erforderlichen Konsequenzniveau entsprechen.

## Netzwerk-Preflight-Checkliste

- [ ] Die Autorisierung umfasst das Zugangsnetzwerk, das Ziel, die Zeiträume und die Quellinfrastruktur.
- [ ] Der Endpoint enthält keine nicht zugehörigen Identitäten oder aktiven Sync-Sessions.
- [ ] IPv4, IPv6, DNS und das Reconnect-Verhalten entsprechen dem Plan.
- [ ] Kontrollierte DHCP-/lokale Subnetz-Routeninjektion kann Test-Traffic nicht auf das physische Interface verschieben.
- [ ] Das Ziel sieht ausschließlich den erwarteten Egress.
- [ ] Verhalten von Captive Portal und Hotspot wurde ohne sensiblen Traffic getestet.
- [ ] Lokales Sharing/Discovery und automatisches Beitreten zu Netzwerken sind deaktiviert.
- [ ] Die Tabelle der Beobachter und das verbleibende Risiko der Traffic-Korrelation sind akzeptiert.
- [ ] Provider-Richtlinie, Aufbewahrung und Notfallkontakt sind aktuell.

Für Relays mit geteiltem Wissen, route-erzwungene Workloads, Pluggable Transports, Onion Services, I2P und kurzlebige Remote-Browser fahre mit [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) fort.



## References

- [1] [EFF — Das passende VPN auswählen](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Leitfaden zur Gerätesicherheit: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Die Privacy- und Anonymity-Schutzmaßnahmen von Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Eine kurze Einführung in Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor mit anderen Browsern verwenden](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins und Add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor entsperren](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Tor Browser mit einem VPN verwenden](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Sind öffentliche WLAN-Netzwerke sicher?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — WLAN-Privacy mit Apple-Geräten](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC-Randomisierung implementieren](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Prinzipien für sichere privilegierte Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Verbindliche SIM-Registrierung: politische und regulatorische Perspektiven](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Empfehlungen für Betreiber von DNS-Privacy-Services](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Tunnels umgehen: VPN-Client-Traffic durch den Missbrauch von Routing-Tabellen leaken](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Wie Angreifer routingbasierte VPNs für einen vollständigen VPN-Leak enttarnen können](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
