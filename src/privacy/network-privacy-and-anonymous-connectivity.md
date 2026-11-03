# Netzwerkdatenschutz & anonyme Konnektivität

{{#include ../banners/hacktricks-training.md}}

Netzwerkdatenschutz ist eine Routing-Entscheidung, keine vollständige Identität. Wähle einen Pfad danach aus, wer **Quelle**, **Ziel**, **Inhalt** und **Zeitpunkt** nicht miteinander verknüpfen können soll.

Für das normalisierte Inventar – `Pros`, `Cons`, schrittweise `Procedure` und `Detection` für jede Zugangswegfamilie – beginne mit dem [Katalog für anonymen Internetzugang](anonymous-internet-access-techniques.md). Diese Seite erweitert die gängigen, einsetzbaren Optionen.

## Was die einzelnen Beobachter normalerweise sehen können

| Pfad | Lokales Netzwerk / ISP | Zwischenstelle | Ziel | Wichtigste Einschränkung | Relative Geschwindigkeit |
|---|---|---|---|---|---|
| Direktes HTTPS | Quelle, Zielmetadaten, Zeitpunkt/Volumen | Hosting/CDN sieht die Verbindung | Quell-IP, Browser-/App-Daten | Kein Datenschutz für die Quell-IP | Am schnellsten |
| Kommerzielles VPN | Quelle ist mit dem VPN verbunden; normalerweise keine Zielmetadaten | VPN sieht Quelle und Zielmetadaten | VPN-Egress-IP | Ein Anbieter wird zum Korrelationspunkt | Normalerweise schnell |
| Selbst gehostetes VPN/VPS | Quelle ist mit dem VPS verbunden | Host-/Konto-/Zahlungs-/Control-Plane-Protokolle | VPS-Egress-IP | Dem gemieteten Server/Konto leicht zuzuordnen | Normalerweise schnell |
| Tor Browser | Quelle ist mit Tor/Bridge verbunden; Zeitpunkt/Volumen | Jeder Relay sieht nur einen begrenzten Teil | Tor-Exit, Browserdaten | Langsamer; Risiken durch Konten/Endpunkte/Korrelation | Mittel/langsam |
| Tails/Whonix | Ähnlicher Tor-Pfad mit stärkeren Routing-Grenzen | Dieselben Tor-Einschränkungen | Tor-Exit/Anwendungsdaten | Bedienungsfehler sowie Host/Hardware bleiben relevant | Mittel/langsam |
| Öffentliches Gäste-Wi-Fi + HTTPS | Veranstaltungsort sieht lokales Gerät/Zeitpunkt und Ziele | ISP des Veranstaltungsorts sieht Metadaten | Öffentliche Gast-IP | Korrelation über physischen Standort/Captive Portal/Gerät | Schnell/variabel |
| Mobilfunk-Hotspot | Mobilfunkanbieter sieht Teilnehmer/Gerät/Standort und Ziele | VPN/Tor, falls verwendet | Egress-IP des Mobilfunkanbieters, VPNs oder Tors | Mobilfunkvertrag und Standort sind dauerhafte Kennungen | Schnell/variabel |
| Mixnet | Zugang sieht die Nutzung des Mixnets; Zeitpunkt/Volumen | Mehrere Mixing-Knoten | Gateway/Egress | Aufkommendes Ökosystem; Kosten durch Latenz und Bandbreite | Am langsamsten |

HTTPS schützt den Inhalt während der Übertragung, aber nicht alle Metadaten. EFF weist darauf hin, dass Domain, Zeitpunkt und Traffic-Größe für Zwischenstellen sichtbar bleiben können, selbst wenn Seitenpfade, Zugangsdaten und Nachrichten verschlüsselt sind.<sup>[[1]](#references)</sup>

Ein verschlüsseltes Overlay ist nicht automatisch ein Anonymitätsnetzwerk: Direkte Yggdrasil-Peers können die IP-Adressen des jeweils anderen sehen.<sup>[[20]](#references)</sup> Die [Weiterleitung im Userspace und der SOCKS-Transport](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) sind eine Tunneling-Option, keine Ebene zur Anonymisierung der Quelle.<sup>[[20]](#references)[[21]](#references)</sup>

## VPNs: schneller Datenschutz mit konzentriertem Vertrauen

Ein VPN ist nützlich, um Zielmetadaten vor dem Zugangs-ISP zu verbergen, den ersten Hop in einem nicht vertrauenswürdigen Netzwerk zu schützen, eine stabile Egress-Adresse für einen Auftrag bereitzustellen oder ein privates Netzwerk zu erreichen. Es macht einen Benutzer **nicht** anonym. Das VPN sieht die Quellverbindung und kann Zielmetadaten beobachten; Konten, Cookies, GPS, Fingerprints und Zahlungsinformationen bleiben bestehen.<sup>[[1]](#references)</sup>

### Checkliste zur Anbieterbewertung

1. **Eigentümer und Gerichtsbarkeit:** Ermittle die juristische Person, die Muttergesellschaft, die Betriebsländer, Infrastruktur-Subunternehmer und anwendbare rechtliche Verfahren.
2. **Erhobene Daten:** Unterscheide zwischen Konto-/Abrechnungsdaten, Quell-IP, Verbindungszeitstempeln, Bandbreite, Crash-Telemetrie, DNS-Abfragen und Zielprotokollen. „Keine Browsing-Protokolle“ bedeutet nicht „keine Daten“.
3. **Aufbewahrung und Löschung:** Ermittle genaue Aufbewahrungsfristen und ob Backups, Betrugserkennungssysteme und Auftragsverarbeiter denselben Zeitplan einhalten.
4. **Nachweise:** Bevorzuge öffentliche Audits mit Umfang, Datum, Ergebnissen und Abhilfemaßnahmen, reproduzierbare/offene Clients, Transparenzberichte und dokumentierte Vorfälle.
5. **Protokoll und Client:** Gepflegtes WireGuard, OpenVPN oder ein anderes geprüftes Protokoll; automatische Updates; DNS- und IPv6-Verarbeitung; kill switch; sowie Leak-Tests für jede Plattform.
6. **Geschäftsmodell:** Verstehe, wie ein kostenloser oder subventionierter Dienst finanziert wird. Die Präsenz in einem App-Store allein ist kein Beleg für einen vertrauenswürdigen Betrieb.
7. **Zahlungsoptionen:** Eine alternative Zahlungsmethode kann die Offenlegung von Abrechnungsdaten gegenüber dem VPN verringern, löscht aber nicht die bei jeder Verbindung beobachtete Quell-IP.

### VPN konfigurieren und überprüfen

1. Installiere den signierten Client des Anbieters/der Organisation aus der offiziellen Quelle.
2. Wähle **full tunnel**, sofern keine dokumentierte Route daran vorbeiführen muss. Split Tunneling schafft Korrelations- und Leak-Pfade.
3. Aktiviere fail-closed-/always-on-Verhalten und blockiere Traffic während der Wiederverbindung.
4. Leite DNS durch den Tunnel und teste IPv4 sowie IPv6. Deaktiviere ein Protokoll nur, wenn es nicht sicher durch den Tunnel geleitet werden kann und der Funktionsverlust akzeptiert wird.
5. Teste Ruhezustand/Aufwachen, Netzwerkwechsel, Captive-Portal-Anmeldung, Tunnel-Absturz und Hotspot-Tethering. NCSC warnt, dass angebundene Clients auf manchen Plattformen das VPN eines Telefons umgehen können.<sup>[[2]](#references)</sup>
6. Verwende einen von der Organisation kontrollierten Testendpunkt, um beobachtete IPv4, IPv6, DNS-Resolver und Verbindungszeitpunkt zu protokollieren. Setze einen sensiblen Auftrag keinen beliebigen „Leak-Test“-Websites aus.
7. Wiederhole die Tests nach Änderungen am Client, Betriebssystem, Netzwerk oder an Richtlinien.

### Routing-Umgehungen in feindlichen LANs

Ein VPN kann weiterhin sichtbar „verbunden“ sein, während ausgewählte Pakete daran vorbeigeleitet werden, weil das Betriebssystem eine Route auswählt, **bevor** das VPN das Paket verschlüsselt. TunnelCrack zeigte zwei Wege, gängige Routing-Ausnahmen auszunutzen: **LocalNet** lässt ein Internetziel so erscheinen, als befände es sich im direkt verbundenen Subnetz, während **ServerIP** die Auflösung des VPN-Gateways fälscht, sodass eine Zieladresse die Klartext-Netzwerk-Ausnahme erbt, die der VPN-Transport benötigt. Dabei handelt es sich um Fehler im Client/Routing, nicht um Brüche in WireGuard, OpenVPN, IPsec oder TLS; HTTPS-Payloads bleiben Ende-zu-Ende verschlüsselt, aber der lokale Beobachter kann Ziel-/Zeitmetadaten und alle Klartext-Protokolldaten erfassen.<sup>[[18]](#references)</sup>

TunnelVision nutzt denselben Vor-Verschlüsselungs-Primitiv über DHCP-Option 121. Ein bösartiger oder kompromittierter DHCP-Server kann eine classless route installieren, die spezifischer ist als die Catch-all-Route des VPN und für einen beliebigen Host oder Bereich die physische Schnittstelle auswählt. Der VPN-Control-Channel kann aktiv bleiben, sodass ein kill switch, der nur bei einer Tunnelunterbrechung ausgelöst wird, möglicherweise nicht greift. Auch ein einzelner öffentlicher „IP-Leak“-Test kann selektive Umgehungen übersehen.<sup>[[19]](#references)</sup>

Ein Paketfilter-kill switch, der auf der physischen Schnittstelle nur DHCP und den authentifizierten VPN-Transport zulässt, sollte dies in ein fail-closed-Verhalten umwandeln. Gezielte Routeninjektion kann jedoch weiterhin einen selektiven Denial-Side-Channel erzeugen. Für Linux-Workloads mit hohen Konsequenzen empfiehlt sich das stärkere [pro Workload erzwungene Netzwerk-Namespace-Muster](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), bei dem der Anwendungs-Namespace weder eine physische Schnittstelle noch eine Standardroute über das Klartextnetzwerk hat.<sup>[[19]](#references)</sup>

#### Überprüfung im eigenen Labor

Teste den konkreten Client/das konkrete Betriebssystem/die konkrete Version auf einem eigenen AP, DHCP-Server, VPN-Endpunkt und Ziel. Aussagen zu ganzen Produktfamilien veralten schnell, da Routing- und Paketfilterimplementierungen plattformspezifisch sind. Erfasse Traffic sowohl am Endpunkt selbst als auch auf dem Testserver – eine Website zur Anzeige der Egress-IP allein beweist nicht, dass jedes Ziel durch den Tunnel geleitet wird.<sup>[[18]](#references)[[19]](#references)</sup>

1. Verbinde das VPN, notiere die Adresse des VPN-Servers und speichere alle IPv4-/IPv6-Routingtabellen sowie Policy-Routing-Regeln. Verwende unter Windows `route print`, unter macOS `netstat -rn` und unter Linux die folgenden Befehle.
2. Frage die ausgewählte Route für mehrere eigene Ziel-IPs ab. Der nächste Hop/die Schnittstelle muss der Tunnel sein, abgesehen vom dokumentierten VPN-Transportendpunkt.
3. Für TunnelVision: Erneuere das Lease im kontrollierten DHCP-Netzwerk und installiere eine Route der Option 121 **nur für ein eigenes Testziel**. Der Test ist bestanden, wenn der Traffic weiterhin getunnelt oder blockiert wird – er darf niemals als Zieltraffic über die physische Schnittstelle gesendet werden.
4. Für LocalNet: Weise dem Client ein nur für das Labor verwendetes öffentliches Dokumentations-Subnetz wie `203.0.113.0/24` zu und platziere das eigene Testziel darin. Überprüfe, dass die Aktivierung des LAN-Zugriffs Internetziele nicht am Tunnel vorbeileitet.
5. Für ServerIP: Bevor das VPN verbunden wird, lässt du kontrolliertes DNS den eigenen VPN-Hostnamen in die eigene Testzieladresse auflösen, während das Laborgateway den VPN-Transport an den echten, eigenen VPN-Endpunkt weiterleitet. Der Client darf keinen nicht zugehörigen Anwendungs-Traffic zur gefälschten Adresse ausnehmen.
6. Wiederhole den Test mit aktiviertem und deaktiviertem „Zugriff auf lokales Netzwerk“ sowie nach Wiederverbindung, Ruhezustand/Aufwachen, Netzwerkwechsel und Absturz des VPN-Prozesses. Teste IPv4, IPv6 und DNS unabhängig voneinander.
7. Untersuche den Mitschnitt der physischen Schnittstelle. Er sollte DHCP und verschlüsselte Pakete zum VPN-Server enthalten, aber keine direkt an das eigene Testziel adressierten Pakete. Bestätige außerdem, dass eine blockierte Umgehung nach Benutzerabfragen oder einer Verbindungsreparatur nicht stillschweigend auf eine andere Verbindung ausweichen kann.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: stärkere Unverknüpfbarkeit im Web

Tor erstellt einen Circuit über mehrere Relays, sodass normalerweise kein einzelnes Relay sowohl Quelle als auch Ziel kennt. Das Ziel sieht einen Tor-Exit statt der IP-Adresse des Nutzers; das lokale Netzwerk sieht normalerweise eine Tor-Verbindung.<sup>[[3]](#references)</sup> Tor ist für TCP-Anwendungen mit geringer Latenz konzipiert, ist daher langsamer und kann keinen Schutz vor einem Angreifer garantieren, der beide Enden korrelieren kann.<sup>[[4]](#references)</sup>

### Sicherer Tor Browser-Workflow

1. Lade Tor Browser nur vom Tor Project oder einem offiziellen Mirror herunter und überprüfe nach Möglichkeit die Signatur.
2. Verwende **Tor Browser**, nicht einen normalen Browser, der auf einen Tor-SOCKS-Port zeigt. Normale Browser können DNS/WebRTC und identifizierende Zustände leaken.<sup>[[5]](#references)</sup>
3. Behalte die standardmäßige Größe, Schriftarten, Erweiterungen und Datenschutzeinstellungen bei. Zusätzliche Add-ons können den Browser einzigartiger machen.<sup>[[6]](#references)</sup>
4. Wähle die Sicherheitsstufe **Safer** oder **Safest**, wenn die dadurch verursachten Einschränkungen akzeptabel sind.
5. Verwende eine Bridge, wenn Tor direkt blockiert ist oder wenn gewöhnliche Relay-IP-Adressen die lokale Sichtbarkeit unvertretbar erhöhen würden. Bridges erschweren die einfache Erkennung, verhindern aber keine Traffic-Analyse.<sup>[[7]](#references)</sup>
6. Melde dich nicht bei einem identifizierenden Konto an, gib keine identifizierenden Informationen an und öffne heruntergeladene aktive Dokumente nicht in einer externen, vernetzten Anwendung.
7. Verwende für jede Identität eine separate Sitzung/einen separaten Kontext. „New circuit“ ist nicht dasselbe wie das Löschen der Browser-/Anwendungsidentität. Verwende **New Identity** oder starte die isolierte Umgebung bei Bedarf neu.
8. Bevorzuge authentifiziertes HTTPS oder einen authentifizierten Onion Service. Ein Tor-Exit kann unverschlüsselten HTTP-Traffic beobachten.

### Tor plus VPN

Die Kombination ist nicht automatisch sicherer. Ein VPN vor Tor kann direkte Tor-Relay-Verbindungen vor einem ISP verbergen, während das VPN die Quelle sieht. Tor vor einem VPN gibt dem VPN eine beständige Sicht auf Aktivitäten nach Tor und kann die Anonymitätsmenge verkleinern. Fehlkonfigurationen können Leaks verursachen. Das Tor Project empfiehlt solche Kombinationen nur bei fortgeschrittenen, ausdrücklich definierten Bedrohungsmodellen.<sup>[[8]](#references)</sup>

## Öffentliches WLAN und Gäste-WLAN

Dank modernem HTTPS können passive Beobachter in der Nähe normalerweise keine ordnungsgemäß verschlüsselten Webinhalte lesen. Gäste-WLAN bietet jedoch keine Anonymität. Der Betreiber kann Verbindungszeiten, Gerätekennungen, Captive-Portal-Daten, Ziele und DHCP-Details protokollieren; Kameras, Einkäufe, Transport und physische Beobachtung können den Nutzer identifizieren. Ein gefälschter Hotspot mit ähnlich klingendem Namen kann außerdem Portal-Zugangsdaten abfangen oder unverschlüsselten Traffic manipulieren.<sup>[[9]](#references)</sup>

### Sicherer Workflow für Gäste-WLAN

1. Verwende nur ein Netzwerk, das Gästen angeboten wird oder für dessen Nutzung der Eigentümer ausdrücklich seine Erlaubnis erteilt hat. Frage das Personal nach der genauen SSID und dem Portal-Verfahren.
2. Aktualisiere das Endgerät und den Reise-Router vor der Ankunft. Deaktiviere Datei-/Druckerfreigabe, eingehende Geräteerkennung, automatisches Verbinden und die Suche nach gespeicherten Netzwerken.
3. Aktiviere die private/randomisierte WLAN-Adresse des Betriebssystems. Aktuelle Apple-Systeme können in offenen/schwach gesicherten Netzwerken rotierende Adressen verwenden; die Randomisierung moderner Android-Versionen ist üblicherweise pro SSID dauerhaft. Dadurch wird nur eine lokale Kennung weniger sichtbar.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Bevorzuge einen von der Organisation kontrollierten Reise-Router oder ein Bridge-Gerät mit geringem Vertrauensniveau zwischen einer privilegierten Workstation und dem Gäste-WLAN. So lassen sich Firewall-/VPN-Richtlinien zentralisieren, der Router bleibt für den Betreiber jedoch sichtbar.<sup>[[12]](#references)</sup>
5. Schließe ein Captive Portal ausschließlich über das dafür vorgesehene Gerät/den dafür vorgesehenen Browser mit geringem Vertrauensniveau ab. Gib in einem vermeintlich anonymen Kontext niemals persönliche oder wiederverwendete Zugangsdaten ein. Schließe den Portal-Browser, sobald die Verbindung hergestellt ist.
6. Starte vor sensiblen Aktivitäten ein Full-Tunnel-VPN oder Tor und überprüfe, dass bei einem Ausfall keine Verbindung möglich ist.
7. Entferne das Netzwerk nach der Nutzung aus den gespeicherten Netzwerken und überprüfe die Richtlinien für Portal-Konten und Datenspeicherung.

{% hint style="danger" %}
Das Knacken des WLANs eines Nachbarn, das Umgehen eines Portals, die Verwendung geleakter Gast-Zugangsdaten, das Klonen des Zugangs eines anderen Gasts oder das Verstecken eines Raspberry Pi in einem Café sind nicht autorisierte Aktivitäten – keine Datenschutztechniken. Sichere Alternativen sind ein rechtmäßig genutztes Gäste-WLAN, ein vom Kunden genehmigter Standort oder ein dokumentierter Drop Node, der mit schriftlicher Zustimmung des Eigentümers platziert und wieder entfernt wird.
{% endhint %}

## Reise-Router

Ein Reise-Router kann eine Workstation von schädlichen lokalen Broadcasts isolieren, eine Firewall durchsetzen, eine einheitliche interne SSID bereitstellen und ein VPN automatisch wiederverbinden. Er ist **nicht** anonym: Das Upstream-Netzwerk sieht seine Funkkennung und den zeitlichen Verlauf des Traffics, und der VPN-Anbieter sieht die Quelle des Tunnels.

- Verwende unterstützte OpenWrt-/Hersteller-Firmware und entferne nicht benötigte Dienste.
- Verwalte den Router über Ethernet oder eine dedizierte Management-SSID mit einem einzigartigen Passwort.
- Deaktiviere die WAN-seitige Administration, UPnP, WPS, Dateifreigabe und unerwünschten eingehenden Traffic.
- Verwende eine randomisierte/private WAN-MAC-Adresse nur, wenn dies unterstützt und erlaubt ist.
- Setze die VPN-Richtlinien auf dem Router durch, einschließlich DNS und IPv6, und blockiere den ausgehenden Traffic, wenn der Tunnel ausfällt.
- Gehe nicht davon aus, dass ein Telefon-Hotspot angebundene Geräte durch das VPN des Telefons tunnelt; teste es.

## Mobilfunk, SIM-Karten und eSIMs

Mobilfunk ist praktisch, aber nicht anonym. Betreiber speichern Teilnehmer-/Gerätekennungen und den aus der Netzanbindung abgeleiteten Standort; eine eSIM ist weiterhin ein Mobilfunkvertrag. Prepaid bedeutet nicht zuverlässig, dass keine Registrierung erforderlich ist – die Anforderungen unterscheiden sich je nach Land und ändern sich.<sup>[[13]](#references)</sup>

In der Praxis:

- Verwende ein separates, unterstütztes Gerät, um die Offenlegung persönlicher Daten zu verringern, nicht um einen fiktiven Teilnehmer zu erzeugen.
- Trage ein „separates“ Gerät nicht dauerhaft zusätzlich zu einem persönlichen Telefon mit dir, wenn der gemeinsame Standort Teil des Bedrohungsmodells ist.
- Deaktiviere ungenutzten Mobilfunk, WLAN, Bluetooth und Standortzugriff. Ausschalten schafft eine stärkere Funkgrenze als UI-Schalter.
- Leite sensiblen Traffic durch den genehmigten VPN-/Tor-Pfad und beachte dabei, dass der Mobilfunkanbieter weiterhin den Standort des Vertrags/Geräts und den Tunnel-Endpunkt kennt.
- Prüfe die aktuellen Registrierungs- und Aufbewahrungsregeln bei der nationalen Aufsichtsbehörde oder einem lokalen Rechtsberater. Verlasse dich nicht auf Online-Listen zu „anonymen SIM-Ländern“.

## DNS- und TLS-Metadaten

- **DoH/DoT/DoQ** verschlüsseln DNS zwischen Client und Resolver und verhindern so einfaches lokales Mitlesen oder Verändern. Der Resolver sieht jedoch weiterhin Abfragen und Transportkennungen. Dadurch wird Vertrauen verlagert, nicht Anonymität geschaffen.<sup>[[14]](#references)</sup>
- **ODoH** fügt einen Proxy hinzu, sodass der Resolver die Client-IP nicht erfahren muss, sofern Proxy und Ziel nicht kolludieren. Traffic-Analyse liegt ausdrücklich außerhalb des Schutzbereichs.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** kann den inneren Servernamen in einem TLS-Handshake schützen, wenn Client, DNS und Server dies unterstützen. Ziel-IP, Zeitpunkt, Volumen und Endgerät bleiben sichtbar.<sup>[[16]](#references)</sup>
- In einer korrekt konfigurierten VPN- oder Tor-Umgebung sollte DNS dem unterstützten Pfad dieser Umgebung folgen. Ein zusätzlicher, separater Resolver kann einen neuen Beobachter oder Fingerprint schaffen.

### Verifizierungs-Workflow für verschlüsseltes DNS/ECH

1. Entscheide, ob DNS von der VPN-/Tor-Umgebung, dem Betriebssystem oder der Anwendung kontrolliert wird. Konfiguriere es auf **einer** vorgesehenen Ebene, statt unabhängige Resolver zu schichten.
2. Wähle einen Resolver anhand seiner veröffentlichten Datenschutz-/Aufbewahrungsrichtlinie und aktiviere den strikten verschlüsselten Modus, sofern die Plattform ihn unterstützt. Ein opportunistischer Fallback kann unbemerkt zu Klartext zurückkehren.
3. Frage eine eindeutige Subdomain unter einer autoritativen Testzone ab, die du kontrollierst. Bestätige, dass das autoritative Log den vorgesehenen rekursiven Resolver anzeigt.
4. Erfasse mit entsprechender Genehmigung nur den Traffic des Testgeräts. Bestätige, dass das Zugangsnetzwerk DNS nicht im Klartext lesen kann. Beachte dabei, dass es den verschlüsselten Resolver-/Tunnel-Endpunkt sehen kann.
5. Teste einen blockierten/nicht erreichbaren verschlüsselten Resolver. Das erwartete Ergebnis ist das gewählte Fail-Closed- oder dokumentierte Fallback-Verhalten – keine versehentliche Klartextabfrage.
6. Verwende für ECH einen kontrollierten ECH-fähigen Host und prüfe die Client-/Server-Diagnosemeldungen, um zu bestätigen, dass der **innere** ClientHello akzeptiert wurde. Das bloße Anbieten eines HTTPS-Records beweist nicht, dass ECH funktioniert hat.
7. Wiederhole den Test nach Netzwerkänderungen, Captive Portals, Browser-Updates und erneuten VPN-Verbindungen. Dokumentiere, welche Komponente DNS/ECH steuert, damit spätere Administratoren keinen Bypass schaffen.

## Mixnets

Mixnets wie Nym oder Katzenpost ergänzen Fixed-Size-Pakete, Verzögerung, Umordnung und Cover Traffic, um zeitliche Korrelationen zu erschweren. Diese Eigenschaften kosten Latenz und Bandbreite; unabhängige Belege zur Skalierbarkeit des Einsatzes sind begrenzt. Betrachte aktuelle Mixnets für Endverbraucher als **aufkommende Optionen mit hoher Latenz**, nicht als schnellere oder garantierte Alternative zu Tor/VPNs.<sup>[[17]](#references)</sup>

### Evaluierungs-Workflow

1. Ermittle einen gepflegten Client und die genau unterstützte Anwendung. Leite nicht beliebigen Browser-/System-Traffic über einen undokumentierten Proxy um.
2. Lies das aktuelle Bedrohungsmodell zu Entry, Mix Nodes, Gateway, Ziel und Annahmen zur Kollusion.
3. Installiere den Client aus der offiziellen, signierten Quelle in einer separaten Testumgebung und verwende nur einen harmlosen, selbst kontrollierten Endpunkt.
4. Miss Zustelllatenz, Nachrichtengrößenlimits, Zuverlässigkeit, erneute Übertragungen und das Verhalten bei einem nicht verfügbaren Gateway.
5. Prüfe den lokalen Traffic und den selbst kontrollierten Endpunkt, um den vorgesehenen Pfad und die Quelle zu bestätigen. Überprüfe, ob Antworten dasselbe Datenschutzdesign verwenden.
6. Teste das Beenden/Fehlerverhalten: Die Anwendung darf nicht unbemerkt auf direkten Internetzugriff zurückfallen.
7. Deaktiviere Cover Traffic nicht, verkürze Verzögerungen nicht und wähle nicht allein aus Geschwindigkeitsgründen ungewöhnliche feste Routen. Solche Änderungen können das angegebene Anonymitätsmodell ungültig machen.
8. Nutze die Lösung nur experimentell, bis die konkrete Bereitstellung, unabhängige Analysen und die betriebliche Zuverlässigkeit dem erforderlichen Konsequenzniveau entsprechen.

## Checkliste vor der Netzwerknutzung

- [ ] Die Genehmigung umfasst das Zugangsnetzwerk, das Ziel, die Zeiträume und die Quellinfrastruktur.
- [ ] Das Endgerät enthält keine fremden Identitäten oder aktiven Synchronisierungssitzungen.
- [ ] IPv4, IPv6, DNS und das Verhalten bei erneuter Verbindung entsprechen dem Plan.
- [ ] Durch kontrolliertes DHCP/Einfügen lokaler Subnetzrouten kann kein Test-Traffic auf die physische Schnittstelle umgeleitet werden.
- [ ] Das Ziel sieht nur den erwarteten Egress.
- [ ] Das Verhalten von Captive Portal und Hotspot wurde ohne sensiblen Traffic getestet.
- [ ] Lokale Freigaben/Geräteerkennung und automatisches Verbinden mit Netzwerken sind deaktiviert.
- [ ] Die Tabelle der Beobachter und das verbleibende Risiko einer Traffic-Korrelation sind akzeptiert.
- [ ] Richtlinien des Anbieters, Aufbewahrungsfristen und Notfallkontakt sind aktuell.

Informationen zu Relays mit aufgeteiltem Wissen, Workloads mit erzwungenem Routing, Pluggable Transports, Onion Services, I2P und kurzlebigen Remote-Browsern findest du unter [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Das passende VPN auswählen](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Leitfaden zur Gerätesicherheit: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Die Datenschutz- und Anonymitätsschutzfunktionen von Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Eine kurze Einführung in Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor mit anderen Browsern verwenden](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins und Add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor entsperren](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Tor Browser mit einem VPN verwenden](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Sind öffentliche WLAN-Netzwerke sicher?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — WLAN-Datenschutz mit Apple-Geräten](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC-Randomisierung implementieren](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Grundsätze für sichere Workstations mit privilegiertem Zugriff](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obligatorische SIM-Registrierung: politische und regulatorische Perspektiven](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Empfehlungen für Betreiber von DNS-Datenschutzdiensten](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Bedrohungsmodell](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Tunnel umgehen: VPN-Client-Traffic durch Ausnutzen von Routingtabellen leaken](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Wie Angreifer Routing-basierte VPNs enttarnen und einen vollständigen VPN-Leak verursachen können](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil FAQ: Ist Yggdrasil anonym?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
