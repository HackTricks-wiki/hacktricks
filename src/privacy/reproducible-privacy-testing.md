# Reproduzierbares Privacy-Testing

Ein Privacy-Setup ist nicht fertig, wenn es eine Verbindung herstellt. Es ist fertig, wenn seine behauptete Grenze unter normaler Nutzung, bei Ausfällen, bei der Wiederherstellung und beim Teardown getestet wurde. Teste gegen Infrastruktur, die dir gehört oder deren Prüfung dir erlaubt ist; öffentliche „leak test“-Seiten werden zu einem weiteren Beobachter.

## Eine kleine autorisierte Testumgebung aufbauen

Verwende drei Rollen, idealerweise bei separaten Anbietern/Netzwerken:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Vor jedem Test erfassen:

- Test-ID, UTC-Start/-Ende, Betreiber und Autorisierung;
- Endpunkt-/OS-/Client-Versionen und Konfigurations-Hash;
- erwartete Beobachtungen zu IPv4, IPv6, DNS, TLS, Konto, Zahlung und physischen Merkmalen;
- welche Logs geprüft werden und deren Uhren/Zeitzonen;
- Pass/Fail-Regel und Teardown-Zeit.

Teste niemals zuerst eine sensible Identität. Verwende ein synthetisches Konto und harmlose, eindeutige Canary-Werte, die dem Tester gehören.

## Netzpfadtest

### 1. Baseline erfassen

Erfasse vor dem Aktivieren des Privacy-Pfads lokale Routen und Resolver:
```bash
ip route
ip -6 route
resolvectl status
```
Verwende unter macOS `route -n get default`, `netstat -rn -f inet6` und `scutil --dns`. Speichere die Ausgabe ausschließlich im kontrollierten Evidence Store; sie kann lokale Identifikatoren enthalten.

### 2. Verbindung herstellen und Routing überprüfen

Aktiviere den VPN/Tor/workload namespace und überprüfe anschließend die ausgewählte Route für kontrollierte öffentliche Adressen:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Ersetze die Dokumentationsadressen durch die Adressen des Testservers. Bestätige, dass die ausgewählte Oberfläche/Tabelle mit dem Design übereinstimmt.

### 3. Von beiden Seiten beobachten

Lege die URL des kontrollierten Endpunkts fest und fordere anschließend einen eindeutigen, harmlosen Pfad an:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Verwende eine echte, vom Tester kontrollierte Domain, authentifiziertes TLS und ein nicht sensibles Pfad-Token. Prüfe das Server-Log auf:

- Quelladresse/ASN und erwarteten Egress;
- IPv4 im Vergleich zu IPv6;
- am Endpoint sichtbares Host-/SNI-Verhalten;
- User-Agent und Anwendungs-Header;
- genaue Zeit und Wiederverwendung der Anfrage.

Füge einer vermeintlich getrennten Anfrage weder `X-Forwarded-For` noch eindeutige Debug-Header oder identitätsbehaftete Cookies hinzu.

### 4. DNS mit einem eigenen Canary testen

Konfiguriere eine autoritative Testzone, deren Query-Logs du kontrollierst. Frage über das Compartment ein eindeutiges zufälliges Label ab:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Prüfe das authoritative log. Es sieht normalerweise den recursive resolver, nicht unbedingt den Client. Vergleiche diesen resolver mit dem vorgesehenen VPN/Tor/application DNS design. Eine zufällige öffentliche DNS-leak-Website ist nicht erforderlich.

### 5. Teste das fail-closed-Verhalten

Halte eine harmlose Request-Schleife aufrecht, die auf den eigenen Endpoint zielt, und stoppe dann den privacy path. Die Workload muss fehlschlagen, statt auf ein physisches Interface zu wechseln. Prüfe beide address families und DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Wiederhole dies während:

- Absturz des tunnel-Prozesses;
- Wechsel von Wi-Fi zu Ethernet oder zu einem Hotspot;
- Ruhezustand/Aufwachen;
- DHCP-Erneuerung;
- captive-portal-Zustand;
- erneuter Verbindung des Providers/Ablauf des Schlüssels.

Für einen Linux-Namespace/Container stoppe dessen tunnel und überprüfe, dass er keine andere Standardroute oder keinen anderen Resolver hat:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Namen und Befehle unterscheiden sich je nach Deployment. Füge sie nicht ohne Konsolenwiederherstellung in einen entfernten Produktionshost ein.

### 6. Lokale Sockets und Pakete untersuchen

Prüfe mit entsprechender Genehmigung, welcher Prozess/welche Schnittstelle tatsächlich kommuniziert:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Ersetze `TEST_SERVER_IP` durch die explizit autorisierte Adresse; vermeide eine weitreichende Erfassung nicht beteiligter Benutzer. Die physische Schnittstelle sollte den Tunnel-/Bridge-Peer sehen, während Klartext-Zielverkehr nur auf der vorgesehenen Ebene vorhanden sein sollte.

## Tor- und Onion-Service-Test

1. Rufe im Tor Browser die Verbindungsprüfung des Tor Project auf und bestätige die Tor-Nutzung. Behandle dies nicht als Identitätsnachweis.<sup>[[1]](#references)</sup>
2. Rufe den autorisierten HTTPS-Endpunkt mit einem eindeutigen canary auf und bestätige, dass er einen Tor-Exit sieht, keine identifizierenden Cookies vorhanden sind und der Standard-Browserkontext verwendet wird.
3. Wähle **New Identity**, rufe den Endpunkt mit einem anderen canary erneut auf und überprüfe, dass der lokale Zustand erwartungsgemäß gelöscht wurde. Eine Änderung der Exit-IP ist weder garantiert noch der Zweck von New Identity.
4. Greife auf einen Onion Service ausschließlich über Tor Browser zu. Bestätige mit einem autorisierten externen Scan, dass der Service-Host keinen öffentlichen Listener besitzt, und dass die Anwendungsantworten keinen öffentlichen Hostnamen bzw. keine öffentliche IP enthalten.
5. Untersuche ausgehendes DNS/HTTP des Ursprungs, Templates, Fehlerseiten, E-Mails/Webhooks und Assets von Drittanbietern. Jeder direkte Abruf kann den Ursprung oder das Betreiberkonto offenlegen.
6. Wenn eine Client-Autorisierung aktiviert ist, bestätige, dass ein nicht authentifizierter sauberer Tor Browser keine Verbindung herstellen kann und ein authentifizierter dies kann.
7. Rotiere einen Test-Autorisierungsschlüssel und bestätige, dass der widerrufene Client den Zugriff verliert, ohne die Onion-Identität zu ändern.

## Browser-Kompartiment-Test

Erstelle eine kontrollierte Seite, die nur die für den Test erforderlichen Felder mit einer kurzen Aufbewahrungsdauer erfasst. Vergleiche persönliche und Privacy-Kompartimente hinsichtlich:

- Cookies/Local Storage/Service Worker und Cache;
- Browser-Synchronisierung/Login-Zustand;
- Sprache, Zeitzone, Bildschirm-/Fensterabmessungen und Fonts;
- WebRTC-/Netzwerk-Kandidaten;
- Berechtigungen und für Extensions sichtbare Änderungen;
- TLS-/HTTP-User-Agent-Daten auf dem Server.

Versuche nicht, Tor Browser „zufälliger“ zu machen. Die Bestehensbedingung ist die Ähnlichkeit mit seiner standardmäßigen Anonymity Set und das Fehlen persönlicher Zustände, nicht der maximale Unterschied zum persönlichen Browser.

Teste Kopieren/Einfügen, Drag-and-drop, das Öffnen heruntergeladener Dateien, Vorschläge des Passwort-Managers und Schaltflächen von Identity Providern. Dies sind häufige Brücken zwischen Kompartimenten.

## Test der Betriebssystem-Isolation

### Tails

1. Beginne mit einer harmlosen Datei/einem canary in einer Sitzung ohne Persistent Storage.
2. Führe ein vollständiges Herunterfahren durch, starte neu und bestätige, dass die Datei bzw. der canary verschwunden ist.
3. Aktiviere nur eine erforderliche Persistence-Kategorie, wiederhole den Vorgang und bestätige, dass kein nicht zugehöriger Browser-/Anwendungszustand erhalten bleibt.
4. Überprüfe, dass der Unsafe Browser nach dem Portal-Login nicht für sensible Aktivitäten verwendet werden kann und dass Tor-Anwendungen normal erneut eine Verbindung herstellen.

### Whonix/Qubes

1. Stoppe die Gateway-/Net-Qube und beweise, dass die Workstation-/App-Qube IPv4, IPv6 oder DNS nicht erreichen kann.
2. Versuche nur den ausdrücklich konfigurierten Clipboard-/Dateipfad zwischen Qubes und bestätige, dass andere Pfade über gemeinsame Ordner/Geräte nicht vorhanden sind.
3. Öffne ein harmloses Testdokument in einer Disposable Qube, schließe es und bestätige, dass sein Zustand verschwindet.
4. Überprüfe, dass die Vault Qube keine NetVM besitzt und durch eine Änderung von Template/Standardwerten keine erwerben kann.
5. Erstelle einen Snapshot einer Test-VM bzw. stelle ihn wieder her und untersuche, ob identitätsbezogener Zustand unerwartet zurückkehrt.

## Test der Kommunikationsmetadaten

Für jeden ausgewählten Messenger:

1. Erstelle ausschließlich für Tests bestimmte Teilnehmer auf kontrollierten Geräten.
2. Dokumentiere, was die Registrierung erfordert: Telefonnummer, App-Store-Konto, IP, Push Service, Benutzername oder Einladung.
3. Sende eine harmlose Nachricht und untersuche dabei Benachrichtigungsvorschauen, verknüpfte Desktops, Wearables und Backups.
4. Überprüfe Sicherheits-/Security-Codes über einen unabhängigen Kanal.
5. Deaktiviere Empfangsbestätigungen/Push oder aktiviere Tor/lokale Transports jeweils einzeln und beobachte Änderungen bei Zuverlässigkeit und Metadaten.
6. Exportiere ein Test-Backup bzw. stelle es wieder her und dokumentiere genau, welche Profil-, Kontakt- und Verlaufsdaten es enthält.
7. Verliere ein Testgerät bzw. widerrufe es und bestätige, dass die verbleibenden Teilnehmer die erwartete Schlüssel-/Geräteänderung sehen.

Teste nicht, indem du unbeteiligte Personen kontaktierst oder missbräuchlichen Datenverkehr erzeugst.

## Test der Dateibereinigung

1. Hash den Originalinhalt und bewahre ihn in einem verschlüsselten Beweisspeicher auf:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Erstelle mithilfe des formatspezifischen Prozesses in [Datenschutzfreundliche Kommunikation und Freigabe](privacy-preserving-communications-and-sharing.md) eine bereinigte Kopie.
3. Vergleiche die Metadateninventare:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Die Kopie in einem disposable context rendern/öffnen. Versteckte Inhalte, Anhänge, Links, Formulare, Ebenen, Thumbnails und visuelle Identifikatoren prüfen.
5. Nur die staged copy nach bekannten Canary-Autor-/E-Mail-/Pfad-Strings durchsuchen.
6. Die finale Ausgabe hashen und von einer zweiten Person die exakt zu veröffentlichende Datei verifizieren lassen.

Das Fehlen in der ExifTool-Ausgabe ist kein Beweis für Anonymität; Format-Interna, Pixel, Prosa und Verteilungsaufzeichnungen bleiben bestehen.

## Payment privacy test

Den kleinstmöglichen zulässigen Betrag oder ein offizielles Testnetzwerk/eine Sandbox verwenden:

1. Die erwartete Sicht für Zahler, Zahlungsempfänger/Händler, Issuer/Exchange, Netzwerk/Node, öffentliches Ledger und Accountant/Controller dokumentieren.
2. Eine eindeutige Testrechnung/einen eindeutigen Merchant-Kontext ohne falsche Identität erstellen.
3. Einmal zahlen und anschließend die **eigenen** Belege, den Kontoauszug, das Merchant-Dashboard, den Wallet-/Node-Log und, sofern anwendbar, die Ansicht der öffentlichen Chain erfassen.
4. Prüfen, ob Betrag, Zeitstempel, Adresse/Token, Konto, IP/Gerät, Lieferung und Rückerstattungsweg mit der Beobachtertabelle übereinstimmen.
5. Für Bitcoin die Adresswiederverwendung, ausgewählte Inputs, Change und spätere Konsolidierung in der Coin-Control-Ansicht der Wallet prüfen.
6. Bei shielded protocols den tatsächlichen Pool/Pfad und das verifizieren, was ein Viewing Key offenlegt; Privatsphäre nicht aus dem Wallet-Branding ableiten.
7. Bei E-Cash/Taler Backup/Recovery, Rückerstattung und Redemption mit geringem Wert testen; die Aufzeichnungen an der Mint-/Exchange-/Federation-Grenze dokumentieren.
8. Eine virtuelle Karte/ein Test-Credential widerrufen und bestätigen, dass eine spätere Autorisierung fehlschlägt, während die legitime Rückerstattungsabwicklung weiterhin verstanden wird.
9. Erforderliche Steuer-/Autorisierungsnachweise abgleichen und verschlüsselt aufbewahren.

Niemals zirkuläre Transfers, Aufteilung in Schwellenwerte, gefälschte Käufe oder verdächtige Rückerstattungen als „privacy test“ erstellen.

## Authorized red-team accountability drill

Vor der Übung ein Tabletop und einen technischen Drill durchführen:

1. Ein Operator startet von jedem genehmigten Source Path einen harmlosen Canary.
2. Das Ziel-SOC dokumentiert, was es erkennt, ohne die Identität des Operators zu erhalten, wenn blind testing vorgesehen ist.
3. Der Exercise Controller löst die Zuordnung Source → Engagement → Operator anhand der hinterlegten Map und des signierten Job Records auf.
4. Der Controller sendet den Emergency Stop; Operator und Infrastructure Owner demonstrieren das Herunterfahren innerhalb der ROE-Zeit.
5. Provider Abuse erhält den korrekten 24/7-Kontakt und die Autorisierungsreferenz.
6. Die Beweise zeigen Target, Zeitpunkt, Tool/Job und Operator, ohne unnötige Payload-Inhalte aufzubewahren.
7. Ein zweiter Operator verifiziert Credential Revocation und Resource Teardown.

Die Readiness Review nicht bestehen, wenn das SOC persönliche Infrastruktur oder Heim-Infrastruktur **ODER** wenn der Controller die Source nicht schnell zuordnen und stoppen kann.

## Test record template
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Verbindungstest](https://check.torproject.org/)
- [2] [WireGuard — Routing und Netzwerk-Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ und Metadaten-Leitfaden](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Technischer Leitfaden für Tests und Bewertungen der Informationssicherheit](https://csrc.nist.gov/pubs/sp/800/115/final)
