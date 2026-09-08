# Reproduzierbares Privacy-Testing

{{#include ../banners/hacktricks-training.md}}

Eine Privacy-Konfiguration ist nicht fertig, wenn sie eine Verbindung herstellt. Sie ist fertig, wenn ihre behauptete Grenze bei normaler Nutzung, bei Fehlern, bei der Wiederherstellung und beim Teardown getestet wurde. Teste gegen Infrastruktur, die dir gehört oder deren Prüfung du autorisiert bist; öffentliche „leak test“-Websites werden zu einem weiteren Beobachter.

## Eine kleine autorisierte Testumgebung erstellen

Verwende drei Rollen, idealerweise bei separaten Anbietern/Netzwerken:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Vor jedem Test aufzeichnen:

- Test-ID, UTC-Start/-Ende, Operator und Autorisierung;
- Endpunkt-/OS-/Client-Versionen und Konfigurations-Hash;
- erwartete IPv4-, IPv6-, DNS-, TLS-, Konto-, Zahlungs- und physischen Beobachtungen;
- welche Logs überprüft werden und deren Uhren/Zeitzonen;
- Pass/Fail-Regel und Zeit des Teardowns.

Teste niemals zuerst eine sensible Identität. Verwende ein synthetisches Konto und harmlose, eindeutige Canary-Werte, die dem Tester gehören.

## Netzwerkpfad-Test

### 1. Baseline erfassen

Zeichne vor der Aktivierung des Datenschutzpfads die lokalen Routen und Resolver auf:
```bash
ip route
ip -6 route
resolvectl status
```
Verwende unter macOS `route -n get default`, `netstat -rn -f inet6` und `scutil --dns`. Speichere die Ausgabe ausschließlich im kontrollierten Beweisspeicher; sie kann lokale Identifikatoren enthalten.

### 2. Verbindung herstellen und Routing überprüfen

Aktiviere den VPN/Tor/workload namespace und überprüfe anschließend die für kontrollierte öffentliche Adressen ausgewählte Route:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Ersetze die Dokumentationsadressen durch die Adressen des Testservers. Bestätige, dass die ausgewählte Schnittstelle/Tabelle mit dem Design übereinstimmt.

### 3. Von beiden Enden beobachten

Lege die URL des kontrollierten Endpunkts fest und fordere anschließend einen eindeutigen, harmlosen Pfad an:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Verwende eine von den Testern kontrollierte Domain, authentifiziertes TLS und ein nicht sensibles Pfad-Token. Prüfe das Server-Log auf:

- Quelladresse/ASN und erwarteten Egress;
- IPv4 gegenüber IPv6;
- am Endpoint sichtbares Host-/SNI-Verhalten;
- User-Agent und Application-Header;
- genaue Zeit und Wiederverwendung der Anfrage.

Füge einer angeblich getrennten Anfrage weder `X-Forwarded-For` noch eindeutige Debug-Header oder identitätsbezogene Cookies hinzu.

### 4. DNS mit einem eigenen canary testen

Konfiguriere eine autoritative Testzone, deren Query-Logs du kontrollierst. Frage über das Compartment ein eindeutiges zufälliges Label ab:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Prüfe den autoritativen Log. Er sieht normalerweise den rekursiven Resolver, nicht unbedingt den Client. Vergleiche diesen Resolver mit dem vorgesehenen DNS-Design für VPN/Tor/Anwendungen. Eine zufällige öffentliche DNS-leak-Seite ist nicht erforderlich.

### 5. Fail-Closed-Verhalten testen

Halte eine harmlose Request-Schleife aufrecht, die auf den eigenen Endpunkt zielt, und stoppe anschließend den Privacy-Pfad. Die Workload muss fehlschlagen, statt auf ein physisches Interface umzuschalten. Prüfe sowohl beide Adressfamilien als auch DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Wiederholen bei:

- Absturz des tunnel-Prozesses;
- Wechsel von Wi-Fi zu Ethernet oder zu einem Hotspot;
- Ruhezustand/Aufwachen;
- DHCP-Erneuerung;
- Zustand des Captive Portals;
- erneuter Verbindung des Providers/Ablauf des Schlüssels.

Für einen Linux-Namespace/Container den tunnel stoppen und überprüfen, dass keine andere Standardroute oder kein anderer Resolver vorhanden ist:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Namen und Befehle unterscheiden sich je nach Deployment. Füge sie nicht ohne Wiederherstellung über die Konsole in einen Remote-Produktionshost ein.

### 6. Lokale Sockets und Pakete untersuchen

Prüfe mit entsprechender Autorisierung, welcher Prozess/welche Schnittstelle tatsächlich kommuniziert:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Ersetze `TEST_SERVER_IP` durch die explizit eigene Adresse; vermeide eine weitreichende Erfassung nicht beteiligter Benutzer. Die physische Schnittstelle sollte den Tunnel-/Bridge-Peer sehen, während Klartext-Zielverkehr nur auf der vorgesehenen Ebene vorhanden sein sollte.

## Tor- und Onion-Service-Test

1. Rufe im Tor Browser die Verbindungsprüfung des Tor Project auf und bestätige die Tor-Nutzung. Betrachte dies nicht als Identitätsnachweis.<sup>[[1]](#references)</sup>
2. Rufe den eigenen HTTPS-Endpunkt mit einem eindeutigen Canary auf und bestätige, dass er einen Tor-Exit, keine identifizierenden Cookies und den standardmäßigen Browser-Kontext sieht.
3. Wähle **New Identity**, rufe den Endpunkt mit einem anderen Canary erneut auf und überprüfe, dass der lokale Zustand wie erwartet gelöscht wurde. Eine Änderung der Exit-IP ist weder garantiert noch der Zweck von New Identity.
4. Greife auf einen Onion Service ausschließlich über den Tor Browser zu. Bestätige mit einem autorisierten externen Scan, dass der Service-Host keinen öffentlichen Listener hat und dass die Anwendungsantworten keinen öffentlichen Hostnamen bzw. keine öffentliche IP enthalten.
5. Untersuche ausgehendes DNS/HTTP des Ursprungs, Templates, Fehlerseiten, E-Mail/Webhooks und Assets von Drittanbietern. Jeder direkte Abruf kann den Ursprung oder das Operator-Konto offenlegen.
6. Wenn Client-Autorisierung aktiviert ist, bestätige, dass ein nicht authentifizierter sauberer Tor Browser keine Verbindung herstellen kann und ein authentifizierter dies kann.
7. Rotiere einen Test-Autorisierungsschlüssel und bestätige, dass der widerrufene Client den Zugriff verliert, ohne die Onion-Identität zu ändern.

## Browser-Kompartiment-Test

Erstelle eine kontrollierte Seite, die nur die für den Test erforderlichen Felder mit einer kurzen Aufbewahrungsdauer aufzeichnet. Vergleiche persönliche und Privacy-Kompartimente hinsichtlich:

- Cookies/Local Storage/Service Worker und Cache;
- Browser-Synchronisierung/Login-Zustand;
- Sprache, Zeitzone, Bildschirm-/Fensterabmessungen und Schriftarten;
- WebRTC-/Netzwerk-Kandidaten;
- Berechtigungen und für Erweiterungen sichtbare Änderungen;
- TLS-/HTTP-User-Agent-Daten auf dem Server.

Versuche nicht, den Tor Browser „zufälliger“ zu machen. Die Testbedingung ist die Ähnlichkeit mit seiner standardmäßigen Anonymitätsmenge und das Fehlen persönlicher Zustände, nicht der maximale Unterschied zum persönlichen Browser.

Teste Kopieren/Einfügen, Drag-and-drop, das Öffnen heruntergeladener Dateien, Vorschläge des Passwort-Managers und Schaltflächen von Identity Providern. Dies sind häufige Brücken zwischen Kompartimenten.

## Test der Betriebssystem-Isolation

### Tails

1. Beginne mit einer harmlosen Datei/einem Canary in einer Sitzung ohne Persistent Storage.
2. Führe ein vollständiges Herunterfahren durch, starte neu und bestätige, dass die Datei bzw. der Canary verschwunden ist.
3. Aktiviere nur eine erforderliche Persistence-Kategorie, wiederhole den Vorgang und bestätige, dass kein unabhängiger Browser-/Anwendungszustand erhalten bleibt.
4. Überprüfe, dass der Unsafe Browser nach der Portal-Anmeldung nicht für sensible Aktivitäten verwendet werden kann und dass Tor-Anwendungen sich normal erneut verbinden.

### Whonix/Qubes

1. Stoppe die Gateway-/Net-Qube und beweise, dass die Workstation-/App-Qube IPv4, IPv6 oder DNS nicht erreichen kann.
2. Versuche ausschließlich den explizit konfigurierten Clipboard-/Dateipfad zwischen Quubes und bestätige, dass andere Pfade für gemeinsame Ordner/Geräte nicht vorhanden sind.
3. Öffne ein harmloses Testdokument in einer Disposable-Qube, schließe sie und bestätige, dass ihr Zustand verschwindet.
4. Überprüfe, dass die Vault-Qube keine NetVM hat und durch eine Änderung von Template/Standardwert keine erwerben kann.
5. Erstelle einen Snapshot/eine Wiederherstellung einer Test-VM und untersuche, ob identitätsbezogener Zustand unerwartet zurückkehrt.

## Test der Kommunikationsmetadaten

Für jeden ausgewählten Messenger:

1. Erstelle ausschließlich für den Test bestimmte Teilnehmer auf kontrollierten Geräten.
2. Zeichne auf, was für die Registrierung erforderlich ist: Telefonnummer, App-Store-Konto, IP, Push-Service, Benutzername oder Einladung.
3. Sende eine harmlose Nachricht und untersuche dabei Benachrichtigungsvorschauen, verknüpfte Desktops, Wearables und Backups.
4. Überprüfe Sicherheits-/Security-Codes über einen unabhängigen Kanal.
5. Deaktiviere Lesebestätigungen/Push oder aktiviere Tor/lokale Transports jeweils einzeln und beobachte Änderungen bei Zuverlässigkeit und Metadaten.
6. Exportiere ein Test-Backup oder stelle es wieder her und dokumentiere genau, welches Profil, welche Kontakte und welchen Verlauf es enthält.
7. Verliere ein Testgerät oder widerrufe es und bestätige, dass die verbleibenden Teilnehmer die erwartete Schlüssel-/Geräteänderung sehen.

Teste nicht, indem du unbeteiligte Personen kontaktierst oder missbräuchlichen Traffic erzeugst.

## Test der Dateibereinigung

1. Hash die Originaldatei und bewahre sie in einem verschlüsselten Beweisspeicher auf:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Erstelle mithilfe des formatspezifischen Prozesses in [Datenschutzfreundliche Kommunikation und Freigabe](privacy-preserving-communications-and-sharing.md) eine bereinigte Kopie.
3. Vergleiche die Metadateninventare:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Rendern/Öffnen Sie die Kopie in einem disposable context. Prüfen Sie verborgene Inhalte, Anhänge, Links, Formulare, Ebenen, Thumbnails und visuelle identifiers.
5. Durchsuchen Sie ausschließlich die staged copy nach bekannten Canary-Strings für Autor/E-Mail/Pfad.
6. Hashen Sie die finale Ausgabe und lassen Sie von einer zweiten Person die exakt zu veröffentlichende Datei verifizieren.

Das Fehlen in der ExifTool-Ausgabe ist kein Beweis für Anonymität; Format-Interna, Pixel, Prosa und Verteilungsaufzeichnungen bleiben bestehen.

## Datenschutztest für Zahlungen

Verwenden Sie den kleinstmöglichen zulässigen Betrag oder ein offizielles Testnetzwerk/eine Sandbox:

1. Notieren Sie die erwartete Sicht für Zahler, Zahlungsempfänger/Händler, Issuer/Exchange, Netzwerk/Node, öffentliches Ledger und Buchhalter/Controller.
2. Erstellen Sie eine eindeutige Test-Rechnungs-/Händlerumgebung ohne falsche Identität.
3. Zahlen Sie einmal und sammeln Sie anschließend Ihren **eigenen** Beleg, Kontoauszug, Händler-Dashboard, Wallet-/Node-Log und gegebenenfalls die Ansicht der öffentlichen Blockchain.
4. Prüfen Sie, ob Betrag, Zeitstempel, Adresse/Token, Konto, IP/Gerät, Lieferung und Rückerstattungsweg mit der Beobachtertabelle übereinstimmen.
5. Prüfen Sie bei Bitcoin die Adresswiederverwendung, ausgewählte Inputs, Wechselgeld und spätere Konsolidierung in der Coin-Control-Ansicht der Wallet.
6. Verifizieren Sie bei abgeschirmten Protokollen den tatsächlichen Pool/Pfad und was ein Viewing Key offenlegt; schließen Sie nicht aus dem Wallet-Branding auf Privacy.
7. Testen Sie bei E-Cash/Taler Backup/Wiederherstellung, Rückerstattung und Einlösung mit einem kleinen Wert; dokumentieren Sie Mint-/Exchange-/Federation-Grenzaufzeichnungen.
8. Widerrufen Sie eine virtuelle Karte/ein Test-Credential und bestätigen Sie, dass eine spätere Autorisierung fehlschlägt, während die legitime Abwicklung von Rückerstattungen weiterhin verstanden wird.
9. Stimmen Sie die erforderlichen Steuer-/Autorisierungsnachweise ab und bewahren Sie sie verschlüsselt auf.

Erstellen Sie niemals zirkuläre Transfers, Aufteilungen unter Schwellenwerten, Scheinkäufe oder verdächtige Rückerstattungen als „Privacy-Test“.

## Verantwortlichkeitsübung für autorisiertes red-team

Führen Sie vor der Übung eine Tabletop- und technische Übung durch:

1. Ein Operator startet von jedem genehmigten source path einen harmlosen Canary.
2. Das Ziel-SOC protokolliert, was es erkennt, ohne die Identität des Operators zu erhalten, wenn Blind Testing vorgesehen ist.
3. Der Übungs-Controller stellt anhand der hinterlegten Zuordnung und des signierten Job-Datensatzes die Zuordnung Quelle → Engagement → Operator her.
4. Der Controller sendet den Not-Aus; Operator und Infrastrukturverantwortlicher demonstrieren die Abschaltung innerhalb der ROE-Zeit.
5. Der Provider-Abuse-Kontakt erhält die korrekte 24/7-Kontaktmöglichkeit und den Autorisierungsverweis.
6. Die Beweise zeigen Ziel, Zeitpunkt, Tool/Job und Operator, ohne unnötige Payload-Inhalte aufzubewahren.
7. Ein zweiter Operator verifiziert den Widerruf der Credentials und den Abbau der Ressourcen.

Lehnen Sie die Bereitschaftsprüfung ab, wenn das SOC persönliche Infrastruktur oder Heim-Infrastruktur **ODER** der Controller die Quelle nicht schnell zuordnen und stoppen kann.

## Vorlage für Testprotokoll
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

- [1] [Tor Project — Verbindungsprüfung](https://check.torproject.org/)
- [2] [WireGuard — Routing und Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ und Leitfaden zu Metadaten](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Technischer Leitfaden für Tests und Bewertungen der Informationssicherheit](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
