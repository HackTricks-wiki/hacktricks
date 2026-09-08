# Datenschutzfreundliche Kommunikation und gemeinsame Nutzung

End-to-end encryption schützt Inhalte. Sie verbirgt nicht automatisch das Konto, die Telefonnummer, das Kontaktgraphen, die IP-Adresse, den Push-Token, die Benachrichtigungsvorschau, den Zeitpunkt, Dateimetadaten oder das Verhalten des Empfängers. Wähle ein Tool anhand der Metadaten aus, die es entfernt, und der Beobachter, die es einführt.

## Kommunikationsmodelle vergleichen

| Tool/Modell | Nützliche Eigenschaft | Verbleibende Beobachter und Einschränkungen |
|---|---|---|
| Signal | Ausgereifte E2EE; Usernames können Kontaktaufnahme ermöglichen, ohne die Nummer zu teilen; sealed sender reduziert Service-Metadaten | Telefonnummer für die Registrierung erforderlich; Service, Push-Anbieter, Kontakte und Endpoints behalten einige Beobachtungsmöglichkeiten |
| SimpleX | Keine globale Benutzerkennung; Queues pro Kontakt; optionaler Tor-Transport | Relay-Timing/Transport, Push-Service, Einladungen und Endpoints; neueres/kleineres Ökosystem |
| Briar | Direkte Synchronisierung; Tor online; Bluetooth/Wi-Fi offline; kein zentraler Nachrichtenspeicher | Kontakte und Endpoints; lokale Funkbeobachter; auf Android ausgerichtet; beide Seiten müssen verfügbar sein oder Mailbox verwenden |
| OnionShare | Direkte Dateiübertragung, Empfang, Chat oder Website über einen temporären Onion-Service; kein Storage-Provider | Der Computer des Senders ist der Service; der Link-Besitzer erfährt, dass er Zugriff hat; Timing und Endpoints bleiben sichtbar |
| Mit `age` verschlüsselte Datei | Einfache Verschlüsselung mit Empfängerschlüssel, unabhängig vom Transport | Der Transport sieht Sender, Empfänger, Zeitpunkt und Größe; Dateinamen/Archivmetadaten und Endpoints bleiben sichtbar |
| Gewöhnliche E-Mail + TLS | Verschlüsselung der Server-zu-Server-Verbindung | Beide Mail-Provider können Inhalte normalerweise lesen und Routing-/Kontometadaten speichern |

## Signal: privater Kontakt ohne Offenlegung der Nummer

Signal-Usernames können einen Chat starten, ohne die Telefonnummer des Benutzers gegenüber dem neuen Kontakt offenzulegen; für die Registrierung bleibt eine Telefonnummer erforderlich.<sup>[[1]](#references)</sup> Sealed sender ist ein schrittweiser Metadatenschutz und kein Schutz gegen jede IP-/Timing-Korrelation.<sup>[[2]](#references)</sup>

### Arbeitsablauf

1. Installiere Signal aus dem offiziellen App-Store/Projekt und aktualisiere zuerst das OS.
2. Registriere dich mit einer Nummer, zu deren Nutzung du rechtmäßig berechtigt bist. Verwende keine gemieteten SMS-Aktivierungen, nicht die Nummer einer anderen Person und kein Provider-Konto, das mit einer falschen Identität erworben wurde.
3. Lege unter **Settings → Privacy → Phone Number** entsprechend dem Threat Model fest, wer die Nummer sehen und wer das Konto anhand der Nummer finden kann.
4. Erstelle für die Auffindbarkeit durch neue Kontakte einen Username. Teile den exakten Link/QR über einen bereits authentifizierten Kanal; Usernames können geändert werden und sind nicht der Profilname.
5. Deaktiviere den Kontakt-Upload bzw. die entsprechenden Berechtigungen, wenn der Komfort die Verknüpfung nicht rechtfertigt, und füge Kontakte manuell hinzu, sofern die Plattform dies unterstützt.
6. Öffne die Kontaktdetails und vergleiche die Sicherheitsnummer/den QR-Code vor dem Austausch sensibler Inhalte über einen zweiten Kanal oder persönlich.
7. Überprüfe verknüpfte Geräte, Registrierungssperre/PIN, Benachrichtigungsvorschauen, Bildschirmsicherheit, Anrufweiterleitung, Voreinstellungen für verschwindende Nachrichten und das Backup-Verhalten.
8. Sende eine nicht sensible Testnachricht und tätige einen Anruf. Überprüfe auf beiden Seiten die Spuren auf Sperrbildschirm, Desktop, Wearable und in Cloud-Benachrichtigungen.
9. Behandle eine geänderte Sicherheitsnummer oder ein unerwartet verknüpftes Gerät als Untersuchungsereignis und nicht als Warnung, die automatisch verworfen wird.

Vermische kein pseudonymes Profilbild, keine Bio, keine Gruppenmitgliedschaft und keinen Zeitplan mit einem identifizierenden Signal-Kontext.

## SimpleX: Verbindungen pro Kontakt ohne globale Kennung

SimpleX leitet Nachrichten über unidirektionale Queues weiter und weist keine netzwerkweite Benutzerkennung zu. Die eigene Richtlinie dokumentiert dennoch Transportsitzungen, temporäre Serverdaten, Abwägungen bei Push-Benachrichtigungen und die Verantwortung für Endpoints.<sup>[[3]](#references)</sup>

### Arbeitsablauf

1. Lade einen gepflegten Client aus dem offiziellen Projekt/Store herunter und überprüfe den Herausgeber. Verwende ein dediziertes OS-/App-Profil, wenn Identitäten nicht vermischt werden dürfen.
2. Erstelle ein **lokales** Profil mit einem kontextbezogenen Anzeigenamen und Bild. Wird die App ohne Backup gelöscht, können Profil und Verbindungen verloren gehen.
3. Wähle beim ersten Start den Benachrichtigungsmodus bewusst. Instant mobile push kann zusätzliche Metadaten gegenüber der Apple-/Google-Infrastruktur offenlegen.
4. Erstelle einen einmaligen Einladungslink für einen Kontakt. Übertrage ihn über einen authentifizierten Kanal; jeder, der eine aktive Einladung erhält, kann versuchen, sie zu verwenden.
5. Öffne nach der Verbindung die Kontaktdetails und vergleiche den Sicherheitscode persönlich oder über einen unabhängig verifizierten Kanal.<sup>[[4]](#references)</sup>
6. Verwende, sofern unterstützt, ein Incognito-Profil pro Gruppe, statt dasselbe Profil in voneinander unabhängigen Gruppen wiederzuverwenden.
7. Konfiguriere den vom Client unterstützten Tor-Transport, wenn das lokale Netzwerk/der Server die direkte IP nicht sehen soll. Bestätige die Verbindung nach der Änderung; erzwinge keinen nicht unterstützten System-Proxy.
8. Überprüfe Zustellbestätigungen, Link-Vorschauen, Anrufe, automatische Downloads sowie Datenbankexport und Backup. Jede dieser Funktionen verändert Metadaten oder die Offenlegung gegenüber Endpoints.
9. Teste die Wiederherstellung auf einem separaten isolierten Gerät, ohne einen duplizierten aktiven Profilstatus auszuführen; das Projekt warnt, dass gleichzeitig ausgeführte Kopien Unterhaltungen stören können.

Eine globale Kennung verhindert nicht, dass ein Kontakt den Benutzer anhand von Inhalten, Profilwiederverwendung, Einladungszustellung, Timing oder sozialem Graphen identifiziert.

## Briar: direkte und störungsresistente Nachrichtenübermittlung

Briar synchronisiert direkt zwischen Geräten, online über Tor und bei lokalen Ausfällen über Bluetooth/Wi-Fi. Das offizielle Threat Model geht nur von einer begrenzten gegnerischen Überwachung von Kurzstreckenfunk aus; lokaler Funk ist daher nicht unsichtbar.<sup>[[5]](#references)</sup>

### Arbeitsablauf

1. Installiere Briar aus der offiziellen Briar-Distribution und überprüfe die Paketquelle. Verwende ein unterstütztes Android-Gerät mit aktuellen Sicherheitsupdates.
2. Erstelle ein lokales Konto mit einem eindeutigen kontextbezogenen Spitznamen und einem starken Passwort. Es gibt keinen Weg zum Zurücksetzen des Passworts; stelle sicher, dass das Entsperrgeheimnis wiederhergestellt werden kann.
3. Füge Kontakte nach Möglichkeit persönlich hinzu, indem ihr gegenseitig eure QR-Codes scannt. Dadurch wird der Kontakt authentifiziert und die Übertragung eines Links über einen korrelierbaren Kanal vermieden.
4. Aktiviere in den Verbindungseinstellungen nur die benötigten Transporte: Tor/Internet, Wi-Fi und/oder Bluetooth. Deaktiviere lokale Funkverbindungen, wenn sie nicht benötigt werden.
5. Prüfe für die asynchrone Zustellung Briar Mailbox auf einem dedizierten, dauerhaft mit Strom versorgten Gerät; erfasse es und schütze es physisch wie einen Nachrichtenserver.
6. Sende eine unkritische Testnachricht, während das Internet verfügbar ist, und teste anschließend den geplanten Ausfallpfad mit deaktiviertem Internet an einem vom Eigentümer autorisierten Ort.
7. Überprüfe Android-Backups, Benachrichtigungsvorschauen, Screenshots und exportierte Inhalte. Der lokale verschlüsselte Speicher ist offengelegt, wenn der Endpoint entsperrt oder kompromittiert ist.
8. Entferne verlorene Kontakte/Geräte und löse den gesamten Kontext auf, wenn die physische Kontrolle oder das Kontopasswort kompromittiert wurde.

## OnionShare: direkter temporärer Transfer

OnionShare führt einen Onion-Service auf dem Computer des Senders/Empfängers aus; Dateien werden nicht zu einem Storage-Provider hochgeladen, und der Datenverkehr ist innerhalb von Tor End-to-end verschlüsselt.<sup>[[6]](#references)</sup> Die vollständige Onion-URL ist eine Bearer Capability und muss geschützt werden.

### GUI-Dateifreigabe-Arbeitsablauf

1. Installiere OnionShare aus seiner offiziellen signierten Distribution und Tor Browser auf der Seite des Empfängers.
2. Lege **bereinigte Kopien** der Dateien in einem dedizierten Staging-Verzeichnis ab. Verweise OnionShare nicht auf ein persönliches Home-Verzeichnis.
3. Öffne **Share Files**, füge nur die bereitgestellten Dateien hinzu, lasse den Schutz durch privaten Schlüssel/Zugriff aktiviert und aktiviere **Stop sharing after files have been sent** für einen Empfänger.
4. Starte die Freigabe und sende die vollständige Onion-URL über einen bereits authentifizierten E2EE-Kanal. Füge sie nicht in E-Mails, Issue-Tracker oder öffentliche Chats ein.
5. Der Empfänger öffnet die URL in Tor Browser, überprüft gemeinsam mit dem Sender die erwarteten Dateinamen und die Größe und lädt die Dateien herunter.
6. Vergleicht beide Seiten einen vorab vereinbarten oder separat übermittelten SHA-256-Hash für die Integrität, wenn die Datei selbst die Sicherheitsgrenze bildet.
7. Bestätige, dass OnionShare nach dem Download beendet wurde; andernfalls beende die Freigabe manuell und schließe die Anwendung.
8. Lösche die bereitgestellte Kopie entsprechend der Aufbewahrungsrichtlinie und überprüfe die OnionShare-Verlaufs-/Log-Einstellungen auf unbeabsichtigte Offenlegung von Dateinamen.

### CLI-Arbeitsablauf

Die offizielle CLI akzeptiert Dateien als Positionsargumente und beendet sich nach der standardmäßigen einmalig abgeschlossenen Freigabe. Auf einem Host mit installierter offizieller CLI/Tor-Software:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Übermittle die vollständige URL sicher. Füge `--public`, `--no-autostop-sharing`, eine ausführliche Protokollierung von Dateinamen oder Persistenz nicht hinzu, es sei denn, das Threat Model erfordert die daraus resultierende Offenlegung ausdrücklich.<sup>[[7]](#references)</sup>

Behandle empfangene Dokumente als feindselig. Öffne sie in einer Disposable-VM bzw. einem Renderer im Dangerzone-Stil und nicht auf dem Host, der deine Identität trägt.

## Eine Datei unabhängig mit `age` verschlüsseln

Eine vom Transport unabhängige Verschlüsselung ist nützlich, wenn ein Speicher-/E-Mail-Anbieter das Objekt sehen kann. Sie verbirgt weder Absender noch Empfänger, Größe, Zeitpunkt oder Dateinamen, sofern diese Aspekte nicht separat behandelt werden.

### Einrichtung des Empfängers
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Authentifiziere die öffentliche Empfängerzeichenfolge über einen zweiten Kanal. Der Sender führt anschließend Folgendes aus:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Der Empfänger entschlüsselt in einen neuen Pfad:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Die offizielle CLI warnt, dass `-o` eine vorhandene Ausgabe überschreibt. Verwende daher ein neues Verzeichnis und überprüfe Digest/Inhalt, bevor du die Datei verschiebst.<sup>[[8]](#references)</sup> Sende die Identitätsdatei niemals zusammen mit dem Chiffretext.

## Reproduzierbare Pipeline zur Dateibereinigung

Das Entfernen von Metadaten ist formatspezifisch. Bewahre das verschlüsselte Original auf, wenn Authentizität, Forensik oder Beweiskette relevant sind, und arbeite mit einer Kopie.

### JPEG-Beispiel
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Dies folgt den sichereren JPEG-Empfehlungen von ExifTool: Das blinde Entfernen jedes Tags kann auch Farbinformationen entfernen.<sup>[[9]](#references)</sup> Überprüfe anschließend die Pixel visuell auf Gesichter, Spiegelungen, Bildschirme, Orientierungspunkte und einzigartige Beschädigungs-/Rauschmuster.

### Office/PDF-Workflow

1. Bewahre das bearbeitbare Original verschlüsselt und getrennt vom Veröffentlichungsumfeld offline auf.
2. Entferne Kommentare, nachverfolgte Änderungen, ausgeblendete Folien/Tabellenblätter, eingebettete Dateien, persönliche Vorlagen und Dokumenteigenschaften in der Authoring-Anwendung.
3. Exportiere ein neues PDF aus einem dedizierten sauberen Profil; „drucke“ nicht auf einen Cloud-Drucker.
4. Überprüfe es sowohl mit formatbewussten Tools als auch mit einem verworfenen visuellen Renderer:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Durchsuche die gerenderte Ausgabe nach Namen, Pfaden, E-Mail-Adressen und Revisionstext. Rasterisierung kann aktive Strukturen entfernen, beeinträchtigt jedoch Barrierefreiheit und Suche und entfernt weder sichtbare Inhalte noch den Schreibstil.
6. Hash den finalen Inhalt und übertrage ausschließlich diese Kopie durch das Publication Compartment.

## Privacy Pass: anonyme Autorisierung für Service-Designer

Privacy Pass trennt die **Ausgabe** von Tokens von ihrer **Einlösung**. Ein Origin kann erfahren, dass ein Client ein vom Issuer genehmigtes Token besitzt, ohne die spezifische Ausstellung-Interaktion des Clients zu erfahren. Die Wiederverwendung eines Tokens, eindeutige Metadaten, zeitliche Zusammenhänge oder Kollusion können die Verknüpfbarkeit wiederherstellen.<sup>[[10]](#references)</sup>

Sicheres Deployment-Muster:

1. Definiere die Aussage, die das Token beweist (z. B. die Berechtigung für Rate-Limiting), nicht eine verborgene globale Identität.
2. Verwende die standardisierte Architektur und die standardisierten Ausgabeprotokolle; implementiere keine Blind-Signature-Kryptografie von Grund auf neu.
3. Trenne die Verwaltung von Issuer/Attester und Origin, wenn die gewünschte Eigenschaft dies erfordert.
4. Minimiere öffentliche/private Token-Metadaten und stelle sicher, dass die Anonymitätsgruppen groß genug sind.
5. Stelle, sofern unterstützt, vor der Nutzung Batches aus, damit der Ausgabezeitpunkt nicht trivial dem Einlösungszeitpunkt zugeordnet werden kann.
6. Löse jedes Token nur einmal ein, validiere die an den Origin gebundene Challenge und lösche abgelaufenen Token-Status.
7. Verhindere, dass Cookies, IP-Logging und Anwendungskonten die Privacy-Eigenschaft des Tokens unbemerkt aushebeln.
8. Teste, ob Issuer- und Origin-Logs ein kontrolliertes Ausgabe- und Einlösungsereignis anhand von Zeitpunkten, Metadaten oder eindeutigen Fehlern zusammenführen können.

Privacy Pass ist ein Anwendungs-Feature und nichts, das ein Benutzer an ein beliebiges Konto nachträglich anbringen kann.

## Checkliste zur Kommunikationsverifizierung

- [ ] Kontakt/Einladung/Schlüssel wurde unabhängig authentifiziert.
- [ ] Die Offenlegung von Telefonnummer, Benutzernamen, Profil, Gruppe und hochgeladenen Kontakten ist bekannt.
- [ ] Direkte IP-, Relay-, Tor-, Push-Provider- und lokale Funkbeobachter sind aufgeführt.
- [ ] Benachrichtigungsvorschauen, Wearables, verknüpfte Desktops und Backups wurden getestet.
- [ ] Dateien wurden bereinigt, bei Bedarf verschlüsselt und in einem Disposable Context geöffnet.
- [ ] Die Wiederherstellung funktioniert, ohne nicht zusammengehörige Identitäten zu verknüpfen.
- [ ] Für Logs, Verlauf und temporäre Sharing-Services gibt es eine Regel zur Abschaltung/Aufbewahrung.

## References

- [1] [Signal — Datenschutz für Telefonnummern und Benutzernamen](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Datenschutzrichtlinie und Nutzungsbedingungen](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Leitfaden zu Datenschutz und Sicherheit](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Funktionsweise](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Sicherheitsdesign](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Erweiterte Nutzung und CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — offizielle CLI und Nutzung](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Sicheres Entfernen von Metadaten](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy-Pass-Architektur](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
