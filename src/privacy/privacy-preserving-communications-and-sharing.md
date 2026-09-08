# Datenschutzfreundliche Kommunikation und gemeinsames Teilen

{{#include ../banners/hacktricks-training.md}}

End-to-end encryption schützt den Inhalt. Sie verbirgt nicht automatisch das Konto, die Telefonnummer, das Kontaktgraph, die IP-Adresse, das Push-Token, die Benachrichtigungsvorschau, den zeitlichen Ablauf, Dateimetadaten oder das Verhalten des Empfängers. Wähle ein Tool anhand der Metadaten aus, die es entfernt, und der Beobachter, die es einführt.

## Kommunikationsmodelle vergleichen

| Tool/Modell | Nützliche Eigenschaft | Verbleibende Beobachter und Einschränkungen |
|---|---|---|
| Signal | Ausgereifte E2EE; Usernames können Kontaktaufnahme ohne Weitergabe der Nummer ermöglichen; Sealed Sender reduziert Service-Metadaten | Telefonnummer für die Registrierung erforderlich; Service, Push-Provider, Kontakte und Endpoints behalten einige Beobachtungsmöglichkeiten |
| SimpleX | Keine globale Benutzerkennung; Queues pro Kontakt; optionaler Tor-Transport | Relay-Timing/Transport, Push-Service, Einladungen und Endpoints; neueres/kleineres Ökosystem |
| Briar | Direkte Synchronisierung; online über Tor; offline über Bluetooth/Wi-Fi; kein zentraler Nachrichtenspeicher | Kontakte und Endpoints; lokale Funkbeobachter; Android-orientiert; beide Seiten müssen verfügbar sein oder Mailbox verwenden |
| OnionShare | Direkte Dateiübertragung/Empfang/Chat/Website über einen temporären Onion-Service; kein Storage-Provider | Der Computer des Senders ist der Service; der Besitzer des Links erfährt den Zugriff; Timing und Endpoints bleiben sichtbar |
| Verschlüsselte `age`-Datei | Einfache Verschlüsselung für Empfänger unabhängig vom Transport | Der Transport sieht Sender/Empfänger, Timing und Größe; Dateinamen/Archivmetadaten und Endpoints bleiben sichtbar |
| Gewöhnliche E-Mail + TLS | Verschlüsselung des Kanals zwischen Servern | Beide Mail-Provider können den Inhalt normalerweise lesen und Routing-/Kontometadaten speichern |

## Signal: privater Kontakt ohne Offenlegung der Nummer

Signal-Usernames können einen Chat starten, ohne die Telefonnummer des Benutzers gegenüber dem neuen Kontakt offenzulegen; für die Registrierung bleibt eine Telefonnummer erforderlich.<sup>[[1]](#references)</sup> Sealed Sender bietet einen zusätzlichen Metadatenschutz, ist aber kein Schutz gegen jede IP-/Timing-Korrelation.<sup>[[2]](#references)</sup>

### Ablauf

1. Installiere Signal aus dem offiziellen App-Store/Projekt und aktualisiere zuerst das Betriebssystem.
2. Registriere dich mit einer Nummer, zu deren Nutzung du rechtmäßig berechtigt bist. Verwende keine gemieteten SMS-Aktivierungen, die Nummer einer anderen Person oder ein Provider-Konto, das mit einer falschen Identität erstellt wurde.
3. Lege unter **Einstellungen → Datenschutz → Telefonnummer** fest, wer die Nummer sehen und wer das Konto anhand der Nummer finden kann, entsprechend dem Threat Model.
4. Erstelle einen Username für die Suche nach neuen Kontakten. Teile den exakten Link/QR über einen bereits authentifizierten Kanal; Usernames können geändert werden und sind nicht der Profilname.
5. Deaktiviere den Kontakt-Upload bzw. die entsprechenden Berechtigungen, wenn der Komfort die Verknüpfung nicht rechtfertigt, und füge Kontakte manuell hinzu, sofern die Plattform dies unterstützt.
6. Öffne die Kontaktdetails und vergleiche die Sicherheitsnummer/den QR über einen zweiten Kanal oder persönlich, bevor du vertrauliche Inhalte sendest.
7. Überprüfe verknüpfte Geräte, Registrierungssperre/PIN, Benachrichtigungsvorschauen, Bildschirmsicherheit, Anrufweiterleitung, Standards für verschwindende Nachrichten und das Backup-Verhalten.
8. Sende eine nicht vertrauliche Testnachricht und führe einen Anruf durch. Überprüfe auf beiden Seiten Spuren auf Sperrbildschirm, Desktop, Wearable und in Cloud-Benachrichtigungen.
9. Behandle eine geänderte Sicherheitsnummer oder ein unerwartetes verknüpftes Gerät als Untersuchungsereignis und nicht als Warnung, die automatisch verworfen wird.

Vermische kein pseudonymes Profilbild, keine Biografie, keine Gruppenmitgliedschaft und keinen Zeitplan mit einem identifizierenden Signal-Kontext.

## SimpleX: Verbindungen pro Kontakt ohne globale Kennung

SimpleX leitet Nachrichten über unidirektionale Queues weiter und weist keine netzwerkweite Benutzerkennung zu. Die eigene Richtlinie dokumentiert dennoch Transportsitzungen, temporäre Serverdaten, Abwägungen bei Push-Benachrichtigungen und die Verantwortung der Endpoints.<sup>[[3]](#references)</sup>

### Ablauf

1. Lade einen gepflegten Client aus dem offiziellen Projekt/Store herunter und überprüfe den Herausgeber. Verwende ein dediziertes Betriebssystem-/App-Profil, wenn Identitäten nicht vermischt werden dürfen.
2. Erstelle ein **lokales** Profil mit einem kontextspezifischen Anzeigenamen und Bild. Das Löschen der App ohne Backup kann zum Verlust des Profils und der Verbindungen führen.
3. Wähle beim ersten Start den Benachrichtigungsmodus bewusst. Sofortige mobile Push-Benachrichtigungen können zusätzliche Metadaten gegenüber der Apple-/Google-Infrastruktur offenlegen.
4. Erstelle einen einmaligen Einladungslink für einen Kontakt. Übertrage ihn über einen authentifizierten Kanal; jeder, der eine aktive Einladung erhält, kann versuchen, sie zu verwenden.
5. Öffne nach der Verbindung die Kontaktdetails und vergleiche den Sicherheitscode persönlich oder über einen unabhängig verifizierten Kanal.<sup>[[4]](#references)</sup>
6. Verwende, sofern unterstützt, ein Inkognito-Profil pro Gruppe, anstatt dasselbe Profil in voneinander unabhängigen Gruppen wiederzuverwenden.
7. Konfiguriere den vom Client unterstützten Tor-Transport, wenn das lokale Netzwerk/der Server die direkte IP nicht sehen soll. Bestätige die Verbindung nach der Änderung; erzwinge keinen nicht unterstützten System-Proxy.
8. Überprüfe Zustellbestätigungen, Link-Vorschauen, Anrufe, automatische Downloads sowie Datenbankexporte und Backups. Jede dieser Funktionen verändert Metadaten oder die Exposition des Endpoints.
9. Teste die Wiederherstellung auf einem separaten isolierten Gerät, ohne einen duplizierten aktiven Profilstatus auszuführen; das Projekt warnt, dass parallele Kopien Unterhaltungen stören können.

Eine globale Kennung verhindert nicht, dass ein Kontakt den Benutzer anhand von Inhalten, Profilwiederverwendung, Einladungsübertragung, Timing oder sozialem Graph identifiziert.

## Briar: direkte und störungsresistente Nachrichtenübermittlung

Briar synchronisiert direkt zwischen Geräten, online über Tor und bei lokalen Ausfällen über Bluetooth/Wi-Fi. Das offizielle Threat Model geht nur von einer begrenzten gegnerischen Überwachung der Kurzstrecken-Funkkommunikation aus; lokaler Funk ist daher nicht unsichtbar.<sup>[[5]](#references)</sup>

### Ablauf

1. Installiere die offizielle Briar-Distribution und überprüfe die Paketquelle. Verwende ein unterstütztes Android-Gerät mit aktuellen Sicherheitsupdates.
2. Erstelle ein lokales Konto mit einem eindeutigen kontextbezogenen Spitznamen und einem starken Passwort. Es gibt keinen Weg zum Zurücksetzen des Passworts; teste, ob das Entsperrgeheimnis wiederhergestellt werden kann.
3. Füge Kontakte möglichst persönlich hinzu, indem ihr gegenseitig eure QR-Codes scannt. Dadurch wird der Kontakt authentifiziert und das Senden eines Links über einen korrelierbaren Kanal vermieden.
4. Aktiviere in den Verbindungseinstellungen nur die benötigten Transporte: Tor/Internet, Wi-Fi und/oder Bluetooth. Deaktiviere lokale Funkmodule, wenn sie nicht benötigt werden.
5. Für asynchrone Zustellung solltest du Briar Mailbox auf einem dedizierten Gerät mit permanenter Stromversorgung evaluieren; erfasse es und schütze es physisch wie einen Nachrichtenserver.
6. Sende einen unkritischen Test, während das Internet verfügbar ist, und teste anschließend den geplanten Ausfallpfad mit deaktiviertem Internet an einem vom Eigentümer autorisierten Ort.
7. Überprüfe Android-Backups, Benachrichtigungsvorschauen, Screenshots und exportierte Inhalte. Der lokale verschlüsselte Speicher ist offengelegt, wenn der Endpoint entsperrt oder kompromittiert ist.
8. Entferne verlorene Kontakte/Geräte und beende den gesamten Kontext, wenn die physische Kontrolle oder das Kontopasswort kompromittiert wurde.

## OnionShare: direkte temporäre Übertragung

OnionShare führt einen Onion-Service auf dem Computer des Senders/Empfängers aus; Dateien werden nicht zu einem Storage-Provider hochgeladen, und der Datenverkehr ist innerhalb von Tor end-to-end verschlüsselt.<sup>[[6]](#references)</sup> Die vollständige Onion-URL ist eine Bearer-Capability und muss geschützt werden.

### GUI-Workflow zum Teilen von Dateien

1. Installiere OnionShare aus seiner offiziellen signierten Distribution sowie Tor Browser auf der Seite des Empfängers.
2. Lege **bereinigte Kopien** der Dateien in einem dedizierten Staging-Verzeichnis ab. Verweise OnionShare nicht auf ein persönliches Home-Verzeichnis.
3. Öffne **Dateien teilen**, füge nur die bereitgestellten Dateien hinzu, lasse den Schutz durch privaten Schlüssel/Zugriff aktiviert und aktiviere **Teilen beenden, nachdem Dateien gesendet wurden** für einen Empfänger.
4. Starte das Teilen und sende die vollständige Onion-URL über einen bereits authentifizierten E2EE-Kanal. Füge sie nicht in E-Mails, Issue-Tracker oder öffentliche Chats ein.
5. Der Empfänger öffnet die URL in Tor Browser, überprüft die erwarteten Dateinamen/die Größe mit dem Sender und lädt die Dateien herunter.
6. Beide Seiten vergleichen einen vorab vereinbarten oder separat übermittelten SHA-256-Digest auf Integrität, wenn die Datei selbst die Sicherheitsgrenze darstellt.
7. Bestätige, dass OnionShare nach dem Download beendet wurde; andernfalls beende es manuell und schließe die Anwendung.
8. Lösche die bereitgestellte Kopie gemäß der Aufbewahrungsrichtlinie und überprüfe die Verlaufs-/Log-Einstellungen von OnionShare auf unbeabsichtigte Offenlegung von Dateinamen.

### CLI-Workflow

Die offizielle CLI akzeptiert Dateien als Positionsargumente und beendet sich nach dem standardmäßig einzelnen abgeschlossenen Share. Auf einem Host mit installierter offizieller CLI/Tor-Installation:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Übermittle die resultierende vollständige URL sicher. Füge `--public`, `--no-autostop-sharing`, ausführliche Protokollierung von Dateinamen oder Persistenz nicht hinzu, es sei denn, das Bedrohungsmodell erfordert die daraus resultierende Offenlegung.<sup>[[7]](#references)</sup>

Behandle empfangene Dokumente als feindselig. Öffne sie in einer kurzlebigen VM bzw. einem Renderer im Dangerzone-Stil und nicht auf dem Host, der deine Identität trägt.

## Eine Datei unabhängig mit `age` verschlüsseln

Von Transportwegen unabhängige Verschlüsselung ist nützlich, wenn ein Speicher- oder E-Mail-Provider das Objekt sehen kann. Sie verbirgt weder Absender, Empfänger, Größe, Zeitpunkt noch Dateinamen, sofern diese nicht separat behandelt werden.

### Einrichtung des Empfängers
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Authentifizieren Sie die öffentliche Empfängerzeichenfolge über einen zweiten Kanal. Der Absender führt anschließend Folgendes aus:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Der Empfänger entschlüsselt in einen neuen Pfad:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Die offizielle CLI warnt, dass `-o` eine vorhandene Ausgabe überschreibt. Verwende daher ein neues Verzeichnis und überprüfe den Digest/Inhalt, bevor du sie verschiebst.<sup>[[8]](#references)</sup> Sende niemals die Identitätsdatei zusammen mit dem Ciphertext.

## Reproduzierbare Pipeline zur Dateibereinigung

Das Entfernen von Metadaten ist formatspezifisch. Bewahre ein verschlüsseltes Original auf, wenn Authentizität, Forensik oder Beweiskette wichtig sind, und arbeite mit einer Kopie.

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
Dies folgt ExifTools sichereren JPEG-Empfehlungen: Das blinde Entfernen jedes Tags kann auch Farbinformationen entfernen.<sup>[[9]](#references)</sup> Untersuchen Sie anschließend die Pixel visuell auf Gesichter, Spiegelungen, Bildschirme, Wahrzeichen und einzigartige Beschädigungs-/Rauschmuster.

### Office/PDF-Workflow

1. Bewahren Sie das bearbeitbare Original verschlüsselt und getrennt vom Veröffentlichungskontext offline auf.
2. Entfernen Sie Kommentare, nachverfolgte Änderungen, ausgeblendete Folien/Tabellenblätter, eingebettete Dateien, persönliche Vorlagen und Dokumenteigenschaften in der Authoring-Anwendung.
3. Exportieren Sie eine neue PDF aus einem dedizierten sauberen Profil; „drucken“ Sie nicht auf einen cloud printer.
4. Prüfen Sie die Datei sowohl mit formatbewussten Tools als auch mit einem visuellen Renderer zur einmaligen Verwendung:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Durchsuche die gerenderte Ausgabe nach Namen, Pfaden, E-Mail-Adressen und Revisionstext. Rasterisierung kann aktive Strukturen entfernen, beeinträchtigt jedoch Barrierefreiheit und Suchfunktionen und entfernt weder sichtbare Inhalte noch den Schreibstil.
6. Hash den finalen Datensatz und übertrage **nur** diese Kopie durch das Publication Compartment.

## Privacy Pass: anonyme Autorisierung für Service-Designer

Privacy Pass trennt die **Ausgabe** von Tokens von deren **Einlösung**. Ein Origin kann erfahren, dass ein Client ein vom Issuer genehmigtes Token besitzt, ohne die spezifische Interaktion des Clients bei der Ausgabe zu erfahren. Die Wiederverwendung eines Tokens sowie eindeutige Metadaten, Timing oder Kollusion können die Verknüpfbarkeit wiederherstellen.<sup>[[10]](#references)</sup>

Sicheres Deployment-Muster:

1. Definiere die Aussage, die das Token beweist (zum Beispiel die Berechtigung für Rate-Limiting), nicht eine verborgene globale Identität.
2. Verwende die standardisierte Architektur und die Issuance-Protokolle; implementiere keine Blind-Signature-Kryptografie von Grund auf selbst.
3. Trenne die Administration von Issuer/Attester und Origin, sofern die gewünschte Eigenschaft dies erfordert.
4. Minimiere öffentliche/private Token-Metadaten und stelle sicher, dass die Anonymity Sets groß genug sind.
5. Gib, sofern unterstützt, Batches vor der Nutzung aus, damit die Ausgabezeit nicht trivially mit der Einlösungszeit abgeglichen werden kann.
6. Löse jedes Token nur einmal ein, validiere die Origin-gebundene Challenge und lösche abgelaufenen Token-Zustand.
7. Verhindere, dass Cookies, IP-Logging und Application Accounts die Privacy-Eigenschaft des Tokens unbemerkt aushebeln.
8. Teste, ob Issuer- und Origin-Logs ein kontrolliertes Ausgabe- und Einlösungsereignis anhand von Timing, Metadaten oder eindeutigen Fehlern zusammenführen können.

Privacy Pass ist ein Application Feature und nichts, das ein Benutzer nachträglich an ein beliebiges Konto anbauen kann.

## Checkliste zur Kommunikationsverifizierung

- [ ] Kontakt/Einladung/Key wurde unabhängig authentifiziert.
- [ ] Die Offenlegung durch Telefonnummer, Username, Profil, Gruppe und Kontakt-Upload ist verstanden.
- [ ] Direkte IP-, Relay-, Tor-, Push-Provider- und lokale Funknetzwerk-Beobachter sind aufgelistet.
- [ ] Benachrichtigungsvorschauen, Wearables, verknüpfte Desktops und Backups wurden getestet.
- [ ] Dateien wurden bereinigt, bei Bedarf verschlüsselt und in einem Disposable Context geöffnet.
- [ ] Die Wiederherstellung funktioniert, ohne nicht zusammengehörige Identitäten zu verbinden.
- [ ] Für Logs, Verlauf und temporäre Share-Services gibt es eine Regel für Abschaltung/Aufbewahrung.

## References

- [1] [Signal — Datenschutz für Telefonnummern und Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Datenschutzrichtlinie und Nutzungsbedingungen](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Leitfaden zu Datenschutz und Sicherheit](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — So funktioniert es](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Sicherheitsdesign](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Erweiterte Nutzung und CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — offizielle CLI und Nutzung](https://github.com/FiloSottile/age)
- [9] [ExifTool-FAQ — Metadaten sicher entfernen](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy-Pass-Architektur](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
