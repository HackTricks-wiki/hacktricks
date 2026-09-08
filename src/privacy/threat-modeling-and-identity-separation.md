# Bedrohungsmodellierung & Identitätstrennung

{{#include ../banners/hacktricks-training.md}}

Der häufigste Fehler bei der Anonymität ist keine fehlerhafte Kryptografie. Es ist die **Verknüpfbarkeit**: Eine Kennung, ein Zeitmuster, ein Gerät, ein Konto, eine Zahlung, eine Datei oder menschliche Gewohnheit verbindet zwei Kontexte, die eigentlich getrennt bleiben sollten.

## Ein Datenschutz-Bedrohungsmodell erstellen

Der Sicherheitsplan mit sechs Fragen der EFF ist eine gute Grundlage: Was muss geschützt werden, vor wem, welche Auswirkungen und Wahrscheinlichkeit hat ein Fehlschlag, welcher Aufwand steht zur Verfügung und welche Unterstützer können helfen.<sup>[[1]](#references)</sup> Machen Sie ihn mit einer kleinen Tabelle operationalisierbar:

| Asset/Aktion | Beobachter | Beobachtbare Daten | Weg zur Korrelation | Kontrolle | Restrisiko |
|---|---|---|---|---|---|
| Recherche zu einem Kunden | ISP | Ziel-/Zeitmetadaten | Heimanschluss-Datensatz | Tor Browser | Tor-Nutzung sichtbar; Ende-zu-Ende-Korrelation |
| Pseudonymes Konto | Plattform | IP, Browser, Wiederherstellungsdaten | Wiederverwendete Telefonnummer/E-Mail/Fotografie | Dedizierter Kontext und Alias | Korrelation durch Schreibstil/soziales Netzwerk |
| Online-Kauf | Händler | Konto, Lieferung, tokenisierte Karte | Adresse und Kontohistorie | Gast-Checkout, minimale Felder, virtuelle Karte | Herausgeber und Versanddienstleister behalten Datensätze |
| Red-Team-Datenverkehr | Ziel/Kunde | Quell-IP und Verhalten | Provider-/Auftragsdatensätze | Dedizierter autorisierter Egress | Bei Eskalation absichtlich zuordenbar |

Überprüfen Sie die Tabelle jedes Mal, wenn sich Standort, Provider, Gerät, Gegenpartei oder Konsequenzen ändern.

## Den Verknüpfbarkeitsgraphen zeichnen

Behandeln Sie jede Identität als separaten Knoten. Fügen Sie für jedes gemeinsame Attribut eine Kante hinzu:

- E-Mail- oder Wiederherstellungsadresse;
- Telefonnummer oder Upload des Kontaktbuchs;
- Benutzername, Avatar, Foto, Biografie oder Schreib-/Code-Stil;
- Passwort, Passkey-Sync-Konto oder Sicherheitsfrage;
- Gerät, Advertising-ID, Browserprofil, Cookies, Fonts oder Extensions;
- IP-Adresse, Zeitzone, Sprache, Zeitplan oder gleichzeitig aktiver Online-Status;
- Bankkarte, Exchange-Konto, Wallet-Cluster, Lieferadresse oder Treueprogramm;
- Autorenfelder des Dokuments, EXIF-Standort, Druckermarkierungen oder Besitzer einer Cloud-Freigabe;
- Kollege, Gruppenmitgliedschaft und soziales Netzwerk.

Eine Kante ist nicht automatisch fatal, aber sie zeigt, welcher Beobachter die Verbindung herstellen kann. Die EFF warnt ausdrücklich davor, dass Telefonnummern, E-Mail-Adressen und wiederverwendete Fotos Profile miteinander verknüpfen können.<sup>[[2]](#references)</sup>

## Eine Compartment Schritt für Schritt erstellen

1. **Kontext und verbotene Verknüpfungen benennen.** Beispiel: `client-red-2026`, darf nicht mit persönlicher E-Mail, Browserprofilen des Heimgeräts, persönlichen Zahlungsmethoden oder nicht verwandten Kunden verbunden werden.
2. **Die Isolationsgrenze wählen.** Mit zunehmender Stärke: separates Browserprofil → separates OS-Konto → separate VM/qube → dediziertes Gerät. Ein separater Tab oder ein privates Fenster ist keine Sicherheitsgrenze.
3. **Frische Kennungen innerhalb dieser Grenze erstellen.** Verwenden Sie eine kontextspezifische E-Mail/Alias, einen Benutzernamen, ein Passwort-Manager-Vault oder eine Sammlung sowie Authentifizierungsschlüssel. Fügen Sie keinen persönlichen Wiederherstellungskanal hinzu, wenn die Unverknüpfbarkeit gegenüber dem Provider wichtig ist.
4. **Eine Netzwerkregel festlegen.** Entscheiden Sie, ob der Kontext immer ein Kunden-VPN, einen Engagement-VPS, ein vertrauenswürdiges VPN oder Tor verwendet. Erzwingen Sie nach Möglichkeit ein Fail-closed-Routing.
5. **Eine Zahlungsregel festlegen.** Die Zahlungsmethode muss zum Beobachtermodell passen; eine virtuelle Karte kann die PAN vor einem Händler verbergen, identifiziert den Kunden aber weiterhin gegenüber dem Herausgeber.
6. **Regeln für Datenübertragungen festlegen.** Bevorzugen Sie eng begrenzte, bewusste Übertragungen. Behandeln Sie Zwischenablage, freigegebene Ordner, USB-Geräte, Cloud-Sync, Drucker und Screenshots als mögliche Brücken.
7. **Erstellungs- und Abbauzeitpunkte dokumentieren.** Legen Sie fest, welche Nachweise für Verträge/Steuern/Compliance aufbewahrt werden müssen und welche temporären Daten ablaufen sollen.
8. **Vor der Nutzung auf Verknüpfungen testen.** Prüfen Sie Kontoeinstellungen, Wiederherstellungsfelder, öffentliche Profile, IP/DNS, Browserzustand, Dateimetadaten und Provider-Dashboards.

{% hint style="warning" %}
Erfinden Sie keine Identitätsinformationen, wenn ein Dienst oder Gesetz eine korrekte Identifizierung verlangt. Ein Privacy-Compartment dient der Datenminimierung und Trennung, nicht Identitätsbetrug oder der Umgehung der Customer Due Diligence.
{% endhint %}

## Endpoint- und Konto-Baseline

- Verwenden Sie unterstützte Hardware und installieren Sie zeitnah Updates für OS, Browser, Wallet und Firmware.
- Aktivieren Sie die Geräteverschlüsselung und verwenden Sie einen starken Gerätecode. Verschlüsselung im Ruhezustand hilft, wenn ein ausgeschaltetes Gerät verloren geht oder beschlagnahmt wird, aber nicht, solange Malware oder eine entsperrte Sitzung Daten lesen kann.<sup>[[3]](#references)</sup>
- Verwenden Sie eindeutige, zufällig generierte Passwörter in einem Passwort-Manager.
- Bevorzugen Sie phishing-resistente Authentifizierung wie WebAuthn/Passkeys oder Hardware-Sicherheitsschlüssel, sofern das Bedrohungsmodell deren Wiederherstellungs-/Sync-Modell zulässt. NIST weist darauf hin, dass manuell eingegebene OTPs nicht phishing-resistent sind, weil ein Angreifer sie weiterleiten kann.<sup>[[4]](#references)</sup>
- Bewahren Sie Wiederherstellungscodes offline und getrennt vom Endpoint auf. Prüfen Sie, ob ein synchronisiertes Passkey-Konto Identitäten miteinander verbindet, die getrennt bleiben sollten.
- Deaktivieren Sie unnötige Berechtigungen für Standort, Kontakte, Mikrofon, Kamera, Bluetooth, Advertising-ID und Hintergrundaktivität.
- Mischen Sie persönliche Cloud-Synchronisierung, Browser-Sync, Passwort-Manager-Konten oder App-Stores nicht in einen Kontext mit hoher Trennung.

## Browser-Datenschutz

Browser-Fingerprinting verwendet beobachtbare Konfigurationen, Geräte-, Umgebungs- und Verhaltensmerkmale, um einen Nutzer zu identifizieren oder zu korrelieren. Das Löschen von Cookies oder Ändern von IP-Adressen verhindert dies nicht zuverlässig, und das W3C hält eine vollständige technische Beseitigung mit weit verbreiteten Mitteln für unrealistisch.<sup>[[5]](#references)</sup>

Für gewöhnlichen Datenschutz:

1. Verwenden Sie einen gepflegten Browser mit HTTPS-only-Modus und starkem Tracking-Schutz.
2. Blockieren Sie Tracking durch Dritte und partitionieren Sie Zustände, sofern unterstützt.
3. Verwenden Sie separate Browserprofile für tatsächlich getrennte Kontexte.
4. Deaktivieren Sie nicht benötigte Berechtigungen und löschen Sie Website-Daten nach einem festgelegten Zeitplan.
5. Vermeiden Sie die Anmeldung bei kontenreichen Identitäten, während Sie unabhängige sensible Recherchen durchführen.

Für Web-Anonymität verwenden Sie **Tor Browser in seiner Standardkonfiguration**. Leiten Sie keinen normalen Browser über Tor weiter: Das Tor Project warnt, dass gewöhnliche Browser über DNS/WebRTC, dauerhaften Zustand, Fonts, Plugins und Unterschiede beim Fingerprinting leaken können.<sup>[[6]](#references)</sup> Vermeiden Sie zusätzliche Extensions, ungewöhnliche Fenstergrößen, benutzerdefinierte Fonts und Einstellungen, durch die sich der Browser abhebt.<sup>[[7]](#references)</sup>

## Kommunikation und Metadaten

Metadaten umfassen Absender, Empfänger, Zeitpunkt, Standort und weiteren Kontext, selbst wenn der Nachrichteninhalt verschlüsselt ist.<sup>[[8]](#references)</sup>

- Bevorzugen Sie Ende-zu-Ende-verschlüsselte Tools mit minimierten serverseitigen Metadaten und, wo praktikabel, offenen Protokollen/Clients.
- Verifizieren Sie sensible Kontakte über einen unabhängigen Kanal oder persönlich. Die Sicherheitsnummern von Signal sind für diese Prüfung vorgesehen.<sup>[[9]](#references)</sup>
- Signal-Benutzernamen können den Kontaktaufbau ermöglichen, ohne eine Telefonnummer zu teilen; für die Registrierung ist jedoch weiterhin eine Telefonnummer erforderlich. Konfigurieren Sie die Sichtbarkeit und Auffindbarkeit der Telefonnummer bewusst.<sup>[[9]](#references)</sup>
- Verschwindende Nachrichten reduzieren gespeicherte Kopien; Empfänger können Inhalte weiterhin fotografieren, kopieren, weiterleiten oder archivieren.
- E-Mail legt normalerweise Routing-Metadaten offen. Selbst datenschutzorientierte Provider können eine Nachricht nicht Ende-zu-Ende-verschlüsseln, wenn die andere Seite gewöhnliche E-Mail verwendet, sofern nicht beide Parteien eine kompatible E2EE-Methode nutzen. Proton dokumentiert beispielsweise, dass gewöhnliche Nachrichten an andere Provider TLS verwenden und für den empfangenden Provider lesbar bleiben.<sup>[[10]](#references)</sup>
- Trennen Sie Adressbücher und laden Sie keine persönlichen Kontakte in ein pseudonymes Konto hoch.

## Dateien, Fotos und Urheberschaft

Tails warnt, dass Fotos Kamera- und Standortdaten enthalten können und Office-Dokumente Autoren- und Erstellungszeitfelder enthalten können.<sup>[[11]](#references)</sup>

Vor dem Teilen:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Dann öffnen Sie die bereinigte Kopie erneut in einem isolierten Viewer und prüfen Sie:

- Dokumenteigenschaften, Kommentare, nachverfolgte Änderungen, ausgeblendete Tabellenblätter/Folien, Miniaturansichten und Anhänge;
- EXIF/XMP/IPTC, GPS, Zeitstempel, Geräte-/Softwarenamen und eindeutige IDs;
- sichtbare Spiegelungen, Orientierungspunkte, Bildschirminhalte, Stimmen, Gesichter und Hintergrundgeräusche;
- Dateiname, Archivpfade, Inhaber der Cloud-Freigabe, Signaturzertifikat und Revisionsverlauf.

Die Bereinigung kann Beweise oder Authentizität beschädigen. Bewahren Sie ein verschlüsseltes Original auf, wenn die Beweiskette oder eine spätere Überprüfung wichtig ist. Stylometrie und coding style können ebenfalls die Urheberschaft verknüpfen; das Entfernen von Metadaten ändert den menschlichen Stil nicht.

## Häufige Fehlermuster

- Anmeldung bei einem persönlichen Konto über eine „anonymous“ Verbindung.
- Wiederverwendung einer Wiederherstellungs-Telefonnummer, eines Avatars, Benutzernamens, Public Keys, Wallets oder einer Spendenadresse.
- Gleichzeitiger Betrieb zweier Identitäten aus korrelierten Kontexten.
- Kopieren von Texten/Dateien über eine persönliche Cloud-Zwischenablage oder einen freigegebenen Ordner.
- Installation markanter Tor Browser-Erweiterungen oder Änderung vieler Standardeinstellungen.
- Vertrauen auf die Behauptung „keine Logs“, ohne zu verstehen, was protokolliert wird, wie lange und von welchen Subunternehmern.
- Annahme, dass ein Zweittelefon anonym ist, während es zusammen mit einem persönlichen Telefon unterwegs ist. Die EFF weist darauf hin, dass Mobilfunkstandort und gemeinsames Reisen die Geräte korrelieren können.<sup>[[3]](#references)</sup>
- Verschlüsselung als Löschung behandeln; Endpunkte und Empfänger können Klartext behalten.

## Verifizierungs-Checkliste

- [ ] Der Kontext enthält keine persönliche Wiederherstellungsadresse, Telefonnummer, kein Sync-Konto und keine wiederverwendeten Medien, sofern dies nicht bewusst akzeptiert wurde.
- [ ] Der vorgesehene Netzwerkpfad ist aktiv und fällt bei Fehlern geschlossen aus.
- [ ] Zeitzone, Locale, Erweiterungen und Berechtigungen des Browsers/Geräts entsprechen dem Plan.
- [ ] Im Compartment sind keine persönlichen Konten geöffnet.
- [ ] Dateien wurden geprüft und bereinigt; Originale werden separat behandelt.
- [ ] Kontakte werden über einen zweiten Kanal authentifiziert.
- [ ] Die für den Anbieter sichtbaren Metadaten und die Aufbewahrungsdauer sind bekannt.
- [ ] Verfahren für Teardown, Beweissicherung und Kontowiederherstellung sind dokumentiert.

## References

- [1] [EFF Surveillance Self-Defense — Ihr Sicherheitsplan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Schutz Ihrer Identität in sozialen Netzwerken](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Teilnahme an einer Demonstration](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentifizierung und Verwaltung von Authentifikatoren](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Minderung von Browser-Fingerprinting in Web-Spezifikationen](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Tor mit anderen Browsern verwenden](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins und Add-ons im Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Warum Kommunikationsmetadaten wichtig sind](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Datenschutz von Telefonnummern und Benutzernamen: Vertiefung](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Was ist in Proton Mail verschlüsselt?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnungen: Tails ist sicher, aber kein Zauber](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
