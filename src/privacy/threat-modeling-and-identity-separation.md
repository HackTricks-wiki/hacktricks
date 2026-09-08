# Threat Modeling & Identitätstrennung

Der häufigste Fehler bei der Anonymität ist keine gebrochene Kryptografie. Es ist **Linkage**: Eine Kennung, ein Zeitmuster, ein Gerät, ein Account, eine Zahlung, eine Datei oder eine menschliche Gewohnheit verbindet zwei Kontexte, die eigentlich getrennt bleiben sollten.

## Ein Privacy-Threat-Model erstellen

EFFs Sicherheitsplan mit sechs Fragen ist eine solide Grundlage: Was muss geschützt werden, vor wem, welche Auswirkungen und Wahrscheinlichkeit hat ein Fehler, welcher Aufwand steht zur Verfügung und welche Verbündeten können helfen.<sup>[[1]](#references)</sup> Mache ihn mit einer kleinen Tabelle operativ:

| Asset/Aktion | Beobachter | Beobachtbare Daten | Korrelationsweg | Kontrolle | Verbleibendes Risiko |
|---|---|---|---|---|---|
| Recherche zu einem Kunden | ISP | Ziel-/Zeitmetadaten | Heimkunden-Datensatz | Tor Browser | Tor-Nutzung sichtbar; End-to-End-Korrelation |
| Pseudonymer Account | Plattform | IP, Browser, Recovery-Daten | Wiederverwendete Telefonnummer/E-Mail/Fotografie | Dedizierter Kontext und Alias | Korrelation durch Schreibstil/soziales Netzwerk |
| Online-Kauf | Händler | Account, Lieferung, tokenisierte Karte | Adresse und Account-Historie | Gast-Checkout, minimale Angaben, virtuelle Karte | Aussteller und Zusteller bewahren Datensätze auf |
| Red-Team-Traffic | Ziel/Kunde | Quell-IP und Verhalten | Provider-/Auftragsdatensätze | Dedizierter autorisierter Egress | Bei Eskalation absichtlich zuordenbar |

Überprüfe die Tabelle jedes Mal, wenn sich Standort, Provider, Gerät, Gegenpartei oder Konsequenzen ändern.

## Den Linkability-Graphen zeichnen

Behandle jede Identität als separaten Knoten. Füge für jedes gemeinsame Attribut eine Kante hinzu:

- E-Mail oder Recovery-Adresse;
- Telefonnummer oder Upload des Kontaktbuchs;
- Benutzername, Avatar, Foto, Biografie oder Schreib-/Code-Stil;
- Passwort, Passkey-Sync-Account oder Recovery-Frage;
- Gerät, Advertising-ID, Browserprofil, Cookies, Fonts oder Extensions;
- IP-Adresse, Zeitzone, Sprache, Zeitplan oder gleichzeitig aktiver Online-Status;
- Bankkarte, Exchange-Account, Wallet-Cluster, Lieferadresse oder Loyalty-Programm;
- Autorenfelder von Dokumenten, EXIF-Standort, Druckermarkierungen oder Besitzer eines Cloud-Shares;
- Kollege, Gruppenmitgliedschaft und soziales Netzwerk.

Eine Kante ist nicht automatisch fatal, aber sie zeigt dir, welcher Beobachter die Verbindung herstellen kann. EFF warnt ausdrücklich davor, dass Telefonnummern, E-Mail-Adressen und wiederverwendete Fotos Profile miteinander verknüpfen können.<sup>[[2]](#references)</sup>

## Ein Compartment Schritt für Schritt erstellen

1. **Benenne den Kontext und verbotene Verbindungen.** Beispiel: `client-red-2026`, verboten für persönliche E-Mail, private Browserprofile, persönliche Zahlungsmethoden und nicht verbundene Kunden.
2. **Wähle die Isolationsgrenze.** Mit zunehmender Stärke: separates Browserprofil → separates OS-Konto → separate VM/qube → dediziertes Gerät. Ein separater Tab oder ein privates Fenster ist keine Sicherheitsgrenze.
3. **Erstelle innerhalb dieser Grenze neue Kennungen.** Verwende eine kontextspezifische E-Mail/Alias, einen Benutzernamen, einen Passwort-Manager-Tresor oder eine Collection sowie Authentication Keys. Füge keinen persönlichen Recovery-Kanal hinzu, wenn Unlinkability gegenüber dem Provider wichtig ist.
4. **Wähle eine Netzwerk-Policy.** Entscheide, ob der Kontext immer ein Client-VPN, Engagement-VPS, vertrauenswürdiges VPN oder Tor verwendet. Erzwinge nach Möglichkeit fail-closed Routing.
5. **Wähle eine Zahlungs-Policy.** Die Zahlungsmethode muss zum Beobachtermodell passen; eine virtuelle Karte kann die PAN vor einem Händler verbergen, identifiziert den Kunden aber weiterhin gegenüber dem Aussteller.
6. **Lege Regeln für Datentransfers fest.** Bevorzuge eng begrenzte, bewusste Transfers. Behandle Clipboard, Shared Folders, USB-Geräte, Cloud-Sync, Drucker und Screenshots als mögliche Brücken.
7. **Dokumentiere Erstellungs- und Abbau-Daten.** Definiere, welche Nachweise für Verträge/Steuern/Compliance aufbewahrt werden müssen und welche flüchtigen Daten ablaufen sollen.
8. **Teste vor der Nutzung auf Verbindungen.** Prüfe Account-Einstellungen, Recovery-Felder, öffentliches Profil, IP/DNS, Browserzustand, Dateimetadaten und Provider-Dashboards.

{% hint style="warning" %}
Erfinde keine Identitätsangaben, wenn ein Dienst oder Gesetz eine korrekte Identifizierung verlangt. Ein Privacy-Compartment dient der Datenminimierung und Trennung, nicht Identitätsbetrug oder der Umgehung einer Customer Due Diligence.
{% endhint %}

## Endpoint- und Account-Baseline

- Verwende unterstützte Hardware und installiere zeitnah OS-, Browser-, Wallet- und Firmware-Updates.
- Aktiviere die Geräteverschlüsselung und verwende einen starken Geräte-Passcode. Verschlüsselung im Ruhezustand hilft, wenn ein ausgeschaltetes Gerät verloren geht oder beschlagnahmt wird, aber nicht, solange Malware oder eine entsperrte Session Daten lesen kann.<sup>[[3]](#references)</sup>
- Verwende einzigartige, zufällig generierte Passwörter in einem Passwort-Manager.
- Bevorzuge phishing-resistente Authentifizierung wie WebAuthn/passkeys oder Hardware-Security-Keys, sofern das Threat-Model deren Recovery-/Sync-Modell erlaubt. NIST weist darauf hin, dass manuell eingegebene OTPs nicht phishing-resistent sind, weil ein Angreifer sie weiterleiten kann.<sup>[[4]](#references)</sup>
- Bewahre Recovery-Codes offline und getrennt vom Endpoint auf. Prüfe, ob ein synchronisierter Passkey-Account Identitäten verbindet, die getrennt bleiben sollten.
- Deaktiviere unnötige Berechtigungen für Standort, Kontakte, Mikrofon, Kamera, Bluetooth, Advertising-ID und Hintergrundaktivität.
- Vermische persönlichen Cloud-Sync, Browser-Sync, Passwort-Manager-Accounts oder App-Stores nicht mit einem Kontext, der eine hohe Trennung erfordert.

## Browser-Privacy

Browser-Fingerprinting verwendet beobachtbare Konfigurationen, Geräte-, Umgebungs- und Verhaltensmerkmale, um einen Benutzer zu identifizieren oder zu korrelieren. Das Löschen von Cookies oder Ändern von IP-Adressen verhindert dies nicht zuverlässig, und das W3C hält eine vollständige technische Beseitigung durch weit verbreitete Mittel für unplausibel.<sup>[[5]](#references)</sup>

Für gewöhnliche Privacy:

1. Verwende einen gepflegten Browser mit HTTPS-only-Modus und starkem Tracking-Schutz.
2. Blockiere Third-Party-Tracking und partitioniere den Zustand, sofern unterstützt.
3. Verwende separate Browserprofile für tatsächlich getrennte Kontexte.
4. Deaktiviere nicht benötigte Berechtigungen und lösche Website-Daten nach einem festgelegten Zeitplan.
5. Vermeide es, dich während nicht zusammenhängender sensibler Recherche in Accounts mit umfangreichen Identitätsdaten einzuloggen.

Für Web-Anonymität verwende **Tor Browser in seiner Standardkonfiguration**. Leite keinen normalen Browser durch Tor: Das Tor Project warnt, dass gewöhnliche Browser durch DNS/WebRTC, dauerhaften Zustand, Fonts, Plugins und Fingerprint-Unterschiede leak können.<sup>[[6]](#references)</sup> Vermeide zusätzliche Extensions, ungewöhnliche Fenstergrößen, benutzerdefinierte Fonts und Einstellungen, durch die sich der Browser von anderen abhebt.<sup>[[7]](#references)</sup>

## Kommunikation und Metadaten

Metadaten umfassen Absender, Empfänger, Zeitpunkt, Standort und weiteren Kontext, selbst wenn der Nachrichteninhalt verschlüsselt ist.<sup>[[8]](#references)</sup>

- Bevorzuge Ende-zu-Ende-verschlüsselte Tools mit minimierten serverseitigen Metadaten und offenen Protokollen/Clients, sofern praktikabel.
- Verifiziere sensible Kontakte über einen unabhängigen Kanal oder persönlich. Signal Safety Numbers sind für diese Prüfung vorgesehen.<sup>[[9]](#references)</sup>
- Signal-Benutzernamen können den Kontaktaufbau ermöglichen, ohne eine Telefonnummer zu teilen; für die Registrierung ist jedoch weiterhin eine Telefonnummer erforderlich. Konfiguriere die Sichtbarkeit und Auffindbarkeit der Telefonnummer bewusst.<sup>[[9]](#references)</sup>
- Verschwindende Nachrichten reduzieren gespeicherte Kopien; Empfänger können Inhalte weiterhin fotografieren, kopieren, weiterleiten oder archivieren.
- E-Mail legt normalerweise Routing-Metadaten offen. Selbst Privacy-orientierte Provider können eine Nachricht nicht Ende-zu-Ende-verschlüsseln, wenn die andere Seite gewöhnliche E-Mail verwendet, sofern nicht beide Parteien eine kompatible E2EE-Methode einsetzen. Proton dokumentiert beispielsweise, dass gewöhnliche E-Mails an andere Provider TLS verwenden und für den empfangenden Provider lesbar bleiben.<sup>[[10]](#references)</sup>
- Trenne Adressbücher und lade keine persönlichen Kontakte in einen pseudonymen Account hoch.

## Dateien, Fotos und Urheberschaft

Tails warnt, dass Fotos Kamera- und Standortdaten enthalten können und Office-Dokumente Autoren- und Erstellungszeitfelder enthalten können.<sup>[[11]](#references)</sup>

Vor dem Teilen:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Öffne anschließend die bereinigte Kopie erneut in einem isolierten Viewer und überprüfe:

- Dokumenteigenschaften, Kommentare, nachverfolgte Änderungen, ausgeblendete Tabellenblätter/Folien, Miniaturansichten und Anhänge;
- EXIF/XMP/IPTC, GPS, Zeitstempel, Geräte-/Softwarenamen und eindeutige IDs;
- sichtbare Spiegelungen, markante Orte, Bildschirminhalte, Stimmen, Gesichter und Hintergrundgeräusche;
- Dateiname, Archivpfade, Besitzer der Cloud-Freigabe, Signaturzertifikat und Revisionsverlauf.

Sanitization kann Beweise oder Authentizität beschädigen. Bewahre ein verschlüsseltes Original auf, wenn die Beweiskette oder eine spätere Verifizierung wichtig ist. Stylometrie und Coding Style können ebenfalls die Urheberschaft verknüpfen; das Entfernen von Metadaten verändert den menschlichen Stil nicht.

## Häufige Fehlermuster

- Anmeldung bei einem persönlichen Konto über eine „anonyme“ Verbindung.
- Wiederverwendung einer Wiederherstellungs-Telefonnummer, eines Avatars, Benutzernamens, öffentlichen Schlüssels, Wallets oder einer Spendenadresse.
- Gleichzeitiger Betrieb zweier Identitäten aus korrelierten Kontexten.
- Kopieren von Text/Dateien über eine persönliche Cloud-Zwischenablage oder einen geteilten Ordner.
- Installation charakteristischer Tor Browser-Erweiterungen oder Änderung vieler Standardeinstellungen.
- Vertrauen auf die Behauptung „keine Logs“, ohne zu verstehen, was protokolliert wird, wie lange und durch welche Subunternehmer.
- Annahme, dass ein sekundäres Telefon anonym ist, während es zusammen mit einem persönlichen Telefon unterwegs ist. Die EFF weist darauf hin, dass Mobilfunkstandort und gemeinsames Unterwegssein die Geräte miteinander korrelieren können.<sup>[[3]](#references)</sup>
- Behandlung von Verschlüsselung als Löschung; Endpunkte und Empfänger können Klartext behalten.

## Verifizierungs-Checkliste

- [ ] Der Kontext enthält keine persönliche Wiederherstellungsadresse, Telefonnummer, kein Sync-Konto und keine wiederverwendeten Medien, sofern dies nicht bewusst akzeptiert wurde.
- [ ] Der vorgesehene Netzwerkpfad ist aktiv und schlägt geschlossen fehl.
- [ ] Zeitzone, Regionseinstellungen, Erweiterungen und Berechtigungen von Browser/Gerät entsprechen dem Plan.
- [ ] Im Compartment sind keine persönlichen Konten geöffnet.
- [ ] Dateien wurden überprüft und bereinigt; Originale werden separat behandelt.
- [ ] Kontakte werden über einen zweiten Kanal authentifiziert.
- [ ] Die für den Anbieter sichtbaren Metadaten und der Aufbewahrungszeitraum sind bekannt.
- [ ] Abbau, Beweissicherung und Verfahren zur Kontowiederherstellung sind dokumentiert.

## References

- [1] [EFF Surveillance Self-Defense — Dein Sicherheitsplan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Schutz in sozialen Netzwerken](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Teilnahme an einer Protestveranstaltung](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentifizierung und Verwaltung von Authentifikatoren](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Minderung von Browser-Fingerprinting in Web-Spezifikationen](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Tor mit anderen Browsern verwenden](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins und Add-ons im Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Warum Kommunikationsmetadaten wichtig sind](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Datenschutz bei Telefonnummern und Benutzernamen: Vertiefung](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Was wird innerhalb von Proton Mail verschlüsselt?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnungen: Tails ist sicher, aber kein Zauber](https://tails.net/doc/about/warnings/index.en.html)
