# Playbooks für operative Privatsphäre

{{#include ../banners/hacktricks-training.md}}

Diese Playbooks kombinieren die Kontrollen aus dem restlichen Abschnitt. Sie sind Ausgangspunkte, keine Garantien: Aktualisieren Sie das Threat Model jedes Mal, wenn ein neuer Beobachter, Account, ein neues Gerät, ein neuer Standort, eine neue Zahlung, Datei oder Gegenpartei in den Workflow gelangt.

## Universeller Preflight

1. Formulieren Sie das legitime Ziel und was **vor wem** privat bleiben muss.
2. Erfassen Sie die Identitäten, Geräte, Netzwerke, Accounts, Zahlungswege, Gegenparteien, physischen Standorte und Daten, mit denen die Aktivität in Berührung kommt.
3. Identifizieren Sie den wahrscheinlich stärksten Beobachter und die Konsequenzen eines Fehlschlags.
4. Bestätigen Sie die Autorisierung, geltendes Recht, Providerbedingungen und organisatorischen Richtlinien.
5. Entscheiden Sie, was aus Sicherheits-, Incident-Response-, Buchhaltungs- und Audit-Gründen intern zuordenbar bleiben muss.
6. Wählen Sie das kleinste praktikable Compartment; richten Sie dessen Wiederherstellungs- und Abschaltpfade vor der Nutzung ein.
7. Testen Sie das Compartment gegen einen kontrollierten Service, einschließlich IP/DNS/IPv6, Browseridentität, Dokumentmetadaten, Zahlungsabrechnung und Notification-Leaks.

Verwenden Sie das detaillierte Modell in [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Grundlage für alltägliche Privatsphäre

Ziel: kommerzielles Tracking, Account-Übernahmen und unnötige Offenlegung reduzieren, ohne zu versuchen, anonym zu werden.

- Verwenden Sie ein gepflegtes OS mit Full-Disk Encryption, automatischen Updates, Bildschirmsperre und, sofern verfügbar, Secure Boot.
- Richten Sie zuerst Passwortmanager, Recovery-E-Mail und phishing-resistente MFA/Security Keys ein.
- Überprüfen Sie App-Berechtigungen, Standortverlauf, Werbe-IDs, Cloud-Sync und Verbindungen zu Drittanbieter-Accounts.
- Verwenden Sie einen verbreiteten Browser mit wenigen Extensions, Tracking-Schutz und HTTPS sowie getrennten Profilen für Arbeits-, private und risikoreiche Nutzung.
- Verwenden Sie Private-Relay-Aliase oder je nach Beziehung unterschiedliche E-Mail-Adressen; verwenden Sie keine persönliche Telefonnummer, wenn sie lediglich optional ist.
- Bevorzugen Sie für Inhalte Ende-zu-Ende-verschlüsselte Nachrichten, bedenken Sie jedoch, dass Teilnehmer, Zeitpunkte, Gruppen und Endpunkte weiterhin Metadaten darstellen.
- Entfernen Sie Metadaten bewusst aus Dateien und prüfen Sie vor der Veröffentlichung die exportierte Kopie – nicht das Original.
- Verwenden Sie Virtual-Card- oder Wallet-Tokens zur Trennung von Zahlungsdaten; bezeichnen Sie sie nicht als anonym.
- Sichern Sie verschlüsseltes Recovery-Material und testen Sie die Wiederherstellung.

## Pseudonyme Veröffentlichung

Ziel: Verhindern, dass Leser und Plattformen eine Veröffentlichung trivial mit einer bürgerlichen Identität verknüpfen können. Dies vereitelt keine leistungsfähige, gezielte Untersuchung.

1. Legen Sie fest, ob die Plattform, der Hosting-Provider, Leser, Kontakte, das lokale Netzwerk, der Zahlungsanbieter oder ein rechtliches Verfahren Teil des Threat Models sind.
2. Erstellen Sie ausgehend von einer sauberen Ausgangsbasis einen dedizierten Endpunkt-/Account-Kontext. Deaktivieren Sie persönliche Browser-Synchronisierung, Cloud-Dokumente, den Upload von Kontakten und Notification-Vorschauen.
3. Erstellen Sie den pseudonymen Account über das gewählte Netzwerk-Compartment. Verwenden Sie keine Benutzernamen, Avatare, Recovery-Kanäle, Schreibvorlagen oder persönlichen Login-Daten eines Identity Providers erneut.
4. Verwenden Sie Tor Browser, wenn die Unverknüpfbarkeit des Ziels wichtiger als die Geschwindigkeit ist; fügen Sie keine Extensions hinzu, ändern Sie die Größe oder Konfiguration nicht stark und öffnen Sie heruntergeladene Dokumente nicht online in einer gewöhnlichen Desktop-Sitzung.
5. Verfassen Sie Inhalte mit einem Prozess, der keine persönlichen Vorlagennamen, Änderungsautoren, Druckerpfade, GPS/EXIF-Daten, Thumbnails oder verborgenen Ebenen einbettet. Exportieren Sie eine Kopie und prüfen Sie sie mit geeigneten Metadaten-Tools.
6. Prüfen Sie Inhalte auf selbstidentifizierende Fakten: einzigartige Daten, Details zum Arbeitsplatz, lokales Wetter/Zeitzone, Spiegelungen, Hintergrundaudio, sprachliche Gewohnheiten und die Wiederverwendung zuvor veröffentlichter Texte.
7. Verwenden Sie einen separaten Reply-Kanal. Behandeln Sie jeden direkten Kontakt, Anhang und Link als potenziellen Korrelations- oder Phishing-Versuch.
8. Wenn Geld involviert ist, verwenden Sie die rechtmäßige Methode, die nur die notwendigen Daten offenlegt. Gehen Sie davon aus, dass die Plattform und der regulierte Intermediär den Zahlungsempfänger kennen können, selbst wenn Leser dies nicht tun.
9. Veröffentlichen Sie und prüfen Sie anschließend das öffentliche Ergebnis aus einem anderen sauberen Kontext. Dokumentieren Sie, was die Plattform hinzugefügt oder verändert hat.
10. Behalten Sie einen geplanten Veröffentlichungsrhythmus nur bei, wenn dadurch kein stabiles Verhaltensprofil entsteht; geben Sie das Compartment auf, statt es stillschweigend für andere Zwecke weiterzuverwenden.

Für ernsthaften Journalismus, Aktivismus, häusliche Gewalt oder Risiken auf staatlicher Ebene sollten Sie maßgeschneiderte Hilfe von einer erfahrenen Organisation für digitale Sicherheit einholen; eine statische Checkliste kann lokale Gesetze oder einen aktiven Gegner nicht modellieren.

## Autorisiertes Red-Team-Engagement

Ziel: Die persönlichen Identitäten und Heimnetzwerke der Operator aus der Telemetrie des Ziels heraushalten und gleichzeitig Autorisierung, Kontrolle und Incident Response gewährleisten.

### Vor dem Startfenster

- Schließen Sie den Infrastruktur-Anhang des ROE, Ziele/Ausschlüsse, Quellbereiche, Zeiträume, Notabschaltung sowie Berechtigungen von Drittanbietern/Providern ab.
- Weisen Sie ein dediziertes Operator-Profil oder eine VM, Engagement-Secrets, einen Evidence Store, ein Cloud-Projekt, Domains und ein Budget zu.
- Bevorzugen Sie vom Client bereitgestellten Egress oder einen von der Organisation kontrollierten festen Bastion Host. Testen Sie das Verhalten von Full-Tunnel IPv4/IPv6/DNS sowie die Fail-Closed-Richtlinie.
- Hinterlegen Sie die Zuordnung zwischen Operator und öffentlicher Infrastruktur beim Exercise Controller oder einem vereinbarten Escrow-Kontakt.
- Richten Sie Rate Limits, Destination Allowlists und eine separate Genehmigung für destruktive, Wireless-, physische, Phishing- oder Credential-Collection-Aktionen ein.
- Verwenden Sie einen von der Organisation kontrollierten Zahlungsweg und dokumentieren Sie die Genehmigungen intern.

### Während des Engagements

- Starten Sie vom genehmigten Endpunkt und Tunnel; überprüfen Sie den beobachteten Egress vor Assessment-Traffic.
- Halten Sie persönliche Accounts, Geräte, Telefonnummern, Repositories, SSH/GPG-Keys und Cloud-Sync aus dem Compartment heraus.
- Protokollieren Sie Operator/Job, Start/Stopp, Quelle, Ziel im Scope und Konfigurationsänderungen, ohne unnötige Client-Inhalte zu erfassen.
- Stoppen Sie bei unklarem Scope, unerwarteten Systemen Dritter, Provider-Missbrauchsmeldungen, Sicherheitsauswirkungen, verlorenem Equipment oder abgebrochenem Kontakt zum Controller.
- Improvisieren Sie niemals mit dem WLAN eines Nachbarn, gestohlenen Credentials, einer nicht genehmigten SIM/einem nicht genehmigten Account oder an einem Veranstaltungsort versteckter Hardware.

### Ende des Engagements

- Stoppen Sie Jobs und C2; holen Sie genehmigte Drop-Geräte zurück; widerrufen Sie Tokens, Credentials und Zertifikate.
- Gleichen Sie Infrastruktur, Domains, Quelladressen, Ausgaben, Daten und Provider-Fälle mit dem Inventar ab.
- Geben Sie Client-Daten vertragsgemäß zurück, löschen oder bewahren Sie sie entsprechend auf, sichern Sie die minimal erforderlichen Audit-Nachweise und lassen Sie die Abschaltung von einem zweiten Operator überprüfen.

Siehe [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) für die vollständige Anleitung zu Aufbau und Abbau.

## Rechtmäßiger privater Kauf oder Spende

Ziel: Die Offenlegung gegenüber Händler oder Öffentlichkeit minimieren und gleichzeitig Pflichten gegenüber Herausgeber, Buchhaltung, Steuer- und Sanktionsvorschriften erfüllen.

1. Führen Sie auf, wer was nicht erfahren darf: die Öffentlichkeit, der Händler, der Zahlungsintermediär, der Arbeitgeber/Familien-Account-Delegierte, der Lieferdienst oder ein Blockchain-Beobachter.
2. Prüfen Sie lokale Vorschriften, den Empfänger/die Gegenpartei, Providerbedingungen, Bargeldlimits und Anforderungen an die Aufbewahrung von Aufzeichnungen.
3. Wählen Sie den Zahlungsweg:
- Bargeld für akzeptierte rechtmäßige lokale Zahlungen ohne Aufzeichnung im Zahlungsnetzwerk;
- eine regulierte Virtual Card oder händlerspezifische Karte zur Trennung von Online-Zahlungsdaten;
- Cryptocurrency erst nach Analyse von Erwerb, Ledger, Wallet-Backend, Netzwerk, Gegenpartei und späteren Ausgabenverknüpfungen.
4. Verwenden Sie wahrheitsgemäße erforderliche Angaben und lassen Sie nur optionale Loyalty-/Marketing-Informationen weg. Verwenden Sie nicht die Identität oder Adresse einer anderen Person und teilen Sie eine Transaktion nicht auf, um einen Schwellenwert zu umgehen.
5. Trennen Sie den Browser-/Account-Kontext des Händlers und vermeiden Sie nicht zugehörige Social-Logins, Loyalty- oder persönlichen Recovery-Kanäle.
6. Bestätigen Sie, was auf Abrechnungen, Belegen, Notifications, Versandunterlagen und öffentlichen Spenderlisten erscheint.
7. Speichern Sie erforderliche Beleg-, Steuer- und Autorisierungsnachweise verschlüsselt; widerrufen Sie Wegwerf-Zahlungs-Credentials nach Ablauf des Erstattungszeitraums.

Siehe [Private Digital Payments](private-digital-payments.md) und [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Reisen und nicht vertrauenswürdige Netzwerke

Ziel: Daten und Accounts in Netzwerken schützen, die nicht vom Benutzer verwaltet werden – nicht, um unautorisierte Aktivitäten zu verschleiern.

- Aktualisieren Sie Geräte und laden Sie benötigte Credentials/Karten vor der Reise herunter.
- Minimieren Sie gespeicherte Daten; verwenden Sie Full-Disk Encryption, eine starke Entsperrung, Remote-Recovery-Planung und je nach Rechtsberatung Verfahren für ausgeschaltete Geräte an Grenzen bzw. bei physischen Risiken.
- Überprüfen Sie die Venue-SSID/das Captive Portal. Bevorzugen Sie gegebenenfalls einen persönlichen Hotspot, bedenken Sie jedoch die Subscriber- und Standortaufzeichnungen des Mobilfunknetzes.
- Verwenden Sie für Organisationsdaten ein vollständiges/erzwungenes genehmigtes VPN; überprüfen Sie, ob verbundene Geräte dieses ebenfalls verwenden, und testen Sie das Verhalten von IPv6/DNS.
- Verwenden Sie einen Travel Router zur Client-Isolation und für wiederholbare Richtlinien, nicht als Garantie für Anonymität.
- Behandeln Sie öffentliches USB-Laden, geliehene Computer, öffentliche Drucker und gemeinsam genutzte Systeme in Besprechungsräumen als separate Bedrohungen.
- Gehen Sie davon aus, dass physische Anwesenheit, Funk-IDs, Portal-Login, Kameras sowie Zahlungs- und Standortaufzeichnungen den Besuch korrelieren können.

Vergleich und Einrichtungsdetails finden Sie unter [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Reaktion auf Fehler und Offenlegung

Wenn ein Compartment leakt oder möglicherweise verknüpft wurde:

1. Stoppen Sie die Aktivität, wenn eine Fortsetzung den Schaden vergrößert; verwenden Sie gegebenenfalls die Notabschaltung des Engagements.
2. Sichern Sie erforderliche Beweise, ohne sensible Daten weiterzuverbreiten. Dokumentieren Sie die genaue Uhrzeit, den beobachteten Indikator und die betroffenen Assets.
3. Benachrichtigen Sie den zuständigen Owner/Controller/Security-Kontakt. Verheimlichen Sie keinen Incident, um eine Privatsphäre-Erzählung aufrechtzuerhalten.
4. Widerrufen Sie Sessions, Tokens, Zahlungs-Credentials und Infrastrukturzugriffe; rotieren Sie Secrets von einem bekanntermaßen sauberen Endpunkt aus.
5. Ermitteln Sie, welche Kanten die Verknüpfung hergestellt haben: Endpunkt, Account-Recovery, Netzwerk, Zahlung, Metadaten, Inhalt, Verhalten, Gegenpartei oder physische Anwesenheit.
6. Betrachten Sie das gesamte betroffene Compartment als verbrannt. Ändern Sie nicht lediglich seinen Benutzernamen oder die Exit-IP.
7. Erfüllen Sie die Benachrichtigungspflichten gegenüber Betroffenen, Providern, Clients, Finanzstellen und Behörden.
8. Bauen Sie erst neu auf, nachdem Sie den Prozess geändert haben, der die Verknüpfung verursacht hat; dokumentieren und testen Sie die Kontrolle.

## Regelmäßiges Audit

- [ ] Threat Model sowie rechtliche und Provider-Annahmen nach einem datierten Zeitplan überprüft.
- [ ] Geräte, Accounts, Aliase, Domains, Netzwerkpfade und Zahlungs-Credentials inventarisiert.
- [ ] Recovery-Pfade überschreiten Compartments nicht unerwartet.
- [ ] Full-Tunnel-, DNS-, IPv6- und Fail-Closed-Verhalten getestet.
- [ ] Öffentliche Dateien und Profile auf Metadaten/Textwiederverwendung geprüft.
- [ ] Annahmen zu Wallet-Nodes/Backends und Crypto-Protokollen sind aktuell.
- [ ] Logs und Belege sind minimal, verschlüsselt, zugriffskontrolliert und innerhalb der Aufbewahrungsfrist.
- [ ] Alte Compartments und Engagement-Infrastruktur wurden vollständig stillgelegt.
{{#include ../banners/hacktricks-training.md}}
