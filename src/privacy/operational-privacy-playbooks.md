# Playbooks für operationelle Privatsphäre

Diese Playbooks kombinieren die Kontrollen aus dem restlichen Abschnitt. Sie sind Ausgangspunkte, keine Garantien: Aktualisieren Sie das Bedrohungsmodell, sobald ein neuer Beobachter, Account, ein neues Gerät, ein neuer Standort, eine neue Zahlung, Datei oder Gegenpartei in den Ablauf einbezogen wird.

## Universelle Vorabprüfung

1. Formulieren Sie das legitime Ziel und, **vor wem** was privat bleiben muss.
2. Erfassen Sie die Identitäten, Geräte, Netzwerke, Accounts, Zahlungswege, Gegenparteien, physischen Standorte und Daten, mit denen die Aktivität in Berührung kommt.
3. Identifizieren Sie den wahrscheinlich stärksten Beobachter und die Folgen eines Fehlschlags.
4. Bestätigen Sie die Autorisierung, geltendes Recht, Providerbedingungen und Organisationsrichtlinien.
5. Entscheiden Sie, was aus Sicherheits-, Incident-Response-, Buchhaltungs- und Audit-Gründen intern zuordenbar bleiben muss.
6. Wählen Sie das kleinste praktikable Compartment; richten Sie dessen Wiederherstellungs- und Abschaltpfade vor der Nutzung ein.
7. Testen Sie das Compartment gegen einen kontrollierten Service, einschließlich IP/DNS/IPv6, Browseridentität, Dokumentmetadaten, Zahlungsaufstellung und Benachrichtigungsleaks.

Verwenden Sie das ausführliche Modell in [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Grundlage für alltägliche Privatsphäre

Ziel: kommerzielles Tracking, Account-Übernahmen und unnötige Offenlegung reduzieren, ohne zu versuchen, anonym zu werden.

- Verwenden Sie ein gepflegtes Betriebssystem mit vollständiger Festplattenverschlüsselung, automatischen Updates, Bildschirmsperre und, sofern verfügbar, Secure Boot.
- Richten Sie zuerst Passwortmanager, Recovery-E-Mail und phishing-resistente MFA/Security Keys ein.
- Überprüfen Sie App-Berechtigungen, Standortverlauf, Werbekennungen, Cloud-Synchronisierung und Verbindungen zu Accounts von Drittanbietern.
- Verwenden Sie einen verbreiteten Browser mit wenigen Erweiterungen, Tracking-Schutz, HTTPS und getrennten Profilen für geschäftliches, privates und risikoreiches Browsing.
- Verwenden Sie Private-Relay-Aliase oder je nach Beziehung unterschiedliche E-Mail-Adressen; verwenden Sie keine persönliche Telefonnummer, wenn sie lediglich optional ist.
- Bevorzugen Sie Ende-zu-Ende-verschlüsselte Nachrichten für Inhalte, und beachten Sie, dass Teilnehmer, Zeitpunkte, Gruppen und Endpunkte weiterhin Metadaten darstellen.
- Entfernen Sie Metadaten bewusst aus Dateien und überprüfen Sie vor der Veröffentlichung die exportierte Kopie – nicht das Original.
- Verwenden Sie virtuelle Karten oder Wallet-Tokens zur Abschottung von Zahlungsdaten; bezeichnen Sie sie nicht als anonym.
- Sichern Sie verschlüsseltes Recovery-Material und testen Sie die Wiederherstellung.

## Pseudonyme Veröffentlichung

Ziel: Verhindern, dass gelegentliche Leser und Plattformen eine Veröffentlichung trivial mit einer bürgerlichen Identität verknüpfen können. Dies hält einer fähigen, gezielten Untersuchung nicht stand.

1. Definieren Sie, ob die Plattform, der Hosting-Provider, Leser, Kontakte, das lokale Netzwerk, der Zahlungsanbieter oder ein rechtliches Verfahren Teil des Bedrohungsmodells sind.
2. Erstellen Sie einen dedizierten Endpunkt-/Account-Kontext aus einer sauberen Ausgangsbasis. Deaktivieren Sie die persönliche Browser-Synchronisierung, Cloud-Dokumente, das Hochladen von Kontakten und Benachrichtigungsvorschauen.
3. Erstellen Sie den pseudonymen Account über das gewählte Netzwerk-Compartment. Verwenden Sie keine Benutzernamen, Avatare, Recovery-Kanäle, Schreibvorlagen oder persönlichen Login-Daten eines Identity Providers erneut.
4. Verwenden Sie Tor Browser, wenn die Nichtverknüpfbarkeit des Ziels wichtiger als die Geschwindigkeit ist; fügen Sie keine Erweiterungen hinzu, verändern Sie die Größe oder Konfiguration nicht stark und öffnen Sie heruntergeladene Dokumente nicht während einer normalen Online-Desktop-Sitzung.
5. Verfassen Sie Texte mit einem Verfahren, das keine persönlichen Vorlagennamen, Revisionsautoren, Druckerpfade, GPS/EXIF-Daten, Vorschaubilder oder verborgenen Ebenen einbettet. Exportieren Sie eine Kopie und überprüfen Sie sie mit geeigneten Metadaten-Tools.
6. Prüfen Sie den Inhalt auf selbstidentifizierende Fakten: einzigartige Daten, Details zum Arbeitsplatz, lokales Wetter/die lokale Zeitzone, Reflexionen, Hintergrundaudio, sprachliche Gewohnheiten und die Wiederverwendung bereits veröffentlichter Texte.
7. Verwenden Sie einen separaten Antwortkanal. Behandeln Sie jeden direkten Kontakt, Anhang und Link als potenziellen Korrelations- oder Phishing-Versuch.
8. Wenn Geld beteiligt ist, verwenden Sie die rechtmäßige Methode, die nur die notwendigen Daten offenlegt. Gehen Sie davon aus, dass die Plattform und der regulierte Intermediär den Zahlungsempfänger kennen können, auch wenn die Leser dies nicht tun.
9. Veröffentlichen Sie den Inhalt und überprüfen Sie anschließend das öffentliche Ergebnis aus einem anderen sauberen Kontext. Dokumentieren Sie, was die Plattform hinzugefügt oder verändert hat.
10. Halten Sie nur dann einen geplanten Veröffentlichungsrhythmus ein, wenn dadurch kein stabiles Verhaltensprofil entsteht; geben Sie das Compartment auf, statt es stillschweigend für andere Zwecke wiederzuverwenden.

Bei ernsthaftem Journalismus, Aktivismus, häuslicher Gewalt oder Risiken auf staatlicher Ebene sollten Sie maßgeschneiderte Unterstützung von einer erfahrenen Organisation für digitale Sicherheit einholen; eine statische Checkliste kann weder lokales Recht noch einen aktiven Gegner modellieren.

## Autorisiertes Red-Team-Engagement

Ziel: Die persönlichen Identitäten und Heimnetzwerke der Operator aus der Telemetrie des Ziels heraushalten und gleichzeitig Autorisierung, Kontrolle und Incident Response gewährleisten.

### Vor dem Startfenster

- Finalisieren Sie den Infrastruktur-Anhang der ROE, Ziele/Ausschlüsse, Quellbereiche, Zeiträume, Not-Aus und Berechtigungen von Drittanbietern/Providern.
- Weisen Sie ein dediziertes Operator-Profil oder eine VM, Engagement-Secrets, einen Evidenzspeicher, ein Cloud-Projekt, Domains und ein Budget zu.
- Bevorzugen Sie vom Kunden bereitgestellte Egress-Punkte oder einen von der Organisation kontrollierten festen Bastion-Host. Testen Sie das Verhalten von Full-Tunnel-IPv4/IPv6/DNS sowie die Fail-Closed-Richtlinie.
- Bewahren Sie die Zuordnung zwischen Operator und öffentlicher Infrastruktur beim Exercise Controller oder einem vereinbarten Escrow-Kontakt auf.
- Richten Sie Rate Limits, Destination-Allowlists und separate Freigaben für destruktive, drahtlose, physische, Phishing- oder Aktionen zur Erfassung von Zugangsdaten ein.
- Verwenden Sie einen von der Organisation kontrollierten Zahlungsweg und dokumentieren Sie die Freigaben intern.

### Während des Engagements

- Starten Sie vom freigegebenen Endpunkt und Tunnel und überprüfen Sie den beobachteten Egress vor Assessment-Traffic.
- Halten Sie persönliche Accounts, Geräte, Telefonnummern, Repositories, SSH/GPG-Keys und Cloud-Synchronisierung aus dem Compartment heraus.
- Protokollieren Sie Operator/Job, Start/Stopp, Quelle, Ziel im festgelegten Umfang und Konfigurationsänderungen, ohne unnötige Kundendaten zu erfassen.
- Stoppen Sie bei unklarer Reichweite, unerwarteten Systemen Dritter, einer Abuse-Benachrichtigung des Providers, Sicherheitsauswirkungen, verlorenem Equipment oder abgebrochenem Kontakt zum Controller.
- Improvisieren Sie niemals mit dem WLAN eines Nachbarn, gestohlenen Zugangsdaten, einer nicht freigegebenen SIM/einem nicht freigegebenen Account oder an einem Veranstaltungsort versteckter Hardware.

### Nach dem Engagement

- Stoppen Sie Jobs und C2; holen Sie freigegebene Drop-Geräte zurück und widerrufen Sie Tokens, Zugangsdaten und Zertifikate.
- Stimmen Sie Infrastruktur, Domains, Quelladressen, Ausgaben, Daten und Provider-Fälle mit dem Inventar ab.
- Geben Sie Kundendaten gemäß Vertrag zurück, löschen oder bewahren Sie sie entsprechend auf, bewahren Sie die mindestens erforderlichen Audit-Nachweise auf und lassen Sie die Abschaltung von einem zweiten Operator überprüfen.

Siehe [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) für die vollständige Anleitung zu Einrichtung und Abbau.

## Rechtmäßiger privater Kauf oder Spende

Ziel: Die Offenlegung gegenüber Händler oder Öffentlichkeit minimieren und gleichzeitig Pflichten gegenüber Zahlungsdienstleister, Buchhaltung, Steuerwesen und Sanktionsvorschriften erfüllen.

1. Listen Sie auf, wer was nicht erfahren darf: die Öffentlichkeit, der Händler, der Zahlungsintermediär, ein Arbeitgeber/Familien-Account-Delegierter, der Lieferdienst oder ein Blockchain-Beobachter.
2. Prüfen Sie lokale Vorschriften, den Empfänger/die Gegenpartei, Providerbedingungen, Bargeldlimits und Anforderungen an die Aufbewahrung von Aufzeichnungen.
3. Wählen Sie den Zahlungsweg:
- Bargeld für akzeptierte rechtmäßige lokale Zahlungen ohne Eintrag im Zahlungsnetzwerk;
- eine regulierte virtuelle oder händlerspezifische Karte zur Trennung von Online-Zahlungsdaten;
- Cryptocurrency erst nach Analyse der Verbindungen zwischen Beschaffung, Ledger, Wallet-Backend, Netzwerk, Gegenpartei und späteren Ausgaben.
4. Verwenden Sie wahrheitsgemäße erforderliche Angaben und lassen Sie nur optionale Angaben zu Kundenbindungs- oder Marketingzwecken weg. Verwenden Sie nicht die Identität oder Adresse einer anderen Person und teilen Sie eine Transaktion nicht auf, um einen Schwellenwert zu umgehen.
5. Trennen Sie den Browser-/Account-Kontext des Händlers und vermeiden Sie nicht zugehörige Social-Logins, Kundenbindungsprogramme oder persönliche Recovery-Kanäle.
6. Bestätigen Sie, was auf Kontoauszügen, Quittungen, Benachrichtigungen, Versandunterlagen und öffentlichen Spenderlisten erscheint.
7. Speichern Sie erforderliche Quittungs-, Steuer- und Autorisierungsnachweise verschlüsselt; widerrufen Sie temporäre Zahlungsdaten nach Ablauf des Erstattungszeitraums.

Siehe [Private Digital Payments](private-digital-payments.md) und [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Reisen und nicht vertrauenswürdige Netzwerke

Ziel: Daten und Accounts in Netzwerken schützen, die nicht vom Benutzer verwaltet werden – nicht unbefugte Aktivitäten verbergen.

- Aktualisieren Sie Geräte und laden Sie benötigte Zugangsdaten/Karten vor der Reise herunter.
- Minimieren Sie gespeicherte Daten; verwenden Sie vollständige Festplattenverschlüsselung, eine starke Entsperrmethode, eine Planung für die Remote-Wiederherstellung sowie je nach Rechtsberatung Verfahren für ausgeschaltete Geräte bei Grenzübertritten/physischen Risiken.
- Überprüfen Sie die SSID und das Captive Portal des Veranstaltungsorts. Bevorzugen Sie gegebenenfalls einen persönlichen Hotspot, beachten Sie jedoch die Teilnehmer- und Standortaufzeichnungen des Mobilfunkanbieters.
- Verwenden Sie für Organisationsdaten ein vollständiges/erzwungenes freigegebenes VPN; überprüfen Sie, ob getetherte Geräte dieses ebenfalls verwenden, und testen Sie das Verhalten von IPv6/DNS.
- Verwenden Sie einen Travel Router zur Client-Isolierung und für eine reproduzierbare Richtlinie, nicht als Garantie für Anonymität.
- Behandeln Sie öffentliche USB-Ladeanschlüsse, geliehene Computer, öffentliche Drucker und gemeinsam genutzte Systeme in Besprechungsräumen als separate Bedrohungen.
- Gehen Sie davon aus, dass physische Anwesenheit, Funkkennungen, Portal-Logins, Kameras sowie Zahlungs- und Standortaufzeichnungen den Besuch korrelieren können.

Vergleich und Einrichtungsdetails finden Sie unter [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Reaktion auf Fehler und Offenlegung

Wenn ein Compartment leakt oder möglicherweise verknüpft wurde:

1. Stoppen Sie die Aktivität, wenn ihre Fortsetzung den Schaden vergrößert; verwenden Sie gegebenenfalls den Not-Aus des Engagements.
2. Bewahren Sie notwendige Beweise auf, ohne sensible Daten weiterzuverbreiten. Dokumentieren Sie den genauen Zeitpunkt, den beobachteten Indikator und die betroffenen Assets.
3. Benachrichtigen Sie den zuständigen Eigentümer/Controller/Sicherheitskontakt. Verbergen Sie keinen Incident, um eine Privatsphäre-Erzählung aufrechtzuerhalten.
4. Widerrufen Sie Sessions, Tokens, Zahlungsdaten und Infrastrukturzugriffe; rotieren Sie Secrets von einem bekanntermaßen sauberen Endpunkt aus.
5. Ermitteln Sie, welche Kanten die Verknüpfung ermöglichten: Endpunkt, Account-Recovery, Netzwerk, Zahlung, Metadaten, Inhalt, Verhalten, Gegenpartei oder physische Anwesenheit.
6. Betrachten Sie das gesamte betroffene Compartment als verbrannt. Ändern Sie nicht lediglich seinen Benutzernamen oder seine Exit-IP.
7. Erfüllen Sie Meldepflichten gegenüber Behörden, Providern, Kunden, Finanzstellen und gemäß rechtlichen Vorgaben.
8. Bauen Sie erst dann neu auf, wenn Sie den Prozess geändert haben, der die Verknüpfung verursacht hat; dokumentieren und testen Sie die Kontrolle.

## Regelmäßiges Audit

- [ ] Bedrohungsmodell sowie rechtliche und Provider-Annahmen wurden nach einem datierten Zeitplan überprüft.
- [ ] Geräte, Accounts, Aliase, Domains, Netzwerkpfade und Zahlungsdaten sind inventarisiert.
- [ ] Recovery-Pfade überschreiten Compartments nicht unerwartet.
- [ ] Full-Tunnel-, DNS-, IPv6- und Fail-Closed-Verhalten wurde getestet.
- [ ] Öffentliche Dateien und Profile wurden auf Metadaten und wiederverwendete Inhalte überprüft.
- [ ] Annahmen zu Wallet-Nodes/Backends und Crypto-Protokollen sind weiterhin aktuell.
- [ ] Logs und Quittungen sind minimal, verschlüsselt, zugriffskontrolliert und innerhalb der Aufbewahrungsfrist.
- [ ] Alte Compartments und Engagement-Infrastruktur wurden vollständig außer Betrieb genommen.
