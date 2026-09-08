# Autorisierte Red-Team-Infrastruktur

Für langlebige Geräte vor Ort verwenden Sie das Design und das Runbook zur vermuteten Entdeckung für [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Für ein professionelles Red Team besteht das Ziel in einer **kontrollierten Attribution**, nicht in der Immunität gegenüber Verantwortlichkeit. Das Ziel sollte nicht ohne Weiteres die private IP-Adresse oder persönlichen Konten eines Operators sehen, während der Auftraggeber in der Lage sein muss, die Quelle zu identifizieren, den Betrieb zu stoppen, Missbrauchsmeldungen zu bearbeiten, Beweise zu sichern und die Autorisierung nachzuweisen.

Diese Seite ist die Bereitstellungsgrundlage für einen rechtmäßigen Auftrag. Für die nachzubildenden Vorgehensweisen des Gegners – einschließlich kompromittierter ORBs, Residential Relays, Fronting, Dead Drops und drahtloser Pivots in der Nähe – beginnen Sie mit [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) und [Government and APT Case Studies](government-and-apt-case-studies.md) und reproduzieren Sie anschließend die erforderliche Telemetrie in den [authorized labs](authorized-adversary-emulation-labs.md).

NIST definiert Rules of Engagement (ROE) als vorab festgelegte Einschränkungen, die die Befugnis für definierte Testaktivitäten erteilen.<sup>[[1]](#references)</sup> Eine Privacy-Architektur kann diese Befugnis nicht erweitern.

## Egress-Muster auswählen

| Muster | Beste Verwendung | Für das Ziel sichtbar | Für Provider/lokalen Beobachter sichtbar | Verantwortlichkeit |
|---|---|---|---|---|
| Vom Client bereitgestellter VPN/Jump Host | Die meisten Assessments | Adressbereich des Clients | Client-Identität und Operator-Zugriff | Am stärksten |
| Bastion des Red-Team-Unternehmens | Wiederholbarer kontrollierter Egress | Bereich des Unternehmens | Hosting-Provider und Unternehmen | Stark |
| Engagement-spezifischer VPS | Clients/Kampagnen isolieren | VPS-Adresse | Host-Konto, Abrechnungs-, Control-Plane- und Zugriffslogs | Stark bei Dokumentation |
| Genehmigtes kommerzielles VPN | Research/Scanning, sofern vom Provider und den ROE erlaubt | Gemeinsamer/dedizierter VPN-Egress | VPN-Konto und Quellverbindung | Mittel |
| Tor Browser | Web-Recherche, die eine Unverknüpfbarkeit mit dem Ziel erfordert | Tor-Exit | Lokales Netzwerk sieht Tor/Bridge; das Ziel sieht Tor | Ungeeignet für Allowlisting der Quellattribution |
| Vom Client genehmigter On-Site-Drop | Interne Simulation | Gerät/Adresse vor Ort | Standortnetzwerk und Remote-Tunnel-Provider | Stark bei Inventarisierung |
| Rechtmäßiges Gäste-WLAN | Risikoarme administrative Nutzung/Research | Öffentliche IP-Adresse des Veranstaltungsorts oder Tunnel-Egress | Veranstaltungsort, ISP, VPN/Tor | Schwach und physisch beobachtbar |

Für die meisten Aufgaben ist ein vom Client bereitgestellter oder vom Unternehmen kontrollierter fester Egress sicherer und schneller als Consumer-Anonymisierungsdienste. Außerdem können Verteidiger dadurch bekannte Quellbereiche gemäß dem Design der Übung allowlisten, überwachen oder bewusst **nicht allowlisten**.

## ROE-Infrastrukturanhang

Vor der Bereitstellung dokumentieren:

- die Rechtsträger, die die Autorisierung erteilen und erhalten;
- die genauen Ziele und ausdrücklichen Ausschlüsse;
- Start-/Endzeiten, Zeitzone und zulässige Techniken;
- Quell-IP-Adressen, Namen von Autonomous Systems/Providern, Domains, Redirectors, Mail-Infrastruktur und Kennungen von Geräten vor Ort;
- ob Phishing, C2, Credential Capture, Wireless-Tests, physischer Zugriff, Denial-of-Service, Persistence oder Services Dritter zulässig sind;
- Genehmigungen von Client und Providern, einschließlich etwaiger Referenzen zur Vorabbenachrichtigung;
- Notfall-Stoppphrase, 24/7-Missbrauchskontakte von Client und Provider sowie die maximale Reaktionszeit;
- Datensammlungen, die erfasst werden dürfen, Verschlüsselung, Zugriff, Aufbewahrung und Löschung;
- Anforderungen an Beweise und Logging, einschließlich der Person, die die Zuordnung zwischen öffentlicher Infrastruktur und Operator verwaltet;
- Teardown, Ablauf von Domains, Widerruf von Zertifikaten, Rotation von Zugangsdaten, Rückholung von Geräten und abschließende Bestätigung.

Überprüfen Sie, dass öffentliche IP-Adressen und Domains tatsächlich von der autorisierenden Partei kontrolliert werden oder ausdrücklich im Scope enthalten sind. NIST SP 800-115 empfiehlt, vor dem Test zu bestätigen, dass öffentliche Zieladressen dem Zuständigkeitsbereich der Organisation unterliegen.<sup>[[2]](#references)</sup>

## Engagement-spezifischer Fast Egress

### Workflow für den Aufbau

1. **Erstellen Sie ein Engagement-Konto/Projekt** unter dem Red-Team-Unternehmen und verwenden Sie korrekte Abrechnungs- und Eigentümerangaben. Trennen Sie Rollen, API-Keys, Budgets und Audit-Logs von denen anderer Clients.
2. **Prüfen Sie die Richtlinien jedes Providers.** Cloud-, VPS-, CDN-, Domain-, E-Mail- und VPN-Provider haben unterschiedliche Regeln. AWS erlaubt beispielsweise bestimmte Assessments, verlangt jedoch eine vorherige Genehmigung für gehostete C2-/Covert-Simulationen und untersagt aufgeführte Aktivitäten.<sup>[[3]](#references)</sup>
3. **Weisen Sie feste Egress-Adressen zu** und tragen Sie diese in den ROE-Anhang ein. Vermeiden Sie ein schnelles Wechseln von IPs/Ressourcen; dies erschwert die Incident Response und kann gegen Provider-Richtlinien verstoßen.
4. **Härten Sie die Verwaltung:** SSH nur mit Keys oder eine Identity-Aware-Management-Plane, phishing-resistente MFA, separates Admin-Netzwerk, Least Privilege, gepatchte Images, keine öffentlichen Admin-Ports und verschlüsselte Speicherung von Secrets.
5. **Erstellen Sie einen Full-Tunnel-Pfad** vom Operator-Endpunkt zur Bastion. Routen Sie DNS und IPv6 bewusst und erzwingen Sie eine Firewall-Sperre, wenn der Tunnel ausfällt.
6. **Beschränken Sie ausgehende Ziele und Ports** nach Möglichkeit auf den autorisierten Scope. Begrenzen Sie die Rate von Scannern und stellen Sie irreversible/destruktive Techniken hinter ein separates Genehmigungsgate.
7. **Loggen Sie zur Verantwortlichkeit, nicht zur Überwachung:** Operator-Authentifizierung, Konfigurationsänderungen, Start/Stopp, Quelladresse, Ziel im Scope und Tool-/Job-Kennungen. Vermeiden Sie Payload-/Credential-Capture, sofern dies nicht für die Übung erforderlich und durch den Datenplan geschützt ist.
8. **Validieren Sie über einen kontrollierten Endpunkt** im Besitz der Organisation: beobachtetes IPv4/IPv6, DNS-Pfad, Reverse DNS, Uhrzeit, Verhalten von Quellports, Ausfall/Wiederverbindung und Missbrauchskontakt des Providers.
9. **Teilen Sie die Attribution Map sicher** mit dem Übungsleiter oder einem vereinbarten Escrow-Kontakt. Veröffentlichen Sie sie nicht für das Zielteam, wenn eine blinde Erkennung Teil des Tests ist.

### Architektur
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
Ein VPS ist nur gegenüber dem Ziel pseudonym. Der Host kann Kontakt-, Abrechnungs-, Identitäts-, Quell-IP-, API-, Geräte-, Standort- und Nutzungsdaten aufzeichnen; allein die für Kunden sichtbare AWS CloudTrail-Historie kann Verwaltungsaktivitäten offenlegen.<sup>[[4]](#references)</sup> Die Bezahlung des Hostings mit Kryptowährung löscht diese Aufzeichnungen nicht.

## Domains und Zertifikate

- Verwende ein engagement-spezifisches Registrar-Konto im Besitz der Organisation.
- Aktiviere Registrar-Lock, DNSSEC, sofern unterstützt, MFA/Sicherheitsschlüssel und die automatische Verlängerung nur für den genehmigten Zeitraum.
- Verwende Registrierungsschutz, um die öffentliche Sichtbarkeit zu reduzieren, nicht um Registrantendaten falsch darzustellen. Die ICANN-Richtlinie verpflichtet Registrare, Registrierungsdaten zu erfassen, auch wenn die öffentliche Anzeige geschwärzt oder über einen Proxy erfolgt.<sup>[[5]](#references)</sup>
- Vermeide Namen, die unrechtmäßig den Anschein erwecken, zu nicht beteiligten Parteien zu gehören. Typosquatting-/Lookalike-Domains erfordern die ausdrückliche Genehmigung des Kunden und des Providers.
- Erfasse DNS, Zertifikate, CDN-/Redirector-Konfiguration und Analysen von Drittanbietern, durch die Operatoren oder Kunden geleakt werden könnten.
- Entferne beim Teardown Datensätze, widerrufe Zertifikate/Tokens, bewahre vereinbarte Beweise auf und entscheide, ob die Domain präventiv behalten werden soll.

## Autorisierte On-Site-Drop-Nodes

Ein Raspberry Pi oder ein ähnliches Gerät ist nur zulässig, wenn der Eigentümer des Standorts/Netzwerks und der Kunde dessen genauen Aufstellungsort und Verhalten ausdrücklich genehmigen. Ein sicherer Plan:

1. Erfasse Geräteseriennummer, MAC-/Private-MAC-Richtlinie, Foto, Eigentümer, genau genehmigten Standort, Stromquelle, Abholfrist und Kontakt für Manipulationsfälle.
2. Verwende ein minimales signiertes Image, verschlüsselte Secrets, schreibgeschützten oder wiederherstellbaren Speicher, eine Host-Firewall, soweit praktikabel automatische Sicherheitsupdates und keine Standardpasswörter.
3. Konfiguriere ausschließlich ausgehende Kommunikation zu einem benannten Engagement-Endpunkt. Betreibe keinen nicht authentifizierten Listener.
4. Erlaube nur freigegebene Ziele und Fähigkeiten. Packet Capture, Credential Collection, Wireless-Impersonation und Lateral Movement müssen jeweils ausdrücklich genehmigt werden.
5. Verwende gegenseitige Authentifizierung, kurzlebige Schlüssel, Remote-Kill, Zustandsmeldungen und Bandbreitenlimits.
6. Stelle sicher, dass Verlust oder Diebstahl keine wiederverwendbaren Zugangsdaten oder Kundendaten offenlegt.
7. Trage Abholung und sicheres Löschen bzw. Decommissioning in den Kalender ein; hole einen signierten Abholungsnachweis ein.

Verstecke Hardware nicht in einem Café, Hotel, gemeinsam genutzten Büro, auf dem Grundstück eines Nachbarn oder an einem öffentlichen Ort ohne die schriftliche Genehmigung des Eigentümers/Betreibers.

## Gastnetzwerke und Travel Router

Wenn ein autorisiertes Szenario Gastzugang erfordert:

- Überprüfe die SSID und die Acceptable-Use-Richtlinie mit dem Veranstaltungsort/Kunden.
- Verwende einen organisations­eigenen Travel Router oder ein Bridge-Gerät mit geringem Vertrauensniveau, um die privilegierte Workstation zu isolieren.
- Schließe Captive Portals außerhalb der privilegierten Workstation ab.
- Starte den genehmigten Tunnel vor dem Assessment-Traffic.
- Bestätige, dass verbundene Geräte diesen Tunnel tatsächlich verwenden.
- Gehe davon aus, dass der Veranstaltungsort Funkassoziation, Portal, physische Anwesenheit sowie Kamera- und Zahlungsdaten miteinander korrelieren kann.
- Umgehe niemals Zugriffskontrollen, klone kein anderes Gerät, greife kein Wi-Fi an und lasse keine Ausrüstung zurück.

## Operative Trennung

- Ein Client/Engagement pro Endpoint-Kompartiment, Cloud-Projekt, Secret-Set, Domain-Gruppe, Redirector-Set und Evidence Store.
- Keine persönliche E-Mail-Adresse, Browser-Synchronisierung, Telefonnummer, Cloud Drive, SSH-/GPG-Schlüssel, Code-Signing-Identität oder Zahlungserstattung außerhalb genehmigter Organisationssysteme.
- Verwende charakteristische Payload-Konfigurationen, Callback-Pfade, Zertifikate oder öffentliche Repositories nicht für mehrere Kunden wieder, sofern das Exercise-Design Fingerprinting nicht akzeptiert.
- Gib der Infrastruktur ein Abschaltdatum und einen Budget-Alarm. Verwaiste Systeme werden zu einem Risiko für den Kunden und das Internet.
- Bewahre genügend interne Zuordnungsdaten auf, um Unfälle zu untersuchen. „Keine Logs“ ist in der Regel nicht mit professionellen Beweis- und Sicherheitsverpflichtungen vereinbar.

## Für die Defender blind, dem Controller zuordenbar

Wenn das Ziel des Exercises die Messung der Detection und nicht das Testen einer Allowlist ist, kann der Ziel-SOC blind bleiben, ohne dass der Vorgang nicht mehr rechenschaftspflichtig ist:

1. Der Exercise-Controller genehmigt jede öffentliche Quelle, Domain, jedes Zertifikat und jedes On-Site-Gerät, hält die Liste jedoch vor dem SOC zurück.
2. Der Controller speichert die Zuordnung von Quelle zu Engagement/Operator in einem separaten verschlüsselten Vault mit Notfallzugriff durch zwei Personen.
3. Jeder Operator-Job erhält ein signiertes Manifest mit Scope, Zeitfenster, Source-Kompartiment und einer unumkehrbaren Job-ID. Das Ziel muss das Manifest im Normalbetrieb nicht sehen.
4. Bastion-Audit-Ereignisse werden verkettet oder append-only an den Speicher des Controllers gesendet, damit ein Operator die Zuordnung nach einem Vorfall nicht unbemerkt umschreiben kann.
5. Ein 24/7-Provider-Abuse-Kontakt verfügt über eine Verifizierungsphrase bzw. Referenz, die die Autorisierung bestätigt, ohne den Kunden öffentlich offenzulegen.
6. Jeder Pfad implementiert einen Out-of-Band-Stop-Kanal, der nicht von der Assessment-C2, dem Zielnetzwerk oder dem Konto eines einzelnen Operators abhängt.
7. Sende vor dem Live-Testing harmlose Canaries von jeder Quelle. Bestätige, dass der Controller sie innerhalb der im ROE festgelegten Reaktionszeit auflösen und stoppen kann.
8. Vergleiche nach dem Exercise die SOC-Telemetrie mit dem Controller-Ledger, lege die Quellenliste offen und erkläre verpasste oder fehlerhafte Detections.

Füge keine Anti-Forensik, Log-Zerstörung, kompromittierten Relays oder falschen Subscriber-Identitäten hinzu. Diese Maßnahmen untergraben rechenschaftspflichtiges Testing, statt es zu verbessern.

## Teardown-Checkliste

- [ ] Der Exercise-Controller bestätigt den Stopp.
- [ ] C2, Tunnel, Redirectors, Mail, VPN und geplante Jobs sind deaktiviert.
- [ ] On-Site-Geräte wurden physisch zurückgeholt und abgeglichen.
- [ ] Tokens, API-Keys, SSH-Schlüssel, Zertifikate und erfasste Zugangsdaten wurden widerrufen/rotiert.
- [ ] DNS- und Cloud-Ressourcen wurden entfernt oder zur defensiven Aufbewahrung übertragen.
- [ ] Kundendaten wurden gemäß Vertrag zurückgegeben, aufbewahrt oder vernichtet.
- [ ] Erforderliche Finanz-, Audit- und Autorisierungsaufzeichnungen verbleiben verschlüsselt und zugriffskontrolliert.
- [ ] Provider-Abuse-Fälle wurden geschlossen und der Kunde hat die endgültigen Quellindikatoren erhalten.
- [ ] Ein zweiter Operator überprüft, dass keine Infrastruktur aktiv geblieben ist.

## References

- [1] [NIST CSRC — Regeln für das Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Technischer Leitfaden für Tests und Bewertungen der Informationssicherheit](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Kundensupport-Richtlinie für Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Datenschutzhinweis](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Richtlinie für Registrierungsdaten](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
