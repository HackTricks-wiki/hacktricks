# Authorized Red-Team-Infrastruktur

{{#include ../banners/hacktricks-training.md}}

Verwende für langlebige Geräte vor Ort das Design [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) sowie das Runbook zur vermuteten Entdeckung.

Für ein professionelles red team ist das Ziel eine **kontrollierte Zuordnung**, nicht die Immunität gegenüber Rechenschaftspflicht. Das Ziel sollte nicht ohne Weiteres die private IP-Adresse oder persönlichen Konten eines Operators sehen, während der Auftraggeber in der Lage sein muss, die Quelle zu identifizieren, den Vorgang zu stoppen, Missbrauchsmeldungen zu bearbeiten, Beweise zu sichern und die Autorisierung nachzuweisen.

Diese Seite bildet die Bereitstellungsgrundlage für einen rechtmäßigen Auftrag. Für die nachzuahmenden Tradecrafts des Angreifers – einschließlich kompromittierter ORBs, Residential Relays, Fronting, Dead Drops und drahtloser Pivots in der Nähe – beginne mit [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) und [Government and APT Case Studies](government-and-apt-case-studies.md), und reproduziere anschließend die erforderliche Telemetrie in den [authorized labs](authorized-adversary-emulation-labs.md).

NIST definiert Rules of Engagement (ROE) als vorab festgelegte Einschränkungen, die Autorität für bestimmte Testaktivitäten gewähren.<sup>[[1]](#references)</sup> Privacy-Architektur kann diese Autorität nicht erweitern.

## Ein Egress-Muster auswählen

| Muster | Beste Verwendung | Für das Ziel sichtbar | Für Provider/lokalen Beobachter sichtbar | Rechenschaftspflicht |
|---|---|---|---|---|
| Vom Client bereitgestelltes VPN/Jump Host | Die meisten Assessments | Adressbereich des Clients | Client-Identität und Operator-Zugriff | Am stärksten |
| Bastion der red-team-Organisation | Wiederholbarer kontrollierter Egress | Bereich der Organisation | Hosting-Provider und Organisation | Stark |
| Engagement-spezifischer VPS | Clients/Kampagnen isolieren | VPS-Adresse | Host-Konto, Abrechnung sowie Control-Plane- und Access-Logs | Stark, wenn dokumentiert |
| Genehmigtes kommerzielles VPN | Vom Provider und den ROE erlaubte Recherche/Scans | Gemeinsamer/dedizierter VPN-Egress | VPN-Konto und Quellverbindung | Mittel |
| Tor Browser | Web-Recherche, die eine Unverknüpfbarkeit mit dem Ziel benötigt | Tor-Exit | Lokales Netzwerk sieht Tor/Bridge; Ziel sieht Tor | Ungeeignet für die Attribution über eine allowlistete Quelle |
| Vom Client genehmigter On-Site-Drop | Interne Simulation | On-Site-Gerät/-Adresse | Standortnetzwerk und Remote-Tunnel-Provider | Stark, wenn inventarisiert |
| Rechtmäßiges Gäste-WLAN | Risikoarme administrative/recherchebezogene Nutzung | Öffentliche IP des Veranstaltungsorts oder Tunnel-Egress | Veranstaltungsort, ISP, VPN/Tor | Schwach und physisch beobachtbar |

Für die meisten Arbeiten ist ein vom Client bereitgestellter oder von der Organisation kontrollierter fixer Egress sicherer und schneller als Consumer-Anonymisierungsdienste. Außerdem können Verteidiger dadurch Quellbereiche gemäß dem Design der Übung allowlisten, überwachen oder absichtlich **nicht** allowlisten.

## ROE-Infrastruktur-Anhang

Vor der Bereitstellung dokumentieren:

- die Rechtsträger, die die Autorisierung erteilen und erhalten;
- die genauen Ziele und ausdrücklichen Ausschlüsse;
- Start-/Endzeiten, Zeitzone und zulässige Techniken;
- Quell-IPs, Namen von Autonomous Systems/Providern, Domains, Redirectors, Mail-Infrastruktur und Identifikatoren von On-Site-Geräten;
- ob Phishing, C2, Credential Capture, Wireless-Tests, physischer Zugriff, Denial-of-Service, Persistence oder Drittanbieterdienste zulässig sind;
- Genehmigungen von Client und Provider, einschließlich einer Referenz für etwaige Vorabbenachrichtigungen;
- Notfall-Stoppphrase, 24/7-Missbrauchskontakte von Client und Provider sowie die maximale Reaktionszeit;
- Datenklassen, die erfasst werden dürfen, Verschlüsselung, Zugriff, Aufbewahrung und Löschung;
- Anforderungen an Beweise und Logging, einschließlich der Person oder Stelle, die die Zuordnung von öffentlicher Infrastruktur zu Operator verwaltet;
- Teardown, Domain-Ablauf, Zertifikatswiderruf, Credential-Rotation, Wiederbeschaffung von Geräten und abschließende Bestätigung.

Stelle sicher, dass öffentliche IPs und Domains tatsächlich von der autorisierenden Partei kontrolliert werden oder ausdrücklich im Scope enthalten sind. NIST SP 800-115 empfiehlt, vor dem Test zu bestätigen, dass öffentliche Zieladressen der Zuständigkeit der Organisation unterliegen.<sup>[[2]](#references)</sup>

## Engagement-spezifischer schneller Egress

### Workflow erstellen

1. **Ein Engagement-Konto/Projekt erstellen** unter der red-team-Organisation und dabei korrekte Abrechnungs- und Eigentümerangaben verwenden. Rollen, API-Keys, Budgets und Audit-Logs von anderen Clients trennen.
2. **Jede Provider-Richtlinie prüfen.** Cloud-, VPS-, CDN-, Domain-, E-Mail- und VPN-Provider haben unterschiedliche Regeln. AWS erlaubt beispielsweise bestimmte Assessments, verlangt aber für gehostete C2-/Covert-Simulationen eine vorherige Genehmigung und verbietet die aufgeführten Aktivitäten.<sup>[[3]](#references)</sup>
3. **Feste Egress-Adressen zuweisen** und in den ROE-Anhang aufnehmen. Schnelle IP-/Ressourcenwechsel vermeiden; sie erschweren die Incident Response und können gegen Provider-Richtlinien verstoßen.
4. **Management härten:** SSH nur mit Keys oder eine Identity-Aware-Management-Plane, phishing-resistente MFA, separates Admin-Netzwerk, Least Privilege, gepatchte Images, keine öffentlichen Admin-Ports und verschlüsselte Speicherung von Secrets.
5. **Einen Full-Tunnel-Pfad erstellen** vom Operator-Endpunkt zur Bastion. DNS und IPv6 bewusst routen und eine Firewall-Sperre erzwingen, wenn der Tunnel ausgefallen ist.
6. **Ausgehende Ziele und Ports auf den autorisierten Scope beschränken**, sofern möglich. Scanner mit Rate-Limits versehen und irreversible/destruktive Techniken hinter ein separates Genehmigungsgate stellen.
7. **Für Rechenschaftspflicht loggen, nicht für Überwachung:** Operator-Authentifizierung, Konfigurationsänderungen, Start/Stopp, Quelladresse, Ziel im Scope sowie Tool-/Job-IDs. Payload-/Credential-Capture vermeiden, sofern es nicht für die Übung erforderlich und durch den Datenplan geschützt ist.
8. **Über einen kontrollierten, der Organisation gehörenden Endpunkt validieren:** beobachtetes IPv4/IPv6, DNS-Pfad, Reverse DNS, Zeit, Verhalten der Quellports, Ausfall/Wiederverbindung und Abuse-Kontakt des Providers.
9. **Die Attribution-Map sicher** mit dem Übungsleiter oder einem vereinbarten Escrow-Kontakt teilen. Nicht für das Zielteam veröffentlichen, wenn blinde Erkennung Teil des Tests ist.

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
Ein VPS ist nur gegenüber dem Ziel pseudonym. Der Host kann Kontakt-, Abrechnungs-, Identitäts-, Quell-IP-, API-, Geräte-, Standort- und Nutzungsdaten aufzeichnen; allein die für Kunden sichtbare AWS CloudTrail-Historie kann Verwaltungsaktivitäten offenlegen.<sup>[[4]](#references)</sup> Das Bezahlen des Hostings mit Kryptowährung löscht diese Aufzeichnungen nicht.

## Domains und Zertifikate

- Verwende ein engagement-spezifisches Registrar-Konto, das der Organisation gehört.
- Aktiviere Registrar Lock, DNSSEC, sofern unterstützt, MFA/Sicherheitsschlüssel und die automatische Verlängerung nur für den genehmigten Zeitraum.
- Verwende Registrierungsschutz, um die öffentliche Sichtbarkeit zu verringern, nicht um Registrierungsinformationen falsch darzustellen. Die ICANN-Richtlinie verpflichtet Registrare, Registrierungsdaten zu erfassen, auch wenn die öffentliche Anzeige redigiert oder über einen Proxy erfolgt.<sup>[[5]](#references)</sup>
- Vermeide Namen, die unrechtmäßig andere, nicht verbundene Parteien imitieren. Typosquatting-/Lookalike-Domains erfordern die ausdrückliche Genehmigung des Kunden und des Providers.
- Erfasse DNS, Zertifikate, CDN-/Redirector-Konfiguration und Analysen von Drittanbietern, durch die Operatoren oder Kunden geleakt werden könnten.
- Entferne beim Teardown Datensätze, widerrufe Zertifikate/Tokens, bewahre vereinbarte Beweise auf und entscheide, ob die Domain defensiv behalten werden soll.

## Autorisierte On-Site-Drop-Nodes

Ein Raspberry Pi oder ein ähnliches Gerät ist nur dann akzeptabel, wenn der Eigentümer des Standorts/Netzwerks und der Kunde dessen genauen Aufstellungsort und Verhalten ausdrücklich genehmigen. Ein sicherer Plan:

1. Erfasse Geräteseriennummer, MAC-/Private-MAC-Richtlinie, Foto, Eigentümer, exakt genehmigten Standort, Stromquelle, Abholfrist und Kontakt für Manipulationsfälle.
2. Verwende ein minimales signiertes Image, verschlüsselte Secrets, schreibgeschützten oder wiederherstellbaren Speicher, eine Host-Firewall, automatische Sicherheitsupdates, sofern praktikabel, und keine Standard-Zugangsdaten.
3. Konfiguriere ausschließlich ausgehende Kommunikation zu einem benannten Engagement-Endpunkt. Betreibe keinen nicht authentifizierten Listener.
4. Erlaube Ziele und Fähigkeiten per Allowlist. Packet Capture, Credential Collection, Wireless-Impersonation und laterale Bewegung müssen jeweils ausdrücklich genehmigt werden.
5. Verwende gegenseitige Authentifizierung, kurzlebige Schlüssel, Remote Kill, Zustandsmeldungen und Bandbreitenlimits.
6. Stelle sicher, dass Verlust oder Diebstahl keine wiederverwendbaren Zugangsdaten oder Kundendaten offenlegt.
7. Plane Abholung und sicheres Wipe/Decommissioning im Kalender ein; hole einen unterschriebenen Abholnachweis ein.

Verstecke Hardware nicht in einem Café, Hotel, gemeinsam genutzten Büro, auf dem Grundstück eines Nachbarn oder an einem öffentlichen Ort ohne die schriftliche Genehmigung des Eigentümers/Betreibers.

## Gastnetzwerke und Reiserouter

Wenn ein autorisiertes Szenario Gastzugang erfordert:

- Überprüfe SSID und Acceptable-Use-Richtlinie mit dem Veranstaltungsort/Kunden.
- Verwende einen organisations-eigenen Reiserouter oder ein Bridge-Gerät mit geringem Vertrauensniveau, um die privilegierte Workstation zu isolieren.
- Schließe Captive Portals außerhalb der privilegierten Workstation ab.
- Starte den genehmigten Tunnel vor dem Assessment-Datenverkehr.
- Bestätige, dass verbundene Geräte diesen Tunnel tatsächlich verwenden.
- Gehe davon aus, dass der Veranstaltungsort Funkassoziation, Portal, physische Anwesenheit sowie Kamera- und Zahlungsdaten miteinander korrelieren kann.
- Umgehe niemals Zugriffskontrollen, klone kein anderes Gerät, greife kein Wi-Fi an und lasse keine Ausrüstung zurück.

## Operative Trennung

- Ein Client/Engagement pro Endpoint-Kompartiment, Cloud-Projekt, Secrets-Satz, Domain-Gruppe, Redirector-Gruppe und Evidence Store.
- Keine persönliche E-Mail-Adresse, Browser-Synchronisierung, Telefonnummer, Cloud-Laufwerk, SSH-/GPG-Schlüssel, Code-Signing-Identität oder Zahlungserstattung außerhalb genehmigter Organisationssysteme.
- Verwende charakteristische Payload-Konfigurationen, Callback-Pfade, Zertifikate oder öffentliche Repositories nicht für mehrere Kunden wieder, sofern das Übungsdesign Fingerprinting nicht akzeptiert.
- Gib der Infrastruktur ein Abschaltdatum und einen Budgetalarm. Verwaiste Systeme werden zu einem Risiko für den Kunden und das Internet.
- Bewahre ausreichend interne Zuordnungsdaten auf, um Unfälle zu untersuchen. „Keine Logs“ ist normalerweise nicht mit professionellen Beweis- und Sicherheitsverpflichtungen vereinbar.

## Für Verteidiger blind, dem Controller zuordenbar

Wenn das Übungsziel darin besteht, die Erkennung zu messen, statt eine Allowlist zu testen, kann das Ziel-SOC blind bleiben, ohne dass der Betrieb nicht nachvollziehbar wird:

1. Der Übungscontroller genehmigt jede öffentliche Quelle, Domain, jedes Zertifikat und jedes On-Site-Gerät, hält die Liste jedoch vor dem SOC geheim.
2. Der Controller speichert die Zuordnung von Quelle zu Engagement/Operator in einem separaten verschlüsselten Vault mit Notfallzugriff durch zwei Personen.
3. Jeder Operator-Job erhält ein signiertes Manifest mit Scope, Zeitfenster, Source-Kompartiment und irreversibler Job-ID. Das Ziel muss das Manifest während des normalen Betriebs nicht sehen.
4. Bastion-Audit-Ereignisse werden verkettet oder append-only an den Speicher des Controllers gesendet, sodass ein Operator die Zuordnung nach einem Vorfall nicht unbemerkt umschreiben kann.
5. Ein 24/7-Provider-Abuse-Kontakt verfügt über eine Verifikationsphrase/-referenz, die die Autorisierung bestätigt, ohne den Kunden öffentlich offenzulegen.
6. Jeder Pfad implementiert einen Out-of-Band-Stop-Kanal, der nicht vom Assessment-C2, Zielnetzwerk oder Konto eines einzelnen Operators abhängt.
7. Sende vor Live-Tests harmlose Canaries von jeder Quelle. Bestätige, dass der Controller sie innerhalb der ROE-Reaktionszeit auflösen und stoppen kann.
8. Vergleiche nach der Übung die SOC-Telemetrie mit dem Controller-Ledger, lege die Quellenliste offen und erläutere verpasste oder falsche Erkennungen.

Füge keine Anti-Forensik, Log-Zerstörung, kompromittierten Relays oder falschen Teilnehmeridentitäten hinzu. Diese Maßnahmen verhindern verantwortungsvolle Tests, statt sie zu verbessern.

## Teardown-Checkliste

- [ ] Der Übungscontroller bestätigt den Stopp.
- [ ] C2, Tunnel, Redirectors, Mail, VPN und geplante Jobs sind deaktiviert.
- [ ] On-Site-Geräte wurden physisch zurückgeholt und abgeglichen.
- [ ] Tokens, API-Keys, SSH-Keys, Zertifikate und erfasste Zugangsdaten wurden widerrufen/rotiert.
- [ ] DNS- und Cloud-Ressourcen wurden entfernt oder zur defensiven Aufbewahrung übertragen.
- [ ] Kundendaten wurden gemäß Vertrag zurückgegeben, aufbewahrt oder vernichtet.
- [ ] Erforderliche Finanz-, Audit- und Autorisierungsaufzeichnungen bleiben verschlüsselt und zugriffskontrolliert.
- [ ] Provider-Abuse-Fälle wurden geschlossen und der Kunde hat die endgültigen Quellindikatoren erhalten.
- [ ] Ein zweiter Operator überprüft, dass keine Infrastruktur aktiv bleibt.

## References

- [1] [NIST CSRC — Regeln für Engagements](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Technischer Leitfaden für Tests und Bewertungen der Informationssicherheit](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Kundensupport-Richtlinie für Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Datenschutzhinweis](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Richtlinie für Registrierungsdaten](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
