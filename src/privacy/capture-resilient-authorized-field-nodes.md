# Capture-Resiliente autorisierte Field Nodes

{{#include ../banners/hacktricks-training.md}}

Ein Raspberry Pi, Mini-PC, Travel Router oder Mobilfunkgerät vor Ort kann einem autorisierten Red Team einen dauerhaften Ausgangspunkt bieten. Es ist jedoch auch ein wahrscheinlicher Ort für Entdeckung, Diebstahl und Attribution. Das richtige Designziel ist daher **stabiler, kontrollierter Zugriff mit wenig Autorität auf dem Field Node** und kein nicht zurückverfolgbarer Implant.

Dieser Leitfaden gilt ausschließlich für Geräte, die mit der schriftlichen Genehmigung des Eigentümers vor Ort platziert wurden. Ein Café, Nachbar, Hotel oder gemeinsam genutztes Gebäude ist nicht allein deshalb im Umfang enthalten, weil sein Netzwerk erreichbar ist. Verstecke keine Hardware an einem Ort ohne Zustimmung, umgehe kein Captive Portal, verwende keine Zugangsdaten einer anderen Person, greife nicht in Monitoring ein und versuche nicht, nach der Entdeckung Beweise zu löschen.

{% hint style="warning" %}
Es gibt keine verlässliche Einstellung für „keine Spuren hinterlassen“. Aufzeichnungen über Radioverbindungen, DHCP/NAT, Carrier, Kameras, Käufe, Geräte, Provider, Controller und Ziele können das Gerät überdauern. Ein verantwortungsbewusstes Red Team entfernt stattdessen **persönliche und nicht zugehörige Secrets** vom Node, bewahrt die geschützte Attribution auf dem Controller auf und gestaltet die Erfassung so, dass sie kostengünstig eingedämmt werden kann.
{% endhint %}

## Vor- und Nachteile

**Vorteile:** realistische interne oder zielnahe Quelle; stabiles High-Speed-Testing; validiert NAC, Egress, physische Inventarisierung und SOC-Abdeckung; kann Änderungen der Operator-Adresse überstehen; der Zugriff kann zentral eingeschränkt werden.

**Nachteile:** Die physische Platzierung erzeugt starke Beweise; ein Verlust kann Geräte-Credentials, Netzwerkprofile und gesammelte Daten offenlegen; wiederholter Control-Traffic ist erkennbar; Stromversorgung, Portale und Änderungen der Funkverbindung beeinträchtigen die Zuverlässigkeit; ein breiter Tunnel kann zu einem unkontrollierten Pivot werden.

## Threat Model und Design-Invarianten

Gehe davon aus, dass ein Finder den Speicher entfernen, die Firmware untersuchen, jedes softwareseitig gespeicherte Secret kopieren, späteres Netzwerkverhalten beobachten und das Gerät dem Kunden oder den Strafverfolgungsbehörden übergeben kann. Full-Disk-Encryption schützt ein ausgeschaltetes Gerät nur innerhalb des dafür angegebenen Threat Models; ein laufender, entsperrter Node und in den Speicher geladene Schlüssel sind andere Fälle.

| Invariante | Praktische Konsequenz |
|---|---|
| Keine direkte Operator-zu-Node-Identität | Der Operator meldet sich am Organization Gateway an; der Node besitzt eine andere Geräteidentität |
| Kein Material von persönlichen Workstations | Kein persönlicher SSH-Key, kein Browserprofil, keine E-Mail, kein Passwortmanager, kein Phone Pairing und kein Cloud-CLI-Cache |
| Kein Master-Secret des Controllers | Ein Node kann keinen anderen registrieren, keine Richtlinie ändern und keine anderen Engagements entschlüsseln |
| Nur ausgehend und eng begrenzt | Das Field-Netzwerk akzeptiert keinen Management-Listener; der Node erreicht nur benannte Rendezvous-, Update- und Time-Services |
| Kurzlebige, begrenzte Autorität | Jedes Credential gilt für genau ein Gerät, eine Audience, einen Service und eine Ablaufzeit und besitzt einen sofort nutzbaren Revocation-Pfad |
| Minimale lokale Daten | Ergebnisse werden an den Controller gestreamt; Caches sind verschlüsselt, hinsichtlich Größe und TTL begrenzt und nicht maßgeblich |
| Die Verantwortlichkeit des Controllers bleibt nach der Erfassung bestehen | Die Zuordnung von Asset zu Engagement, Genehmigungen, Operator-Zugriffe und Befehle werden zentral gespeichert und zugriffskontrolliert |
| Verlust beendet die Arbeit | Entdeckung oder eine nicht erklärte Zustandsänderung löst Stopp, Revocation, Benachrichtigung und Beweissicherung aus – nicht die Remote-Zerstörung |

Die IoT-Baseline des NIST gruppiert Geräteidentifikation, Konfiguration, Datenschutz, logischen Zugriff, sichere Softwareupdates und das Bewusstsein für den Cybersecurity-Zustand als zentrale Fähigkeiten. Sie behandelt insbesondere Zustandsbewusstsein und ereignisbezogene Aufzeichnungen außerhalb des Geräts als Unterstützung bei der Untersuchung von Kompromittierungen.<sup>[[1]](#references)</sup>

## Referenzarchitektur
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Das Gateway muss wissen, welcher benannte Operator welches benannte Gerät erreicht hat. Der Feldknoten benötigt für das Rendezvous lediglich eine Geräteanmeldedaten. Er erfährt niemals die Quelladresse oder das Authentifizierungsgeheimnis des Operators, und der Operator kopiert niemals einen privaten Managementschlüssel auf den Knoten. Dadurch wird die aus dem **Feldspeicher** wiederherstellbare persönliche Verknüpfung reduziert, ohne die Nachvollziehbarkeit der Übung zu zerstören.

Für eine größere Flotte kann ein Workload-Identity-System kurzlebige X.509-Identitäten ausstellen und Schlüssel automatisch rotieren. SPIFFE empfiehlt nach Möglichkeit X.509 SVIDs und beschreibt kurze Gültigkeitsdauern sowie häufige Rotation als Maßnahmen zur Begrenzung der Auswirkungen eines Schlüsselkompromisses.<sup>[[2]](#references)</sup> Ein kleines Team kann dieselben Eigenschaften mit einer privaten CA und automatisierten gerätespezifischen Zertifikaten umsetzen; die Installation von SPIRE ist nicht erforderlich, um dieses Muster umzusetzen.

## Schritt 1: die Platzierung autorisieren und registrieren

1. Erfasse den Eigentümer, den Standort, die exakt zulässige Platzierungszone, die zulässigen Netzwerke, das Bewertungsfenster, die zulässigen Ziele/Aktionen und die Notfallkontakte.
2. Erfasse das Modell, die Seriennummer, die Speicherseriennummer, die kabelgebundenen/drahtlosen MACs, die Modem-IMEI/eSIM oder SIM-ICCID, die Stromversorgung und ein aktuelles Foto.
3. Gib dem Gerät eine nicht personenbezogene Engagement-Kennung, zum Beispiel `E2026-014-DROP03`. Kodiere keinen Kundennamen in Broadcast-Hostnames oder SSIDs.
4. Informiere den Übungsleiter und die kleinste erforderliche Gruppe aus physischer Sicherheit/SOC darüber, was „verloren“, „bewegt“ und „entdeckt“ für diesen Test bedeutet.
5. Vereinbare im Voraus, wer es abholen darf und wie ein Finder den Fund melden kann. Ein Sicherheitsetikett kann sensible Kundendetails weglassen und zugleich eine kontrollierte Rückrufmöglichkeit bereitstellen.
6. Lege ein automatisches Ablaufdatum der Autorisierung fest. Eine über das Ende des Geltungsbereichs hinaus fortbestehende Konnektivität darf die Berechtigung nicht verlängern.

## Schritt 2: ein minimales wiederherstellbares Image erstellen

Verwende ein unterstütztes OS-Image, verifiziere dessen Signatur/Checksumme über den vom Hersteller dokumentierten Kanal, installiere Sicherheitsupdates und bewahre ein reproduzierbares Build-Manifest auf. Bevorzuge eine schreibgeschützte oder unveränderliche Basis mit einer kleinen beschreibbaren Datenpartition, sofern die Software dies zulässt.

1. Entferne Standardkonten, Demo-Dienste, Compiler und Pakete, die für die autorisierte Workload nicht benötigt werden.
2. Deaktiviere die lokale GUI, Bluetooth, Discovery-Protokolle, Dateifreigabe, Wi-Fi P2P und eingehende Administration, sofern die Übung nicht ausdrücklich eines davon erfordert.
3. Aktiviere Secure Boot und Measured Boot bzw. eine TPM-gestützte Schlüsselbereitstellung, wenn die Hardware dies tatsächlich unterstützt; behaupte nicht, dass eine Raspberry-Pi-Konfiguration über PC-Klasse-Measured-Boot verfügt, ohne das exakte Modell zu validieren.
4. Verschlüssele den lokal beschreibbaren Zustand und konfiguriere eine strikte maximale Größe sowie Aufbewahrungsdauer. Verschlüsselung ist eine Maßnahme zur Verzögerung/Eindämmung und kein Beleg dafür, dass ein laufender Knoten nichts preisgibt.
5. Sende wichtige Logs vom Gerät weg. Begrenze lokale Journale, um eine Erschöpfung des Speichers zu verhindern, konfiguriere jedoch kein Löschen von Logs oder keine anti-forensische Löschung.
6. Speichere das Image-Manifest, Paketversionen, den Konfigurations-Hash und Wiederherstellungsanweisungen beim Controller.
7. Erstelle ein Ersatzgerät anhand des Manifests neu und führe denselben Integritätstest aus. Ein Design, das nur von seinem Ersteller wiederhergestellt werden kann, ist nicht für den Feldeinsatz geeignet.

## Schritt 3: Identitäten mit einseitigem Vertrauen ausstellen

Erstelle drei unterschiedliche Identitäten:

- eine **Geräteidentität**, die nur vom Rendezvous für dieses Gerät akzeptiert wird;
- eine **Operatoridentität**, die vom Organisations-Gateway akzeptiert und mit phishing-resistenter MFA geschützt wird; und
- eine **Controller-/Deployment-Identität**, die zum Signieren genehmigter Jobs oder Konfigurationen verwendet und außerhalb von Operator und Feldknoten verwahrt wird.

Der Knoten sollte über den öffentlichen Schlüssel verfügen, der zum Verifizieren signierter Jobs erforderlich ist, niemals jedoch über den Signierschlüssel. Ein abgegriffenes Geräte-Credential darf sich nicht bei Cloud-Konsolen, Source-Repositories, Zahlungskonten, anderen Knoten oder der Produktionsumgebung des Kunden authentifizieren.

Verwende kurze Zertifikatslaufzeiten, sofern eine automatische Erneuerung zuverlässig funktioniert. Wenn ein langlebiger WireGuard-Schlüssel betrieblich erforderlich ist, behandle seinen öffentlichen Schlüssel als Revocation-Handle und beschränke ihn durch eine peerspezifische Tunneladresse, eine Firewall-Richtlinie und eine Broker-Autorisierung. Halte eine getestete Controller-Aktion bereit, die diesen Peer sofort entfernt.

## Schritt 4: stabiles ausgehendes Rendezvous

Das folgende Muster für ein eigenes Labor ermöglicht stabiles Management hinter NAT, ohne einen eingehenden Dienst offenzulegen. Es handelt sich um gewöhnliche WireGuard-Netzwerkkommunikation, nicht um eine verdeckte Reverse Shell. Verwende Dokumentationsadressen und ersetze sie nur durch organisationsseitig betriebene Endpunkte.

Weise beim Organisations-Rendezvous `10.77.0.1/32` zu; weise dem Feldknoten `10.77.0.20/32` zu. Der Peer-Eintrag des Gateways sollte nur die einzelne Adresse des Knotens akzeptieren:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Der Node stellt eine ausgehende Verbindung zum Rendezvous her und hält das NAT-Mapping nur bei Bedarf aufrecht:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard dokumentiert 25 Sekunden als sinnvolles Keepalive-Intervall über viele NAT-/Firewall-Implementierungen hinweg, wenn Persistenz erforderlich ist; wenn sie nicht benötigt wird, sollte es deaktiviert bleiben.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` macht dies bewusst zu einem Management-Pfad und nicht zu einem Default-Route-Pivot.

Wende anschließend Kontrollen außerhalb von WireGuard an:

1. Löse `vpn.redteam.example` über den genehmigten Bootstrap-DNS-Pfad auf und pinne den erwarteten Organisationsendpunkt in den Deployment-Datensätzen.
2. Erlaube auf dem Node ausgehendes DHCP/RA, erforderliches DNS/NTP, den Rendezvous-Endpunkt und den minimal erforderlichen genehmigten Update-Pfad. Verweigere nicht angeforderten eingehenden Traffic auf jedem Uplink.
3. Erlaube auf dem Rendezvous, dass `10.77.0.20` ausschließlich den für die Übung erforderlichen Broker-/Health-Service erreicht. Leite den Traffic nicht allgemein in ein Client-Netzwerk weiter.
4. Stelle interaktiven Operator-Zugriff hinter das Organisations-Gateway. Vermeide es, SSH vom Node über den Tunnel bereitzustellen, wenn eine signierte Pull-Job-Schnittstelle für die Bewertung ausreicht.
5. Konfiguriere den Service-Manager so, dass der Tunnel nach dem Netzwerkstart beginnt, sich nach einem Fehler mit begrenztem Backoff neu startet und nach wiederholten Fehlern einen Alert auslöst. Eine Restart-Schleife darf den Veranstaltungsort nicht überlasten oder den zugrunde liegenden Fehler verbergen.
6. Überprüfe den letzten Handshake des Peers, verwende jedoch nicht „Handshake vorhanden“ als Beweis dafür, dass das Gerät nicht kompromittiert ist.

TURN kann Relay-only-Erreichbarkeit für eine speziell entwickelte WebRTC-Control-Plane bereitstellen, und eine Message Queue kann intermittierenden Service tolerieren. TURN gibt einem Client hinter NAT ausdrücklich eine öffentliche Relay-Adresse; sein Server bleibt ein Beobachter.<sup>[[4]](#references)</sup> Wähle eine Control-Architektur, statt Tunnel ohne benannten Beobachter oder Zuverlässigkeitsvorteil übereinanderzustapeln.

## Step 5: Uplink-Stabilität ohne persönliche Verbindungen

Für einen autorisierten Venue-Node sollte diese Reihenfolge bevorzugt werden:

1. vom Client bereitgestellte kabelgebundene Verbindung oder dediziertes Test-VLAN;
2. vom Eigentümer genehmigtes Enterprise-/Guest-Wi-Fi-Profil;
3. von der Organisation vertraglich gebundener Cellular-/privater-APN-Fallback.

Statte ihn niemals mit einem persönlichen Smartphone-Hotspot, einer Heim-SSID, einer persönlichen eSIM, einem persönlichen Apple-/Google-Konto oder einem aus einem täglich verwendeten Laptop exportierten Wi-Fi-Profil aus. Genau diese Artefakte wird sich eine Capture-Situation aneignen.

Für jeden genehmigten Uplink:

- SSID/BSSID oder Switch/VLAN sowie das erwartete Captive-Portal-Verhalten dokumentieren;
- eine deterministische Priorität und einen Health Check zu einem eigenen Endpunkt festlegen;
- sicherstellen, dass ein Failover nur den Underlay ändert; Geräte- und Operator-Identitäten bleiben beim Broker;
- sicherstellen, dass DNS-, IPv6- und Application-Traffic während des Übergangs den Rendezvous nicht umgeht;
- bei unbekannter SSID/BSSID, SIM-Änderung, neuem Default-Gateway, Änderung von Public IP/ASN oder gleichzeitigen Uplinks einen Alert auslösen;
- vor dem Deployment Stromausfall, DHCP-Erneuerung, AP-Neustart, Änderung der Public IP, 24 Stunden Leerlauf, Tunnelausfall und die Wiederherstellung von Primary zu Secondary zu Primary testen.

Private MAC-Adressierung kann beiläufiges netzwerkübergreifendes Tracking reduzieren, aber für autorisiertes NAC ist häufig eine stabile MAC-Adresse pro Netzwerk erforderlich. Dokumentiere, was das gewählte OS tatsächlich macht, und rotiere nicht um die Zugriffskontrolle des Eigentümers herum.

## Step 6: Arbeit und Daten beschränken

Ein sicherer Field-Node sollte keine beliebigen Shell-Texte aus einem Mailbox-System akzeptieren. Definiere signierte Job-Typen wie `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` oder eine andere Aktion, die ausdrücklich in den Rules of Engagement genannt ist. Validiere Ziel, Dauer, Rate, Ausgabegröße und Scope erneut auf dem Node.

1. Gib jedem Job eine eindeutige ID, eine Geräte-Zielgruppe, einen Ausgabezeitpunkt, einen Ablaufzeitpunkt, eine Scope-Referenz und eine maximale Ausgabegröße.
2. Signiere ihn mit der Controller-/Deployment-Identität.
3. Weise unbekannte Felder, abgelaufene oder wiederverwendete Jobs sowie Jobs für ein anderes Gerät zurück.
4. Streame Ergebnisse an einen eigenen Collector; verschlüssele und TTL unvermeidbare lokale Spools.
5. Protokolliere beim Controller die akzeptierte/abgelehnte Job-ID und den Ergebnis-Hash. Platziere keine sensiblen Befehlsparameter in einem öffentlichen Monitoring-Kanal.
6. Beende die Verarbeitung, wenn die Autorisierung abläuft, die Identitätsrotation fehlschlägt oder der Controller das Gerät unter Quarantäne stellt.

## Monitoring für Entdeckung, Verlust oder Kompromittierung

Monitoring kann dem Controller mitteilen, dass sich der beobachtete Zustand geändert hat. Es kann nicht zuverlässig beweisen, dass „Ermittler das Gerät gefunden haben“, und der Versuch, Einsatzkräfte zu überwachen oder ihre Systeme zu sondieren, würde den Umfang einer autorisierten Bewertung überschreiten.

### Zustand außerhalb des Geräts sammeln

Sende in einem randomisierten, aber begrenzten operativen Intervall einen signierten Health-Datensatz mit geringer Datenmenge an den Controller. Füge nur ein, was der Controller benötigt:

- Geräte-ID, Boot-ID/-Zähler und monotone Uptime;
- Konfigurations-/Image-Hash und Softwareversion;
- Seriennummer des Geräte-Zertifikats und Erneuerungsstatus;
- Uplink-Klasse, Interface, BSSID oder Switch-Kontext, soweit autorisiert, Hash des Default-Gateways sowie Public IP/ASN, wie von einem eigenen Service beobachtet;
- Alter des Tunnel-Handshakes, Paket-Zähler und Queue-Tiefe;
- Gehäuseschalter- oder Hardware-Tamper-Status, sofern der Eigentümer den Sensor genehmigt hat;
- Festplattenauslastung, Temperatur, Schätzung der Clock-Abweichung und ID des letzten erfolgreichen Jobs;
- eine Sequenznummer und Signatur, um Replay oder Lücken sichtbar zu machen.

Speichere Gateway-Authentifizierung, Policy-Entscheidungen, Operator-Zugriff, Job-Übermittlung, Ergebnis-Hashes, Provider-Audit-Events und Alerts zentral. CISA empfiehlt, Logs zu zentralisieren, sie vor Löschung zu schützen, normale Aktivitäten zu baselinen und Kontakte für Incident Response zu benennen.<sup>[[5]](#references)</sup>

### Indikatoren für Entdeckung/Kompromittierung

| Signal | Mögliche Erklärungen | Aktion des Controllers |
|---|---|---|
| Heartbeat fehlt | Strom-/Netzwerkausfall, Portaländerung, Beschädigung, absichtliche Blockierung oder Entfernung | Provider-/Standortstatus korrelieren; nicht über einen nicht genehmigten Pfad erneut verbinden |
| Boot-Zähler unerwartet geändert | Stromunterbrechung, Crash, Entfernung oder Wartung | Jobs unter Quarantäne stellen; Zeit- und Standortereignisse vergleichen |
| Konfigurations-/Image-Hash geändert | Update-Fehler, Speicherfehler oder Manipulation | Arbeit stoppen; widerrufen, falls es sich nicht um ein vom Controller genehmigtes Release handelt |
| Neuer Uplink/BSSID/Gateway/ASN | AP-Austausch, Roaming, bewegtes Gerät oder Interception | Mit genehmigtem Inventar vergleichen; einen ungeklärten Übergang unter Quarantäne stellen |
| Wiederholt abgelehnter Job/Signatur | Beschädigung, Replay oder nicht autorisierter Controller | Verarbeitung stoppen und Gateway-/Controller-Logs untersuchen |
| Geräte-Credential zweimal oder über inkompatible Pfade verwendet | geklonter Schlüssel, wiederverwendeter Snapshot oder Netzwerkübergang | Sofort widerrufen; beide Sitzungsdatensätze behalten |
| Unerwarteter lokaler Login, unerwartetes Interface, unerwarteter Prozess oder Privilege-Event | Wartung oder Kompromittierung | Über die Broker-Policy isolieren; Beweise sichern |
| Übergang des Gehäuseschalters/-status | Service, Bewegung oder Entdeckung | Benannten Standortkontakt benachrichtigen; keine destruktive Aktion auslösen |
| Provider-Abuse-Mitteilung/Account-Anfrage oder SOC-Alert | Entdeckung, Fehlkonfiguration oder Traffic außerhalb des Scopes | Aktivität stoppen und Deconfliction-/Incident-Prozess einleiten |
| Sentinel-Credential verwendet | Jemand hat ein ausschließlich für diesen Node bestimmtes Decoy-Secret ohne Privilegien gelesen | Echte Geräteidentität widerrufen und die Alert-Spur sichern |

Eine Sentinel-Credential darf **keinen Zugriff** gewähren, darf nur einen organisations-eigenen Alert-Service aufrufen und muss in den Rules of Engagement offengelegt werden. Sie ist ein Tripwire für unbefugtes Lesen, kein Beacon zur Verfolgung der Person, die das Gerät gefunden hat.

### Alert-Schwellenwerte

Verwende zustandsbehaftete Regeln statt eines einzelnen dramatischen „Erwischt“-Alarms:

- **warning:** ein verpasstes Intervall, normale Adressänderung oder wachsende Queue;
- **degraded:** drei aufeinanderfolgende verpasste Intervalle, Verzögerung bei der Erneuerung, Verlust des Primary-Uplinks oder wiederholter Restart;
- **quarantine:** nicht genehmigte Hash-/Boot-/Uplink-Änderung, doppelte Credential, Sentinel-Nutzung oder unerwartetes privilegiertes Event;
- **confirmed discovery/loss:** Meldung vom Standort/Controller, Abweichung im physischen Inventar, Wiedererlangung des Geräts durch eine ungeplante Partei oder validierte Eskalation durch Provider/SOC.

Teste die Alert-Zustellung über einen vom Field-Node unabhängigen Kanal. Vermeide es, sensible Client-/Gerätedetails an persönliche Messaging- oder Consumer-Push-Konten zu senden.

## Runbook für vermutete Entdeckung oder Capture

1. **Stop:** Neue Jobs und Operator-Sitzungen aussetzen. Keine Probe senden, die prüft, ob das Gerät überwacht wird.
2. **Quarantine:** Den Broker so konfigurieren, dass er die Geräteidentität und ihre Routen verweigert, während vorhandene Logs erhalten bleiben.
3. **Revoke:** Geräte-Zertifikat/-Schlüssel, Queue-Token, Update-Credential und jedes Single-Purpose-Service-Token widerrufen. Die Organisations-SIM sperren, wenn ein physischer Verlust plausibel ist.
4. **Preserve:** Controller-, Gateway-, Provider- und Alert-Datensätze sichern; vertrauenswürdige Zeit, handelnde Person und letzte bekannte Konfiguration dokumentieren. Den Node nicht löschen oder remote wipen.
5. **Notify:** Übungs-Controller, Client-Incident-Kontakt sowie die in der Autorisierung definierten Legal-/Privacy-Kontakte benachrichtigen. Falls eine dritte Partei ihn gefunden hat, den vorab vereinbarten Recovery-Prozess verwenden.
6. **Assess:** Davon ausgehen, dass jedes Secret und jedes gecachte Ergebnis auf dem Node offengelegt wurde. Genau auflisten, worauf jedes Secret zugreifen konnte und ob es nach dem verdächtigen Ereignis verwendet wurde.
7. **Contain downstream:** Betroffene Service-Credentials rotieren, ausstehende Jobs invalidieren und Logs eigener Ziele/Provider auf unerwartetes Verhalten prüfen.
8. **Recover safely:** Nur durch eine autorisierte Person zurückholen; fotografieren/verpacken, die Chain of Custody dokumentieren und forensische Beweise nach Anweisung des Clients sichern.
9. **Resume with a new identity:** Die erfasste Credential niemals stillschweigend wieder aktivieren. Aus dem bekannten Manifest neu aufbauen, den Kontrollfehler beheben und eine ausdrückliche Genehmigung einholen.

Die aktuellen Incident-Response-Empfehlungen von NIST integrieren Vorbereitung, Erkennung, Reaktion und Wiederherstellung in das organisationsweite Cybersecurity-Risikomanagement; sichere zuerst die Beweise, damit der Client feststellen kann, was geschehen ist, und die geeignete Reaktion auswählen kann.<sup>[[6]](#references)</sup>

## Capture-Drill vor dem Deployment

Übergib ein entsperrtes Testgerät oder eine Kopie seines Speichers an eine unabhängige prüfende Person und bitte sie, Folgendes zu inventarisieren:

1. Geräte-/Standort-/Engagement-Identifikatoren;
2. Operator-Namen, persönliche Konten, Heim-/Workstation-Netzwerke und Recovery-Kontakte;
3. Controller-/Broker-Ziele und Credentials;
4. Client-Netzwerkprofile und gecachte Ergebnisse;
5. andere Geräte/Projekte, die mit jedem Secret erreichbar sind;
6. Wert- oder Zahlungs-Credentials;
7. was der Controller widerrufen kann und wie schnell;
8. welche Aktivitäten anhand zentraler Logs weiterhin zugeordnet werden können.

Erfolgskriterien: keine persönlichen Konten/Workstation-Schlüssel; keine engagementübergreifende oder Enrollment-Autorität; keine Zahlungs-Credential; begrenzter verschlüsselter Cache; eine dokumentierte Geräte-Widerrufsaktion; vollständige Verantwortlichkeit auf Controller-Seite. Behandle jede unerwartete persönliche Verbindung oder laterale Fähigkeit als Release-Blocker.

## Closeout

1. Jobs stoppen und die Broker-Route am Ende des Scopes deaktivieren.
2. Das genaue Inventar zurückholen und abgleichen; Fehlendes melden.
3. Logs/Ergebnisse und, falls erforderlich, ein forensisches Image gemäß dem Aufbewahrungsplan des Engagements sichern.
4. Geräte-, SIM-, Queue-, Update- und Service-Identitäten widerrufen, auch wenn die Hardware wiedererlangt wurde.
5. Erst nach Sicherung/Abnahme die Medien über den vom Eigentümer genehmigten Prozess zur Datenentsorgung bereinigen oder zerstören und den Abschluss dokumentieren. Dies ist Lifecycle-Management, keine Verschleierung.
6. Venue-NAC-/DHCP-Reservierungen, Broker-Routen, DNS, Cloud-Rollen, Alert-Regeln und temporäre Kontakte entfernen.
7. Erkannte Aktivitäten, fehlende Telemetrie, Zeit bis zur Quarantäne und jedes durch die Capture-Situation offengelegte Artefakt dokumentieren.

## References

- [1] [NIST — Katalog der Cybersecurity-Fähigkeiten für IoT-Geräte](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Konzepte und kurzlebige Workload-Identitäten](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistentes Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Logging auf Geschäftssystemen verwenden](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Empfehlungen und Überlegungen zur Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
