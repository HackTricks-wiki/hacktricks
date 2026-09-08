# Capture-Resiliente Authorized Field Nodes

Ein Raspberry Pi, Mini-PC, Travel Router oder Mobilfunkgerät vor Ort kann einem autorisierten Red Team einen dauerhaften Ausgangspunkt bieten. Es ist jedoch auch ein wahrscheinlicher Punkt für Entdeckung, Diebstahl und Zuordnung. Das richtige Designziel ist daher **stabiler, kontrollierter Zugriff mit möglichst wenig Berechtigungen auf dem Field Node**, nicht ein nicht zurückverfolgbares Implantat.

Dieser Leitfaden gilt ausschließlich für Geräte, die mit der schriftlichen Genehmigung des Site-Eigentümers platziert wurden. Ein Café, Nachbar, Hotel oder gemeinsam genutztes Gebäude fällt nicht allein deshalb in den Geltungsbereich, weil sein Netzwerk erreichbar ist. Verstecke keine Hardware an einem Ort ohne Zustimmung, umgehe kein Captive Portal, nutze keine Zugangsdaten einer anderen Person, greife nicht in die Überwachung ein und versuche nach einer Entdeckung nicht, Beweise zu löschen.

{% hint style="warning" %}
Es gibt keine zuverlässige Einstellung „keine Spuren hinterlassen“. Funkverbindungs-, DHCP/NAT-, Carrier-, Kamera-, Kauf-, Geräte-, Provider-, Controller- und Zielsystemaufzeichnungen können das Gerät überdauern. Ein verantwortungsbewusstes Red Team entfernt stattdessen **persönliche und sachfremde Geheimnisse** vom Node, bewahrt die geschützte Zuordnung auf der Controller-Seite auf und sorgt dafür, dass eine Beschlagnahmung kostengünstig eingedämmt werden kann.
{% endhint %}

## Vor- und Nachteile

**Vorteile:** realistische interne oder zielnahe Quelle; stabile Hochgeschwindigkeitstests; Validierung von NAC, Egress, physischer Inventarisierung und SOC-Abdeckung; kann Änderungen der Operator-Adresse überstehen; der Zugriff kann zentral und begrenzt widerrufen werden.

**Nachteile:** Die physische Platzierung erzeugt starke Beweise; bei Verlust können Gerätezugangsdaten, Netzwerkprofile und gesammelte Daten offengelegt werden; wiederholter Control-Traffic ist erkennbar; Stromversorgung, Portale und Änderungen der Funkverbindung beeinträchtigen die Zuverlässigkeit; ein breiter Tunnel kann zu einem unkontrollierten Pivot werden.

## Threat Model und Design-Invarianten

Gehe davon aus, dass ein Finder den Speicher entfernen, die Firmware untersuchen, jedes softwareseitig gespeicherte Geheimnis kopieren, späteres Netzwerkverhalten beobachten und das Gerät dem Kunden oder den Strafverfolgungsbehörden übergeben kann. Full-Disk Encryption schützt ein ausgeschaltetes Gerät nur innerhalb des angegebenen Threat Models; ein laufender, entsperrter Node und in den Speicher freigegebene Schlüssel sind unterschiedliche Fälle.

| Invariante | Praktische Konsequenz |
|---|---|
| Keine direkte Operator-zu-Node-Identität | Der Operator meldet sich am Organisations-Gateway an; der Node besitzt eine andere Geräteidentität |
| Keine persönlichen Workstation-Materialien | Kein persönlicher SSH-Key, Browser-Profil, E-Mail-Konto, Passwortmanager, Phone Pairing oder Cloud-CLI-Cache |
| Kein Master Secret des Controllers | Ein Node kann keinen anderen registrieren, keine Richtlinie ändern und keine anderen Engagements entschlüsseln |
| Nur ausgehend und eng begrenzt | Das Field Network akzeptiert keinen Management-Listener; der Node erreicht nur benannte Rendezvous-, Update- und Zeitdienste |
| Kurzlebige, begrenzte Berechtigungen | Jedes Credential ist auf ein Gerät, eine Audience, einen Service, eine Ablaufzeit und einen sofortigen Widerrufspfad beschränkt |
| Minimale lokale Daten | Ergebnisse werden an den Controller gestreamt; Caches sind verschlüsselt, in Größe und TTL begrenzt und nicht autoritativ |
| Die Verantwortlichkeit des Controllers bleibt bei einer Beschlagnahmung erhalten | Die Zuordnung von Asset zu Engagement, Genehmigungen, Operator-Zugriffe und Befehle werden zentral gespeichert und zugriffskontrolliert |
| Verlust beendet die Arbeit | Eine Entdeckung oder unerklärliche Zustandsänderung löst Stopp, Widerruf, Benachrichtigung und Beweissicherung aus – keine Fernzerstörung |

Die IoT-Baseline des NIST gruppiert Geräteidentifikation, Konfiguration, Datenschutz, logischen Zugriff, sichere Softwareupdates und das Bewusstsein für den Cybersecurity-Zustand als zentrale Fähigkeiten. Sie behandelt insbesondere Zustandsbewusstsein und Ereignisaufzeichnungen außerhalb des Geräts als Unterstützung bei der Untersuchung einer Kompromittierung.<sup>[[1]](#references)</sup>

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
Das Gateway muss wissen, welcher benannte Operator welches benannte Gerät erreicht hat. Der Feldknoten benötigt für das Rendezvous lediglich ein Geräte-Credential. Er erfährt niemals die Quelladresse oder das Authentifizierungsgeheimnis des Operators, und der Operator kopiert niemals einen privaten Managementschlüssel auf den Knoten. Dadurch wird die aus dem **Feldspeicher** rekonstruierbare persönliche Verbindung reduziert, ohne die Nachvollziehbarkeit der Übung zu zerstören.

Für eine größere Flotte kann ein Workload-Identity-System kurzlebige X.509-Identitäten ausstellen und Schlüssel automatisch rotieren. SPIFFE empfiehlt nach Möglichkeit X.509 SVIDs und beschreibt kurze Gültigkeitszeiten sowie häufige Rotation als Maßnahmen zur Begrenzung der Auswirkungen eines Schlüsselkompromittierung.<sup>[[2]](#references)</sup> Ein kleines Team kann dieselben Eigenschaften mit einer privaten CA und automatisierten gerätespezifischen Zertifikaten umsetzen; die Installation von SPIRE ist nicht erforderlich, um dieses Muster zu erfüllen.

## Step 1: die Platzierung autorisieren und registrieren

1. Eigentümer, Standort, exakt zulässige Platzierungszone, zulässige Netzwerke, Bewertungszeitraum, zulässige Ziele/Aktionen und Notfallkontakte erfassen.
2. Modell, Seriennummer, Speicherseriennummer, kabelgebundene/drahtlose MACs, Modem-IMEI/eSIM oder SIM-ICCID, Stromversorgung und ein aktuelles Foto erfassen.
3. Dem Gerät eine nicht personenbezogene Engagement-Kennung geben, zum Beispiel `E2026-014-DROP03`. Keinen Clientnamen in Broadcast-Hostnames oder SSIDs codieren.
4. Dem Übungsleiter und der kleinsten erforderlichen Gruppe für physische Sicherheit/SOC-Deconfliction mitteilen, was „verloren“, „bewegt“ und „entdeckt“ für diesen Test bedeutet.
5. Im Voraus vereinbaren, wer es abholen darf und wie ein Finder den Fund melden kann. Ein Sicherheitslabel kann sensible Clientdetails auslassen und dennoch einen kontrollierten Rückruf ermöglichen.
6. Ein automatisches Ablaufdatum der Autorisierung festlegen. Eine über das Scope-Ende hinaus fortbestehende Konnektivität darf die Berechtigung nicht verlängern.

## Step 2: ein minimal wiederherstellbares Image erstellen

Ein unterstütztes OS-Image verwenden, seine Signatur/Checksumme über den dokumentierten Kanal des Vendors verifizieren, Security-Updates installieren und ein reproduzierbares Build-Manifest aufbewahren. Wenn die Software dies erlaubt, eine schreibgeschützte oder unveränderliche Basis mit einer kleinen beschreibbaren Datenpartition bevorzugen.

1. Standardkonten, Demo-Services, Compiler und für den autorisierten Workload nicht benötigte Pakete entfernen.
2. Lokale GUI, Bluetooth, Discovery-Protokolle, File Sharing, Wi-Fi P2P und eingehende Administration deaktivieren, sofern die Übung nicht ausdrücklich eines davon erfordert.
3. Secure Boot und Measured Boot/TPM-gestützte Schlüssel-Freigabe aktivieren, wenn die Hardware dies tatsächlich unterstützt; nicht behaupten, dass eine Raspberry-Pi-Konfiguration ohne Validierung des exakten Modells PC-klassisches Measured Boot besitzt.
4. Lokalen beschreibbaren Zustand verschlüsseln und eine strikte maximale Größe sowie Aufbewahrungsdauer konfigurieren. Verschlüsselung ist eine Verzögerungs-/Eindämmungskontrolle, kein Beleg dafür, dass ein laufender Knoten nichts preisgibt.
5. Wichtige Logs vom Gerät weg senden. Lokale Journale begrenzen, um eine Erschöpfung des Speichers zu verhindern, aber kein Löschen von Logs oder anti-forensisches Löschen konfigurieren.
6. Image-Manifest, Paketversionen, Konfigurations-Hash und Wiederherstellungsanweisungen beim Controller speichern.
7. Einen Ersatz aus dem Manifest neu imagen und denselben Health-Test ausführen. Ein Design, das nur von seinem Ersteller wiederhergestellt werden kann, ist nicht feldtauglich.

## Step 3: Identitäten mit unidirektionalem Trust ausstellen

Drei unterschiedliche Identitäten erstellen:

- eine **Geräteidentität**, die nur vom Rendezvous für dieses Gerät akzeptiert wird;
- eine **Operatoridentität**, die vom Organisations-Gateway akzeptiert und mit phishing-resistenter MFA geschützt wird; und
- eine **Controller-/Deployment-Identität**, die zum Signieren genehmigter Jobs oder Konfigurationen verwendet und außerhalb von Operator und Feldknoten aufbewahrt wird.

Der Knoten sollte den öffentlichen Schlüssel zur Verifizierung signierter Jobs besitzen, niemals den Signierschlüssel. Ein erbeutetes Geräte-Credential darf sich nicht bei Cloud-Konsolen, Source-Repositories, Zahlungskonten, anderen Knoten oder der Client-Production authentifizieren.

Kurze Zertifikatslaufzeiten verwenden, wenn eine automatische Erneuerung zuverlässig funktioniert. Wenn ein langlebiger WireGuard-Schlüssel operativ erforderlich ist, seinen öffentlichen Schlüssel als Revocation-Handle behandeln und ihn mit einer Peer-spezifischen Tunneladresse, Firewall-Policy und Broker-Autorisierung einschränken. Eine getestete Controller-Aktion bereithalten, die diesen Peer sofort entfernt.

## Step 4: stabiles Outbound-Rendezvous

Das folgende Owned-Lab-Muster ermöglicht stabiles Management durch NAT, ohne einen eingehenden Service offenzulegen. Es handelt sich um gewöhnliches WireGuard-Networking, nicht um eine verdeckte Reverse Shell. Dokumentationsadressen verwenden und diese nur durch organisations-eigene Endpunkte ersetzen.

Beim Organisations-Rendezvous `10.77.0.1/32` zuweisen; dem Feldknoten `10.77.0.20/32` zuweisen. Der Gateway-Peer-Eintrag sollte nur die einzelne Adresse des Knotens akzeptieren:
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
WireGuard dokumentiert 25 Sekunden als sinnvolles Keepalive-Intervall für viele NAT-/Firewall-Implementierungen, wenn Persistenz erforderlich ist; wenn es nicht benötigt wird, sollte es deaktiviert bleiben.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` macht dies bewusst zu einem Management-Pfad und nicht zu einem Default-Route-Pivot.

Wende anschließend Kontrollen außerhalb von WireGuard an:

1. Löse `vpn.redteam.example` über den genehmigten Bootstrap-DNS-Pfad auf und hinterlege den erwarteten Organisationsendpunkt in den Deployment-Aufzeichnungen.
2. Erlaube auf dem Node ausgehendes DHCP/RA, den erforderlichen DNS/NTP-Verkehr, den Rendezvous-Endpunkt und den minimal erforderlichen genehmigten Update-Pfad. Verweigere nicht angeforderten eingehenden Traffic auf jedem Uplink.
3. Erlaube auf dem Rendezvous, dass `10.77.0.20` nur den für die Übung erforderlichen Broker-/Health-Service erreicht. Leite es nicht allgemein in ein Client-Netzwerk weiter.
4. Stelle interaktiven Operator-Zugriff hinter das Organisations-Gateway. Vermeide es, SSH vom Node über den Tunnel bereitzustellen, wenn eine signierte Pull-Job-Schnittstelle für das Assessment ausreicht.
5. Konfiguriere den Service Manager so, dass der Tunnel nach dem Netzwerkstart gestartet wird, nach einem Fehler mit begrenztem Backoff neu startet und nach wiederholten Fehlern einen Alert auslöst. Eine Restart-Schleife darf den Veranstaltungsort nicht überlasten oder den zugrunde liegenden Fehler verbergen.
6. Prüfe den letzten Handshake des Peers, verwende jedoch nicht „Handshake vorhanden“ als Beweis dafür, dass das Gerät nicht kompromittiert ist.

TURN kann Relay-only-Reichbarkeit für eine speziell entwickelte WebRTC-Control-Plane bereitstellen, und eine Message Queue kann intermittierenden Service tolerieren. TURN weist einem Client hinter NAT ausdrücklich eine öffentliche Relay-Adresse zu; sein Server bleibt ein Beobachter.<sup>[[4]](#references)</sup> Wähle eine Control-Architektur statt mehrere Tunnel zu stapeln, ohne einen benannten Beobachter oder Zuverlässigkeitsvorteil zu haben.

## Schritt 5: Uplink-Stabilität ohne persönliche Verbindungen

Für einen autorisierten Venue-Node sollte folgende Reihenfolge bevorzugt werden:

1. vom Client bereitgestellte kabelgebundene Verbindung oder dedizierte Test-VLAN;
2. vom Eigentümer genehmigtes Enterprise-/Guest-Wi-Fi-Profil;
3. von der Organisation vertraglich bereitgestellter Mobilfunk-/privater-APN-Fallback.

Statte ihn niemals mit einem persönlichen Telefon-Hotspot, einer privaten SSID, einer persönlichen eSIM, einem persönlichen Apple-/Google-Konto oder einem aus einem täglich verwendeten Laptop exportierten Wi-Fi-Profil aus. Genau diese Artefakte würde sich ein Capture aneignen.

Für jeden genehmigten Uplink:

- erfasse SSID/BSSID oder Switch/VLAN sowie das erwartete Verhalten des Captive Portals;
- setze eine deterministische Priorität und einen Health Check zu einem eigenen Endpunkt;
- sorge dafür, dass ein Failover nur das Underlay ändert; Geräte- und Operator-Identitäten bleiben beim Broker;
- stelle sicher, dass DNS-, IPv6- und Application-Traffic während des Übergangs den Rendezvous nicht umgeht;
- löse bei unbekannter SSID/BSSID, SIM-Wechsel, neuem Default Gateway, Änderung der öffentlichen IP/ASN oder gleichzeitigen Uplinks einen Alert aus;
- teste vor dem Deployment Stromausfall, DHCP-Erneuerung, AP-Neustart, Änderung der öffentlichen IP, 24 Stunden Inaktivität, Tunnelverlust und die Wiederherstellung von primär zu sekundär zu primär.

Private MAC-Adressierung kann beiläufiges netzwerkübergreifendes Tracking reduzieren, für autorisiertes NAC wird jedoch häufig eine stabile MAC-Adresse pro Netzwerk benötigt. Erfasse, was das ausgewählte OS tatsächlich tut, und rotiere nicht um die Zugriffskontrolle eines Eigentümers herum.

## Schritt 6: Arbeit und Daten beschränken

Ein sicherer Field-Node sollte keine beliebigen Shell-Texte aus einem Mailbox-System akzeptieren. Definiere signierte Job-Typen wie `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` oder eine andere Aktion, die ausdrücklich in den Rules of Engagement genannt ist. Validiere Ziel, Dauer, Rate, Ausgabegröße und Scope erneut auf dem Node.

1. Gib jedem Job eine eindeutige ID, eine Geräte-Zielgruppe, eine Ausgabezeit, einen Ablaufzeitpunkt, eine Scope-Referenz und eine maximale Ausgabegröße.
2. Signiere ihn mit der Controller-/Deployment-Identität.
3. Verwirf unbekannte Felder, abgelaufene oder erneut abgespielte Jobs sowie Jobs für ein anderes Gerät.
4. Übertrage Ergebnisse an einen eigenen Collector; verschlüssele jeden unvermeidbaren lokalen Spool und versehe ihn mit einer TTL.
5. Protokolliere angenommene/abgelehnte Job-ID und den Ergebnis-Hash beim Controller. Platziere keine sensiblen Command-Parameter in einem öffentlichen Monitoring-Kanal.
6. Stoppe die Verarbeitung, wenn die Autorisierung abläuft, die Identitätsrotation fehlschlägt oder der Controller das Gerät unter Quarantäne stellt.

## Monitoring auf Discovery, Verlust oder Kompromittierung

Monitoring kann dem Controller mitteilen, dass sich der beobachtete Zustand geändert hat. Es kann nicht zuverlässig beweisen, dass „Ermittler das Gerät gefunden haben“, und der Versuch, Einsatzkräfte zu überwachen oder ihre Systeme zu sondieren, würde den Umfang eines autorisierten Assessments überschreiten.

### Zustand außerhalb des Geräts erfassen

Sende dem Controller in einem randomisierten, aber begrenzten betrieblichen Intervall einen signierten Health Record mit geringer Datenmenge. Nimm nur auf, was der Controller benötigt:

- Geräte-ID, Boot-ID/-Zähler und monotone Uptime;
- Konfigurations-/Image-Hash und Softwareversion;
- Seriennummer des Geräte-Zertifikats und dessen Erneuerungsstatus;
- Uplink-Klasse, Interface, BSSID oder Switch-Kontext, soweit autorisiert, Hash des Default Gateways sowie die von einem eigenen Service beobachtete öffentliche IP/ASN;
- Alter des Tunnel-Handshakes, Paket-Zähler und Queue-Tiefe;
- Gehäuseschalter- oder Hardware-Tamper-Status, sofern der Eigentümer den Sensor genehmigt hat;
- Festplattenauslastung, Temperatur, geschätzte Clock-Abweichung und ID des letzten erfolgreichen Jobs;
- eine Sequenznummer und Signatur, um Replay oder Lücken sichtbar zu machen.

Speichere Gateway-Authentifizierung, Policy-Entscheidungen, Operator-Zugriff, Job-Übermittlung, Ergebnis-Hashes, Provider-Audit-Events und Alerts zentral. CISA empfiehlt, Logs zu zentralisieren, sie vor Löschung zu schützen, normale Aktivitäten als Baseline zu erfassen und Ansprechpartner für Incident Response zu benennen.<sup>[[5]](#references)</sup>

### Indikatoren für Discovery/Kompromittierung

| Signal | Mögliche Erklärungen | Aktion des Controllers |
|---|---|---|
| Heartbeat fehlt | Strom-/Netzwerkausfall, Portaländerung, Beschädigung, absichtliche Blockierung oder Entfernung | Provider-/Site-Status abgleichen; nicht über einen nicht genehmigten Pfad erneut verbinden |
| Boot-Zähler unerwartet geändert | Stromunterbrechung, Crash, Entfernung oder Wartung | Jobs unter Quarantäne stellen; Zeit- und Site-Events vergleichen |
| Konfigurations-/Image-Hash geändert | Update-Fehler, Speicherfehler oder Tampering | Arbeit stoppen; widerrufen, wenn es sich nicht um ein vom Controller genehmigtes Release handelt |
| Neuer Uplink/BSSID/Gateway/ASN | AP-Austausch, Roaming, verschobenes Gerät oder Interception | Mit genehmigtem Inventar vergleichen; unerklärten Übergang unter Quarantäne stellen |
| Wiederholt abgelehnter Job/Signatur | Beschädigung, Replay oder nicht autorisierter Controller | Verarbeitung stoppen und Gateway-/Controller-Logs untersuchen |
| Geräte-Credential zweimal oder über inkompatible Pfade verwendet | geklonter Schlüssel, wiederverwendeter Snapshot oder Netzwerkübergang | Sofort widerrufen; beide Session-Aufzeichnungen aufbewahren |
| Unerwarteter lokaler Login, Interface-, Prozess- oder Privilege-Event | Wartung oder Kompromittierung | Über Broker-Policy isolieren; Beweise sichern |
| Übergang des Gehäuseschalters/-status | Service, Bewegung oder Discovery | Benannten Site-Kontakt benachrichtigen; keine destruktive Aktion auslösen |
| Provider-Abuse-Meldung/Account-Anfrage oder SOC-Alert | Erkennung, Fehlkonfiguration oder Traffic außerhalb des Scopes | Aktivität stoppen und Deconfliction-/Incident-Prozess einleiten |
| Sentinel-Credential verwendet | Jemand hat ein einzigartiges Decoy-Secret ohne Berechtigungen gelesen | Reale Geräteidentität widerrufen und die Alert-Spur sichern |

Eine Sentinel-Credential darf **keinen Zugriff** gewähren, darf nur einen organisations-eigenen Alert-Service aufrufen und muss in den Rules of Engagement offengelegt werden. Sie ist ein Tripwire für unbefugtes Lesen, kein Beacon zum Tracking der Person, die das Equipment gefunden hat.

### Alert-Schwellenwerte

Verwende zustandsbehaftete Regeln statt eines dramatischen „Caught“-Alarms:

- **warning:** ein verpasstes Intervall, normale Adressänderung oder wachsender Queue;
- **degraded:** drei aufeinanderfolgende verpasste Intervalle, verzögerte Erneuerung, Verlust des primären Uplinks oder wiederholter Restart;
- **quarantine:** nicht genehmigte Hash-/Boot-/Uplink-Änderung, doppelte Credential, Verwendung eines Sentinel oder unerwartetes privilegiertes Event;
- **confirmed discovery/loss:** Meldung von Site/Controller, Abweichung im physischen Inventar, Wiedererlangung des Geräts durch eine nicht eingeplante Person oder validierte Eskalation durch Provider/SOC.

Teste die Alert-Zustellung über einen vom Field-Node unabhängigen Kanal. Vermeide es, sensible Client-/Gerätedetails an persönliche Messaging- oder Consumer-Push-Konten zu senden.

## Runbook bei vermuteter Discovery oder Capture

1. **Stop:** Suspendiere neue Jobs und Operator-Sessions. Sende keine Probe mit der Frage, ob das Gerät überwacht wird.
2. **Quarantine:** Lass den Broker die Geräteidentität und deren Routen verweigern, während vorhandene Logs erhalten bleiben.
3. **Revoke:** Widerrufe Geräte-Zertifikat/-Schlüssel, Queue-Token, Update-Credential und jedes Single-Purpose-Service-Token. Sperre die Organisations-SIM, wenn ein physischer Verlust plausibel ist.
4. **Preserve:** Erstelle Snapshots der Controller-, Gateway-, Provider- und Alert-Aufzeichnungen; dokumentiere die vertrauenswürdige Zeit, die handelnde Person und die zuletzt bekannte Konfiguration. Lösche den Node nicht und führe keinen Remote-Wipe durch.
5. **Notify:** Kontaktiere den Exercise Controller, den Client-Incident-Kontakt sowie die in der Autorisierung definierten Legal-/Privacy-Kontakte. Wenn eine dritte Partei das Gerät gefunden hat, verwende den vorab vereinbarten Recovery-Prozess.
6. **Assess:** Gehe davon aus, dass jedes Secret und jedes gecachte Ergebnis auf dem Node offengelegt wurde. Ermittle genau, worauf jedes Secret zugreifen konnte und ob es nach dem verdächtigen Ereignis verwendet wurde.
7. **Contain downstream:** Rotiere betroffene Service-Credentials, invalidiere ausstehende Jobs und untersuche Logs eigener Targets/Provider auf unerwartetes Verhalten.
8. **Recover safely:** Hole das Gerät nur durch eine autorisierte Person zurück; fotografiere und verpacke es, dokumentiere die Beweismittelkette und erfasse forensische Beweise gemäß den Anweisungen des Clients.
9. **Resume with a new identity:** Aktiviere die erfasste Credential niemals stillschweigend wieder. Erstelle das System aus dem bekannten Manifest neu, behebe den Kontrollfehler und hole eine ausdrückliche Genehmigung ein.

Die aktuelle Incident-Response-Leitlinie des NIST integriert Vorbereitung, Erkennung, Reaktion und Wiederherstellung in ein organisationsweites Cybersecurity-Risikomanagement; sichere zuerst die Beweise, damit der Client feststellen kann, was passiert ist, und die geeignete Reaktion auswählen kann.<sup>[[6]](#references)</sup>

## Capture-Drill vor dem Deployment

Übergib ein entsperrtes Testgerät oder eine Kopie seines Speichers an einen unabhängigen Reviewer und bitte ihn, Folgendes zu ermitteln:

1. Geräte-/Site-/Engagement-Identifikatoren;
2. Namen von Operatoren, persönliche Konten, Heim-/Workstation-Netzwerke und Recovery-Kontakte;
3. Controller-/Broker-Ziele und Credentials;
4. Client-Netzwerkprofile und gecachte Ergebnisse;
5. andere Geräte/Projekte, die mit jedem Secret erreichbar sind;
6. Wert- oder Zahlungs-Credentials;
7. was der Controller widerrufen kann und wie schnell;
8. welche Aktivitäten aus zentralen Logs weiterhin zugeordnet werden können.

Abnahmekriterien: keine persönlichen Konten/Workstation-Schlüssel; keine engagementübergreifende oder Enrollment-Autorität; keine Zahlungs-Credential; begrenzter verschlüsselter Cache; eine dokumentierte Geräte-Widerrufsaktion; vollständige Verantwortlichkeit auf Controller-Seite. Behandle jeden unerwarteten persönlichen Link oder jede laterale Fähigkeit als Release-Blocker.

## Abschluss

1. Stoppe Jobs und deaktiviere die Broker-Route am Ende des Scopes.
2. Hole das exakte Inventar zurück, gleiche es ab und melde alles Fehlende.
3. Bewahre Logs/Ergebnisse und, falls erforderlich, ein forensisches Image gemäß dem Aufbewahrungsplan des Engagements auf.
4. Widerrufe Geräte-, SIM-, Queue-, Update- und Service-Identitäten, auch wenn die Hardware zurückerlangt wurde.
5. Erst nach Sicherung/Abnahme: Bereinige oder zerstöre Medien mit dem vom Eigentümer genehmigten Prozess zur Datenentsorgung und dokumentiere den Abschluss. Dies ist Lifecycle-Management, keine Verschleierung.
6. Entferne Venue-NAC-/DHCP-Reservierungen, Broker-Routen, DNS, Cloud-Rollen, Alert-Regeln und temporäre Kontakte.
7. Dokumentiere die erkannte Aktivität, fehlende Telemetrie, die Zeit bis zur Quarantäne und jedes Artefakt, das durch das Capture offengelegt wurde.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
