# Verdeckter physischer und drahtloser Zugriff

{{#include ../banners/hacktricks-training.md}}

Eine detaillierte, vom Eigentümer genehmigte Implementierung mit ausgehender Rendezvous-Verbindung, Wiederherstellung von Energieversorgung/Uplink, auf dem Gerät gespeicherten minimalen Secrets, Capture-Tests und Überwachung auf mögliche Entdeckung findet sich unter [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Eine Änderung des Netzwerkpfads kann auch den scheinbaren physischen Ursprung verändern. Ein hochentwickelter Akteur kann ein kompromittiertes System in der Nähe, ein verstecktes Gerät, einen öffentlichen Zugang, ein Mobilfunk-Backhaul oder einen Satellitenempfänger verwenden, sodass die Logs des Ziels von der tatsächlichen Position des Operators wegweisen. Keine dieser Methoden beseitigt physische, funkbasierte oder providerseitige Beweise; sie verlagert die Zuordnung in andere Datensätze.

## Technikmatrix

| Technik | Scheinbarer Ursprung | Notwendige Voraussetzung | Beweismittel mit hohem Wert |
|---|---|---|---|
| Drahtloser Pivot in der Nähe | ein Unternehmen/ein Zuhause neben dem Ziel | kompromittierter dual-homed Host und Wi-Fi-Zugriff auf das Ziel | Endpoint-Logs des Nachbarhosts, RF-Assoziierung sowie RADIUS/DHCP des Ziels |
| Öffentliches/Gastnetzwerk | Venue-NAT oder Tunnel-Exit | rechtmäßiger Zugriff oder Umgehung der Zugriffskontrolle | Captive Portal, DHCP, AP-Assoziierung, CCTV sowie Zahlungs-/Standortdaten |
| Verdecktes Drop-Gerät | kabelgebundene, Wi-Fi- oder Mobilfunkadresse am Ziel oder in der Nähe | physische Platzierung oder Lieferung | Switchport/USB, RF, Inventar, Stromversorgung und Telemetrie des ausgehenden Tunnels |
| Mobilfunkrouter/eSIM | Carrier-NAT oder dedizierte APN | Modem/SIM/Abonnement | IMEI/IMSI/eSIM, Mobilfunksektor, Carrier-Konto und zeitliche Abstimmung des Datenverkehrs |
| Missbrauch eines Satellitenlinks | Teilnehmeradresse im Footprint des Beams | protokoll- und dienstspezifische Schwachstelle | RF-Ortung, Uplink-Datenfluss, unmögliche RTTs/Routen sowie Provideraufzeichnungen |

## Nearest-neighbor attack

Volexity dokumentierte 2022 eine APT28/GRU-Operation, bei der sich der Akteur räumlich entfernt von seinem eigentlichen Ziel befand. Er führte Password-Spraying gegen den öffentlichen Dienst des Ziels durch, um gültige Zugangsdaten zu erhalten, doch MFA verhinderte die direkte Anmeldung über das Internet. Das Enterprise-Wi-Fi des Ziels akzeptierte diese Zugangsdaten ohne MFA. Der Akteur kompromittierte Organisationen in unmittelbarer physischer Nähe des Ziels, fand ein dual-homed System mit drahtloser Reichweite und nutzte dieses System zur Authentifizierung am Wi-Fi des Ziels. Volexity bezeichnete dies als **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Die Neuheit liegt in der Kombination. Kein Operator reist zum Ziel, und die MFA des aus dem Internet erreichbaren Dienstes funktioniert weiterhin. Der kompromittierte Nachbar stellt die physische Nähe bereit; das gestohlene Ziel-Credential liefert den logischen Zugriff; das Ziel-Wi-Fi wird zum Pfad über die Grenze.

### Voraussetzungen und Sichtbarkeit

- Ein System in der Nähe muss remote steuerbar sein und über ein kompatibles Funkmodul oder Zugriff auf einen anderen nahegelegenen Pivot verfügen.
- Die Ziel-SSID muss dieses System erreichen, und die Wi-Fi-Zulassung muss ein wiederverwendbares Credential, Zertifikat oder einen wiederverwendbaren Gerätezustand akzeptieren.
- Der Pivot benötigt häufig zwei gleichzeitige Pfade: einen zurück zum Operator und einen in das Ziel-WLAN.
- Das Ziel sieht möglicherweise eine neue Stations-MAC und einen legitimen Benutzernamen, aber kein zugehöriges Managed-Device-Zertifikat, keine erwarteten Gerätezustandsdaten, keine Historie oder keinen passenden Gebäudeeintritt.
- Logs des benachbarten Endpunkts können Wireless-Scans, neue Profile, Interface-Änderungen, Tunneling und Remote-Control-Aktivitäten zeigen.

### Erkennung und Prävention

1. Für Enterprise-Wi-Fi sollten zertifikatsbasierte EAP-TLS- und Managed-Device-Posture-Prüfungen vorgeschrieben werden; ein Passwort, das bei der MFA im Internet gescheitert ist, darf nicht allein deshalb ausreichen, weil es über Funk eingeht.
2. RADIUS-Authentifizierung mit MDM/NAC-Identität, historischer Bindung von Station und Gerät, AP-Standort, Ereignissen des physischen Zugangs und gleichzeitigen Sessions korrelieren.
3. Alarmieren, wenn sich ein Account erstmals, von einem ungewöhnlichen AP-Randbereich, ohne Managed-Zertifikat oder während dieselbe Identität an einem anderen Ort aktiv ist, assoziiert.
4. Endpunkte überwachen, die Interfaces bridgen können. Unter Windows, Linux und auf Network Appliances unerwartete WLAN-Profile, Forwarding-/NAT-Konfigurationen, virtuelle Adapter und persistente Tunnel untersuchen.
5. Unnötiges Signals Spill durch sinnvolle AP-Platzierung und Power-Planung reduzieren. Dies ist eine unterstützende Maßnahme, keine Authentifizierung.
6. Incident Response mit benachbarten Mietern koordinieren: Die tatsächliche Funkquelle kann selbst ein Opfer sein.

Das [eigene Zwei-Organisationen-Lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduziert diese Observables, ohne einen Nachbarn anzugreifen.

## Öffentliche Orte und Wi-Fi von Drittanbietern

Die Nutzung von Wi-Fi in Cafés, Hotels, Flughäfen oder kommunalen Einrichtungen ändert die IP-Adresse, die bei einem Ziel angezeigt wird. Sie schafft keine Anonymität. Der Betreiber des Ortes oder sein Provider kann AP-Assoziation, Geräte-MAC, DHCP-Lease, Captive-Portal-Account, SMS-/E-Mail-Validierung und Flow-Logs speichern. Physischer Zutritt, CCTV, Käufe, mobile Standortdaten und Reisedaten können das digitale Ereignis mit einer Person verknüpfen.

Ein Akteur kann versuchen, eine einzelne Identifikationsmöglichkeit durch randomisierte MAC-Adressen, ein separates Gerät, Bargeld oder einen Tunnel zu reduzieren. Eine Korrelation über mehrere Ebenen bleibt durch Ankunftszeit, wiederholte Nutzungsmuster des Ortes, Radio-Fingerprints, Portalverhalten, Traffic-Timing, Kameraaufnahmen und den Tunnelprovider möglich. Ein VPN verlagert das Ziel lediglich von den Logs des Ortes zu den VPN-Logs; es beseitigt nicht das Wissen des Ortes, dass das Gerät dort anwesend war.

Betreiber öffentlicher Zugänge sollten Clients isolieren, lateralen Traffic blockieren, nach Möglichkeit WPA2/3-Enterprise oder gerätebezogene Keys einsetzen, angemessene DHCP-/RADIUS-/Security-Logs aufbewahren, Captive Portals schützen und einen Abuse-Prozess veröffentlichen. Red Teams sollten einen solchen Ort nur nutzen, wenn dessen Bedingungen und der Auftrag dies erlauben; das Umgehen eines Portals, der Diebstahl von Zugangsdaten oder das Angreifen anderer Gäste ist keine autorisierte Testing-Abkürzung.

## Verdeckte Drop-Geräte und Warshipping

Ein Drop ist ein kleines System, das an einem Standort platziert oder dorthin geliefert und anschließend über ausgehendes Ethernet, Wi-Fi oder Mobilfunk gesteuert wird. Beim „Warshipping“ wird das Gerät so verpackt, dass eine gewöhnliche Lieferung es innerhalb des Funkbereichs transportiert. Die mögliche Hardware reicht von einem Single-Board-Computer über ein modifiziertes Ladegerät, ein USB-Peripheriegerät oder eine Network Appliance bis zu einem batteriebetriebenen Modem.

Betriebsarchitektur:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Das Gerät kann einen Remote-Foothold bereitstellen, Funkmessungen durchführen, ein autorisiertes Übungs-Peripheriegerät emulieren oder Datenverkehr weiterleiten. Seine scheinbare Quelle ist lokal, doch es erzeugt physische Spuren: Seriennummern, Verpackungen, Fingerabdrücke, Kameras, Zutrittsprotokolle, Stromverbrauch, USB-Deskriptoren, Switchport-Aushandlung, DHCP-Fingerprints, MAC-OUI-/Randomisierungsverhalten, RF-Emissionen und wiederkehrende Rendezvous-Verbindungen.

### Defensive controls

- Verfahren für Wareneingang und Asset-Inventar pflegen; unerwartete Elektronik und Pakete inspizieren, die an nicht existente Mitarbeiter adressiert sind.
- 802.1X/NAC für kabelgebundene und drahtlose Zugänge einsetzen, nicht verwendete Ports deaktivieren und unbekannte Geräte in ein eingeschränktes Remediation-VLAN verschieben.
- Auf neue DHCP-Fingerprints, dauerhaft verwendete lokal verwaltete MACs, neue USB-Netzwerk-/HID-Geräte, nicht autorisiertes Wi-Fi Direct/Bluetooth und langlebige ausgehende Tunnel alarmieren.
- Switchport-, Power-over-Ethernet-, DNS- und TLS-Verhalten als Baseline erfassen. Ein kleiner Host ohne Inventareintrag, der regelmäßig verschlüsselte Verbindungen herstellt, ist aussagekräftiger als allein ein „Raspberry Pi OUI“.
- Während einer Übung Inventar erstellen, kennzeichnen, den Scope festlegen, verschlüsseln, einen Remote-Kill bereitstellen, eine Frist für die Rückholung setzen und sicherstellen, dass ein Verlust keine wiederverwendbaren Zugangsdaten offenlegt.

## Cellular and eSIM backhaul

Ein Cellular-Modem umgeht das Internet-Gateway des Ziels und kann einen Drop hinter Carrier-NAT über ein ausgehendes Rendezvous erreichbar halten. Mobile Adressen können rotieren oder gemeinsam genutzt werden; der Cellular-Betreiber verfügt dennoch über umfangreiche Teilnehmer- und Netzwerkdaten: SIM-/eSIM-Identität, IMSI, Geräte-IMEI, zugewiesene Adressen/Ports, Timing von Zellen/Sektoren sowie Konto-, Zahlungs- und Roaming-Datensätze.

Aus Sicht des Unternehmens lassen sich unerwartete Modems und persönliche Hotspots durch Wireless-/RF-Surveys, die USB-/PCI-Inventarisierung von Endpoints, MDM-Einschränkungen, die Überwachung nicht autorisierter SSIDs und physische Inspektionen erkennen. Ein Drop, der Cellular zur Steuerung verwendet, kann weiterhin anhand seines lokalen Ethernet-/Wi-Fi-Verhaltens und seiner Funkemissionen entdeckt werden.

Für autorisierte Übungen sollte die Organisation das Abonnement und das Modem besitzen, die Identifikatoren beim Controller dokumentieren und prüfen, ob die Bedingungen des Carriers/Providers den Datenverkehr erlauben. Ein Prepaid-Label oder der Kauf mit Kryptowährung löscht keine Aufzeichnungen von Funkzellen, Geräten oder Händlern.

## MAC randomization and device fingerprinting

Moderne Systeme können pro Netzwerk eine lokal verwaltete zufällige MAC verwenden. Dies reduziert die passive Langzeitverfolgung über eine stabile werkseitige MAC; es verbirgt jedoch nicht:

- Probe-/Association-Timing und die angeforderten Netzwerkfähigkeiten;
- 802.11-Informationselemente, unterstützte Datenraten und herstellerspezifisches Verhalten;
- DHCP-Optionen/Hostname, IPv6-Identifikatoren und Captive-Portal-/Browser-Fingerprint;
- authentifizierte 802.1X-Identität oder Zertifikat;
- Account auf höheren Schichten, Tunnel- und Datenverkehrsmuster; oder
- physische Beobachtung.

Defender sollten MAC-Allowlists nicht als Authentifizierung verwenden. Die Funkidentität sollte mit Zertifikat und Gerätezustand verknüpft werden; wechselnde MACs sollten als normal gelten, sofern kein anderer Kontext anomal ist.

## Satellite-link hijacking

Kaspersky dokumentierte, dass Turla Schwachstellen im älteren unidirektionalen DVB-S-Satellite-Internet nutzte. Im beschriebenen Modell sendete ein legitimer Remote-Teilnehmer ausgehende Anfragen über eine terrestrische Verbindung, empfing nachgelagerte Daten jedoch über eine unverschlüsselte, großflächige Satellite-Broadcast-Verbindung. Ein Akteur innerhalb der Satellite-Abdeckung konnte den Downlink beobachten, eine aktive Teilnehmer-IP auswählen und dafür sorgen, dass C2-Antworten an diese IP adressiert wurden. Sowohl der legitime Teilnehmer als auch der Akteur empfingen den Broadcast; der Akteur extrahierte den Datenverkehr für den ausgewählten Port, während der legitime Teilnehmer nicht angeforderte Pakete verwarf. Der C2-Betreiber schien anschließend eine Satellite-Provider-Adresse in einer anderen geografischen Region zu verwenden.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Dies war protokoll-/dienstspezifisch, bandbreitenbeschränkt und nicht gleichbedeutend mit der Kompromittierung eines modernen bidirektional verschlüsselten Satellitenterminals. Außerdem wurde der ausgehende Anfragepfad des Akteurs nicht vor einem ausreichend leistungsfähigen Beobachter verborgen. Erkennungsmöglichkeiten umfassen asymmetrisches/unmögliches Routing, Datenverkehr zu einem Teilnehmer, der den Flow nicht initiiert hat, ungewöhnliche Zielports, Provider-Telemetrie, Untersuchungen des Empfängerstandorts/der RF-Umgebung sowie die Malware-Konfiguration. Nutze diesen Fall, um die Annahme infrage zu stellen, dass die Geolokalisierung einer C2-IP-Adresse den Standort ihres Controllers bestimmt – nicht als Anleitung zum Nachbauen.

## Arbeitsblatt zur physisch-digitalen Korrelation

Wenn eine scheinbar lokale Quelle verdächtig ist, erstelle eine gemeinsame Zeitleiste:

1. synchronisiere die Uhren von AP, RADIUS, DHCP, DNS, Proxy, VPN, EDR, Switch und physischer Zutrittskontrolle;
2. ermittle die erste Funkassoziation oder den ersten Link-up, nicht nur den ersten Alert;
3. ordne die Station Zertifikat, Gerätestatus, DHCP-Fingerprint und Switch-/AP-Standort zu;
4. suche auf Systemen in der Nähe nach gleichzeitiger Fernsteuerungs-/Tunnelaktivität;
5. prüfe Lieferungen, Besucher, Inventarausnahmen, Kameras und RF-Befunde gemäß den geltenden Richtlinien/Gesetzen;
6. sichere das verdächtige Gerät und den flüchtigen Netzwerkstatus; führe nicht blind einen Power-Cycle durch;
7. ermittle, ob die scheinbare Quelle eine vom Akteur kontrollierte Infrastruktur oder ein weiteres Opfer ist.

## References

- [1] [Volexity — Der Nearest-Neighbor-Angriff: Wie eine russische APT nahegelegene Wi-Fi-Netzwerke für verdeckten Zugriff bewaffnete](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT-Command-and-Control im Himmel](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware-Erweiterungen (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Richtlinien zur Absicherung drahtloser lokaler Netzwerke](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
