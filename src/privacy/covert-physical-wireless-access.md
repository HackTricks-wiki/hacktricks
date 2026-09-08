# Covert Physical and Wireless Access

Eine detaillierte, vom Eigentümer genehmigte Implementierung mit ausgehendem Rendezvous, Wiederherstellung von Stromversorgung/Uplink, minimalen auf dem Gerät gespeicherten Geheimnissen, Capture-Tests und Überwachung auf mögliche Entdeckung finden Sie unter [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Die Änderung des Netzwerkpfads kann auch den scheinbaren physischen Ursprung verändern. Ein ausgefeilter Akteur kann ein nahegelegenes kompromittiertes System, ein verborgenes Gerät, einen öffentlichen Zugang, ein Mobilfunk-Backhaul oder einen Satellitenempfänger verwenden, sodass die Logs des Ziels vom Operator wegweisen. Keine dieser Maßnahmen beseitigt physische, Funk- oder Provider-Beweise; sie verlagert die Attribution in andere Datensätze.

## Technique matrix

| Technik | Scheinbarer Ursprung | Erforderliche Voraussetzung | Besonders wertvolle Beweise |
|---|---|---|---|
| Nearby wireless pivot | ein Unternehmen/ein Haushalt neben dem Ziel | kompromittierter dual-homed Host und WLAN-Zugriff auf das Ziel | Endpoint-Logs des Nachbarhosts, RF-Assoziation sowie RADIUS/DHCP des Ziels |
| Public/guest network | NAT des Veranstaltungsorts oder Tunnel-Exit | rechtmäßiger Zugriff oder Umgehung der Zugriffskontrolle | Captive Portal, DHCP, AP-Assoziation, CCTV sowie Zahlungs-/Standortaufzeichnungen |
| Covert drop device | kabelgebundene, WLAN- oder Mobilfunkadresse am Ziel oder in dessen Nähe | physische Platzierung oder Zustellung | Switchport/USB, RF, Inventar, Stromversorgung und Telemetrie des ausgehenden Tunnels |
| Cellular router/eSIM | Carrier-NAT oder dedizierte APN | Modem/SIM/Subscription | IMEI/IMSI/eSIM, Mobilfunksektor, Carrier-Konto und zeitliche Abstimmung des Datenverkehrs |
| Satellite-link abuse | Teilnehmeradresse im Beam-Footprint | protokoll- und dienstspezifische Schwachstelle | RF-Standort, Uplink-Flow, unmögliche RTT/Routenführung und Provider-Aufzeichnungen |

## Nearest-neighbor attack

Volexity dokumentierte 2022 eine APT28/GRU-Operation, bei der sich der Akteur räumlich entfernt von seinem eigentlichen Ziel befand. Er führte Password Spraying gegen den öffentlich erreichbaren Dienst des Ziels durch, um gültige Zugangsdaten zu erhalten, doch MFA verhinderte die direkte Anmeldung über das Internet. Das Enterprise-WLAN des Ziels akzeptierte diese Zugangsdaten ohne MFA. Der Akteur kompromittierte Organisationen in unmittelbarer physischer Nähe des Ziels, fand ein dual-homed System mit WLAN-Reichweite und verwendete dieses System, um sich am WLAN des Ziels zu authentifizieren. Volexity bezeichnete dies als **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Die Neuheit liegt in der Kombination. Kein Operator reist zum Ziel, und die Internet-facing service's MFA funktioniert weiterhin. Der kompromittierte Nachbar stellt die physische Nähe bereit; das gestohlene Ziel-Credential liefert den logischen Zugriff; das Ziel-Wi-Fi wird zum Pfad über die Grenze hinweg.

### Voraussetzungen und Sichtbarkeit

- Ein System in der Nähe muss remote steuerbar sein und über ein kompatibles Radio oder Zugriff auf einen weiteren nahegelegenen Pivot verfügen.
- Die Ziel-SSID muss dieses System erreichen, und die Wi-Fi-Zulassung muss ein wiederverwendbares Credential, Zertifikat oder einen Gerätezustand akzeptieren.
- Der Pivot benötigt häufig zwei gleichzeitig bestehende Pfade: einen zurück zum Operator und einen in das Ziel-WLAN.
- Das Ziel sieht möglicherweise eine neue Stations-MAC und einen legitimen Benutzernamen, aber kein zugehöriges Managed-Device-Zertifikat, keinen passenden Posture-, Verlaufs- oder erwarteten Gebäudeeintrag.
- Logs des Nachbar-Endpoints können Wireless-Scans, neue Profile, Interface-Änderungen, Tunneling und Remote-Control-Aktivitäten anzeigen.

### Erkennung und Prävention

1. Fordern Sie certificate-backed EAP-TLS und Managed-Device-Posture für Enterprise-Wi-Fi. Ein Password, das im Internet an MFA gescheitert ist, darf nicht allein deshalb ausreichen, weil es über Funk eintrifft.
2. Korrelieren Sie die RADIUS-Authentifizierung mit MDM/NAC-Identität, historischer Station-/Device-Bindung, AP-Standort, Ereignissen des physischen Zugangs und parallelen Sessions.
3. Lösen Sie einen Alert aus, wenn sich ein Account erstmals, von einem ungewöhnlichen AP-Randbereich, ohne Managed Certificate oder während dieselbe Identität an einem anderen Ort aktiv ist, verbindet.
4. Überwachen Sie Endpoints, die Interfaces bridgen können. Untersuchen Sie unter Windows, Linux und auf Network Appliances unerwartete WLAN-Profile, Forwarding-/NAT-Konfigurationen, virtuelle Adapter und persistente Tunnel.
5. Reduzieren Sie unnötige Signalabstrahlung durch eine sinnvolle AP-Platzierung und Power-Planung. Dies ist eine unterstützende Maßnahme, keine Authentifizierung.
6. Koordinieren Sie die Incident Response mit benachbarten Mietern: Die endgültige Funkquelle kann selbst ein Opfer sein.

Das [owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduziert diese Observables, ohne einen Nachbarn anzugreifen.

## Öffentliche Orte und Wi-Fi von Drittanbietern

Die Nutzung von Café-, Hotel-, Flughafen- oder kommunalem Wi-Fi ändert die IP-Adresse, die ein Ziel sieht. Sie schafft keine Anonymität. Der Betreiber des Ortes oder dessen Provider kann AP-Assoziierung, Device-MAC, DHCP-Lease, Captive-Portal-Account, SMS-/E-Mail-Validierung und Flow-Logs speichern. Physischer Zutritt, CCTV, Käufe, mobile Standortdaten und Reisedaten können das digitale Ereignis mit einer Person verknüpfen.

Ein Akteur kann versuchen, ein Identifikationsmerkmal durch randomisierte MAC-Adressen, ein separates Gerät, Bargeld oder einen Tunnel zu reduzieren. Eine Korrelation über mehrere Ebenen bleibt durch Ankunftszeit, wiederholte Muster beim Besuch von Orten, Radio-Fingerprints, Portal-Verhalten, Traffic-Timing, Kameraaufnahmen und den Tunnel-Provider möglich. Ein VPN verlagert das Ziel lediglich von den Logs des Ortes zu den VPN-Logs; es beseitigt nicht das Wissen des Ortes darüber, dass das Gerät anwesend war.

Betreiber öffentlicher Zugänge sollten Clients isolieren, lateralen Traffic blockieren, wenn möglich WPA2/3-Enterprise oder Per-Device-Keys einsetzen, angemessene DHCP-/RADIUS-/Security-Logs aufbewahren, Captive Portals schützen und einen Abuse-Prozess veröffentlichen. Red Teams sollten einen solchen Ort nur nutzen, wenn dessen Bedingungen und der Auftrag dies erlauben; das Umgehen eines Portals, das Stehlen von Zugriff oder das Targeting anderer Gäste ist keine autorisierte Testing-Abkürzung.

## Covert-Drop-Geräte und Warshipping

Ein Drop ist ein kleines System, das an einem Ort platziert oder dorthin geliefert und anschließend über ausgehendes Ethernet, Wi-Fi oder Mobilfunk kontrolliert wird. „Warshipping“ verpackt das Gerät so, dass eine gewöhnliche Lieferung es innerhalb des Funkbereichs transportiert. Die mögliche Hardware reicht von einem Single-Board-Computer bis zu einem modifizierten Ladegerät, USB-Peripheriegerät, Network Appliance oder batteriebetriebenen Modem.

Operative Architektur:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Das Gerät kann einen remote foothold bereitstellen, Wireless-Messungen durchführen, ein autorisiertes Exercise-Peripheriegerät emulieren oder Traffic weiterleiten. Seine scheinbare Quelle ist lokal, doch es erzeugt physische Spuren: Seriennummern, Verpackungen, Fingerabdrücke, Kameras, Zutrittsprotokolle, Stromverbrauch, USB-Deskriptoren, Switchport-Aushandlung, DHCP-Fingerprints, MAC-OUI-/Randomisierungsverhalten, RF-Emissionen und wiederkehrende Rendezvous-Verbindungen.

### Defensive controls

- Verfahren für Wareneingang und Asset-Inventar pflegen; unerwartete Elektronik und Pakete inspizieren, die an nicht existente Mitarbeiter adressiert sind.
- 802.1X/NAC für kabelgebundene und Wireless-Zugänge einsetzen, ungenutzte Ports deaktivieren und unbekannte Geräte in ein eingeschränktes Remediation-VLAN verschieben.
- Auf neue DHCP-Fingerprints, dauerhaft bestehende lokal vergebene MACs, neue USB-Netzwerk-/HID-Geräte, nicht autorisiertes Wi-Fi Direct/Bluetooth und langlebige ausgehende Tunnel alarmieren.
- Switchport-, Power-over-Ethernet-, DNS- und TLS-Verhalten als Baseline erfassen. Ein kleiner Host ohne Inventareintrag, der periodische verschlüsselte Verbindungen herstellt, ist aussagekräftiger als allein ein „Raspberry Pi OUI“.
- Während eines Exercises Inventar erstellen, kennzeichnen, den Scope festlegen, verschlüsseln, einen remote kill bereitstellen, eine Rückgabefrist setzen und sicherstellen, dass ein Verlust keine wiederverwendbaren Zugangsdaten offenlegen kann.

## Cellular and eSIM backhaul

Ein Cellular-Modem umgeht das Internet-Gateway des Ziels und kann einen Drop hinter Carrier-NAT durch ein ausgehendes Rendezvous erreichbar halten. Mobile Adressen können rotieren oder gemeinsam genutzt werden; der Cellular-Provider verfügt dennoch über aussagekräftige Subscriber- und Netzwerkdaten: SIM-/eSIM-Identität, IMSI, Geräte-IMEI, zugewiesene Adressen/Ports, Cell-/Sektor-Timing sowie Konto-, Zahlungs- und Roaming-Datensätze.

Aus Sicht des Unternehmens lassen sich unerwartete Modems und persönliche Hotspots durch Wireless-/RF-Surveys, USB-/PCI-Inventarisierung an Endpoints, MDM-Einschränkungen, die Überwachung nicht autorisierter SSIDs und physische Inspektion erkennen. Ein Drop, der Cellular für die Steuerung nutzt, kann weiterhin durch sein lokales Ethernet-/Wi-Fi-Verhalten und seine Funksignale erkannt werden.

Bei autorisierten Exercises sollte die Organisation das Subscription und das Modem besitzen, die Identifikatoren beim Controller dokumentieren und prüfen, ob die Bedingungen des Carriers/Providers den Traffic erlauben. Ein Prepaid-Label oder der Kauf mit Cryptocurrency löscht keine Tower-, Geräte- oder Händlerdatensätze.

## MAC randomization and device fingerprinting

Moderne Systeme können pro Netzwerk eine lokal vergebene randomisierte MAC verwenden. Dies reduziert die passive langfristige Nachverfolgung über eine stabile werkseitige MAC; es verbirgt jedoch nicht:

- Probe-/Association-Timing und die Menge der angeforderten Netzwerkfähigkeiten;
- 802.11-Information-Elements, unterstützte Datenraten und anbieterspezifisches Verhalten;
- DHCP-Optionen/Hostname, IPv6-Identifikatoren und Captive-Portal-/Browser-Fingerprint;
- authentifizierte 802.1X-Identität oder Zertifikat;
- Account-, Tunnel- und Traffic-Muster auf höheren Protokollebenen; oder
- physische Beobachtung.

Defender sollten MAC-Allowlists nicht als Authentication verwenden. Die Funkidentität sollte mit Zertifikat und Gerätezustand verknüpft werden; wechselnde MACs sollten als normal behandelt werden, sofern kein anderer Kontext anomal ist.

## Satellite-link hijacking

Kaspersky dokumentierte, wie Turla Schwachstellen im älteren unidirektionalen DVB-S-Satellite-Internet ausnutzte. Im beschriebenen Modell sendete ein legitimer Remote-Subscriber ausgehende Requests über eine terrestrische Verbindung, empfing Downstream-Daten jedoch über einen unverschlüsselten großflächigen Satellite-Broadcast. Ein Akteur innerhalb der Satellite-Abdeckung konnte den Downlink beobachten, eine aktive Subscriber-IP auswählen und dafür sorgen, dass C2-Replies an diese IP adressiert wurden. Sowohl der legitime Subscriber als auch der Akteur empfingen den Broadcast; der Akteur extrahierte den Traffic für den ausgewählten Port, während der legitime Subscriber nicht angeforderte Packets verwarf. Der C2-Betreiber schien anschließend eine Satellite-Provider-Adresse in einer anderen geografischen Region zu verwenden.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Dies war protokoll-/dienstspezifisch, bandbreitenbeschränkt und nicht gleichbedeutend mit der Kompromittierung eines modernen bidirektional verschlüsselten Satellitenterminals. Außerdem wurde der ausgehende Anfragepfad des Akteurs nicht vor einem ausreichend leistungsfähigen Beobachter verborgen. Zu den Erkennungsmöglichkeiten gehören asymmetrisches bzw. unmögliches Routing, Datenverkehr zu einem Teilnehmer, der den Datenfluss nicht initiiert hat, ungewöhnliche Zielports, Provider-Telemetrie, die Untersuchung des Empfängerstandorts und der RF-Umgebung sowie die Malware-Konfiguration. Verwende diesen Fall, um die Annahme infrage zu stellen, dass die Geolokalisierung einer C2-IP-Adresse den Standort ihres Controllers bestimmt – nicht als Bauanleitung.

## Arbeitsblatt zur physisch-digitalen Korrelation

Wenn eine scheinbar lokale Quelle verdächtig ist, erstelle eine einzige Zeitleiste:

1. synchronisiere die Uhren von AP, RADIUS, DHCP, DNS, Proxy, VPN, EDR, Switch und physischer Zutrittskontrolle;
2. identifiziere die erste Funkassoziation oder den ersten Link-up, nicht nur den ersten Alert;
3. ordne die Station Zertifikat, Geräte-Posture, DHCP-Fingerprint und Switch-/AP-Standort zu;
4. suche auf nahegelegenen Systemen nach gleichzeitigem Remote-Control-/Tunnel-Verkehr;
5. prüfe Lieferungen, Besucher, Inventarausnahmen, Kameras und RF-Befunde gemäß den geltenden Richtlinien und Gesetzen;
6. sichere das mutmaßliche Gerät und den flüchtigen Netzwerkstatus; führe nicht blind einen Power-Cycle durch;
7. ermittle, ob die scheinbare Quelle eine vom Akteur kontrollierte Infrastruktur oder ein weiteres Opfer ist.

## References

- [1] [Volexity — Der Nearest Neighbor Attack: Wie ein russischer APT nahegelegene Wi-Fi-Netzwerke für verdeckten Zugriff bewaffnete](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT-Command-and-Control im Himmel](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware-Erweiterungen (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Richtlinien zur Absicherung drahtloser lokaler Netzwerke](https://csrc.nist.gov/pubs/sp/800/153/final)
