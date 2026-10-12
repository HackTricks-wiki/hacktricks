# Verdeckter physischer und drahtloser Zugriff

{{#include ../banners/hacktricks-training.md}}

Eine detaillierte, vom Eigentümer genehmigte Umsetzung mit ausgehendem Rendezvous, Wiederherstellung von Stromversorgung/Uplink, minimalen auf dem Gerät gespeicherten Geheimnissen, Capture-Tests und Überwachung auf mögliche Entdeckung findest du unter [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Eine Änderung des Netzwerkpfads kann auch den scheinbaren physischen Ursprung verändern. Ein ausgefeilter Akteur kann ein kompromittiertes System in der Nähe, ein verborgenes Gerät, öffentlichen Zugriff, eine Mobilfunkanbindung oder einen Satellitenempfänger nutzen, sodass die Protokolle des Ziels auf einen anderen Ort als den des Operators verweisen. Nichts davon beseitigt physische, Funk- oder Provider-Spuren; die Zuordnung verlagert sich lediglich in andere Datensätze.

## Technikmatrix

| Technik | Scheinbarer Ursprung | Erforderliche Voraussetzung | Besonders aussagekräftige Beweise |
|---|---|---|---|
| Drahtloser Pivot in der Nähe | ein Unternehmen/ein Wohnhaus neben dem Ziel | kompromittierter dual-homed Host und WLAN-Zugriff auf das Ziel | Endpoint-Protokolle des Nachbarhosts, Funkverbindung und RADIUS/DHCP des Ziels |
| Öffentliches/Gastnetzwerk | NAT oder Tunnelausgang des Veranstaltungsorts | rechtmäßiger Zugriff oder Umgehung der Zugangskontrolle | Captive Portal, DHCP, AP-Verbindung, CCTV sowie Zahlungs-/Standortdaten |
| Verdecktes Drop-Gerät | kabelgebundene, WLAN- oder Mobilfunkadresse des Ziels oder der Umgebung | physische Platzierung oder Zustellung | Switchport/USB, Funk, Inventar, Stromversorgung und Telemetrie des ausgehenden Tunnels |
| Mobilfunkrouter/eSIM | Carrier-NAT oder dedizierte APN | Modem/SIM/Abonnement | IMEI/IMSI/eSIM, Mobilfunkzelle, Kundenkonto beim Provider und Zeitpunkt des Datenverkehrs |
| Missbrauch eines Satellitenlinks | Teilnehmeradresse im Abdeckungsbereich des Beams | protokoll- und dienstspezifische Schwachstelle | Funkortung, Uplink-Datenfluss, unmögliche RTT/Weiterleitung und Provider-Aufzeichnungen |

## Nearest-Neighbor-Angriff

Volexity dokumentierte eine APT28/GRU-Operation aus dem Jahr 2022, bei der sich der Akteur räumlich weit entfernt von seinem eigentlichen Ziel befand. Er führte Password-Spraying gegen den öffentlichen Dienst des Ziels durch, um gültige Zugangsdaten zu erhalten, doch MFA verhinderte eine direkte Anmeldung über das Internet. Das Unternehmens-WLAN des Ziels akzeptierte diese Zugangsdaten ohne MFA. Der Akteur kompromittierte Organisationen in unmittelbarer Nähe des Ziels, fand ein dual-homed System mit drahtloser Reichweite und nutzte dieses System, um sich beim WLAN des Ziels anzumelden. Volexity bezeichnete diese Methode als **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

Die Neuheit liegt in der Kombination. Kein Operator reist zum Ziel, und die MFA des über das Internet erreichbaren Dienstes funktioniert weiterhin. Der kompromittierte Nachbar stellt die physische Nähe bereit; die gestohlene Zielanmeldedaten ermöglichen den logischen Zugriff; das Ziel-Wi-Fi wird zum Pfad über die Grenze.

### Voraussetzungen und Sichtbarkeit

- Ein nahegelegenes System muss aus der Ferne steuerbar sein und über ein kompatibles Funkmodul oder Zugriff auf einen weiteren nahegelegenen Pivot verfügen.
- Die Ziel-SSID muss dieses System erreichen, und die Wi-Fi-Zulassung muss ein wiederverwendbares Credential, Zertifikat oder Gerätestatus akzeptieren.
- Der Pivot benötigt oft zwei gleichzeitige Pfade: einen zurück zum Operator und einen ins Ziel-WLAN.
- Das Ziel sieht möglicherweise eine neue Stations-MAC und einen legitimen Benutzernamen, aber kein entsprechendes Zertifikat eines verwalteten Geräts, keinen Gerätestatus, keine Historie und keinen erwarteten Gebäudeeintritt.
- Die Endpunktprotokolle des Nachbarn zeigen möglicherweise WLAN-Scans, neue Profile, Schnittstellenänderungen, Tunneling und Aktivitäten zur Fernsteuerung.

### Erkennung und Prävention

1. Verlange für Unternehmens-Wi-Fi zertifikatsbasiertes EAP-TLS und den Gerätestatus verwalteter Geräte. Ein Passwort, dessen MFA im Internet fehlgeschlagen ist, darf nicht allein deshalb ausreichen, weil es über Funk eingeht.
2. Korreliere die RADIUS-Authentifizierung mit MDM/NAC-Identität, historischer Zuordnung von Station und Gerät, AP-Standort, Zutrittsereignissen und gleichzeitigen Sitzungen.
3. Löse einen Alarm aus, wenn sich ein Konto zum ersten Mal von einem ungewöhnlichen AP-Rand aus anmeldet, kein verwaltetes Zertifikat vorliegt oder dieselbe Identität andernorts aktiv ist.
4. Überwache Endpunkte, die Schnittstellen überbrücken können. Untersuche unter Windows, Linux und auf Netzwerkgeräten unerwartete WLAN-Profile, Weiterleitungs-/NAT-Konfigurationen, virtuelle Adapter und persistente Tunnel.
5. Verringere unnötige Signalabstrahlung durch sinnvolle AP-Platzierung und Leistungsplanung. Dies ist eine unterstützende Maßnahme, keine Authentifizierung.
6. Stimme die Incident Response mit benachbarten Mietern ab: Die eigentliche Funkquelle kann selbst ein Opfer sein.

Das [autorisierte Labor mit zwei Organisationen](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduziert diese beobachtbaren Merkmale, ohne einen Nachbarn anzugreifen.

### Einen Windows-Pivot-Pfad validieren

Ein Dual-Homed-Windows-Host überbrückt seine Schnittstellen nicht automatisch. Erfasse zuerst seine Adapter, Routen und den WLAN-Status und verbinde dich dann ausschließlich über ein genehmigtes Profil. Das Argument `name` für `netsh wlan connect` bezeichnet ein installiertes Profil, keine beliebige SSID und kein beliebiges Passwort. Vergleiche die Routingtabelle vor und nach der Verbindung, damit eine neue Standardroute weder den Kontrollpfad unterbricht noch das Ergebnis verfälscht. Fahre erst mit den [Prüfungen nach der Verbindung](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) fort, wenn du die vorgesehene Schnittstelle und Route bestätigt hast.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Das von Volexity veröffentlichte Vorfallsartefakt zeigt eine weitere nützliche Unterscheidung. Der eingebettete C#-Code öffnet die WLAN-API, listet Schnittstellen auf, liest EAP-XML von der Festplatte und ruft `WlanSetProfileEapXmlUserData` für ein benanntes Profil auf der ersten Wireless-Schnittstelle auf. Die API legt EAP-Benutzerdaten für ein vorhandenes 802.1X-Profil fest, doch die veröffentlichte Komponente enthält weder `WlanConnect` noch die im Bericht beschriebene Erkennungslogik. Betrachte sie als Bereitstellung eines Profils und nicht als vollständigen Connector und untersuche das resultierende Profil im Rahmen der [Bewertung von Clients und Supplicants](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Öffentliche Orte und WLANs von Drittanbietern

Die Nutzung von Café-, Hotel-, Flughafen- oder kommunalem WLAN ändert die IP-Adresse, die einem Ziel angezeigt wird. Sie schafft keine Anonymität. Der Betreiber des Ortes oder sein Anbieter kann AP-Verbindungen, Geräte-MAC-Adressen, DHCP-Leases, Captive-Portal-Konten, SMS-/E-Mail-Verifizierungen und Flow-Logs speichern. Zutritt, Videoüberwachung, Einkäufe, Standortdaten von Mobilgeräten und Reiseunterlagen können das digitale Ereignis mit einer Person verknüpfen.

Ein Angreifer könnte versuchen, eine dieser Spuren durch randomisierte MAC-Adressen, ein separates Gerät, Bargeld oder einen Tunnel zu reduzieren. Eine Korrelation über verschiedene Ebenen hinweg bleibt durch Ankunftszeit, wiederholte Nutzung desselben Ortes, Funkfingerabdrücke, Portalverhalten, Traffic-Zeitpunkte, Kameraaufnahmen und den Tunnelanbieter möglich. Ein VPN verlagert zudem die Informationen über das Ziel von den Logs des Ortes zu den VPN-Logs; es beseitigt nicht das Wissen des Betreibers, dass das Gerät vor Ort war.

Betreiber öffentlicher Zugangspunkte sollten Clients isolieren, lateralen Traffic blockieren, nach Möglichkeit WPA2/3-Enterprise oder gerätespezifische Schlüssel verwenden, angemessene DHCP-/RADIUS-/Sicherheits-Logs speichern, Captive Portals schützen und einen Prozess für Missbrauchsmeldungen veröffentlichen. Red Teams sollten solche Orte nur nutzen, wenn die Nutzungsbedingungen und der Auftrag dies erlauben; ein Portal zu umgehen, Zugangsdaten zu stehlen oder andere Gäste anzugreifen, ist keine autorisierte Abkürzung beim Testen.

## Verdeckte Drop-Geräte und Warshipping

Ein Drop ist ein kleines System, das an einem Standort platziert oder dorthin geliefert und anschließend über ausgehendes Ethernet, WLAN oder Mobilfunk gesteuert wird. Beim „Warshipping“ wird das Gerät so verpackt, dass es durch eine gewöhnliche Lieferung in den Funkbereich gelangt. Als Hardware kommen beispielsweise Einplatinencomputer, modifizierte Ladegeräte, USB-Peripheriegeräte, Netzwerkgeräte oder batteriebetriebene Modems infrage.

Betriebsarchitektur:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

Das Gerät kann einen Remote-Foothold bereitstellen, drahtlose Messungen durchführen, ein autorisiertes Übungsperipheriegerät emulieren oder Traffic weiterleiten. Seine scheinbare Quelle ist lokal, es hinterlässt jedoch physische Spuren: Seriennummern, Verpackungen, Fingerabdrücke, Kameras, Zugriffsprotokolle, Stromverbrauch, USB-Deskriptoren, Switchport-Aushandlung, DHCP-Fingerprints, MAC-OUI-/Randomisierungsverhalten, RF-Emissionen und wiederkehrende Rendezvous-Verbindungen.

### Defensive Maßnahmen

- Führen Sie Verfahren für Empfangsräume und Asset-Inventare; prüfen Sie unerwartete Elektronik und Pakete, die an nicht existierende Mitarbeitende adressiert sind.
- Verwenden Sie 802.1X/NAC für kabelgebundene und drahtlose Zugriffe, deaktivieren Sie ungenutzte Ports und platzieren Sie unbekannte Geräte in einem eingeschränkten Remediation-VLAN.
- Erzeugen Sie Alerts bei neuen DHCP-Fingerprints, dauerhaft vorhandenen lokal verwalteten MACs, neuen USB-Netzwerk-/HID-Geräten, nicht autorisiertem Wi-Fi Direct/Bluetooth und langlebigen ausgehenden Tunneln.
- Erstellen Sie eine Baseline für Switchport-, Power-over-Ethernet-, DNS- und TLS-Verhalten. Ein kleiner Host ohne Inventareintrag, der regelmäßig verschlüsselte Verbindungen herstellt, ist aussagekräftiger als allein die „Raspberry Pi OUI“.
- Erfassen Sie bei einer Übung die Geräte im Inventar, kennzeichnen Sie sie, legen Sie den Scope fest, verschlüsseln Sie sie, richten Sie einen Remote-Kill ein, setzen Sie eine Rückgabefrist und stellen Sie sicher, dass bei Verlust keine wiederverwendbaren Zugangsdaten offengelegt werden können.

## Mobilfunk- und eSIM-Backhaul

Ein Mobilfunkmodem umgeht das Internet-Gateway des Ziels und kann einen Drop hinter Carrier-NAT über ein ausgehendes Rendezvous erreichbar halten. Mobile Adressen können wechseln oder gemeinsam genutzt werden; der Mobilfunkanbieter verfügt weiterhin über aussagekräftige Teilnehmer- und Netzdaten: SIM-/eSIM-Identität, IMSI, Geräte-IMEI, zugewiesene Adressen/Ports, Zeitangaben zu Funkzellen/Sektoren sowie Konto-, Zahlungs- und Roaming-Daten.

Aus Unternehmenssicht lassen sich unerwartete Modems und persönliche Hotspots durch Wireless-/RF-Messungen, USB-/PCI-Inventare der Endgeräte, MDM-Einschränkungen, Überwachung nicht autorisierter SSIDs und physische Inspektionen erkennen. Ein Drop, der Mobilfunk zur Steuerung nutzt, kann dennoch anhand seines lokalen Ethernet-/Wi-Fi-Verhaltens und seiner Funkemissionen erkannt werden.

Bei autorisierten Übungen sollte die Organisation das Abonnement und das Modem besitzen, die Kennungen zusammen mit dem Controller erfassen und prüfen, ob die Bedingungen des Mobilfunkanbieters/Providers den Traffic erlauben. Ein vorausbezahltes Etikett oder der Kauf mit Kryptowährung löscht keine Funkzellen-, Geräte- oder Einzelhandelsdaten.

## MAC-Randomisierung und Geräte-Fingerprinting

Moderne Systeme können pro Netzwerk eine lokal verwaltete zufällige MAC verwenden. Das reduziert die passive Langzeitverfolgung anhand einer stabilen werkseitigen MAC, verbirgt jedoch nicht:

- Probe-/Assoziierungszeitpunkte und die Menge der angeforderten Netzwerkfunktionen;
- 802.11-Informationselemente, unterstützte Datenraten und herstellerspezifisches Verhalten;
- DHCP-Optionen/Hostname, IPv6-Kennungen und Captive-Portal-/Browser-Fingerprint;
- authentifizierte 802.1X-Identität oder Zertifikat;
- Accounts auf höheren Netzwerkschichten, Tunnel und Traffic-Muster; oder
- physische Beobachtung.

Verteidiger sollten MAC-Allowlists nicht zur Authentifizierung verwenden. Verknüpfen Sie die Funkidentität mit Zertifikat und Gerätestatus und behandeln Sie wechselnde MACs als normal, sofern der übrige Kontext nicht anomal ist.

## Hijacking von Satellitenverbindungen

Kaspersky dokumentierte, dass Turla Schwachstellen in älteren Einweg-DVB-S-Satelliten-Internetverbindungen ausnutzte. Beim beschriebenen Modell sendete ein legitimer Remote-Teilnehmer ausgehende Anfragen über eine terrestrische Verbindung, empfing Downstream-Daten jedoch über eine unverschlüsselte Satelliten-Broadcast-Verbindung mit großer Reichweite. Ein Akteur innerhalb der Satellitenabdeckung konnte den Downlink beobachten, eine aktive Teilnehmer-IP auswählen und dafür sorgen, dass C2-Antworten an diese IP adressiert wurden. Sowohl der legitime Teilnehmer als auch der Akteur empfingen den Broadcast; der Akteur extrahierte den Traffic für den ausgewählten Port, während der legitime Teilnehmer nicht angeforderte Pakete verwarf. Der C2-Betreiber schien dadurch eine Satellitenanbieter-Adresse in einer anderen geografischen Region zu verwenden.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Dies war protokoll- und dienstspezifisch, bandbreitenbeschränkt und nicht gleichbedeutend mit der Kompromittierung eines modernen bidirektionalen, verschlüsselten Satellitenterminals. Außerdem verbarg es den ausgehenden Anfragepfad des Akteurs nicht vor einem ausreichend leistungsfähigen Beobachter. Zu den Erkennungsmöglichkeiten zählen asymmetrisches/unmögliches Routing, Datenverkehr zu einem Teilnehmer, der den Datenfluss nicht initiiert hat, ungewöhnliche Zielports, Telemetriedaten des Anbieters, Untersuchungen des Empfängerstandorts und der HF-Umgebung sowie die Malware-Konfiguration. Nutzen Sie diesen Fall, um die Annahme zu hinterfragen, dass die Geolokalisierung einer C2-IP-Adresse auch den Standort des Controllers bestimmt — nicht als Bauanleitung.

## Arbeitsblatt zur physischen-digitalen Korrelation

Wenn eine scheinbar lokale Quelle verdächtig ist, erstellen Sie eine gemeinsame Zeitleiste:

1. Zeiten von AP, RADIUS, DHCP, DNS, Proxy, VPN, EDR, Switch und physischer Zugangskontrolle vereinheitlichen;
2. die erste Funkverbindung oder den ersten Verbindungsaufbau ermitteln, nicht nur die erste Warnung;
3. die Station Zertifikat, Gerätestatus, DHCP-Fingerabdruck und Switch-/AP-Standort zuordnen;
4. nach gleichzeitigen Fernsteuerungs-/Tunnelaktivitäten auf Systemen in der Nähe suchen;
5. Lieferungen, Besucher, Inventarabweichungen, Kameras und HF-Erkenntnisse gemäß geltenden Richtlinien/Gesetzen überprüfen;
6. das verdächtige Gerät und den flüchtigen Netzwerkstatus sichern; nicht blind aus- und wieder einschalten;
7. feststellen, ob die scheinbare Quelle eine vom Akteur kontrollierte Infrastruktur oder ein weiteres Opfer ist.

## References

- [1] [Volexity — Der Angriff des nächsten Nachbarn: Wie eine russische APT nahegelegene Wi-Fi-Netzwerke für verdeckten Zugriff missbrauchte](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT-Kommando und -Kontrolle am Himmel](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware-Ergänzungen (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Leitlinien zur Absicherung drahtloser lokaler Netzwerke](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Redigierter PowerShell-/C#-WLAN-Profilcode](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — WlanSetProfileEapXmlUserData-Funktion](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
