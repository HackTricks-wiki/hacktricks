# Fallstudien zu Regierungen und APTs

{{#include ../banners/hacktricks-training.md}}

Diese öffentlichen Fälle zeigen, wie verschiedene Privacy-Techniken in realen Operationen miteinander kombiniert werden. Die Zuordnungsbezeichnungen entsprechen denen der zitierten Ermittler oder Regierungen; Eine IP-Adresse, Überschneidungen bei Tools oder eine geopolitische Übereinstimmung allein sind keine schlüssigen Belege für eine Zuordnung.

## APT28: Remote-Wi-Fi-Zugriff über den nächstgelegenen Nachbarn

**Öffentlicher Befund.** Volexity ordnete einen Einbruch im Jahr 2022 GruesomeLarch/APT28 zu. Nachdem der Internetzugriff mit einem validierten Credential durch MFA unterbunden worden war, kompromittierte der Akteur Organisationen in der Nähe des Ziels und erreichte das Enterprise-Wi-Fi des Ziels von einem nahegelegenen Dual-Homed-Host aus. Der Wi-Fi-Pfad akzeptierte das Credential ohne das extern erforderliche MFA.<sup>[[1]](#references)</sup>

**Privacy-Auswirkung.** Der endgültige Zugriff erfolgte aus physischer Funkreichweite, und die zwischengeschalteten Organisationen waren Opfer. Die Operation vermied Reisen und sorgte dafür, dass die herkömmliche IP-Geolokalisierung auf einen Nachbarn zeigte.

**Was den Vorgang aufdeckte.** Die Zielwarnung, die Host-/Netzwerkuntersuchung, die Credential-Aktivität, die Interface-Topologie und die physische Nähe mussten als eine zusammenhängende Kette analysiert werden. Die anomale Tatsache war nicht lediglich eine neue IP-Adresse, sondern dass eine legitime Identität über einen ungewöhnlichen Wi-Fi-/Gerätekontext eintraf, während Systeme in der Nähe kompromittiert waren.

**Defensive Lehre.** Zertifikats-/gerätegestützten Zugriff auf Wi-Fi anwenden, RADIUS mit NAC/MDM und dem physischen Kontext korrelieren und die Infrastruktur in der Umgebung untersuchen, statt davon auszugehen, dass der letzte Hop der Operator ist.

## APT28: Von der GRU zweckentfremdete kriminelle Moobot-Infrastruktur

**Öffentlicher Befund.** Im Februar 2024 beschrieb das US Department of Justice ein Botnet aus Hunderten Ubiquiti-EdgeOS-Routern. Kriminelle Akteure hatten Moobot auf Routern installiert, die bekannte Standard-Administrator-Credentials beibehalten hatten; die GRU-Einheit 26165 fügte anschließend Skripte und Dateien hinzu und verwandelte ein bestehendes kriminelles Botnet in eine für Spearphishing und Credential Theft genutzte Spionageplattform.<sup>[[2]](#references)</sup>

**Privacy-Auswirkung.** Die GRU baute nicht die gesamte Infrastruktur selbst auf. Das Ausleihen einer bereits kompromittierten Flotte platzierte Adressen unbeteiligter Privathaushalte und kleiner Büros zwischen dem Akteur und den Zielen, vermischte staatliche Aktivitäten mit kriminellen Aktivitäten und reduzierte akteursspezifische Registrierungsartefakte.

**Was den Vorgang aufdeckte.** Router-Dateien, das Control-Verhalten der Malware und nicht-inhaltliche Routing-Informationen unterstützten die Untersuchung. Die Unterbrechung änderte vorübergehend Firewall-Regeln und entfernte schädliche Dateien, während das DOJ warnte, dass unveränderte Standard-Credentials eine erneute Infektion ermöglichen könnten.

**Defensive Lehre.** Nicht mehr unterstützte Router ersetzen, aus dem Internet erreichbare Administration entfernen, Standardwerte ändern, patchen, Konfigurations-/Flow-Daten von Edge-Geräten erfassen und nach Flottenverhalten suchen. „Residential US IP“ ist kein Beleg für einen US-Operator.

## Volt Typhoon: KV Botnet und Living off the Land

**Öffentlicher Befund.** Das DOJ und ein gemeinsamer CISA-Hinweis beschrieben, wie der staatlich unterstützte chinesische Akteur Volt Typhoon das KV Botnet nutzte, das hauptsächlich kompromittierte Cisco- und NETGEAR-SOHO-Router am Ende ihres Lebenszyklus umfasste, um den Ursprung der Aktivitäten aus der VR China bei Angriffen auf kritische Infrastruktur zu verschleiern. Innerhalb der Opferumgebungen bevorzugte der Akteur gültige Accounts und integrierte Administrationstools; Behörden meldeten, dass der Zugriff in einigen Umgebungen mindestens fünf Jahre andauerte.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Datenschutzauswirkung.** Der ORB-ähnliche Pfad verbarg den Ursprung, während die Nutzung vorhandener Systemmittel nach dem Zugriff neue Binärdateien und Signaturmöglichkeiten reduzierte. Netzwerk- und Endpoint-Verschleierung verstärkten sich gegenseitig.

**Was ihn entlarvte.** Router-/Controller-Struktur, gerichtlich genehmigte technische Datenerfassung, wiederkehrende Aktivitäten und die Analyse über mehrere Opfer hinweg waren wichtiger als ein einzelner IOC. Ein Neustart des Routers entfernte in den beschriebenen Fällen die volatile KV-Malware, behob jedoch nicht die zugrunde liegende End-of-Life-Sicherheitslücke des Geräts.

**Defensive Lehre.** EOL-Edge-Geräte ersetzen, Authentifizierung und Netzwerkgeräte-Logs zentralisieren, das Verhalten von Administratoren als Baseline erfassen, ausgehende Verbindungen einschränken und nach Verhaltenssequenzen über Identity-, Endpoint- und Netzwerkebenen hinweg suchen.

## China-nexus ORB networks: infrastructure as a service

**Öffentliche Erkenntnis.** Mandiant beschrieb ein Ökosystem von ORB networks, die von mehreren China-nexus-Spionageakteuren genutzt wurden. Provisioned networks verwendeten gemietete VPS-Knoten; non-provisioned networks verwendeten kompromittierte IoT-Geräte und Router; hybride Netzwerke kombinierten beide. ORB3/SPACEHOP unterstützte Aktivitäten im Zusammenhang mit APT5/APT15. ORB2/FLORAHOX kombinierte einen Administrationsserver, gemietete Server, eine angepasste Tor-Schicht sowie kompromittierte Cisco-, ASUS- und DrayTek-Geräte. Mandiant bewertete einige Netzwerke als unabhängig verwaltet und an mehrere APT-Akteure vermietet.<sup>[[5]](#references)</sup>

**Datenschutzauswirkung.** Die Infrastruktur wurde zu einer Service-Grenze. Ein Betreiber konnte geografische bzw. private Exit-Punkte erhalten, ohne die Opferflotte selbst zu verwalten, während viele gemeinsame Kunden die einfache Zuordnung von Akteur zu IP-Adresse erschwerten. Der schnelle Austausch der Flotte beschleunigte das „IOC extinction“.

**Was ihn entlarvte.** Netzwerktopologie, geklonte Server-Images, Ports/Services, Controller-Beziehungen, Router-Implants und Lebenszyklusmuster blieben gruppierbar. Mandiant berichtete, dass einige Node-IP-Adressen nur 31 Tage lang in einem ORB verblieben.

**Defensive Lehre.** Einen ORB als sich verändernde Einheit verfolgen: Node-Rollen, Service-Fingerprints, Upstream-Beziehungen, Scan-Verhalten und Rotationsrhythmus. Das Ablaufen eines IP-Indikators sollte den Cluster aktualisieren, nicht den Fall löschen.

## PRC global espionage system: routers, trusted links and traffic mirroring

**Öffentliche Erkenntnis.** Ein multinationales Advisory aus dem Jahr 2025 beschrieb Aktivitäten, die sich mit kommerziellen Bezeichnungen wie Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 und GhostEmperor überschnitten. Die Behörden berichteten über gemietete VPSs und kompromittierte Zwischenrouter, die zum Erreichen von Telekommunikations- und Netzwerkanbietern verwendet wurden. Die Akteure pivotierten über vertrauenswürdige Provider-/Kundenverbindungen, änderten Routen, erstellten GRE/IPsec-Tunnel, verwendeten Device-Container und aktivierten SPAN/RSPAN/ERSPAN oder native Packet Capture, um Authentifizierungs- und Kundendatenverkehr zu erfassen.<sup>[[13]](#references)</sup>

**Datenschutzauswirkung.** Ein kompromittierter Router ist gleichzeitig Relay, Beobachtungspunkt und vertrauenswürdiger Netzwerkteilnehmer. Private Verbindungen können Kontrollen umgehen, die auf das öffentliche Internet ausgerichtet sind, während Traffic Mirroring Credentials erfasst, ohne einen Endpoint-Agent bereitzustellen.

**Was ihn entlarvt.** Konfigurations-Diffs, unerwartete SNMP-/SSH-/Web-Administration, neue statische Routen/Tunnel, Mirror-Sessions, Guest-Shell-Container, PCAP-Dateien, Änderungen an TACACS+/RADIUS-Zielen und deaktiviertes Logging. Das Advisory betont, dass einige Zwischenrouter nicht Teil eines zuvor benannten öffentlichen Botnets waren; das Fehlen bekannter ORB-Indikatoren war daher kein Entlastungsgrund.

**Defensive Lehre.** Out-of-Band-Administration, zentralisierte Konfigurations-/Authentifizierungs-Logs, Integritätsprüfungen für signierte Images und die Laufzeitintegrität, Einschränkungen für den Egress von Management-Interfaces sowie Alerts für Routen-/Mirror-/Tunnel-/AAA-Änderungen verwenden. Einen vermuteten Kompromiss vor der Bereinigung über vertrauenswürdige Peers hinweg eingrenzen.

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Öffentliche Erkenntnis.** Mandiant schrieb UNC3886 benutzerdefinierte, von TINYSHELL abgeleitete Backdoors auf End-of-Life-Juniper-MX-Routern zu. Die Sammlung umfasste aktive und passive Implants, Namen, die legitime Daemons nachahmten, Verhalten zum Deaktivieren von Logs, Process Injection in einen vertrauenswürdigen Prozess, SOCKS-Proxy-Funktionen sowie als ORB-Staging-Nodes bewertete Infrastruktur. Passive Varianten untersuchten Pakete über `libpcap` und wurden erst nach einem Magic Pattern aktiv; eine Variante konnte auf einen im Trigger übermittelten aktiven Callback umschalten.<sup>[[14]](#references)</sup>

**Datenschutzauswirkung.** Ein passives Implant verfügt über keinen periodischen Beacon, anhand dessen es entdeckt werden kann. Es teilt Ports und Datenverkehr mit einem echten Netzwerkgerät, wird kurzzeitig aktiv und kann über einen ORB weiterleiten, anstatt sich direkt mit einem endgültigen Controller zu verbinden.

**Was ihn entlarvt.** Memory-Analyse, Unterschiede zwischen auf der Festplatte vorhandenem und laufendem Code, unerwartete Packet-Capture-Filter-/Socket-Aktivitäten, Prozess-/Dateinamen, die legitime Daemons nur annähernd nachbilden, Administration über Terminalserver, fehlende Logs sowie die zweistufige Beziehung zwischen Staging-Nodes und einem Backend-Controller.

**Defensive Lehre.** Neben Dateisystem-/Konfigurationsbeweisen auch den Arbeitsspeicher erfassen, Prozesse/Module mit einem bekannten Good Image vergleichen, die Verwendung von Packet Capture und Socket-Filtern überwachen, Management-Terminalserver absichern und EOL-Netzwerkhardware ersetzen. Eine Suche ohne saubere Outbound-Beacons ist keine Unbedenklichkeitsbescheinigung.

## APT29: Tor domain fronting

**Öffentliche Erkenntnis.** MITRE dokumentiert, dass APT29 den `meek`-Transport von Tor zur Verschleierung von C2-Datenverkehr mittels Domain Fronting einsetzte. Der äußere TLS-Name schien eine erlaubte, von einem CDN gehostete Domain zu sein, während der innere HTTP-Host die tatsächliche Route auswählte.<sup>[[6]](#references)</sup>

**Datenschutzauswirkung.** Ein filternder Beobachter konnte ein gemeinsames Front/CDN statt des inneren Ziels sehen, und eine Blockierung konnte Kollateralschäden verursachen.

**Was ihn entlarvt.** Das CDN kann die Routing-Abweichung beobachten, und ein Verteidiger mit Endpoint- oder rechtmäßig verfügbarer TLS-Sichtbarkeit kann Prozess, Authority, Verbindungsdauer, Byte-Muster und nachfolgende Aktivitäten korrelieren. Änderungen an den Provider-Richtlinien können die Technik deaktivieren.

**Defensive Lehre.** Nicht allein auf SNI-Allowlisting verlassen. Application-aware Egress erzwingen, TLS- und HTTP-Identitäten vergleichen, sofern sichtbar, und das Netzwerkereignis mit dem auslösenden Prozess verknüpfen.

## APT41 and other dead-drop resolvers

**Öffentliche Erkenntnis.** MITRE dokumentiert, dass APT41 legitime Websites wie GitHub, Pastebin, Microsoft TechNet, Cloudflare und Community-Foren nutzte, um C2-Informationen zu veröffentlichen oder abzurufen. Andere staatlich verbundene Tools verwendeten in ähnlicher Weise Posts, Dokumente und soziale Medien.<sup>[[7]](#references)</sup>

**Datenschutzauswirkung.** Eine Binärdatei enthält einen legitimen Service bzw. ein legitimes Objekt statt einer stabilen C2-Adresse. Das Objekt kann bearbeitet werden, um die Infrastruktur zu rotieren, und die initiale Anfrage geht in gewöhnlichem TLS-Datenverkehr unter.

**Was ihn entlarvt.** Die Objekt- oder Account-ID ist stabil; seltene Prozesse rufen sie wiederholt ab; der Inhalt wird decodiert; anschließend folgt eine zweite ausgehende Verbindung. Provider-Account- und API-Aufzeichnungen können die Veröffentlichung mit dem Betreiber verknüpfen.

**Defensive Lehre.** Vollständige Proxy-Pfade/Objekt-IDs und die Prozessherkunft des Endpoints aufbewahren. Ein Ereignis auf Domain-Ebene wie „mit GitHub verbunden“ ist zu grob.

## Turla: satellite-address C2

**Öffentliche Erkenntnis.** Kaspersky berichtete, dass Turla unverschlüsselte Downstream-Broadcasts älterer unidirektionaler DVB-S-Internetdienste missbrauchte. Ein Betreiber innerhalb des Satelliten-Footprints konnte die Adresse eines legitimen Abonnenten auswählen und Antworten empfangen, die an diese Adresse gesendet wurden. Dadurch schien das C2 hinter einem Satellitenanbieter in einer anderen Region gehostet zu sein.<sup>[[8]](#references)</sup>

**Datenschutzauswirkung.** Die scheinbare Serveradresse identifizierte den Empfänger nicht, und herkömmliche Verfahren zur Beschlagnahmung von Hosting sowie WHOIS waren weniger nützlich.

**Was ihn entlarvt.** Der Akteur benötigte weiterhin einen ausgehenden Anfragepfad, das Routing war asymmetrisch, der legitime Abonnent initiierte den C2-Austausch nicht, und RF-/Provider-Untersuchungen konnten den Empfangs-Footprint eingrenzen.

**Defensive Lehre.** Geolocation als eine Hypothese behandeln. Pfadsymmetrie, RTT, Routing-Eigentümer und die Frage prüfen, ob der angebliche Endpoint den beobachteten Service tatsächlich bereitstellen konnte.

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Öffentliche Erkenntnis.** Ein Advisory von NCSC/CISA/FBI/NSA aus dem Jahr 2022 beschrieb Sandworms modulares Cyclops-Blink-Malware auf WatchGuard-Geräten, das dauerhaft als Firmware-Update eingesetzt wurde und Module hinzufügen konnte. Das DOJ beschrieb separat das frühere APT28-VPNFilter-Botnet aus Routern und NAS-Geräten als fähig zur Nachrichtengewinnung, zu destruktiven Aktivitäten und zur Fehlattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Datenschutzauswirkung.** Edge-Appliances sind dauerhaft online, werden als Infrastruktur vertraut und von EDR nur unzureichend abgedeckt. Firmware-Persistenz kann einen gewöhnlichen Neustart überstehen und ein Opfergerät zu einem Relay oder Kontrollpunkt machen.

**Was ihn entlarvt.** Firmware-Integrität, herstellerspezifisches Implant-Protokoll, unerwartete Management-Exponierung, Konfigurationsänderungen und ausgehende Beacons. Edge-Geräte müssen forensische Untersuchungsobjekte sein, keine transparente Infrastruktur.

## DPRK: identity, network and financial layering

**Öffentliche Erkenntnis.** DOJ-Fälle beschreiben, wie DPRK-Mitarbeiter mithilfe falscher oder gestohlener Identitätsmaterialien und VPNs Remote-Arbeitsplätze erhielten, Kryptowährungen empfingen, Transfers aufteilten, Assets/Chains tauschten, NFTs verwendeten und Erträge vermischten. Andere Fälle beschreiben OTC-Trader und Briefkastenfirmen, die gestohlene Kryptowährungen in Käufe umwandelten. Treasury und FBI haben Lazarus-/TraderTraitor-Erträge öffentlich mit Mixern in Verbindung gebracht und Adressen aus größeren Diebstählen identifiziert.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Datenschutzauswirkung.** Dies ist keine „private coin“. Es handelt sich um eine domänenübergreifende Kette: Persona und Remote Access verbergen den Standort des Mitarbeiters; Kryptowährung verschiebt Werte; Layering unterbricht einfache Transaktionsnarrative; OTC-Trader und Briefkastenfirmen schlagen die Brücke zu Waren und Fiat.

**Was ihn entlarvt.** Anomalien bei Arbeitgebern/Geräten, wiederverwendete Facilitators, zeitliche und wertmäßige Kontinuität auf der Blockchain, Exchange-/Bridge-Aufzeichnungen, sanktionierte Adressen, Account-Identität sowie Versand-/Unternehmensunterlagen verbinden die Kette wieder.

**Defensive Lehre.** Teams für Hiring, IAM, Endpoint, Payroll, Blockchain und Sanktionen benötigen ein gemeinsames Fallmodell. Weitere Details finden sich unter [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Cross-case patterns

| Muster | APT-Beispiele | Anpassung der Verteidigung |
|---|---|---|
| Der Exit ist ein weiteres Opfer | APT28/Moobot, Volt Typhoon/KV, ORBs | den Exit untersuchen und bereinigen; ihn nicht mit dem Standort des Akteurs gleichsetzen |
| Kontrollen unterscheiden sich je nach Grenze | APT28 nearest neighbor | internem/Wireless-Zugriff dieselbe Identity Assurance wie dem Internetzugriff geben |
| Ein legitimer Service ist eine Routing-Schicht | APT29, APT41 | Objekt-/Pfad-/Prozesskontext aufbewahren, nicht nur die Ziel-Domain |
| Edge-Geräte verfügen über keine Telemetrie | KV, Moobot, Cyclops Blink, ORBs | Konfigurations-/Authentifizierungs-/Flow-Logs zentralisieren und Firmware/Inventar überprüfen |
| Infrastruktur wird geteilt und ist kurzlebig | China-nexus ORBs | Verhalten/Topologie clustern und Rollenänderungen über die Zeit verfolgen |
| Mehrere schwache Trennungen ergeben zusammen ein Ganzes | DPRK-Personas + VPN + Krypto + OTC | Identitäts-, Geräte-, Netzwerk-, Zahlungs- und physische Beweise zusammenführen |

## References

- [1] [Volexity — Der Nearest-Neighbor-Angriff](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Unterbrechung des vom GRU kontrollierten Moobot-Router-Botnets](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Unterbrechung des PRC-KV-Botnets](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC-Akteure kompromittieren kritische US-Infrastruktur und erhalten dauerhaften Zugriff](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus-Spionageakteure verwenden ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops-Blink-Advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Unterbrechung von APT28 VPNFilter](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Vertreter der DPRK Foreign Trade Bank wegen Verschwörungen zur Krypto-Geldwäsche angeklagt](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io-Sanktionen und Lazarus-Gelder](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Bekämpfung der Kompromittierung weltweiter Netzwerke durch chinesische staatlich geförderte Akteure](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 zielt auf Juniper-Router](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
