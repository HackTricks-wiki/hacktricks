# Hacking industrieller Steuerungssysteme

{{#include ../banners/hacktricks-training.md}}

## Über diesen Abschnitt

Dieser Abschnitt stellt Komponenten, Architekturen, Protokolle und Methoden zur Sicherheitsbewertung industrieller Steuerungssysteme (ICS) vor. ICS ist Teil des umfassenderen Bereichs der Operational Technology (OT): programmierbare Systeme und Geräte, die physische Prozesse überwachen oder Veränderungen daran bewirken. Häufige Beispiele sind Leitsysteme mit Datenerfassung (SCADA), verteilte Steuerungssysteme (DCS) und speicherprogrammierbare Steuerungen (SPS).<sup>[[1]](#references)</sup>

Bei Sicherheitsarbeiten in diesen Umgebungen müssen Anforderungen berücksichtigt werden, die sich von denen der herkömmlichen IT unterscheiden, darunter Prozesssicherheit, Zuverlässigkeit, Verfügbarkeit, deterministischer Betrieb und Gerätelebenszyklen. Eine technisch gültige Sicherheitsmaßnahme kann dennoch ungeeignet sein, wenn sie den physischen Prozess beeinträchtigt. Tests und Behebungsmaßnahmen sollten daher mit dem Systemverantwortlichen und dem Betriebspersonal abgestimmt werden.<sup>[[1]](#references)</sup>

Eine Kompromittierung oder unbeabsichtigte Störung kann die Produktion zum Stillstand bringen, Geräte beschädigen, gefährliche Stoffe freisetzen, die Umwelt schädigen oder Verletzungen und Todesfälle verursachen. Aufgrund dieser potenziellen physischen Auswirkungen müssen der gesteuerte Prozess und seine sicheren Betriebsgrenzen verstanden werden, bevor aktive Tests beginnen.<sup>[[1]](#references)</sup>

Viele OT-Umgebungen verwenden weiterhin veraltete Betriebssysteme, Anwendungen und Protokolle, da Geräte eine lange Nutzungsdauer haben und Änderungen betriebliche Tests und Sicherheitsprüfungen erfordern. Manche Protokolle wurden ohne moderne Authentifizierung oder Verschlüsselung entwickelt. Zudem kann das Einspielen von Patches durch den Herstellersupport oder Wartungsfenster eingeschränkt sein. Sind direkte Upgrades nicht möglich, können Segmentierung, Zugriffskontrollen und Überwachung als Ausgleich dienen.<sup>[[1]](#references)</sup>

## Schwerpunkte der Sicherheitsbewertung

Beginnen Sie damit, den gesteuerten Prozess, Systemgrenzen, Netzwerktopologie, Anlagen, Datenflüsse, Vertrauensbeziehungen und externe Verbindungen zu verstehen. Ähnliche Gerätetypen können an verschiedenen Standorten unterschiedliche Funktionen erfüllen. Gehen Sie daher nicht davon aus, dass die Architektur oder das Auswirkungsmodell einer Umgebung auch für eine andere gilt.<sup>[[1]](#references)</sup>

Bevorzugen Sie nach Möglichkeit passive Erkennung und vorhandene technische Dokumentation. Aktive Scans oder Exploitation sollten nur gemäß einem genehmigten Testplan erfolgen, der Sicherheitsauflagen, Wartungsfenster, Wiederherstellungsverfahren und Abbruchbedingungen festlegt. Befunde sollten sowohl hinsichtlich ihrer Auswirkungen auf die Cybersicherheit als auch möglicher Folgen für den physischen Prozess bewertet werden.<sup>[[1]](#references)</sup>

Dasselbe Architekturwissen unterstützt auch defensive Maßnahmen wie Anlageninventarisierung, Netzwerksegmentierung, Überwachung, Incident Response und risikobasiertes Schwachstellenmanagement.<sup>[[1]](#references)</sup>

## Missbrauch übergeordneter Kälteanlagensteuerungen

Ein Kälteanlagenmanager koordiniert Kompressoren- und Kühlstellensteuerungen, kühlt die Kühlstellen jedoch nicht selbst. Der Zugriff auf seine Verwaltungsschnittstelle kann daher über die normale Verteilung von Konfigurationen die Kontrolle über viele untergeordnete Geräte ermöglichen. Das unterscheidet sich von der Änderung eines einzelnen Thermostats oder der direkten Ansteuerung eines Kompressors.<sup>[[3]](#references)[[4]](#references)</sup>

### Anmeldung mit wartungsbezogenem, aus dem Datum abgeleitetem Code

Bei betroffenen Systemmanagern von Danfoss akzeptiert eine alternative XML-Anmeldung einen aus dem Datum des Steuergeräts abgeleiteten Code anstelle eines Kontopassworts.<sup>[[2]](#references)[[3]](#references)</sup> Bei SM800 und SC255 verfolgte Synacktiv die Attribute `eds_only` und `quantum_only` über `xml_load_file` und `check_authorize` bis zu `check_code_of_day`. Der Sicherheitshinweis zeigt außerdem, dass `read_date_time` über `xml.cgi` das Datum des Steuergeräts ohne Authentifizierung offenlegt.<sup>[[2]](#references)</sup> Claroty fand einen entsprechenden `getauth`-Pfad beim AK-SM 800A, schwärzte jedoch die auslösenden Attribute. Es sollte nicht davon ausgegangen werden, dass die Attributnamen älterer Modelle auf dieser Plattform funktionieren.<sup>[[3]](#references)</sup>

Synacktiv dokumentiert die nicht authentifizierte Datumsabfrage wie folgt:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Der Code enthält kein gerätespezifisches Geheimnis: Wird der Algorithmus aus der [firmware](../hardware-physical-access/firmware-analysis/) rekonstruiert, kann dies ein zeitlich gültiges Zugangsdatenpaar für Geräte mit derselben betroffenen Implementierung ergeben.<sup>[[2]](#references)[[3]](#references)</sup> Bestätigen Sie zuerst Modell und firmware. Eine Datumsantwort allein belegt weder, dass die alternative Anmeldung verfügbar ist, noch dass eine Session zustande kam.

### Massenkonfiguration und Missbrauch des Abtauheizers

Ermitteln Sie nach dem administrativen Zugriff, welche Kühlstellenregler dem Systemmanager zugeordnet sind und ob dessen Konfigurationsverteilungsfunktion sie gemeinsam aktualisieren kann. Eine Änderung des Sollwerts einer Kühlstelle erwärmt einen Schrank normalerweise nur bis auf Raumtemperatur. Um ihn über die Umgebungstemperatur hinaus zu erwärmen, ist der elektrische Verdampfer-Abtauheizer des Kühlstellenreglers entscheidend: Beim Abtauen wird die Kühlung gestoppt und der Heizer betrieben, bis ein Sensor oder ein Timer den Zyklus beendet. Wird stattdessen die Abtaumethode, der Zeitplan, die Abschalttemperatur und das Zeitlimit geändert, kann der Heizer dauerhaft eingeschaltet bleiben. Der Manager kann solche Änderungen auf viele Kühlstellen verteilen und zugehörige Alarme unterdrücken, wodurch aus einer einzelnen Kompromittierung der übergeordneten Steuerung eine Prozessänderung im gesamten Geschäft wird.<sup>[[4]](#references)</sup>

Dies stellt eine Gefahr für den physischen Prozess dar und ist kein sicherer Proof of Concept für ein Live-System. Vorhandene Temperaturschutzschalter können den Betrieb des Heizers zwar begrenzen, doch Dauerbetrieb kann trotzdem eine bereits geschwächte elektrische Verbindung überhitzen. Überprüfen Sie Konfiguration und Auswirkungen nur in einem genehmigten Labor oder gemäß dem Prozesssicherheitsplan des Betreibers.<sup>[[4]](#references)</sup>

## Protokoll-Einstiegspunkte

- [Modbus-Tests](../network-services-pentesting/pentesting-modbus.md) behandeln Modbus TCP, serielle Varianten, Funktionscodes und Registerzugriffe.
- [OPC-UA-Tests](../network-services-pentesting/4840-pentesting-opc-ua.md) behandeln den industriellen Datenaustauschdienst.
- [BACnet-Tests](../network-services-pentesting/47808-udp-bacnet.md) behandeln Gebäudeautomations-Steuernetzwerke.

## References

- [1] [NIST SP 800-82 Rev. 3 – Leitfaden zur Sicherheit von Operational Technology (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv – Authentifizierungsumgehung bei Danfoss System-Managern SM800 und SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 – Den Controller einfrieren, die Lebensmittel auftauen](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners – Man braucht keinen Nationalstaat, um einen Kühlschrank aufzuwärmen](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
