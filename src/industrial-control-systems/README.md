# Hacking von industriellen Steuerungssystemen

{{#include ../banners/hacktricks-training.md}}

## Über diesen Abschnitt

Dieser Abschnitt stellt Komponenten, Architekturen, Protokolle und Methoden zur Sicherheitsbewertung industrieller Steuerungssysteme (ICS) vor. ICS sind Teil des umfassenderen Bereichs der Betriebstechnologie (OT): programmierbare Systeme und Geräte, die physische Prozesse überwachen oder Veränderungen daran bewirken. Zu den gängigen Beispielen zählen Überwachungs-, Steuerungs- und Datenerfassungssysteme (SCADA), verteilte Steuerungssysteme (DCS) und speicherprogrammierbare Steuerungen (SPS).<sup>[[1]](#references)</sup>

Bei der Sicherheitsarbeit in diesen Umgebungen müssen Anforderungen berücksichtigt werden, die sich von denen herkömmlicher IT unterscheiden, darunter Prozesssicherheit, Zuverlässigkeit, Verfügbarkeit, deterministischer Betrieb und Lebenszyklen der Ausrüstung. Eine technisch gültige Sicherheitsmaßnahme kann dennoch ungeeignet sein, wenn sie den physischen Prozess stört. Tests und Abhilfemaßnahmen sollten daher mit dem Systemverantwortlichen und dem Betriebspersonal abgestimmt werden.<sup>[[1]](#references)</sup>

Eine Kompromittierung oder versehentliche Störung kann die Produktion zum Stillstand bringen, Anlagen beschädigen, Gefahrstoffe freisetzen, der Umwelt schaden oder Verletzungen und Todesfälle verursachen. Wegen dieser möglichen Auswirkungen auf die physische Welt müssen vor aktiven Tests der gesteuerte Prozess und seine sicheren Betriebsgrenzen verstanden werden.<sup>[[1]](#references)</sup>

Viele OT-Umgebungen nutzen weiterhin veraltete Betriebssysteme, Anwendungen und Protokolle, da Anlagen eine lange Lebensdauer haben und Änderungen betriebliche und sicherheitstechnische Tests erfordern. Einige Protokolle wurden ohne moderne Authentifizierung oder Verschlüsselung entwickelt, und das Einspielen von Patches kann durch den Herstellersupport oder Wartungsfenster eingeschränkt sein. Sind direkte Upgrades nicht möglich, können Segmentierung, Zugriffskontrollen und Überwachung Abhilfe schaffen.<sup>[[1]](#references)</sup>

## Schwerpunkte der Sicherheitsbewertung

Beginnen Sie damit, den gesteuerten Prozess, die Systemgrenzen, die Netzwerktopologie, die Assets, Datenflüsse, Vertrauensbeziehungen und externen Verbindungen zu verstehen. Ähnliche Gerätetypen können an verschiedenen Standorten unterschiedliche Funktionen erfüllen. Gehen Sie daher nicht davon aus, dass die Architektur oder das Wirkungsmodell einer Umgebung auch für eine andere gilt.<sup>[[1]](#references)</sup>

Bevorzugen Sie nach Möglichkeit passive Erkundung und vorhandene technische Dokumentation. Aktive Scans oder Exploitation sollten nur gemäß einem genehmigten Testplan erfolgen, der Sicherheitsbeschränkungen, Wartungsfenster, Wiederherstellungsverfahren und Abbruchbedingungen festlegt. Ergebnisse sollten sowohl hinsichtlich ihrer Auswirkungen auf die Cybersicherheit als auch möglicher Folgen für den physischen Prozess bewertet werden.<sup>[[1]](#references)</sup>

Dasselbe Wissen über die Architektur unterstützt auch defensive Maßnahmen wie Asset-Inventarisierung, Netzwerksegmentierung, Überwachung, Incident Response und risikobasiertes Vulnerability Management.<sup>[[1]](#references)</sup>

## Protokoll-Einstiegspunkte

- [Modbus-Tests](../network-services-pentesting/pentesting-modbus.md) behandeln Modbus TCP, serielle Varianten, Funktionscodes und den Registerzugriff.
- [OPC-UA-Tests](../network-services-pentesting/4840-pentesting-opc-ua.md) behandeln den industriellen Datenaustauschdienst.
- [BACnet-Tests](../network-services-pentesting/47808-udp-bacnet.md) behandeln Steuerungsnetzwerke der Gebäudeautomation.

## References

- [1] [NIST SP 800-82 Rev. 3 – Leitfaden zur Sicherheit von Betriebstechnologie (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
