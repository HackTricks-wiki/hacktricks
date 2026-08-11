# Hacking industrieller Steuerungssysteme

{{#include ../../banners/hacktricks-training.md}}

## Über diesen Abschnitt

Dieser Abschnitt stellt Komponenten, Architekturen, Protokolle und Methoden zur Sicherheitsbewertung industrieller Steuerungssysteme (ICS) vor. ICS sind Teil des übergeordneten Bereichs der Operational Technology (OT): programmierbare Systeme und Geräte, die physische Prozesse überwachen oder Veränderungen daran bewirken. Häufige Beispiele sind Supervisory-Control-and-Data-Acquisition-(SCADA-)Systeme, Distributed-Control-Systems (DCSs) und Programmable Logic Controllers (PLCs).<sup>[[1]](#references)</sup>

Bei der Sicherheitsarbeit in diesen Umgebungen müssen Anforderungen berücksichtigt werden, die sich von denen herkömmlicher IT unterscheiden, darunter Prozesssicherheit, Zuverlässigkeit, Verfügbarkeit, deterministischer Betrieb und Gerätelebenszyklen. Eine technisch gültige Sicherheitsmaßnahme kann dennoch ungeeignet sein, wenn sie den physischen Prozess stört. Daher sollten Tests und Abhilfemaßnahmen mit dem Systemverantwortlichen und dem Betriebspersonal koordiniert werden.<sup>[[1]](#references)</sup>

## Bewertungsschwerpunkte

Beginne damit, den gesteuerten Prozess, Systemgrenzen, Netzwerktopologie, Assets, Datenflüsse, Vertrauensbeziehungen und externen Verbindungen zu verstehen. Ähnliche Gerätetypen können an verschiedenen Standorten unterschiedliche Funktionen erfüllen. Vermeide daher die Annahme, dass die Architektur oder das Auswirkungsmodell einer Bereitstellung auf eine andere übertragbar ist.<sup>[[1]](#references)</sup>

Bevorzuge nach Möglichkeit passive Erkundung und vorhandene technische Dokumentation. Jedes aktive Scanning oder jede Exploitation sollte einem genehmigten Testplan folgen, der Sicherheitsvorgaben, Wartungsfenster, Wiederherstellungsverfahren und Abbruchbedingungen festlegt. Findings sollten sowohl hinsichtlich ihrer Auswirkungen auf die Cybersicherheit als auch hinsichtlich möglicher Auswirkungen auf den physischen Prozess bewertet werden.<sup>[[1]](#references)</sup>

Dasselbe Architekturwissen unterstützt defensive Aktivitäten wie Asset-Inventarisierung, Netzwerksegmentierung, Monitoring, Incident Response und risikobasiertes Vulnerability Management.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Leitfaden zur Sicherheit von Operational Technology (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
