# Hacking von industriellen Steuerungssystemen

{{#include ../../banners/hacktricks-training.md}}

## Über diesen Abschnitt

Dieser Abschnitt stellt Komponenten, Architekturen, Protokolle und Methoden zur Sicherheitsbewertung industrieller Steuerungssysteme (ICS) vor. ICS sind Teil des übergeordneten Bereichs der Operational Technology (OT): programmierbare Systeme und Geräte, die physische Prozesse überwachen oder Veränderungen an ihnen bewirken. Häufige Beispiele sind Supervisory-Control-and-Data-Acquisition-Systeme (SCADA), Distributed-Control-Systeme (DCSs) und Programmable Logic Controller (PLCs).<sup>[[1]](#references)</sup>

Bei der Sicherheitsarbeit in diesen Umgebungen müssen Anforderungen berücksichtigt werden, die sich von denen der herkömmlichen IT unterscheiden, darunter Prozesssicherheit, Zuverlässigkeit, Verfügbarkeit, deterministischer Betrieb und Lebenszyklen von Geräten. Eine technisch gültige Sicherheitsmaßnahme kann dennoch ungeeignet sein, wenn sie den physischen Prozess beeinträchtigt. Daher sollten Tests und Behebung von Schwachstellen mit dem Systemeigner und dem Betriebspersonal koordiniert werden.<sup>[[1]](#references)</sup>

Eine Kompromittierung oder unbeabsichtigte Störung kann die Produktion stoppen, Geräte beschädigen, gefährliche Stoffe freisetzen, die Umwelt schädigen oder Verletzungen und Todesfälle verursachen. Dieses potenzielle physische Ausmaß der Auswirkungen ist der Grund, warum das Verständnis des gesteuerten Prozesses und seiner sicheren Betriebsgrenzen vor aktiven Tests erfolgen muss.<sup>[[1]](#references)</sup>

Viele OT-Implementierungen verwenden weiterhin veraltete Betriebssysteme, Anwendungen und Protokolle, da Geräte eine lange Nutzungsdauer haben und Änderungen betriebliche sowie sicherheitstechnische Tests erfordern. Einige Protokolle wurden ohne moderne Authentifizierung oder Verschlüsselung entwickelt, und das Patchen kann durch den Herstellersupport oder Wartungsfenster eingeschränkt sein. Wo direkte Upgrades nicht umsetzbar sind, sollte dies durch Segmentierung, Zugriffskontrolle und Monitoring ausgeglichen werden.<sup>[[1]](#references)</sup>

## Prioritäten bei der Bewertung

Beginnen Sie damit, den gesteuerten Prozess, Systemgrenzen, Netzwerktopologie, Assets, Datenflüsse, Vertrauensbeziehungen und externen Verbindungen zu verstehen. Ähnliche Gerätetypen können an verschiedenen Standorten unterschiedliche Funktionen erfüllen. Vermeiden Sie daher die Annahme, dass die Architektur oder das Auswirkungsmodell einer Implementierung auf eine andere übertragen werden kann.<sup>[[1]](#references)</sup>

Bevorzugen Sie, wo möglich, passive Erkundung und vorhandene technische Dokumentation. Aktives Scanning oder Exploitation sollte einem genehmigten Testplan folgen, der Sicherheitsvorgaben, Wartungsfenster, Wiederherstellungsverfahren und Abbruchbedingungen festlegt. Findings sollten sowohl hinsichtlich ihrer Auswirkungen auf die Cybersecurity als auch hinsichtlich möglicher Auswirkungen auf den physischen Prozess bewertet werden.<sup>[[1]](#references)</sup>

Dasselbe Architekturwissen unterstützt defensive Aktivitäten wie Asset-Inventarisierung, Netzwerksegmentierung, Monitoring, Incident Response und risikobasiertes Vulnerability Management.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Leitfaden zur Sicherheit von Operational Technology (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
