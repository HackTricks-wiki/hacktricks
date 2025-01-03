{{#include ../../banners/hacktricks-training.md}}

# Basislinie

Eine Basislinie besteht darin, einen Snapshot bestimmter Teile eines Systems zu erstellen, um **diesen mit einem zukünftigen Status zu vergleichen, um Änderungen hervorzuheben**.

Zum Beispiel können Sie den Hash jeder Datei des Dateisystems berechnen und speichern, um herauszufinden, welche Dateien geändert wurden.\
Dies kann auch mit den erstellten Benutzerkonten, laufenden Prozessen, laufenden Diensten und allem anderen, was sich nicht viel oder gar nicht ändern sollte, durchgeführt werden.

## Datei-Integritätsüberwachung

Die Datei-Integritätsüberwachung (FIM) ist eine kritische Sicherheitstechnik, die IT-Umgebungen und Daten schützt, indem sie Änderungen an Dateien verfolgt. Sie umfasst zwei wichtige Schritte:

1. **Basislinienvergleich:** Eine Basislinie unter Verwendung von Datei-Attributen oder kryptografischen Prüfziffern (wie MD5 oder SHA-2) für zukünftige Vergleiche zur Erkennung von Änderungen festlegen.
2. **Echtzeit-Änderungsbenachrichtigung:** Sofortige Benachrichtigungen erhalten, wenn Dateien zugegriffen oder geändert werden, typischerweise durch OS-Kernel-Erweiterungen.

## Werkzeuge

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Referenzen

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
