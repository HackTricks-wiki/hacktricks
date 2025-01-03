# Geräte in anderen Organisationen anmelden

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung

Wie [**bereits kommentiert**](./#what-is-mdm-mobile-device-management)**,** um ein Gerät in eine Organisation einzuschreiben, **wird nur eine Seriennummer benötigt, die zu dieser Organisation gehört**. Sobald das Gerät eingeschrieben ist, installieren mehrere Organisationen sensible Daten auf dem neuen Gerät: Zertifikate, Anwendungen, WiFi-Passwörter, VPN-Konfigurationen [und so weiter](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daher könnte dies ein gefährlicher Einstiegspunkt für Angreifer sein, wenn der Einschreibungsprozess nicht korrekt geschützt ist.

**Die folgende Zusammenfassung basiert auf der Forschung [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Überprüfen Sie sie für weitere technische Details!**

## Übersicht über DEP und MDM-Binäranalyse

Diese Forschung befasst sich mit den Binärdateien, die mit dem Device Enrollment Program (DEP) und Mobile Device Management (MDM) auf macOS verbunden sind. Wichtige Komponenten sind:

- **`mdmclient`**: Kommuniziert mit MDM-Servern und löst DEP-Check-ins auf macOS-Versionen vor 10.13.4 aus.
- **`profiles`**: Verwaltet Konfigurationsprofile und löst DEP-Check-ins auf macOS-Versionen 10.13.4 und später aus.
- **`cloudconfigurationd`**: Verwaltet DEP-API-Kommunikationen und ruft Geräteanmeldungsprofile ab.

DEP-Check-ins nutzen die Funktionen `CPFetchActivationRecord` und `CPGetActivationRecord` aus dem privaten Konfigurationsprofil-Framework, um den Aktivierungsdatensatz abzurufen, wobei `CPFetchActivationRecord` mit `cloudconfigurationd` über XPC koordiniert.

## Tesla-Protokoll und Absinthe-Schema Reverse Engineering

Der DEP-Check-in umfasst, dass `cloudconfigurationd` eine verschlüsselte, signierte JSON-Nutzlast an _iprofiles.apple.com/macProfile_ sendet. Die Nutzlast enthält die Seriennummer des Geräts und die Aktion "RequestProfileConfiguration". Das verwendete Verschlüsselungsschema wird intern als "Absinthe" bezeichnet. Das Entschlüsseln dieses Schemas ist komplex und umfasst zahlreiche Schritte, was zur Erkundung alternativer Methoden führte, um beliebige Seriennummern in die Aktivierungsdatensatzanfrage einzufügen.

## Proxying von DEP-Anfragen

Versuche, DEP-Anfragen an _iprofiles.apple.com_ mit Tools wie Charles Proxy abzufangen und zu modifizieren, wurden durch die Verschlüsselung der Nutzlast und SSL/TLS-Sicherheitsmaßnahmen behindert. Das Aktivieren der Konfiguration `MCCloudConfigAcceptAnyHTTPSCertificate` ermöglicht jedoch das Umgehen der Serverzertifikatsvalidierung, obwohl die verschlüsselte Natur der Nutzlast weiterhin eine Modifikation der Seriennummer ohne den Entschlüsselungsschlüssel verhindert.

## Instrumentierung von System-Binärdateien, die mit DEP interagieren

Die Instrumentierung von System-Binärdateien wie `cloudconfigurationd` erfordert das Deaktivieren des System Integrity Protection (SIP) auf macOS. Mit deaktiviertem SIP können Tools wie LLDB verwendet werden, um sich an Systemprozesse anzuhängen und möglicherweise die in DEP-API-Interaktionen verwendete Seriennummer zu modifizieren. Diese Methode ist vorzuziehen, da sie die Komplexität von Berechtigungen und Code-Signierung vermeidet.

**Ausnutzung der Binärinstrumentierung:**
Die Modifikation der DEP-Anfrage-Nutzlast vor der JSON-Serialisierung in `cloudconfigurationd` erwies sich als effektiv. Der Prozess umfasste:

1. Anheften von LLDB an `cloudconfigurationd`.
2. Lokalisierung des Punktes, an dem die Systemseriennummer abgerufen wird.
3. Einspeisen einer beliebigen Seriennummer in den Speicher, bevor die Nutzlast verschlüsselt und gesendet wird.

Diese Methode ermöglichte das Abrufen vollständiger DEP-Profile für beliebige Seriennummern und demonstrierte eine potenzielle Schwachstelle.

### Automatisierung der Instrumentierung mit Python

Der Ausnutzungsprozess wurde mit Python unter Verwendung der LLDB-API automatisiert, was es ermöglichte, programmgesteuert beliebige Seriennummern einzufügen und die entsprechenden DEP-Profile abzurufen.

### Potenzielle Auswirkungen von DEP- und MDM-Schwachstellen

Die Forschung hob erhebliche Sicherheitsbedenken hervor:

1. **Informationsoffenlegung**: Durch die Bereitstellung einer DEP-registrierten Seriennummer können sensible organisatorische Informationen, die im DEP-Profil enthalten sind, abgerufen werden.

{{#include ../../../banners/hacktricks-training.md}}
