# Geräte in anderen Organisationen registrieren

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung

Wie [**zuvor kommentiert**](#what-is-mdm-mobile-device-management)**,** ist zum Versuch, ein Gerät in einer Organisation zu registrieren, **nur eine Seriennummer dieser Organisation erforderlich**. Sobald das Gerät registriert ist, installieren mehrere Organisationen sensible Daten auf dem neuen Gerät: Zertifikate, Anwendungen, WiFi-Passwörter, VPN-Konfigurationen [und so weiter](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daher könnte dies ein gefährlicher Einstiegspunkt für Angreifer sein, wenn der Registrierungsprozess nicht korrekt geschützt ist.

**Das Folgende ist eine Zusammenfassung der Forschung [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Weitere technische Details finden sich dort!**<sup>[[1]](#references)</sup>

## Überblick über die Binäranalyse von DEP und MDM

Diese Forschung untersucht die mit dem Device Enrollment Program (DEP) und Mobile Device Management (MDM) unter macOS verbundenen Binärdateien. Zu den wichtigsten Komponenten gehören:

- **`mdmclient`**: Kommuniziert mit MDM-Servern und löst bei macOS-Versionen vor 10.13.4 DEP-Check-ins aus.
- **`profiles`**: Verwaltet Configuration Profiles und löst bei macOS-Versionen ab 10.13.4 DEP-Check-ins aus.
- **`cloudconfigurationd`**: Verwaltet die DEP-API-Kommunikation und ruft Device Enrollment-Profile ab.

DEP-Check-ins verwenden die Funktionen `CPFetchActivationRecord` und `CPGetActivationRecord` aus dem privaten Configuration Profiles Framework, um den Activation Record abzurufen. Dabei kommuniziert `CPFetchActivationRecord` über XPC mit `cloudconfigurationd`.<sup>[[1]](#references)</sup>

## Reverse Engineering des Tesla-Protokolls und des Absinthe-Schemas

Beim DEP-Check-in sendet `cloudconfigurationd` eine verschlüsselte und signierte JSON-Nutzlast an _iprofiles.apple.com/macProfile_. Die Nutzlast enthält die Seriennummer des Geräts und die Aktion "RequestProfileConfiguration". Das verwendete Verschlüsselungsschema wird intern als "Absinthe" bezeichnet. Die Entschlüsselung dieses Schemas ist komplex und umfasst zahlreiche Schritte, weshalb alternative Methoden untersucht wurden, um beliebige Seriennummern in die Activation-Record-Anfrage einzufügen.<sup>[[1]](#references)</sup>

## Proxying von DEP-Anfragen

Versuche, DEP-Anfragen an _iprofiles.apple.com_ mit Tools wie Charles Proxy abzufangen und zu verändern, wurden durch die Verschlüsselung der Nutzlast und SSL/TLS-Sicherheitsmaßnahmen erschwert. Durch Aktivieren der Konfiguration `MCCloudConfigAcceptAnyHTTPSCertificate` kann die Validierung des Serverzertifikats umgangen werden. Die verschlüsselte Natur der Nutzlast verhindert jedoch weiterhin die Änderung der Seriennummer ohne den Entschlüsselungsschlüssel.<sup>[[1]](#references)</sup>

## Instrumentierung von System-Binärdateien, die mit DEP interagieren

Die Instrumentierung von System-Binärdateien wie `cloudconfigurationd` erfordert das Deaktivieren des System Integrity Protection (SIP) unter macOS. Bei deaktiviertem SIP können Tools wie LLDB verwendet werden, um sich an Systemprozesse anzuhängen und möglicherweise die bei DEP-API-Interaktionen verwendete Seriennummer zu ändern. Diese Methode ist vorzuziehen, da sie die Komplexität von Entitlements und Code Signing vermeidet.

**Ausnutzen der Binärinstrumentierung:**
Das Ändern der DEP-Anfragenutzlast vor der JSON-Serialisierung in `cloudconfigurationd` erwies sich als effektiv. Der Prozess umfasste:

1. LLDB an `cloudconfigurationd` anhängen.
2. Die Stelle lokalisieren, an der die Systemseriennummer abgerufen wird.
3. Eine beliebige Seriennummer in den Speicher einschleusen, bevor die Nutzlast verschlüsselt und gesendet wird.

Diese Methode ermöglichte das Abrufen vollständiger DEP-Profile für beliebige Seriennummern und demonstrierte eine potenzielle Schwachstelle.<sup>[[1]](#references)</sup>

### Automatisierung der Instrumentierung mit Python

Der Exploit-Prozess wurde mithilfe von Python und der LLDB-API automatisiert. Dadurch wurde es möglich, beliebige Seriennummern programmgesteuert einzuschleusen und die zugehörigen DEP-Profile abzurufen.<sup>[[1]](#references)</sup>

### Potenzielle Auswirkungen von DEP- und MDM-Schwachstellen

Die Forschung hob erhebliche Sicherheitsbedenken hervor:

1. **Offenlegung von Informationen**: Durch Angabe einer bei DEP registrierten Seriennummer können sensible Organisationsinformationen aus dem DEP-Profil abgerufen werden.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
