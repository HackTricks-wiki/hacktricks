# Geräte in anderen Organisationen registrieren

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung

Wie [**zuvor kommentiert**](#what-is-mdm-mobile-device-management)**,** ist zum Versuch, ein Gerät in einer Organisation zu registrieren, **nur eine zu dieser Organisation gehörende Seriennummer erforderlich**. Sobald das Gerät registriert ist, installieren mehrere Organisationen vertrauliche Daten auf dem neuen Gerät: Zertifikate, Anwendungen, WiFi-Passwörter, VPN-Konfigurationen [und so weiter](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daher könnte dies ein gefährlicher Einstiegspunkt für Angreifer sein, wenn der Registrierungsprozess nicht korrekt geschützt ist.

**Das Folgende ist eine Zusammenfassung der Untersuchung [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Weitere technische Details findest du dort!**<sup>[[1]](#references)</sup>

## Übersicht über die DEP- und MDM-Binäranalyse

Diese Untersuchung befasst sich mit den Binärdateien, die mit dem Device Enrollment Program (DEP) und Mobile Device Management (MDM) unter macOS verbunden sind. Zu den wichtigsten Komponenten gehören:

- **`mdmclient`**: Kommuniziert mit MDM-Servern und löst DEP-Check-ins bei macOS-Versionen vor 10.13.4 aus.
- **`profiles`**: Verwaltet Configuration Profiles und löst DEP-Check-ins bei macOS-Versionen ab 10.13.4 aus.
- **`cloudconfigurationd`**: Verwaltet die DEP-API-Kommunikation und ruft Device Enrollment-Profile ab.

DEP-Check-ins verwenden die Funktionen `CPFetchActivationRecord` und `CPGetActivationRecord` aus dem privaten Configuration Profiles-Framework, um den Activation Record abzurufen. Dabei koordiniert `CPFetchActivationRecord` die Kommunikation mit `cloudconfigurationd` über XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering des Tesla-Protokolls und des Absinthe-Schemas

Beim DEP-Check-in sendet `cloudconfigurationd` eine verschlüsselte und signierte JSON-Nutzlast an _iprofiles.apple.com/macProfile_. Die Nutzlast enthält die Seriennummer des Geräts und die Aktion "RequestProfileConfiguration". Das verwendete Verschlüsselungsschema wird intern als "Absinthe" bezeichnet. Die Entschlüsselung dieses Schemas ist komplex und umfasst zahlreiche Schritte, was zur Untersuchung alternativer Methoden zum Einfügen beliebiger Seriennummern in die Activation-Record-Anfrage führte.<sup>[[1]](#references)</sup>

## Proxying von DEP-Anfragen

Versuche, DEP-Anfragen an _iprofiles.apple.com_ mit Tools wie Charles Proxy abzufangen und zu verändern, wurden durch die Verschlüsselung der Nutzlast sowie durch SSL/TLS-Sicherheitsmaßnahmen erschwert. Das Aktivieren der Konfiguration `MCCloudConfigAcceptAnyHTTPSCertificate` ermöglicht jedoch das Umgehen der Serverzertifikatsvalidierung. Die verschlüsselte Natur der Nutzlast verhindert weiterhin die Änderung der Seriennummer ohne den Entschlüsselungsschlüssel.<sup>[[1]](#references)</sup>

## Instrumentierung von System-Binärdateien, die mit DEP interagieren

Die Instrumentierung von System-Binärdateien wie `cloudconfigurationd` erfordert das Deaktivieren des System Integrity Protection (SIP) unter macOS. Bei deaktiviertem SIP können Tools wie LLDB verwendet werden, um sich an Systemprozesse anzuhängen und möglicherweise die bei DEP-API-Interaktionen verwendete Seriennummer zu ändern. Diese Methode ist vorzuziehen, da sie die Komplexität von Entitlements und Code Signing vermeidet.<sup>[[1]](#references)</sup>

**Ausnutzen der Binärinstrumentierung:**
Die Änderung der DEP-Anfragenutzlast vor der JSON-Serialisierung in `cloudconfigurationd` erwies sich als effektiv. Der Prozess umfasste:

1. LLDB an `cloudconfigurationd` anhängen.
2. Die Stelle ermitteln, an der die Systemseriennummer abgerufen wird.
3. Eine beliebige Seriennummer in den Speicher injizieren, bevor die Nutzlast verschlüsselt und gesendet wird.

Diese Methode ermöglichte das Abrufen vollständiger DEP-Profile für beliebige Seriennummern und zeigte eine potenzielle Schwachstelle.<sup>[[1]](#references)</sup>

### Automatisierung der Instrumentierung mit Python

Der Exploit-Prozess wurde mithilfe von Python und der LLDB-API automatisiert. Dadurch wurde es möglich, programmgesteuert beliebige Seriennummern zu injizieren und die entsprechenden DEP-Profile abzurufen.<sup>[[1]](#references)</sup>

### Potenzielle Auswirkungen von DEP- und MDM-Schwachstellen

Die Untersuchung zeigte erhebliche Sicherheitsbedenken auf:

1. **Offenlegung von Informationen**: Durch die Angabe einer bei DEP registrierten Seriennummer können vertrauliche Organisationsinformationen aus dem DEP-Profil abgerufen werden.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
