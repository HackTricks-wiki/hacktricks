# Geräte in anderen Organisationen registrieren

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung

Wie [**zuvor kommentiert**](#what-is-mdm-mobile-device-management)**,** ist zum Versuch, ein Gerät in einer Organisation zu registrieren, **nur eine dieser Organisation zugehörige Seriennummer erforderlich**. Sobald das Gerät registriert ist, installieren mehrere Organisationen sensible Daten auf dem neuen Gerät: Zertifikate, Anwendungen, WiFi-Passwörter, VPN-Konfigurationen [und so weiter](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daher könnte dies ein gefährlicher entrypoint für Angreifer sein, wenn der Registrierungsprozess nicht korrekt geschützt ist.

**Das Folgende ist eine Zusammenfassung der Forschung [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Weitere technische Details finden sich dort!**<sup>[1]</sup>

## Überblick über DEP- und MDM-Binary-Analyse

Diese Forschung untersucht die mit dem Device Enrollment Program (DEP) und Mobile Device Management (MDM) unter macOS verbundenen Binaries. Zu den wichtigsten Komponenten gehören:

- **`mdmclient`**: Kommuniziert mit MDM-Servern und löst bei macOS-Versionen vor 10.13.4 DEP-Check-ins aus.
- **`profiles`**: Verwaltet Configuration Profiles und löst bei macOS-Versionen ab 10.13.4 DEP-Check-ins aus.
- **`cloudconfigurationd`**: Verwaltet die DEP-API-Kommunikation und ruft Device Enrollment-Profile ab.

DEP-Check-ins verwenden die Funktionen `CPFetchActivationRecord` und `CPGetActivationRecord` aus dem privaten Configuration Profiles Framework, um den Activation Record abzurufen. `CPFetchActivationRecord` koordiniert dabei über XPC mit `cloudconfigurationd`.<sup>[1]</sup>

## Reverse Engineering des Tesla-Protokolls und des Absinthe-Schemas

Beim DEP-Check-in sendet `cloudconfigurationd` eine verschlüsselte und signierte JSON-Payload an _iprofiles.apple.com/macProfile_. Die Payload enthält die Seriennummer des Geräts sowie die Aktion "RequestProfileConfiguration". Das verwendete Verschlüsselungsschema wird intern als "Absinthe" bezeichnet. Die Entschlüsselung dieses Schemas ist komplex und umfasst zahlreiche Schritte, weshalb alternative Methoden untersucht wurden, um beliebige Seriennummern in die Activation-Record-Anfrage einzufügen.<sup>[1]</sup>

## Proxying von DEP-Anfragen

Versuche, DEP-Anfragen an _iprofiles.apple.com_ mit Tools wie Charles Proxy abzufangen und zu verändern, wurden durch die Payload-Verschlüsselung und SSL/TLS-Sicherheitsmaßnahmen erschwert. Das Aktivieren der Konfiguration `MCCloudConfigAcceptAnyHTTPSCertificate` ermöglicht jedoch das Umgehen der Validierung des Serverzertifikats. Die verschlüsselte Payload verhindert weiterhin die Änderung der Seriennummer ohne den Entschlüsselungsschlüssel.<sup>[1]</sup>

## Instrumentierung von System-Binaries mit DEP-Interaktion

Die Instrumentierung von System-Binaries wie `cloudconfigurationd` erfordert das Deaktivieren des System Integrity Protection (SIP) unter macOS. Bei deaktiviertem SIP können Tools wie LLDB an Systemprozesse angehängt werden, um möglicherweise die für DEP-API-Interaktionen verwendete Seriennummer zu verändern. Diese Methode ist vorzuziehen, da sie die Komplexität von Entitlements und Code Signing vermeidet.

**Ausnutzung der Binary-Instrumentierung:**
Die Änderung der DEP-Anfrage-Payload vor der JSON-Serialisierung in `cloudconfigurationd` erwies sich als effektiv. Der Prozess umfasste:

1. LLDB an `cloudconfigurationd` anhängen.
2. Die Stelle finden, an der die Systemseriennummer abgerufen wird.
3. Eine beliebige Seriennummer in den Speicher einschleusen, bevor die Payload verschlüsselt und gesendet wird.

Diese Methode ermöglichte das Abrufen vollständiger DEP-Profile für beliebige Seriennummern und demonstrierte eine potenzielle Schwachstelle.<sup>[1]</sup>

### Automatisierung der Instrumentierung mit Python

Der Exploit-Prozess wurde mithilfe von Python und der LLDB-API automatisiert. Dadurch wurde es möglich, programmgesteuert beliebige Seriennummern einzuschleusen und die zugehörigen DEP-Profile abzurufen.<sup>[1]</sup>

### Potenzielle Auswirkungen von DEP- und MDM-Schwachstellen

Die Forschung hob erhebliche Sicherheitsbedenken hervor:

1. **Offenlegung von Informationen**: Durch die Angabe einer bei DEP registrierten Seriennummer können im DEP-Profil enthaltene sensible Informationen der Organisation abgerufen werden.<sup>[1]</sup>

## Referenzen

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
