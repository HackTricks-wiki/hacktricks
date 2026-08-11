# Geräte in anderen Organisationen registrieren

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Apple Automated Device Enrollment (früher DEP) beginnt mit der Identifizierung eines Geräts, das einer Organisation zugewiesen ist. Die hier zusammengefasste Untersuchung aus dem Jahr 2018 zeigte, dass die Kenntnis einer zugewiesenen Seriennummer ausreichte, um die Enrollment-Profile einiger Organisationen abzurufen, da diese Organisationen keine ausreichende zusätzliche Authentifizierung verlangten. Dies ist ein historischer Befund und keine Behauptung, dass jedem aktuellen MDM ausschließlich mit einer Seriennummer beigetreten werden kann. Profile können Zertifikate, Anwendungen, WLAN-Secrets, VPN-Einstellungen und andere sensible Konfigurationen enthalten.<sup>[[1]](#references)[[2]](#references)</sup>

**Das Folgende ist eine Zusammenfassung der Untersuchung [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Weitere technische Details finden Sie dort!**<sup>[[1]](#references)</sup>

## Überblick über die Binary-Analyse von DEP und MDM

Die Untersuchung analysierte Binaries, die mit DEP und MDM auf den zu diesem Zeitpunkt aktuellen macOS-Versionen verbunden waren. Komponentennamen und Zuständigkeiten können sich zwischen Releases ändern:

- **`mdmclient`**: Kommuniziert mit MDM-Servern und löst DEP-Check-ins auf macOS-Versionen vor 10.13.4 aus.
- **`profiles`**: Verwaltet Configuration Profiles und löst DEP-Check-ins auf macOS-Versionen ab 10.13.4 aus.
- **`cloudconfigurationd`**: Verwaltet die DEP-API-Kommunikation und ruft Device Enrollment-Profile ab.

DEP-Check-ins verwenden die Funktionen `CPFetchActivationRecord` und `CPGetActivationRecord` des privaten Configuration Profiles Frameworks, um den Activation Record abzurufen. Dabei kommuniziert `CPFetchActivationRecord` über XPC mit `cloudconfigurationd`.<sup>[[1]](#references)</sup>

## Reverse Engineering des Tesla-Protokolls und des Absinthe-Schemas

Beim DEP-Check-in sendet `cloudconfigurationd` eine verschlüsselte und signierte JSON-Payload an _iprofiles.apple.com/macProfile_. Die Payload enthält die Seriennummer des Geräts und die Aktion "RequestProfileConfiguration". Das verwendete Verschlüsselungsschema wird intern als "Absinthe" bezeichnet. Die Entschlüsselung dieses Schemas ist komplex und umfasst zahlreiche Schritte, weshalb alternative Methoden untersucht wurden, um beliebige Seriennummern in die Activation-Record-Anfrage einzufügen.<sup>[[1]](#references)</sup>

## Proxying von DEP-Anfragen

Versuche, DEP-Anfragen an _iprofiles.apple.com_ mit Tools wie Charles Proxy abzufangen und zu verändern, wurden durch die Verschlüsselung der Payload sowie Sicherheitsmaßnahmen für SSL/TLS erschwert. Das Aktivieren der Konfiguration `MCCloudConfigAcceptAnyHTTPSCertificate` ermöglicht jedoch das Umgehen der Validierung des Serverzertifikats. Die verschlüsselte Natur der Payload verhindert weiterhin die Änderung der Seriennummer ohne den Entschlüsselungsschlüssel.<sup>[[1]](#references)</sup>

## Instrumentierung von System-Binaries, die mit DEP interagieren

Die Instrumentierung von System-Binaries wie `cloudconfigurationd` erfordert das Deaktivieren von System Integrity Protection (SIP) unter macOS. Bei deaktiviertem SIP können Tools wie LLDB an Systemprozesse angehängt werden, um möglicherweise die bei DEP-API-Interaktionen verwendete Seriennummer zu ändern. Diese Methode ist vorzuziehen, da sie die Komplexität von Entitlements und Code Signing vermeidet.<sup>[[1]](#references)</sup>

**Ausnutzung der Binary-Instrumentierung:**
Die Änderung der DEP-Anfrage-Payload vor der JSON-Serialisierung in `cloudconfigurationd` erwies sich als effektiv. Der Prozess umfasste:

1. LLDB an `cloudconfigurationd` anhängen.
2. Die Stelle ermitteln, an der die Systemseriennummer abgerufen wird.
3. Eine beliebige Seriennummer in den Speicher einschleusen, bevor die Payload verschlüsselt und gesendet wird.

Mit dieser Methode konnten die Forscher DEP-Profile für angegebene, zugewiesene Seriennummern abrufen. Eine nicht zugewiesene beliebige Seriennummer wurde dadurch nicht gültig.<sup>[[1]](#references)</sup>

### Automatisierung der Instrumentierung mit Python

Der Ausnutzungsprozess wurde mit Python und der LLDB-API automatisiert. Dadurch war es möglich, beliebige Seriennummern programmgesteuert einzuschleusen und die entsprechenden DEP-Profile abzurufen.<sup>[[1]](#references)</sup>

### Potenzielle Auswirkungen von DEP- und MDM-Schwachstellen

Die Untersuchung wies auf erhebliche Sicherheitsbedenken hin:

1. **Offenlegung von Informationen**: Durch die Angabe einer bei DEP registrierten Seriennummer können sensible Organisationsinformationen aus dem DEP-Profil abgerufen werden.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Sicherheit des Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automatisiertes Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
