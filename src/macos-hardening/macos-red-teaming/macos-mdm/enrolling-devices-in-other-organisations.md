# Geräte in anderen Organisationen registrieren

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Apple Automated Device Enrollment (früher DEP) beginnt mit der Identifizierung eines einer Organisation zugewiesenen Geräts. Die hier zusammengefasste Untersuchung aus dem Jahr 2018 zeigte, dass die Kenntnis einer zugewiesenen Seriennummer ausreichte, um die Enrollment-Profile einiger Organisationen abzurufen, da diese Organisationen keine ausreichende zusätzliche Authentifizierung verlangten. Dies ist eine historische Erkenntnis und keine Behauptung, dass jedem aktuellen MDM nur mit einer Seriennummer beigetreten werden kann. Profile können Zertifikate, Anwendungen, WLAN-Secrets, VPN-Einstellungen und andere sensible Konfigurationen enthalten.<sup>[[1]](#references)[[2]](#references)</sup>

**Das Folgende ist eine Zusammenfassung der Untersuchung [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Weitere technische Details finden sich dort!**<sup>[[1]](#references)</sup>

## Übersicht über DEP und MDM Binary Analysis

Die Untersuchung analysierte Binaries im Zusammenhang mit DEP und MDM auf den zum damaligen Zeitpunkt aktuellen macOS-Versionen. Komponentennamen und Zuständigkeiten können sich zwischen Releases ändern:

- **`mdmclient`**: Kommuniziert mit MDM-Servern und löst DEP-Check-ins auf macOS-Versionen vor 10.13.4 aus.
- **`profiles`**: Verwaltet Configuration Profiles und löst DEP-Check-ins auf macOS-Versionen ab 10.13.4 aus.
- **`cloudconfigurationd`**: Verwaltet die DEP-API-Kommunikation und ruft Device Enrollment-Profile ab.

DEP-Check-ins verwenden die Funktionen `CPFetchActivationRecord` und `CPGetActivationRecord` aus dem privaten Configuration Profiles Framework, um den Activation Record abzurufen. Dabei koordiniert `CPFetchActivationRecord` die Kommunikation mit `cloudconfigurationd` über XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering des Tesla Protocol und des Absinthe Scheme

Beim DEP-Check-in sendet `cloudconfigurationd` einen verschlüsselten und signierten JSON-Payload an _iprofiles.apple.com/macProfile_. Der Payload enthält die Seriennummer des Geräts und die Aktion "RequestProfileConfiguration". Das verwendete Verschlüsselungsschema wird intern als "Absinthe" bezeichnet. Die Entschlüsselung dieses Schemas ist komplex und umfasst zahlreiche Schritte, was zur Untersuchung alternativer Methoden zum Einfügen beliebiger Seriennummern in die Activation-Record-Anfrage führte.<sup>[[1]](#references)</sup>

## Proxying von DEP-Anfragen

Versuche, DEP-Anfragen an _iprofiles.apple.com_ mit Tools wie Charles Proxy abzufangen und zu ändern, wurden durch Payload-Verschlüsselung und SSL/TLS-Sicherheitsmaßnahmen erschwert. Die Aktivierung der Konfiguration `MCCloudConfigAcceptAnyHTTPSCertificate` ermöglicht jedoch das Umgehen der Serverzertifikat-Validierung. Die verschlüsselte Natur des Payloads verhindert weiterhin, die Seriennummer ohne den Entschlüsselungsschlüssel zu ändern.<sup>[[1]](#references)</sup>

## Instrumentierung von System-Binaries, die mit DEP interagieren

Die Instrumentierung von System-Binaries wie `cloudconfigurationd` erfordert das Deaktivieren des System Integrity Protection (SIP) unter macOS. Bei deaktiviertem SIP können Tools wie LLDB verwendet werden, um sich an Systemprozesse anzuhängen und möglicherweise die bei DEP-API-Interaktionen verwendete Seriennummer zu ändern. Diese Methode ist vorzuziehen, da sie die Komplexität von Entitlements und Code Signing vermeidet.<sup>[[1]](#references)</sup>

**Ausnutzen der Binary-Instrumentierung:**
Das Ändern des DEP-Request-Payloads vor der JSON-Serialisierung in `cloudconfigurationd` erwies sich als effektiv. Der Prozess umfasste:

1. LLDB an `cloudconfigurationd` anhängen.
2. Die Stelle finden, an der die Systemseriennummer abgerufen wird.
3. Eine beliebige Seriennummer in den Speicher injizieren, bevor der Payload verschlüsselt und gesendet wird.

Mit dieser Methode konnten die Forscher DEP-Profile für angegebene, zugewiesene Seriennummern abrufen. Eine nicht zugewiesene beliebige Seriennummer wurde dadurch nicht gültig.<sup>[[1]](#references)</sup>

### Instrumentierung mit Python automatisieren

Der Exploit-Prozess wurde mithilfe von Python und der LLDB-API automatisiert. Dadurch wurde es möglich, beliebige Seriennummern programmgesteuert zu injizieren und die entsprechenden DEP-Profile abzurufen.<sup>[[1]](#references)</sup>

## Erneute Untersuchung 2025: Rogue Enrollment aus einer VM

Die Forschung von Black Hat Asia 2025 zeigte, dass das ursprüngliche Trust-Boundary-Problem weiterhin auf der **MDM-Schicht** relevant sein kann: Statt `cloudconfigurationd` mit LLDB zu patchen, führten die Forscher macOS unter QEMU/KVM mit OpenCore aus und stellten die Kandidatenidentität über die SMBIOS der VM bereit. Der unveränderte macOS-Enrollment-Stack führte anschließend den verschlüsselten Austausch mit Apple durch. Öffentlich geleakte Seriennummern und plausibel wirkende Kandidaten können daher getestet werden, ohne den entsprechenden physischen Mac zu besitzen. Ein Treffer erfordert weiterhin, dass die Seriennummer einer Organisation zugewiesen ist und der Enrollment-Pfad der Organisation unzureichend authentifiziert wird.<sup>[[3]](#references)</sup>

Für ein autorisiertes Lab-Gerät umfassen die relevanten OpenCore-`PlatformInfo`-Werte ein Produktmodell und eine Seriennummer (bei realen Deployments müssen ROM und UUID außerdem intern konsistent bleiben):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
Dieselbe Untersuchung identifizierte den Status `CheckProfilesFetchRateLimit` in der privaten Datei `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Da die Prüfung auf dem Client erfolgte, konnte sie durch das Ändern der gespeicherten Zeitwerte außer Kraft gesetzt werden. Diese Pfade sind nicht dokumentiert und versionsabhängig, aber sie sind nützliche Reverse-Engineering-Ansatzpunkte bei der Analyse eines aktuellen macOS-Builds:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Das zweite Artefakt kann den zwischengespeicherten Aktivierungsdatensatz offenlegen, einschließlich der Information, ob der Flow eine direkte `ConfigurationURL` oder eine authentifizierte `ConfigurationWebURL` verwendet. Teste sowohl den beworbenen Flow als auch alle MDM-spezifischen Legacy-Enrollment-Endpunkte: SSO nur im Haupt-Web-Flow zu aktivieren, schützt keinen parallelen direkten Endpunkt. Die vollständige Protokollsequenz findest du in der [macOS MDM overview](README.md).<sup>[[3]](#references)</sup>

### Secret Hunting nach dem Enrollment

Ein Rogue-Enrollment ist nur der Einstiegspunkt. Untersuche nach dem Enrollment jedes zugestellte Profil, jede Bootstrap-Policy, jede Package-Repository-Konfiguration, jedes Agent-Installationsskript und jedes Self-Service-Element. Die Forschung von 2025 förderte Beispiele für Wi-Fi-Zugangsdaten, gemeinsam genutzte lokale Administratorpasswörter, signierte Cloud-Storage-URLs, Webhook-URLs, Aktivierungsdaten von Security-Agents sowie MDM/API-Credentials zutage. Ein Tenant-API-Credential in einem zugestellten Skript kann einen einzelnen Rogue-Endpunkt in die Kontrolle über andere verwaltete Geräte verwandeln. Suche daher sowohl im aktiven Dateisystem als auch in heruntergeladenen bzw. zwischengespeicherten Policy-Inhalten.<sup>[[3]](#references)</sup>

Nützliche Prüfziele umfassen:<sup>[[3]](#references)</sup>

- Installierte `.mobileconfig`-Payloads und die Datenbank der Configuration Profiles.
- PreStage-/Bootstrap-Skripte und Packages, die Accounts erstellen oder EDR-/VPN-Agents installieren.
- Munki- oder andere Package-Repository-URLs, insbesondere Query-Strings mit Bearer-/SAS-ähnlichen Signaturen.
- Self-Service-Kataloge und die zugehörigen Policy-APIs, einschließlich Legacy-Routen, die die Enrollment-SSO-Policy möglicherweise nicht durchsetzen.
- Shell-History und zwischengespeicherte Policy-Ausgaben nach `password`, `token`, `secret`, `Authorization`, Webhook-Hostnames und Vendor-API-Endpunkten.

### Absicherung der Trust Boundary

Behandle eine Seriennummer als Inventar-/Routing-Attribut, **nicht** als Besitznachweis. Fordere eine Benutzerauthentifizierung für Enrollment und Self-Service, generiere eindeutige lokale Administratorpasswörter pro Gerät und bette niemals Tenant-API-Credentials oder wiederverwendbare Infrastruktur-Secrets in Profile oder Skripte ein. Halte unvermeidbare Bootstrap-Tokens kurzlebig und auf die einzelne Aktion sowie das Gerät zu beschränken, die bzw. das provisioniert wird.<sup>[[3]](#references)</sup>

Auf Apple-Silicon-Macs mit macOS 14 oder höher kann Managed Device Attestation die Identität kryptografisch an die Secure Enclave binden. Die auf Apple-Root-of-Trust basierende Attestation kann eine frische Nonce sowie Seriennummer, UDID, OS-Version, SIP-Status und Secure-Boot-Status enthalten; ACME kann anschließend eine hardwaregebundene Client-Identität ausstellen. Verwende diese Identität, um den MDM-Kanal zu schützen und den Zugriff auf hochwertige Zertifikate, VPN-Zugriff und andere Ressourcen zu steuern. Behalte dabei eine separate Benutzerauthentifizierung bei, da die Device Attestation das Gerät und nicht den Operator nachweist.<sup>[[4]](#references)</sup>

## Potenzielle Auswirkungen von DEP- und MDM-Schwachstellen

Die Forschung hob erhebliche Sicherheitsbedenken hervor:

1. **Offenlegung von Informationen**: Durch die Angabe einer bei DEP registrierten Seriennummer können vertrauliche Organisationsinformationen aus dem DEP-Profil abgerufen werden.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Sicherheit des Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automatisiertes Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking von Apple-MDMs durch Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
