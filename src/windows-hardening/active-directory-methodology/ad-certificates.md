# AD-Zertifikate

{{#include ../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet dessen Eigentümer.
- Ein **Public Key** ist mit einem privat gehaltenen Schlüssel gekoppelt, um das Zertifikat seinem rechtmäßigen Besitzer zuzuordnen.
- Der **Validity Period**, definiert durch die **NotBefore**- und **NotAfter**-Daten, markiert die gültige Laufzeit des Zertifikats.
- Eine eindeutige **Serial Number**, von der Certificate Authority (CA) vergeben, identifiziert jedes Zertifikat.
- Der **Issuer** bezieht sich auf die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Subject und erhöht so die Flexibilität der Identifikation.
- **Basic Constraints** geben an, ob das Zertifikat für eine CA oder eine Endentität bestimmt ist und definieren Nutzungsbeschränkungen.
- **Extended Key Usages (EKUs)** legen die spezifischen Verwendungszwecke des Zertifikats fest, wie Code Signing oder E-Mail-Verschlüsselung, über Object Identifiers (OIDs).
- Der **Signature Algorithm** spezifiziert die Methode zum Signieren des Zertifikats.
- Die **Signature**, erstellt mit dem privaten Schlüssel des Issuers, garantiert die Authentizität des Zertifikats.

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten, was für Server mit mehreren Domains entscheidend ist. Sichere Ausstellungsprozesse sind essentiell, um Identitätsdiebstahl zu vermeiden, wenn Angreifer die SAN-Spezifikation manipulieren.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einem AD-Forest über bestimmte Container an, die jeweils unterschiedliche Rollen erfüllen:

- Der **Certification Authorities**-Container enthält vertrauenswürdige Root-CA-Zertifikate.
- Der **Enrolment Services**-Container beschreibt Enterprise CAs und deren Certificate Templates.
- Das **NTAuthCertificates**-Objekt enthält CA-Zertifikate, die für AD-Authentifizierung autorisiert sind.
- Der **AIA (Authority Information Access)**-Container erleichtert die Validierung der Zertifikatskette mit Intermediate- und Cross-CA-Zertifikaten.

### Zertifikatserwerb: Client Certificate Request Flow

1. Der Anforderungsprozess beginnt damit, dass Clients eine Enterprise CA finden.
2. Es wird eine CSR erstellt, die einen Public Key und weitere Details enthält, nachdem ein Public-Private-Key-Paar generiert wurde.
3. Die CA bewertet die CSR anhand verfügbarer Certificate Templates und stellt das Zertifikat auf Basis der Berechtigungen des Templates aus.
4. Nach Zustimmung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und gibt es an den Client zurück.

### Certificate Templates

Diese Templates, die in AD definiert sind, legen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest, einschließlich erlaubter EKUs sowie Registrierungs- oder Änderungsrechte, und sind entscheidend für die Verwaltung des Zugriffs auf Zertifikatdienste.

Das Schema der Templates-Version ist wichtig. Legacy-**v1**-Templates (zum Beispiel das eingebaute **WebServer**-Template) fehlen mehrere moderne Kontrollmöglichkeiten. Die **ESC15/EKUwu**-Forschung zeigte, dass bei **v1 templates** ein Anforderer **Application Policies/EKUs** in der CSR einbetten kann, die gegenüber den im Template konfigurierten EKUs bevorzugt werden, wodurch client-auth-, enrollment agent- oder code-signing-Zertifikate mit nur Enrollment-Rechten möglich werden. Bevorzugen Sie **v2/v3 templates**, entfernen oder ersetzen Sie v1-Standardwerte und grenzen Sie EKUs eng auf den vorgesehenen Zweck ein.

## Zertifikatsregistrierung

Der Registrierungsprozess für Zertifikate wird durch einen Administrator initiiert, der ein **certificate template** erstellt, das dann von einer Enterprise Certificate Authority (CA) **published** wird. Dadurch wird das Template für die Client-Registrierung verfügbar, ein Schritt, der erreicht wird, indem der Name des Templates dem `certificatetemplates`-Feld eines Active Directory-Objekts hinzugefügt wird.

Damit ein Client ein Zertifikat anfordern kann, müssen **enrollment rights** gewährt sein. Diese Rechte werden durch Security Descriptors auf dem Certificate Template und auf der Enterprise CA selbst definiert. Berechtigungen müssen an beiden Stellen gewährt werden, damit eine Anforderung erfolgreich ist.

### Template Enrollment Rights

Diese Rechte werden durch Access Control Entries (ACEs) spezifiziert und beschreiben Berechtigungen wie:

- **Certificate-Enrollment** und **Certificate-AutoEnrollment**-Rechte, jeweils mit spezifischen GUIDs verknüpft.
- **ExtendedRights**, die alle erweiterten Berechtigungen erlauben.
- **FullControl/GenericAll**, die vollständige Kontrolle über das Template gewähren.

### Enterprise CA Enrollment Rights

Die Rechte der CA sind in ihrem Security Descriptor festgelegt, zugänglich über die Certificate Authority Management Console. Einige Einstellungen erlauben sogar Low-Privileged-Usern Remote-Zugriff, was ein Sicherheitsrisiko darstellen kann.

### Zusätzliche Ausstellungs-Kontrollen

Bestimmte Kontrollen können angewendet werden, wie z. B.:

- **Manager Approval**: Setzt Anfragen in einen Pending-Status, bis sie von einem Certificate Manager genehmigt werden.
- **Enrolment Agents and Authorized Signatures**: Legt die Anzahl der erforderlichen Signaturen auf einer CSR und die nötigen Application Policy OIDs fest.

### Methoden zur Anforderung von Zertifikaten

Zertifikate können angefordert werden über:

1. Das **Windows Client Certificate Enrollment Protocol** (MS-WCCE), unter Verwendung von DCOM-Interfaces.
2. Das **ICertPassage Remote Protocol** (MS-ICPR), über Named Pipes oder TCP/IP.
3. Die **certificate enrollment web interface**, wenn die Certificate Authority Web Enrollment-Rolle installiert ist.
4. Den **Certificate Enrollment Service** (CES) in Verbindung mit dem Certificate Enrollment Policy (CEP)-Service.
5. Den **Network Device Enrollment Service** (NDES) für Netzwerkgeräte, unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate außerdem über die GUI (`certmgr.msc` oder `certlm.msc`) oder Kommandozeilentools (`certreq.exe` oder PowerShells `Get-Certificate`-Befehl) anfordern.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatsauthentifizierung

Active Directory (AD) unterstützt Zertifikatsauthentifizierung, hauptsächlich unter Verwendung der Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers für ein Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage unterliegt mehreren Prüfungen durch den Domänencontroller, einschließlich der **Gültigkeit**, des **Pfads** und des **Widerrufsstatus** des Zertifikats. Zu den Prüfungen gehört auch die Verifizierung, dass das Zertifikat aus einer vertrauenswürdigen Quelle stammt, sowie die Bestätigung der Existenz des Ausstellers im **NTAUTH certificate store**. Erfolgreiche Prüfungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD, zu finden unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für den Aufbau von Vertrauen bei der Zertifikatsauthentifizierung.

### Secure Channel (Schannel) Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen, wobei während des Handshakes der Client ein Zertifikat präsentiert, das bei erfolgreicher Validierung Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann Kerberos’ **S4U2Self**-Funktion oder den **Subject Alternative Name (SAN)** des Zertifikats nutzen, neben anderen Methoden.

### AD Certificate Services-Enumerierung

AD's certificate services können durch LDAP-Abfragen enumeriert werden, wodurch Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offenbart werden. Dies ist für jeden domain-authentifizierten Benutzer ohne besondere Berechtigungen zugänglich. Werkzeuge wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden für die Enumerierung und Schwachstellenbewertung in AD CS-Umgebungen verwendet.

Befehle zur Verwendung dieser Tools umfassen:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Jüngste Schwachstellen & Sicherheitsupdates (2022–2025)

| Jahr | ID / Name | Auswirkung | Wichtige Erkenntnisse |
|------|-----------|------------|-----------------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* durch Spoofing von Machine-Account-Zertifikaten während PKINIT. | Patch ist in den Sicherheitsupdates vom **10. Mai 2022** enthalten. Auditing- & strong-mapping-Kontrollen wurden via **KB5014754** eingeführt; Umgebungen sollten jetzt im *Full Enforcement*-Modus sein.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in den AD CS Web Enrollment (certsrv) und CES-Rollen. | Öffentliche PoCs sind begrenzt, aber die verwundbaren IIS-Komponenten sind intern oft exponiert. Patch verfügbar seit **Patch Tuesday Juli 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Auf **v1 templates** kann ein Antragsteller mit Enrollment-Rechten **Application Policies/EKUs** in der CSR einbetten, die gegenüber den Template-EKUs bevorzugt werden und so client-auth-, enrollment agent- oder code-signing-Zertifikate erzeugen. | Gepatcht ab **12. November 2024**. Ersetze oder überschreibe v1 templates (z. B. default WebServer), beschränke EKUs auf die beabsichtigte Verwendung und limitiere Enrollment-Rechte. |

### Microsoft-Härtungszeitplan (KB5014754)

Microsoft hat eine dreiphasige Einführung (Compatibility → Audit → Enforcement) eingeführt, um die Kerberos-Zertifikatsauthentifizierung von schwachen impliziten Mappings wegzubewegen. Seit dem **11. Februar 2025** wechseln Domain-Controller automatisch in den **Full Enforcement**-Modus, wenn der Registrierungswert `StrongCertificateBindingEnforcement` nicht gesetzt ist. Administratoren sollten:

1. Alle DCs & AD CS-Server patchen (Mai 2022 oder später).
2. Event ID 39/41 während der *Audit*-Phase auf schwache Mappings überwachen.
3. client-auth-Zertifikate mit der neuen **SID extension** neu ausstellen oder starke manuelle Mappings konfigurieren, bevor Februar 2025 eintritt.

---

## Erkennung & Härtungsverbesserungen

* **Defender for Identity AD CS sensor (2023-2024)** zeigt jetzt Posture-Assessments für ESC1-ESC8/ESC11 und generiert Echtzeit-Alerts wie *“Domain-controller certificate issuance for a non-DC”* (ESC8) und *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Stelle sicher, dass Sensoren auf allen AD CS-Servern bereitgestellt sind, um von diesen Erkennungen zu profitieren.
* Deaktiviere oder engere das **“Supply in the request”**-Option auf allen Templates; bevorzugt sind explizit definierte SAN/EKU-Werte.
* Entferne **Any Purpose** oder **No EKU** aus Templates, sofern nicht absolut erforderlich (adressiert ESC2-Szenarien).
* Fordere **Manager Approval** oder dedizierte Enrollment Agent-Workflows für sensitive Templates (z. B. WebServer / CodeSigning).
* Beschränke Web Enrollment (certsrv) und CES/NDES-Endpunkte auf vertrauenswürdige Netzwerke oder setze sie hinter client-certificate authentication.
* Erzwinge RPC-Enrollment-Verschlüsselung (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), um ESC11 (RPC relay) zu mindern. Das Flag ist standardmäßig aktiviert, wird aber oft für Legacy-Clients deaktiviert, wodurch das Relay-Risiko erneut entsteht.
* Sichere IIS-basierte Enrollment-Endpunkte (CES/Certsrv): deaktiviere NTLM wo möglich oder erfordere HTTPS + Extended Protection, um ESC8-Relays zu blockieren.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
