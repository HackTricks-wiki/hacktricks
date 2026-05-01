# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Certificate

- Das **Subject** des Certificate bezeichnet seinen Besitzer.
- Ein **Public Key** wird mit einem privat gehaltenen Key gekoppelt, um das Certificate mit seinem rechtmäßigen Besitzer zu verknüpfen.
- Der **Validity Period**, definiert durch die Daten **NotBefore** und **NotAfter**, markiert die effektive Gültigkeitsdauer des Certificate.
- Eine eindeutige **Serial Number**, bereitgestellt von der Certificate Authority (CA), identifiziert jedes Certificate.
- Der **Issuer** bezeichnet die CA, die das Certificate ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für das Subject und erhöht die Flexibilität bei der Identifizierung.
- **Basic Constraints** identifizieren, ob das Certificate für eine CA oder eine End Entity ist, und definieren Nutzungseinschränkungen.
- **Extended Key Usages (EKUs)** legen die spezifischen Zwecke des Certificate fest, wie code signing oder email encryption, über Object Identifiers (OIDs).
- Der **Signature Algorithm** legt die Methode zum Signieren des Certificate fest.
- Die **Signature**, erstellt mit dem privaten Key des Issuers, garantiert die Authentizität des Certificate.

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Certificate auf mehrere Identitäten, was für Server mit mehreren Domains entscheidend ist. Sichere Ausstellungsprozesse sind wichtig, um Impersonation-Risiken durch Angreifer zu vermeiden, die die SAN-Spezifikation manipulieren.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erkennt CA certificates in einem AD forest über definierte Container an, die jeweils einzigartige Rollen erfüllen:

- Der Container **Certification Authorities** enthält vertrauenswürdige Root CA certificates.
- Der Container **Enrolment Services** enthält Details zu Enterprise CAs und ihren certificate templates.
- Das Objekt **NTAuthCertificates** umfasst CA certificates, die für AD authentication autorisiert sind.
- Der Container **AIA (Authority Information Access)** erleichtert die Validierung der certificate chain mit Intermediate- und Cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. Der Anforderungsprozess beginnt damit, dass Clients eine Enterprise CA finden.
2. Es wird eine CSR erstellt, die einen Public Key und andere Details enthält, nachdem ein Public-Private-Key-Paar generiert wurde.
3. Die CA prüft die CSR anhand verfügbarer certificate templates und stellt das Certificate basierend auf den Berechtigungen des templates aus.
4. Nach der Genehmigung signiert die CA das Certificate mit ihrem privaten Key und sendet es an den Client zurück.

### Certificate Templates

Diese in AD definierten Templates beschreiben die Einstellungen und Berechtigungen für die Ausstellung von Certificates, einschließlich erlaubter EKUs sowie Enrollment- oder Änderungsrechten, die für die Verwaltung des Zugriffs auf certificate services entscheidend sind.

**Template schema version matters.** Legacy **v1** templates (for example, the built-in **WebServer** template) lack several modern enforcement knobs. The **ESC15/EKUwu** research showed that on **v1 templates**, a requester can embed **Application Policies/EKUs** in the CSR that are **preferred over** the template's configured EKUs, enabling client-auth, enrollment agent, or code-signing certificates with only enrollment rights. Prefer **v2/v3 templates**, remove or supersede v1 defaults, and tightly scope EKUs to the intended purpose.

## Certificate Enrollment

Der Enrollment-Prozess für Certificates wird von einem Administrator initiiert, der **ein certificate template erstellt**, das anschließend von einer Enterprise Certificate Authority (CA) **veröffentlicht** wird. Dadurch wird das Template für das Client Enrollment verfügbar; dies wird erreicht, indem der Name des Templates zum Feld `certificatetemplates` eines Active Directory-Objekts hinzugefügt wird.

Damit ein Client ein Certificate anfordern kann, müssen **Enrollment Rights** gewährt werden. Diese Rechte sind durch security descriptors auf dem certificate template und der Enterprise CA selbst definiert. Damit eine Anforderung erfolgreich ist, müssen die Berechtigungen an beiden Stellen vergeben sein.

### Template Enrollment Rights

Diese Rechte werden über Access Control Entries (ACEs) festgelegt und beschreiben Berechtigungen wie:

- **Certificate-Enrollment** und **Certificate-AutoEnrollment** rights, jeweils mit spezifischen GUIDs verknüpft.
- **ExtendedRights**, erlaubt alle erweiterten Berechtigungen.
- **FullControl/GenericAll**, bietet vollständige Kontrolle über das Template.

### Enterprise CA Enrollment Rights

Die Rechte der CA sind in ihrem security descriptor festgelegt, der über die Certificate Authority-Verwaltungskonsole zugänglich ist. Einige Einstellungen erlauben sogar Benutzern mit niedrigen Rechten den Remote-Zugriff, was ein Sicherheitsrisiko darstellen könnte.

### Additional Issuance Controls

Bestimmte Controls können gelten, zum Beispiel:

- **Manager Approval**: Versetzt Anfragen in einen Pending-Status, bis sie von einem certificate manager genehmigt werden.
- **Enrolment Agents and Authorized Signatures**: Legen die Anzahl der für eine CSR erforderlichen Signatures und die notwendigen Application Policy OIDs fest.

### Methods to Request Certificates

Certificates können angefordert werden über:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), unter Verwendung von DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), über named pipes oder TCP/IP.
3. Die **certificate enrollment web interface**, mit installierter Certificate Authority Web Enrollment-Rolle.
4. Der **Certificate Enrollment Service** (CES) in Verbindung mit dem Certificate Enrollment Policy (CEP)-Service.
5. Der **Network Device Enrollment Service** (NDES) für network devices, unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows users can also request certificates via the GUI (`certmgr.msc` or `certlm.msc`) or command-line tools (`certreq.exe` or PowerShell's `Get-Certificate` command).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatsauthentifizierung

Active Directory (AD) unterstützt Zertifikatsauthentifizierung, primär unter Verwendung der Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anforderung eines Benutzers für ein Ticket Granting Ticket (TGT) mit dem **private key** des Zertifikats des Benutzers signiert. Diese Anfrage durchläuft mehrere Validierungen durch den Domain Controller, einschließlich der **validity**, des **path** und des **revocation status** des Zertifikats. Zu den Validierungen gehört auch die Überprüfung, dass das Zertifikat aus einer vertrauenswürdigen Quelle stammt, sowie die Bestätigung der Präsenz des Ausstellers im **NTAUTH certificate store**. Erfolgreiche Validierungen führen zur Ausstellung eines TGT. Das Objekt **`NTAuthCertificates`** in AD, zu finden unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für das Herstellen von Vertrauen für certificate authentication.

Seit dem Rollout von **KB5014754** geht es bei modernem Kerberos certificate auth hauptsächlich um **mapping strength**, nicht nur um EKUs. In gehärteten Forests:

- Ein Certificate, das nur einen **UPN/DNS SAN** enthält, reicht für logon möglicherweise nicht mehr aus.
- Der KDC bevorzugt eine **strong binding**, typischerweise die **SID security extension** (`1.3.6.1.4.1.311.25.2`) oder ein starkes explizites Mapping in `altSecurityIdentities`.
- Wenn das cert kein starkes Mapping hat, protokollieren DCs im compatibility mode **Kdcsvc Event ID 39/41** und verweigern die Authentifizierung im enforcement mode.
- In gemischten attack paths sind **ESC9/ESC16** wichtig, weil sie die SID extension aus ausgestellten certs entfernen; Operatoren verlassen sich dann auf explizite Mappings oder SAN URL SID Formate, wo der attack path dies unterstützt.

### Secure Channel (Schannel) Authentication

Schannel ermöglicht sichere TLS/SSL-Verbindungen, wobei während eines Handshakes der client ein Certificate präsentiert, das bei erfolgreicher Validierung den Zugang autorisiert. Das Mapping eines Certificate auf ein AD account kann unter anderem die Kerberos-Funktion **S4U2Self** oder den **Subject Alternative Name (SAN)** des Certificates umfassen.

Schannel ist außerdem der praktische Fallback, wenn **PKINIT** nicht verfügbar ist. Wenn beispielsweise ein domain controller kein geeignetes **Smart Card Logon** Certificate hat, kann `certipy auth`/PKINIT-Tooling möglicherweise kein TGT erhalten, aber dasselbe Certificate kann weiterhin gegen **LDAPS** oder **LDAP StartTLS** für authentication und LDAP-Operationen nutzbar sein.

### AD Certificate Services Enumeration

Die certificate services von AD können über LDAP-Queries enumeriert werden, wodurch Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offengelegt werden. Dies ist jedem domain-authenticated user ohne besondere privileges zugänglich. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden für die Enumeration und Vulnerability-Assessment in AD CS-Umgebungen verwendet.

Befehle zur Verwendung dieser Tools umfassen:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Aktuelle Schwachstellen & Sicherheits-Updates (2022-2025)

| Year | ID / Name | Impact | Key- takeaways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* durch Spoofing von Machine-Account-Zertifikaten während PKINIT. | Patch ist in den **May 10 2022** Security-Updates enthalten. Auditing- und Strong-Mapping-Kontrollen wurden über **KB5014754** eingeführt; Umgebungen sollten jetzt im *Full Enforcement* Modus sein.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in den AD CS Web Enrollment (certsrv)- und CES-Rollen. | Öffentliche PoCs sind begrenzt, aber die verwundbaren IIS-Komponenten sind oft intern erreichbar. Patch ab **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Auf **v1 templates** kann ein Anforderer mit enrollment rights **Application Policies/EKUs** in die CSR einbetten, die gegenüber den template EKUs bevorzugt werden und client-auth-, enrollment-agent- oder code-signing-Zertifikate erzeugen. | Gefixt ab **November 12, 2024**. Ersetze oder übersteuere v1 templates (z. B. das Standard- **WebServer**), beschränke EKUs auf den Zweck und limitiere enrollment rights. |

### Microsoft hardening timeline (KB5014754)

Microsoft führte einen Rollout in drei Phasen ein (Compatibility → Audit → Enforcement), um die Kerberos certificate authentication von schwachen impliziten Mappings wegzubewegen. Stand **February 11, 2025** wechseln Domain Controller automatisch zu **Full Enforcement**, wenn der Registry-Wert `StrongCertificateBindingEnforcement` nicht gesetzt ist. Microsoft hat die Timeline später so aktualisiert, dass ein Fallback in den Compatibility-Modus bis zum **September 9, 2025** Security Update weiterhin möglich bleibt. Administratoren sollten:

1. Alle DCs & AD CS servers patchen (May 2022 oder später).
2. Event ID 39/41 auf schwache Mappings während der *Audit*-Phase überwachen.
3. Client-auth-Zertifikate mit der neuen **SID extension** neu ausstellen oder starke manuelle Mappings konfigurieren, bevor Enforcement schwache Mappings blockiert.

### Operator notes for hardened forests

- **ESC1/ESC6 allein ist 2025+ Umgebungen nicht mehr die ganze Geschichte**. Wenn du ein Cert für einen anderen Principal anforderst, brauchst du meist zusätzlich ein starkes Mapping-Artefakt wie die SID extension oder ein explizites Mapping.
- **ESC15 (EKUwu)** ist hauptsächlich in ungepatchten Umgebungen wertvoll, weil es harmlose **v1** templates wie **WebServer** durch das Einschleusen von **Application Policies** in Zertifikate mit Authentifizierungs- oder Enrollment-Agent-Fähigkeiten verwandelt. Kerberos PKINIT prüft EKUs weiterhin, aber **LDAP Schannel** akzeptiert ebenfalls Application Policies, wodurch LDAP-basierter Missbrauch relevant bleibt.
- **ESC16** ist ein CA-weiter Schalter: Wenn die CA die SID-Security-Extension global deaktiviert, fällt jedes ausgestellte Zertifikat eher auf schwächeres Mapping-Verhalten zurück, außer die Angriffskette injiziert eine SID in einem anderen unterstützten Format.

---

## Detection & Hardening Enhancements

* Der **Defender for Identity AD CS sensor (2023-2024)** zeigt jetzt Posture-Assessments für ESC1-ESC8/ESC11 an und erzeugt Echtzeit-Warnungen wie *“Domain-controller certificate issuance for a non-DC”* (ESC8) und *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Stelle sicher, dass Sensoren auf allen AD CS servers bereitgestellt sind, um von diesen Erkennungen zu profitieren.
* Deaktiviere oder beschränke die Option **“Supply in the request”** auf allen templates streng; bevorzuge explizit definierte SAN/EKU-Werte.
* Entferne **Any Purpose** oder **No EKU** aus templates, sofern nicht absolut erforderlich (deckt ESC2-Szenarien ab).
* Erfordere **manager approval** oder dedizierte Enrollment-Agent-Workflows für sensible templates (z. B. WebServer / CodeSigning).
* Beschränke web enrollment (`certsrv`) und CES/NDES endpoints auf vertrauenswürdige Netzwerke oder hinter client-certificate authentication.
* Erzwinge RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), um ESC11 (RPC relay) zu mitigieren. Das Flag ist **standardmäßig aktiviert**, wird aber oft für Legacy-Clients deaktiviert, wodurch das Relay-Risiko wieder geöffnet wird.
* Sichere **IIS-basierte enrollment endpoints** (CES/Certsrv): Deaktiviere NTLM wenn möglich oder erfordere HTTPS + Extended Protection, um ESC8 relays zu blockieren.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
