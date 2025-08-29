# AD-Zertifikate

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

### Bestandteile eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet seinen Inhaber.
- Ein **Public Key** ist mit einem privat gehaltenen Schlüssel gepaart, um das Zertifikat seinem rechtmäßigen Inhaber zuzuordnen.
- Die **Validity Period**, definiert durch die **NotBefore**- und **NotAfter**-Daten, gibt die Gültigkeitsdauer des Zertifikats an.
- Eine eindeutige **Serial Number**, von der Certificate Authority (CA) vergeben, identifiziert jedes Zertifikat.
- Der **Issuer** ist die CA, die das Zertifikat ausgestellt hat.
- Die **SubjectAlternativeName** erlaubt zusätzliche Namen für den Subject und erhöht die Flexibilität bei der Identifikation.
- Die **Basic Constraints** geben an, ob das Zertifikat für eine CA oder für ein End Entity bestimmt ist, und definieren Nutzungsbeschränkungen.
- Die **Extended Key Usages (EKUs)** legen die spezifischen Zwecke des Zertifikats fest, z. B. Code-Signing oder E-Mail-Verschlüsselung, über Object Identifiers (OIDs).
- Der **Signature Algorithm** legt die Methode zum Signieren des Zertifikats fest.
- Die **Signature**, mit dem privaten Schlüssel des Issuers erstellt, garantiert die Authentizität des Zertifikats.

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten und sind besonders wichtig für Server mit mehreren Domains. Sichere Ausstellungsprozesse sind entscheidend, um Risiken der Identitätsvortäuschung zu vermeiden, etwa durch Angreifer, die die SAN-Spezifikation manipulieren.

### Zertifizierungsstellen (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einem AD-Forest durch bestimmte Container an, die jeweils unterschiedliche Rollen erfüllen:

- Der Container **Certification Authorities** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Enrolment Services** enthält Informationen zu Enterprise CAs und deren Zertifikatvorlagen.
- Das Objekt **NTAuthCertificates** enthält CA-Zertifikate, die für AD-Authentifizierung autorisiert sind.
- Der **AIA (Authority Information Access)** Container erleichtert die Validierung der Zertifikatskette mit Zwischen- und Cross-CA-Zertifikaten.

### Zertifikatserwerb: Ablauf einer Client-Zertifikatsanfrage

1. Der Anforderungsprozess beginnt damit, dass Clients eine Enterprise CA finden.
2. Ein CSR wird erstellt, der nach Generierung eines Public-/Private-Key-Paares einen Public Key und weitere Details enthält.
3. Die CA bewertet den CSR anhand verfügbarer Zertifikatvorlagen und stellt das Zertifikat basierend auf den Berechtigungen der Vorlage aus.
4. Nach Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und gibt es an den Client zurück.

### Zertifikatvorlagen

In AD definierte Vorlagen legen Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest, einschließlich erlaubter EKUs und Enrollment- oder Änderungsrechte, und sind entscheidend für die Verwaltung des Zugriffs auf Zertifikatdienste.

## Zertifikats-Enrollment

Der Enrollment-Prozess wird von einem Administrator initiiert, der eine **Zertifikatvorlage erstellt**, die dann von einer Enterprise Certificate Authority (CA) **publiziert** wird. Dadurch wird die Vorlage für Client-Enrollment verfügbar, ein Schritt, der erreicht wird, indem der Name der Vorlage dem Feld `certificatetemplates` eines Active Directory-Objekts hinzugefügt wird.

Damit ein Client ein Zertifikat anfordern kann, müssen **enrollment rights** gewährt werden. Diese Rechte werden durch Sicherheitsdeskriptoren sowohl auf der Zertifikatvorlage als auch auf der Enterprise CA selbst definiert. Berechtigungen müssen an beiden Stellen vergeben sein, damit eine Anfrage erfolgreich ist.

### Enrollment-Berechtigungen der Vorlage

Diese Rechte werden durch Access Control Entries (ACEs) festgelegt und beschreiben Berechtigungen wie:

- **Certificate-Enrollment** und **Certificate-AutoEnrollment** Rechte, jeweils mit bestimmten GUIDs verknüpft.
- **ExtendedRights**, die alle erweiterten Berechtigungen erlauben.
- **FullControl/GenericAll**, die vollständige Kontrolle über die Vorlage gewähren.

### Enterprise-CA Enrollment-Berechtigungen

Die Rechte der CA sind in ihrem Sicherheitsdeskriptor festgelegt und über die Certificate Authority Management-Konsole zugänglich. Einige Einstellungen erlauben sogar niedrig privilegierten Benutzern Remote-Zugriff, was ein Sicherheitsrisiko darstellen kann.

### Zusätzliche Ausstellungssteuerungen

Bestimmte Kontrollen können angewendet werden, z. B.:

- **Manager Approval**: Setzt Anfragen in einen ausstehenden Zustand, bis sie von einem Certificate Manager genehmigt werden.
- **Enrolment Agents and Authorized Signatures**: Legen die Anzahl erforderlicher Signaturen auf einem CSR und die notwendigen Application Policy OIDs fest.

### Methoden zum Anfordern von Zertifikaten

Zertifikate können angefordert werden über:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), über DCOM-Schnittstellen.
2. **ICertPassage Remote Protocol** (MS-ICPR), über Named Pipes oder TCP/IP.
3. Die **certificate enrollment web interface**, wenn die Certificate Authority Web Enrollment-Rolle installiert ist.
4. Den **Certificate Enrollment Service** (CES), in Verbindung mit dem Certificate Enrollment Policy (CEP)-Dienst.
5. Den **Network Device Enrollment Service** (NDES) für Netzwerkgeräte, unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder über Kommandozeilentools (`certreq.exe` oder PowerShells `Get-Certificate`-Befehl) anfordern.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatsauthentifizierung

Active Directory (AD) unterstützt Zertifikatsauthentifizierung und verwendet primär die Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers für ein Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage unterliegt mehreren Prüfungen durch den Domain Controller, einschließlich der **Gültigkeit**, des **Zertifikatspfads** und des **Widerrufsstatus** des Zertifikats. Zu den Prüfungen gehört auch die Überprüfung, dass das Zertifikat von einer vertrauenswürdigen Quelle stammt, sowie die Bestätigung, dass der Aussteller im **NTAUTH Zertifikatspeicher** vorhanden ist. Erfolgreiche Prüfungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD, zu finden unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für den Aufbau von Vertrauen bei der Zertifikatsauthentifizierung.

### Secure Channel (Schannel) Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen, bei denen der Client während des Handshakes ein Zertifikat präsentiert, das bei erfolgreicher Validierung Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann Kerberos’ **S4U2Self**-Funktion oder den Zertifikats-**Subject Alternative Name (SAN)** sowie andere Methoden involvieren.

### AD Certificate Services Enumeration

Die Certificate Services von AD können durch LDAP-Abfragen enumerated werden und liefern Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen. Dies ist für jeden domänenauthentifizierten Benutzer ohne besondere Privilegien zugänglich. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden für enumeration und vulnerability assessment in AD CS-Umgebungen verwendet.

Befehle zur Verwendung dieser Tools umfassen:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Referenzen

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
