# AD-Zertifikate

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet dessen Besitzer.
- Ein **Public Key** wird mit einem privat gehaltenen Schlüssel verknüpft, um das Zertifikat seinem rechtmäßigen Besitzer zuzuordnen.
- Der **Validity Period**, definiert durch die Daten **NotBefore** und **NotAfter**, kennzeichnet den Gültigkeitszeitraum des Zertifikats.
- Eine eindeutige **Serial Number**, die von der Certificate Authority (CA) bereitgestellt wird, identifiziert jedes Zertifikat.
- Der **Issuer** bezeichnet die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Subject und erhöht dadurch die Flexibilität bei der Identifizierung.
- **Basic Constraints** geben an, ob das Zertifikat für eine CA oder eine Endentität bestimmt ist, und definieren Nutzungsbeschränkungen.
- **Extended Key Usages (EKUs)** legen über Object Identifiers (OIDs) die spezifischen Zwecke des Zertifikats fest, beispielsweise Code Signing oder E-Mail-Verschlüsselung.
- Der **Signature Algorithm** gibt die Methode zum Signieren des Zertifikats an.
- Die **Signature**, die mit dem privaten Schlüssel des Issuers erstellt wird, garantiert die Authentizität des Zertifikats.<sup>[[1]](#references)</sup>

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten, was für Server mit mehreren Domains entscheidend ist. Sichere Ausstellungsprozesse sind unerlässlich, um Impersonation-Risiken durch Angreifer zu vermeiden, die die SAN-Spezifikation manipulieren.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einer AD-Forest über dafür vorgesehene Container, die jeweils spezielle Aufgaben erfüllen:<sup>[[1]](#references)</sup>

- Der Container **Certification Authorities** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Enrolment Services** enthält Informationen zu Enterprise-CAs und deren Certificate Templates.
- Das Objekt **NTAuthCertificates** enthält CA-Zertifikate, die für die AD-Authentifizierung autorisiert sind.
- Der Container **AIA (Authority Information Access)** erleichtert die Validierung der Zertifikatskette mit Intermediate- und Cross-CA-Zertifikaten.

### Zertifikatserwerb: Client Certificate Request Flow

1. Der Anfrageprozess beginnt damit, dass Clients eine Enterprise-CA finden.
2. Nach der Generierung eines Public-Private-Key-Paares wird ein CSR erstellt, der einen Public Key und weitere Informationen enthält.
3. Die CA bewertet den CSR anhand der verfügbaren Certificate Templates und stellt das Zertifikat auf Grundlage der Berechtigungen des Templates aus.
4. Nach der Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und sendet es an den Client zurück.<sup>[[1]](#references)</sup>

### Certificate Templates

Diese in AD definierten Templates legen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest, einschließlich der zulässigen EKUs sowie der Rechte zur Registrierung oder Änderung. Sie sind entscheidend für die Verwaltung des Zugriffs auf Certificate Services.<sup>[[1]](#references)</sup>

## Zertifikatsregistrierung

Der Registrierungsprozess für Zertifikate wird von einem Administrator eingeleitet, der **ein Certificate Template erstellt**, das anschließend von einer Enterprise Certificate Authority (CA) **veröffentlicht** wird. Dadurch wird das Template für die Client-Registrierung verfügbar. Dies wird erreicht, indem der Name des Templates zum Feld `certificatetemplates` eines Active-Directory-Objekts hinzugefügt wird.<sup>[[1]](#references)</sup>

Damit ein Client ein Zertifikat anfordern kann, müssen **Registrierungsrechte** gewährt werden. Diese Rechte werden durch Security Descriptors auf dem Certificate Template und der Enterprise-CA definiert. Damit eine Anfrage erfolgreich ist, müssen an beiden Stellen Berechtigungen gewährt werden.<sup>[[1]](#references)</sup>

### Registrierungsrechte des Templates

Diese Rechte werden durch Access Control Entries (ACEs) festgelegt und definieren unter anderem folgende Berechtigungen:<sup>[[1]](#references)</sup>

- Die Rechte **Certificate-Enrollment** und **Certificate-AutoEnrollment**, die jeweils bestimmten GUIDs zugeordnet sind.
- **ExtendedRights**, die alle erweiterten Berechtigungen erlauben.
- **FullControl/GenericAll**, die vollständige Kontrolle über das Template gewähren.

### Registrierungsrechte der Enterprise-CA

Die Rechte der CA sind in ihrem Security Descriptor festgelegt, der über die Certificate Authority Management Console zugänglich ist. Einige Einstellungen erlauben sogar Benutzern mit geringen Berechtigungen den Remotezugriff, was ein Sicherheitsrisiko darstellen kann.<sup>[[1]](#references)</sup>

### Zusätzliche Ausgabekontrollen

Es können bestimmte Kontrollen gelten, beispielsweise:<sup>[[1]](#references)</sup>

- **Manager Approval**: Versetzt Anfragen in einen ausstehenden Status, bis sie von einem Certificate Manager genehmigt wurden.
- **Enrolment Agents and Authorized Signatures**: Legen die Anzahl der erforderlichen Signaturen für einen CSR sowie die notwendigen Application Policy OIDs fest.

### Methoden zum Anfordern von Zertifikaten

Zertifikate können über folgende Wege angefordert werden:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE) unter Verwendung von DCOM-Schnittstellen.
2. **ICertPassage Remote Protocol** (MS-ICPR) über Named Pipes oder TCP/IP.
3. Die **Certificate Enrollment Web Interface**, wenn die Rolle Certificate Authority Web Enrollment installiert ist.
4. Der **Certificate Enrollment Service** (CES) in Verbindung mit dem Dienst Certificate Enrollment Policy (CEP).
5. Der **Network Device Enrollment Service** (NDES) für Netzwerkgeräte unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder über Command-Line-Tools (`certreq.exe` oder den PowerShell-Befehl `Get-Certificate`) anfordern.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatsauthentifizierung

Active Directory (AD) unterstützt die Zertifikatsauthentifizierung und verwendet dabei hauptsächlich die Protokolle **Kerberos** und **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers nach einem Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage wird vom Domain Controller mehreren Prüfungen unterzogen, darunter der **Gültigkeit**, dem **Pfad** und dem **Widerrufsstatus** des Zertifikats. Zu den Prüfungen gehören außerdem die Verifizierung, dass das Zertifikat aus einer vertrauenswürdigen Quelle stammt, sowie die Bestätigung, dass der Aussteller im **NTAUTH certificate store** vorhanden ist. Erfolgreiche Prüfungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD befindet sich unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für die Herstellung von Vertrauen bei der Zertifikatsauthentifizierung.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel)-Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen. Während eines Handshakes präsentiert der Client ein Zertifikat, das bei erfolgreicher Validierung den Zugriff autorisiert.<sup>[[2]](#references)</sup> Die Zuordnung eines Zertifikats zu einem AD-Konto kann unter anderem über die **S4U2Self**-Funktion von Kerberos oder den **Subject Alternative Name (SAN)** des Zertifikats erfolgen.<sup>[[1]](#references)</sup>

### Enumeration der AD Certificate Services

Die Certificate Services von AD können über LDAP-Abfragen enumeriert werden, wodurch Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offengelegt werden. Darauf kann jeder domänenauthentifizierte Benutzer ohne besondere Berechtigungen zugreifen.<sup>[[1]](#references)</sup> Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden für Enumeration und Vulnerability Assessment in AD CS-Umgebungen verwendet.<sup>[[3]](#references)</sup>

Zu den Befehlen für die Verwendung dieser Tools gehören:
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
Rubeus kann auch ein passwortgeschütztes PFX-Zertifikat für die PKINIT-Authentifizierung verwenden und ein TGT anfordern. Der optionale Schalter `/getcredentials` fordert ein U2U-Service-Ticket an und versucht, den NT-Hash des Kontos wiederherzustellen:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Missbrauch der Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Was ist SSL/TLS-Client-Authentifizierung und wie funktioniert sie?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
