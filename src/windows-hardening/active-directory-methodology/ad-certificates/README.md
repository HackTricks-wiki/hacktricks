# AD-Zertifikate

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet dessen Besitzer.
- Ein **Public Key** wird mit einem privat gehaltenen Schlüssel kombiniert, um das Zertifikat mit seinem rechtmäßigen Besitzer zu verknüpfen.
- Der **Validity Period**, definiert durch die Datumsangaben **NotBefore** und **NotAfter**, kennzeichnet den Gültigkeitszeitraum des Zertifikats.
- Eine eindeutige **Serial Number**, die von der Certificate Authority (CA) bereitgestellt wird, identifiziert jedes Zertifikat.
- Der **Issuer** bezeichnet die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Subject und erweitert dadurch die Flexibilität bei der Identifizierung.
- **Basic Constraints** geben an, ob das Zertifikat für eine CA oder eine End-Entity bestimmt ist, und definieren Nutzungsbeschränkungen.
- **Extended Key Usages (EKUs)** grenzen die spezifischen Zwecke des Zertifikats ab, beispielsweise Codesignierung oder E-Mail-Verschlüsselung, anhand von Object Identifiers (OIDs).
- Der **Signature Algorithm** gibt die Methode an, mit der das Zertifikat signiert wird.
- Die **Signature**, die mit dem privaten Schlüssel des Issuers erstellt wird, garantiert die Authentizität des Zertifikats.<sup>[[1]](#references)</sup>

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten, was für Server mit mehreren Domains entscheidend ist. Sichere Ausstellungsprozesse sind wichtig, um Identitätsvortäuschungen durch Angreifer zu verhindern, die die SAN-Spezifikation manipulieren.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einer AD-Forest anhand bestimmter Container an, die jeweils einzigartige Aufgaben erfüllen:<sup>[[1]](#references)</sup>

- Der Container **Certification Authorities** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Enrolment Services** enthält Informationen zu Enterprise-CAs und deren certificate templates.
- Das Objekt **NTAuthCertificates** enthält CA-Zertifikate, die für die AD-Authentifizierung autorisiert sind.
- Der Container **AIA (Authority Information Access)** erleichtert die Validierung der Zertifikatskette anhand von Intermediate- und Cross-CA-Zertifikaten.

### Zertifikatsbeschaffung: Ablauf einer Client-Zertifikatsanforderung

1. Der Anforderungsprozess beginnt damit, dass Clients eine Enterprise CA finden.
2. Nach der Generierung eines Public-Private-Key-Paars wird eine CSR erstellt, die einen Public Key und weitere Angaben enthält.
3. Die CA bewertet die CSR anhand der verfügbaren certificate templates und stellt das Zertifikat auf Grundlage der Berechtigungen des templates aus.
4. Nach der Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und sendet es an den Client zurück.<sup>[[1]](#references)</sup>

### Certificate Templates

Diese in AD definierten templates legen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest. Dazu gehören zulässige EKUs sowie Enrollment- oder Änderungsrechte, die für die Verwaltung des Zugriffs auf Zertifikatsdienste entscheidend sind.<sup>[[1]](#references)</sup>

## Zertifikatsregistrierung

Der Registrierungsprozess für Zertifikate wird von einem Administrator initiiert, der **ein certificate template erstellt**, das anschließend von einer Enterprise Certificate Authority (CA) **veröffentlicht** wird. Dadurch wird das template für die Client-Registrierung verfügbar. Dies wird erreicht, indem der Name des templates zum Feld `certificatetemplates` eines Active-Directory-Objekts hinzugefügt wird.<sup>[[1]](#references)</sup>

Damit ein Client ein Zertifikat anfordern kann, müssen **Enrollment-Rechte** gewährt werden. Diese Rechte werden durch Security Descriptors auf dem certificate template und der Enterprise CA definiert. Damit eine Anforderung erfolgreich ist, müssen an beiden Stellen Berechtigungen gewährt werden.<sup>[[1]](#references)</sup>

### Enrollment-Rechte des Templates

Diese Rechte werden durch Access Control Entries (ACEs) festgelegt und umfassen beispielsweise folgende Berechtigungen:<sup>[[1]](#references)</sup>

- Die Rechte **Certificate-Enrollment** und **Certificate-AutoEnrollment**, die jeweils bestimmten GUIDs zugeordnet sind.
- **ExtendedRights**, die alle erweiterten Berechtigungen ermöglichen.
- **FullControl/GenericAll**, die vollständige Kontrolle über das template gewähren.

### Enrollment-Rechte der Enterprise CA

Die Rechte der CA sind in ihrem Security Descriptor festgelegt, der über die Verwaltungskonsole der Certificate Authority aufgerufen werden kann. Einige Einstellungen ermöglichen sogar Benutzern mit geringen Berechtigungen den Remotezugriff, was ein Sicherheitsrisiko darstellen kann.<sup>[[1]](#references)</sup>

### Zusätzliche Ausgabekontrollen

Es können bestimmte Kontrollen gelten, beispielsweise:<sup>[[1]](#references)</sup>

- **Manager Approval**: Versetzt Anforderungen in einen ausstehenden Zustand, bis sie von einem Zertifikatsmanager genehmigt wurden.
- **Enrolment Agents and Authorized Signatures**: Legen die Anzahl der erforderlichen Signaturen für eine CSR sowie die notwendigen Application Policy OIDs fest.

### Methoden zum Anfordern von Zertifikaten

Zertifikate können über folgende Wege angefordert werden:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE) unter Verwendung von DCOM-Schnittstellen.
2. **ICertPassage Remote Protocol** (MS-ICPR) über Named Pipes oder TCP/IP.
3. Die **certificate enrollment web interface**, wenn die Certificate Authority Web Enrollment-Rolle installiert ist.
4. Der **Certificate Enrollment Service** (CES) zusammen mit dem Certificate Enrollment Policy (CEP)-Dienst.
5. Der **Network Device Enrollment Service** (NDES) für Netzwerkgeräte unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder über Kommandozeilentools (`certreq.exe` oder PowerShells Befehl `Get-Certificate`) anfordern.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatsauthentifizierung

Active Directory (AD) unterstützt die Zertifikatsauthentifizierung und verwendet dabei hauptsächlich die Protokolle **Kerberos** und **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Kerberos-Authentifizierungsprozess

Beim Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers nach einem Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage wird vom Domain Controller mehreren Prüfungen unterzogen, darunter der **Gültigkeit**, dem **Pfad** und dem **Widerrufsstatus** des Zertifikats. Zu den Prüfungen gehören außerdem die Verifizierung, dass das Zertifikat aus einer vertrauenswürdigen Quelle stammt, sowie die Bestätigung, dass der Aussteller im **NTAUTH certificate store** vorhanden ist. Erfolgreiche Prüfungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD befindet sich unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für die Herstellung von Vertrauen bei der Zertifikatauthentifizierung.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel)-Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen. Während eines Handshakes präsentiert der Client ein Zertifikat, das bei erfolgreicher Validierung den Zugriff autorisiert.<sup>[[2]](#references)</sup> Die Zuordnung eines Zertifikats zu einem AD-Konto kann unter anderem über die **S4U2Self**-Funktion von Kerberos oder den **Subject Alternative Name (SAN)** des Zertifikats erfolgen.<sup>[[1]](#references)</sup>

### Aufzählung der AD Certificate Services

Die Certificate Services von AD können über LDAP-Abfragen aufgezählt werden, wodurch Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offengelegt werden. Dies ist für jeden domänenauthentifizierten Benutzer ohne besondere Berechtigungen zugänglich.<sup>[[1]](#references)</sup> Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Aufzählung und Schwachstellenbewertung in AD-CS-Umgebungen verwendet.<sup>[[3]](#references)</sup>

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
## Referenzen

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [What Is SSL/TLS Client Authentication & How Does It Work?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
