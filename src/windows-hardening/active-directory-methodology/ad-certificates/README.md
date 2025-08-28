# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- The **Subject** of the certificate denotes its owner.
- A **Public Key** is paired with a privately held key to link the certificate to its rightful owner.
- The **Validity Period**, defined by **NotBefore** and **NotAfter** dates, marks the certificate's effective duration.
- A unique **Serial Number**, provided by the Certificate Authority (CA), identifies each certificate.
- The **Issuer** refers to the CA that has issued the certificate.
- **SubjectAlternativeName** allows for additional names for the subject, enhancing identification flexibility.
- **Basic Constraints** identify if the certificate is for a CA or an end entity and define usage restrictions.
- **Extended Key Usages (EKUs)** delineate the certificate's specific purposes, like code signing or email encryption, through Object Identifiers (OIDs).
- The **Signature Algorithm** specifies the method for signing the certificate.
- The **Signature**, created with the issuer's private key, guarantees the certificate's authenticity.

### Special Considerations

- **Subject Alternative Names (SANs)** expand a certificate's applicability to multiple identities, crucial for servers with multiple domains. Secure issuance processes are vital to avoid impersonation risks by attackers manipulating the SAN specification.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS acknowledges CA certificates in an AD forest through designated containers, each serving unique roles:

- **Certification Authorities** container holds trusted root CA certificates.
- **Enrolment Services** container details Enterprise CAs and their certificate templates.
- **NTAuthCertificates** object includes CA certificates authorized for AD authentication.
- **AIA (Authority Information Access)** container facilitates certificate chain validation with intermediate and cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. The request process begins with clients finding an Enterprise CA.
2. A CSR is created, containing a public key and other details, after generating a public-private key pair.
3. The CA assesses the CSR against available certificate templates, issuing the certificate based on the template's permissions.
4. Upon approval, the CA signs the certificate with its private key and returns it to the client.

### Certificate Templates

Defined within AD, these templates outline the settings and permissions for issuing certificates, including permitted EKUs and enrollment or modification rights, critical for managing access to certificate services.

## Certificate Enrollment

Der Enrollment-Prozess für Zertifikate wird von einem Administrator initiiert, der eine **certificate template** erstellt, welche anschließend von einer Enterprise Certificate Authority (CA) **veröffentlicht** wird. Dadurch wird die Vorlage für die Client-Enrollments verfügbar, ein Schritt, der erreicht wird, indem der Name der Vorlage zum `certificatetemplates` Feld eines Active Directory-Objekts hinzugefügt wird.

Damit ein Client ein Zertifikat anfordern kann, müssen ihm **Enrollment-Rechte** gewährt werden. Diese Rechte werden durch Security Descriptors auf der certificate template und auf der Enterprise CA selbst definiert. Berechtigungen müssen an beiden Stellen gesetzt sein, damit eine Anfrage erfolgreich ist.

### Template Enrollment Rights

Diese Rechte werden über Access Control Entries (ACEs) spezifiziert und beschreiben Berechtigungen wie:

- **Certificate-Enrollment** und **Certificate-AutoEnrollment** Rechte, jeweils verknüpft mit spezifischen GUIDs.
- **ExtendedRights**, die alle erweiterten Berechtigungen zulassen.
- **FullControl/GenericAll**, die vollständige Kontrolle über die Vorlage gewähren.

### Enterprise CA Enrollment Rights

Die Rechte der CA sind im Security Descriptor der CA beschrieben, der über die Certificate Authority Management-Konsole zugänglich ist. Einige Einstellungen erlauben sogar Low-Privileged Usern Remote-Zugriff, was ein Sicherheitsrisiko darstellen kann.

### Additional Issuance Controls

Bestimmte Kontrollen können angewendet werden, wie z. B.:

- **Manager Approval**: Platziert Anfragen in einem Pending-Zustand, bis ein Certificate Manager diese genehmigt.
- **Enrolment Agents and Authorized Signatures**: Legen die Anzahl erforderlicher Signaturen auf einer CSR und die nötigen Application Policy OIDs fest.

### Methods to Request Certificates

Zertifikate können angefordert werden über:

1. Das **Windows Client Certificate Enrollment Protocol** (MS-WCCE), unter Verwendung von DCOM-Interfaces.
2. Das **ICertPassage Remote Protocol** (MS-ICPR), über Named Pipes oder TCP/IP.
3. Die **certificate enrollment web interface**, wenn die Certificate Authority Web Enrollment Rolle installiert ist.
4. Den **Certificate Enrollment Service** (CES), in Verbindung mit dem Certificate Enrollment Policy (CEP) Service.
5. Den **Network Device Enrollment Service** (NDES) für Netzwerkgeräte, unter Nutzung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate außerdem über die GUI (`certmgr.msc` oder `certlm.msc`) oder über Kommandozeilentools (`certreq.exe` oder PowerShells `Get-Certificate`-Befehl) anfordern.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikat-Authentifizierung

Active Directory (AD) unterstützt die Zertifikat-Authentifizierung und verwendet hauptsächlich die Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers für ein Ticket Granting Ticket (TGT) mit dem **private key** des Benutzerzertifikats signiert. Diese Anfrage durchläuft beim Domain Controller mehrere Prüfungen, darunter die **Gültigkeit**, der **Pfad** und der **Widerrufsstatus** des Zertifikats. Zu den Prüfungen gehört außerdem die Überprüfung, dass das Zertifikat aus einer vertrauenswürdigen Quelle stammt und die Bestätigung, dass der Aussteller im **NTAUTH certificate store** vorhanden ist. Erfolgreiche Prüfungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD, zu finden unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für den Aufbau von Vertrauen bei der Zertifikatsauthentifizierung.

### Secure Channel (Schannel) Authentifizierung

Schannel erleichtert sichere TLS/SSL-Verbindungen, bei denen während eines Handshakes der Client ein Zertifikat präsentiert, das, wenn es erfolgreich validiert wird, den Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann Kerberos’ **S4U2Self**-Funktion oder den **Subject Alternative Name (SAN)** des Zertifikats umfassen, neben anderen Methoden.

### AD Certificate Services Enumeration

Die Zertifikatdienste von AD können über LDAP-Abfragen enumeriert werden, wodurch Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offenbart werden. Dies ist für jeden domänen-authentifizierten Benutzer ohne besondere Berechtigungen zugänglich. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Enumeration und Schwachstellenbewertung in AD CS-Umgebungen verwendet.

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
