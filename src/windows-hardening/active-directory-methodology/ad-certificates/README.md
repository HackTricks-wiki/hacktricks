# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

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

### Posebne napomene

- **Subject Alternative Names (SANs)** proširuju primenjivost sertifikata na više identiteta, što je ključno za servere sa više domena. Sigurni procesi izdavanja su neophodni da bi se izbegao rizik od lažiranja kroz manipulaciju specifikacije SAN-a.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS prepoznaje CA sertifikate u AD forestu kroz određene kontejnere, od kojih svaki ima svoju ulogu:

- **Certification Authorities** container holds trusted root CA certificates.
- **Enrolment Services** container details Enterprise CAs and their certificate templates.
- **NTAuthCertificates** object includes CA certificates authorized for AD authentication.
- **AIA (Authority Information Access)** container facilitates certificate chain validation with intermediate and cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. Proces zahteva počinje tako što klijenti pronalaze Enterprise CA.
2. Kreira se CSR koji sadrži public key i ostale podatke nakon generisanja para ključeva (public/private).
3. CA procenjuje CSR u odnosu na dostupne certificate templates i izdaje sertifikat bazirano na dozvolama iz template-a.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.

### Certificate Templates

Definisani u AD-u, ovi template-i opisuju podešavanja i permisije za izdavanje sertifikata, uključujući dozvoljene EKU-e i prava za enrollment ili izmenu — što je ključno za kontrolu pristupa servisima za izdavanje sertifikata.

## Certificate Enrollment

Proces enrolementa sertifikata pokreće administrator koji **kreira certificate template**, a zatim ga **publikuje** na Enterprise Certificate Authority (CA). Time template postaje dostupan za enrolement klijenata, što se postiže dodavanjem imena template-a u `certificatetemplates` polje Active Directory objekta.

Da bi klijent mogao da zahteva sertifikat, mora mu biti dodeljeno **enrollment rights**. Ta prava su definisana kroz security descriptor-e na certificate template-u i na samom Enterprise CA. Dozvole moraju biti dodeljene na oba mesta da bi zahtev bio uspešan.

### Template Enrollment Rights

Ova prava se specifišu kroz Access Control Entries (ACEs) i opisuju dozvole kao što su:

- **Certificate-Enrollment** i **Certificate-AutoEnrollment** rights, svaki povezan sa specifičnim GUID-ovima.
- **ExtendedRights**, omogućavajući sve proširene dozvole.
- **FullControl/GenericAll**, dajući potpuni kontrolu nad template-om.

### Enterprise CA Enrollment Rights

Prava CA-e su definisana u njenom security descriptor-u, koji je dostupan preko Certificate Authority konzole za upravljanje. Neka podešavanja čak mogu omogućiti udaljeni pristup korisnicima sa niskim privilegijama, što predstavlja sigurnosni rizik.

### Dodatne kontrole izdavanja

Neke kontrole koje se mogu primeniti uključuju:

- **Manager Approval**: stavlja zahteve u pending stanje dok ne budu odobreni od strane certificate manager-a.
- **Enrolment Agents and Authorized Signatures**: specificiraju broj potrebnih potpisa na CSR-u i neophodne Application Policy OID-e.

### Methods to Request Certificates

Sertifikati se mogu zahtevati putem:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), koristeći DCOM interfejse.
2. **ICertPassage Remote Protocol** (MS-ICPR), preko named pipes ili TCP/IP.
3. The **certificate enrollment web interface**, with the Certificate Authority Web Enrollment role installed.
4. The **Certificate Enrollment Service** (CES), in conjunction with the Certificate Enrollment Policy (CEP) service.
5. The **Network Device Enrollment Service** (NDES) for network devices, using the Simple Certificate Enrollment Protocol (SCEP).

Windows korisnici takođe mogu zahtevati sertifikate preko GUI-a (`certmgr.msc` ili `certlm.msc`) ili komandnih alata (`certreq.exe` ili PowerShell's `Get-Certificate` command).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autentifikacija sertifikatom

Active Directory (AD) podržava autentifikaciju sertifikatom, uglavnom koristeći **Kerberos** i **Secure Channel (Schannel)** protokole.

### Kerberos autentifikacioni proces

U Kerberos autentifikacionom procesu, zahtev korisnika za Ticket Granting Ticket (TGT) potpisuje se pomoću **private key** korisnikovog sertifikata. Ovaj zahtev prolazi kroz više provera od strane domain controller-a, uključujući **validnost**, **putanju** i **status opoziva** sertifikata. Provere takođe uključuju potvrđivanje da sertifikat potiče iz pouzdanog izvora i potvrdu prisustva izdavaoca u **NTAUTH certificate store**. Uspešne provere rezultiraju izdavanjem TGT-a. Objekat **`NTAuthCertificates`** u AD-u, koji se nalazi na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je ključno za uspostavljanje poverenja pri autentifikaciji pomoću sertifikata.

### Secure Channel (Schannel) autentifikacija

Schannel omogućava sigurne TLS/SSL veze, gde klijent tokom handshake-a predstavlja sertifikat koji, ako je uspešno verifikovan, odobrava pristup. Mapiranje sertifikata na AD nalog može uključivati Kerberos-ovu funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, između ostalih metoda.

### Enumeracija AD Certificate Services

AD Certificate Services mogu se enumerisati putem LDAP upita, otkrivajući informacije o **Enterprise Certificate Authorities (CAs)** i njihovim konfiguracijama. Ovo je dostupno bilo kom korisniku autentifikovanom u domenu bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeraciju i procenu ranjivosti u AD CS okruženjima.

Komande za korišćenje ovih alata uključuju:
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
## Izvori

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
