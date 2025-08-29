# AD Sertifikati

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

- The **Subject** sertifikata označava njegovog vlasnika.
- A **Public Key** je u paru sa privatnim ključem kako bi povezao sertifikat sa njegovim zakonitim vlasnikom.
- The **Validity Period**, definisan putem datuma **NotBefore** i **NotAfter**, označava važeći period sertifikata.
- Jedinstveni **Serial Number**, koji obezbeđuje Certificate Authority (CA), identifikuje svaki sertifikat.
- The **Issuer** označava CA koja je izdala sertifikat.
- **SubjectAlternativeName** omogućava dodatna imena za subject, povećavajući fleksibilnost identifikacije.
- **Basic Constraints** identifikuju da li je sertifikat za CA ili krajnji entitet i definišu ograničenja upotrebe.
- **Extended Key Usages (EKUs)** određuju specifične namene sertifikata, kao što su code signing ili email encryption, pomoću Object Identifiers (OIDs).
- The **Signature Algorithm** specificira metod za potpisivanje sertifikata.
- The **Signature**, kreirana privatnim ključem izdavaoca, garantuje autentičnost sertifikata.

### Posebne napomene

- **Subject Alternative Names (SANs)** proširuju primenjivost sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni procesi izdavanja su vitalni da bi se izbegli rizici impersonacije ako napadači manipulišu specifikacijom SAN-a.

### Certificate Authorities (CAs) u Active Directory (AD)

AD CS prepoznaje CA sertifikate u AD forestu kroz određene kontejnere, od kojih svaki ima jedinstvenu ulogu:

- **Certification Authorities** kontejner sadrži poverene root CA sertifikate.
- **Enrolment Services** kontejner sadrži informacije o Enterprise CA i njihovim certificate templates.
- **NTAuthCertificates** objekat uključuje CA sertifikate ovlašćene za AD autentikaciju.
- **AIA (Authority Information Access)** kontejner olakšava validaciju lanca sertifikata pomoću posredničkih (intermediate) i cross-CA sertifikata.

### Nabavka sertifikata: Tok zahteva klijenta za sertifikat

1. Proces započinje kada klijenti pronađu Enterprise CA.
2. CSR se kreira i sadrži public key i ostale podatke, nakon generisanja para public-private ključeva.
3. CA procenjuje CSR u odnosu na dostupne certificate templates i izdaje sertifikat na osnovu permisija definisanih šablonom.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.

### Certificate Templates

Definisani u AD, ovi šabloni navode podešavanja i dozvole za izdavanje sertifikata, uključujući dozvoljene EKU-ove i prava za enrolovanje ili izmene, što je kritično za upravljanje pristupom servisima za sertifikate.

## Enrolovanje sertifikata

Proces enrolovanja sertifikata pokreće administrator koji **kreira šablon sertifikata**, koji potom **objavljuje** Enterprise Certificate Authority (CA). Time je šablon dostupan za enrolovanje klijenata, što se postiže dodavanjem imena šablona u polje `certificatetemplates` objekta u Active Directory.

Da bi klijent mogao da zatraži sertifikat, moraju mu biti dodeljena **prava za enrolovanje**. Ta prava su definisana kroz security descriptor-e na šablonu sertifikata i na samom Enterprise CA. Dozvole moraju biti dodeljene na oba mesta da bi zahtev bio uspešan.

### Prava za enrolovanje šablona

Ova prava su specificirana kroz Access Control Entries (ACEs), i detalji dozvola uključuju, na primer:

- **Certificate-Enrollment** i **Certificate-AutoEnrollment** prava, svako povezano sa specifičnim GUID-ovima.
- **ExtendedRights**, dozvoljavajući sve extended permisije.
- **FullControl/GenericAll**, pružajući potpunu kontrolu nad šablonom.

### Prava za enrolovanje na Enterprise CA

Prava CA su navedena u njegovom security descriptor-u, dostupnom preko Certificate Authority management konzole. Neka podešavanja čak omogućavaju udaljeni pristup korisnicima sa niskim privilegijama, što može predstavljati sigurnosni rizik.

### Dodatne kontrole izdavanja

Mogu važiti određene kontrole, kao što su:

- **Manager Approval**: Stavlja zahteve u pending stanje dok ih ne odobri menadžer za sertifikate.
- **Enrolment Agents and Authorized Signatures**: Specifikuju broj potrebnih potpisa na CSR-u i neophodne Application Policy OID-ove.

### Metode za zahtevanje sertifikata

Sertifikati se mogu tražiti putem:

1. Windows Client Certificate Enrollment Protocol (MS-WCCE), korišćenjem DCOM interfejsa.
2. ICertPassage Remote Protocol (MS-ICPR), preko named pipes ili TCP/IP.
3. certificate enrollment web interface, uz instaliranu Certificate Authority Web Enrollment ulogu.
4. Certificate Enrollment Service (CES), u saradnji sa Certificate Enrollment Policy (CEP) servisom.
5. Network Device Enrollment Service (NDES) za mrežne uređaje, koristeći Simple Certificate Enrollment Protocol (SCEP).

Korisnici na Windows-u mogu takođe zahtevati sertifikate preko GUI-ja (`certmgr.msc` ili `certlm.msc`) ili alata iz komandne linije (`certreq.exe` ili PowerShell komande `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) podržava autentifikaciju pomoću sertifikata, prvenstveno koristeći protokole **Kerberos** i **Secure Channel (Schannel)**.

### Kerberos Authentication Process

U Kerberos procesu autentifikacije, zahtev korisnika za Ticket Granting Ticket (TGT) se potpisuje koristeći **privatni ključ** korisnikovog sertifikata. Ovaj zahtev prolazi kroz nekoliko provera od strane kontrolera domena, uključujući **validnost**, **putanju** i **status opoziva** sertifikata. Provere takođe uključuju verifikaciju da sertifikat potiče iz poverenog izvora i potvrdu prisustva izdavaoca u **NTAUTH skladištu sertifikata**. Uspešne provere rezultuju izdavanjem TGT-a. Objekat **`NTAuthCertificates`** u AD, koji se nalazi na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je centralno za uspostavljanje poverenja za autentifikaciju sertifikatom.

### Secure Channel (Schannel) Authentication

Schannel omogućava sigurne TLS/SSL veze, gde tokom handshake-a klijent predstavlja sertifikat koji, ako je uspešno verifikovan, ovlašćuje pristup. Mapiranje sertifikata na AD nalog može uključivati Kerberosovu funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, između ostalih metoda.

### AD Certificate Services Enumeration

AD-ove usluge sertifikata mogu se enumerisati kroz LDAP upite, otkrivajući informacije o **Enterprise Certificate Authorities (CAs)** i njihovim konfiguracijama. Ovo je dostupno svakom korisniku autentifikovanom u domenu bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeraciju i procenu ranjivosti u AD CS okruženjima.

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
