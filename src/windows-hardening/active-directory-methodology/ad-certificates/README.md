# AD Sertifikate

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar aan.
- 'n **Public Key** word gepaard met 'n privaat gehoude sleutel om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Validity Period**, bepaal deur **NotBefore** en **NotAfter** datums, merk die sertifikaat se geldigheidsduur.
- 'n unieke **Serial Number**, verskaf deur die Certificate Authority (CA), identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat addisionele name vir die subject toe, wat identifikasie meer buigsaam maak.
- **Basic Constraints** identifiseer of die sertifikaat vir 'n CA of 'n eindentiteit is en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** omskryf die sertifikaat se spesifieke doeleindes, soos code signing of email encryption, deur Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode vir die ondertekening van die sertifikaat.
- Die **Signature**, geskep met die issuer se private sleutel, waarborg die sertifikaat se egtheid.

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid uit na meerdere identiteite, noodsaaklik vir bedieners met meerdere domeine. Veilige uitreikprosesse is van kardinale belang om te voorkom dat 'n aanvaller die SAN-spesifikasie manipuleer en impersonasie doen.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD-bos deur aangewese houers, elk met unieke rolle:

- **Certification Authorities** container hou vertroude root CA-sertifikate.
- **Enrolment Services** container bevat besonderhede oor Enterprise CAs en hul sertifikaatsjablone.
- **NTAuthCertificates** objek sluit CA-sertifikate in wat gemagtig is vir AD-authentication.
- **AIA (Authority Information Access)** container fasiliteer sertifikaatkettingvalidasie met intermediate en cross CA-sertifikate.

### Sertifikaatverkryging: Kliënt Sertifikaataanvraagvloei

1. Die proses begin met kliënte wat 'n Enterprise CA vind.
2. 'n CSR word geskep, wat 'n public key en ander besonderhede bevat, nadat 'n public-private sleutelpaar gegenereer is.
3. Die CA beoordeel die CSR teen beskikbare sertifikaatsjablone en keur die sertifikaat uit op grond van die sjabloon se toestemmings.
4. Na goedkeuring teken die CA die sertifikaat met sy private sleutel en stuur dit terug aan die kliënt.

### Sertifikaatsjablone

Gedefinieer binne AD, beskryf hierdie sjablone die instellings en regte vir die uitreiking van sertifikate, insluitend toegelate EKUs en inskrywings- of wysigingsregte, krities vir die bestuur van toegang tot sertifikaatdienste.

## Sertifikaatinskrywing

Die inskrywingsproses vir sertifikate word geïnisieer deur 'n administrateur wat 'n sertifikaatsjabloon skep, wat dan deur 'n Enterprise Certificate Authority (CA) gepubliseer word. Dit maak die sjabloon beskikbaar vir kliëntinskrywing, 'n stap wat bereik word deur die sjabloonnaam by die `certificatetemplates` veld van 'n Active Directory-objek te voeg.

Vir 'n kliënt om 'n sertifikaat aan te vra, moet **enrollment rights** toegekend word. Hierdie regte word bepaal deur sekuriteitsdescriptors op die sertifikaatsjabloon en op die Enterprise CA self. Permissies moet op beide plekke gegee word vir 'n aanvraag om suksesvol te wees.

### Sjabloon Inskrywingsregte

Hierdie regte word gespesifiseer deur Toegangsbeheerinsette (Access Control Entries, ACEs), wat toestemmings soos volg beskryf:

- **Certificate-Enrollment** en **Certificate-AutoEnrollment** regte, elk geassosieer met spesifieke GUIDs.
- **ExtendedRights**, wat alle uitgebreide toestemmings toelaat.
- **FullControl/GenericAll**, wat volledige beheer oor die sjabloon bied.

### Enterprise CA Inskrywingsregte

Die CA se regte word uiteengesit in sy sekuriteitsdescriptor, beskikbaar via die Certificate Authority-beheerconsole. Sommige instellings laat selfs lae-geprivilegieerde gebruikers afgeleë toegang toe, wat 'n sekuriteitsrisiko kan wees.

### Addisionele Uitreikbeheerders

Sekere beheerders kan van toepassing wees, soos:

- **Manager Approval**: Plaas aansoeke in 'n hangende toestand totdat dit deur 'n sertifikaatbestuurder goedgekeur word.
- **Enrolment Agents and Authorized Signatures**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Application Policy OIDs.

### Metodes om Sertifikate aan te vra

Sertifikate kan aangevra word deur:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), met DCOM-koppelvlakke.
2. **ICertPassage Remote Protocol** (MS-ICPR), via named pipes of TCP/IP.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment rol geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), saam met die Certificate Enrollment Policy (CEP) diens.
5. Die **Network Device Enrollment Service** (NDES) vir netwerktoestelle, wat die Simple Certificate Enrollment Protocol (SCEP) gebruik.

Windows-gebruikers kan ook sertifikate versoek via die GUI (`certmgr.msc` of `certlm.msc`) of opdraglyn-instrumente (`certreq.exe` of PowerShell se `Get-Certificate` opdrag).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaat-outentisering

Active Directory (AD) ondersteun sertifikaat-outentisering, hoofsaaklik deur gebruik te maak van **Kerberos** en **Secure Channel (Schannel)** protokolle.

### Kerberos-outentiseringsproses

In die Kerberos-outentiseringsproses word 'n gebruiker se versoek vir 'n Ticket Granting Ticket (TGT) onderteken met die **private key** van die gebruiker se sertifikaat. Hierdie versoek deurgaan verskeie validerings deur die domain controller, insluitend die sertifikaat se **geldigheid**, **pad**, en **herroepingsstatus**. Validerings sluit ook in die verifikasie dat die sertifikaat van 'n betroubare bron kom en die bevestiging van die uitreiker se teenwoordigheid in die **NTAUTH certificate store**. Suksesvolle validerings lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`** object in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal in die vestiging van vertroue vir sertifikaatautentisering.

### Secure Channel (Schannel) Autentisering

Schannel maak veilige TLS/SSL-verbindinge moontlik, waar tydens 'n handshake die kliënt 'n sertifikaat voorlê wat, indien suksesvol gevalideer, toegang magtig. Die kartering van 'n sertifikaat na 'n AD-rekening kan Kerberos se **S4U2Self** funksie of die sertifikaat se **Subject Alternative Name (SAN)** insluit, onder andere metodes.

### AD Sertifikaatdienste Enumerasie

AD se sertifikaatdienste kan deur LDAP-navrae opgenoem word, wat inligting oor **Enterprise Sertifikaatautoriteite (CAs)** en hul konfigurasies openbaar. Dit is toeganklik vir enige domeingeverifieerde gebruiker sonder spesiale voorregte. Gereedskap soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir enumerasie en kwesbaarheidsassessering in AD CS omgewings.

Opdragte vir die gebruik van hierdie gereedskap sluit in:
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
## Verwysings

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
