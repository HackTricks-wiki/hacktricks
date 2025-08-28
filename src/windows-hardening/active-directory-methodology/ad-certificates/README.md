# AD Sertifikate

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar aan.
- 'n **Public Key** word gepaard met 'n privaat sleutel om die sertifikaat aan die regmatige eienaar te koppel.
- Die **Validity Period**, gedefinieer deur **NotBefore** en **NotAfter** datums, dui die sertifikaat se geldigheidsduur aan.
- 'n unieke **Serial Number**, voorsien deur die Certificate Authority (CA), identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat addisionele name vir die subject toe, wat identifikasiebuigbaarheid verbeter.
- **Basic Constraints** identifiseer of die sertifikaat vir 'n CA of 'n eindentiteit is en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** omskryf die sertifikaat se spesifieke doeleindes, soos code signing of e-pos enkripsie, via Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode om die sertifikaat te onderteken.
- Die **Signature**, geskep met die issuer se privaat sleutel, waarborg die sertifikaat se egtheid.

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid uit na meerdere identiteite, wat kritiek is vir servers met verskeie domeine. Veiligheid in die uitreikproses is noodsaaklik om te voorkom dat aanvallers die SAN-spesifikasie manipuleer en sodoende tot identiteitsmisleiding lei.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD-forest deur aangewese houers, elk met 'n unieke rol:

- Die **Certification Authorities** kontainer hou vertroude root CA-sertifikate.
- Die **Enrolment Services** kontainer bevat besonderhede van Enterprise CAs en hul sertifikaattemplates.
- Die **NTAuthCertificates** objek sluit CA-sertifikate in wat gemagtig is vir AD-verifikasie.
- Die **AIA (Authority Information Access)** kontainer fasiliteer sertifikaatkettingvalidasie met intermediêre en cross-CA sertifikate.

### Sertifikaatverkryging: Kliënt Sertifikaataanvraag-vloei

1. Die aanvraagproses begin daarmee dat kliënte 'n Enterprise CA vind.
2. 'n CSR word geskep en bevat 'n public key en ander besonderhede, nadat 'n publieke-privaat sleutelpaartjie gegenereer is.
3. Die CA evalueer die CSR teen beskikbare sertifikaattemplates en gee die sertifikaat uit gebaseer op die template se regte.
4. Na goedkeuring teken die CA die sertifikaat met sy privaat sleutel en stuur dit terug na die kliënt.

### Sertifikaattemplates

Binne AD gedefinieer, beskryf hierdie templates die instellings en regte vir die uitreiking van sertifikate, insluitend toegelate EKUs en registrasie- of wysigingsregte, wat kritiek is vir die bestuur van toegang tot sertifikaatdienste.

## Sertifikaatinskrywing

Die inskrywingsproses vir sertifikate word geïnisieer deur 'n administrateur wat **'n sertifikaattemplate skep**, wat dan deur 'n Enterprise Certificate Authority (CA) **gepubliseer** word. Dit maak die template beskikbaar vir kliëntinskrywing, 'n stap wat bereik word deur die template se naam by die `certificatetemplates` veld van 'n Active Directory-objek te voeg.

Om 'n sertifikaat te versoek, moet **enrollment rights** toegeken word. Hierdie regte word gedefinieer deur security descriptors op die sertifikaattemplate en op die Enterprise CA self. Permissies moet in beide plekke toegeken word vir 'n suksesvolle aanvraag.

### Template Inskrywingsregte

Hierdie regte word gespesifiseer deur Access Control Entries (ACEs), en beskryf permissies soos:

- **Certificate-Enrollment** en **Certificate-AutoEnrollment** regte, elk geassosieer met spesifieke GUIDs.
- **ExtendedRights**, wat alle uitgebreide permissies toelaat.
- **FullControl/GenericAll**, wat volle beheer oor die template bied.

### Enterprise CA Inskrywingsregte

Die CA se regte word uiteengesit in sy security descriptor, toeganklik via die Certificate Authority bestuurkonsole. Sommige instellings laat selfs lae-bevoorregte gebruikers afgeleë toegang toe, wat 'n sekuriteitsrisiko kan wees.

### Addisionele Uitreikbeheer

Sekere kontroles kan van toepassing wees, soos:

- **Manager Approval**: Plaas versoeke in 'n hangende toestand totdat goedgekeur deur 'n sertifikaatbestuurder.
- **Enrolment Agents and Authorized Signatures**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Application Policy OIDs.

### Metodes om Sertifikate te Versoek

Sertifikate kan versoek word deur:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), met gebruik van DCOM-intefaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur named pipes of TCP/IP.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment-rol geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), saam met die Certificate Enrollment Policy (CEP) diens.
5. Die **Network Device Enrollment Service** (NDES) vir netwerktoestelle, met gebruik van die Simple Certificate Enrollment Protocol (SCEP).

Windows gebruikers kan sertifikate ook versoek via die GUI (`certmgr.msc` of `certlm.msc`) of reëllyninstrumente (`certreq.exe` of PowerShell se `Get-Certificate` opdrag).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaatverifikasie

Active Directory (AD) ondersteun sertifikaatverifikasie, hoofsaaklik deur die **Kerberos** en **Secure Channel (Schannel)** protokolle te gebruik.

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek vir 'n Ticket Granting Ticket (TGT) geteken met die **privaat sleutel** van die gebruiker se sertifikaat. Hierdie versoek ondergaan verskeie kontrole deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad**, en **herroepingsstatus**. Kontroles sluit ook in die verifiëring dat die sertifikaat van 'n betroubare bron afkomstig is en die bevestiging van die uitreiker se teenwoordigheid in die **NTAUTH certificate store**. Suksesvolle kontroles lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`**-object in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal vir die vestiging van vertroue vir sertifikaatverifikasie.

### Secure Channel (Schannel) Verifikasie

Schannel fasiliteer veilige TLS/SSL-verbindinge, waar tydens 'n handshake die kliënt 'n sertifikaat voorlê wat, indien suksesvol gevalideer, toegang magtig. Die kartysering van 'n sertifikaat na 'n AD-rekening kan Kerberos’s **S4U2Self** funksie of die sertifikaat se **Subject Alternative Name (SAN)** betrek, onder andere metodes.

### AD Sertifikaatdienste-enumerasie

AD se sertifikaatdienste kan deur LDAP-navrae gedenumeriseer word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies openbaar. Dit is toeganklik vir enige domein-geauthentiseerde gebruiker sonder spesiale voorregte. Gereedskap soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir enumerasie en kwesbaarheidsevaluering in AD CS-omgewings.

Kommando's vir die gebruik van hierdie gereedskap sluit in:
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
