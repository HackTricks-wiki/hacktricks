# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar daarvan aan.
- 'n **Public Key** word met 'n privaat gehoude sleutel gepaar om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Validity Period**, gedefinieer deur **NotBefore**- en **NotAfter**-datums, dui die sertifikaat se geldigheidsduur aan.
- 'n Unieke **Serial Number**, verskaf deur die Certificate Authority (CA), identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** maak addisionele name vir die onderwerp moontlik, wat identifikasiebuigsaamheid verbeter.
- **Basic Constraints** identifiseer of die sertifikaat vir 'n CA of 'n eindentiteit is en gebruiksbeperkings definieer.
- **Extended Key Usages (EKUs)** omskryf die sertifikaat se spesifieke doeleindes, soos code signing of email encryption, deur Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode waarmee die sertifikaat onderteken word.
- Die **Signature**, wat met die uitgewer se private key geskep is, waarborg die sertifikaat se egtheid.<sup>[[1]](#references)</sup>

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid na verskeie identiteite uit, wat noodsaaklik is vir servers met veelvuldige domains. Veilige uitreikingsprosesse is noodsaaklik om impersonation-risiko's te voorkom wat deur attackers veroorsaak kan word wanneer hulle die SAN-spesifikasie manipuleer.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA certificates in 'n AD forest deur aangewese containers, wat elk unieke rolle vervul:<sup>[[1]](#references)</sup>

- Die **Certification Authorities**-container bevat trusted root CA certificates.
- Die **Enrolment Services**-container bevat besonderhede oor Enterprise CAs en hul certificate templates.
- Die **NTAuthCertificates**-object bevat CA certificates wat vir AD authentication gemagtig is.
- Die **AIA (Authority Information Access)**-container fasiliteer certificate chain validation met intermediate en cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. Die versoekproses begin wanneer clients 'n Enterprise CA vind.
2. 'n CSR word geskep nadat 'n public-private key pair gegenereer is, en bevat 'n public key en ander besonderhede.
3. Die CA evalueer die CSR teen beskikbare certificate templates en reik die sertifikaat uit gebaseer op die template se permissions.
4. Na goedkeuring onderteken die CA die sertifikaat met sy private key en stuur dit aan die client terug.<sup>[[1]](#references)</sup>

### Certificate Templates

Hierdie templates, wat binne AD gedefinieer word, beskryf die settings en permissions vir die uitreiking van certificates, insluitend toegelate EKUs en enrollment- of modification rights, wat krities is vir die bestuur van toegang tot certificate services.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Die enrollment-proses vir certificates word begin deur 'n administrator wat **creates a certificate template**, waarna dit deur 'n Enterprise Certificate Authority (CA) **published** word. Dit maak die template beskikbaar vir client enrollment, 'n stap wat bereik word deur die template se naam by die `certificatetemplates`-veld van 'n Active Directory-object te voeg.<sup>[[1]](#references)</sup>

Vir 'n client om 'n certificate aan te vra, moet **enrollment rights** toegeken word. Hierdie regte word deur security descriptors op die certificate template en die Enterprise CA self gedefinieer. Permissions moet op albei plekke toegeken word sodat 'n versoek suksesvol kan wees.<sup>[[1]](#references)</sup>

### Template Enrollment Rights

Hierdie regte word deur Access Control Entries (ACEs) gespesifiseer en beskryf permissions soos:<sup>[[1]](#references)</sup>

- **Certificate-Enrollment**- en **Certificate-AutoEnrollment**-rights, elk geassosieer met spesifieke GUIDs.
- **ExtendedRights**, wat alle extended permissions toelaat.
- **FullControl/GenericAll**, wat volledige beheer oor die template verskaf.

### Enterprise CA Enrollment Rights

Die CA se regte word in sy security descriptor uiteengesit, wat deur die Certificate Authority management console verkrygbaar is. Sommige settings laat selfs low-privileged users remote access toe, wat 'n security concern kan wees.<sup>[[1]](#references)</sup>

### Additional Issuance Controls

Sekere controls kan van toepassing wees, soos:<sup>[[1]](#references)</sup>

- **Manager Approval**: Plaas versoeke in 'n hangende toestand totdat dit deur 'n certificate manager goedgekeur word.
- **Enrolment Agents and Authorized Signatures**: Spesifiseer die aantal vereiste signatures op 'n CSR en die nodige Application Policy OIDs.

### Methods to Request Certificates

Certificates kan deur die volgende aangevra word:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), wat DCOM interfaces gebruik.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur named pipes of TCP/IP.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment role geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), saam met die Certificate Enrollment Policy (CEP) service.
5. Die **Network Device Enrollment Service** (NDES) vir network devices, wat die Simple Certificate Enrollment Protocol (SCEP) gebruik.

Windows users kan ook certificates deur die GUI (`certmgr.msc` of `certlm.msc`) of command-line tools (`certreq.exe` of PowerShell se `Get-Certificate` command) aanvra.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaatverifikasie

Active Directory (AD) ondersteun sertifikaatverifikasie, hoofsaaklik deur gebruik te maak van die **Kerberos**- en **Secure Channel (Schannel)**-protokolle.<sup>[[1]](#references)</sup>

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek vir 'n Ticket Granting Ticket (TGT) met die **private key** van die gebruiker se sertifikaat onderteken. Hierdie versoek ondergaan verskeie validasies deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad** en herroepingsstatus. Validasies sluit ook in om te verifieer dat die sertifikaat van 'n vertroude bron afkomstig is en om die uitgewer se teenwoordigheid in die **NTAUTH certificate store** te bevestig. Suksesvolle validasies lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`**-objek in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal tot die vestiging van vertroue vir sertifikaatverifikasie.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel)-verifikasie

Schannel fasiliteer veilige TLS/SSL-verbindings, waar die kliënt tydens ’n handshake ’n sertifikaat aanbied wat, indien dit suksesvol gevalideer word, toegang magtig.<sup>[[2]](#references)</sup> Die kartering van ’n sertifikaat na ’n AD-rekening kan onder andere Kerberos se **S4U2Self**-funksie of die sertifikaat se **Subject Alternative Name (SAN)** behels.<sup>[[1]](#references)</sup>

### Enumerasie van AD Certificate Services

AD se certificate services kan deur LDAP-navrae geënumereer word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies onthul. Dit is toeganklik vir enige domein-geauthentiseerde gebruiker sonder spesiale voorregte.<sup>[[1]](#references)</sup> Gereedskap soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word vir enumerasie en kwesbaarheidsbepaling in AD CS-omgewings gebruik.<sup>[[3]](#references)</sup>

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
Rubeus kan ook ’n wagwoordbeskermde PFX-sertifikaat vir PKINIT-verifikasie gebruik en ’n TGT aanvra. Die opsionele `/getcredentials`-skakelaar vra ’n U2U-dienskaartjie aan en probeer om die rekening se NT-hash te herwin:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Misbruik van Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Wat is SSL/TLS Client Authentication en hoe werk dit?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
