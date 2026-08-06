# AD-sertifikate

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Onderwerp** van die sertifikaat dui die eienaar daarvan aan.
- 'n **Publieke Sleutel** word met 'n privaat beheerde sleutel gepaar om die sertifikaat aan die regmatige eienaar daarvan te koppel.
- Die **Geldigheidstydperk**, wat deur **NotBefore**- en **NotAfter**-datums gedefinieer word, dui die sertifikaat se effektiewe duur aan.
- 'n Unieke **Reeksnommer**, wat deur die Certificate Authority (CA) verskaf word, identifiseer elke sertifikaat.
- Die **Uitreiker** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat bykomende name vir die onderwerp toe, wat identifikasiefleksibiliteit verbeter.
- **Basiese Beperkings** identifiseer of die sertifikaat vir 'n CA of 'n eindentiteit is en gebruiksbeperkings definieer.
- **Uitgebreide Sleutelgebruike (EKUs)** omskryf die spesifieke doeleindes van die sertifikaat, soos code signing of e-pos-enkripsie, deur Object Identifiers (OIDs).
- Die **Handtekeningalgoritme** spesifiseer die metode wat gebruik word om die sertifikaat te onderteken.
- Die **Handtekening**, wat met die uitreiker se private sleutel geskep word, waarborg die sertifikaat se egtheid.<sup>[[1]](#references)</sup>

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid na veelvuldige identiteite uit, wat noodsaaklik is vir servers met verskeie domains. Veilige uitreikingsprosesse is noodsaaklik om impersonation-risiko's te vermy wat kan ontstaan wanneer attackers die SAN-spesifikasie manipuleer.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD-forest deur aangewese containers, wat elk unieke rolle vervul:<sup>[[1]](#references)</sup>

- Die **Certification Authorities**-container bevat vertroude root CA-sertifikate.
- Die **Enrolment Services**-container bevat besonderhede oor Enterprise CAs en hul sertifikaatsjablone.
- Die **NTAuthCertificates**-object bevat CA-sertifikate wat vir AD-authentication gemagtig is.
- Die **AIA (Authority Information Access)**-container fasiliteer sertifikaatkettingvalidering met intermediate en cross CA-sertifikate.

### Sertifikaatverkryging: Client Certificate Request Flow

1. Die versoekproses begin wanneer clients 'n Enterprise CA vind.
2. 'n CSR word geskep wat 'n publieke sleutel en ander besonderhede bevat nadat 'n publieke-private sleutelpaart gegenereer is.
3. Die CA evalueer die CSR teenoor beskikbare sertifikaatsjablone en reik die sertifikaat uit op grond van die sjabloon se permissions.
4. Ná goedkeuring onderteken die CA die sertifikaat met sy private sleutel en stuur dit aan die client terug.<sup>[[1]](#references)</sup>

### Sertifikaatsjablone

Hierdie sjablone, wat binne AD gedefinieer word, beskryf die settings en permissions vir die uitreiking van sertifikate, insluitend toegelate EKUs en enrollment- of modification-regte, wat noodsaaklik is vir die bestuur van toegang tot sertifikaatdienste.<sup>[[1]](#references)</sup>

## Sertifikaat-enrollment

Die enrollment-proses vir sertifikate word deur 'n administrator geïnisieer wat **'n sertifikaatsjabloon skep**, waarna dit deur 'n Enterprise Certificate Authority (CA) **gepubliseer** word. Dit maak die sjabloon vir client-enrollment beskikbaar, wat bereik word deur die sjabloon se naam by die `certificatetemplates`-veld van 'n Active Directory-object te voeg.<sup>[[1]](#references)</sup>

Vir 'n client om 'n sertifikaat aan te vra, moet **enrollment-regte** toegeken word. Hierdie regte word deur security descriptors op die sertifikaatsjabloon en die Enterprise CA self gedefinieer. Permissions moet op albei plekke toegeken word vir 'n versoek om suksesvol te wees.<sup>[[1]](#references)</sup>

### Sjabloon-enrollment-regte

Hierdie regte word deur Access Control Entries (ACEs) gespesifiseer en beskryf permissions soos:<sup>[[1]](#references)</sup>

- **Certificate-Enrollment**- en **Certificate-AutoEnrollment**-regte, elk geassosieer met spesifieke GUIDs.
- **ExtendedRights**, wat alle uitgebreide permissions toelaat.
- **FullControl/GenericAll**, wat volledige beheer oor die sjabloon verskaf.

### Enterprise CA-enrollment-regte

Die CA se regte word in sy security descriptor uiteengesit, wat deur die Certificate Authority-bestuurskonsole verkrygbaar is. Sommige settings laat selfs low-privileged users remote access toe, wat 'n security concern kan wees.<sup>[[1]](#references)</sup>

### Bykomende Uitreikingskontroles

Sekere kontroles kan van toepassing wees, soos:<sup>[[1]](#references)</sup>

- **Bestuurdergoedkeuring**: Plaas versoeke in 'n pending state totdat dit deur 'n sertifikaatbestuurder goedgekeur word.
- **Enrolment Agents en Gemagtigde Handtekeninge**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Application Policy OIDs.

### Metodes om Sertifikate aan te vra

Sertifikate kan aangevra word deur:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), wat DCOM-interfaces gebruik.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur named pipes of TCP/IP.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment-rol geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), in samewerking met die Certificate Enrollment Policy (CEP)-diens.
5. Die **Network Device Enrollment Service** (NDES) vir network devices, wat die Simple Certificate Enrollment Protocol (SCEP) gebruik.

Windows-gebruikers kan ook sertifikate deur die GUI (`certmgr.msc` of `certlm.msc`) of command-line tools (`certreq.exe` of PowerShell se `Get-Certificate`-command) aanvra.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaatverifikasie

Active Directory (AD) ondersteun sertifikaatverifikasie, hoofsaaklik deur die **Kerberos**- en **Secure Channel (Schannel)**-protokolle te gebruik.<sup>[[1]](#references)</sup>

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek om 'n Ticket Granting Ticket (TGT) met die **private sleutel** van die gebruiker se sertifikaat onderteken. Hierdie versoek ondergaan verskeie validerings deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad** en **herroepingstatus**. Validerings sluit ook in dat daar geverifieer word dat die sertifikaat van 'n vertroude bron afkomstig is en dat die uitreiker in die **NTAUTH certificate store** voorkom. Suksesvolle validerings lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`**-objek in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal tot die vestiging van vertroue vir sertifikaatverifikasie.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Schannel fasiliteer veilige TLS/SSL-verbindings, waar die kliënt tydens ’n handshake ’n sertifikaat aanbied wat, indien dit suksesvol gevalideer word, toegang magtig.<sup>[[2]](#references)</sup> Die koppeling van ’n sertifikaat aan ’n AD-rekening kan onder meer Kerberos se **S4U2Self**-funksie of die sertifikaat se **Subject Alternative Name (SAN)** behels.<sup>[[1]](#references)</sup>

### AD Certificate Services Enumeration

AD se certificate services kan deur LDAP-navrae geënumeer word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies openbaar. Dit is toeganklik vir enige domein-geoutentiseerde gebruiker sonder spesiale voorregte.<sup>[[1]](#references)</sup> Tools soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word vir enumeration en kwesbaarheidsassessering in AD CS-omgewings gebruik.<sup>[[3]](#references)</sup>

Commands vir die gebruik van hierdie tools sluit in:
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

- [1] [Certified Pre-Owned: Misbruik van Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Wat is SSL/TLS-kliëntverifikasie en hoe werk dit?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
