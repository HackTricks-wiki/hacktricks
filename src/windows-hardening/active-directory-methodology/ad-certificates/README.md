# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- Die **Onderwerp** van die sertifikaat dui sy eienaar aan.
- 'n **Publieke Sleutel** word gekoppel aan 'n privaat besit sleutel om die sertifikaat aan sy regmatige eienaar te verbind.
- Die **Geldigheidsperiode**, gedefinieer deur **NotBefore** en **NotAfter** datums, merk die sertifikaat se effektiewe duur.
- 'n Unieke **Serienommer**, verskaf deur die Sertifikaatowerheid (CA), identifiseer elke sertifikaat.
- Die **Uitgewer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat vir addisionele name vir die onderwerp, wat identifikasiefleksibiliteit verbeter.
- **Basiese Beperkings** identifiseer of die sertifikaat vir 'n CA of 'n eindentiteit is en definieer gebruiksbeperkings.
- **Verlengde Sleutelgebruik (EKUs)** delineer die sertifikaat se spesifieke doele, soos kodehandtekening of e-posversleuteling, deur middel van Objektidentifiseerders (OIDs).
- Die **Handtekening Algoritme** spesifiseer die metode vir die ondertekening van die sertifikaat.
- Die **Handtekening**, geskep met die uitgewer se privaat sleutel, waarborg die sertifikaat se egtheid.

### Special Considerations

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepasbaarheid uit na verskeie identiteite, wat noodsaaklik is vir bedieners met verskeie domeine. Veilige uitreikprosesse is noodsaaklik om te verhoed dat aanvallers die SAN-spesifikasie manipuleer en sodoende identiteitsdiefstal risikos skep.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD-woud deur middel van aangewese houers, elk wat unieke rolle dien:

- Die **Sertifikaatowerhede** houer bevat vertroude wortel CA-sertifikate.
- Die **Inskrywingsdienste** houer detail Enterprise CA's en hul sertifikaat sjablone.
- Die **NTAuthCertificates** objek sluit CA-sertifikate in wat gemagtig is vir AD-outehentisering.
- Die **AIA (Authority Information Access)** houer fasiliteer sertifikaatkettingvalidasie met tussenliggende en kruis CA-sertifikate.

### Certificate Acquisition: Client Certificate Request Flow

1. Die versoekproses begin met kliënte wat 'n Enterprise CA vind.
2. 'n CSR word geskep, wat 'n publieke sleutel en ander besonderhede bevat, na die generering van 'n publieke-privaat sleutel paar.
3. Die CA evalueer die CSR teenoor beskikbare sertifikaat sjablone, en stel die sertifikaat uit op grond van die sjabloon se toestemmings.
4. Na goedkeuring, onderteken die CA die sertifikaat met sy privaat sleutel en keer dit terug na die kliënt.

### Certificate Templates

Gedefinieer binne AD, skets hierdie sjablone die instellings en toestemmings vir die uitreiking van sertifikate, insluitend toegelate EKUs en inskrywings- of wysigingsregte, wat krities is vir die bestuur van toegang tot sertifikaatdienste.

## Certificate Enrollment

Die inskrywingsproses vir sertifikate word geinitieer deur 'n administrateur wat **'n sertifikaat sjabloon skep**, wat dan **gepubliseer** word deur 'n Enterprise Sertifikaatowerheid (CA). Dit maak die sjabloon beskikbaar vir kliëntinskrywing, 'n stap wat bereik word deur die sjabloon se naam by die `certificatetemplates` veld van 'n Active Directory objek te voeg.

Vir 'n kliënt om 'n sertifikaat aan te vra, moet **inskrywingsregte** toegeken word. Hierdie regte word gedefinieer deur sekuriteitsbeskrywings op die sertifikaat sjabloon en die Enterprise CA self. Toestemmings moet in beide plekke toegeken word vir 'n versoek om suksesvol te wees.

### Template Enrollment Rights

Hierdie regte word gespesifiseer deur middel van Toegang Beheer Inskrywings (ACEs), wat toestemmings soos:

- **Sertifikaat-Inskrywing** en **Sertifikaat-AutoInskrywing** regte, elk geassosieer met spesifieke GUIDs.
- **VerlengdeRegte**, wat alle verlengde toestemmings toelaat.
- **VolleBeheer/GenerieseAlles**, wat volledige beheer oor die sjabloon bied.

### Enterprise CA Enrollment Rights

Die CA se regte word uiteengesit in sy sekuriteitsbeskrywing, toeganklik via die Sertifikaatowerheid bestuurconsole. Sommige instellings laat selfs laag-geprivilegieerde gebruikers toe om afstandstoegang te hê, wat 'n sekuriteitskwessie kan wees.

### Additional Issuance Controls

Sekere kontroles mag van toepassing wees, soos:

- **Bestuurder Goedkeuring**: Plaas versoeke in 'n hangende toestand totdat dit deur 'n sertifikaatbestuurder goedgekeur word.
- **Inskrywingsagente en Gemagtigde Handtekeninge**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Aansoekbeleid OIDs.

### Methods to Request Certificates

Sertifikate kan aangevra word deur:

1. **Windows Kliënt Sertifikaat Inskrywing Protokol** (MS-WCCE), met DCOM interfaces.
2. **ICertPassage Afstand Protokol** (MS-ICPR), deur middel van benoemde pype of TCP/IP.
3. Die **sertifikaat inskrywing web koppelvlak**, met die Sertifikaatowerheid Web Inskrywing rol geïnstalleer.
4. Die **Sertifikaat Inskrywing Diens** (CES), in samewerking met die Sertifikaat Inskrywing Beleid (CEP) diens.
5. Die **Netwerk Toestel Inskrywing Diens** (NDES) vir netwerktoestelle, met die gebruik van die Simple Certificate Enrollment Protocol (SCEP).

Windows gebruikers kan ook sertifikate aan vra via die GUI (`certmgr.msc` of `certlm.msc`) of opdraglyn gereedskap (`certreq.exe` of PowerShell se `Get-Certificate` opdrag).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaat Verifikasie

Active Directory (AD) ondersteun sertifikaat verifikasie, hoofsaaklik deur gebruik te maak van **Kerberos** en **Secure Channel (Schannel)** protokolle.

### Kerberos Verifikasie Proses

In die Kerberos verifikasie proses, word 'n gebruiker se versoek vir 'n Ticket Granting Ticket (TGT) onderteken met die **privaat sleutel** van die gebruiker se sertifikaat. Hierdie versoek ondergaan verskeie validerings deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad**, en **herroepingstatus**. Validerings sluit ook in om te verifieer dat die sertifikaat van 'n vertroude bron kom en om die uitreiker se teenwoordigheid in die **NTAUTH sertifikaat stoor** te bevestig. Suksesvolle validerings lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`** objek in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal tot die vestiging van vertroue vir sertifikaatverifikasie.

### Secure Channel (Schannel) Verifikasie

Schannel fasiliteer veilige TLS/SSL verbindings, waar tydens 'n handdruk, die kliënt 'n sertifikaat aanbied wat, indien suksesvol geverifieer, toegang magtig. Die toewysing van 'n sertifikaat aan 'n AD-rekening kan die Kerberos se **S4U2Self** funksie of die sertifikaat se **Subject Alternative Name (SAN)** insluit, onder andere metodes.

### AD Sertifikaat Dienste Enumerasie

AD se sertifikaatdienste kan deur LDAP navrae gelys word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies onthul. Dit is toeganklik vir enige domein-geverifieerde gebruiker sonder spesiale voorregte. Gereedskap soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir enumerasie en kwesbaarheidsevaluering in AD CS omgewings.

Opdragte om hierdie gereedskap te gebruik sluit in:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Verwysings

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../../banners/hacktricks-training.md}}
