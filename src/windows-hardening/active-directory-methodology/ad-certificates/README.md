# AD Vyeti

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

### Vipengele vya Cheti

- **Subject** ya cheti inaonyesha mmiliki wake.
- **Public Key** imeambatanishwa na ufunguo wa kibinafsi ili kuunganisha cheti na mmiliki wake halali.
- **Validity Period**, inayofafanuliwa na tarehe za **NotBefore** na **NotAfter**, inaonyesha muda wa uhalali wa cheti.
- **Serial Number** ya kipekee, inayotolewa na Certificate Authority (CA), inatambulisha kila cheti.
- **Issuer** inarejea CA iliyotolewa cheti.
- **SubjectAlternativeName** inaruhusu majina ya ziada kwa subject, ikiongeza ufanisi wa utambuzi.
- **Basic Constraints** zinaonyesha kama cheti ni kwa ajili ya CA au kwa entiti ya mwisho na zinafafanua vizuizi vya matumizi.
- **Extended Key Usages (EKUs)** zinaainisha madhumuni maalum ya cheti, kama kusaini code au kushughulikia encryption ya barua pepe, kupitia Object Identifiers (OIDs).
- **Signature Algorithm** inaelezea njia ya kusaini cheti.
- **Signature**, inayotengenezwa kwa ufunguo wa kibinafsi wa issuer, inahakikisha uhalali wa cheti.

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** huongeza matumizi ya cheti kwa vitambulisho vingi, jambo muhimu kwa seva zenye domains nyingi. Mchakato salama wa utoaji ni muhimu ili kuepuka hatari ya kuigwa au utapeli kwa wapinzani wanaoweza kubadilisha vipimo vya SAN.

### Certificate Authorities (CAs) katika Active Directory (AD)

AD CS inatambua vyeti vya CA katika AD forest kupitia containers zilizotengwa, kila moja ikiwa na jukumu maalum:

- **Certification Authorities** container inashikilia vyeti vya root CA vinavyoaminika.
- **Enrolment Services** container inaeleza Enterprise CAs na template zao za cheti.
- **NTAuthCertificates** object inajumuisha vyeti vya CA vinavyoruhusiwa kwa uthibitisho wa AD.
- **AIA (Authority Information Access)** container inasaidia uthibitisho wa mnyororo wa vyeti kwa vyeti vya intermediate na cross CA.

### Upataji wa Cheti: Mtiririko wa Ombi la Cheti la Mteja

1. Mchakato wa ombi unaanza kwa wateja kupata Enterprise CA.
2. CSR inaundwa, ikiwa na public key na maelezo mengine, baada ya kuunda jozi ya ufunguo wa umma/wa kibinafsi.
3. CA inapima CSR dhidi ya template za cheti zilizo wazi, na kutoa cheti kulingana na ruhusa za template.
4. Baada ya kuidhinishwa, CA inasaini cheti kwa ufunguo wake wa kibinafsi na kurirudisha kwa mteja.

### Violezo vya Cheti

Violezo hivi vinavyowekwa ndani ya AD vinaeleza mipangilio na ruhusa za kutoa vyeti, ikiwa ni pamoja na EKUs zinazoruhusiwa na haki za kujiandikisha au kuhariri, muhimu kwa kusimamia ufikiaji kwa huduma za vyeti.

## Usajili wa Cheti

Mchakato wa usajili wa vyeti unaanzishwa na msimamizi anayehubiri **kuunda template ya cheti**, ambayo kisha **inachapishwa** na Enterprise Certificate Authority (CA). Hii inafanya template kupatikana kwa ajili ya usajili wa mteja, hatua ambayo hufikiwa kwa kuongeza jina la template kwenye shamba la `certificatetemplates` la kitu katika Active Directory.

Ili mteja aombe cheti, lazima apewe **haki za usajili**. Haki hizi zinafafanuliwa na security descriptors kwenye template ya cheti na kwenye Enterprise CA yenyewe. Ruhusa lazima zitatekelezwa katika maeneo yote mawili ili ombi lifanikiwe.

### Haki za Usajili za Template

Haki hizi zinaainishwa kupitia Access Control Entries (ACEs), zikieleza ruhusa kama:

- Haki za **Certificate-Enrollment** na **Certificate-AutoEnrollment**, kila moja ikiwa na GUID maalum.
- **ExtendedRights**, kuruhusu ruhusa zote zilizopanuliwa.
- **FullControl/GenericAll**, kutoa udhibiti kamili juu ya template.

### Haki za Usajili za Enterprise CA

Haki za CA zimetajwa katika security descriptor yake, inayopatikana kupitia consola ya Certificate Authority. Mipangilio fulani hata inaweza kuruhusu watumiaji wenye hadhi ndogo kufikia mbali, jambo ambalo linaweza kuwa hatari kwa usalama.

### Udhibiti wa Ziada wa Utoaji

Udhibiti fulani unaweza kutumika, kama vile:

- **Manager Approval**: Inuweka maombi katika hali ya kusubiri hadi idhini itolewe na meneja wa vyeti.
- **Enrolment Agents and Authorized Signatures**: Huweka idadi ya saini zinazohitajika kwenye CSR na Application Policy OIDs zinazohitajika.

### Njia za Kuomba Vyeti

Vyeti vinaweza kuombwa kupitia:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), kwa kutumia interfaces za DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), kupitia named pipes au TCP/IP.
3. kiolesura cha wavuti cha **certificate enrollment**, ikiwa role ya Certificate Authority Web Enrollment imewekwa.
4. **Certificate Enrollment Service** (CES), pamoja na Certificate Enrollment Policy (CEP) service.
5. **Network Device Enrollment Service** (NDES) kwa vifaa vya mtandao, kwa kutumia Simple Certificate Enrollment Protocol (SCEP).

Watumiaji wa Windows pia wanaweza kuomba vyeti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za mstari wa amri (`certreq.exe` au amri ya PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitishaji wa Cheti

Active Directory (AD) inaunga mkono uthibitishaji wa vyeti, hasa ikitumia protokoli za **Kerberos** na **Secure Channel (Schannel)**.

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la Ticket Granting Ticket (TGT) linasainiwa kwa kutumia **private key** ya cheti cha mtumiaji. Ombi hili hupitia uthibitisho kadhaa na domain controller, ikijumuisha **validity**, **path**, na **revocation status** ya cheti. Uthibitisho pia unajumuisha kuthibitisha kwamba cheti kinatokana na chanzo kinachotegemewa na kuthibitisha uwepo wa muuzaji katika **NTAUTH certificate store**. Uthibitisho uliopitishwa husababisha utolewaji wa TGT. Kitu cha **`NTAuthCertificates`** katika AD, kinapatikana katika:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ni muhimu katika kuanzisha uaminifu kwa uthibitishaji wa vyeti.

### Secure Channel (Schannel) Authentication

Schannel inawezesha miunganisho salama ya TLS/SSL, ambapo wakati wa handshake, mteja huwasilisha cheti ambacho, ikiwa kimeidhinishwa kwa mafanikio, hutoa idhini ya upatikanaji. Kuambatanisha cheti kwa akaunti ya AD kunaweza kuhusisha Kerberos’s **S4U2Self** function au cheti’s **Subject Alternative Name (SAN)**, miongoni mwa mbinu nyingine.

### AD Certificate Services Enumeration

AD's certificate services zinaweza kuorodheshwa kupitia maswali ya LDAP, zikifichua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** na usanidi wao. Hii inapatikana kwa mtumiaji yeyote aliye domain-authenticated bila vibali maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** zinatumiwa kwa ajili ya kuorodhesha na tathmini ya udhaifu katika mazingira ya AD CS.

Amri za kutumia zana hizi ni pamoja na:
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
## Marejeo

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
