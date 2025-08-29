# AD Vyeti

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

### Vipengele vya Cheti

- **Subject** ya cheti inaonyesha mmiliki wake.
- **Public Key** ni sambamba na key iliyohifadhiwa kwa siri ili kuunganisha cheti na mmiliki halali.
- **Validity Period**, iliyofafanuliwa kwa tarehe za **NotBefore** na **NotAfter**, inaonyesha muda cheti kinachofanya kazi.
- **Serial Number** ya kipekee, inayotolewa na Certificate Authority (CA), inatambua kila cheti.
- **Issuer** inarejea CA iliyetoa cheti.
- **SubjectAlternativeName** inaruhusu majina ya ziada kwa subject, ikiongeza kubadilika kwa utambuzi.
- **Basic Constraints** zinaonyesha kama cheti ni kwa CA au kwa entiti ya mwisho na zinafafanua vikwazo vya matumizi.
- **Extended Key Usages (EKUs)** zinaainisha madhumuni maalum ya cheti, kama code signing au email encryption, kupitia Object Identifiers (OIDs).
- **Signature Algorithm** inaeleza njia ya kusaini cheti.
- **Signature**, iliyotengenezwa kwa private key ya issuer, inahakikisha uhalali wa cheti.

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** hueneza uhalali wa cheti kwa vitambulisho vingi, muhimu kwa server zenye domains nyingi. Mchakato salama wa utoaji ni muhimu ili kuepuka hatari za utapeli ambapo wadukuzi wanaweza kubadilisha vipimo vya SAN.

### Certificate Authorities (CAs) katika Active Directory (AD)

AD CS inatambua vyeti vya CA ndani ya msitu wa AD kupitia makontena yaliyoteuliwa, kila mmoja ukiwa na jukumu lake la kipekee:

- **Certification Authorities** container ina vyeti vya CA za root vinavyotendwa kuaminiwa.
- **Enrolment Services** container inaelezea Enterprise CAs na template za vyeti zao.
- **NTAuthCertificates** object inajumuisha vyeti vya CA vilivyoidhinishwa kwa authentication ya AD.
- **AIA (Authority Information Access)** container inasaidia uhakiki wa mnyororo wa vyeti kwa vyeti vya intermediate na cross CA.

### Certificate Acquisition: Client Certificate Request Flow

1. Mchakato wa ombi huanza kwa wateja kutafuta Enterprise CA.
2. CSR inaundwa, ikiwa na public key na maelezo mengine, baada ya kutengeneza jozi ya public-private key.
3. CA inakagua CSR dhidi ya template za vyeti zilizopo, ikitoa cheti kulingana na ruhusa za kiolezo.
4. Baada ya kuidhinishwa, CA inasaini cheti kwa private key yake na kurudisha kwa mteja.

### Certificate Templates

Zilizoainishwa ndani ya AD, violezo hivi vinaelezea mipangilio na ruhusa za kutoa vyeti, ikiwa ni pamoja na EKUs zinazoruhusiwa na haki za usajili au uhariri, muhimu kwa kusimamia ufikiaji wa huduma za cheti.

## Usajili wa Cheti

Mchakato wa usajili wa vyeti unaanzishwa na msimamizi anayeyaunda **certificate template**, ambayo kisha **huchapishwa** na Enterprise Certificate Authority (CA). Hii hufanya kiolezo kupatikana kwa usajili wa mteja, hatua inayofikiwa kwa kuongeza jina la kiolezo kwenye uwanja wa `certificatetemplates` wa kitu cha Active Directory.

Ili mteja kuomba cheti, lazima apewe **haki za usajili**. Haki hizi zimetengwa na security descriptors kwenye kiolezo cha cheti na kwenye Enterprise CA yenyewe. Ruhusa lazima zichukuliwe katika maeneo yote mawili ili ombi lifanikiwe.

### Haki za Usajili za Kiolezo

Haki hizi zinaainishwa kupitia Access Control Entries (ACEs), zikielezea ruhusa kama:

- **Certificate-Enrollment** na **Certificate-AutoEnrollment** rights, kila moja ikihusishwa na GUID maalum.
- **ExtendedRights**, ikiruhusu ruhusa zote za ziada.
- **FullControl/GenericAll**, ikitoa udhibiti kamili juu ya kiolezo.

### Haki za Usajili za Enterprise CA

Haki za CA zimetajwa kwenye security descriptor yake, inayopatikana kupitia Certificate Authority management console. Baadhi ya mipangilio hata inaruhusu watumiaji wenye haki ndogo ufikiaji wa mbali, jambo ambalo linaweza kuwa hatari kwa usalama.

### Udhibiti wa Ziada wa Utoaji

Udhibiti fulani unaweza kutumika, kama:

- **Manager Approval**: Inaweka maombi katika hali ya kusubiri hadi yaidhinishwe na meneja wa vyeti.
- **Enrolment Agents and Authorized Signatures**: Huaeleza idadi ya saini zinazohitajika kwenye CSR na Application Policy OIDs zinazohitajika.

### Mbinu za Kuomba Vyeti

Vyeti vinaweza kuombwa kupitia:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), kwa kutumia DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), kupitia named pipes au TCP/IP.
3. interface ya wavuti ya certificate enrollment, kwa kusakinisha Certificate Authority Web Enrollment role.
4. **Certificate Enrollment Service** (CES), kwa pamoja na huduma ya Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) kwa vifaa vya mtandao, ikitumia Simple Certificate Enrollment Protocol (SCEP).

Watumiaji wa Windows pia wanaweza kuomba vyeti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za command-line (`certreq.exe` au amri ya PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitishaji wa Vyeti

Active Directory (AD) inaunga mkono uthibitishaji wa vyeti, hasa ikitumia protokali za **Kerberos** na **Secure Channel (Schannel)**.

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la Ticket Granting Ticket (TGT) linasainiwa kwa kutumia **funguo binafsi** ya cheti cha mtumiaji. Ombi hili hupitia uthibitisho kadhaa na domain controller, ikiwa ni pamoja na **uhalali**, **mlolongo (path)**, na **hali ya kufutwa (revocation status)** ya cheti. Uthibitisho pia unajumuisha kuthibitisha kwamba cheti kimetoka kwa chanzo kinachotambulika na kuthibitisha uwepo wa mdhibitishaji katika **NTAUTH certificate store**. Uthibitisho uliofanikiwa husababisha kutolewa kwa TGT. Kitu cha **`NTAuthCertificates`** katika AD, kilicho katika:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ina jukumu kuu katika kuanzisha uaminifu kwa uthibitishaji wa cheti.

### Uthibitishaji wa Secure Channel (Schannel)

Schannel huwezesha muunganisho salama wa TLS/SSL, ambapo wakati wa handshake, mteja huwasilisha cheti ambacho, ikiwa kimethibitishwa kwa mafanikio, kinaruhusu upatikanaji. Ulinganifu wa cheti na akaunti ya AD unaweza kuhusisha kipengele cha Kerberos **S4U2Self** au **Subject Alternative Name (SAN)** ya cheti, miongoni mwa mbinu nyingine.

### AD Certificate Services Enumeration

Huduma za cheti za AD zinaweza kuorodheshwa kupitia maswali ya LDAP, zikifichua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** na usanidi wao. Hii inapatikana kwa mtumiaji yeyote aliyeathibitishwa kwenye domaine bila ruhusa maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** zinatumiwa kwa uorodheshaji na tathmini ya udhaifu katika mazingira ya AD CS.

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
## Marejeleo

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
