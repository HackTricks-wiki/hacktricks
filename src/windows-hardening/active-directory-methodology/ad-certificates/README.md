# Vyeti vya AD

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

### Vipengele vya Cheti

- **Subject** ya cheti huonyesha mmiliki wake.
- **Public Key** huunganishwa na key inayoshikiliwa kwa siri ili kuhusisha cheti na mmiliki wake halali.
- **Validity Period**, inayofafanuliwa na tarehe za **NotBefore** na **NotAfter**, huonyesha muda ambao cheti kinafanya kazi.
- **Serial Number** ya kipekee, inayotolewa na Certificate Authority (CA), hutambulisha kila cheti.
- **Issuer** humaanisha CA iliyotoa cheti.
- **SubjectAlternativeName** huruhusu majina ya ziada ya subject, hivyo kuongeza unyumbufu wa utambulisho.
- **Basic Constraints** hutambulisha ikiwa cheti ni cha CA au cha end entity, na hufafanua vizuizi vya matumizi.
- **Extended Key Usages (EKUs)** huainisha madhumuni mahususi ya cheti, kama code signing au usimbaji fiche wa barua pepe, kupitia Object Identifiers (OIDs).
- **Signature Algorithm** hubainisha mbinu ya kusaini cheti.
- **Signature**, inayoundwa kwa kutumia private key ya issuer, huhakikisha uhalisi wa cheti.<sup>[[1]](#references)</sup>

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** hupanua matumizi ya cheti kwa identities nyingi, jambo muhimu kwa servers zenye domains nyingi. Michakato salama ya utoaji ni muhimu ili kuzuia hatari za impersonation zinazoweza kusababishwa na attackers wanaobadilisha maelezo ya SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) katika Active Directory (AD)

AD CS hutambua CA certificates katika AD forest kupitia containers maalum, kila mmoja akiwa na jukumu la kipekee:<sup>[[1]](#references)</sup>

- Container ya **Certification Authorities** huhifadhi root CA certificates zinazoaminika.
- Container ya **Enrolment Services** hutoa maelezo kuhusu Enterprise CAs na certificate templates zao.
- Object ya **NTAuthCertificates** hujumuisha CA certificates zilizoidhinishwa kwa AD authentication.
- Container ya **AIA (Authority Information Access)** hurahisisha uthibitishaji wa certificate chain kwa kutumia intermediate na cross CA certificates.

### Upatikanaji wa Cheti: Mtiririko wa Ombi la Client Certificate

1. Mchakato wa ombi huanza clients wanapotafuta Enterprise CA.
2. CSR huundwa ikiwa na public key na maelezo mengine, baada ya kutengeneza public-private key pair.
3. CA huchunguza CSR dhidi ya certificate templates zinazopatikana, na kutoa cheti kulingana na permissions za template.
4. Baada ya kuidhinishwa, CA husaini cheti kwa private key yake na kukirudisha kwa client.<sup>[[1]](#references)</sup>

### Certificate Templates

Zikiwa zimefafanuliwa ndani ya AD, templates hizi huainisha settings na permissions za kutoa certificates, zikiwemo EKUs zinazoruhusiwa pamoja na enrollment au modification rights, ambazo ni muhimu kwa kusimamia access ya certificate services.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Mchakato wa enrollment wa certificates huanzishwa na administrator ambaye **huunda certificate template**, kisha **huchapishwa** na Enterprise Certificate Authority (CA). Hii hufanya template ipatikane kwa client enrollment, hatua inayotekelezwa kwa kuongeza jina la template kwenye field ya `certificatetemplates` ya Active Directory object.<sup>[[1]](#references)</sup>

Ili client iweze kuomba cheti, **enrollment rights** lazima zitolewe. Rights hizi hufafanuliwa na security descriptors kwenye certificate template na Enterprise CA yenyewe. Permissions lazima zitolewe katika maeneo yote mawili ili ombi lifanikiwe.<sup>[[1]](#references)</sup>

### Template Enrollment Rights

Rights hizi hubainishwa kupitia Access Control Entries (ACEs), zinazofafanua permissions kama:<sup>[[1]](#references)</sup>

- **Certificate-Enrollment** na **Certificate-AutoEnrollment** rights, kila moja ikihusishwa na GUIDs maalum.
- **ExtendedRights**, zinazoruhusu extended permissions zote.
- **FullControl/GenericAll**, zinazotoa udhibiti kamili wa template.

### Enterprise CA Enrollment Rights

Rights za CA zimeainishwa katika security descriptor yake, inayoweza kufikiwa kupitia Certificate Authority management console. Baadhi ya settings huruhusu hata low-privileged users kupata remote access, jambo linaloweza kuwa tatizo la usalama.<sup>[[1]](#references)</sup>

### Additional Issuance Controls

Baadhi ya controls zinaweza kutumika, kama vile:<sup>[[1]](#references)</sup>

- **Manager Approval**: Huweka maombi katika hali ya pending hadi yaidhinishwe na certificate manager.
- **Enrolment Agents and Authorized Signatures**: Hubainisha idadi ya signatures zinazohitajika kwenye CSR pamoja na Application Policy OIDs zinazohitajika.

### Methods to Request Certificates

Certificates zinaweza kuombwa kupitia:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), kwa kutumia DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), kupitia named pipes au TCP/IP.
3. **certificate enrollment web interface**, ikiwa Certificate Authority Web Enrollment role imewekwa.
4. **Certificate Enrollment Service** (CES), kwa kushirikiana na Certificate Enrollment Policy (CEP) service.
5. **Network Device Enrollment Service** (NDES) kwa network devices, kwa kutumia Simple Certificate Enrollment Protocol (SCEP).

Windows users wanaweza pia kuomba certificates kupitia GUI (`certmgr.msc` au `certlm.msc`) au command-line tools (`certreq.exe` au command ya PowerShell ya `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitishaji wa Certificate

Active Directory (AD) inasaidia uthibitishaji wa certificate, hasa kwa kutumia protocols za **Kerberos** na **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la Ticket Granting Ticket (TGT) husainiwa kwa kutumia **private key** ya certificate ya mtumiaji. Ombi hili hupitia validations kadhaa na domain controller, zikiwemo **validity**, **path**, na **revocation status** ya certificate. Validations pia hujumuisha kuthibitisha kwamba certificate imetoka kwenye chanzo kinachoaminika na kuthibitisha uwepo wa issuer katika **NTAUTH certificate store**. Validations zikifaulu, TGT hutolewa. Object ya **`NTAuthCertificates`** katika AD, inayopatikana katika:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ni msingi wa kuanzisha trust kwa certificate authentication.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Schannel huwezesha miunganisho salama ya TLS/SSL, ambapo wakati wa handshake, client huwasilisha certificate ambayo, ikithibitishwa kwa mafanikio, huidhinisha ufikiaji.<sup>[[2]](#references)</sup> Uhusishaji wa certificate na account ya AD unaweza kuhusisha function ya Kerberos ya **S4U2Self** au **Subject Alternative Name (SAN)** ya certificate, miongoni mwa mbinu nyingine.<sup>[[1]](#references)</sup>

### AD Certificate Services Enumeration

Certificate services za AD zinaweza ku-enumerate kupitia LDAP queries, na kufichua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** pamoja na configurations zake. Hii inapatikana kwa user yeyote aliye-authenticate kwenye domain bila privileges maalum.<sup>[[1]](#references)</sup> Tools kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** hutumika kwa enumeration na vulnerability assessment katika mazingira ya AD CS.<sup>[[3]](#references)</sup>

Commands za kutumia tools hizi ni pamoja na:
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

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Uthibitishaji wa Mteja wa SSL/TLS Ni Nini na Unafanyaje Kazi?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
