# Vyeti vya AD

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

### Vipengele vya Cheti

- **Subject** ya cheti huonyesha mmiliki wake.
- **Public Key** huunganishwa na ufunguo unaomilikiwa kwa siri ili kuunganisha cheti na mmiliki wake halali.
- **Validity Period**, inayofafanuliwa na tarehe za **NotBefore** na **NotAfter**, huonyesha muda ambao cheti kinatumika.
- **Serial Number** ya kipekee, inayotolewa na Certificate Authority (CA), hutambulisha kila cheti.
- **Issuer** humaanisha CA iliyotoa cheti.
- **SubjectAlternativeName** huruhusu majina mengine ya subject, na kuongeza unyumbufu wa utambulisho.
- **Basic Constraints** hubainisha kama cheti ni cha CA au cha huluki ya mwisho, na kufafanua vizuizi vya matumizi.
- **Extended Key Usages (EKUs)** hufafanua madhumuni mahususi ya cheti, kama vile kusaini msimbo au kusimba barua pepe, kupitia Object Identifiers (OIDs).
- **Signature Algorithm** hubainisha mbinu ya kusaini cheti.
- **Signature**, inayoundwa kwa kutumia ufunguo wa siri wa issuer, huhakikisha uhalisi wa cheti.<sup>[[4]](#references)</sup>

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** hupanua matumizi ya cheti ili kihusishe utambulisho mbalimbali, jambo muhimu kwa seva zenye domains nyingi. Michakato salama ya utoaji ni muhimu ili kuepuka hatari ya washambuliaji kujifanya wengine kwa kuchezea usanidi wa SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) katika Active Directory (AD)

AD CS hutambua vyeti vya CA katika AD forest kupitia containers maalum, kila moja ikiwa na jukumu lake la kipekee:<sup>[[4]](#references)</sup>

- Container ya **Certification Authorities** huhifadhi vyeti vya root CA vinavyoaminika.
- Container ya **Enrolment Services** hueleza Enterprise CAs na certificate templates zake.
- Object ya **NTAuthCertificates** hujumuisha vyeti vya CA vilivyoidhinishwa kwa uthibitishaji wa AD.
- Container ya **AIA (Authority Information Access)** hurahisisha uthibitishaji wa certificate chain kwa kutumia vyeti vya intermediate na cross CA.

### Upatikanaji wa Cheti: Mchakato wa Ombi la Cheti kutoka kwa Mteja

1. Mchakato wa ombi huanza kwa wateja kutafuta Enterprise CA.
2. CSR huundwa ikiwa na public key na maelezo mengine, baada ya kutengeneza jozi ya public-private key.
3. CA hukagua CSR kulingana na certificate templates zilizopo, kisha hutoa cheti kulingana na ruhusa za template.
4. Baada ya kuidhinishwa, CA husaini cheti kwa kutumia ufunguo wake wa siri na kumrejeshea mteja.<sup>[[4]](#references)</sup>

### Certificate Templates

Zinazofafanuliwa ndani ya AD, templates hizi huweka mipangilio na ruhusa za kutoa vyeti, ikiwemo EKUs zinazoruhusiwa na haki za uandikishaji au urekebishaji. Hizi ni muhimu katika kudhibiti ufikiaji wa huduma za vyeti.<sup>[[4]](#references)</sup>

**Toleo la schema la template ni muhimu.** Templates za zamani za **v1** (kwa mfano, template iliyojengewa ndani ya **WebServer**) hazina baadhi ya vidhibiti vya kisasa vya utekelezaji. Utafiti wa **ESC15/EKUwu** ulionyesha kuwa kwenye templates za **v1**, mwombaji anaweza kuingiza **Application Policies/EKUs** kwenye CSR, ambazo **hupewa kipaumbele kuliko** EKUs zilizosanidiwa kwenye template. Hii huwezesha kupata vyeti vya client-auth, enrollment agent, au code-signing kwa kutumia haki za uandikishaji pekee. Pendelea templates za **v2/v3**, ondoa au badilisha chaguomsingi za v1, na zuia EKUs zitumike kwa madhumuni yaliyokusudiwa pekee.<sup>[[1]](#references)</sup>

## Uandikishaji wa Vyeti

Mchakato wa uandikishaji wa vyeti huanzishwa na msimamizi **anayeunda certificate template**, ambayo kisha **huchapishwa** na Enterprise Certificate Authority (CA). Hii hufanya template ipatikane kwa wateja wanaotaka kujiandikisha; hatua hii hutekelezwa kwa kuongeza jina la template kwenye sehemu ya `certificatetemplates` ya object ya Active Directory.<sup>[[4]](#references)</sup>

Ili mteja aombe cheti, lazima apewe **haki za uandikishaji**. Haki hizi hufafanuliwa na security descriptors kwenye certificate template na kwenye Enterprise CA yenyewe. Ruhusa lazima zitolewe katika sehemu zote mbili ili ombi lifanikiwe.

### Haki za Uandikishaji za Template

Haki hizi hubainishwa kupitia Access Control Entries (ACEs), zinazofafanua ruhusa kama vile:

- Haki za **Certificate-Enrollment** na **Certificate-AutoEnrollment**, kila moja ikiwa na GUID maalum.
- **ExtendedRights**, zinazoruhusu ruhusa zote zilizopanuliwa.
- **FullControl/GenericAll**, zinazotoa udhibiti kamili wa template.

### Haki za Uandikishaji za Enterprise CA

Haki za CA zimeorodheshwa kwenye security descriptor yake, inayoweza kufikiwa kupitia console ya usimamizi ya Certificate Authority. Baadhi ya mipangilio huruhusu hata watumiaji wenye ruhusa chache kupata ufikiaji wa mbali, jambo linaloweza kuwa hatari ya kiusalama.

### Vidhibiti vya Ziada vya Utoaji

Vidhibiti fulani vinaweza kutumika, kama vile:

- **Manager Approval**: Huweka maombi katika hali ya kusubiri hadi yaidhinishwe na msimamizi wa vyeti.
- **Enrolment Agents and Authorized Signatures**: Hubainisha idadi ya sahihi zinazohitajika kwenye CSR na Application Policy OIDs zinazohitajika.

### Mbinu za Kuomba Vyeti

Vyeti vinaweza kuombwa kupitia:

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

## Uthibitishaji wa Cheti

Active Directory (AD) inasaidia uthibitishaji wa cheti, hasa kwa kutumia itifaki za **Kerberos** na **Secure Channel (Schannel)**.

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la kupata Ticket Granting Ticket (TGT) husainiwa kwa kutumia **private key** ya cheti cha mtumiaji. Ombi hili hufanyiwa ukaguzi kadhaa na domain controller, ikiwemo **uhalali**, **njia**, na **hali ya kubatilishwa** kwa cheti. Ukaguzi huu pia unajumuisha kuthibitisha kuwa cheti kimetoka kwenye chanzo kinachoaminika na kuthibitisha kuwa mtoaji wake yupo kwenye **NTAUTH certificate store**. Ukaguzi ukifaulu, TGT hutolewa. Kitu cha **`NTAuthCertificates`** katika AD kinapatikana kwenye:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ni muhimu katika kuanzisha uaminifu kwa uthibitishaji wa cheti.<sup>[[4]](#references)</sup>

Tangu kuanza kwa **KB5014754**, uthibitishaji wa kisasa wa cheti cha Kerberos unahusu zaidi **nguvu ya ulinganishaji**, si EKUs pekee.<sup>[[2]](#references)</sup> Katika misitu iliyoimarishwa:

- Cheti chenye **UPN/DNS SAN** pekee huenda kisitoshe tena kuingia.
- KDC hupendelea **binding imara**, kwa kawaida **SID security extension** (`1.3.6.1.4.1.311.25.2`) au ulinganishaji imara uliofafanuliwa wazi katika `altSecurityIdentities`.
- Cheti kikikosa ulinganishaji imara, DC huandika **Kdcsvc Event ID 39/41** katika hali ya uoanifu na hukataa uthibitishaji katika hali ya utekelezaji.
- Katika njia mchanganyiko za mashambulizi, **ESC9/ESC16** ni muhimu kwa sababu huondoa SID extension kwenye vyeti vinavyotolewa; kisha wahusika hutegemea ulinganishaji uliofafanuliwa wazi au miundo ya SAN URL SID pale ambapo njia ya shambulizi inaiunga mkono.

### Uthibitishaji wa Secure Channel (Schannel)

Schannel huwezesha miunganisho salama ya TLS/SSL. Wakati wa handshake, mteja huwasilisha cheti ambacho, kikithibitishwa kwa mafanikio, huruhusu ufikiaji. Ulinganishaji wa cheti na akaunti ya AD unaweza kutumia kitendakazi cha Kerberos cha **S4U2Self** au **Subject Alternative Name (SAN)** ya cheti, miongoni mwa mbinu nyingine.<sup>[[4]](#references)</sup>

Schannel pia ni njia mbadala inayotumika kiutendaji wakati **PKINIT** haipatikani. Kwa mfano, ikiwa domain controller haina cheti kinachofaa cha **Smart Card Logon**, zana za `certipy auth`/PKINIT zinaweza kushindwa kupata TGT, lakini cheti hicho hicho bado kinaweza kutumika dhidi ya **LDAPS** au **LDAP StartTLS** kwa uthibitishaji na shughuli za LDAP.

### Uhesabuji wa Huduma za Vyeti za AD

Huduma za vyeti za AD zinaweza kuhesabiwa kupitia maswali ya LDAP, na kufichua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** na usanidi wake. Mtumiaji yeyote aliyethibitishwa katika domain anaweza kupata taarifa hizi bila ruhusa maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** hutumika kwa uhesabuji na tathmini ya udhaifu katika mazingira ya AD CS.

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

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnerabilities za Hivi Karibuni na Masasisho ya Usalama (2022-2025)

| Mwaka | ID / Jina | Athari | Mambo Muhimu ya Kuzingatia |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Kuongeza ruhusa* kwa kughushi machine account certificates wakati wa PKINIT. | Kiraka kimejumuishwa kwenye masasisho ya usalama ya **May 10 2022**. Vidhibiti vya ukaguzi na strong-mapping vilianzishwa kupitia **KB5014754**; mazingira sasa yanapaswa kuwa katika hali ya *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Utekelezaji wa msimbo kwa mbali* katika majukumu ya AD CS Web Enrollment (certsrv) na CES. | PoCs za umma ni chache, lakini vipengele vya IIS vilivyo hatarini mara nyingi huwekwa wazi ndani ya mtandao. Weka kiraka kilichotolewa kwenye Patch Tuesday ya **July 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Kwenye **v1 templates**, mwombaji mwenye ruhusa za enrollment anaweza kupachika **Application Policies/EKUs** katika CSR, ambazo hupewa kipaumbele kuliko EKUs za template, na hivyo kutoa vyeti vya client-auth, enrollment agent, au code-signing. | Ilipatiwa kiraka kufikia **November 12, 2024**. Badilisha au weka v1 templates nyingine zinazochukua nafasi yake (kwa mfano, WebServer chaguomsingi), punguza EKUs kulingana na madhumuni, na punguza ruhusa za enrollment. |

### Ratiba ya Microsoft ya kuimarisha usalama (KB5014754)

Microsoft ilianzisha utekelezaji wa awamu tatu (Compatibility → Audit → Enforcement) ili kuhamisha uthibitishaji wa cheti wa Kerberos kutoka kwenye mappings dhaifu zisizo wazi. Kufikia **February 11, 2025**, domain controllers hubadilika kiotomatiki kwenda **Full Enforcement** ikiwa thamani ya registry ya `StrongCertificateBindingEnforcement` haijawekwa. Baadaye Microsoft ilisasisha ratiba ili kuruhusu kurejea kwenye hali ya compatibility hadi sasisho la usalama la **September 9, 2025**.<sup>[[2]](#references)</sup> Wasimamizi wanapaswa:

1. Kuweka viraka kwenye DCs na seva zote za AD CS (May 2022 au baadaye).
2. Kufuatilia Event ID 39/41 ili kubaini mappings dhaifu wakati wa awamu ya *Audit*.
3. Kutoa upya vyeti vya client-auth kwa kutumia **SID extension** mpya, au kusanidi mappings madhubuti za mwongozo kabla enforcement haijazuia mappings dhaifu.

### Maelezo kwa waendeshaji wa forests zilizoimarishwa usalama

- **ESC1/ESC6 pekee si simulizi zima tena** katika mazingira ya 2025 na baadaye. Ukiomba cheti cha principal mwingine, kwa kawaida unahitaji pia ushahidi wa strong mapping, kama SID extension au mapping iliyowekwa wazi.
- **ESC15 (EKUwu)** ina manufaa zaidi katika mazingira ambayo hayajapewa viraka, kwa sababu hubadilisha templates zisizo hatari za **v1** kama **WebServer** na kuwa vyeti vinavyoweza kutumika kwa authentication au enrollment agent kwa kuingiza **Application Policies**. Kerberos PKINIT bado hutathmini EKUs, lakini **LDAP Schannel** pia huzingatia Application Policies, hivyo matumizi mabaya yanayotegemea LDAP bado yanawezekana.<sup>[[1]](#references)</sup>
- **ESC16** ni mpangilio unaohusu CA nzima: CA ikizima SID security extension kwa jumla, kila cheti kinachotolewa hurudi kwenye tabia dhaifu zaidi ya mapping isipokuwa msururu wa mashambulizi uingize SID kwa umbizo jingine linaloungwa mkono.
- **Ruhusa za ESC7 ni tofauti:** ruhusa ya `ManageCA` kwenye CA inaweza kuruhusu mabadiliko ya mipangilio kama `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), huku `ManageCertificates` ikidhibiti uidhinishaji wa maombi. Deny iliyowekwa wazi kwa ruhusa za certificate-manager inaweza kuzuia njia hiyo ya uidhinishaji hata kama Allow pia ipo; tathmini ACL inayotumika ya CA kabla ya kuunganisha mipangilio na templates. Tazama [tathmini ya CA ACL ya Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Maboresho ya Ugunduzi na Uimarishaji wa Usalama

* **Defender for Identity AD CS sensor (2023-2024)** sasa huonyesha tathmini za hali ya usalama kwa ESC1-ESC8/ESC11 na kutoa arifa za wakati halisi kama *“Utoaji wa cheti cha domain-controller kwa kifaa kisicho DC”* (ESC8) na *“Zuia Certificate Enrollment kwa kutumia Application Policies holela”* (ESC15). Hakikisha sensors zimesakinishwa kwenye seva zote za AD CS ili kunufaika na ugunduzi huu.<sup>[[3]](#references)</sup>
* Zima au punguza kwa ukali chaguo la **“Supply in the request”** kwenye templates zote; pendelea thamani za SAN/EKU zilizofafanuliwa wazi.
* Ondoa **Any Purpose** au **No EKU** kwenye templates isipokuwa ni lazima kabisa (hushughulikia hali za ESC2).
* Hitaji **idhini ya meneja** au taratibu maalum za Enrollment Agent kwa templates nyeti (kwa mfano, WebServer / CodeSigning).
* Punguza ufikiaji wa web enrollment (`certsrv`) na endpoints za CES/NDES kwa mitandao inayoaminika au ziweke nyuma ya client-certificate authentication.
* Tekeleza usimbaji fiche wa RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) ili kupunguza ESC11 (RPC relay). Bendera hii **imewashwa kwa chaguomsingi**, lakini mara nyingi huzimwa kwa ajili ya clients za zamani, jambo linalofungua tena hatari ya relay.
* Linda **IIS-based enrollment endpoints** (CES/Certsrv): zima NTLM inapowezekana au hitaji HTTPS + Extended Protection ili kuzuia ESC8 relays.

Tathmini ESC11 kwenye host inayoendesha CA, ambayo inaweza kuwa seva mwanachama wa domain badala ya domain controller. Soma `InterfaceFlags` ya CA inayotumika chini ya `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; thamani isiyoweza kusomwa au ambayo haipo inamaanisha matokeo hayajulikani, si uthibitisho kwamba usimbaji fiche wa RPC umezimwa. Biti ya `IF_ENFORCEENCRYPTICERTREQUEST` ikiwa wazi ni ishara ya kuchunguza usanidi, lakini bado kunahitajika enrollment RPC endpoint inayofikika, credentials zinazoweza kushurutishwa, na certificate template inayoweza kutumika. Kwa ESC8, changamoto ya HTTP NTLM pekee haitoshi: thibitisha kuwa kuna enrollment endpoint inayofanya kazi.

---

## References

- [1] [EKUwu: Si ESC nyingine tu ya AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Mabadiliko ya authentication inayotegemea vyeti kwenye Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Tathmini za hali ya usalama wa vyeti - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Matumizi mabaya ya Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
