# Vyeti vya AD

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

### Vipengele vya Cheti

- **Subject** ya cheti humtambulisha mmiliki wake.
- **Public Key** huunganishwa na ufunguo unaohifadhiwa kwa siri ili kuunganisha cheti na mmiliki wake halali.
- **Validity Period**, inayobainishwa na tarehe za **NotBefore** na **NotAfter**, huonyesha muda ambao cheti ni halali.
- **Serial Number** ya kipekee, inayotolewa na Certificate Authority (CA), hutambulisha kila cheti.
- **Issuer** humaanisha CA iliyotoa cheti.
- **SubjectAlternativeName** huruhusu kuongeza majina mengine ya subject, na hivyo kuboresha unyumbufu wa utambulisho.
- **Basic Constraints** hubainisha kama cheti ni cha CA au cha huluki ya mwisho, na kufafanua vikwazo vya matumizi.
- **Extended Key Usages (EKUs)** hufafanua madhumuni mahususi ya cheti, kama vile kusaini msimbo au kusimba barua pepe kwa njia fiche, kupitia Object Identifiers (OIDs).
- **Signature Algorithm** hubainisha mbinu ya kusaini cheti.
- **Signature**, inayoundwa kwa ufunguo binafsi wa issuer, huhakikisha uhalisi wa cheti.<sup>[[4]](#references)</sup>

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** hupanua matumizi ya cheti kwa utambulisho mbalimbali, jambo muhimu kwa seva zenye domains nyingi. Michakato salama ya utoaji wa vyeti ni muhimu ili kuepuka hatari za kujifanya mtu mwingine, zinazoweza kusababishwa na washambuliaji wanaobadilisha vipimo vya SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) katika Active Directory (AD)

AD CS hutambua vyeti vya CA katika AD forest kupitia containers maalum, kila moja ikiwa na jukumu lake la kipekee:<sup>[[4]](#references)</sup>

- Container ya **Certification Authorities** huhifadhi vyeti vinavyoaminika vya root CA.
- Container ya **Enrolment Services** inaeleza Enterprise CAs na certificate templates zake.
- Object ya **NTAuthCertificates** inajumuisha vyeti vya CA vilivyoidhinishwa kwa uthibitishaji wa AD.
- Container ya **AIA (Authority Information Access)** hurahisisha uthibitishaji wa certificate chain kwa kutumia intermediate na cross CA certificates.

### Upatikanaji wa Cheti: Mtiririko wa Ombi la Cheti cha Mteja

1. Mchakato wa ombi huanza kwa clients kutafuta Enterprise CA.
2. CSR huundwa ikiwa na public key na maelezo mengine, baada ya kuzalisha jozi ya public-private key.
3. CA hukagua CSR dhidi ya certificate templates zilizopo, kisha hutoa cheti kulingana na ruhusa za template.
4. Ombi likiidhinishwa, CA husaini cheti kwa private key yake na kukirejesha kwa client.<sup>[[4]](#references)</sup>

### Certificate Templates

Zilizofafanuliwa ndani ya AD, templates hizi huweka mipangilio na ruhusa za kutoa vyeti, ikiwemo EKUs zinazoruhusiwa na haki za kujiandikisha au kufanya mabadiliko. Hili ni muhimu katika kudhibiti ufikiaji wa huduma za vyeti.<sup>[[4]](#references)</sup>

**Toleo la schema la template ni muhimu.** Templates za zamani za **v1** (kwa mfano, template ya ndani ya **WebServer**) hazina baadhi ya vidhibiti vya kisasa vya utekelezaji. Utafiti wa **ESC15/EKUwu** ulionyesha kuwa kwenye **v1 templates**, mwombaji anaweza kuweka **Application Policies/EKUs** ndani ya CSR, na hizo **hupewa kipaumbele kuliko** EKUs zilizosanidiwa kwenye template. Hii huwezesha kupata vyeti vya client-auth, enrollment agent, au code-signing kwa kutumia haki za kujiandikisha pekee. Pendelea **v2/v3 templates**, ondoa au badilisha defaults za v1, na weka EKUs kwa madhumuni yaliyokusudiwa pekee.<sup>[[1]](#references)</sup>

## Uandikishaji wa Cheti

Mchakato wa kujiandikisha kupata vyeti huanzishwa na msimamizi **anayeunda certificate template**, ambayo baadaye **huchapishwa** na Enterprise Certificate Authority (CA). Hii hufanya template ipatikane kwa ajili ya clients kujiandikisha, hatua inayotekelezwa kwa kuongeza jina la template kwenye sehemu ya `certificatetemplates` ya object ya Active Directory.<sup>[[4]](#references)</sup>

Ili client iweze kuomba cheti, ni lazima ipewe **haki za kujiandikisha**. Haki hizi hufafanuliwa na security descriptors kwenye certificate template na Enterprise CA yenyewe. Ruhusa lazima zitolewe katika maeneo yote mawili ili ombi lifanikiwe.

### Haki za Kujiandikisha za Template

Haki hizi hubainishwa kupitia Access Control Entries (ACEs), zinazoeleza ruhusa kama vile:

- Haki za **Certificate-Enrollment** na **Certificate-AutoEnrollment**, kila moja ikihusishwa na GUID maalum.
- **ExtendedRights**, zinazoruhusu ruhusa zote zilizopanuliwa.
- **FullControl/GenericAll**, zinazotoa udhibiti kamili wa template.

### Haki za Kujiandikisha za Enterprise CA

Haki za CA zimeainishwa kwenye security descriptor yake, inayoweza kufikiwa kupitia console ya usimamizi wa Certificate Authority. Baadhi ya mipangilio huruhusu hata watumiaji wenye ruhusa ndogo kufikia mfumo kwa mbali, jambo linaloweza kuwa hatari ya usalama.

### Vidhibiti vya Ziada vya Utoaji

Baadhi ya vidhibiti vinaweza kutumika, kama vile:

- **Manager Approval**: Huweka maombi katika hali ya kusubiri hadi yaidhinishwe na msimamizi wa vyeti.
- **Enrolment Agents and Authorized Signatures**: Hubainisha idadi ya sahihi zinazohitajika kwenye CSR na OIDs za Application Policy zinazohitajika.

### Mbinu za Kuomba Vyeti

Vyeti vinaweza kuombwa kupitia:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), kwa kutumia DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), kupitia named pipes au TCP/IP.
3. **certificate enrollment web interface**, ikiwa jukumu la Certificate Authority Web Enrollment limesakinishwa.
4. **Certificate Enrollment Service** (CES), kwa kushirikiana na huduma ya Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) kwa vifaa vya mtandao, kwa kutumia Simple Certificate Enrollment Protocol (SCEP).

Watumiaji wa Windows wanaweza pia kuomba vyeti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za command-line (`certreq.exe` au amri ya PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Uthibitishaji wa Cheti

Active Directory (AD) hutumia uthibitishaji wa cheti, hasa kupitia itifaki za **Kerberos** na **Secure Channel (Schannel)**.

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la Ticket Granting Ticket (TGT) husainiwa kwa kutumia **private key** ya cheti cha mtumiaji. Ombi hili hukaguliwa mara kadhaa na domain controller, ikijumuisha **uhalali**, **mfuatano wa cheti**, na **hali ya kufutwa** kwa cheti. Ukaguzi pia hujumuisha kuthibitisha kuwa cheti kinatoka kwenye chanzo kinachoaminika na kuthibitisha uwepo wa mtoaji katika **NTAUTH certificate store**. Ukaguzi ukifaulu, TGT hutolewa. Kitu cha **`NTAuthCertificates`** katika AD kinapatikana katika:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ni muhimu katika kuweka msingi wa uaminifu kwa uthibitishaji wa certificate.<sup>[[4]](#references)</sup>

Tangu kuanza kutolewa kwa **KB5014754**, uthibitishaji wa kisasa wa Kerberos kwa kutumia certificate unahusu zaidi **nguvu ya mapping**, si EKU pekee.<sup>[[2]](#references)</sup> Katika forest zilizoimarishwa:

- Certificate yenye **UPN/DNS SAN** pekee huenda isitoshe tena kwa logon.
- KDC hupendelea **strong binding**, kwa kawaida **SID security extension** (`1.3.6.1.4.1.311.25.2`) au explicit mapping thabiti katika `altSecurityIdentities`.
- Ikiwa cert haina strong mapping, DC huandika **Kdcsvc Event ID 39/41** katika compatibility mode na hukataa auth katika enforcement mode.
- Katika njia mseto za attack, **ESC9/ESC16** ni muhimu kwa sababu huondoa SID extension kutoka kwenye cert zinazotolewa; kisha operators hutegemea explicit mappings au miundo ya SAN URL SID pale ambapo njia ya attack inaiunga mkono.

### Uthibitishaji wa Secure Channel (Schannel)

Schannel huwezesha miunganisho salama ya TLS/SSL; wakati wa handshake, client huwasilisha certificate ambayo, ikithibitishwa kwa mafanikio, huidhinisha ufikiaji. Ulinganishaji wa certificate na akaunti ya AD unaweza kuhusisha function ya Kerberos ya **S4U2Self** au **Subject Alternative Name (SAN)** ya certificate, pamoja na mbinu nyingine.<sup>[[4]](#references)</sup>

Schannel pia ndiyo fallback inayotumika kiutendaji wakati **PKINIT** haipatikani. Kwa mfano, ikiwa domain controller haina certificate inayofaa ya **Smart Card Logon**, `certipy auth`/zana za PKINIT zinaweza kushindwa kupata TGT, lakini certificate hiyo hiyo bado inaweza kutumika dhidi ya **LDAPS** au **LDAP StartTLS** kwa uthibitishaji na shughuli za LDAP.

### Uhesabuji wa AD Certificate Services

Certificate services za AD zinaweza kuhesabiwa kupitia LDAP queries, zikifichua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** na usanidi wake. Taarifa hizi zinaweza kufikiwa na mtumiaji yeyote aliyethibitishwa kwenye domain bila ruhusa maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** hutumika kwa uhesabuji na tathmini ya udhaifu katika mazingira ya AD CS.

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

## Udhaifu wa Hivi Karibuni na Masasisho ya Usalama (2022-2025)

| Mwaka | ID / Jina | Athari | Mambo Muhimu ya Kuzingatia |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Kupandisha mamlaka* kwa kughushi vyeti vya akaunti za mashine wakati wa PKINIT. | Kiraka kimejumuishwa kwenye masasisho ya usalama ya **May 10 2022**. Udhibiti wa ukaguzi na strong-mapping ulianzishwa kupitia **KB5014754**; mazingira yanapaswa sasa kuwa katika hali ya *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Utekelezaji wa msimbo wa mbali* katika majukumu ya AD CS Web Enrollment (certsrv) na CES. | PoC za hadharani ni chache, lakini vipengele vilivyo hatarini vya IIS mara nyingi huonekana ndani ya mtandao. Tumia kiraka kilichotolewa kwenye Patch Tuesday ya **July 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Kwenye **v1 templates**, mwombaji mwenye ruhusa za enrollment anaweza kupachika **Application Policies/EKUs** kwenye CSR, ambazo hupewa kipaumbele kuliko EKU za template, na hivyo kutoa vyeti vya client-auth, enrollment agent, au code-signing. | Ilifanyiwa kiraka kufikia **November 12, 2024**. Badilisha au weka templates za v1 mpya zaidi (kwa mfano, WebServer ya chaguomsingi), zuia EKU ziendane na matumizi yaliyokusudiwa, na punguza ruhusa za enrollment. |

### Ratiba ya Microsoft ya kuimarisha usalama (KB5014754)

Microsoft ilianzisha utoaji wa awamu tatu (Compatibility → Audit → Enforcement) ili kuhamisha uthibitishaji wa cheti cha Kerberos kutoka kwenye mappings dhaifu zisizo wazi. Kufikia **February 11, 2025**, domain controllers hubadilika kiotomatiki kwenda **Full Enforcement** ikiwa thamani ya registry ya `StrongCertificateBindingEnforcement` haijawekwa. Baadaye Microsoft ilisasisha ratiba ili kuruhusu kurejea kwenye hali ya compatibility hadi sasisho la usalama la **September 9, 2025**.<sup>[[2]](#references)</sup> Wasimamizi wanapaswa:

1. Kusasisha DC zote na seva za AD CS (May 2022 au toleo la baadaye).
2. Kufuatilia Event ID 39/41 ili kugundua mappings dhaifu wakati wa awamu ya *Audit*.
3. Kutoa upya vyeti vya client-auth kwa kutumia **SID extension** mpya au kusanidi mappings thabiti za mikono kabla enforcement haijazuia mappings dhaifu.

### Vidokezo kwa waendeshaji wa misitu iliyoimarishwa kiusalama

- **ESC1/ESC6 pekee si simulizi zima tena** katika mazingira ya 2025 na kuendelea. Ukiomba cheti cha principal mwingine, kwa kawaida utahitaji pia kipengele cha strong mapping, kama vile SID extension au mapping iliyoainishwa wazi.
- **ESC15 (EKUwu)** huwa na manufaa zaidi katika mazingira ambayo hayajafanyiwa viraka, kwa kuwa hubadilisha templates za **v1** zisizo na madhara kama **WebServer** kuwa vyeti vinavyoweza kutumika kwa uthibitishaji au kama enrollment agent kwa kuingiza **Application Policies**. Kerberos PKINIT bado hukagua EKU, lakini **LDAP Schannel** pia huzingatia Application Policies, hivyo matumizi mabaya yanayotegemea LDAP yanaendelea kuwa muhimu.<sup>[[1]](#references)</sup>
- **ESC16** ni mpangilio unaohusu CA nzima: CA ikizima SID security extension kwa ujumla, kila cheti kinachotolewa hurudi kwenye tabia ya mapping dhaifu zaidi, isipokuwa mnyororo wa shambulio uingize SID kwa umbizo jingine linaloungwa mkono.
- **Ruhusa za ESC7 ni tofauti:** ruhusa ya `ManageCA` kwenye CA inaweza kuruhusu mabadiliko ya mipangilio kama `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), ilhali `ManageCertificates` hudhibiti idhini ya maombi. Deny iliyoainishwa wazi kwa ruhusa za msimamizi wa vyeti inaweza kuzuia njia hiyo ya idhini hata kama Allow pia ipo; kagua CA ACL inayotumika kabla ya kuunganisha mipangilio na templates. Tazama [tathmini ya CA ACL ya Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Maboresho ya Ugunduzi na Uimarishaji wa Usalama

* **Defender for Identity AD CS sensor (2023-2024)** sasa huonyesha tathmini za hali ya usalama za ESC1-ESC8/ESC11 na kutoa arifa za wakati halisi kama *“Kutolewa kwa cheti cha domain controller kwa kifaa kisicho DC”* (ESC8) na *“Zuia Enrollment ya Vyeti kwa kutumia Application Policies holela”* (ESC15). Hakikisha sensa zimewekwa kwenye seva zote za AD CS ili kunufaika na ugunduzi huu.<sup>[[3]](#references)</sup>
* Zima au punguza kwa ukali chaguo la **“Supply in the request”** kwenye templates zote; pendelea kuweka thamani za SAN/EKU wazi.
* Ondoa **Any Purpose** au **No EKU** kwenye templates isipokuwa kama zinahitajika kabisa (hushughulikia hali za ESC2).
* Hitaji **idhini ya msimamizi** au taratibu maalum za Enrollment Agent kwa templates nyeti (kwa mfano, WebServer / CodeSigning).
* Zuia web enrollment (`certsrv`) na endpoint za CES/NDES zitumike kwenye mitandao inayoaminika pekee au ziweke nyuma ya uthibitishaji wa client-certificate.
* Lazimisha usimbaji fiche wa RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) ili kupunguza ESC11 (RPC relay). Bendera hii **huwa imewashwa kwa chaguomsingi**, lakini mara nyingi huzimwa kwa ajili ya clients za zamani, jambo linalofungua tena hatari ya relay.
* Linda **endpoint za enrollment zinazotumia IIS** (CES/Certsrv): zima NTLM inapowezekana au hitaji HTTPS + Extended Protection ili kuzuia ESC8 relay.

Tathmini ESC11 kwenye host inayoendesha CA, ambayo inaweza kuwa seva mwanachama wa domain badala ya domain controller. Soma `InterfaceFlags` ya CA inayotumika chini ya `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; thamani isiyoweza kusomeka au iliyokosekana huashiria matokeo yasiyojulikana, si uthibitisho kwamba usimbaji fiche wa RPC umezimwa. Biti ya `IF_ENFORCEENCRYPTICERTREQUEST` ikiwa haijawekwa, hilo ni kidokezo cha usanidi ambacho bado kinahitaji endpoint ya enrollment RPC inayoweza kufikiwa, credentials zinazoweza kulazimishwa, na certificate template inayoweza kutumika. Kwa ESC8, changamoto ya HTTP NTLM pekee haitoshi: thibitisha kuwa kuna endpoint ya enrollment inayofanya kazi.

---

## References

- [1] [EKUwu: Si ESC nyingine tu ya AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Mabadiliko ya uthibitishaji unaotegemea vyeti kwenye Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Tathmini za hali ya usalama wa vyeti - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Matumizi mabaya ya Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
