# Vyeti vya AD

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

### Vipengele vya Cheti

- **Subject** ya cheti huonyesha mmiliki wake.
- **Public Key** huunganishwa na ufunguo unaohifadhiwa kwa faragha ili kuhusisha cheti na mmiliki wake halali.
- **Validity Period**, inayofafanuliwa na tarehe za **NotBefore** na **NotAfter**, huonyesha muda ambao cheti kinatumika.
- **Serial Number** ya kipekee, inayotolewa na Certificate Authority (CA), hutambulisha kila cheti.
- **Issuer** humaanisha CA iliyotoa cheti.
- **SubjectAlternativeName** huruhusu majina ya ziada kwa subject, hivyo kuongeza unyumbufu wa utambulisho.
- **Basic Constraints** hutambua ikiwa cheti ni cha CA au end entity na kufafanua vizuizi vya matumizi.
- **Extended Key Usages (EKUs)** hufafanua madhumuni mahususi ya cheti, kama vile code signing au usimbaji fiche wa barua pepe, kupitia Object Identifiers (OIDs).
- **Signature Algorithm** hutaja mbinu inayotumika kusaini cheti.
- **Signature**, inayoundwa kwa kutumia ufunguo wa faragha wa issuer, huhakikisha uhalisi wa cheti.<sup>[[4]](#references)</sup>

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** huongeza matumizi ya cheti kwa identities nyingi, jambo muhimu kwa servers zenye domains nyingi. Michakato salama ya utoaji ni muhimu ili kuzuia hatari za impersonation zinazoweza kusababishwa na attackers wanaobadilisha maelezo ya SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) katika Active Directory (AD)

AD CS hutambua certificates za CA katika AD forest kupitia containers zilizotengwa, ambapo kila moja ina jukumu la kipekee:<sup>[[4]](#references)</sup>

- **Certification Authorities** container huhifadhi certificates zinazoaminika za root CA.
- **Enrolment Services** container hutoa maelezo kuhusu Enterprise CAs na certificate templates zao.
- **NTAuthCertificates** object hujumuisha certificates za CA zilizoidhinishwa kwa authentication ya AD.
- **AIA (Authority Information Access)** container hurahisisha uthibitishaji wa certificate chain kwa kutumia intermediate na cross CA certificates.

### Upataji wa Cheti: Mtiririko wa Ombi la Client Certificate

1. Mchakato wa ombi huanza clients wanapotafuta Enterprise CA.
2. CSR huundwa, ikiwa na public key na maelezo mengine, baada ya kutengeneza public-private key pair.
3. CA hutathmini CSR dhidi ya certificate templates zilizopo, kisha hutoa cheti kulingana na permissions za template.
4. Baada ya kuidhinishwa, CA husaini cheti kwa kutumia private key yake na kukirudisha kwa client.<sup>[[4]](#references)</sup>

### Certificate Templates

Zikiwa zimefafanuliwa ndani ya AD, templates hizi huainisha settings na permissions za kutoa certificates, ikiwemo EKUs zinazoruhusiwa pamoja na rights za enrollment au modification, ambazo ni muhimu katika kudhibiti access kwa certificate services.<sup>[[4]](#references)</sup>

**Toleo la schema la template ni muhimu.** Templates za zamani za **v1** (kwa mfano, template iliyojengwa ndani ya **WebServer**) hazina baadhi ya enforcement knobs za kisasa. Utafiti wa **ESC15/EKUwu** ulionyesha kuwa kwenye **v1 templates**, requester anaweza kuingiza **Application Policies/EKUs** katika CSR ambazo **hupewa kipaumbele kuliko** EKUs zilizosanidiwa kwenye template, na hivyo kuwezesha client-auth, enrollment agent, au code-signing certificates kwa kutumia enrollment rights pekee. Pendelea **v2/v3 templates**, ondoa au supersede v1 defaults, na punguza EKUs kwa ukaribu kulingana na madhumuni yaliyokusudiwa.<sup>[[1]](#references)</sup>

## Usajili wa Vyeti

Mchakato wa enrollment wa certificates huanzishwa na administrator ambaye **huunda certificate template**, ambayo baadaye **huchapishwa** na Enterprise Certificate Authority (CA). Hii hufanya template ipatikane kwa client enrollment, hatua inayotekelezwa kwa kuongeza jina la template kwenye sehemu ya `certificatetemplates` ya Active Directory object.<sup>[[4]](#references)</sup>

Ili client iweze kuomba cheti, **enrollment rights** lazima zitolewe. Rights hizi hufafanuliwa na security descriptors kwenye certificate template na Enterprise CA yenyewe. Permissions lazima zitolewe katika maeneo yote mawili ili ombi lifanikiwe.

### Template Enrollment Rights

Rights hizi hubainishwa kupitia Access Control Entries (ACEs), zinazofafanua permissions kama:

- **Certificate-Enrollment** na **Certificate-AutoEnrollment** rights, kila moja ikiwa inahusishwa na GUIDs maalum.
- **ExtendedRights**, zinazoruhusu extended permissions zote.
- **FullControl/GenericAll**, zinazotoa udhibiti kamili wa template.

### Enterprise CA Enrollment Rights

Rights za CA zimeainishwa katika security descriptor yake, inayoweza kufikiwa kupitia Certificate Authority management console. Baadhi ya settings huruhusu hata low-privileged users kupata remote access, jambo ambalo linaweza kuwa security concern.

### Vidhibiti vya Ziada vya Utoaji

Baadhi ya controls zinaweza kutumika, kama vile:

- **Manager Approval**: Hupeleka maombi katika hali ya pending hadi yaidhinishwe na certificate manager.
- **Enrolment Agents and Authorized Signatures**: Hubainisha idadi ya signatures zinazohitajika kwenye CSR na Application Policy OIDs zinazohitajika.

### Mbinu za Kuomba Certificates

Certificates zinaweza kuombwa kupitia:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), kwa kutumia DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), kupitia named pipes au TCP/IP.
3. **certificate enrollment web interface**, ikiwa Certificate Authority Web Enrollment role imewekwa.
4. **Certificate Enrollment Service** (CES), kwa kushirikiana na Certificate Enrollment Policy (CEP) service.
5. **Network Device Enrollment Service** (NDES) kwa network devices, kwa kutumia Simple Certificate Enrollment Protocol (SCEP).

Windows users pia wanaweza kuomba certificates kupitia GUI (`certmgr.msc` au `certlm.msc`) au command-line tools (`certreq.exe` au command ya PowerShell ya `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitishaji kwa Vyeti

Active Directory (AD) inaauni uthibitishaji kwa vyeti, hasa kwa kutumia itifaki za **Kerberos** na **Secure Channel (Schannel)**.

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la Ticket Granting Ticket (TGT) linasainiwa kwa kutumia **private key** ya cheti cha mtumiaji. Ombi hili hupitia uthibitishaji kadhaa unaofanywa na domain controller, ikiwemo **validity**, **path**, na hali ya **revocation** ya cheti. Uthibitishaji pia unajumuisha kuthibitisha kuwa cheti kinatoka kwenye chanzo kinachoaminika na kuthibitisha uwepo wa mtoaji wa cheti katika **NTAUTH certificate store**. Uthibitishaji ukifanikiwa, TGT hutolewa. Objekti ya **`NTAuthCertificates`** katika AD, inayopatikana kwenye:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ni muhimu katika kuanzisha uaminifu kwa certificate authentication.<sup>[[4]](#references)</sup>

Tangu kusambazwa kwa **KB5014754**, modern Kerberos certificate auth inahusu zaidi **mapping strength**, si EKUs pekee.<sup>[[2]](#references)</sup> Katika forests zilizoimarishwa:

- Certificate inayobeba tu **UPN/DNS SAN** huenda isitoshe tena kwa logon.
- KDC hupendelea **strong binding**, kwa kawaida **SID security extension** (`1.3.6.1.4.1.311.25.2`) au mapping thabiti iliyo wazi katika `altSecurityIdentities`.
- Ikiwa cert haina strong mapping, DCs huandika **Kdcsvc Event ID 39/41** katika compatibility mode na hukataa auth katika enforcement mode.
- Katika attack paths mchanganyiko, **ESC9/ESC16** ni muhimu kwa sababu huondoa SID extension kutoka kwenye certs zinazotolewa; operators hutegemea explicit mappings au SAN URL SID formats pale attack path inapoziauni.

### Schannel Authentication

Schannel huwezesha miunganisho salama ya TLS/SSL, ambapo wakati wa handshake, client huwasilisha certificate ambayo, ikiwa imethibitishwa kwa mafanikio, huidhinisha access. Mapping ya certificate kwa AD account inaweza kuhusisha function ya Kerberos **S4U2Self** au certificate’s **Subject Alternative Name (SAN)**, miongoni mwa methods nyingine.<sup>[[4]](#references)</sup>

Schannel pia ni fallback ya vitendo wakati **PKINIT** haipatikani. Kwa mfano, ikiwa domain controller haina certificate inayofaa ya **Smart Card Logon**, `certipy auth`/PKINIT tooling inaweza kushindwa kupata TGT, lakini certificate hiyo hiyo bado inaweza kutumika dhidi ya **LDAPS** au **LDAP StartTLS** kwa authentication na LDAP operations.

### AD Certificate Services Enumeration

Certificate services za AD zinaweza kuenumerate kupitia LDAP queries, na kufichua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** na configurations zake. Hii inapatikana kwa domain-authenticated user yeyote bila special privileges. Tools kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** hutumika kwa enumeration na vulnerability assessment katika mazingira ya AD CS.

Commands za kutumia tools hizi ni pamoja na:
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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* kupitia spoofing ya machine account certificates wakati wa PKINIT. | Patch imejumuishwa katika masasisho ya usalama ya **Mei 10, 2022**. Vidhibiti vya auditing na strong-mapping vilianzishwa kupitia **KB5014754**; mazingira yanapaswa sasa kuwa katika hali ya *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* katika AD CS Web Enrollment (certsrv) na majukumu ya CES. | Public PoCs ni chache, lakini vipengele vya IIS vilivyo hatarini mara nyingi huonekana ndani ya mtandao. Weka patch iliyotolewa kwenye Patch Tuesday ya **Julai 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Kwenye **v1 templates**, requester mwenye enrollment rights anaweza kuingiza **Application Policies/EKUs** kwenye CSR, ambazo hupewa kipaumbele kuliko template EKUs, na hivyo kutengeneza client-auth, enrollment agent, au code-signing certificates. | Iliwekewa patch kufikia **Novemba 12, 2024**. Badilisha au supersede v1 templates (kwa mfano, default WebServer), punguza EKUs kulingana na madhumuni, na punguza enrollment rights. |

### Ratiba ya Microsoft ya hardening (KB5014754)

Microsoft ilianzisha rollout ya awamu tatu (Compatibility → Audit → Enforcement) ili kuhamisha certificate authentication ya Kerberos kutoka implicit mappings dhaifu. Kufikia **Februari 11, 2025**, domain controllers hubadilika kiotomatiki kwenda **Full Enforcement** ikiwa registry value ya `StrongCertificateBindingEnforcement` haijawekwa. Baadaye Microsoft ilisasisha ratiba ili fallback kwenda compatibility mode iendelee kuwezekana hadi security update ya **Septemba 9, 2025**.<sup>[[2]](#references)</sup> Administrators wanapaswa:

1. Kuweka patch kwenye DCs zote na AD CS servers (Mei 2022 au baadaye).
2. Kufuatilia Event ID 39/41 kwa weak mappings wakati wa awamu ya *Audit*.
3. Kutoa tena client-auth certificates zenye **SID extension** mpya au kusanidi strong manual mappings kabla enforcement haijazuia weak mappings.

### Maelezo ya waendeshaji kwa forests zilizo-harden

- **ESC1/ESC6 pekee si tena hadithi nzima** katika mazingira ya 2025+. Ukiomba cert kwa niaba ya principal mwingine, kwa kawaida utahitaji pia strong mapping artifact kama SID extension au mapping iliyoainishwa wazi.
- **ESC15 (EKUwu)** ina umuhimu zaidi katika mazingira ambayo hayajawekewa patch kwa sababu hubadilisha **v1** templates zisizo na madhara, kama **WebServer**, kuwa authentication- au enrollment-agent-capable certs kwa kuingiza **Application Policies**. Kerberos PKINIT bado hutathmini EKUs, lakini **LDAP Schannel** pia huheshimu Application Policies, jambo linalofanya abuse inayotegemea LDAP iendelee kuwa muhimu.<sup>[[1]](#references)</sup>
- **ESC16** ni setting inayohusu CA nzima: ikiwa CA itazima SID security extension kimataifa, kila certificate inayotolewa itarejea kwenye tabia dhaifu zaidi ya mapping isipokuwa attack chain iingize SID kwa format nyingine inayotumika.

---

## Maboresho ya Detection na Hardening

* **Defender for Identity AD CS sensor (2023-2024)** sasa huonyesha posture assessments za ESC1-ESC8/ESC11 na hutengeneza alerts za wakati halisi kama *“Domain-controller certificate issuance for a non-DC”* (ESC8) na *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Hakikisha sensors zimewekwa kwenye AD CS servers zote ili kunufaika na detections hizi.<sup>[[3]](#references)</sup>
* Zima au punguza kwa ukali scope ya chaguo la **“Supply in the request”** kwenye templates zote; pendelea SAN/EKU values zilizobainishwa wazi.
* Ondoa **Any Purpose** au **No EKU** kwenye templates isipokuwa zinahitajika kabisa (hushughulikia scenarios za ESC2).
* Hitaji **manager approval** au Enrollment Agent workflows maalum kwa templates nyeti (kwa mfano, WebServer / CodeSigning).
* Punguza web enrollment (`certsrv`) na CES/NDES endpoints kwenye trusted networks au ziweke nyuma ya client-certificate authentication.
* Imarisha RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) ili kupunguza ESC11 (RPC relay). Flag hii **imewezeshwa kwa default**, lakini mara nyingi huzimwa kwa legacy clients, jambo linalofungua tena relay risk.
* Linda **IIS-based enrollment endpoints** (CES/Certsrv): zima NTLM inapowezekana au hitaji HTTPS + Extended Protection ili kuzuia ESC8 relays.

---

## Marejeo

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
