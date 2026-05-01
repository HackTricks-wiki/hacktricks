# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

### Vipengele vya Certificate

- **Subject** ya certificate inaonyesha mmiliki wake.
- **Public Key** huunganishwa na key iliyohifadhiwa kwa siri ili kuunganisha certificate na mmiliki wake halali.
- **Validity Period**, iliyofafanuliwa na tarehe za **NotBefore** na **NotAfter**, inaonyesha muda ambao certificate ni halali.
- **Serial Number** ya kipekee, inayotolewa na Certificate Authority (CA), hutambulisha kila certificate.
- **Issuer** inarejelea CA iliyotoa certificate.
- **SubjectAlternativeName** huruhusu majina ya ziada kwa subject, ikiboresha unyumbufu wa utambuzi.
- **Basic Constraints** hutambua ikiwa certificate ni ya CA au end entity na hufafanua vizuizi vya matumizi.
- **Extended Key Usages (EKUs)** huainisha madhumuni mahususi ya certificate, kama code signing au email encryption, kupitia Object Identifiers (OIDs).
- **Signature Algorithm** hubainisha njia ya kusaini certificate.
- **Signature**, iliyoundwa kwa private key ya issuer, huhakikisha uhalisia wa certificate.

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** huongeza matumizi ya certificate kwa identities nyingi, jambo muhimu kwa servers zenye domains nyingi. Michakato salama ya utoaji ni muhimu ili kuepuka hatari za kujifanya mtu mwingine kwa attackers wanaobadilisha SAN specification.

### Certificate Authorities (CAs) katika Active Directory (AD)

AD CS inatambua CA certificates ndani ya AD forest kupitia containers zilizoteuliwa, kila moja ikiwa na jukumu la kipekee:

- **Certification Authorities** container huhifadhi trusted root CA certificates.
- **Enrolment Services** container hutoa maelezo ya Enterprise CAs na certificate templates zake.
- **NTAuthCertificates** object inajumuisha CA certificates zilizoidhinishwa kwa AD authentication.
- **AIA (Authority Information Access)** container hurahisisha uthibitishaji wa certificate chain pamoja na intermediate na cross CA certificates.

### Kupata Certificate: Client Certificate Request Flow

1. Mchakato wa request huanza kwa clients kutafuta Enterprise CA.
2. CSR huundwa, ikiwa na public key na taarifa nyingine, baada ya kutengeneza public-private key pair.
3. CA hutathmini CSR dhidi ya certificate templates zilizopo, na kutoa certificate kulingana na permissions za template.
4. Baada ya kuidhinishwa, CA husaini certificate kwa private key yake na kuirudisha kwa client.

### Certificate Templates

Zinafafanuliwa ndani ya AD, templates hizi huainisha settings na permissions za kutoa certificates, ikijumuisha EKUs zinazoruhusiwa na enrollment au modification rights, muhimu kwa kusimamia access kwenye certificate services.

**Template schema version matters.** Legacy **v1** templates (for example, the built-in **WebServer** template) lack several modern enforcement knobs. The **ESC15/EKUwu** research showed that on **v1 templates**, a requester can embed **Application Policies/EKUs** in the CSR that are **preferred over** the template's configured EKUs, enabling client-auth, enrollment agent, or code-signing certificates with only enrollment rights. Prefer **v2/v3 templates**, remove or supersede v1 defaults, and tightly scope EKUs to the intended purpose.

## Certificate Enrollment

Mchakato wa enrollment wa certificates huanzishwa na administrator ambaye **huunda certificate template**, ambayo kisha **huchapishwa** na Enterprise Certificate Authority (CA). Hii hufanya template ipatikane kwa client enrollment, hatua inayofikiwa kwa kuongeza jina la template kwenye uwanja wa `certificatetemplates` wa object ya Active Directory.

Ili client aweze kuomba certificate, **enrollment rights** lazima zipewe. Rights hizi hufafanuliwa na security descriptors kwenye certificate template na Enterprise CA yenyewe. Permissions lazima zitolewe katika maeneo yote mawili ili request ifanikiwe.

### Template Enrollment Rights

Rights hizi hubainishwa kupitia Access Control Entries (ACEs), zikieleza permissions kama:

- **Certificate-Enrollment** na **Certificate-AutoEnrollment** rights, kila moja ikiwa na GUID mahususi.
- **ExtendedRights**, kuruhusu permissions zote zilizopanuliwa.
- **FullControl/GenericAll**, kutoa udhibiti kamili juu ya template.

### Enterprise CA Enrollment Rights

Rights za CA zimeainishwa kwenye security descriptor yake, inayopatikana kupitia Certificate Authority management console. Baadhi ya settings hata huruhusu users wenye privileges chache kupata remote access, jambo ambalo linaweza kuwa wasiwasi wa usalama.

### Additional Issuance Controls

Controls fulani zinaweza kutumika, kama:

- **Manager Approval**: Huweka request katika hali ya pending hadi iidhinishwe na certificate manager.
- **Enrolment Agents and Authorized Signatures**: Hubainisha idadi ya signatures zinazohitajika kwenye CSR na Application Policy OIDs zinazohitajika.

### Methods to Request Certificates

Certificates zinaweza kuombwa kupitia:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), kwa kutumia DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), kupitia named pipes au TCP/IP.
3. The **certificate enrollment web interface**, ikiwa role ya Certificate Authority Web Enrollment imesakinishwa.
4. **Certificate Enrollment Service** (CES), kwa pamoja na huduma ya Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) kwa network devices, kwa kutumia Simple Certificate Enrollment Protocol (SCEP).

Windows users wanaweza pia kuomba certificates kupitia GUI (`certmgr.msc` au `certlm.msc`) au command-line tools (`certreq.exe` au PowerShell's `Get-Certificate` command).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitishaji wa Certificate

Active Directory (AD) inasaidia uthibitishaji wa certificate, hasa ikitumia itifaki za **Kerberos** na **Secure Channel (Schannel)**.

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la Ticket Granting Ticket (TGT) husainiwa kwa kutumia **private key** ya certificate ya mtumiaji. Ombi hili hupitia uthibitisho kadhaa na domain controller, ikijumuisha **validity** ya certificate, **path**, na hali ya **revocation**. Uthibitisho pia hujumuisha kuthibitisha kuwa certificate inatoka kwenye chanzo kinachoaminika na kuthibitisha uwepo wa issuer katika **NTAUTH certificate store**. Uthibitisho uliofanikiwa husababisha utoaji wa TGT. Objekti ya **`NTAuthCertificates`** katika AD, inayopatikana katika:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ni muhimu sana katika kuanzisha uaminifu kwa uthibitishaji wa certificate.

Tangu usambazaji wa **KB5014754**, modern Kerberos certificate auth hasa unahusu **mapping strength**, si EKUs tu. Katika hardened forests:

- certificate inayobeba tu **UPN/DNS SAN** inaweza isiwe tena ya kutosha kwa logon.
- KDC hupendelea **strong binding**, kwa kawaida **SID security extension** (`1.3.6.1.4.1.311.25.2`) au strong explicit mapping katika `altSecurityIdentities`.
- Ikiwa cert haina strong mapping, DCs huweka kumbukumbu ya **Kdcsvc Event ID 39/41** katika compatibility mode na hukataa auth katika enforcement mode.
- Katika mixed attack paths, **ESC9/ESC16** ni muhimu kwa sababu huondoa SID extension kutoka kwa issued certs; operators basi hutegemea explicit mappings au SAN URL SID formats pale ambapo attack path inaziunga mkono.

### Secure Channel (Schannel) Authentication

Schannel huwezesha secure TLS/SSL connections, ambapo wakati wa handshake, client huwasilisha certificate ambayo, ikiwa imethibitishwa kwa mafanikio, huidhinisha access. Mapping ya certificate kwenda kwa AD account inaweza kuhusisha Kerberos’s **S4U2Self** function au certificate’s **Subject Alternative Name (SAN)**, miongoni mwa mbinu nyingine.

Schannel pia ni practical fallback wakati **PKINIT** haipatikani. Kwa mfano, ikiwa domain controller haina **Smart Card Logon** certificate inayofaa, `certipy auth`/PKINIT tooling inaweza kushindwa kupata TGT, lakini certificate hiyo hiyo bado inaweza kutumika dhidi ya **LDAPS** au **LDAP StartTLS** kwa uthibitishaji na LDAP operations.

### AD Certificate Services Enumeration

AD's certificate services zinaweza kuorodheshwa kupitia LDAP queries, zikifichua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** na configurations zao. Hii inapatikana kwa user yeyote aliyethibitishwa kwenye domain bila special privileges. Tools kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** hutumika kwa enumeration na vulnerability assessment katika mazingira ya AD CS.

Amri za kutumia hizi tools ni pamoja na:
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

## Athari za Hivi Karibuni & Sasisho za Usalama (2022-2025)

| Mwaka | ID / Jina | Athari | Mambo Muhimu ya Kuchukua |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* kwa kudanganya vyeti vya akaunti ya machine wakati wa PKINIT. | Patch imejumuishwa katika sasisho za usalama za **May 10 2022**. Ukaguzi & vidhibiti vya strong-mapping vilianzishwa kupitia **KB5014754**; mazingira sasa yanapaswa kuwa katika hali ya *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* katika AD CS Web Enrollment (certsrv) na majukumu ya CES. | Public PoCs ni chache, lakini vipengele vya IIS vilivyo hatarini mara nyingi vinaonekana ndani ya mtandao. Patch kuanzia **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Kwenye **v1 templates**, mtoa ombi aliye na enrollment rights anaweza kupachika **Application Policies/EKUs** kwenye CSR ambazo hupendelewa kuliko template EKUs, na kutoa vyeti vya client-auth, enrollment agent, au code-signing. | Imepatched kuanzia **November 12, 2024**. Badilisha au chukua nafasi ya v1 templates (kwa mfano, default WebServer), zuia EKUs kwa madhumuni yaliyokusudiwa, na punguza enrollment rights. |

### Ratiba ya hardening ya Microsoft (KB5014754)

Microsoft ilianzisha utekelezaji wa awamu tatu (Compatibility → Audit → Enforcement) ili kuhamisha Kerberos certificate authentication mbali na weak implicit mappings. Kuanzia **February 11, 2025**, domain controllers hubadilika kiotomatiki kwenda **Full Enforcement** ikiwa thamani ya registry `StrongCertificateBindingEnforcement` haijawekwa. Baadaye Microsoft ilisasisha ratiba hivyo fallback kwenda compatibility mode bado inawezekana hadi sasisho la usalama la **September 9, 2025**. Administrators wanapaswa:

1. Patch DCs zote & AD CS servers (May 2022 au baadaye).
2. Fuatilia Event ID 39/41 kwa weak mappings wakati wa hatua ya *Audit*.
3. Toa upya client-auth certificates zenye **SID extension** mpya au sanidi strong manual mappings kabla enforcement haijazuia weak mappings.

### Operator notes kwa forests zilizohardeniwa

- **ESC1/ESC6 pekee si tena hadithi nzima** katika mazingira ya 2025+. Ukimuomba cert kwa principal mwingine, kawaida pia utahitaji strong mapping artifact kama SID extension au explicit mapping.
- **ESC15 (EKUwu)** ni muhimu zaidi kwenye mazingira ambayo hayajapatched kwa sababu hugeuza **v1** templates zisizo na madhara kama **WebServer** kuwa certs zenye uwezo wa authentication- au enrollment-agent kwa kuingiza **Application Policies**. Kerberos PKINIT bado huzingatia EKUs, lakini **LDAP Schannel** pia hukubali Application Policies, jambo linaloifanya matumizi mabaya ya LDAP kubaki muhimu.
- **ESC16** ni CA-wide knob: ikiwa CA inazima SID security extension kwa ujumla, kila cert iliyotolewa hurudi kuelekea weak mapping behavior isipokuwa attack chain iingize SID kwa format nyingine inayoungwa mkono.

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** sasa huonyesha posture assessments kwa ESC1-ESC8/ESC11 na hutengeneza real-time alerts kama *“Domain-controller certificate issuance for a non-DC”* (ESC8) na *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Hakikisha sensors zimesambazwa kwa AD CS servers zote ili kufaidika na detections hizi.
* Zima au punguza kwa ukali chaguo la **“Supply in the request”** kwenye templates zote; tumia thamani za SAN/EKU zilizoainishwa wazi.
* Ondoa **Any Purpose** au **No EKU** kutoka templates isipokuwa ni lazima kabisa (inahusu ESC2 scenarios).
* Hitaji **manager approval** au workflows maalum za Enrollment Agent kwa templates nyeti (kwa mfano, WebServer / CodeSigning).
* Zuia web enrollment (`certsrv`) na endpoints za CES/NDES kwenye networks zinazoaminika au nyuma ya client-certificate authentication.
* Tekeleza RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) ili kupunguza ESC11 (RPC relay). Bendera hii iko **on by default**, lakini mara nyingi huzimwa kwa legacy clients, jambo linalofungua tena hatari ya relay.
* Linda **IIS-based enrollment endpoints** (CES/Certsrv): zima NTLM pale inapowezekana au hitaji HTTPS + Extended Protection ili kuzuia ESC8 relays.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
