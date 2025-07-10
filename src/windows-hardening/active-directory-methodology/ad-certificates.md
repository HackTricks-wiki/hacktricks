# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **Mada** ya cheti inaonyesha mmiliki wake.
- **Funguo za Umma** zimeunganishwa na funguo za kibinafsi ili kuunganisha cheti na mmiliki wake halali.
- **Muda wa Uhalali**, unaofafanuliwa na tarehe za **NotBefore** na **NotAfter**, inaashiria muda wa ufanisi wa cheti.
- Nambari ya **Serial** ya kipekee, inayotolewa na Mamlaka ya Cheti (CA), inatambulisha kila cheti.
- **Mtoaji** inahusisha CA ambayo imetoa cheti.
- **SubjectAlternativeName** inaruhusu majina ya ziada kwa mada, ikiongeza kubadilika kwa utambuzi.
- **Mipaka ya Msingi** inatambua ikiwa cheti ni kwa CA au kitengo cha mwisho na kufafanua vizuizi vya matumizi.
- **Matumizi ya Funguo ya Kupanuliwa (EKUs)** yanabainisha madhumuni maalum ya cheti, kama vile kusaini msimbo au usimbaji wa barua pepe, kupitia Vitambulisho vya Kitu (OIDs).
- **Algorithimu ya Sahihi** inaelezea njia ya kusaini cheti.
- **Sahihi**, iliyoundwa kwa funguo ya kibinafsi ya mtoaji, inahakikisha uhalali wa cheti.

### Special Considerations

- **Majina Alternatif ya Mada (SANs)** yanapanua matumizi ya cheti kwa vitambulisho vingi, muhimu kwa seva zenye maeneo mengi. Mchakato wa usambazaji salama ni muhimu ili kuepuka hatari za kujifanya kwa washambuliaji wanaoshughulikia spesifikas za SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS inatambua cheti za CA katika msitu wa AD kupitia vyombo vilivyotengwa, kila moja ikihudumu majukumu ya kipekee:

- **Mamlaka za Cheti** chombo kinashikilia cheti za CA za mizizi zinazotegemewa.
- **Huduma za Usajili** chombo kinaelezea CA za Biashara na templeti zao za cheti.
- **NTAuthCertificates** kitu kinajumuisha cheti za CA zilizoidhinishwa kwa uthibitishaji wa AD.
- **AIA (Upatikanaji wa Taarifa za Mamlaka)** chombo kinasaidia uthibitishaji wa mnyororo wa cheti na cheti za CA za kati na za msalaba.

### Certificate Acquisition: Client Certificate Request Flow

1. Mchakato wa ombi huanza na wateja wakitafuta CA ya Biashara.
2. CSR inaundwa, ikiwa na funguo ya umma na maelezo mengine, baada ya kuunda jozi ya funguo ya umma na ya kibinafsi.
3. CA inakagua CSR dhidi ya templeti za cheti zilizopo, ikitoa cheti kulingana na ruhusa za templeti.
4. Baada ya idhini, CA inasaini cheti kwa funguo yake ya kibinafsi na kuirudisha kwa mteja.

### Certificate Templates

Zimefafanuliwa ndani ya AD, templeti hizi zinaelezea mipangilio na ruhusa za kutoa vyeti, ikiwa ni pamoja na EKUs zinazoruhusiwa na haki za usajili au mabadiliko, muhimu kwa usimamizi wa ufikiaji wa huduma za cheti.

## Certificate Enrollment

Mchakato wa usajili wa vyeti huanzishwa na msimamizi ambaye **anaunda templeti ya cheti**, ambayo kisha **inasambazwa** na Mamlaka ya Cheti ya Biashara (CA). Hii inafanya templeti kuwa inapatikana kwa usajili wa mteja, hatua inayofikiwa kwa kuongeza jina la templeti kwenye uwanja wa `certificatetemplates` wa kitu cha Active Directory.

Ili mteja aombe cheti, **haki za usajili** lazima zipewe. Haki hizi zinafafanuliwa na waelekezi wa usalama kwenye templeti ya cheti na CA ya Biashara yenyewe. Ruhusa lazima zipewe katika maeneo yote mawili ili ombi liwe na mafanikio.

### Template Enrollment Rights

Haki hizi zinaelezwa kupitia Kuingilia kwa Udhibiti wa Ufikiaji (ACEs), zikifafanua ruhusa kama:

- Haki za **Usajili wa Cheti** na **Usajili wa Cheti wa Otomatiki**, kila moja ikihusishwa na GUID maalum.
- **Haki za Kupanuliwa**, zikiruhusu ruhusa zote za ziada.
- **Udhibiti Kamili/GenericAll**, ukitoa udhibiti kamili juu ya templeti.

### Enterprise CA Enrollment Rights

Haki za CA zinaelezwa katika waelekezi wake wa usalama, zinazopatikana kupitia console ya usimamizi wa Mamlaka ya Cheti. Mipangilio mingine hata inaruhusu watumiaji wenye mamlaka ya chini kupata mbali, ambayo inaweza kuwa wasiwasi wa usalama.

### Additional Issuance Controls

Madhara fulani yanaweza kutumika, kama vile:

- **Idhini ya Meneja**: Inatia maombi katika hali ya kusubiri hadi idhini itolewe na meneja wa cheti.
- **Wakala wa Usajili na Sahihi Zilizothibitishwa**: Zinaelezea idadi ya sahihi zinazohitajika kwenye CSR na OIDs za Sera ya Maombi zinazohitajika.

### Methods to Request Certificates

Vyeti vinaweza kuombwa kupitia:

1. **Protokali ya Usajili wa Cheti ya Mteja wa Windows** (MS-WCCE), ikitumia interfaces za DCOM.
2. **Protokali ya ICertPassage Remote** (MS-ICPR), kupitia mabomba yaliyopewa majina au TCP/IP.
3. Kiolesura cha wavuti cha **usajili wa cheti**, na jukumu la Usajili wa Wavuti wa Mamlaka ya Cheti lililosakinishwa.
4. **Huduma ya Usajili wa Cheti** (CES), kwa kushirikiana na huduma ya Sera ya Usajili wa Cheti (CEP).
5. **Huduma ya Usajili wa Vifaa vya Mtandao** (NDES) kwa vifaa vya mtandao, ikitumia Protokali ya Usajili wa Cheti Rahisi (SCEP).

Watumiaji wa Windows wanaweza pia kuomba vyeti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za mistari ya amri (`certreq.exe` au amri ya PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitisho wa Cheti

Active Directory (AD) inasaidia uthibitisho wa cheti, hasa ikitumia **Kerberos** na **Secure Channel (Schannel)** protokali.

### Mchakato wa Uthibitisho wa Kerberos

Katika mchakato wa uthibitisho wa Kerberos, ombi la mtumiaji la Tiketi ya Kutoa Tiketi (TGT) linatiwa saini kwa kutumia **funguo ya faragha** ya cheti cha mtumiaji. Ombi hili hupitia uthibitisho kadhaa na msimamizi wa eneo, ikiwa ni pamoja na **uhalali** wa cheti, **njia**, na **hali ya kufutwa**. Uthibitisho pia unajumuisha kuangalia kwamba cheti kinatoka kwa chanzo kinachotegemewa na kuthibitisha uwepo wa mtoaji katika **duka la cheti la NTAUTH**. Uthibitisho uliofanikiwa unapelekea utoaji wa TGT. Kitu cha **`NTAuthCertificates`** katika AD, kinapatikana kwenye:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ni muhimu katika kuanzisha uaminifu kwa uthibitishaji wa cheti.

### Uthibitishaji wa Kituo Salama (Schannel)

Schannel inarahisisha muunganisho salama wa TLS/SSL, ambapo wakati wa mkutano, mteja anawasilisha cheti ambacho, ikiwa kimefanikiwa kuthibitishwa, kinatoa ruhusa ya ufikiaji. Mchoro wa cheti kwa akaunti ya AD unaweza kujumuisha kazi ya Kerberos **S4U2Self** au **Subject Alternative Name (SAN)** ya cheti, kati ya mbinu nyingine.

### Uhesabu wa Huduma za Cheti za AD

Huduma za cheti za AD zinaweza kuhesabiwa kupitia maswali ya LDAP, zikifunua habari kuhusu **Mamlaka ya Cheti ya Biashara (CAs)** na mipangilio yao. Hii inapatikana kwa mtumiaji yeyote aliyeidhinishwa na kikoa bila ruhusa maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** zinatumika kwa uhesabu na tathmini ya udhaifu katika mazingira ya AD CS.

Amri za kutumia zana hizi ni:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
---

## Uthibitisho wa Hivi Karibuni & Sasisho za Usalama (2022-2025)

| Mwaka | ID / Jina | Athari | Mambo Muhimu |
|-------|-----------|--------|---------------|
| 2022  | **CVE-2022-26923** – “Certifried” / ESC6 | *Kuongeza mamlaka* kwa kudanganya vyeti vya akaunti za mashine wakati wa PKINIT. | Patch imejumuishwa katika sasisho za usalama za **Machi 10 2022**. Ukaguzi & udhibiti wa nguvu za ramani zilianzishwa kupitia **KB5014754**; mazingira yanapaswa sasa kuwa katika hali ya *Utekelezaji Kamili*. citeturn2search0 |
| 2023  | **CVE-2023-35350 / 35351** | *Utendaji wa msimbo wa mbali* katika AD CS Web Enrollment (certsrv) na majukumu ya CES. | PoCs za umma ni chache, lakini vipengele vya IIS vilivyo hatarini mara nyingi vinakabiliwa ndani. Patch kuanzia **Julai 2023** Patch Jumanne. citeturn3search0 |
| 2024  | **CVE-2024-49019** – “EKUwu” / ESC15 | Watumiaji wenye mamlaka ya chini walio na haki za kujiandikisha wanaweza kubadilisha **yoyote** EKU au SAN wakati wa uzalishaji wa CSR, kutoa vyeti vinavyoweza kutumika kwa uthibitishaji wa mteja au kusaini msimbo na kusababisha *kuvunjika kwa eneo*. | Imetatuliwa katika sasisho za **Aprili 2024**. Ondoa “Weka katika ombi” kutoka kwa templeti na punguza ruhusa za kujiandikisha. citeturn1search3 |

### Muda wa kuimarisha wa Microsoft (KB5014754)

Microsoft ilianzisha utaratibu wa hatua tatu (Ulinganifu → Ukaguzi → Utekelezaji) ili kuhamasisha uthibitisho wa vyeti vya Kerberos mbali na ramani dhaifu za kimya. Kuanzia **Februari 11 2025**, wasimamizi wa eneo moja moja hujibadilisha kiotomatiki kuwa **Utekelezaji Kamili** ikiwa thamani ya rejista ya `StrongCertificateBindingEnforcement` haijakamilishwa. Wasimamizi wanapaswa:

1. Patch DC zote & seva za AD CS (Machi 2022 au baadaye).
2. Fuata Kitambulisho cha Tukio 39/41 kwa ramani dhaifu wakati wa hatua ya *Ukaguzi*.
3. Toa tena vyeti vya uthibitishaji wa mteja na **kiendelezi kipya cha SID** au weka ramani za nguvu za mikono kabla ya Februari 2025. citeturn2search0

---

## Ugunduzi & Uboreshaji wa Kuimarisha

* **Defender for Identity AD CS sensor (2023-2024)** sasa inaonyesha tathmini za hali kwa ESC1-ESC8/ESC11 na inazalisha arifa za wakati halisi kama *“Utoaji wa cheti cha msimamizi wa eneo kwa DC asiye DC”* (ESC8) na *“Zuia Uandikishaji wa Cheti na Sera za Maombi zisizo na mipaka”* (ESC15). Hakikisha sensa zimewekwa kwenye seva zote za AD CS ili kufaidika na ugunduzi huu. citeturn5search0
* Zima au punguza kwa karibu chaguo la **“Weka katika ombi”** kwenye templeti zote; pendelea thamani za SAN/EKU zilizofafanuliwa wazi.
* Ondoa **Madhumuni Yoyote** au **Hakuna EKU** kutoka kwa templeti isipokuwa inahitajika kabisa (inashughulikia hali za ESC2).
* Hitaji **idhini ya meneja** au michakato ya Wakala wa Uandikishaji iliyotengwa kwa templeti nyeti (mfano, WebServer / CodeSigning).
* Punguza uandikishaji wa wavuti (`certsrv`) na mwisho wa CES/NDES kwa mitandao ya kuaminika au nyuma ya uthibitishaji wa cheti cha mteja.
* Tekeleza usimbuaji wa uandikishaji wa RPC (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`) ili kupunguza ESC11.

---

## Marejeleo

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
