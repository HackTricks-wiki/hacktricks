# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Jifunze kuhusu macOS MDM hapa:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Misingi

### **Muhtasari wa MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) hutumiwa kusimamia vifaa mbalimbali vya watumiaji wa mwisho kama vile simu mahiri, kompyuta mpakato na tableti. Hasa kwenye majukwaa ya Apple (iOS, macOS, tvOS), inahusisha seti ya vipengele maalum, API na mbinu. Uendeshaji wa MDM hutegemea seva ya MDM inayooana, ambayo hupatikana kibiashara au ni open-source, na lazima iauni [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Mambo muhimu ni:

- Udhibiti wa vifaa kutoka sehemu moja.
- Kutegemea seva ya MDM inayofuata itifaki ya MDM.
- Seva ya MDM inaweza kutuma amri mbalimbali kwa vifaa, kwa mfano, kufuta data kwa mbali au kusakinisha usanidi.

### **Misingi ya DEP (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) inayotolewa na Apple hurahisisha kuunganisha Mobile Device Management (MDM) kwa kuwezesha usanidi wa iOS, macOS na tvOS bila kugusa kifaa. DEP huendesha mchakato wa uandikishaji kiotomatiki, hivyo vifaa huwa tayari kutumika vinapotolewa kwenye boksi, bila kuhitaji mtumiaji au msimamizi kuingilia kati sana. Mambo muhimu ni:

- Huwezesha vifaa kujisajili vyenyewe kwenye seva ya MDM iliyofafanuliwa awali vinapowashwa kwa mara ya kwanza.
- Hufaa zaidi kwa vifaa vipya kabisa, lakini pia hutumika kwa vifaa vinavyosanidiwa upya.
- Huwezesha usanidi rahisi, na kufanya vifaa viwe tayari kutumiwa na shirika haraka.

### **Mazingatio ya Usalama**

Ni muhimu kutambua kwamba urahisi wa uandikishaji unaotolewa na DEP, ingawa una manufaa, unaweza pia kuleta hatari za usalama. Ikiwa hatua za ulinzi hazitatekelezwa ipasavyo kwa uandikishaji wa MDM, washambuliaji wanaweza kutumia mchakato huu rahisi kusajili kifaa chao kwenye seva ya MDM ya shirika, huku wakijifanya kuwa kifaa cha kampuni.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Tahadhari ya Usalama**: Uandikishaji rahisi wa DEP unaweza kuruhusu vifaa visivyoidhinishwa kujisajili kwenye seva ya MDM ya shirika ikiwa hakuna ulinzi unaofaa.

### Misingi: SCEP (Simple Certificate Enrolment Protocol) ni nini?

- Ni itifaki ya zamani kiasi, iliyoundwa kabla ya TLS na HTTPS kuenea.
- Huwapa wateja njia sanifu ya kutuma **Certificate Signing Request** (CSR) ili kupata cheti. Mteja huiomba seva impe cheti kilichotiwa saini.

### Configuration Profiles (zinazojulikana pia kama mobileconfigs) ni nini?

- Njia rasmi ya Apple ya **kuweka/kulazimisha usanidi wa mfumo.**
- Muundo wa faili unaoweza kuwa na payload nyingi.
- Hutegemea property lists (aina ya XML).
- “zinaweza kutiwa saini na kusimbwa kwa njia fiche ili kuthibitisha zilipotoka, kuhakikisha uadilifu wake, na kulinda yaliyomo.” Basics — Ukurasa wa 70, iOS Security Guide, Januari 2018.

## Itifaki

### MDM

- Mchanganyiko wa APNs (**seva za Apple**) + RESTful API (seva za **vendor** wa **MDM**)
- **Mawasiliano** hufanyika kati ya **kifaa** na seva inayohusishwa na **bidhaa** ya **usimamizi** wa **kifaa**
- **Amri** hutumwa kutoka MDM kwenda kwenye kifaa kama **kamusi zilizowekwa msimbo wa plist**
- Yote hufanyika kupitia **HTTPS**. Seva za MDM zinaweza kutumia certificate pinning (na kwa kawaida hutumia).
- Apple humpa vendor wa MDM **cheti cha APNs** kwa ajili ya uthibitishaji

### DEP

- **API 3**: moja ya wauzaji, moja ya vendor wa MDM, na moja ya utambulisho wa kifaa (haijaandikwa kwenye nyaraka):
  - Kinachoitwa [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Seva za MDM hutumia API hii kuhusisha DEP profiles na vifaa maalum.
  - [DEP API inayotumiwa na Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) kuandikisha vifaa, kuangalia hali ya uandikishaji na kuangalia hali ya miamala.
  - DEP API ya faragha ambayo haijaandikwa kwenye nyaraka. Apple Devices huitumia kuomba DEP profile yake. Kwenye macOS, binary ya `cloudconfigurationd` ndiyo inayowasiliana kupitia API hii.
- Ni ya kisasa zaidi na hutumia **JSON** (kinyume na plist)
- Apple humpa vendor wa MDM **OAuth token**

**DEP "cloud service" API**

- RESTful
- husawazisha rekodi za vifaa kutoka Apple kwenda kwenye seva ya MDM
- husawazisha “DEP profiles” kutoka seva ya MDM kwenda Apple (ambapo baadaye Apple huzituma kwa kifaa)
- DEP “profile” ina:
  - URL ya seva ya vendor wa MDM
  - Vyeti vya ziada vinavyoaminika vya URL ya seva (hiari, kwa ajili ya pinning)
  - Mipangilio ya ziada (kwa mfano, skrini zipi za kuruka kwenye Setup Assistant)

## Nambari ya Serial

Vifaa vya Apple vilivyotengenezwa baada ya 2010 kwa kawaida huwa na nambari za serial za **herufi na tarakimu 12**, ambapo **tarakimu tatu za kwanza huonyesha mahali pa utengenezaji**, **mbili** zinazofuata huonyesha **mwaka** na **wiki** ya utengenezaji, **tarakimu tatu** zinazofuata hutoa **kitambulisho** **cha kipekee**, na **tarakimu nne** za **mwisho** huonyesha **nambari ya model**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Hatua za uandikishaji na usimamizi

1. Kuunda rekodi ya kifaa (Reseller, Apple): Rekodi ya kifaa kipya huundwa
2. Kukabidhi rekodi ya kifaa (Customer): Kifaa hukabidhiwa kwa seva ya MDM
3. Kusawazisha rekodi ya kifaa (MDM vendor): MDM husawazisha rekodi za kifaa na kutuma DEP profiles kwa Apple
4. DEP check-in (Device): Kifaa hupata DEP profile yake
5. Kupata profile (Device)
6. Kusakinisha profile (Device) a. ikijumuisha MDM, SCEP na root CA payloads
7. Kutuma amri za MDM (Device)

![Nambari ya Serial - Hatua za uandikishaji na usimamizi: 7. Kutuma amri za MDM (Device)](<../../../images/image (694).png>)

Faili ya `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` husafirisha functions zinazoweza kuchukuliwa kuwa **"hatua" za kiwango cha juu** za mchakato wa uandikishaji.

### Hatua ya 4: DEP check-in - Kupata Activation Record

Sehemu hii ya mchakato hutokea **mtumiaji anapowasha Mac kwa mara ya kwanza** (au baada ya kufuta kila kitu)

![Hatua za uandikishaji na usimamizi - Hatua ya 4: DEP check-in - Kupata Activation Record: Sehemu hii ya mchakato hutokea mtumiaji anapowasha Mac kwa mara ya kwanza (au baada ya kufuta kila kitu...](<../../../images/image (1044).png>)

au unapoendesha `sudo profiles show -type enrollment`

- Hubaini **ikiwa kifaa kimewezeshwa DEP**
- Activation Record ni jina la ndani la **DEP “profile”**
- Huanza mara tu kifaa kinapounganishwa kwenye Intaneti
- Huendeshwa na **`CPFetchActivationRecord`**
- Hutekelezwa na **`cloudconfigurationd`** kupitia XPC. **"Setup Assistant**" (kifaa kinapowashwa kwa mara ya kwanza) au amri ya **`profiles`** huwasiliana na **daemon hii** ili kupata activation record.
  - LaunchDaemon (huendeshwa kama root kila wakati)

Hufuata hatua kadhaa kupata Activation Record, zinazoendeshwa na **`MCTeslaConfigurationFetcher`**. Mchakato huu hutumia usimbaji fiche unaoitwa **Absinthe**<sup>[[1]](#references)</sup>

1. Pata **cheti**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Anzisha** hali kutoka kwenye cheti (**`NACInit`**)
   1. Hutumia data mbalimbali maalum kwa kifaa (yaani, **Nambari ya Serial kupitia `IOKit`**)
3. Pata **session key**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Anzisha session (**`NACKeyEstablishment`**)
5. Tuma ombi
   1. POST kwa [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) ikituma data `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. JSON payload husimbwa kwa Absinthe (**`NACSign`**)
   3. Maombi yote hupitia HTTPs; vyeti vya root vilivyojengewa ndani hutumika

![Hatua za uandikishaji na usimamizi - Hatua ya 4: DEP check-in - Kupata Activation Record: 3. Maombi yote hupitia HTTPs; vyeti vya root vilivyojengewa ndani hutumika](<../../../images/image (566) (1).png>)

Jibu ni kamusi ya JSON yenye data muhimu kama:

- **url**: URL ya host ya vendor wa MDM kwa activation profile
- **anchor-certs**: Safu ya vyeti vya DER vinavyotumika kama anchor zinazoaminika

### **Hatua ya 5: Kupata Profile**

![Hatua ya 4: DEP check-in - Kupata Activation Record - Hatua ya 5: Kupata Profile: Hatua ya 5: Kupata Profile](<../../../images/image (444).png>)

- Ombi hutumwa kwenye **url iliyotolewa kwenye DEP profile**.
- **Anchor certificates** hutumika **kutathmini uaminifu** ikiwa zimetolewa.
  - Kumbuka: sifa ya **anchor_certs** ya DEP profile
- **Ombi ni .plist rahisi** yenye utambulisho wa kifaa
  - Mifano: **UDID, toleo la OS**.
- Imetiwa saini kwa CMS na kusimbwa kwa DER
- Imetiwa saini kwa kutumia **cheti cha utambulisho wa kifaa (kutoka APNS)**
- **Certificate chain** ina **Apple iPhone Device CA** iliyoisha muda wake

![Hatua ya 4: DEP check-in - Kupata Activation Record - Hatua ya 5: Kupata Profile: Imetiwa saini kwa kutumia cheti cha utambulisho wa kifaa (kutoka APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Hatua ya 6: Kusakinisha Profile

- Baada ya kupatikana, **profile huhifadhiwa kwenye mfumo**
- Hatua hii huanza kiotomatiki (ikiwa iko kwenye **setup assistant**)
- Huendeshwa na **`CPInstallActivationProfile`**
- Hutekelezwa na mdmclient kupitia XPC
  - LaunchDaemon (kama root) au LaunchAgent (kama mtumiaji), kutegemea muktadha
- Configuration profiles zina payload nyingi za kusakinisha
- Framework ina usanifu unaotegemea plugin wa kusakinisha profiles
- Kila aina ya payload huhusishwa na plugin
  - Inaweza kuwa XPC (kwenye framework) au Cocoa ya kawaida (kwenye ManagedClient.app)
- Mfano:
  - Certificate Payloads hutumia CertificateService.xpc

Kwa kawaida, **activation profile** inayotolewa na vendor wa MDM **itakuwa na payloads zifuatazo**:

- `com.apple.mdm`: ili **kuandikisha** kifaa kwenye MDM
- `com.apple.security.scep`: ili kutoa **client certificate** kwa kifaa kwa usalama.
- `com.apple.security.pem`: ili **kusakinisha vyeti vya CA vinavyoaminika** kwenye System Keychain ya kifaa.
- Kusakinisha MDM payload ni sawa na **MDM check-in kwenye nyaraka**
- Payload **ina sifa muhimu**:
- - MDM Check-In URL (**`CheckInURL`**)
  - MDM Command Polling URL (**`ServerURL`**) + APNs topic ya kuianzisha
- Ili kusakinisha MDM payload, ombi hutumwa kwenye **`CheckInURL`**
- Hutekelezwa kwenye **`mdmclient`**
- MDM payload inaweza kutegemea payload nyingine
- Huruhusu **maombi kufungamanishwa na vyeti maalum**:
  - Sifa: **`CheckInURLPinningCertificateUUIDs`**
  - Sifa: **`ServerURLPinningCertificateUUIDs`**
  - Hutolewa kupitia PEM payload
- Huruhusu kifaa kuhusishwa na cheti cha utambulisho:
  - Sifa: IdentityCertificateUUID
  - Hutolewa kupitia SCEP payload

### **Hatua ya 7: Kusikiliza amri za MDM**

- Baada ya MDM check-in kukamilika, vendor anaweza **kutuma push notifications kwa kutumia APNs**
- Zinapopokelewa, hushughulikiwa na **`mdmclient`**
- Ili kupata amri za MDM, ombi hutumwa kwenye ServerURL
- Hutumia MDM payload iliyosakinishwa awali:
  - **`ServerURLPinningCertificateUUIDs`** kwa ajili ya certificate pinning ya ombi
  - **`IdentityCertificateUUID`** kwa ajili ya TLS client certificate

## Mashambulizi

### Kuandikisha Vifaa kwenye Mashirika Mengine

Nambari ya serial iliyokabidhiwa inaweza kuonyesha njia ya uandikishaji ya shirika, lakini **haithibitishi** kuwa kifaa kitaandikishwa kwenye MDM. Seva inaweza kuhitaji uthibitishaji wa mtumiaji kupitia `configuration_web_url` kabla ya kurudisha enrollment profile. Hakikisha kama njia mbadala ya uandikishaji haina ukaguzi huo, badala ya kudhani kwamba kila nambari ya serial iliyokabidhiwa inaweza kujiunga na kundi la vifaa.<sup>[[3]](#references)</sup>

Kwa utaratibu wa rogue-enrollment, tumia ukurasa uliounganishwa hapa chini. Kwa udhibiti wa MDM na usambazaji wa package baada ya compromise, tazama [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Uchambuzi wa Kina wa macOS MDM (na Jinsi Inavyoweza Kuhatarishwa)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (utafiti wa usalama wa uandikishaji wa DEP/MDM)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Kuthibitisha utambulisho kupitia web views](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
