# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Ili kujifunza kuhusu macOS MDM angalia:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Misingi

### **Muhtasari wa MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) hutumika kusimamia vifaa mbalimbali vya watumiaji wa mwisho kama vile smartphones, laptops na tablets. Hasa kwa platforms za Apple (iOS, macOS, tvOS), inahusisha seti ya features, APIs na practices maalum. Uendeshaji wa MDM hutegemea MDM server inayooana, ambayo inaweza kuwa ya kibiashara au open-source, na lazima iunge mkono [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Mambo muhimu ni pamoja na:

- Udhibiti wa vifaa kutoka sehemu ya kati.
- Kutegemea MDM server inayofuata MDM protocol.
- Uwezo wa MDM server kutuma commands mbalimbali kwa vifaa, kwa mfano kufuta data kwa mbali au kusakinisha configuration.

### **Misingi ya DEP (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) inayotolewa na Apple hurahisisha ujumuishaji wa Mobile Device Management (MDM) kwa kuwezesha configuration ya zero-touch kwa vifaa vya iOS, macOS na tvOS. DEP hu-automate mchakato wa enrollment, hivyo vifaa vinaweza kuwa tayari kufanya kazi mara tu vinapotolewa kwenye boksi, kwa uingiliaji mdogo wa mtumiaji au administrator. Vipengele muhimu ni pamoja na:

- Huviwezesha vifaa kujisajili vyenyewe kwenye MDM server iliyowekwa awali vinapowashwa kwa mara ya kwanza.
- Hufaa hasa kwa vifaa vipya kabisa, lakini pia inaweza kutumika kwa vifaa vinavyofanyiwa reconfiguration.
- Hurahisisha setup, na kufanya vifaa viwe tayari kutumiwa na shirika kwa haraka.

### **Mazingatio ya Usalama**

Ni muhimu kutambua kwamba urahisi wa enrollment unaotolewa na DEP, ingawa una manufaa, unaweza pia kuleta security risks. Ikiwa hatua za ulinzi hazitatekelezwa ipasavyo kwa MDM enrollment, attackers wanaweza kutumia mchakato huu uliorahisishwa kusajili device yao kwenye MDM server ya shirika, huku wakijifanya kuwa ni device ya kampuni.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Security Alert**: DEP enrollment iliyorahisishwa inaweza kuruhusu usajili usioidhinishwa wa device kwenye MDM server ya shirika ikiwa safeguards zinazofaa hazipo.

### Misingi SCEP (Simple Certificate Enrolment Protocol) ni nini?

- Ni protocol ya zamani kwa kiasi, iliyoundwa kabla TLS na HTTPS hazijasambaa kwa kiasi kikubwa.
- Huwapa clients njia sanifu ya kutuma **Certificate Signing Request** (CSR) kwa madhumuni ya kupewa certificate. Client humwomba server impe certificate iliyosainiwa.

### Configuration Profiles (pia huitwa mobileconfigs) ni nini?

- Njia rasmi ya Apple ya **kuweka/kutekeleza system configuration.**
- File format inayoweza kuwa na payloads nyingi.
- Inategemea property lists (aina ya XML).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- Mchanganyiko wa APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers)
- **Communication** hufanyika kati ya **device** na server inayohusishwa na **device** **management** **product**
- **Commands** hutumwa kutoka MDM kwenda kwenye device katika **plist-encoded dictionaries**
- Yote kupitia **HTTPS**. MDM servers zinaweza (na kwa kawaida) kutumia certificate pinning.
- Apple humpa MDM vendor **APNs certificate** kwa ajili ya authentication

### DEP

- **APIs 3**: 1 ya resellers, 1 ya MDM vendors, 1 ya device identity (haijaandikwa):
- Inayoitwa [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Hutumiwa na MDM servers kuhusisha DEP profiles na devices maalum.
- [DEP API inayotumiwa na Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) kwa ajili ya ku-enroll devices, kuangalia enrollment status na kuangalia transaction status.
- DEP API ya faragha ambayo haijaandikwa. Hutumiwa na Apple Devices kuomba DEP profile yao. Kwenye macOS, binary ya `cloudconfigurationd` inawajibika kwa kuwasiliana kupitia API hii.
- Ni ya kisasa zaidi na inategemea **JSON** (ikilinganishwa na plist)
- Apple humpa MDM vendor **OAuth token**

**DEP "cloud service" API**

- RESTful
- husync device records kutoka Apple kwenda kwenye MDM server
- husync “DEP profiles” kutoka MDM server kwenda Apple (ambapo baadaye Apple huzifikisha kwenye device)
- DEP “profile” huwa na:
- URL ya MDM vendor server
- Certificates za ziada zinazoaminika kwa server URL (optional pinning)
- Settings za ziada (kwa mfano, ni screens zipi zirukwe kwenye Setup Assistant)

## Serial Number

Apple devices zilizotengenezwa baada ya 2010 kwa ujumla zina serial numbers za **herufi na namba zenye urefu wa characters 12**, ambapo **digits tatu za kwanza huwakilisha eneo la utengenezaji**, **mbili zinazofuata** huonyesha **mwaka** na **wiki** ya utengenezaji, **digits tatu zinazofuata** hutoa **identifier** **ya kipekee**, na **digits nne za mwisho** huwakilisha **model number**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Hatua za enrollment na management

1. Kuundwa kwa device record (Reseller, Apple): Record ya device mpya huundwa
2. Kugawiwa kwa device record (Customer): Device hugawiwa MDM server
3. Kusync kwa device record (MDM vendor): MDM husync device records na kusukuma DEP profiles kwenda Apple
4. DEP check-in (Device): Device hupokea DEP profile yake
5. Profile retrieval (Device)
6. Profile installation (Device) a. ikijumuisha MDM, SCEP na root CA payloads
7. MDM command issuance (Device)

![Serial Number - Hatua za enrollment na management: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

File `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` inatoa functions zinazoweza kuchukuliwa kuwa **"hatua" za kiwango cha juu** za mchakato wa enrollment.

### Hatua ya 4: DEP check-in - Kupata Activation Record

Sehemu hii ya mchakato hutokea wakati **mtumiaji anapoanzisha Mac kwa mara ya kwanza** (au baada ya wipe kamili)

![Hatua za enrollment na management - Hatua ya 4: DEP check-in - Kupata Activation Record: Sehemu hii ya mchakato hutokea wakati mtumiaji anapoanzisha Mac kwa mara ya kwanza (au baada ya...](<../../../images/image (1044).png>)

au wakati wa kutekeleza `sudo profiles show -type enrollment`

- Kuamua **ikiwa device imewezeshwa DEP**
- Activation Record ni jina la ndani la **DEP “profile”**
- Huanzia mara tu device inapounganishwa kwenye Internet
- Huendeshwa na **`CPFetchActivationRecord`**
- Hutekelezwa na **`cloudconfigurationd`** kupitia XPC. **"Setup Assistant**" (device inapowashwa kwa mara ya kwanza) au command ya **`profiles`** **huwasiliana na daemon hii** ili kupata activation record.
- LaunchDaemon (huendeshwa kila mara kama root)

Hufuata hatua kadhaa za kupata Activation Record zinazotekelezwa na **`MCTeslaConfigurationFetcher`**. Mchakato huu hutumia encryption inayoitwa **Absinthe**<sup>[[1]](#references)</sup>

1. Kupata **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Kuanzisha** state kutoka kwenye certificate (**`NACInit`**)
1. Hutumia data mbalimbali maalum kwa device (yaani **Serial Number kupitia `IOKit`**)
3. Kupata **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Kuanzisha session (**`NACKeyEstablishment`**)
5. Kufanya request
1. POST kwenda [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) ikituma data `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload husimbwa kwa encryption kwa kutumia Absinthe (**`NACSign`**)
3. Requests zote kupitia HTTPs, root certificates zilizojengwa ndani hutumika

![Hatua za enrollment na management - Hatua ya 4: DEP check-in - Kupata Activation Record: 3. Requests zote kupitia HTTPs, root certificates zilizojengwa ndani hutumika](<../../../images/image (566) (1).png>)

Jibu ni JSON dictionary yenye data muhimu kama:

- **url**: URL ya MDM vendor host kwa activation profile
- **anchor-certs**: Array ya DER certificates zinazotumika kama trusted anchors

### **Hatua ya 5: Profile Retrieval**

![Hatua ya 4: DEP check-in - Kupata Activation Record - Hatua ya 5: Profile Retrieval: Hatua ya 5: Profile Retrieval](<../../../images/image (444).png>)

- Request hutumwa kwenye **url iliyotolewa katika DEP profile**.
- **Anchor certificates** hutumika **kutathmini trust** ikiwa zimetolewa.
- Kumbuka: property ya **anchor_certs** ya DEP profile
- **Request ni .plist rahisi** yenye device identification
- Mifano: **UDID, OS version**.
- CMS-signed, DER-encoded
- Imesainiwa kwa kutumia **device identity certificate (kutoka APNS)**
- **Certificate chain** inajumuisha **Apple iPhone Device CA** iliyokwisha muda wake

![Hatua ya 4: DEP check-in - Kupata Activation Record - Hatua ya 5: Profile Retrieval: Imesainiwa kwa kutumia device identity certificate (kutoka APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Hatua ya 6: Profile Installation

- Baada ya kupatikana, **profile huhifadhiwa kwenye system**
- Hatua hii huanza automatically (ikiwa iko kwenye **setup assistant**)
- Huendeshwa na **`CPInstallActivationProfile`**
- Hutekelezwa na mdmclient kupitia XPC
- LaunchDaemon (kama root) au LaunchAgent (kama user), kulingana na context
- Configuration profiles zina payloads nyingi za kusakinisha
- Framework ina architecture inayotumia plugins kwa ajili ya kusakinisha profiles
- Kila payload type inahusishwa na plugin
- Inaweza kuwa XPC (kwenye framework) au classic Cocoa (kwenye ManagedClient.app)
- Mfano:
- Certificate Payloads hutumia CertificateService.xpc

Kwa kawaida, **activation profile** inayotolewa na MDM vendor **itajumuisha payloads zifuatazo**:

- `com.apple.mdm`: kwa **ku-enroll** device kwenye MDM
- `com.apple.security.scep`: kwa kumpa device **client certificate** kwa usalama.
- `com.apple.security.pem`: kwa **kusakinisha trusted CA certificates** kwenye System Keychain ya device.
- Kusakinisha MDM payload ni sawa na **MDM check-in katika documentation**
- Payload **ina key properties**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic ya ku-trigger
- Ili kusakinisha MDM payload, request hutumwa kwenye **`CheckInURL`**
- Hutekelezwa katika **`mdmclient`**
- MDM payload inaweza kutegemea payloads nyingine
- Huruhusu **requests kupinned kwenye certificates maalum**:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- Hutumwa kupitia PEM payload
- Huruhusu device kuhusishwa na identity certificate:
- Property: IdentityCertificateUUID
- Hutumwa kupitia SCEP payload

### **Hatua ya 7: Kusikiliza MDM commands**

- Baada ya MDM check-in kukamilika, vendor anaweza **kutuma push notifications kwa kutumia APNs**
- Zinapopokelewa, hushughulikiwa na **`mdmclient`**
- Ili ku-poll MDM commands, request hutumwa kwenye ServerURL
- Hutumia MDM payload iliyosakinishwa awali:
- **`ServerURLPinningCertificateUUIDs`** kwa pinning request
- **`IdentityCertificateUUID`** kwa TLS client certificate

## Attacks

### Ku-enroll Devices katika Mashirika Mengine

Kama ilivyotajwa awali, ili kujaribu ku-enroll device katika shirika **kinachohitajika ni Serial Number moja tu inayomilikiwa na shirika hilo**. Baada ya device ku-enrolliwa, mashirika kadhaa yatasakinisha data nyeti kwenye device mpya: certificates, applications, WiFi passwords, VPN configurations [na kadhalika](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Kwa hiyo, hii inaweza kuwa entrypoint hatari kwa attackers ikiwa mchakato wa enrollment haujalindwa ipasavyo:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
