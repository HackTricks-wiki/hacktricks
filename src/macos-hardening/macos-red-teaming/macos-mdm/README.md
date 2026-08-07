# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Kujifunza kuhusu macOS MDMs angalia:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Misingi

### **Muhtasari wa MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) hutumika kusimamia vifaa mbalimbali vya watumiaji wa mwisho kama smartphones, laptops, na tablets. Hasa kwa platforms za Apple (iOS, macOS, tvOS), inahusisha seti ya features, APIs, na practices maalum. Uendeshaji wa MDM hutegemea MDM server inayooana, ambayo inaweza kuwa ya kibiashara au open-source, na lazima iauni [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Mambo muhimu ni:

- Udhibiti wa vifaa kutoka sehemu kuu.
- Kutegemea MDM server inayofuata MDM protocol.
- Uwezo wa MDM server kutuma commands mbalimbali kwa vifaa, kwa mfano kufuta data kwa mbali au kusakinisha configuration.

### **Misingi ya DEP (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) inayotolewa na Apple hurahisisha kuunganisha Mobile Device Management (MDM) kwa kuwezesha zero-touch configuration kwa vifaa vya iOS, macOS, na tvOS. DEP hu-automate mchakato wa enrollment, hivyo vifaa vinaweza kuwa tayari kutumika mara tu vinapotolewa kwenye boksi, bila uingiliaji mkubwa wa mtumiaji au administrator. Vipengele muhimu ni:

- Huwezesha vifaa kujisajili vyenyewe kwenye MDM server iliyofafanuliwa awali wakati wa activation ya kwanza.
- Hufaa zaidi kwa vifaa vipya kabisa, lakini pia inaweza kutumika kwa vifaa vinavyofanyiwa reconfiguration.
- Hurahisisha setup, na kufanya vifaa viwe tayari kwa matumizi ya shirika kwa haraka.

### **Mazingatio ya Usalama**

Ni muhimu kutambua kwamba urahisi wa enrollment unaotolewa na DEP, ingawa una manufaa, unaweza pia kuleta security risks. Ikiwa protective measures hazitatekelezwa ipasavyo kwa MDM enrollment, attackers wanaweza kutumia mchakato huu uliorahisishwa kusajili device yao kwenye MDM server ya shirika, huku wakijifanya kuwa ni device ya shirika.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Security Alert**: DEP enrollment iliyorahisishwa inaweza kuruhusu usajili usioidhinishwa wa device kwenye MDM server ya shirika ikiwa safeguards zinazofaa hazipo.

### Misingi: SCEP (Simple Certificate Enrolment Protocol) ni nini?

- Ni protocol ya zamani kiasi, iliyoundwa kabla TLS na HTTPS hazijasambaa kwa matumizi ya kawaida.
- Huwapa clients njia sanifu ya kutuma **Certificate Signing Request** (CSR) kwa madhumuni ya kupewa certificate. Client ataiomba server impe certificate iliyosainiwa.

### Configuration Profiles (pia huitwa mobileconfigs) ni nini?

- Njia rasmi ya Apple ya **kuweka/kulazimisha system configuration.**
- File format inayoweza kuwa na payloads nyingi.
- Inategemea property lists (aina ya XML).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- Mchanganyiko wa APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers)
- **Communication** hutokea kati ya **device** na server inayohusishwa na **device** **management** **product**
- **Commands** hutumwa kutoka MDM kwenda kwenye device katika **plist-encoded dictionaries**
- Yote hupitia **HTTPS**. MDM servers zinaweza (na kwa kawaida) kutumia certificate pinning.
- Apple humpa MDM vendor **APNs certificate** kwa ajili ya authentication

### DEP

- **3 APIs**: 1 kwa resellers, 1 kwa MDM vendors, 1 kwa device identity (isiyorekodiwa):
- Kinachoitwa [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Hii hutumiwa na MDM servers kuhusisha DEP profiles na devices maalum.
- [DEP API inayotumiwa na Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) ku-enroll devices, kukagua enrollment status, na kukagua transaction status.
- Private DEP API isiyorekodiwa. Hii hutumiwa na Apple Devices kuomba DEP profile yao. Kwenye macOS, binary ya `cloudconfigurationd` ndiyo inayohusika na mawasiliano kupitia API hii.
- Ya kisasa zaidi na inayotegemea **JSON** (dhidi ya plist)
- Apple humpa **OAuth token** MDM vendor

**DEP "cloud service" API**

- RESTful
- husync device records kutoka Apple kwenda kwenye MDM server
- husync “DEP profiles” kutoka MDM server kwenda Apple (ambazo baadaye hutumwa na Apple kwenda kwenye device)
- DEP “profile” huwa na:
- MDM vendor server URL
- Additional trusted certificates kwa server URL (optional pinning)
- Extra settings (kwa mfano, ni screens zipi zirukwe kwenye Setup Assistant)

## Serial Number

Apple devices zilizotengenezwa baada ya 2010 kwa ujumla zina **12-character alphanumeric** serial numbers, ambapo **digits tatu za kwanza zinawakilisha eneo la utengenezaji**, **mbili zinazofuata** zinaonyesha **mwaka** na **wiki** ya utengenezaji, **digits tatu zinazofuata** zinatoa **unique** **identifier**, na **digits nne za mwisho** zinawakilisha **model number**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Hatua za enrollment na management

1. Device record creation (Reseller, Apple): Record ya device mpya huundwa
2. Device record assignment (Customer): Device hupewa MDM server
3. Device record sync (MDM vendor): MDM husync device records na kusukuma DEP profiles kwenda Apple
4. DEP check-in (Device): Device hupokea DEP profile yake
5. Profile retrieval (Device)
6. Profile installation (Device) a. ikijumuisha MDM, SCEP na root CA payloads
7. MDM command issuance (Device)

![Serial Number - Hatua za enrollment na management: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

File `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` inatoa functions zinazoweza kuchukuliwa kuwa **"steps" za kiwango cha juu** za mchakato wa enrollment.

### Step 4: DEP check-in - Kupata Activation Record

Sehemu hii ya mchakato hutokea wakati **user anapowasha Mac kwa mara ya kwanza** (au baada ya wipe kamili)

![Hatua za enrollment na management - Step 4: DEP check-in - Kupata Activation Record: Sehemu hii ya mchakato hutokea wakati user anapowasha Mac kwa mara ya kwanza (au baada ya...](<../../../images/image (1044).png>)

au wakati wa kutekeleza `sudo profiles show -type enrollment`

- Kubaini **ikiwa device imewezeshwa DEP**
- Activation Record ni jina la ndani la **DEP “profile”**
- Huanzia mara tu device inapounganishwa kwenye Internet
- Huendeshwa na **`CPFetchActivationRecord`**
- Hutekelezwa na **`cloudconfigurationd`** kupitia XPC. **"Setup Assistant**" (device inapowashwa kwa mara ya kwanza) au command ya **`profiles`** itawasiliana na **daemon hii** ili kupata activation record.
- LaunchDaemon (huendesha kila wakati kama root)

Hufuata hatua kadhaa za kupata Activation Record zinazotekelezwa na **`MCTeslaConfigurationFetcher`**. Mchakato huu hutumia encryption inayoitwa **Absinthe**<sup>[[1]](#references)</sup>

1. Retrieve **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialize** state kutoka kwenye certificate (**`NACInit`**)
1. Hutumia data mbalimbali maalum kwa device (yaani **Serial Number kupitia `IOKit`**)
3. Retrieve **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establish session (**`NACKeyEstablishment`**)
5. Fanya request
1. POST kwenda [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) ikituma data `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload husimbwa kwa encryption kwa kutumia Absinthe (**`NACSign`**)
3. Requests zote hupitia HTTPs, na built-in root certificates hutumika

![Hatua za enrollment na management - Step 4: DEP check-in - Kupata Activation Record: 3. Requests zote hupitia HTTPs, na built-in root certificates hutumika](<../../../images/image (566) (1).png>)

Response ni JSON dictionary yenye data muhimu kama:

- **url**: URL ya MDM vendor host kwa activation profile
- **anchor-certs**: Array ya DER certificates zinazotumika kama trusted anchors

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Kupata Activation Record - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- Request hutumwa kwenye **url iliyotolewa katika DEP profile**.
- **Anchor certificates** hutumika **kutathmini trust** ikiwa zimetolewa.
- Kumbuka: property ya **anchor_certs** ya DEP profile
- **Request ni .plist rahisi** yenye device identification
- Mifano: **UDID, OS version**.
- CMS-signed, DER-encoded
- Imesainiwa kwa kutumia **device identity certificate (kutoka APNS)**
- **Certificate chain** inajumuisha **Apple iPhone Device CA** iliyokwisha muda wake

![Step 4: DEP check-in - Kupata Activation Record - Step 5: Profile Retrieval: Imesainiwa kwa kutumia device identity certificate (kutoka APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- Baada ya kupatikana, **profile huhifadhiwa kwenye system**
- Hatua hii huanza automatically (ikiwa iko kwenye **setup assistant**)
- Huendeshwa na **`CPInstallActivationProfile`**
- Hutekelezwa na mdmclient kupitia XPC
- LaunchDaemon (kama root) au LaunchAgent (kama user), kutegemea context
- Configuration profiles zina payloads nyingi za kusakinisha
- Framework ina plugin-based architecture ya kusakinisha profiles
- Kila payload type inahusishwa na plugin
- Inaweza kuwa XPC (kwenye framework) au classic Cocoa (kwenye ManagedClient.app)
- Mfano:
- Certificate Payloads hutumia CertificateService.xpc

Kwa kawaida, **activation profile** inayotolewa na MDM vendor **itajumuisha payloads zifuatazo**:

- `com.apple.mdm`: kwa ajili ya **ku-enroll** device kwenye MDM
- `com.apple.security.scep`: kwa ajili ya kumpa device **client certificate** kwa usalama.
- `com.apple.security.pem`: kwa ajili ya **kusakinisha trusted CA certificates** kwenye System Keychain ya device.
- Kusakinisha MDM payload ni sawa na **MDM check-in katika documentation**
- Payload **ina key properties**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic ya ku-trigger
- Ili kusakinisha MDM payload, request hutumwa kwenye **`CheckInURL`**
- Hutekelezwa katika **`mdmclient`**
- MDM payload inaweza kutegemea payloads nyingine
- Huruhusu **requests ku-pinned kwenye certificates maalum**:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- Hutumwa kupitia PEM payload
- Huruhusu device kuhusishwa na identity certificate:
- Property: IdentityCertificateUUID
- Hutumwa kupitia SCEP payload

### **Step 7: Kusikiliza MDM commands**

- Baada ya MDM check-in kukamilika, vendor anaweza **kutuma push notifications kwa kutumia APNs**
- Baada ya kupokelewa, hushughulikiwa na **`mdmclient`**
- Ili ku-poll MDM commands, request hutumwa kwenye ServerURL
- Hutumia MDM payload iliyosakinishwa awali:
- **`ServerURLPinningCertificateUUIDs`** kwa pinning request
- **`IdentityCertificateUUID`** kwa TLS client certificate

## Attacks

### Ku-enroll Devices katika Mashirika Mengine

Kama ilivyotajwa awali, ili kujaribu ku-enroll device katika organization **kinachohitajika ni Serial Number moja tu inayomilikiwa na Organization hiyo**. Baada ya device ku-enrolliwa, mashirika kadhaa yatasakinisha data nyeti kwenye device mpya: certificates, applications, WiFi passwords, VPN configurations [na kadhalika](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Kwa hiyo, hii inaweza kuwa entrypoint hatari kwa attackers ikiwa mchakato wa enrollment haulindwi ipasavyo:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
