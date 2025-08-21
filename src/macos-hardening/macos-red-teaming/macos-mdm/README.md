# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Ili kujifunza kuhusu macOS MDMs angalia:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Msingi

### **Muhtasari wa MDM (Usimamizi wa Vifaa vya Mkononi)**

[Usimamizi wa Vifaa vya Mkononi](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) unatumika kwa kusimamia vifaa mbalimbali vya mwisho kama vile simu za mkononi, kompyuta za mkononi, na vidonge. Hasa kwa majukwaa ya Apple (iOS, macOS, tvOS), inahusisha seti ya vipengele maalum, API, na mazoea. Uendeshaji wa MDM unategemea seva ya MDM inayofaa, ambayo inaweza kuwa inapatikana kibiashara au ya chanzo wazi, na inapaswa kuunga mkono [Protokali ya MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Mambo muhimu ni pamoja na:

- Udhibiti wa kati juu ya vifaa.
- Kutegemea seva ya MDM inayofuata protokali ya MDM.
- Uwezo wa seva ya MDM kutuma amri mbalimbali kwa vifaa, kwa mfano, kufuta data kwa mbali au kufunga usanidi.

### **Msingi wa DEP (Mpango wa Usajili wa Vifaa)**

[Mpango wa Usajili wa Vifaa](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) unaotolewa na Apple unarahisisha uunganisho wa Usimamizi wa Vifaa vya Mkononi (MDM) kwa kuwezesha usanidi wa sifuri wa kugusa kwa vifaa vya iOS, macOS, na tvOS. DEP inafanya mchakato wa usajili kuwa wa kiotomatiki, ikiruhusu vifaa kuwa na kazi mara moja kutoka kwenye sanduku, kwa kuingilia kidogo kutoka kwa mtumiaji au msimamizi. Mambo muhimu ni pamoja na:

- Inaruhusu vifaa kujiandikisha kwa uhuru na seva ya MDM iliyowekwa awali mara tu inapoanzishwa.
- Inafaida hasa kwa vifaa vipya, lakini pia inatumika kwa vifaa vinavyopitia usanidi upya.
- Inarahisisha usanidi rahisi, ikifanya vifaa kuwa tayari kwa matumizi ya shirika haraka.

### **Kuzingatia Usalama**

Ni muhimu kutambua kwamba urahisi wa usajili unaotolewa na DEP, ingawa ni wa manufaa, unaweza pia kuleta hatari za usalama. Ikiwa hatua za kinga hazitekelezwi ipasavyo kwa usajili wa MDM, washambuliaji wanaweza kutumia mchakato huu rahisi kujiandikisha kifaa chao kwenye seva ya MDM ya shirika, wakijifanya kuwa kifaa cha kampuni.

> [!CAUTION]
> **Tahadhari ya Usalama**: Usajili wa DEP ulio rahisishwa unaweza kuruhusu usajili usioidhinishwa wa kifaa kwenye seva ya MDM ya shirika ikiwa hatua sahihi za kinga hazipo.

### Msingi Ni SCEP (Protokali ya Usajili wa Cheti Rahisi)?

- Protokali ya zamani, iliyoundwa kabla ya TLS na HTTPS kuwa maarufu.
- Inatoa wateja njia iliyo sanifishwa ya kutuma **Ombi la Kusaini Cheti** (CSR) kwa lengo la kupata cheti. Mteja ataomba seva impe cheti kilichosainiwa.

### Ni Nini Profaili za Usanidi (pia inajulikana kama mobileconfigs)?

- Njia rasmi ya Apple ya **kuweka/kulazimisha usanidi wa mfumo.**
- Muundo wa faili ambao unaweza kuwa na mzigo mwingi.
- Imejengwa kwa orodha za mali (aina ya XML).
- “inaweza kusainiwa na kuandikwa ili kuthibitisha asili yao, kuhakikisha uadilifu wao, na kulinda maudhui yao.” Msingi — Ukurasa wa 70, Mwongozo wa Usalama wa iOS, Januari 2018.

## Protokali

### MDM

- Mchanganyiko wa APNs (**seva za Apple**) + API ya RESTful (**seva za wauzaji wa MDM**)
- **Mawasiliano** hutokea kati ya **kifaa** na seva inayohusishwa na **bidhaa ya usimamizi wa kifaa**
- **Amri** hutolewa kutoka kwa MDM kwenda kwa kifaa katika **kamusi za plist zilizokodishwa**
- Kote **HTTPS**. Seva za MDM zinaweza kuwa (na kawaida huwa) zimepinned.
- Apple inampa muuzaji wa MDM **cheti cha APNs** kwa uthibitisho

### DEP

- **API 3**: 1 kwa wauzaji, 1 kwa wauzaji wa MDM, 1 kwa utambulisho wa kifaa (isiyoandikwa):
- API inayoitwa [DEP "huduma ya wingu"](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Hii inatumika na seva za MDM kuunganisha profaili za DEP na vifaa maalum.
- [API ya DEP inayotumiwa na Wauzaji Waliothibitishwa wa Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) kujiandikisha vifaa, kuangalia hali ya usajili, na kuangalia hali ya muamala.
- API ya DEP ya kibinafsi isiyoandikwa. Hii inatumika na Vifaa vya Apple kuomba profaili yao ya DEP. Kwenye macOS, binary ya `cloudconfigurationd` inawajibika kwa mawasiliano kupitia API hii.
- Ya kisasa zaidi na inategemea **JSON** (kinyume na plist)
- Apple inampa muuzaji wa MDM **token ya OAuth**

**API ya DEP "huduma ya wingu"**

- RESTful
- sambaza rekodi za kifaa kutoka Apple hadi seva ya MDM
- sambaza “profaili za DEP” kwa Apple kutoka seva ya MDM (iliyotolewa na Apple kwa kifaa baadaye)
- Profaili ya DEP ina:
- URL ya seva ya muuzaji wa MDM
- Cheti za ziada za kuaminika kwa URL ya seva (pinned ya hiari)
- Mipangilio ya ziada (mfano: ni skrini zipi za kupita katika Msaidizi wa Usanidi)

## Nambari ya Serial

Vifaa vya Apple vilivyotengenezwa baada ya mwaka 2010 kwa ujumla vina **nambari za serial za alphanumeric za herufi 12**, ambapo **nambari tatu za kwanza zinaonyesha mahali pa utengenezaji**, mbili zinazofuata zinaashiria **mwaka** na **wiki** ya utengenezaji, nambari tatu zinazofuata zinatoa **kitambulisho** **maalum**, na **nambari nne** za mwisho zinaonyesha **nambari ya mfano**.

{{#ref}}
macos-serial-number.md
{{#endref}}

## Hatua za usajili na usimamizi

1. Uundaji wa rekodi ya kifaa (Muuzaji, Apple): Rekodi ya kifaa kipya inaundwa
2. Ugawaji wa rekodi ya kifaa (Mteja): Kifaa kinapewa seva ya MDM
3. Usawazishaji wa rekodi ya kifaa (Muuzaji wa MDM): MDM inasawazisha rekodi za vifaa na kusukuma profaili za DEP kwa Apple
4. Kuangalia DEP (Kifaa): Kifaa kinapata profaili yake ya DEP
5. Urejeleaji wa Profaili (Kifaa)
6. Usanidi wa Profaili (Kifaa) a. ikijumuisha MDM, SCEP na mzigo wa CA wa mizizi
7. Kutolewa kwa amri za MDM (Kifaa)

![](<../../../images/image (694).png>)

Faili `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` inatoa kazi ambazo zinaweza kuzingatiwa kama **"hatua" za juu** za mchakato wa usajili.

### Hatua ya 4: Kuangalia DEP - Kupata Rekodi ya Uanzishaji

Sehemu hii ya mchakato hutokea wakati **mtumiaji anapoanzisha Mac kwa mara ya kwanza** (au baada ya kufuta kabisa)

![](<../../../images/image (1044).png>)

au wakati wa kutekeleza `sudo profiles show -type enrollment`

- Kuamua **kama kifaa kina uwezo wa DEP**
- Rekodi ya Uanzishaji ni jina la ndani la **"profaili" ya DEP**
- Huanzia mara tu kifaa kinapounganishwa kwenye Mtandao
- Inasukumwa na **`CPFetchActivationRecord`**
- Imeanzishwa na **`cloudconfigurationd`** kupitia XPC. **"Msaidizi wa Usanidi"** (wakati kifaa kinapoanzishwa kwa mara ya kwanza) au amri ya **`profiles`** itawasiliana na **daemon** hii ili kupata rekodi ya uanzishaji.
- LaunchDaemon (daima inafanya kazi kama root)

Inafuata hatua chache ili kupata Rekodi ya Uanzishaji inayofanywa na **`MCTeslaConfigurationFetcher`**. Mchakato huu unatumia usimbuaji unaoitwa **Absinthe**

1. Pata **cheti**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Anzisha** hali kutoka kwa cheti (**`NACInit`**)
1. Inatumia data mbalimbali maalum za kifaa (yaani **Nambari ya Serial kupitia `IOKit`**)
3. Pata **funguo ya kikao**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Kuanzisha kikao (**`NACKeyEstablishment`**)
5. Fanya ombi
1. POST kwa [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) ukituma data `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Mzigo wa JSON unakuwa umeandikwa kwa kutumia Absinthe (**`NACSign`**)
3. Maombi yote kupitia HTTPs, cheti za mizizi zilizojengwa ndani zinatumika

![](<../../../images/image (566) (1).png>)

Jibu ni kamusi ya JSON yenye data muhimu kama:

- **url**: URL ya mwenyeji wa muuzaji wa MDM kwa profaili ya uanzishaji
- **cheti za ankara**: Orodha ya cheti za DER zinazotumika kama ankara za kuaminika

### **Hatua ya 5: Urejeleaji wa Profaili**

![](<../../../images/image (444).png>)

- Ombi lilitumwa kwa **url iliyotolewa katika profaili ya DEP**.
- **Cheti za ankara** zinatumika ili **kuthibitisha uaminifu** ikiwa zimetolewa.
- Kumbuka: mali ya **anchor_certs** ya profaili ya DEP
- **Ombi ni .plist** rahisi yenye utambulisho wa kifaa
- Mifano: **UDID, toleo la OS**.
- Imeandikwa CMS, imeandikwa kwa DER
- Imeandikwa kwa kutumia **cheti ya utambulisho wa kifaa (kutoka APNS)**
- **Mnyororo wa cheti** unajumuisha **Apple iPhone Device CA** iliyokwisha muda

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Hatua ya 6: Usanidi wa Profaili

- Mara tu inapopatikana, **profaili inahifadhiwa kwenye mfumo**
- Hatua hii huanza kiotomatiki (ikiwa katika **msaidizi wa usanidi**)
- Inasukumwa na **`CPInstallActivationProfile`**
- Imeanzishwa na mdmclient kupitia XPC
- LaunchDaemon (kama root) au LaunchAgent (kama mtumiaji), kulingana na muktadha
- Profaili za usanidi zina mzigo mwingi wa kusakinisha
- Mfumo huu una usanidi wa msingi wa plugin kwa ajili ya kusakinisha profaili
- Kila aina ya mzigo inahusishwa na plugin
- Inaweza kuwa XPC (katika mfumo) au Cocoa ya jadi (katika ManagedClient.app)
- Mfano:
- Mzigo wa Cheti unatumia CertificateService.xpc

Kwa kawaida, **profaili ya uanzishaji** inayotolewa na muuzaji wa MDM itajumuisha **mifumo ifuatayo**:

- `com.apple.mdm`: ili **kujiandikisha** kifaa katika MDM
- `com.apple.security.scep`: ili kutoa kwa usalama **cheti cha mteja** kwa kifaa.
- `com.apple.security.pem`: ili **kusakinisha cheti za CA zinazotambulika** kwenye Keychain ya Mfumo wa kifaa.
- Kusakinisha mzigo wa MDM ni sawa na **kuangalia MDM katika nyaraka**
- Mzigo **una mali muhimu**:
- - URL ya Kuangalia MDM (**`CheckInURL`**)
- URL ya Kuangalia Amri za MDM (**`ServerURL`**) + mada ya APNs kuisukuma
- Ili kusakinisha mzigo wa MDM, ombi litatumwa kwa **`CheckInURL`**
- Imeanzishwa katika **`mdmclient`**
- Mzigo wa MDM unaweza kutegemea mzigo mingine
- Inaruhusu **maombi kuunganishwa na cheti maalum**:
- Mali: **`CheckInURLPinningCertificateUUIDs`**
- Mali: **`ServerURLPinningCertificateUUIDs`**
- Imetolewa kupitia mzigo wa PEM
- Inaruhusu kifaa kupewa cheti cha utambulisho:
- Mali: IdentityCertificateUUID
- Imetolewa kupitia mzigo wa SCEP

### **Hatua ya 7: Kusikiliza amri za MDM**

- Baada ya kuangalia MDM kukamilika, muuzaji anaweza **kutuma arifa za kusukuma kwa kutumia APNs**
- Mara tu inapopokelewa, inashughulikiwa na **`mdmclient`**
- Ili kupiga kura kwa amri za MDM, ombi litatumwa kwa ServerURL
- Inatumia mzigo wa MDM uliosakinishwa awali:
- **`ServerURLPinningCertificateUUIDs`** kwa ombi la kuunganishwa
- **`IdentityCertificateUUID`** kwa cheti cha mteja cha TLS

## Mashambulizi

### Kujiandikisha Vifaa katika Mashirika Mengine

Kama ilivyosemwa awali, ili kujaribu kujiandikisha kifaa katika shirika **ni nambari ya Serial inayomilikiwa na Shirika hilo pekee inahitajika**. Mara kifaa kinapojisajili, mashirika kadhaa yataweka data nyeti kwenye kifaa kipya: cheti, programu, nywila za WiFi, usanidi wa VPN [na kadhalika](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Hivyo, hii inaweza kuwa njia hatari kwa washambuliaji ikiwa mchakato wa usajili haujalindwa ipasavyo:

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
