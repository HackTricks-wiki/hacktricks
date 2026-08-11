# Kusajili Vifaa katika Mashirika Mengine

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Apple Automated Device Enrollment (zamani ikiitwa DEP) huanza kwa kutambua kifaa kilichokabidhiwa shirika. Utafiti wa mwaka 2018 uliofupishwa hapa ulionyesha kwamba kujua serial number ya kifaa kilichokabidhiwa kulitosha kupata baadhi ya enrollment profiles za mashirika, kwa sababu mashirika hayo hayakuhitaji authentication ya ziada ya kutosha. Hili ni jambo la kihistoria, si madai kwamba kila MDM ya sasa inaweza kujiunga kwa kutumia serial number pekee. Profiles zinaweza kuwa na certificates, applications, siri za Wi-Fi, mipangilio ya VPN, na configuration nyingine nyeti.<sup>[[1]](#references)[[2]](#references)</sup>

**Yafuatayo ni muhtasari wa utafiti [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Iangalie kwa maelezo zaidi ya kiufundi!**<sup>[[1]](#references)</sup>

## Muhtasari wa DEP na Binary Analysis ya MDM

Utafiti ulichanganua binaries zinazohusiana na DEP na MDM katika matoleo ya macOS yaliyokuwa ya sasa wakati huo. Majina na majukumu ya components yanaweza kubadilika kati ya releases:

- **`mdmclient`**: Huwasiliana na MDM servers na kuanzisha DEP check-ins katika matoleo ya macOS ya kabla ya 10.13.4.
- **`profiles`**: Hudhibiti Configuration Profiles, na huanzisha DEP check-ins katika matoleo ya macOS ya 10.13.4 na baadaye.
- **`cloudconfigurationd`**: Hudhibiti mawasiliano ya DEP API na hupata Device Enrollment profiles.

DEP check-ins hutumia functions za `CPFetchActivationRecord` na `CPGetActivationRecord` kutoka private Configuration Profiles framework ili kupata Activation Record, huku `CPFetchActivationRecord` ikiratibu mawasiliano na `cloudconfigurationd` kupitia XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering ya Tesla Protocol na Absinthe Scheme

DEP check-in huhusisha `cloudconfigurationd` kutuma JSON payload iliyosimbwa kwa encryption na kusainiwa kwenye _iprofiles.apple.com/macProfile_. Payload hiyo inajumuisha serial number ya kifaa na action ya "RequestProfileConfiguration". Encryption scheme inayotumika huitwa "Absinthe" internally. Kutengua scheme hii ni jambo gumu na linahusisha hatua nyingi, jambo lililopelekea kuchunguza mbinu mbadala za kuingiza serial numbers za kiholela katika ombi la Activation Record.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Majaribio ya kuzuia na kurekebisha DEP requests zinazoelekezwa _iprofiles.apple.com_ kwa kutumia tools kama Charles Proxy yalikwamishwa na payload encryption pamoja na hatua za usalama za SSL/TLS. Hata hivyo, kuwezesha configuration ya `MCCloudConfigAcceptAnyHTTPSCertificate` huruhusu kupita server certificate validation, ingawa hali ya payload kuwa encrypted bado huzuia kurekebisha serial number bila decryption key.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries Zinazoingiliana na DEP

Kuinstrument system binaries kama `cloudconfigurationd` kunahitaji kuzima System Integrity Protection (SIP) kwenye macOS. SIP ikiwa imezimwa, tools kama LLDB zinaweza kutumika kuambatanishwa na system processes na huenda zikarekebisha serial number inayotumika katika DEP API interactions. Mbinu hii inapendelewa kwa sababu huepuka ugumu wa entitlements na code signing.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Kurekebisha DEP request payload kabla ya JSON serialization katika `cloudconfigurationd` kulionekana kuwa na ufanisi. Mchakato ulihusisha:

1. Kuambatanisha LLDB kwenye `cloudconfigurationd`.
2. Kubaini sehemu ambayo system serial number inapatikana.
3. Kuingiza serial number ya kiholela kwenye memory kabla payload haija-encryptiwa na kutumwa.

Mbinu hii iliwawezesha watafiti kupata DEP profiles za serial numbers zilizotolewa na kukabidhiwa. Haikufanya serial number ya kiholela ambayo haijakabidhiwa iwe halali.<sup>[[1]](#references)</sup>

### Ku-automate Instrumentation kwa Python

Mchakato wa exploitation uli-automatekwa kwa kutumia Python pamoja na LLDB API, na kufanya iwezekane kuingiza serial numbers za kiholela programmatically na kupata DEP profiles zinazolingana.<sup>[[1]](#references)</sup>

### Athari Zinazowezekana za DEP na MDM Vulnerabilities

Utafiti ulionyesha masuala makubwa ya usalama:

1. **Information Disclosure**: Kwa kutoa serial number iliyosajiliwa katika DEP, taarifa nyeti za shirika zilizomo kwenye DEP profile zinaweza kupatikana.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — Usalama wa MDM Me Maybe: Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
