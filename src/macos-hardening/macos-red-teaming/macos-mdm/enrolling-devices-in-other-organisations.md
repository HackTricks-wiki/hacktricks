# Kusajili Vifaa katika Mashirika Mengine

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Kama [**ilivyotajwa awali**](#what-is-mdm-mobile-device-management)**,** ili kujaribu kusajili kifaa katika shirika **inahitajika tu Serial Number inayomilikiwa na Shirika hilo**. Baada ya kifaa kusajiliwa, mashirika kadhaa yataweka data nyeti kwenye kifaa hicho kipya: certificates, applications, WiFi passwords, VPN configurations [na kadhalika](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Kwa hivyo, hii inaweza kuwa entrypoint hatari kwa attackers ikiwa mchakato wa usajili haujalindwa ipasavyo.

**Yafuatayo ni muhtasari wa utafiti [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Uupitie kwa maelezo zaidi ya kiufundi!**<sup>[1]</sup>

## Muhtasari wa DEP na Uchambuzi wa Binary wa MDM

Utafiti huu unachunguza binaries zinazohusishwa na Device Enrollment Program (DEP) na Mobile Device Management (MDM) kwenye macOS. Vipengele muhimu ni pamoja na:

- **`mdmclient`**: Huwasiliana na MDM servers na huanzisha DEP check-ins kwenye matoleo ya macOS yaliyo kabla ya 10.13.4.
- **`profiles`**: Hudhibiti Configuration Profiles, na huanzisha DEP check-ins kwenye matoleo ya macOS ya 10.13.4 na ya baadaye.
- **`cloudconfigurationd`**: Hudhibiti mawasiliano ya DEP API na hupata Device Enrollment profiles.

DEP check-ins hutumia functions za `CPFetchActivationRecord` na `CPGetActivationRecord` kutoka kwenye private Configuration Profiles framework ili kupata Activation Record, huku `CPFetchActivationRecord` ikiratibu mawasiliano na `cloudconfigurationd` kupitia XPC.<sup>[1]</sup>

## Tesla Protocol na Reverse Engineering ya Absinthe Scheme

DEP check-in inahusisha `cloudconfigurationd` kutuma JSON payload iliyosimbwa na kusainiwa kwenda _iprofiles.apple.com/macProfile_. Payload hiyo inajumuisha serial number ya kifaa na action ya "RequestProfileConfiguration". Encryption scheme inayotumiwa huitwa "Absinthe" ndani ya mfumo. Kuifumbua scheme hii ni jambo tata linalohusisha hatua nyingi, hali iliyopelekea kuchunguza mbinu mbadala za kuingiza serial numbers arbitrary katika ombi la Activation Record.<sup>[1]</sup>

## Ku-Proxy DEP Requests

Majaribio ya ku-intercept na kurekebisha DEP requests kwenda _iprofiles.apple.com_ kwa kutumia tools kama Charles Proxy yalikwamishwa na payload encryption pamoja na hatua za usalama za SSL/TLS. Hata hivyo, kuwezesha configuration ya `MCCloudConfigAcceptAnyHTTPSCertificate` huruhusu kupita server certificate validation, ingawa hali ya payload kuwa encrypted bado huzuia kurekebisha serial number bila decryption key.<sup>[1]</sup>

## Ku-Instrument System Binaries Zinazoingiliana na DEP

Ku-instrument system binaries kama `cloudconfigurationd` kunahitaji kuzima System Integrity Protection (SIP) kwenye macOS. SIP ikiwa imezimwa, tools kama LLDB zinaweza kutumika ku-attach kwenye system processes na huenda zikarekebisha serial number inayotumiwa katika DEP API interactions. Mbinu hii inapendelewa kwa sababu huepuka ugumu wa entitlements na code signing.

**Kum-exploit Binary Instrumentation:**
Kurekebisha DEP request payload kabla ya JSON serialization kwenye `cloudconfigurationd` kulithibitika kuwa na ufanisi. Mchakato ulihusisha:

1. Ku-attach LLDB kwenye `cloudconfigurationd`.
2. Kutafuta sehemu ambayo system serial number inapatikana.
3. Kuingiza arbitrary serial number kwenye memory kabla payload haijasimbwa na kutumwa.

Mbinu hii iliruhusu kupatikana kwa DEP profiles kamili za arbitrary serial numbers, ikionyesha vulnerability inayoweza kutumiwa.<sup>[1]</sup>

### Ku-Automate Instrumentation kwa Python

Mchakato wa exploitation uli-automate kwa kutumia Python pamoja na LLDB API, na kufanya iwezekane kuingiza arbitrary serial numbers programmatically na kupata DEP profiles zinazolingana.<sup>[1]</sup>

### Athari Zinazowezekana za DEP na MDM Vulnerabilities

Utafiti ulionyesha concerns kubwa za kiusalama:

1. **Information Disclosure**: Kwa kutoa serial number iliyosajiliwa kwenye DEP, taarifa nyeti za shirika zilizomo kwenye DEP profile zinaweza kupatikana.<sup>[1]</sup>

## Marejeleo

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
