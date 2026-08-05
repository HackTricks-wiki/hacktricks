# Kusajili Devices katika Mashirika Mengine

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Kama [**ilivyoelezwa hapo awali**](#what-is-mdm-mobile-device-management)**,** ili kujaribu kusajili device katika shirika, **Serial Number ya shirika hilo pekee ndiyo inahitajika**. Baada ya device kusajiliwa, mashirika kadhaa yatasakinisha data nyeti kwenye device hiyo mpya: certificates, applications, WiFi passwords, VPN configurations [na kadhalika](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Kwa hivyo, hii inaweza kuwa entrypoint hatari kwa attackers ikiwa mchakato wa usajili haujalindwa ipasavyo.

**Ifuatayo ni muhtasari wa utafiti [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Isome kwa maelezo zaidi ya kiufundi!**<sup>[[1]](#references)</sup>

## Muhtasari wa DEP na MDM Binary Analysis

Utafiti huu unachunguza binaries zinazohusishwa na Device Enrollment Program (DEP) na Mobile Device Management (MDM) kwenye macOS. Vipengele muhimu ni pamoja na:

- **`mdmclient`**: Huwasiliana na MDM servers na kuanzisha DEP check-ins kwenye matoleo ya macOS yaliyo kabla ya 10.13.4.
- **`profiles`**: Husimamia Configuration Profiles, na huanzisha DEP check-ins kwenye matoleo ya macOS ya 10.13.4 na baadaye.
- **`cloudconfigurationd`**: Husimamia mawasiliano ya DEP API na kupata Device Enrollment profiles.

DEP check-ins hutumia functions za `CPFetchActivationRecord` na `CPGetActivationRecord` kutoka private Configuration Profiles framework ili kupata Activation Record, huku `CPFetchActivationRecord` ikiratibu mawasiliano na `cloudconfigurationd` kupitia XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering ya Tesla Protocol na Absinthe Scheme

DEP check-in inahusisha `cloudconfigurationd` kutuma JSON payload iliyosimbwa na kusainiwa kwenda _iprofiles.apple.com/macProfile_. Payload hiyo inajumuisha serial number ya device na action ya "RequestProfileConfiguration". Encryption scheme inayotumika huitwa "Absinthe" internally. Kuifumbua scheme hii ni jambo gumu na linahusisha hatua nyingi, jambo lililosababisha kuchunguza methods mbadala za kuingiza serial numbers holela katika ombi la Activation Record.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Majaribio ya kukatiza na kurekebisha DEP requests kwenda _iprofiles.apple.com_ kwa kutumia tools kama Charles Proxy yalizuiwa na payload encryption pamoja na hatua za usalama za SSL/TLS. Hata hivyo, kuwezesha configuration ya `MCCloudConfigAcceptAnyHTTPSCertificate` huruhusu kupita server certificate validation, ingawa hali ya payload iliyosimbwa bado inazuia kurekebisha serial number bila decryption key.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries Zinazoingiliana na DEP

Ku-instrument system binaries kama `cloudconfigurationd` kunahitaji kuzima System Integrity Protection (SIP) kwenye macOS. SIP ikiwa imezimwa, tools kama LLDB zinaweza kutumika ku-attach kwenye system processes na huenda zikarekebisha serial number inayotumika katika DEP API interactions. Method hii inapendelewa kwa sababu huepuka ugumu wa entitlements na code signing.

**Exploiting Binary Instrumentation:**
Kurekebisha DEP request payload kabla ya JSON serialization katika `cloudconfigurationd` kulionekana kuwa effective. Mchakato ulihusisha:

1. Ku-attach LLDB kwenye `cloudconfigurationd`.
2. Kutafuta sehemu ambayo system serial number inapatikana.
3. Kuingiza serial number holela kwenye memory kabla payload haijasimbwa na kutumwa.

Method hii iliruhusu kupata DEP profiles kamili za serial numbers holela, ikionyesha vulnerability inayoweza kutumiwa.<sup>[[1]](#references)</sup>

### Ku-automate Instrumentation kwa Python

Mchakato wa exploitation uli-automate kwa kutumia Python pamoja na LLDB API, na kufanya iwezekane kuingiza serial numbers holela programmatically na kupata DEP profiles zinazohusiana.<sup>[[1]](#references)</sup>

### Potential Impacts za DEP na MDM Vulnerabilities

Utafiti ulionyesha concerns kubwa za usalama:

1. **Information Disclosure**: Kwa kutoa serial number iliyosajiliwa kwenye DEP, taarifa nyeti za shirika zilizomo kwenye DEP profile zinaweza kupatikana.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
