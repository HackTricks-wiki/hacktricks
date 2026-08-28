# Kusajili Devices katika Mashirika Mengine

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Apple Automated Device Enrollment (zamani DEP) huanza kwa kutambua device iliyopewa organization. Utafiti wa mwaka 2018 uliowasilishwa hapa ulionyesha kuwa kujua serial number iliyotolewa kulitosha kupata enrollment profiles za baadhi ya organizations, kwa sababu organizations hizo hazikuhitaji authentication ya ziada ya kutosha. Hili ni tangazo la kihistoria, si dai kwamba kila MDM ya sasa inaweza kujiunga kwa kutumia serial number pekee. Profiles zinaweza kuwa na certificates, applications, Wi-Fi secrets, VPN settings, na configuration nyingine nyeti.<sup>[[1]](#references)[[2]](#references)</sup>

**Ifuatayo ni muhtasari wa utafiti [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Iangalie kwa maelezo zaidi ya kiufundi!**<sup>[[1]](#references)</sup>

## Muhtasari wa DEP na MDM Binary Analysis

Utafiti huo ulichanganua binaries zinazohusiana na DEP na MDM katika matoleo ya macOS yaliyokuwa ya sasa wakati huo. Majina na majukumu ya components yanaweza kubadilika katika releases mbalimbali:

- **`mdmclient`**: Huwasiliana na MDM servers na kuanzisha DEP check-ins kwenye matoleo ya macOS yaliyo kabla ya 10.13.4.
- **`profiles`**: Hudhibiti Configuration Profiles na kuanzisha DEP check-ins kwenye matoleo ya macOS ya 10.13.4 na ya baadaye.
- **`cloudconfigurationd`**: Hudhibiti mawasiliano ya DEP API na hupata Device Enrollment profiles.

DEP check-ins hutumia functions za `CPFetchActivationRecord` na `CPGetActivationRecord` kutoka private Configuration Profiles framework ili kupata Activation Record, huku `CPFetchActivationRecord` ikiratibu mawasiliano na `cloudconfigurationd` kupitia XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering ya Tesla Protocol na Absinthe Scheme

DEP check-in huhusisha `cloudconfigurationd` kutuma JSON payload iliyosimbwa na kusainiwa kwenda _iprofiles.apple.com/macProfile_. Payload hiyo ina serial number ya device na action ya "RequestProfileConfiguration". Encryption scheme inayotumiwa huitwa "Absinthe" ndani ya mfumo. Kuufichua utaratibu huu ni changamano na huhusisha hatua nyingi, jambo lililopelekea kuchunguza methods mbadala za kuingiza serial numbers kiholela kwenye ombi la Activation Record.<sup>[[1]](#references)</sup>

## Proxying Maombi ya DEP

Majaribio ya kuintercept na kurekebisha DEP requests kwenda _iprofiles.apple.com_ kwa kutumia tools kama Charles Proxy yalizuiwa na payload encryption pamoja na hatua za usalama za SSL/TLS. Hata hivyo, kuwezesha configuration ya `MCCloudConfigAcceptAnyHTTPSCertificate` huruhusu kupita server certificate validation, ingawa hali iliyosimbwa ya payload bado huzuia kurekebisha serial number bila decryption key.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries Zinazoingiliana na DEP

Kufanya Instrumenting ya system binaries kama `cloudconfigurationd` kunahitaji kuzima System Integrity Protection (SIP) kwenye macOS. SIP ikiwa imezimwa, tools kama LLDB zinaweza kutumiwa kuattach kwenye system processes na huenda zikarekebisha serial number inayotumiwa katika DEP API interactions. Njia hii inapendelewa kwa sababu huepuka ugumu wa entitlements na code signing.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Kurekebisha DEP request payload kabla ya JSON serialization katika `cloudconfigurationd` kulithibitika kuwa na ufanisi. Mchakato ulihusisha:

1. Kuattach LLDB kwenye `cloudconfigurationd`.
2. Kutafuta sehemu ambayo system serial number hupatikana.
3. Kuingiza serial number ya kiholela kwenye memory kabla payload haijasimbwa na kutumwa.

Njia hii iliwawezesha watafiti kupata DEP profiles za serial numbers zilizotolewa na kupewa. Haikufanya serial number ya kiholela ambayo haijapewa kuwa halali.<sup>[[1]](#references)</sup>

### Kuautomate Instrumentation kwa Python

Mchakato wa exploitation uli-automate kwa kutumia Python pamoja na LLDB API, na hivyo kufanya iwezekane kuingiza serial numbers kiholela kwa njia ya programmatically na kupata DEP profiles zinazolingana.<sup>[[1]](#references)</sup>

## Mapitio ya 2025: Rogue Enrollment kutoka kwa VM

Utafiti wa Black Hat Asia 2025 ulionyesha kwamba tatizo la awali la trust boundary bado linaweza kuwa muhimu katika **MDM layer**: badala ya kupatch `cloudconfigurationd` kwa LLDB, watafiti waliendesha macOS chini ya QEMU/KVM pamoja na OpenCore na kutoa candidate identity kupitia SMBIOS ya VM. Enrollment stack ya macOS ambayo haikubadilishwa iliendesha encrypted Apple exchange. Kwa hiyo, serials zilizoleak hadharani na candidates zinazoonekana kuwa halali zinaweza kujaribiwa bila kuwa na Mac halisi inayolingana; hit bado inahitaji serial hiyo iwe imepewa organization na enrollment path ya organization hiyo isiwe na authentication ya kutosha.<sup>[[3]](#references)</sup>

Kwa device ya maabara iliyoidhinishwa, OpenCore `PlatformInfo` values zinazohusika zinajumuisha product model na serial (katika deployments halisi, ROM na UUID pia huwekwa zikiwa consistent internally):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
Utafiti huo huo ulibaini hali ya `CheckProfilesFetchRateLimit` katika faili binafsi `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Kwa kuwa ukaguzi huo ulidumishwa kwenye client, kurekebisha thamani za muda zilizohifadhiwa kuliushinda. Njia hizi hazijaandikwa kwenye nyaraka rasmi na hutegemea toleo, lakini ni pivots muhimu za reversing wakati wa kutathmini build ya sasa ya macOS:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Kipengee cha pili kinaweza kufichua activation record iliyohifadhiwa kwenye cache, ikijumuisha ikiwa mtiririko unatumia `ConfigurationURL` ya moja kwa moja au `ConfigurationWebURL` inayohitaji uthibitishaji. Jaribu mtiririko uliotangazwa pamoja na endpoint zozote za zamani za enrollment za MDM: kuwezesha SSO kwenye mtiririko mkuu wa wavuti pekee hakulindi endpoint ya moja kwa moja iliyo sambamba. Kwa mfuatano kamili wa protocol, angalia [macOS MDM overview](README.md).<sup>[[3]](#references)</sup>

### Uwindaji wa Secrets Baada ya Enrollment

Enrollment isiyoruhusiwa ni hatua ya kuanzia tu. Baada ya enrollment, kagua kila profile iliyowasilishwa, bootstrap policy, usanidi wa package-repository, installation script ya agent, na kipengee cha self-service. Utafiti wa 2025 ulipata mifano ya credentials za Wi-Fi, passwords za pamoja za local-administrator, URLs zilizotiwa saini za cloud-storage, URLs za webhook, data ya activation ya security-agent, na credentials za MDM/API. Credential ya tenant API iliyo kwenye script iliyowasilishwa inaweza kubadilisha endpoint moja isiyoruhusiwa kuwa udhibiti wa devices nyingine zinazosimamiwa, kwa hiyo tafuta kwenye live filesystem na kwenye policy content iliyopakuliwa au iliyohifadhiwa kwenye cache.<sup>[[3]](#references)</sup>

Malengo muhimu ya ukaguzi ni pamoja na:<sup>[[3]](#references)</sup>

- Payloads za `.mobileconfig` zilizowekwa na database ya Configuration Profiles.
- PreStage/bootstrap scripts na packages zinazounda accounts au kusakinisha EDR/VPN agents.
- URLs za Munki au package repository nyingine, hasa query strings zenye signatures za bearer/SAS.
- Self-service catalogs na backing policy APIs zake, ikijumuisha routes za zamani ambazo huenda hazitekelezi enrollment SSO policy.
- Shell history na policy output iliyohifadhiwa kwenye cache kwa maneno ya `password`, `token`, `secret`, `Authorization`, majina ya host ya webhook, na vendor API endpoints.

### Kuimarisha Mpaka wa Trust

Chukulia serial number kama sifa ya inventory/routing, **si** uthibitisho wa umiliki. Hitaji user authentication kwa enrollment na self service, tengeneza passwords za kipekee za local administrator kwa kila device, na usiwahi kuingiza tenant API credentials au infrastructure secrets zinazoweza kutumika tena ndani ya profiles au scripts. Weka bootstrap token yoyote isiyoepukika iwe ya muda mfupi na izuiwe kwa action moja na device moja inayosanidiwa.<sup>[[3]](#references)</sup>

Kwenye Macs zenye Apple silicon zinazoendesha macOS 14 au matoleo ya baadaye, Managed Device Attestation inaweza kuunganisha identity na Secure Enclave kwa njia ya cryptographic. Attestation yake yenye mzizi wa Apple inaweza kubeba nonce mpya pamoja na serial number, UDID, OS version, hali ya SIP, na hali ya secure-boot; ACME inaweza kisha kutoa client identity iliyofungwa kwenye hardware. Tumia identity hiyo kulinda MDM channel na kudhibiti certificates zenye thamani kubwa, ufikiaji wa VPN, na resources nyingine, huku ukiendelea kutumia user authentication tofauti kwa sababu device attestation inathibitisha device badala ya operator.<sup>[[4]](#references)</sup>

## Athari Zinazowezekana za DEP na MDM Vulnerabilities

Utafiti ulionyesha masuala makubwa ya usalama:

1. **Ufichuaji wa Taarifa**: Kwa kutoa serial number iliyosajiliwa kwenye DEP, taarifa nyeti za shirika zilizomo kwenye DEP profile zinaweza kupatikana.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Usalama wa Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
