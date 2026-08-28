# Toestelle by ander organisasies inskryf

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Apple Automated Device Enrollment (voorheen DEP) begin deur ’n toestel te identifiseer wat aan ’n organisasie toegeken is. Die navorsing uit 2018 wat hier opgesom word, het getoon dat kennis van ’n toegekende reeksnommer voldoende was om sommige organisasies se enrollment-profiele te verkry, omdat daardie organisasies nie voldoende bykomende verifikasie vereis het nie. Dit is ’n historiese bevinding, nie ’n bewering dat elke huidige MDM slegs met ’n reeksnommer aangesluit kan word nie. Profiele kan sertifikate, toepassings, Wi-Fi-geheime, VPN-instellings en ander sensitiewe konfigurasie bevat.<sup>[[1]](#references)[[2]](#references)</sup>

**Die volgende is ’n opsomming van die navorsing [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Raadpleeg dit vir verdere tegniese besonderhede!**<sup>[[1]](#references)</sup>

## Oorsig van DEP- en MDM-binêre-analise

Die navorsing het binaries ontleed wat met DEP en MDM geassosieer word op die macOS-weergawes wat destyds aktueel was. Komponentname en verantwoordelikhede kan tussen vrystellings verander:

- **`mdmclient`**: Kommunikeer met MDM-bedieners en aktiveer DEP check-ins op macOS-weergawes voor 10.13.4.
- **`profiles`**: Bestuur Configuration Profiles en aktiveer DEP check-ins op macOS-weergawes 10.13.4 en later.
- **`cloudconfigurationd`**: Bestuur DEP API-kommunikasie en haal Device Enrollment-profiele op.

DEP check-ins gebruik die `CPFetchActivationRecord`- en `CPGetActivationRecord`-funksies uit die private Configuration Profiles-framework om die Activation Record te haal, met `CPFetchActivationRecord` wat met `cloudconfigurationd` deur XPC koördineer.<sup>[[1]](#references)</sup>

## Tesla Protocol- en Absinthe Scheme-omgekeerde ingenieurswese

Die DEP check-in behels dat `cloudconfigurationd` ’n geënkripteerde, ondertekende JSON-payload na _iprofiles.apple.com/macProfile_ stuur. Die payload bevat die toestel se reeksnommer en die aksie "RequestProfileConfiguration". Die enkripsieskema wat intern as "Absinthe" bekend staan, word gebruik. Om hierdie skema te ontrafel, is kompleks en behels dit talle stappe, wat daartoe gelei het dat alternatiewe metodes ondersoek is om arbitrêre reeksnommers in die Activation Record-versoek in te voeg.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Pogings om DEP-versoeke na _iprofiles.apple.com_ met instrumente soos Charles Proxy te onderskep en te wysig, is deur payload-enkripsie en SSL/TLS-sekuriteitsmaatreëls belemmer. Deur die `MCCloudConfigAcceptAnyHTTPSCertificate`-konfigurasie te aktiveer, kan die bedienersertifikaatvalidasie egter omseil word, hoewel die payload se geënkripteerde aard steeds wysiging van die reeksnommer sonder die dekripsiesleutel voorkom.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries Interacting with DEP

Om stelselbinaries soos `cloudconfigurationd` te instrumenteer, vereis dat System Integrity Protection (SIP) op macOS gedeaktiveer word. Met SIP gedeaktiveer, kan instrumente soos LLDB gebruik word om aan stelselprosesse te koppel en moontlik die reeksnommer te wysig wat in DEP API-interaksies gebruik word. Hierdie metode is verkieslik omdat dit die kompleksiteite van entitlements en code signing vermy.<sup>[[1]](#references)</sup>

**Uitbuiting van binêre-instrumentering:**
Die wysiging van die DEP-versoekpayload voor JSON-serialisering in `cloudconfigurationd` was effektief. Die proses het die volgende behels:

1. Koppel LLDB aan `cloudconfigurationd`.
2. Vind die punt waar die stelselreeksnommer opgehaal word.
3. Voeg ’n arbitrêre reeksnommer in die geheue in voordat die payload geënkripteer en gestuur word.

Hierdie metode het die navorsers toegelaat om DEP-profiele vir verskafde, toegekende reeksnommers op te haal. Dit het nie ’n ontoegekende arbitrêre reeksnommer geldig gemaak nie.<sup>[[1]](#references)</sup>

### Automating Instrumentation with Python

Die uitbuitingsproses is geoutomatiseer met Python en die LLDB API, wat dit haalbaar gemaak het om arbitrêre reeksnommers programmaties in te voeg en die ooreenstemmende DEP-profiele op te haal.<sup>[[1]](#references)</sup>

## 2025 Hersiening: Rogue Enrollment from a VM

Black Hat Asia 2025-navorsing het getoon dat die oorspronklike trust-boundary-probleem steeds op die **MDM-laag** van belang kan wees: in plaas daarvan om `cloudconfigurationd` met LLDB te patch, het die navorsers macOS onder QEMU/KVM met OpenCore laat loop en die kandidaat-identiteit deur die VM se SMBIOS verskaf. Die onveranderde macOS-enrollment stack het daarna die geënkripteerde Apple-uitruiling uitgevoer. Publiek gelekte reeksnommers en kandidate wat geldig lyk, kan dus getoets word sonder om die ooreenstemmende fisiese Mac te besit; ’n treffer vereis steeds dat die reeksnommer aan ’n organisasie toegeken is en dat die organisasie se enrollment-pad onvoldoende geverifieer word.<sup>[[3]](#references)</sup>

Vir ’n gemagtigde laboratoriumtoestel sluit die relevante OpenCore-`PlatformInfo`-waardes ’n produkmodel en reeksnommer in (werklike ontplooiings hou ook die ROM en UUID intern konsekwent):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
Dieselfde navorsing het die `CheckProfilesFetchRateLimit`-toestand in die private lêer `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck` geïdentifiseer. Omdat die kontrole op die kliënt gehandhaaf is, het die wysiging van die gestoorde tydwaardes dit verydel. Hierdie paaie is ongedokumenteerd en weergawe-afhanklik, maar hulle is nuttige reversing-pivots wanneer ’n huidige macOS-build geassesseer word:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Die tweede artefak kan die gekasht aktiveringsrekord openbaar, insluitend of die vloei ’n direkte `ConfigurationURL` of ’n geverifieerde `ConfigurationWebURL` gebruik. Toets beide die geadverteerde vloei en enige MDM-spesifieke legacy-enrollment-endpunte: om SSO slegs op die hoof-webvloei te aktiveer, beskerm nie ’n parallelle direkte endpoint nie. Raadpleeg die [macOS MDM overview](README.md) vir die volledige protokolvolgorde.<sup>[[3]](#references)</sup>

### Soek na geheime ná enrollment

’n Rogue enrollment is slegs die toegangspunt. Inspekteer ná enrollment elke afgelewerde profiel, bootstrap-beleid, pakketbewaarplek-konfigurasie, agent-installation script en self-service-item. Die 2025-navorsing het voorbeelde gevind van Wi-Fi-geloofsbriewe, gedeelde plaaslike-administrateurwagwoorde, getekende cloud-storage-URL’s, webhook-URL’s, security-agent-aktiveringsdata en MDM/API-geloofsbriewe. ’n Tenant API-geloofsbrief in ’n afgelewerde script kan een rogue endpoint in beheer oor ander bestuurde toestelle verander; soek dus in beide die aktiewe lêerstelsel en afgelaaide/gekashtte beleidsinhoud.<sup>[[3]](#references)</sup>

Nuttige teikens vir hersiening sluit in:<sup>[[3]](#references)</sup>

- Geïnstalleerde `.mobileconfig`-payloads en die Configuration Profiles-databasis.
- PreStage/bootstrap-scripts en pakkette wat rekeninge skep of EDR/VPN-agents installeer.
- Munki- of ander pakketbewaarplek-URL’s, veral query strings wat bearer/SAS-st handtekeninge bevat.
- Self-service-katalogusse en hul ondersteunende beleids-API’s, insluitend legacy-roetes wat moontlik nie die enrollment SSO-beleid afdwing nie.
- Shell history en gekashtte beleidsuitset vir `password`, `token`, `secret`, `Authorization`, webhook-gasheername en vendor API-endpunte.

### Versterking van die trust boundary

Behandel ’n reeksnommer as ’n inventaris-/roeteringskenmerk, **nie** as bewys van besit nie. Vereis user authentication vir enrollment en self-service, genereer unieke plaaslike-administrateurwagwoorde per toestel en moet nooit tenant API-geloofsbriewe of herbruikbare infrastruktuurgeheime in profiele of scripts insluit nie. Hou enige onvermydelike bootstrap-token kortstondig en beperk dit tot die enkele aksie en toestel wat voorsien word.<sup>[[3]](#references)</sup>

Op Apple-silicon-Macs met macOS 14 of later kan Managed Device Attestation identiteit kriptografies aan die Secure Enclave bind. Die Apple-gewortelde attestation kan ’n vars nonce plus die reeksnommer, UDID, OS-weergawe, SIP-status en secure-boot-status bevat; ACME kan dan ’n hardewaregebonde kliëntidentiteit uitreik. Gebruik daardie identiteit om die MDM-kanaal te beskerm en hoëwaarde-sertifikate, VPN-toegang en ander hulpbronne te beheer, maar behou afsonderlike user authentication omdat device attestation die toestel, eerder as die operateur, bewys.<sup>[[4]](#references)</sup>

## Potential Impacts of DEP and MDM Vulnerabilities

Die navorsing het beduidende sekuriteitskwessies beklemtoon:

1. **Inligtingsopenbaarmaking**: Deur ’n DEP-geregistreerde reeksnommer te verskaf, kan sensitiewe organisatoriese inligting in die DEP-profiel verkry word.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
