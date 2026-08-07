# Toestelle in Ander Organisasies Inskryf

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Soos [**voorheen kommentaar gelewer**](#what-is-mdm-mobile-device-management)**,** is slegs **'n reeksnommer wat aan daardie organisasie behoort** nodig om 'n toestel by 'n organisasie te probeer inskryf. Sodra die toestel ingeskryf is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: sertifikate, toepassings, WiFi-wagwoorde, VPN-konfigurasies [en so aan](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daarom kan dit 'n gevaarlike toegangspunt vir aanvallers wees indien die inskrywingsproses nie behoorlik beskerm word nie.

**Die volgende is 'n opsomming van die navorsing [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Raadpleeg dit vir verdere tegniese besonderhede!**<sup>[[1]](#references)</sup>

## Oorsig van DEP- en MDM-binêre-analise

Hierdie navorsing ondersoek die binaries wat met die Device Enrollment Program (DEP) en Mobile Device Management (MDM) op macOS geassosieer word. Belangrike komponente sluit in:

- **`mdmclient`**: Kommunikeer met MDM-bedieners en aktiveer DEP-aanmeldings op macOS-weergawes voor 10.13.4.
- **`profiles`**: Bestuur Configuration Profiles en aktiveer DEP-aanmeldings op macOS-weergawes 10.13.4 en later.
- **`cloudconfigurationd`**: Bestuur DEP API-kommunikasie en haal Device Enrollment-profiele op.

DEP-aanmeldings gebruik die `CPFetchActivationRecord`- en `CPGetActivationRecord`-funksies van die private Configuration Profiles-framework om die Activation Record op te haal, met `CPFetchActivationRecord` wat deur middel van XPC met `cloudconfigurationd` koördineer.<sup>[[1]](#references)</sup>

## Omgekeerde Ingenieurswese van die Tesla-protokol en Absinthe-skema

Die DEP-aanmelding behels dat `cloudconfigurationd` 'n geënkripteerde, ondertekende JSON-payload na _iprofiles.apple.com/macProfile_ stuur. Die payload bevat die toestel se reeksnommer en die aksie "RequestProfileConfiguration". Die enkripsieskema wat gebruik word, staan intern as "Absinthe" bekend. Die ontrafeling van hierdie skema is kompleks en behels talle stappe, wat gelei het tot die ondersoek van alternatiewe metodes om arbitrêre reeksnommers in die Activation Record-versoek in te voeg.<sup>[[1]](#references)</sup>

## DEP-versoeke deur 'n proxy stuur

Pogings om DEP-versoeke na _iprofiles.apple.com_ met nutsmiddels soos Charles Proxy te onderskep en te wysig, is deur payload-enkripsie en SSL/TLS-sekuriteitsmaatreëls belemmer. Die aktivering van die `MCCloudConfigAcceptAnyHTTPSCertificate`-konfigurasie laat egter toe dat bedienersertifikaatvalidering omseil word, hoewel die payload se geënkripteerde aard steeds wysiging van die reeksnommer sonder die dekripsiesleutel voorkom.<sup>[[1]](#references)</sup>

## Instrumentering van stelselbinaries wat met DEP interaksie het

Instrumentering van stelselbinaries soos `cloudconfigurationd` vereis dat System Integrity Protection (SIP) op macOS gedeaktiveer word. Met SIP gedeaktiveer kan nutsmiddels soos LLDB gebruik word om aan stelselprosesse te koppel en moontlik die reeksnommer wat in DEP API-interaksies gebruik word, te wysig. Hierdie metode is verkieslik omdat dit die kompleksiteit van entitlements en code signing vermy.<sup>[[1]](#references)</sup>

**Uitbuiting van binêre instrumentering:**
Die wysiging van die DEP-versoek se payload voor JSON-serialisering in `cloudconfigurationd` was effektief. Die proses het die volgende behels:

1. Koppel LLDB aan `cloudconfigurationd`.
2. Vind die punt waar die stelselreeksnommer opgehaal word.
3. Voeg 'n arbitrêre reeksnommer in die geheue in voordat die payload geënkripteer en gestuur word.

Hierdie metode het dit moontlik gemaak om volledige DEP-profiele vir arbitrêre reeksnommers op te haal, wat 'n potensiële kwesbaarheid gedemonstreer het.<sup>[[1]](#references)</sup>

### Instrumentering met Python outomatiseer

Die uitbuitingsproses is geoutomatiseer deur Python met die LLDB API te gebruik, wat dit haalbaar gemaak het om arbitrêre reeksnommers programmaties in te voeg en die ooreenstemmende DEP-profiele op te haal.<sup>[[1]](#references)</sup>

### Potensiële impakte van DEP- en MDM-kwesbaarhede

Die navorsing het beduidende sekuriteitskwessies uitgelig:

1. **Inligtingsopenbaring**: Deur 'n DEP-geregistreerde reeksnommer te verskaf, kan sensitiewe organisatoriese inligting wat in die DEP-profiel vervat is, opgehaal word.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
