# Toestelle by Ander Organisasies Inskryf

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Soos [**voorheen opgemerk**](#what-is-mdm-mobile-device-management)**,** is slegs ’n reeksnommer wat aan daardie organisasie behoort nodig om ’n toestel by ’n organisasie te probeer inskryf. Nadat die toestel ingeskryf is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: sertifikate, toepassings, WiFi-wagwoorde, VPN-konfigurasies [en so meer](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daarom kan dit ’n gevaarlike toegangspunt vir aanvallers wees indien die inskrywingsproses nie behoorlik beskerm word nie.

**Die volgende is ’n opsomming van die navorsing [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Raadpleeg dit vir verdere tegniese besonderhede!**<sup>[[1]](#references)</sup>

## Oorsig van DEP- en MDM-binêre-analise

Hierdie navorsing ondersoek die binaries wat met die Device Enrollment Program (DEP) en Mobile Device Management (MDM) op macOS geassosieer word. Belangrike komponente sluit in:

- **`mdmclient`**: Kommunikeer met MDM-bedieners en aktiveer DEP check-ins op macOS-weergawes voor 10.13.4.
- **`profiles`**: Bestuur Configuration Profiles en aktiveer DEP check-ins op macOS-weergawes 10.13.4 en later.
- **`cloudconfigurationd`**: Bestuur DEP API-kommunikasie en haal Device Enrollment-profiele op.

DEP check-ins gebruik die `CPFetchActivationRecord`- en `CPGetActivationRecord`-funksies uit die private Configuration Profiles-framework om die Activation Record op te haal, waar `CPFetchActivationRecord` met `cloudconfigurationd` deur middel van XPC koördineer.<sup>[[1]](#references)</sup>

## Tesla-protokol en Absinthe Scheme Reverse Engineering

Die DEP check-in behels dat `cloudconfigurationd` ’n geënkripteerde, ondertekende JSON-payload na _iprofiles.apple.com/macProfile_ stuur. Die payload bevat die toestel se reeksnommer en die aksie "RequestProfileConfiguration". Die encryption scheme wat gebruik word, word intern na verwys as "Absinthe". Om hierdie scheme te ontrafel is kompleks en behels talle stappe, wat gelei het tot die ondersoek van alternatiewe metodes om arbitrêre reeksnommers in die Activation Record-versoek in te voeg.<sup>[[1]](#references)</sup>

## Proxying van DEP-versoeke

Pogings om DEP-versoeke na _iprofiles.apple.com_ met tools soos Charles Proxy te onderskep en te wysig, is deur payload-enkripsie en SSL/TLS-sekuriteitsmaatreëls bemoeilik. Deur die `MCCloudConfigAcceptAnyHTTPSCertificate`-konfigurasie te aktiveer, kan die bedienersertifikaatvalidasie egter omseil word, hoewel die geënkripteerde aard van die payload steeds verhoed dat die reeksnommer sonder die decryption key gewysig word.<sup>[[1]](#references)</sup>

## Instrumentering van Stelselbinaries wat met DEP Interaksie het

Om stelselbinaries soos `cloudconfigurationd` te instrumenteer, vereis dat System Integrity Protection (SIP) op macOS gedeaktiveer word. Met SIP gedeaktiveer kan tools soos LLDB gebruik word om aan stelselprosesse te koppel en moontlik die reeksnommer wat in DEP API-interaksies gebruik word, te wysig. Hierdie metode is verkieslik omdat dit die kompleksiteit van entitlements en code signing vermy.

**Ontginning van Binêre Instrumentering:**
Die wysiging van die DEP-versoekpayload voor JSON-serialisering in `cloudconfigurationd` was effektief. Die proses het die volgende behels:

1. Koppel LLDB aan `cloudconfigurationd`.
2. Vind die punt waar die stelselreeksnommer opgehaal word.
3. Spuit ’n arbitrêre reeksnommer in die geheue in voordat die payload geënkripteer en gestuur word.

Hierdie metode het dit moontlik gemaak om volledige DEP-profiele vir arbitrêre reeksnommers op te haal, wat ’n potensiële kwesbaarheid gedemonstreer het.<sup>[[1]](#references)</sup>

### Outomatisering van Instrumentering met Python

Die exploitation-proses is met Python en die LLDB API geoutomatiseer, wat dit haalbaar gemaak het om arbitrêre reeksnommers programmaties in te spuit en die ooreenstemmende DEP-profiele op te haal.<sup>[[1]](#references)</sup>

### Potensiële Impakte van DEP- en MDM-kwesbaarhede

Die navorsing het beduidende sekuriteitskwessies uitgelig:

1. **Inligtingsopenbaarmaking**: Deur ’n DEP-geregistreerde reeksnommer te verskaf, kan sensitiewe organisasie-inligting in die DEP-profiel opgehaal word.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
