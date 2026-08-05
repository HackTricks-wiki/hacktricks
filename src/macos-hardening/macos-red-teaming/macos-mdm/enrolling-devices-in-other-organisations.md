# Toestelle by Ander Organisasies Inskryf

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Soos [**voorheen genoem**](#what-is-mdm-mobile-device-management)**,** is **slegs 'n Serial Number wat aan daardie organisasie behoort nodig** om 'n toestel by 'n organisasie te probeer inskryf. Sodra die toestel ingeskryf is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: sertifikate, toepassings, WiFi-wagwoorde, VPN-konfigurasies [en so aan](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daarom kan dit 'n gevaarlike toegangspunt vir aanvallers wees indien die inskrywingsproses nie behoorlik beskerm word nie.

**Die volgende is 'n opsomming van die navorsing [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Raadpleeg dit vir verdere tegniese besonderhede!**<sup>[1]</sup>

## Oorsig van DEP- en MDM Binary Analysis

Hierdie navorsing ondersoek die binaries wat met die Device Enrollment Program (DEP) en Mobile Device Management (MDM) op macOS geassosieer word. Belangrike komponente sluit in:

- **`mdmclient`**: Kommunikeer met MDM-bedieners en aktiveer DEP check-ins op macOS-weergawes voor 10.13.4.
- **`profiles`**: Bestuur Configuration Profiles en aktiveer DEP check-ins op macOS-weergawes 10.13.4 en later.
- **`cloudconfigurationd`**: Bestuur DEP API-kommunikasie en haal Device Enrollment-profiele op.

DEP check-ins gebruik die `CPFetchActivationRecord`- en `CPGetActivationRecord`-funksies uit die private Configuration Profiles-framework om die Activation Record te haal, met `CPFetchActivationRecord` wat met `cloudconfigurationd` deur XPC koördineer.<sup>[1]</sup>

## Tesla Protocol- en Absinthe Scheme Reverse Engineering

Die DEP check-in behels dat `cloudconfigurationd` 'n encrypted, signed JSON-payload na _iprofiles.apple.com/macProfile_ stuur. Die payload bevat die toestel se serial number en die aksie "RequestProfileConfiguration". Die encryption scheme wat gebruik word, staan intern as "Absinthe" bekend. Om hierdie scheme te ontrafel, is kompleks en behels dit talle stappe, wat gelei het tot die ondersoek van alternatiewe metodes om arbitrêre serial numbers in die Activation Record-versoek in te voeg.<sup>[1]</sup>

## Proxying van DEP Requests

Pogings om DEP requests na _iprofiles.apple.com_ met tools soos Charles Proxy te onderskep en te wysig, is deur payload-enkripsie en SSL/TLS-sekuriteitsmaatreëls belemmer. Deur die `MCCloudConfigAcceptAnyHTTPSCertificate`-konfigurasie te aktiveer, kan die server certificate validation egter omseil word, hoewel die encrypted aard van die payload steeds die wysiging van die serial number sonder die decryption key verhinder.<sup>[1]</sup>

## Instrumentering van System Binaries wat met DEP Interaksie het

Instrumentering van system binaries soos `cloudconfigurationd` vereis dat System Integrity Protection (SIP) op macOS gedeaktiveer word. Met SIP gedeaktiveer kan tools soos LLDB gebruik word om aan system processes te koppel en moontlik die serial number wat in DEP API-interaksies gebruik word, te wysig. Hierdie metode is verkieslik omdat dit die kompleksiteite van entitlements en code signing vermy.

**Exploiting Binary Instrumentation:**
Die wysiging van die DEP request payload voor JSON-serialisering in `cloudconfigurationd` het effektief geblyk te wees. Die proses het die volgende behels:

1. Koppel LLDB aan `cloudconfigurationd`.
2. Vind die punt waar die system serial number opgehaal word.
3. Inject 'n arbitrêre serial number in die memory voordat die payload encrypted en gestuur word.

Hierdie metode het dit moontlik gemaak om volledige DEP-profiele vir arbitrêre serial numbers op te haal, wat 'n potensiële vulnerability gedemonstreer het.<sup>[1]</sup>

### Automatisering van Instrumentering met Python

Die exploitation-proses is geoutomatiseer met Python en die LLDB API, wat dit haalbaar gemaak het om arbitrêre serial numbers programmaties te inject en die ooreenstemmende DEP-profiele op te haal.<sup>[1]</sup>

### Potensiële Impakte van DEP- en MDM-vulnerabilities

Die navorsing het beduidende sekuriteitskwessies uitgelig:

1. **Information Disclosure**: Deur 'n DEP-geregistreerde serial number te verskaf, kan sensitiewe organisatoriese inligting wat in die DEP-profiel vervat is, opgehaal word.<sup>[1]</sup>

## Verwysings

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
