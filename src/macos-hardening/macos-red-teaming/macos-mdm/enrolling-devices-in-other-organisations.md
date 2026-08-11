# Toestelle in Ander Organisasies Inskryf

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Apple Automated Device Enrollment (voorheen DEP) begin deur ’n toestel te identifiseer wat aan ’n organisasie toegewys is. Die navorsing uit 2018 wat hier opgesom word, het getoon dat kennis van ’n toegewese reeksnommer voldoende was om sommige organisasies se enrollment-profiele te verkry, omdat daardie organisasies nie voldoende bykomende authentication vereis het nie. Dit is ’n historiese bevinding en nie ’n bewering dat elke huidige MDM slegs met ’n reeksnommer joined kan word nie. Profiele kan certificates, applications, Wi-Fi-secrets, VPN-instellings en ander sensitiewe configuration bevat.<sup>[[1]](#references)[[2]](#references)</sup>

**Die volgende is ’n opsomming van die navorsing [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Raadpleeg dit vir verdere tegniese besonderhede!**<sup>[[1]](#references)</sup>

## Oorsig van DEP en MDM Binary Analysis

Die navorsing het binaries ontleed wat met DEP en MDM geassosieer word op die macOS-weergawes wat destyds aktueel was. Component-name en responsibilities kan tussen releases verander:

- **`mdmclient`**: Kommunikeer met MDM-servers en trigger DEP check-ins op macOS-weergawes voor 10.13.4.
- **`profiles`**: Bestuur Configuration Profiles en trigger DEP check-ins op macOS-weergawes 10.13.4 en later.
- **`cloudconfigurationd`**: Bestuur DEP API-kommunikasie en retrieve Device Enrollment-profiele.

DEP check-ins gebruik die `CPFetchActivationRecord`- en `CPGetActivationRecord`-funksies uit die private Configuration Profiles-framework om die Activation Record te fetch, met `CPFetchActivationRecord` wat met `cloudconfigurationd` deur XPC koördineer.<sup>[[1]](#references)</sup>

## Tesla Protocol en Absinthe Scheme Reverse Engineering

Die DEP check-in behels dat `cloudconfigurationd` ’n encrypted, signed JSON-payload na _iprofiles.apple.com/macProfile_ stuur. Die payload sluit die toestel se reeksnommer en die aksie "RequestProfileConfiguration" in. Die encryption scheme wat gebruik word, word intern as "Absinthe" aangedui. Om hierdie scheme te ontrafel is kompleks en behels dit talle stappe, wat gelei het tot die ondersoek van alternatiewe metodes om arbitrêre reeksnommers in die Activation Record-request in te voeg.<sup>[[1]](#references)</sup>

## Proxying van DEP Requests

Pogings om DEP-requests na _iprofiles.apple.com_ met tools soos Charles Proxy te onderskep en te wysig, is deur payload-encryption en SSL/TLS-security measures belemmer. Deur die `MCCloudConfigAcceptAnyHTTPSCertificate`-configuration te aktiveer, kan server certificate-validation egter omseil word, hoewel die encrypted aard van die payload steeds wysiging van die reeksnommer sonder die decryption key voorkom.<sup>[[1]](#references)</sup>

## Instrumentering van System Binaries wat met DEP Interaksie het

Om system binaries soos `cloudconfigurationd` te instrumenteer, vereis dat System Integrity Protection (SIP) op macOS gedeaktiveer word. Met SIP gedeaktiveer kan tools soos LLDB gebruik word om aan system processes te attach en moontlik die reeksnommer wat in DEP API-interactions gebruik word, te wysig. Hierdie metode is verkieslik omdat dit die kompleksiteit van entitlements en code signing vermy.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Deur die DEP-request-payload voor JSON-serialization in `cloudconfigurationd` te wysig, het dit effektief geblyk. Die proses het die volgende behels:

1. LLDB aan `cloudconfigurationd` attach.
2. Die punt opspoor waar die system se reeksnommer gefetch word.
3. ’n Arbitrêre reeksnommer in die memory inject voordat die payload encrypted en gestuur word.

Hierdie metode het die navorsers in staat gestel om DEP-profiele vir verskafde, toegewese reeksnommers te retrieve. Dit het nie ’n ontoegewese arbitrêre reeksnommer geldig gemaak nie.<sup>[[1]](#references)</sup>

### Automatisering van Instrumentering met Python

Die exploitation-proses is met Python en die LLDB API geautomatiseer, wat dit haalbaar gemaak het om arbitrêre reeksnommers programmaties te inject en ooreenstemmende DEP-profiele te retrieve.<sup>[[1]](#references)</sup>

### Potensiële Impacts van DEP- en MDM-Vulnerabilities

Die navorsing het beduidende security concerns uitgelig:

1. **Information Disclosure**: Deur ’n DEP-geregistreerde reeksnommer te verskaf, kan sensitiewe organisatoriese information in die DEP-profiel retrieve word.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Security van die Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
