# Registrasie van Toestelle in Ander Organisasies

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Soos [**voorheen opgemerk**](#what-is-mdm-mobile-device-management)**,** om 'n toestel in 'n organisasie te probeer registreer, **is slegs 'n Serienommer wat aan daardie Organisasie behoort, nodig**. Sodra die toestel geregistreer is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: sertifikate, toepassings, WiFi-wagwoorde, VPN-konfigurasies [en so aan](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daarom kan dit 'n gevaarlike toegangspunt vir aanvallers wees as die registrasieproses nie korrek beskerm word nie.

**Die volgende is 'n opsomming van die navorsing [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Kyk daarna vir verdere tegniese besonderhede!**

## Oorsig van DEP en MDM Binaire Analise

Hierdie navorsing delf in die binaire lêers wat geassosieer word met die Toestel Registrasie Program (DEP) en Mobiele Toestel Bestuur (MDM) op macOS. Sleutelelemente sluit in:

- **`mdmclient`**: Kommunikeer met MDM-bedieners en aktiveer DEP-incheckings op macOS weergawes voor 10.13.4.
- **`profiles`**: Bestuur Konfigurasieprofiele, en aktiveer DEP-incheckings op macOS weergawes 10.13.4 en later.
- **`cloudconfigurationd`**: Bestuur DEP API kommunikasies en haal Toestel Registrasie profiele op.

DEP-incheckings gebruik die `CPFetchActivationRecord` en `CPGetActivationRecord` funksies van die private Konfigurasieprofiele raamwerk om die Aktiveringsrekord op te haal, met `CPFetchActivationRecord` wat saamwerk met `cloudconfigurationd` deur XPC.

## Tesla Protokol en Absinthe Skema Omgekeerde Ingenieurswese

Die DEP-incheck betrek `cloudconfigurationd` wat 'n geënkripteerde, ondertekende JSON-payload na _iprofiles.apple.com/macProfile_ stuur. Die payload sluit die toestel se serienommer en die aksie "RequestProfileConfiguration" in. Die enkripsieskema wat gebruik word, word intern as "Absinthe" verwys. Om hierdie skema te ontrafel is kompleks en behels verskeie stappe, wat gelei het tot die verkenning van alternatiewe metodes om arbitrêre serienommers in die Aktiveringsrekord versoek in te voeg.

## Proxie van DEP Versoeke

Pogings om DEP versoeke na _iprofiles.apple.com_ te onderskep en te wysig met behulp van gereedskap soos Charles Proxy is belemmer deur payload-enkripsie en SSL/TLS-sekuriteitsmaatreëls. Dit is egter moontlik om die `MCCloudConfigAcceptAnyHTTPSCertificate` konfigurasie in te skakel, wat die bediener sertifikaatvalidasie omseil, alhoewel die geënkripteerde aard van die payload steeds die wysiging van die serienommer sonder die ontsleuteling sleutel verhinder.

## Instrumentering van Stelsels Binaries wat met DEP Interaksie het

Instrumentering van stelsels binaries soos `cloudconfigurationd` vereis die deaktivering van Stelsel Integriteit Beskerming (SIP) op macOS. Met SIP gedeaktiveer, kan gereedskap soos LLDB gebruik word om aan stelsels prosesse te koppel en moontlik die serienommer wat in DEP API interaksies gebruik word, te wysig. Hierdie metode is verkieslik aangesien dit die kompleksiteite van regte en kodeondertekening vermy.

**Eksploitering van Binaire Instrumentasie:**
Die wysiging van die DEP versoek payload voor JSON-serialisering in `cloudconfigurationd` het effektief geblyk. Die proses het behels:

1. Koppel LLDB aan `cloudconfigurationd`.
2. Vind die punt waar die stelselserienommer opgevraag word.
3. Spuit 'n arbitrêre serienommer in die geheue in voordat die payload geënkripteer en gestuur word.

Hierdie metode het toegelaat om volledige DEP profiele vir arbitrêre serienommers te verkry, wat 'n potensiële kwesbaarheid demonstreer.

### Automatisering van Instrumentasie met Python

Die eksploitasiestap is geoutomatiseer met behulp van Python met die LLDB API, wat dit haalbaar gemaak het om programmaties arbitrêre serienommers in te spuit en ooreenstemmende DEP profiele op te haal.

### Potensiële Impakte van DEP en MDM Kwesbaarhede

Die navorsing het beduidende sekuriteitskwessies uitgelig:

1. **Inligting Ontsluiting**: Deur 'n DEP-geregistreerde serienommer te verskaf, kan sensitiewe organisatoriese inligting wat in die DEP-profiel bevat is, verkry word.

{{#include ../../../banners/hacktricks-training.md}}
