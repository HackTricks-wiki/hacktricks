# Enrolling Devices in Other Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Kao što je [**ranije komentarisano**](#what-is-mdm-mobile-device-management)**,** da bi se pokušalo registrovati uređaj u organizaciji **potreban je samo Serijski Broj koji pripada toj Organizaciji**. Kada je uređaj registrovan, nekoliko organizacija će instalirati osetljive podatke na novom uređaju: sertifikate, aplikacije, WiFi lozinke, VPN konfiguracije [i tako dalje](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Stoga, ovo može biti opasna tačka ulaza za napadače ako proces registracije nije pravilno zaštićen.

**Sledeće je sažetak istraživanja [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Proverite ga za dodatne tehničke detalje!**

## Overview of DEP and MDM Binary Analysis

Ovo istraživanje se bavi binarnim datotekama povezanim sa Programom za registraciju uređaja (DEP) i Upravom mobilnih uređaja (MDM) na macOS-u. Ključne komponente uključuju:

- **`mdmclient`**: Komunicira sa MDM serverima i pokreće DEP prijave na macOS verzijama pre 10.13.4.
- **`profiles`**: Upravljanje Konfiguracionim Profilima, i pokreće DEP prijave na macOS verzijama 10.13.4 i novijim.
- **`cloudconfigurationd`**: Upravljanje DEP API komunikacijama i preuzimanje profila za registraciju uređaja.

DEP prijave koriste `CPFetchActivationRecord` i `CPGetActivationRecord` funkcije iz privatnog okvira Konfiguracionih Profila za preuzimanje Aktivacionog Zapisa, pri čemu `CPFetchActivationRecord` koordinira sa `cloudconfigurationd` putem XPC.

## Tesla Protocol and Absinthe Scheme Reverse Engineering

DEP prijava uključuje `cloudconfigurationd` koji šalje enkriptovani, potpisani JSON payload na _iprofiles.apple.com/macProfile_. Payload uključuje serijski broj uređaja i akciju "RequestProfileConfiguration". Šema enkripcije koja se koristi interno se naziva "Absinthe". Razotkrivanje ove šeme je složeno i uključuje brojne korake, što je dovelo do istraživanja alternativnih metoda za umetanje proizvoljnih serijskih brojeva u zahtev za Aktivacioni Zapis.

## Proxying DEP Requests

Pokušaji presretanja i modifikacije DEP zahteva za _iprofiles.apple.com_ korišćenjem alata kao što je Charles Proxy su ometeni enkripcijom payload-a i SSL/TLS bezbednosnim merama. Međutim, omogućavanje konfiguracije `MCCloudConfigAcceptAnyHTTPSCertificate` omogućava zaobilaženje validacije sertifikata servera, iako enkriptovana priroda payload-a i dalje sprečava modifikaciju serijskog broja bez ključa za dekripciju.

## Instrumenting System Binaries Interacting with DEP

Instrumentacija sistemskih binarnih datoteka kao što je `cloudconfigurationd` zahteva onemogućavanje Zaštite Integriteta Sistema (SIP) na macOS-u. Sa onemogućenim SIP-om, alati kao što je LLDB mogu se koristiti za povezivanje sa sistemskim procesima i potencijalno modifikovanje serijskog broja koji se koristi u DEP API interakcijama. Ova metoda je poželjnija jer izbegava složenosti prava i potpisivanja koda.

**Exploiting Binary Instrumentation:**
Modifikacija DEP zahteva payload-a pre JSON serijalizacije u `cloudconfigurationd` se pokazala efikasnom. Proces je uključivao:

1. Povezivanje LLDB sa `cloudconfigurationd`.
2. Lociranje tačke gde se preuzima serijski broj sistema.
3. Umetanje proizvoljnog serijskog broja u memoriju pre nego što se payload enkriptuje i pošalje.

Ova metoda je omogućila preuzimanje kompletnog DEP profila za proizvoljne serijske brojeve, pokazujući potencijalnu ranjivost.

### Automating Instrumentation with Python

Proces eksploatacije je automatizovan korišćenjem Pythona sa LLDB API, što je omogućilo programatsko umetanje proizvoljnih serijskih brojeva i preuzimanje odgovarajućih DEP profila.

### Potential Impacts of DEP and MDM Vulnerabilities

Istraživanje je istaklo značajne bezbednosne brige:

1. **Informacije o otkrivanju**: Pružanjem serijskog broja registrovanog u DEP, osetljive organizacione informacije sadržane u DEP profilu mogu se preuzeti.

{{#include ../../../banners/hacktricks-training.md}}
