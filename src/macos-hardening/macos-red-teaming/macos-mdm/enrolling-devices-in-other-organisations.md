# Enrolling Devices in Other Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Kao što je [**prethodno komentarisano**](#what-is-mdm-mobile-device-management)**,** da bi se pokušalo upisati uređaj u organizaciju, **potreban je samo Serial Number koji pripada toj organizaciji**. Nakon upisa uređaja, nekoliko organizacija će instalirati osetljive podatke na novi uređaj: sertifikate, aplikacije, WiFi lozinke, VPN konfiguracije [i tako dalje](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Zbog toga bi ovo mogla biti opasna entrypoint tačka za napadače ako proces upisa nije pravilno zaštićen.

**Sledi sažetak istraživanja [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Pogledajte ga za dodatne tehničke detalje!**<sup>[[1]](#references)</sup>

## Pregled DEP i MDM Binary Analysis

Ovo istraživanje analizira binarne datoteke povezane sa Device Enrollment Program (DEP) i Mobile Device Management (MDM) na macOS-u. Ključne komponente uključuju:

- **`mdmclient`**: Komunicira sa MDM serverima i pokreće DEP check-in na macOS verzijama pre 10.13.4.
- **`profiles`**: Upravlja Configuration Profiles i pokreće DEP check-in na macOS verzijama 10.13.4 i novijim.
- **`cloudconfigurationd`**: Upravlja DEP API komunikacijom i preuzima Device Enrollment profile.

DEP check-in koristi funkcije `CPFetchActivationRecord` i `CPGetActivationRecord` iz privatnog Configuration Profiles framework-a za preuzimanje Activation Record-a, pri čemu `CPFetchActivationRecord` komunicira sa `cloudconfigurationd` putem XPC-a.<sup>[[1]](#references)</sup>

## Tesla Protocol i Absinthe Scheme Reverse Engineering

DEP check-in uključuje slanje šifrovanog, potpisanog JSON payload-a iz procesa `cloudconfigurationd` ka _iprofiles.apple.com/macProfile_. Payload sadrži serijski broj uređaja i akciju „RequestProfileConfiguration“. Korišćena šema šifrovanja interno se naziva „Absinthe“. Razumevanje ove šeme je složeno i uključuje brojne korake, što je dovelo do istraživanja alternativnih metoda za ubacivanje proizvoljnih serijskih brojeva u zahtev za Activation Record.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Pokušaji presretanja i izmene DEP zahteva ka _iprofiles.apple.com_ pomoću alata kao što je Charles Proxy bili su otežani šifrovanjem payload-a i SSL/TLS bezbednosnim merama. Međutim, omogućavanje konfiguracije `MCCloudConfigAcceptAnyHTTPSCertificate` dozvoljava zaobilaženje validacije sertifikata servera, iako šifrovana priroda payload-a i dalje onemogućava izmenu serijskog broja bez ključa za dešifrovanje.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries Interacting with DEP

Instrumentacija sistemskih binarnih datoteka kao što je `cloudconfigurationd` zahteva onemogućavanje System Integrity Protection (SIP) na macOS-u. Kada je SIP onemogućen, alati kao što je LLDB mogu da se prikače na sistemske procese i potencijalno izmene serijski broj koji se koristi u DEP API interakcijama. Ovaj metod je poželjniji jer izbegava složenosti vezane za entitlements i code signing.<sup>[[1]](#references)</sup>

**Iskorišćavanje Binary Instrumentation:**
Izmena DEP request payload-a pre JSON serijalizacije u procesu `cloudconfigurationd` pokazala se efikasnom. Proces je uključivao:

1. Priključivanje LLDB-a na `cloudconfigurationd`.
2. Pronalaženje mesta na kom se preuzima sistemski serijski broj.
3. Ubacivanje proizvoljnog serijskog broja u memoriju pre nego što se payload šifruje i pošalje.

Ovaj metod je omogućio preuzimanje kompletnih DEP profila za proizvoljne serijske brojeve, što pokazuje potencijalnu ranjivost.<sup>[[1]](#references)</sup>

### Automating Instrumentation with Python

Proces iskorišćavanja automatizovan je pomoću Python-a i LLDB API-ja, čime je omogućeno programsko ubacivanje proizvoljnih serijskih brojeva i preuzimanje odgovarajućih DEP profila.<sup>[[1]](#references)</sup>

### Potencijalni uticaji DEP i MDM ranjivosti

Istraživanje je ukazalo na značajne bezbednosne probleme:

1. **Otkrivanje informacija**: Dostavljanjem DEP- registrovanog serijskog broja mogu se preuzeti osetljive organizacione informacije sadržane u DEP profilu.<sup>[[1]](#references)</sup>

## Reference

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
