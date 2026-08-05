# Upisivanje uređaja u druge organizacije

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Kao što je [**prethodno navedeno**](#what-is-mdm-mobile-device-management)**,** da bi se uređaj upisao u organizaciju, potreban je **samo Serial Number koji pripada toj organizaciji**. Kada se uređaj upiše, nekoliko organizacija će na novi uređaj instalirati osetljive podatke: sertifikate, aplikacije, WiFi lozinke, VPN konfiguracije [i tako dalje](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Zbog toga ovo može predstavljati opasnu ulaznu tačku za napadače ako proces upisa nije pravilno zaštićen.

**U nastavku je sažetak istraživanja [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Pogledajte ga za dodatne tehničke detalje!**<sup>[1]</sup>

## Pregled DEP i MDM binarne analize

Ovo istraživanje se bavi binarnim datotekama povezanim sa Device Enrollment Program (DEP) i Mobile Device Management (MDM) na macOS-u. Ključne komponente obuhvataju:

- **`mdmclient`**: Komunicira sa MDM serverima i pokreće DEP check-in na macOS verzijama pre 10.13.4.
- **`profiles`**: Upravlja Configuration Profiles i pokreće DEP check-in na macOS verzijama 10.13.4 i novijim.
- **`cloudconfigurationd`**: Upravlja DEP API komunikacijom i preuzima Device Enrollment profile.

DEP check-in koristi funkcije `CPFetchActivationRecord` i `CPGetActivationRecord` iz privatnog Configuration Profiles framework-a za preuzimanje Activation Record-a, pri čemu `CPFetchActivationRecord` komunicira sa `cloudconfigurationd` putem XPC-a.<sup>[1]</sup>

## Obrnuti inženjering Tesla Protocol-a i Absinthe Scheme-a

DEP check-in podrazumeva da `cloudconfigurationd` šalje šifrovani, potpisani JSON payload na _iprofiles.apple.com/macProfile_. Payload sadrži serial number uređaja i akciju „RequestProfileConfiguration“. Šema šifrovanja se interno naziva „Absinthe“. Razotkrivanje ove šeme je složeno i obuhvata veliki broj koraka, što je dovelo do istraživanja alternativnih metoda za ubacivanje proizvoljnih serial number-a u zahtev za Activation Record.<sup>[1]</sup>

## Proxying DEP zahteva

Pokušaji presretanja i izmene DEP zahteva ka _iprofiles.apple.com_ pomoću alata kao što je Charles Proxy bili su otežani šifrovanjem payloada i bezbednosnim merama SSL/TLS-a. Međutim, omogućavanje konfiguracije `MCCloudConfigAcceptAnyHTTPSCertificate` dozvoljava zaobilaženje validacije sertifikata servera, iako šifrovana priroda payloada i dalje onemogućava izmenu serial number-a bez ključa za dešifrovanje.<sup>[1]</sup>

## Instrumentacija sistemskih binarnih datoteka koje komuniciraju sa DEP-om

Instrumentacija sistemskih binarnih datoteka kao što je `cloudconfigurationd` zahteva onemogućavanje System Integrity Protection (SIP) na macOS-u. Kada je SIP onemogućen, alati kao što je LLDB mogu da se prikače na sistemske procese i potencijalno izmene serial number koji se koristi u DEP API interakcijama. Ovaj metod je poželjan jer izbegava složenosti entitlements-a i potpisivanja koda.

**Iskorišćavanje binarne instrumentacije:**
Izmena DEP request payloada pre JSON serijalizacije u procesu `cloudconfigurationd` pokazala se efikasnom. Proces je obuhvatao:

1. Priključivanje LLDB-a na `cloudconfigurationd`.
2. Pronalaženje mesta na kom sistem preuzima serial number.
3. Ubacivanje proizvoljnog serial number-a u memoriju pre nego što se payload šifruje i pošalje.

Ovaj metod je omogućio preuzimanje kompletnih DEP profila za proizvoljne serial number-e, čime je demonstrirana potencijalna ranjivost.<sup>[1]</sup>

### Automatizacija instrumentacije pomoću Python-a

Proces eksploatacije automatizovan je pomoću Python-a i LLDB API-ja, čime je omogućeno programsko ubacivanje proizvoljnih serial number-a i preuzimanje odgovarajućih DEP profila.<sup>[1]</sup>

### Potencijalni uticaji DEP i MDM ranjivosti

Istraživanje je ukazalo na značajne bezbednosne probleme:

1. **Otkrivanje informacija**: Dostavljanjem DEP-registered serial number-a mogu se preuzeti osetljive organizacione informacije sadržane u DEP profilu.<sup>[1]</sup>

## Reference

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
