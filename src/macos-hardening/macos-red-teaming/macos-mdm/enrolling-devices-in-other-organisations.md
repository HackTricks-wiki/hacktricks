# Enrolling Devices in Other Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Apple Automated Device Enrollment (ranije DEP) počinje identifikovanjem uređaja dodeljenog organizaciji. Istraživanje iz 2018. godine, sažeto u nastavku, pokazalo je da je poznavanje dodeljenog serijskog broja bilo dovoljno za preuzimanje enrollment profila nekih organizacija, jer te organizacije nisu zahtevale odgovarajuću dodatnu autentikaciju. Ovo je istorijski nalaz, a ne tvrdnja da se svakom aktuelnom MDM-u može pridružiti samo pomoću serijskog broja. Profili mogu sadržati sertifikate, aplikacije, Wi-Fi secrets, VPN podešavanja i druge osetljive konfiguracije.<sup>[[1]](#references)[[2]](#references)</sup>

**Sledeće predstavlja sažetak istraživanja [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Pogledajte ga za dodatne tehničke detalje!**<sup>[[1]](#references)</sup>

## Pregled DEP i MDM binarne analize

Istraživanje je analiziralo binarne fajlove povezane sa DEP-om i MDM-om na verzijama macOS-a koje su tada bile aktuelne. Nazivi komponenti i njihove odgovornosti mogu se menjati kroz različite verzije:

- **`mdmclient`**: Komunicira sa MDM serverima i pokreće DEP check-in na verzijama macOS-a pre 10.13.4.
- **`profiles`**: Upravlja Configuration Profiles i pokreće DEP check-in na verzijama macOS-a 10.13.4 i novijim.
- **`cloudconfigurationd`**: Upravlja DEP API komunikacijom i preuzima Device Enrollment profile.

DEP check-in koristi funkcije `CPFetchActivationRecord` i `CPGetActivationRecord` iz privatnog Configuration Profiles framework-a za preuzimanje Activation Record-a, pri čemu `CPFetchActivationRecord` komunicira sa `cloudconfigurationd` komponentom putem XPC-a.<sup>[[1]](#references)</sup>

## Tesla Protocol i Absinthe Scheme Reverse Engineering

DEP check-in podrazumeva da `cloudconfigurationd` šalje enkriptovani, potpisani JSON payload na _iprofiles.apple.com/macProfile_. Payload uključuje serijski broj uređaja i akciju `"RequestProfileConfiguration"`. Šema enkripcije koja se interno koristi naziva se "Absinthe". Razjašnjavanje ove šeme je složeno i uključuje brojne korake, što je dovelo do istraživanja alternativnih metoda za ubacivanje proizvoljnih serijskih brojeva u zahtev za Activation Record.<sup>[[1]](#references)</sup>

## Proxying DEP zahteva

Pokušaje presretanja i izmene DEP zahteva ka _iprofiles.apple.com_ pomoću alata kao što je Charles Proxy otežavali su enkripcija payloada i SSL/TLS bezbednosne mere. Međutim, omogućavanje konfiguracije `MCCloudConfigAcceptAnyHTTPSCertificate` dozvoljava zaobilaženje validacije serverskog sertifikata, iako enkriptovana priroda payloada i dalje onemogućava izmenu serijskog broja bez ključa za dekripciju.<sup>[[1]](#references)</sup>

## Instrumenting sistemskih binarnih fajlova koji komuniciraju sa DEP-om

Instrumenting sistemskih binarnih fajlova kao što je `cloudconfigurationd` zahteva onemogućavanje System Integrity Protection-a (SIP) na macOS-u. Kada je SIP onemogućen, alati kao što je LLDB mogu da se prikače na sistemske procese i potencijalno izmene serijski broj koji se koristi u DEP API interakcijama. Ovaj metod je poželjan jer izbegava složenosti u vezi sa entitlements i code signing-om.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Izmena DEP request payloada pre JSON serijalizacije u `cloudconfigurationd` pokazala se efikasnom. Proces je obuhvatao:

1. Priključivanje LLDB-a na `cloudconfigurationd`.
2. Pronalaženje mesta na kojem se preuzima sistemski serijski broj.
3. Ubacivanje proizvoljnog serijskog broja u memoriju pre enkripcije i slanja payloada.

Ovaj metod je istraživačima omogućio preuzimanje DEP profila za prosleđene, dodeljene serijske brojeve. Nije učinio nedodeljeni proizvoljni serijski broj važećim.<sup>[[1]](#references)</sup>

### Automating Instrumentation uz Python

Proces exploitation-a automatizovan je pomoću Python-a i LLDB API-ja, čime je programsko ubacivanje proizvoljnih serijskih brojeva i preuzimanje odgovarajućih DEP profila postalo izvodljivo.<sup>[[1]](#references)</sup>

### Potencijalni uticaji DEP i MDM ranjivosti

Istraživanje je ukazalo na značajne bezbednosne probleme:

1. **Otkrivanje informacija**: Prosleđivanjem DEP-registered serijskog broja mogu se preuzeti osetljive organizacione informacije sadržane u DEP profilu.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
