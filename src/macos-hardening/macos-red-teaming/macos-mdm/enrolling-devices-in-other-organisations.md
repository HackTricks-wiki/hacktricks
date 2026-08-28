# Upisivanje uređaja u druge organizacije

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Apple Automated Device Enrollment (ranije DEP) započinje identifikovanjem uređaja dodeljenog organizaciji. Istraživanje iz 2018. godine, sažeto ovde, pokazalo je da je poznavanje dodeljenog serijskog broja bilo dovoljno za preuzimanje enrollment profila nekih organizacija, jer te organizacije nisu zahtevale odgovarajuću dodatnu autentifikaciju. Ovo je istorijski nalaz, a ne tvrdnja da se svaki aktuelni MDM može pridružiti samo pomoću serijskog broja. Profili mogu sadržati sertifikate, aplikacije, Wi-Fi secrets, VPN podešavanja i drugu osetljivu konfiguraciju.<sup>[[1]](#references)[[2]](#references)</sup>

**U nastavku je sažetak istraživanja [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Pogledajte ga za dodatne tehničke detalje!**<sup>[[1]](#references)</sup>

## Pregled DEP i MDM binarne analize

Istraživanje je analiziralo binaries povezane sa DEP i MDM na macOS verzijama aktuelnim u to vreme. Nazivi komponenti i njihove odgovornosti mogu se menjati kroz različite verzije:

- **`mdmclient`**: Komunicira sa MDM serverima i pokreće DEP check-in na macOS verzijama pre 10.13.4.
- **`profiles`**: Upravlja Configuration Profiles i pokreće DEP check-in na macOS verzijama 10.13.4 i novijim.
- **`cloudconfigurationd`**: Upravlja DEP API komunikacijom i preuzima Device Enrollment profile.

DEP check-in koristi funkcije `CPFetchActivationRecord` i `CPGetActivationRecord` iz privatnog Configuration Profiles frameworka za preuzimanje Activation Record-a, pri čemu `CPFetchActivationRecord` komunicira sa `cloudconfigurationd` putem XPC-a.<sup>[[1]](#references)</sup>

## Obrnuti inženjering Tesla protokola i Absinthe scheme-a

DEP check-in podrazumeva da `cloudconfigurationd` šalje encrypted, potpisani JSON payload na _iprofiles.apple.com/macProfile_. Payload uključuje serijski broj uređaja i akciju "RequestProfileConfiguration". Korišćena encryption scheme interno se naziva "Absinthe". Razotkrivanje ove scheme je složeno i obuhvata brojne korake, što je dovelo do istraživanja alternativnih metoda za ubacivanje proizvoljnih serijskih brojeva u zahtev za Activation Record.<sup>[[1]](#references)</sup>

## Proxying DEP zahteva

Pokušaji presretanja i izmene DEP zahteva ka _iprofiles.apple.com_ pomoću alata kao što je Charles Proxy bili su otežani encryption payload-a i SSL/TLS security merama. Međutim, omogućavanje konfiguracije `MCCloudConfigAcceptAnyHTTPSCertificate` omogućava zaobilaženje validacije sertifikata servera, iako encrypted priroda payload-a i dalje sprečava izmenu serijskog broja bez decryption key-a.<sup>[[1]](#references)</sup>

## Instrumentacija system binaries koji komuniciraju sa DEP-om

Instrumentacija system binaries kao što je `cloudconfigurationd` zahteva onemogućavanje System Integrity Protection (SIP) na macOS-u. Kada je SIP onemogućen, alati kao što je LLDB mogu se koristiti za attach na system processes i potencijalnu izmenu serijskog broja koji se koristi u DEP API interakcijama. Ovaj metod je poželjniji jer izbegava složenosti entitlements-a i code signing-a.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Izmena DEP request payload-a pre JSON serializacije u `cloudconfigurationd` pokazala se efikasnom. Proces je obuhvatao:

1. Attachovanje LLDB-a na `cloudconfigurationd`.
2. Pronalaženje tačke u kojoj se preuzima system serial number.
3. Injectovanje proizvoljnog serijskog broja u memoriju pre nego što se payload encrypted i pošalje.

Ovaj metod je omogućio istraživačima da preuzmu DEP profile za dostavljene, dodeljene serijske brojeve. Nije učinio da nedodeljeni proizvoljni serijski broj postane validan.<sup>[[1]](#references)</sup>

### Automatizacija instrumentacije pomoću Python-a

Proces exploitation-a automatizovan je pomoću Python-a i LLDB API-ja, čime je postalo izvodljivo programsko injectovanje proizvoljnih serijskih brojeva i preuzimanje odgovarajućih DEP profila.<sup>[[1]](#references)</sup>

## Ponovna analiza 2025: Rogue Enrollment iz VM-a

Istraživanje predstavljeno na Black Hat Asia 2025 pokazalo je da problem granice poverenja i dalje može biti relevantan na **MDM layer-u**: umesto patchovanja `cloudconfigurationd` pomoću LLDB-a, istraživači su pokrenuli macOS pod QEMU/KVM-om sa OpenCore-om i prosledili kandidat-identitet kroz SMBIOS VM-a. Neizmenjeni macOS enrollment stack zatim je obavio encrypted Apple razmenu. Zbog toga se javno leaked serijski brojevi i kandidati koji izgledaju validno mogu testirati bez posedovanja odgovarajućeg fizičkog Mac-a; pogodak i dalje zahteva da je serijski broj dodeljen organizaciji i da je enrollment putanja organizacije nedovoljno autentifikovana.<sup>[[3]](#references)</sup>

Za autorizovani lab uređaj, relevantne OpenCore `PlatformInfo` vrednosti obuhvataju model proizvoda i serijski broj (u realnim deployment-ima ROM i UUID se takođe interno održavaju međusobno usklađenim):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
Isto istraživanje je identifikovalo stanje `CheckProfilesFetchRateLimit` u privatnoj datoteci `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Pošto se provera održavala na klijentu, izmena sačuvanih vremenskih vrednosti je zaobilazila tu proveru. Ove putanje nisu dokumentovane i zavise od verzije, ali su korisne kao reversing pivoti prilikom procene trenutne macOS verzije:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Drugi artefakt može otkriti keširani activation record, uključujući informaciju o tome da li tok koristi direktni `ConfigurationURL` ili autentifikovani `ConfigurationWebURL`. Testirajte i oglašeni tok i sve MDM-specifične legacy enrollment endpoint-e: omogućavanje SSO-a samo na glavnom web toku ne štiti paralelni direktni endpoint. Za kompletan sled protokola pogledajte [pregled macOS MDM-a](README.md).<sup>[[3]](#references)</sup>

### Pretraga tajni nakon enrollment-a

Rogue enrollment je samo početna tačka. Nakon enrollment-a pregledajte svaki isporučeni profil, bootstrap policy, konfiguraciju package repository-ja, skriptu za instalaciju agenta i self-service stavku. Istraživanje iz 2025. pronašlo je primere Wi-Fi kredencijala, deljenih lozinki lokalnih administratora, potpisanih URL-ova cloud storage-a, webhook URL-ova, activation podataka security agenta i MDM/API kredencijala. Tenant API credential u isporučenoj skripti može jedan rogue endpoint pretvoriti u kontrolu nad drugim managed uređajima, zato pretražite i aktivni filesystem i preuzeti/keširani policy sadržaj.<sup>[[3]](#references)</sup>

Korisne mete za pregled uključuju:<sup>[[3]](#references)</sup>

- Instalirane `.mobileconfig` payload-e i bazu podataka Configuration Profiles.
- PreStage/bootstrap skripte i pakete koji kreiraju naloge ili instaliraju EDR/VPN agente.
- Munki ili druge URL-ove package repository-ja, naročito query string-ove koji sadrže bearer/SAS-style potpise.
- Self-service kataloge i njihove prateće policy API-je, uključujući legacy rute koje možda ne primenjuju enrollment SSO policy.
- Shell history i keširani policy output za `password`, `token`, `secret`, `Authorization`, webhook hostname-ove i endpoint-e vendor API-ja.

### Ojačavanje granice poverenja

Tretirajte serijski broj kao atribut inventara/usmeravanja, **a ne** kao dokaz posedovanja. Zahtevajte autentifikaciju korisnika za enrollment i self service, generišite jedinstvene lozinke lokalnih administratora za svaki uređaj i nikada ne ugrađujte tenant API kredencijale ili ponovo upotrebljive infrastructure secrets u profile ili skripte. Svaki neizbežni bootstrap token neka bude kratkog veka i ograničen na jednu radnju i uređaj koji se provision-uje.<sup>[[3]](#references)</sup>

Na Mac računarima sa Apple silicon-om koji koriste macOS 14 ili noviji, Managed Device Attestation može kriptografski povezati identitet sa Secure Enclave-om. Njegova attestation zasnovana na Apple root-u može sadržati svež nonce, kao i serijski broj, UDID, verziju OS-a, SIP stanje i stanje secure boot-a; ACME zatim može izdati hardware-bound client identity. Koristite taj identitet za zaštitu MDM kanala i kontrolu pristupa visokovrednim sertifikatima, VPN pristupu i drugim resursima, uz zadržavanje odvojene autentifikacije korisnika, jer device attestation dokazuje uređaj, a ne operatora.<sup>[[4]](#references)</sup>

## Potencijalni uticaji DEP i MDM ranjivosti

Istraživanje je istaklo značajne bezbednosne probleme:

1. **Otkrivanje informacija**: Navođenjem serijskog broja registrovanog u DEP-u mogu se preuzeti osetljive organizacione informacije sadržane u DEP profilu.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — Bezbednost Device Enrollment Programa](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
