# Rejestrowanie urządzeń w innych organizacjach

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Apple Automated Device Enrollment (dawniej DEP) rozpoczyna się od zidentyfikowania urządzenia przypisanego do organizacji. Opisane tutaj badania z 2018 roku wykazały, że znajomość przypisanego numeru seryjnego wystarczała do pobrania profili enrollment niektórych organizacji, ponieważ organizacje te nie wymagały odpowiedniego dodatkowego uwierzytelniania. Jest to historyczne ustalenie, a nie twierdzenie, że do każdego obecnego MDM można dołączyć wyłącznie za pomocą numeru seryjnego. Profile mogą zawierać certyfikaty, aplikacje, sekrety Wi-Fi, ustawienia VPN i inne poufne konfiguracje.<sup>[[1]](#references)[[2]](#references)</sup>

**Poniżej znajduje się podsumowanie badań [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Sprawdź je, aby uzyskać dalsze szczegóły techniczne!**<sup>[[1]](#references)</sup>

## Przegląd analizy binariów DEP i MDM

Badania objęły analizę binariów powiązanych z DEP i MDM w wersjach macOS aktualnych w tamtym czasie. Nazwy komponentów i ich odpowiedzialność mogą zmieniać się w kolejnych wydaniach:

- **`mdmclient`**: Komunikuje się z serwerami MDM i wywołuje DEP check-ins w wersjach macOS wcześniejszych niż 10.13.4.
- **`profiles`**: Zarządza Configuration Profiles i wywołuje DEP check-ins w wersjach macOS 10.13.4 i nowszych.
- **`cloudconfigurationd`**: Zarządza komunikacją z API DEP i pobiera profile Device Enrollment.

DEP check-ins wykorzystują funkcje `CPFetchActivationRecord` i `CPGetActivationRecord` z prywatnego frameworka Configuration Profiles w celu pobrania Activation Record, przy czym `CPFetchActivationRecord` komunikuje się z `cloudconfigurationd` za pośrednictwem XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering protokołu Tesla i schematu Absinthe

DEP check-in obejmuje wysłanie przez `cloudconfigurationd` zaszyfrowanego i podpisanego payloadu JSON do _iprofiles.apple.com/macProfile_. Payload zawiera numer seryjny urządzenia oraz akcję "RequestProfileConfiguration". Schemat szyfrowania jest wewnętrznie określany jako "Absinthe". Rozwikłanie tego schematu jest złożone i obejmuje wiele kroków, co doprowadziło do zbadania alternatywnych metod wstawiania dowolnych numerów seryjnych do żądania Activation Record.<sup>[[1]](#references)</sup>

## Proxying żądań DEP

Próby przechwytywania i modyfikowania żądań DEP do _iprofiles.apple.com_ za pomocą narzędzi takich jak Charles Proxy były utrudnione przez szyfrowanie payloadu oraz mechanizmy bezpieczeństwa SSL/TLS. Jednak włączenie konfiguracji `MCCloudConfigAcceptAnyHTTPSCertificate` pozwala ominąć walidację certyfikatu serwera, chociaż zaszyfrowany charakter payloadu nadal uniemożliwia modyfikację numeru seryjnego bez klucza deszyfrującego.<sup>[[1]](#references)</sup>

## Instrumentacja binariów systemowych współpracujących z DEP

Instrumentacja binariów systemowych, takich jak `cloudconfigurationd`, wymaga wyłączenia System Integrity Protection (SIP) w macOS. Po wyłączeniu SIP narzędzia takie jak LLDB mogą zostać użyte do podłączenia się do procesów systemowych i potencjalnej modyfikacji numeru seryjnego używanego w interakcjach z API DEP. Ta metoda jest preferowana, ponieważ pozwala uniknąć złożoności związanej z entitlements i code signing.<sup>[[1]](#references)</sup>

**Wykorzystanie instrumentacji binariów:**
Modyfikacja payloadu żądania DEP przed serializacją JSON w `cloudconfigurationd` okazała się skuteczna. Proces obejmował:

1. Podłączenie LLDB do `cloudconfigurationd`.
2. Zlokalizowanie miejsca, w którym pobierany jest systemowy numer seryjny.
3. Wstrzyknięcie dowolnego numeru seryjnego do pamięci przed zaszyfrowaniem i wysłaniem payloadu.

Metoda ta umożliwiła badaczom pobieranie profili DEP dla podanych, przypisanych numerów seryjnych. Nie sprawiała ona, że nieprzypisany, dowolny numer seryjny stawał się prawidłowy.<sup>[[1]](#references)</sup>

### Automatyzacja instrumentacji za pomocą Python

Proces exploitation został zautomatyzowany za pomocą Python i API LLDB, dzięki czemu możliwe stało się programowe wstrzykiwanie dowolnych numerów seryjnych i pobieranie odpowiadających im profili DEP.<sup>[[1]](#references)</sup>

## Ponowna analiza w 2025 roku: Rogue Enrollment z maszyny wirtualnej

Badania zaprezentowane podczas Black Hat Asia 2025 wykazały, że pierwotny problem związany z granicą zaufania może nadal mieć znaczenie na **warstwie MDM**: zamiast patchować `cloudconfigurationd` za pomocą LLDB badacze uruchomili macOS pod QEMU/KVM z OpenCore i przekazali potencjalną tożsamość za pośrednictwem SMBIOS maszyny wirtualnej. Niezmodyfikowany stos enrollment macOS wykonał następnie zaszyfrowaną wymianę z Apple. Publicznie leaked numery seryjne i wyglądające na prawidłowe kandydatury można więc testować bez posiadania odpowiadającego im fizycznego Maca; trafienie nadal wymaga, aby numer seryjny był przypisany do organizacji oraz aby ścieżka enrollment tej organizacji była niewystarczająco uwierzytelniona.<sup>[[3]](#references)</sup>

W przypadku autoryzowanego urządzenia laboratoryjnego odpowiednie wartości OpenCore `PlatformInfo` obejmują model produktu i numer seryjny (w rzeczywistych wdrożeniach ROM i UUID również powinny być wewnętrznie spójne):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
Te same badania zidentyfikowały stan `CheckProfilesFetchRateLimit` w prywatnym pliku `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Ponieważ sprawdzanie było przeprowadzane po stronie klienta, modyfikacja zapisanych wartości czasu pozwalała je obejść. Te ścieżki nie są udokumentowane i zależą od wersji, ale są przydatnymi punktami wyjścia do reverse engineeringu podczas oceny bieżącej kompilacji macOS:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Drugi artefakt może ujawnić zapisany w pamięci podręcznej rekord aktywacji, w tym informację, czy przepływ korzysta z bezpośredniego `ConfigurationURL`, czy uwierzytelnionego `ConfigurationWebURL`. Przetestuj zarówno reklamowany przepływ, jak i wszelkie specyficzne dla MDM starsze endpointy enrollmentu: włączenie SSO tylko w głównym przepływie webowym nie chroni równoległego bezpośredniego endpointu. Pełną sekwencję protokołu opisano w [macOS MDM overview](README.md).<sup>[[3]](#references)</sup>

### Poszukiwanie sekretów po enrollment

Rogue enrollment to tylko punkt wejścia. Po enrollment przeanalizuj każdy dostarczony profil, bootstrap policy, konfigurację repozytorium pakietów, skrypt instalacyjny agenta oraz element self-service. Badania z 2025 roku ujawniły przykłady poświadczeń Wi-Fi, współdzielonych haseł lokalnych administratorów, podpisanych URL-i do cloud storage, URL-i webhooków, danych aktywacyjnych agentów bezpieczeństwa oraz poświadczeń MDM/API. Poświadczenie tenant API w dostarczonym skrypcie może zmienić jeden rogue endpoint w możliwość przejęcia kontroli nad innymi zarządzanymi urządzeniami, dlatego przeszukuj zarówno aktywny filesystem, jak i pobraną/zbuforowaną zawartość policy.<sup>[[3]](#references)</sup>

Przydatne cele do analizy obejmują:<sup>[[3]](#references)</sup>

- Zainstalowane payloady `.mobileconfig` oraz bazę danych Configuration Profiles.
- Skrypty i pakiety PreStage/bootstrap, które tworzą konta lub instalują agentów EDR/VPN.
- URL-e Munki lub innych repozytoriów pakietów, szczególnie query stringi zawierające podpisy typu bearer/SAS.
- Katalogi self-service i powiązane z nimi API policy, w tym starsze routes, które mogą nie egzekwować policy enrollment SSO.
- Historię powłoki oraz zbuforowany output policy pod kątem `password`, `token`, `secret`, `Authorization`, hostname'ów webhooków i endpointów vendor API.

### Wzmacnianie granicy zaufania

Traktuj numer seryjny jako atrybut inventory/routing, **a nie** dowód posiadania. Wymagaj uwierzytelnienia użytkownika podczas enrollmentu i korzystania z self-service, generuj unikalne hasła lokalnego administratora dla każdego urządzenia i nigdy nie umieszczaj poświadczeń tenant API ani wielokrotnego użytku sekretów infrastruktury w profilach lub skryptach. Każdy nieunikniony bootstrap token powinien mieć krótki czas ważności i być ograniczony do pojedynczej akcji oraz urządzenia, które jest provisionowane.<sup>[[3]](#references)</sup>

Na Macach z Apple silicon, działających pod kontrolą macOS 14 lub nowszego, Managed Device Attestation może kryptograficznie powiązać tożsamość z Secure Enclave. Attestation zakorzenione w Apple może zawierać świeży nonce wraz z numerem seryjnym, UDID, wersją systemu operacyjnego, stanem SIP i stanem secure boot; ACME może następnie wydać hardware-bound client identity. Użyj tej tożsamości do ochrony kanału MDM i kontrolowania dostępu do certyfikatów o wysokiej wartości, VPN oraz innych zasobów, zachowując jednocześnie oddzielne uwierzytelnianie użytkownika, ponieważ device attestation potwierdza urządzenie, a nie operatora.<sup>[[4]](#references)</sup>

## Potencjalne skutki podatności DEP i MDM

Badania uwidoczniły istotne problemy bezpieczeństwa:

1. **Ujawnienie informacji**: Podanie numeru seryjnego zarejestrowanego w DEP umożliwia pobranie poufnych informacji organizacyjnych zawartych w profilu DEP.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — Bezpieczeństwo Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automatyczny Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Syndrom oszusta: hacking Apple MDM za pomocą rogue device enrollmentów](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
