# Enrolowanie urządzeń w innych organizacjach

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Jak [**wspomniano wcześniej**](#what-is-mdm-mobile-device-management)**,** aby spróbować enrolować urządzenie do organizacji, **wymagany jest tylko numer seryjny należący do tej organizacji**. Po enrolowaniu urządzenia kilka organizacji zainstaluje na nim wrażliwe dane: certyfikaty, aplikacje, hasła WiFi, konfiguracje VPN [i tak dalej](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Dlatego może to stanowić niebezpieczny entrypoint dla atakujących, jeśli proces enrolowania nie jest odpowiednio zabezpieczony.

**Poniżej znajduje się podsumowanie badań [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Sprawdź je, aby uzyskać dodatkowe szczegóły techniczne!**<sup>[[1]](#references)</sup>

## Przegląd analizy binariów DEP i MDM

Badania analizują binaria związane z Device Enrollment Program (DEP) i Mobile Device Management (MDM) w systemie macOS. Kluczowe komponenty obejmują:

- **`mdmclient`**: komunikuje się z serwerami MDM i wywołuje check-iny DEP w wersjach macOS starszych niż 10.13.4.
- **`profiles`**: zarządza Configuration Profiles i wywołuje check-iny DEP w wersjach macOS 10.13.4 i nowszych.
- **`cloudconfigurationd`**: zarządza komunikacją z API DEP i pobiera profile Device Enrollment.

Check-iny DEP wykorzystują funkcje `CPFetchActivationRecord` i `CPGetActivationRecord` z prywatnego frameworka Configuration Profiles do pobrania Activation Record, przy czym `CPFetchActivationRecord` komunikuje się z `cloudconfigurationd` za pośrednictwem XPC.<sup>[[1]](#references)</sup>

## Reverse engineering protokołu Tesla i schematu Absinthe

Podczas check-inu DEP `cloudconfigurationd` wysyła zaszyfrowany i podpisany payload JSON do _iprofiles.apple.com/macProfile_. Payload zawiera numer seryjny urządzenia oraz akcję "RequestProfileConfiguration". Używany schemat szyfrowania jest wewnętrznie nazywany "Absinthe". Rozwikłanie tego schematu jest złożone i obejmuje wiele etapów, co doprowadziło do zbadania alternatywnych metod wstawiania dowolnych numerów seryjnych do żądania Activation Record.<sup>[[1]](#references)</sup>

## Proxyowanie żądań DEP

Próby przechwytywania i modyfikowania żądań DEP do _iprofiles.apple.com_ za pomocą narzędzi takich jak Charles Proxy były utrudnione przez szyfrowanie payloadu oraz mechanizmy bezpieczeństwa SSL/TLS. Jednak włączenie konfiguracji `MCCloudConfigAcceptAnyHTTPSCertificate` pozwala ominąć walidację certyfikatu serwera, chociaż zaszyfrowana natura payloadu nadal uniemożliwia modyfikację numeru seryjnego bez klucza deszyfrującego.<sup>[[1]](#references)</sup>

## Instrumentacja binariów systemowych komunikujących się z DEP

Instrumentacja binariów systemowych, takich jak `cloudconfigurationd`, wymaga wyłączenia System Integrity Protection (SIP) w systemie macOS. Po wyłączeniu SIP narzędzia takie jak LLDB mogą zostać użyte do podłączenia się do procesów systemowych i potencjalnej modyfikacji numeru seryjnego używanego w interakcjach z API DEP. Ta metoda jest preferowana, ponieważ pozwala uniknąć złożoności związanej z entitlements i code signing.<sup>[[1]](#references)</sup>

**Wykorzystanie instrumentacji binariów:**
Modyfikacja payloadu żądania DEP przed serializacją JSON w `cloudconfigurationd` okazała się skuteczna. Proces obejmował:

1. Podłączenie LLDB do `cloudconfigurationd`.
2. Zlokalizowanie miejsca, w którym pobierany jest systemowy numer seryjny.
3. Wstrzyknięcie dowolnego numeru seryjnego do pamięci przed zaszyfrowaniem i wysłaniem payloadu.

Ta metoda umożliwiła pobieranie kompletnych profili DEP dla dowolnych numerów seryjnych, pokazując potencjalną podatność.<sup>[[1]](#references)</sup>

### Automatyzacja instrumentacji za pomocą Python

Proces exploitation został zautomatyzowany przy użyciu Python i API LLDB, dzięki czemu możliwe stało się programowe wstrzykiwanie dowolnych numerów seryjnych i pobieranie odpowiadających im profili DEP.<sup>[[1]](#references)</sup>

### Potencjalne skutki podatności DEP i MDM

Badania wskazały na istotne problemy z bezpieczeństwem:

1. **Ujawnienie informacji**: podanie numeru seryjnego zarejestrowanego w DEP umożliwia pobranie wrażliwych informacji organizacyjnych zawartych w profilu DEP.<sup>[[1]](#references)</sup>

## Referencje

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
