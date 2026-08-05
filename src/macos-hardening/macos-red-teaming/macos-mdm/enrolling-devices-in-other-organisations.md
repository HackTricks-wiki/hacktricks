# Enrolling Devices in Other Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Jak [**wspomniano wcześniej**](#what-is-mdm-mobile-device-management)**,** aby spróbować zarejestrować urządzenie w organizacji, **potrzebny jest tylko numer seryjny należący do tej organizacji**. Po zarejestrowaniu urządzenia wiele organizacji zainstaluje na nim wrażliwe dane: certyfikaty, aplikacje, hasła WiFi, konfiguracje VPN [i tak dalej](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Dlatego może to stanowić niebezpieczny entrypoint dla attackerów, jeśli proces rejestracji nie jest prawidłowo zabezpieczony.

**Poniżej znajduje się podsumowanie badań [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Sprawdź je, aby uzyskać więcej szczegółów technicznych!**<sup>[[1]](#references)</sup>

## Przegląd analizy binarnej DEP i MDM

Te badania analizują pliki binarne powiązane z Device Enrollment Program (DEP) i Mobile Device Management (MDM) w macOS. Najważniejsze komponenty obejmują:

- **`mdmclient`**: Komunikuje się z serwerami MDM i wywołuje check-iny DEP w wersjach macOS wcześniejszych niż 10.13.4.
- **`profiles`**: Zarządza Configuration Profiles i wywołuje check-iny DEP w wersjach macOS 10.13.4 i nowszych.
- **`cloudconfigurationd`**: Zarządza komunikacją z API DEP i pobiera profile Device Enrollment.

Check-iny DEP wykorzystują funkcje `CPFetchActivationRecord` i `CPGetActivationRecord` z prywatnego frameworka Configuration Profiles do pobrania Activation Record, przy czym `CPFetchActivationRecord` komunikuje się z `cloudconfigurationd` przez XPC.<sup>[[1]](#references)</sup>

## Reverse engineering protokołu Tesla i schematu Absinthe

Check-in DEP obejmuje wysłanie przez `cloudconfigurationd` zaszyfrowanego i podpisanego payloadu JSON do _iprofiles.apple.com/macProfile_. Payload zawiera numer seryjny urządzenia oraz akcję „RequestProfileConfiguration”. Stosowany schemat szyfrowania jest wewnętrznie określany jako „Absinthe”. Rozwikłanie tego schematu jest złożone i obejmuje wiele kroków, co doprowadziło do zbadania alternatywnych metod wprowadzania dowolnych numerów seryjnych do żądania Activation Record.<sup>[[1]](#references)</sup>

## Proxying żądań DEP

Próby przechwytywania i modyfikowania żądań DEP do _iprofiles.apple.com_ za pomocą narzędzi takich jak Charles Proxy były utrudnione przez szyfrowanie payloadu oraz mechanizmy bezpieczeństwa SSL/TLS. Jednak włączenie konfiguracji `MCCloudConfigAcceptAnyHTTPSCertificate` pozwala ominąć walidację certyfikatu serwera, chociaż zaszyfrowana natura payloadu nadal uniemożliwia modyfikację numeru seryjnego bez klucza deszyfrującego.<sup>[[1]](#references)</sup>

## Instrumentowanie binariów systemowych wchodzących w interakcję z DEP

Instrumentowanie binariów systemowych, takich jak `cloudconfigurationd`, wymaga wyłączenia System Integrity Protection (SIP) w macOS. Po wyłączeniu SIP narzędzia takie jak LLDB mogą zostać użyte do podłączenia się do procesów systemowych i potencjalnej modyfikacji numeru seryjnego używanego w interakcjach z API DEP. Ta metoda jest preferowana, ponieważ pozwala uniknąć złożoności związanej z entitlements i code signing.

**Exploiting Binary Instrumentation:**
Modyfikowanie żądania DEP przed serializacją JSON w `cloudconfigurationd` okazało się skuteczne. Proces obejmował:

1. Podłączenie LLDB do `cloudconfigurationd`.
2. Zlokalizowanie miejsca, w którym pobierany jest systemowy numer seryjny.
3. Wstrzyknięcie dowolnego numeru seryjnego do pamięci przed zaszyfrowaniem i wysłaniem payloadu.

Metoda ta umożliwiła pobieranie kompletnych profili DEP dla dowolnych numerów seryjnych, demonstrując potencjalną podatność.<sup>[[1]](#references)</sup>

### Automatyzacja instrumentowania za pomocą Python

Proces exploitation został zautomatyzowany za pomocą Python i API LLDB, dzięki czemu możliwe stało się programowe wstrzykiwanie dowolnych numerów seryjnych i pobieranie odpowiadających im profili DEP.<sup>[[1]](#references)</sup>

### Potencjalne skutki podatności DEP i MDM

Badania wykazały istotne problemy z bezpieczeństwem:

1. **Ujawnienie informacji**: Podanie numeru seryjnego zarejestrowanego w DEP umożliwia pobranie wrażliwych informacji organizacyjnych zawartych w profilu DEP.<sup>[[1]](#references)</sup>

## Referencje

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
