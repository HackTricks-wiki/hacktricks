# Rejestrowanie urządzeń w innych organizacjach

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Apple Automated Device Enrollment (dawniej DEP) rozpoczyna się od identyfikacji urządzenia przypisanego do organizacji. Opisane tutaj badania z 2018 roku wykazały, że znajomość przypisanego numeru seryjnego wystarczała do pobrania profili enrollmentu niektórych organizacji, ponieważ organizacje te nie wymagały odpowiedniego dodatkowego uwierzytelniania. Jest to historyczne ustalenie, a nie twierdzenie, że do każdego obecnego MDM można dołączyć wyłącznie za pomocą numeru seryjnego. Profile mogą zawierać certyfikaty, aplikacje, sekrety Wi-Fi, ustawienia VPN oraz inne wrażliwe konfiguracje.<sup>[[1]](#references)[[2]](#references)</sup>

**Poniżej znajduje się podsumowanie badań [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Więcej szczegółów technicznych znajdziesz w tym materiale!**<sup>[[1]](#references)</sup>

## Przegląd analizy binariów DEP i MDM

W ramach badań przeanalizowano binaria powiązane z DEP i MDM w wersjach macOS aktualnych w tamtym czasie. Nazwy komponentów i ich odpowiedzialność mogą zmieniać się między kolejnymi wydaniami:

- **`mdmclient`**: Komunikuje się z serwerami MDM i uruchamia check-iny DEP w wersjach macOS starszych niż 10.13.4.
- **`profiles`**: Zarządza Configuration Profiles i uruchamia check-iny DEP w wersjach macOS 10.13.4 i nowszych.
- **`cloudconfigurationd`**: Zarządza komunikacją z API DEP i pobiera profile Device Enrollment.

Check-iny DEP wykorzystują funkcje `CPFetchActivationRecord` i `CPGetActivationRecord` z prywatnego frameworka Configuration Profiles do pobierania Activation Record, przy czym `CPFetchActivationRecord` komunikuje się z `cloudconfigurationd` za pośrednictwem XPC.<sup>[[1]](#references)</sup>

## Reverse engineering protokołu Tesla i schematu Absinthe

Check-in DEP obejmuje wysłanie przez `cloudconfigurationd` zaszyfrowanego i podpisanego payloadu JSON do _iprofiles.apple.com/macProfile_. Payload zawiera numer seryjny urządzenia oraz akcję "RequestProfileConfiguration". Używany schemat szyfrowania jest wewnętrznie określany jako "Absinthe". Rozwikłanie tego schematu jest złożone i obejmuje wiele kroków, co doprowadziło do zbadania alternatywnych metod wprowadzania dowolnych numerów seryjnych do żądania Activation Record.<sup>[[1]](#references)</sup>

## Proxyowanie żądań DEP

Próby przechwytywania i modyfikowania żądań DEP do _iprofiles.apple.com_ za pomocą narzędzi takich jak Charles Proxy były utrudnione przez szyfrowanie payloadu oraz mechanizmy bezpieczeństwa SSL/TLS. Jednak włączenie konfiguracji `MCCloudConfigAcceptAnyHTTPSCertificate` pozwala ominąć walidację certyfikatu serwera, chociaż zaszyfrowany charakter payloadu nadal uniemożliwia modyfikację numeru seryjnego bez klucza deszyfrującego.<sup>[[1]](#references)</sup>

## Instrumentowanie binariów systemowych komunikujących się z DEP

Instrumentowanie binariów systemowych, takich jak `cloudconfigurationd`, wymaga wyłączenia System Integrity Protection (SIP) w macOS. Po wyłączeniu SIP narzędzia takie jak LLDB mogą zostać użyte do podłączenia się do procesów systemowych i potencjalnej modyfikacji numeru seryjnego używanego w interakcjach z API DEP. Ta metoda jest preferowana, ponieważ pozwala uniknąć złożoności związanej z entitlements i code signing.<sup>[[1]](#references)</sup>

**Wykorzystanie instrumentowania binariów:**
Modyfikowanie payloadu żądania DEP przed serializacją JSON w `cloudconfigurationd` okazało się skuteczne. Proces obejmował:

1. Podłączenie LLDB do `cloudconfigurationd`.
2. Zlokalizowanie miejsca, w którym pobierany jest systemowy numer seryjny.
3. Wstrzyknięcie dowolnego numeru seryjnego do pamięci przed zaszyfrowaniem i wysłaniem payloadu.

Metoda ta pozwoliła badaczom pobierać profile DEP dla podanych, przypisanych numerów seryjnych. Nie sprawiała, że nieprzypisany, dowolny numer seryjny stawał się prawidłowy.<sup>[[1]](#references)</sup>

### Automatyzacja instrumentowania za pomocą Python

Proces exploitation został zautomatyzowany za pomocą Python i API LLDB, dzięki czemu możliwe stało się programowe wstrzykiwanie dowolnych numerów seryjnych i pobieranie odpowiadających im profili DEP.<sup>[[1]](#references)</sup>

### Potencjalne skutki podatności DEP i MDM

Badania zwróciły uwagę na istotne problemy związane z bezpieczeństwem:

1. **Ujawnienie informacji**: Podanie numeru seryjnego zarejestrowanego w DEP umożliwia pobranie wrażliwych informacji organizacyjnych zawartych w profilu DEP.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM może, ale nie musi: bezpieczeństwo Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — automatyczny Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
