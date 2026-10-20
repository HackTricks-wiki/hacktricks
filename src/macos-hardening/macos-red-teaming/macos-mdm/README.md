# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Aby dowiedzieć się więcej o MDM w macOS, sprawdź:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Podstawy

### **Omówienie MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) służy do zarządzania różnymi urządzeniami użytkowników końcowych, takimi jak smartfony, laptopy i tablety. W przypadku platform Apple (iOS, macOS, tvOS) obejmuje zestaw wyspecjalizowanych funkcji, interfejsów API i praktyk. Działanie MDM zależy od zgodnego serwera MDM, który jest dostępny komercyjnie lub w modelu open source i musi obsługiwać [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Najważniejsze informacje:

- Scentralizowane zarządzanie urządzeniami.
- Wymagany serwer MDM zgodny z protokołem MDM.
- Serwer MDM może wysyłać do urządzeń różne polecenia, na przykład zdalnie usuwać dane lub instalować konfigurację.

### **Podstawy DEP (Device Enrollment Program)**

Oferowany przez Apple [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) upraszcza wdrażanie Mobile Device Management (MDM), umożliwiając automatyczną konfigurację urządzeń iOS, macOS i tvOS bez konieczności ręcznej konfiguracji przez użytkownika. DEP automatyzuje proces rejestracji, dzięki czemu urządzenia są gotowe do pracy od razu po wyjęciu z pudełka, przy minimalnym udziale użytkownika lub administratora. Najważniejsze aspekty:

- Umożliwia urządzeniom automatyczne zarejestrowanie się na wstępnie skonfigurowanym serwerze MDM przy pierwszej aktywacji.
- Jest przydatny przede wszystkim w przypadku nowych urządzeń, ale można go też używać przy ponownej konfiguracji urządzeń.
- Upraszcza konfigurację, dzięki czemu urządzenia szybko nadają się do użytku w organizacji.

### **Kwestie bezpieczeństwa**

Należy pamiętać, że ułatwiona przez DEP rejestracja, mimo że jest korzystna, może też stwarzać zagrożenia dla bezpieczeństwa. Jeśli rejestracja w MDM nie jest odpowiednio zabezpieczona, atakujący mogą wykorzystać uproszczony proces, aby zarejestrować własne urządzenie na serwerze MDM organizacji, podszywając się pod urządzenie firmowe.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Alert bezpieczeństwa**: Uproszczona rejestracja DEP może pozwolić na zarejestrowanie nieautoryzowanego urządzenia na serwerze MDM organizacji, jeśli nie wdrożono odpowiednich zabezpieczeń.

### Podstawy: czym jest SCEP (Simple Certificate Enrolment Protocol)?

- Stosunkowo stary protokół, utworzony przed upowszechnieniem się TLS i HTTPS.
- Zapewnia klientom standardowy sposób przesyłania **żądania podpisania certyfikatu** (CSR) w celu otrzymania certyfikatu. Klient prosi serwer o wydanie mu podpisanego certyfikatu.

### Czym są profile konfiguracyjne (czyli mobileconfigs)?

- Oficjalny sposób Apple na **ustawianie/wymuszanie konfiguracji systemu**.
- Format pliku, który może zawierać wiele ładunków.
- Oparty na listach właściwości (w formacie XML).
- „można je podpisać i zaszyfrować, aby zweryfikować ich pochodzenie, zapewnić integralność i chronić ich zawartość”. Podstawy — strona 70, iOS Security Guide, styczeń 2018.

## Protokoły

### MDM

- Połączenie APNs (**serwery Apple**) + RESTful API (**serwery dostawców** **MDM**)
- **Komunikacja** odbywa się między **urządzeniem** a serwerem powiązanym z **produktem** do **zarządzania** **urządzeniami**
- **Polecenia** są przesyłane z MDM do urządzenia w postaci **słowników zakodowanych w plist**
- Cała komunikacja odbywa się przez **HTTPS**. Serwery MDM mogą korzystać z pinningu i zazwyczaj go stosują.
- Apple wydaje dostawcy MDM **certyfikat APNs** do uwierzytelniania

### DEP

- **3 interfejsy API**: 1 dla sprzedawców, 1 dla dostawców MDM, 1 dla tożsamości urządzeń (nieudokumentowany):
  - Tak zwany [interfejs API „usługi w chmurze” DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Serwery MDM używają go do przypisywania profili DEP do konkretnych urządzeń.
  - [Interfejs API DEP używany przez autoryzowanych sprzedawców Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) do rejestrowania urządzeń oraz sprawdzania ich statusu rejestracji i statusu transakcji.
  - Nieudokumentowany, prywatny interfejs API DEP. Urządzenia Apple używają go do pobierania swoich profili DEP. W systemie macOS za komunikację przez ten interfejs API odpowiada plik binarny `cloudconfigurationd`.
- Nowszy, oparty na **JSON** (w przeciwieństwie do plist)
- Apple wydaje dostawcy MDM **token OAuth**

**Interfejs API „usługi w chmurze” DEP**

- RESTful
- synchronizuje rekordy urządzeń z Apple z serwerem MDM
- synchronizuje „profile DEP” z serwera MDM do Apple (Apple dostarcza je później urządzeniu)
- Profil DEP zawiera:
  - URL serwera dostawcy MDM
  - Dodatkowe zaufane certyfikaty dla URL serwera (opcjonalny pinning)
  - Dodatkowe ustawienia (np. określające, które ekrany pominąć w Setup Assistant)

## Numer seryjny

Urządzenia Apple wyprodukowane po 2010 roku mają zazwyczaj **12-znakowe alfanumeryczne** numery seryjne. **Pierwsze trzy cyfry oznaczają miejsce produkcji**, kolejne **dwie** wskazują **rok** i **tydzień** produkcji, następne **trzy** cyfry stanowią **unikalny** **identyfikator**, a **ostatnie** **cztery** cyfry oznaczają **numer modelu**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Etapy rejestracji i zarządzania

1. Utworzenie rekordu urządzenia (sprzedawca, Apple): tworzony jest rekord nowego urządzenia
2. Przypisanie rekordu urządzenia (klient): urządzenie zostaje przypisane do serwera MDM
3. Synchronizacja rekordu urządzenia (dostawca MDM): MDM synchronizuje rekordy urządzeń i przesyła profile DEP do Apple
4. Zgłoszenie do DEP (urządzenie): urządzenie pobiera swój profil DEP
5. Pobranie profilu (urządzenie)
6. Instalacja profilu (urządzenie), w tym ładunków MDM, SCEP i głównego CA
7. Wydawanie poleceń MDM (urządzenie)

![Numer seryjny — etapy rejestracji i zarządzania: 7. Wydawanie poleceń MDM (urządzenie)](<../../../images/image (694).png>)

Plik `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` eksportuje funkcje, które można uznać za **wysokopoziomowe „etapy”** procesu rejestracji.

### Krok 4: Zgłoszenie do DEP — pobranie Activation Record

Ten etap procesu odbywa się, gdy **użytkownik po raz pierwszy uruchamia Maca** (lub po całkowitym wyczyszczeniu urządzenia)

![Etapy rejestracji i zarządzania — krok 4: Zgłoszenie do DEP — pobranie Activation Record: Ten etap procesu odbywa się, gdy użytkownik po raz pierwszy uruchamia Maca (lub po całkowitym...](<../../../images/image (1044).png>)

lub po uruchomieniu polecenia `sudo profiles show -type enrollment`

- Ustalenie, **czy urządzenie jest włączone do DEP**
- Activation Record to wewnętrzna nazwa **„profilu” DEP**
- Proces rozpoczyna się, gdy tylko urządzenie połączy się z Internetem
- Obsługiwany przez **`CPFetchActivationRecord`**
- Implementowany przez **`cloudconfigurationd`** za pośrednictwem XPC. **„Setup Assistant”** (przy pierwszym uruchomieniu urządzenia) lub polecenie **`profiles`** kontaktuje się z **tym demonem**, aby pobrać Activation Record.
  - LaunchDaemon (zawsze działa jako root)

Pobranie Activation Record obejmuje kilka etapów realizowanych przez **`MCTeslaConfigurationFetcher`**. Proces wykorzystuje szyfrowanie Absinthe<sup>[[1]](#references)</sup>

1. Pobranie **certyfikatu**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Zainicjowanie** stanu na podstawie certyfikatu (**`NACInit`**)
   1. Wykorzystuje różne dane specyficzne dla urządzenia (np. **numer seryjny za pośrednictwem `IOKit`**)
3. Pobranie **klucza sesji**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Ustanowienie sesji (**`NACKeyEstablishment`**)
5. Wysłanie żądania
   1. POST do [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) z danymi `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. Ładunek JSON jest szyfrowany za pomocą Absinthe (**`NACSign`**)
   3. Wszystkie żądania są wysyłane przez HTTPS, z użyciem wbudowanych certyfikatów głównych

![Etapy rejestracji i zarządzania — krok 4: Zgłoszenie do DEP — pobranie Activation Record: 3. Wszystkie żądania są wysyłane przez HTTPS, z użyciem wbudowanych certyfikatów głównych](<../../../images/image (566) (1).png>)

Odpowiedź to słownik JSON zawierający ważne dane, takie jak:

- **url**: URL hosta dostawcy MDM dla profilu aktywacji
- **anchor-certs**: tablica certyfikatów DER używanych jako zaufane kotwice

### **Krok 5: Pobranie profilu**

![Krok 4: Zgłoszenie do DEP — pobranie Activation Record — krok 5: Pobranie profilu: Krok 5: Pobranie profilu](<../../../images/image (444).png>)

- Żądanie jest wysyłane na **URL podany w profilu DEP**.
- Jeśli podano **certyfikaty kotwiczące**, są one używane do **oceny zaufania**.
  - Przypomnienie: właściwość **anchor_certs** profilu DEP
- **Żądanie to prosty plik .plist** zawierający identyfikację urządzenia
  - Przykłady: **UDID, wersja systemu operacyjnego**.
- Podpisane przez CMS, zakodowane w DER
- Podpisane za pomocą **certyfikatu tożsamości urządzenia (z APNS)**
- **Łańcuch certyfikatów** zawiera wygasły **Apple iPhone Device CA**

![Krok 4: Zgłoszenie do DEP — pobranie Activation Record — krok 5: Pobranie profilu: Podpisane za pomocą certyfikatu tożsamości urządzenia (z APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Krok 6: Instalacja profilu

- Po pobraniu **profil jest zapisywany w systemie**
- Ten etap rozpoczyna się automatycznie (jeśli odbywa się w **Setup Assistant**)
- Obsługiwany przez **`CPInstallActivationProfile`**
- Implementowany przez mdmclient za pośrednictwem XPC
  - LaunchDaemon (jako root) lub LaunchAgent (jako użytkownik), zależnie od kontekstu
- Profile konfiguracyjne zawierają wiele ładunków do zainstalowania
- Framework korzysta z architektury wtyczek do instalowania profili
- Każdy typ ładunku jest powiązany z wtyczką
  - Może to być XPC (w frameworku) lub klasyczny Cocoa (w ManagedClient.app)
- Przykład:
  - Ładunki certyfikatów korzystają z CertificateService.xpc

Profil **aktywacyjny** dostarczany przez dostawcę MDM zazwyczaj **zawiera następujące ładunki**:

- `com.apple.mdm`: aby **zarejestrować** urządzenie w MDM
- `com.apple.security.scep`: aby bezpiecznie dostarczyć urządzeniu **certyfikat klienta**.
- `com.apple.security.pem`: aby **zainstalować zaufane certyfikaty CA** w pęku kluczy systemu urządzenia.
- Zainstalowanie ładunku MDM odpowiada **zgłoszeniu do MDM opisanemu w dokumentacji**
- Ładunek **zawiera kluczowe właściwości**:
- - URL zgłoszeń do MDM (**`CheckInURL`**)
  - URL odpytywania o polecenia MDM (**`ServerURL`**) + temat APNs, który je wyzwala
- Aby zainstalować ładunek MDM, żądanie jest wysyłane na **`CheckInURL`**
- Implementowany w **`mdmclient`**
- Ładunek MDM może zależeć od innych ładunków
- Umożliwia **przypinanie żądań do określonych certyfikatów**:
  - Właściwość: **`CheckInURLPinningCertificateUUIDs`**
  - Właściwość: **`ServerURLPinningCertificateUUIDs`**
  - Dostarczane przez ładunek PEM
- Umożliwia przypisanie urządzeniu certyfikatu tożsamości:
  - Właściwość: IdentityCertificateUUID
  - Dostarczane przez ładunek SCEP

### **Krok 7: Oczekiwanie na polecenia MDM**

- Po zakończeniu zgłoszenia do MDM dostawca może **wysyłać powiadomienia push za pomocą APNs**
- Po odebraniu są one obsługiwane przez **`mdmclient`**
- Aby pobrać polecenia MDM, żądanie jest wysyłane na ServerURL
- Wykorzystuje wcześniej zainstalowany ładunek MDM:
  - **`ServerURLPinningCertificateUUIDs`** do przypinania żądań
  - **`IdentityCertificateUUID`** jako certyfikat klienta TLS

## Ataki

### Rejestrowanie urządzeń w innych organizacjach

Przypisany numer seryjny może wskazywać ścieżkę rejestracji organizacji, ale **nie** gwarantuje rejestracji w MDM. Serwer może wymagać uwierzytelnienia użytkownika za pośrednictwem `configuration_web_url` przed zwróceniem profilu rejestracyjnego. Sprawdź, czy istnieje alternatywna ścieżka rejestracji, która pomija tę weryfikację, zamiast zakładać, że każdy przypisany numer seryjny pozwala dołączyć urządzeniu do floty.<sup>[[3]](#references)</sup>

Aby przeprowadzić rejestrację nieautoryzowanego urządzenia, skorzystaj z poniższej strony. Informacje o kontroli MDM i dostarczaniu pakietów po uzyskaniu dostępu znajdziesz w sekcji [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Szczegółowa analiza macOS MDM (i jak można je skompromitować)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — „MDM Me Maybe?” (badania nad bezpieczeństwem rejestracji DEP/MDM)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Uwierzytelnianie za pomocą widoków internetowych](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
