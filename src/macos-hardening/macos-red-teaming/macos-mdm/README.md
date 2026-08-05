# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Aby dowiedzieć się więcej o macOS MDM, sprawdź:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Podstawy

### **Przegląd MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) służy do nadzorowania różnych urządzeń użytkowników końcowych, takich jak smartfony, laptopy i tablety. W szczególności w przypadku platform Apple (iOS, macOS, tvOS) obejmuje zestaw wyspecjalizowanych funkcji, API i praktyk. Działanie MDM opiera się na kompatybilnym serwerze MDM, który jest dostępny komercyjnie lub jako open source i musi obsługiwać [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Najważniejsze elementy:

- Scentralizowana kontrola nad urządzeniami.
- Zależność od serwera MDM zgodnego z protokołem MDM.
- Możliwość wysyłania przez serwer MDM różnych poleceń do urządzeń, takich jak zdalne usuwanie danych lub instalowanie konfiguracji.

### **Podstawy DEP (Device Enrollment Program)**

Oferowany przez Apple program [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) upraszcza integrację Mobile Device Management (MDM), umożliwiając bezdotykową konfigurację urządzeń iOS, macOS oraz tvOS. DEP automatyzuje proces rejestracji, dzięki czemu urządzenia mogą działać od razu po wyjęciu z pudełka, przy minimalnej ingerencji użytkownika lub administratora. Najważniejsze aspekty:

- Umożliwia urządzeniom automatyczną rejestrację na wstępnie zdefiniowanym serwerze MDM podczas pierwszej aktywacji.
- Jest przede wszystkim przydatny w przypadku zupełnie nowych urządzeń, ale może być również stosowany do urządzeń poddawanych rekonfiguracji.
- Ułatwia konfigurację, dzięki czemu urządzenia szybko stają się gotowe do użytku w organizacji.

### **Kwestie bezpieczeństwa**

Należy pamiętać, że łatwość rejestracji zapewniana przez DEP, choć korzystna, może również stwarzać zagrożenia bezpieczeństwa. Jeśli mechanizmy ochronne rejestracji MDM nie są odpowiednio wymuszone, atakujący mogą wykorzystać ten uproszczony proces do zarejestrowania własnego urządzenia na serwerze MDM organizacji, podszywając się pod urządzenie firmowe.<sup>[2]</sup>

> [!CAUTION]
> **Alert bezpieczeństwa**: Uproszczona rejestracja DEP może potencjalnie umożliwić nieautoryzowaną rejestrację urządzenia na serwerze MDM organizacji, jeśli nie zostaną wdrożone odpowiednie zabezpieczenia.

### Podstawy: czym jest SCEP (Simple Certificate Enrolment Protocol)?

- Stosunkowo stary protokół, utworzony przed powszechnym użyciem TLS i HTTPS.
- Zapewnia klientom ustandaryzowany sposób wysyłania **Certificate Signing Request** (CSR) w celu uzyskania certyfikatu. Klient prosi serwer o wydanie podpisanego certyfikatu.

### Czym są Configuration Profiles (znane również jako mobileconfigs)?

- Oficjalny sposób Apple na **ustawianie i wymuszanie konfiguracji systemu**.
- Format pliku, który może zawierać wiele payloadów.
- Oparty na property lists (w formacie XML).
- „can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protokoły

### MDM

- Połączenie APNs (**serwery Apple**) + RESTful API (**serwery dostawcy** MDM)
- **Komunikacja** odbywa się między **urządzeniem** a serwerem powiązanym z **produktem** do **zarządzania** **urządzeniami**
- **Polecenia** są dostarczane z MDM do urządzenia w postaci **słowników zakodowanych jako plist**
- Wszystko odbywa się przez **HTTPS**. Serwery MDM mogą używać (i zazwyczaj używają) pinningu.
- Apple przyznaje dostawcy MDM **certyfikat APNs** do uwierzytelniania

### DEP

- **3 API**: 1 dla resellerów, 1 dla dostawców MDM i 1 dla tożsamości urządzenia (nieudokumentowane):
- Tak zwane [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Jest używane przez serwery MDM do kojarzenia profili DEP z określonymi urządzeniami.
- [DEP API używane przez Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) do rejestrowania urządzeń, sprawdzania statusu rejestracji i sprawdzania statusu transakcji.
- Nieudokumentowane prywatne DEP API. Jest używane przez Apple Devices do żądania ich profilu DEP. W systemie macOS za komunikację przez to API odpowiada plik binarny `cloudconfigurationd`.
- Bardziej nowoczesne i oparte na **JSON** (w przeciwieństwie do plist)
- Apple przyznaje dostawcy MDM **token OAuth**

**DEP "cloud service" API**

- RESTful
- synchronizuje rekordy urządzeń z Apple do serwera MDM
- synchronizuje „profile DEP” z serwera MDM do Apple (później są one dostarczane przez Apple do urządzenia)
- Profil DEP zawiera:
- URL serwera dostawcy MDM
- Dodatkowe zaufane certyfikaty dla URL serwera (opcjonalny pinning)
- Dodatkowe ustawienia (np. ekrany, które należy pominąć w Setup Assistant)

## Numer seryjny

Urządzenia Apple wyprodukowane po 2010 roku mają zazwyczaj **12-znakowe alfanumeryczne** numery seryjne, przy czym **pierwsze trzy cyfry oznaczają lokalizację produkcji**, kolejne **dwie** oznaczają **rok** i **tydzień** produkcji, następne **trzy** cyfry stanowią **unikalny** **identyfikator**, a **ostatnie** **cztery** cyfry oznaczają **numer modelu**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Etapy rejestracji i zarządzania

1. Utworzenie rekordu urządzenia (Reseller, Apple): tworzony jest rekord nowego urządzenia
2. Przypisanie rekordu urządzenia (Customer): urządzenie zostaje przypisane do serwera MDM
3. Synchronizacja rekordu urządzenia (dostawca MDM): MDM synchronizuje rekordy urządzeń i przekazuje profile DEP do Apple
4. DEP check-in (urządzenie): urządzenie otrzymuje swój profil DEP
5. Pobranie profilu (urządzenie)
6. Instalacja profilu (urządzenie) a. w tym payloadów MDM, SCEP i głównego CA
7. Wydawanie poleceń MDM (urządzenie)

![Numer seryjny - Etapy rejestracji i zarządzania: 7. Wydawanie poleceń MDM (urządzenie)](<../../../images/image (694).png>)

Plik `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` eksportuje funkcje, które można uznać za **wysokopoziomowe „etapy”** procesu rejestracji.

### Etap 4: DEP check-in - pobieranie Activation Record

Ta część procesu występuje, gdy **użytkownik uruchamia Maca po raz pierwszy** (lub po całkowitym wymazaniu)

![Etapy rejestracji i zarządzania - Etap 4: DEP check-in - pobieranie Activation Record: Ta część procesu występuje, gdy użytkownik uruchamia Maca po raz pierwszy lub po całkowitym...](<../../../images/image (1044).png>)

lub podczas wykonywania `sudo profiles show -type enrollment`

- Określenie, **czy urządzenie ma włączony DEP**
- Activation Record to wewnętrzna nazwa **„profilu” DEP**
- Rozpoczyna się natychmiast po połączeniu urządzenia z Internetem
- Obsługiwane przez **`CPFetchActivationRecord`**
- Implementowane przez **`cloudconfigurationd`** za pośrednictwem XPC. **„Setup Assistant”** (podczas pierwszego uruchomienia urządzenia) lub polecenie **`profiles`** kontaktuje się z **tym daemonem**, aby pobrać activation record.
- LaunchDaemon (zawsze działa jako root)

Aby pobrać Activation Record, wykonywanych jest kilka etapów obsługiwanych przez **`MCTeslaConfigurationFetcher`**. Proces ten używa szyfrowania o nazwie **Absinthe**<sup>[1]</sup>

1. Pobranie **certyfikatu**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicjalizacja** stanu na podstawie certyfikatu (**`NACInit`**)
1. Wykorzystuje różne dane specyficzne dla urządzenia (np. **numer seryjny za pośrednictwem `IOKit`**)
3. Pobranie **klucza sesji**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Nawiązanie sesji (**`NACKeyEstablishment`**)
5. Wykonanie żądania
1. POST do [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) z wysłaniem danych `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Payload JSON jest szyfrowany przy użyciu Absinthe (**`NACSign`**)
3. Wszystkie żądania są wykonywane przez HTTPs, używane są wbudowane certyfikaty główne

![Etapy rejestracji i zarządzania - Etap 4: DEP check-in - pobieranie Activation Record: 3. Wszystkie żądania są wykonywane przez HTTPs, używane są wbudowane certyfikaty główne](<../../../images/image (566) (1).png>)

Odpowiedź jest słownikiem JSON zawierającym ważne dane, takie jak:

- **url**: URL hosta dostawcy MDM dla activation profile
- **anchor-certs**: Tablica certyfikatów DER używanych jako zaufane anchor

### **Etap 5: Pobieranie profilu**

![Etap 4: DEP check-in - pobieranie Activation Record - Etap 5: Pobieranie profilu: Etap 5: Pobieranie profilu](<../../../images/image (444).png>)

- Żądanie jest wysyłane do **URL podanego w profilu DEP**.
- **Certyfikaty anchor** służą do **oceny zaufania**, jeśli zostały podane.
- Przypomnienie: właściwość **anchor_certs** profilu DEP
- **Żądanie jest prostym plikiem .plist** zawierającym identyfikację urządzenia
- Przykłady: **UDID, wersja systemu operacyjnego**.
- Podpisane przez CMS, zakodowane w DER
- Podpisane przy użyciu **certyfikatu tożsamości urządzenia (z APNS)**
- **Łańcuch certyfikatów** zawiera wygasły **Apple iPhone Device CA**

![Etap 4: DEP check-in - pobieranie Activation Record - Etap 5: Pobieranie profilu: Podpisane przy użyciu certyfikatu tożsamości urządzenia (z APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Etap 6: Instalacja profilu

- Po pobraniu **profil jest zapisywany w systemie**
- Ten etap rozpoczyna się automatycznie (jeśli uruchomiony jest **Setup Assistant**)
- Obsługiwany przez **`CPInstallActivationProfile`**
- Implementowany przez mdmclient za pośrednictwem XPC
- LaunchDaemon (jako root) lub LaunchAgent (jako użytkownik), zależnie od kontekstu
- Configuration profiles zawierają wiele payloadów do zainstalowania
- Framework ma architekturę opartą na pluginach do instalowania profili
- Każdy typ payloadu jest powiązany z pluginem
- Może to być XPC (w frameworku) lub klasyczny Cocoa (w ManagedClient.app)
- Przykład:
- Certificate Payloads używają CertificateService.xpc

Zazwyczaj **activation profile** dostarczany przez dostawcę MDM będzie **zawierał następujące payloady**:

- `com.apple.mdm`: do **zarejestrowania** urządzenia w MDM
- `com.apple.security.scep`: do bezpiecznego dostarczenia urządzeniu **certyfikatu klienta**.
- `com.apple.security.pem`: do **zainstalowania zaufanych certyfikatów CA** w System Keychain urządzenia.
- Instalowanie payloadu MDM jest odpowiednikiem **MDM check-in w dokumentacji**
- Payload **zawiera kluczowe właściwości**:
- - URL MDM Check-In (**`CheckInURL`**)
- URL odpytywania poleceń MDM (**`ServerURL`**) + topic APNs do jego wywołania
- Aby zainstalować payload MDM, żądanie jest wysyłane do **`CheckInURL`**
- Implementowane w **`mdmclient`**
- Payload MDM może zależeć od innych payloadów
- Umożliwia **przypinanie żądań do określonych certyfikatów**:
- Właściwość: **`CheckInURLPinningCertificateUUIDs`**
- Właściwość: **`ServerURLPinningCertificateUUIDs`**
- Dostarczane za pośrednictwem payloadu PEM
- Umożliwia przypisanie urządzeniu certyfikatu tożsamości:
- Właściwość: IdentityCertificateUUID
- Dostarczane za pośrednictwem payloadu SCEP

### **Etap 7: Nasłuchiwanie poleceń MDM**

- Po zakończeniu MDM check-in dostawca może **wysyłać powiadomienia push przy użyciu APNs**
- Po otrzymaniu są obsługiwane przez **`mdmclient`**
- Aby odpytać o polecenia MDM, żądanie jest wysyłane do ServerURL
- Wykorzystywany jest wcześniej zainstalowany payload MDM:
- **`ServerURLPinningCertificateUUIDs`** do pinningu żądania
- **`IdentityCertificateUUID`** jako certyfikat klienta TLS

## Ataki

### Rejestrowanie urządzeń w innych organizacjach

Jak wspomniano wcześniej, aby spróbować zarejestrować urządzenie w organizacji, potrzebny jest **wyłącznie numer seryjny należący do tej organizacji**. Po zarejestrowaniu urządzenia wiele organizacji instaluje na nim wrażliwe dane: certyfikaty, aplikacje, hasła WiFi, konfiguracje VPN [i tak dalej](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Dlatego może to być niebezpieczny punkt wejścia dla atakujących, jeśli proces rejestracji nie jest prawidłowo chroniony:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referencje

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
