# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Aby dowiedzieć się o MDM macOS, sprawdź:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Podstawy

### **Przegląd MDM (Zarządzanie Urządzeniami Mobilnymi)**

[Zarządzanie Urządzeniami Mobilnymi](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) jest wykorzystywane do nadzorowania różnych urządzeń końcowych, takich jak smartfony, laptopy i tablety. Szczególnie dla platform Apple (iOS, macOS, tvOS) obejmuje zestaw specjalistycznych funkcji, interfejsów API i praktyk. Działanie MDM opiera się na kompatybilnym serwerze MDM, który jest dostępny komercyjnie lub jako open-source, i musi wspierać [Protokół MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Kluczowe punkty obejmują:

- Centralne zarządzanie urządzeniami.
- Zależność od serwera MDM, który przestrzega protokołu MDM.
- Zdolność serwera MDM do wysyłania różnych poleceń do urządzeń, na przykład zdalnego usuwania danych lub instalacji konfiguracji.

### **Podstawy DEP (Program Rejestracji Urządzeń)**

[Program Rejestracji Urządzeń](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) oferowany przez Apple upraszcza integrację Zarządzania Urządzeniami Mobilnymi (MDM) poprzez umożliwienie konfiguracji bezdotykowej dla urządzeń iOS, macOS i tvOS. DEP automatyzuje proces rejestracji, pozwalając urządzeniom na działanie od razu po wyjęciu z pudełka, z minimalną interwencją użytkownika lub administratora. Kluczowe aspekty obejmują:

- Umożliwia urządzeniom autonomiczne rejestrowanie się na wcześniej zdefiniowanym serwerze MDM po pierwszej aktywacji.
- Głównie korzystne dla nowych urządzeń, ale również stosowane dla urządzeń poddawanych rekonfiguracji.
- Ułatwia prostą konfigurację, szybko przygotowując urządzenia do użytku w organizacji.

### **Rozważania dotyczące bezpieczeństwa**

Ważne jest, aby zauważyć, że łatwość rejestracji zapewniana przez DEP, choć korzystna, może również stwarzać ryzyko bezpieczeństwa. Jeśli środki ochronne nie są odpowiednio egzekwowane dla rejestracji MDM, napastnicy mogą wykorzystać ten uproszczony proces do zarejestrowania swojego urządzenia na serwerze MDM organizacji, podszywając się pod urządzenie korporacyjne.

> [!CAUTION]
> **Alert bezpieczeństwa**: Uproszczona rejestracja DEP może potencjalnie umożliwić nieautoryzowaną rejestrację urządzenia na serwerze MDM organizacji, jeśli odpowiednie zabezpieczenia nie są wdrożone.

### Podstawy Czym jest SCEP (Protokół Prostej Rejestracji Certyfikatów)?

- Stosunkowo stary protokół, stworzony przed powszechnym wprowadzeniem TLS i HTTPS.
- Daje klientom ustandaryzowany sposób wysyłania **Żądania Podpisania Certyfikatu** (CSR) w celu uzyskania certyfikatu. Klient poprosi serwer o wydanie podpisanego certyfikatu.

### Czym są Profile Konfiguracji (znane również jako mobileconfigs)?

- Oficjalny sposób Apple na **ustawianie/egzekwowanie konfiguracji systemu.**
- Format pliku, który może zawierać wiele ładunków.
- Oparty na listach właściwości (w rodzaju XML).
- „może być podpisany i zaszyfrowany, aby zweryfikować ich pochodzenie, zapewnić integralność i chronić ich zawartość.” Podstawy — Strona 70, Przewodnik po Bezpieczeństwie iOS, styczeń 2018.

## Protokoły

### MDM

- Połączenie APNs (**serwery Apple**) + RESTful API (**serwery dostawców MDM**)
- **Komunikacja** zachodzi między **urządzeniem** a serwerem związanym z produktem **zarządzania urządzeniami**
- **Polecenia** dostarczane z MDM do urządzenia w **słownikach zakodowanych w plist**
- Całość przez **HTTPS**. Serwery MDM mogą być (i zazwyczaj są) przypinane.
- Apple przyznaje dostawcy MDM **certyfikat APNs** do uwierzytelniania

### DEP

- **3 API**: 1 dla sprzedawców, 1 dla dostawców MDM, 1 dla to
