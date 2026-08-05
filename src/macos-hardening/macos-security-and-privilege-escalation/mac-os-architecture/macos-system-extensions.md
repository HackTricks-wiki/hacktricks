# Rozszerzenia systemowe macOS

{{#include ../../../banners/hacktricks-training.md}}

## Rozszerzenia systemowe / Endpoint Security Framework

W przeciwieństwie do **Kernel Extensions**, **System Extensions działają w przestrzeni użytkownika**, a nie w przestrzeni jądra, zmniejszając ryzyko awarii systemu spowodowanej nieprawidłowym działaniem rozszerzenia.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Istnieją trzy typy rozszerzeń systemowych: rozszerzenia **DriverKit**, **Network** oraz **Endpoint Security**.

### **Rozszerzenia DriverKit**

DriverKit jest zamiennikiem rozszerzeń jądra, które **zapewniają obsługę sprzętu**. Umożliwia sterownikom urządzeń, takim jak sterowniki USB, Serial, NIC i HID, działanie w przestrzeni użytkownika zamiast w przestrzeni jądra. Framework DriverKit zawiera **wersje wybranych klas I/O Kit przeznaczone dla przestrzeni użytkownika**, a jądro przekazuje standardowe zdarzenia I/O Kit do przestrzeni użytkownika, zapewniając bezpieczniejsze środowisko do działania tych sterowników.<sup>[[2]](#references)</sup>

### **Rozszerzenia Network**

Network Extensions umożliwiają dostosowywanie zachowania sieci. Istnieje kilka typów Network Extensions:

- **App Proxy**: służy do tworzenia klienta VPN implementującego niestandardowy, zorientowany na przepływy protokół VPN. Oznacza to, że obsługuje ruch sieciowy na podstawie połączeń (czyli przepływów), a nie pojedynczych pakietów.
- **Packet Tunnel**: służy do tworzenia klienta VPN implementującego niestandardowy, zorientowany na pakiety protokół VPN. Oznacza to, że obsługuje ruch sieciowy na podstawie pojedynczych pakietów.
- **Filter Data**: służy do filtrowania sieciowych „przepływów”. Może monitorować lub modyfikować dane sieciowe na poziomie przepływu.
- **Filter Packet**: służy do filtrowania pojedynczych pakietów sieciowych. Może monitorować lub modyfikować dane sieciowe na poziomie pakietów.
- **DNS Proxy**: służy do tworzenia niestandardowego dostawcy DNS. Może służyć do monitorowania lub modyfikowania żądań i odpowiedzi DNS.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security to framework dostarczany przez Apple w systemie macOS, który udostępnia zestaw API do zabezpieczania systemu. Jest przeznaczony dla **dostawców zabezpieczeń i deweloperów tworzących produkty mogące monitorować i kontrolować aktywność systemu**, aby wykrywać złośliwe działania i chronić przed nimi.

Framework ten udostępnia **zbiór API do monitorowania i kontrolowania aktywności systemu**, takiej jak uruchamianie procesów, zdarzenia systemu plików oraz zdarzenia sieciowe i zdarzenia jądra.

Główna część tego frameworka jest zaimplementowana w jądrze jako Kernel Extension (KEXT), znajdujące się w lokalizacji **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Ten KEXT składa się z kilku kluczowych komponentów:

- **EndpointSecurityDriver**: pełni funkcję „punktu wejścia” dla rozszerzenia jądra. Jest głównym punktem interakcji między systemem operacyjnym a frameworkiem Endpoint Security.
- **EndpointSecurityEventManager**: ten komponent odpowiada za implementację hooków jądra. Hooki jądra umożliwiają frameworkowi monitorowanie zdarzeń systemowych poprzez przechwytywanie wywołań systemowych.
- **EndpointSecurityClientManager**: zarządza komunikacją z klientami w przestrzeni użytkownika, śledząc, którzy klienci są połączeni i muszą otrzymywać powiadomienia o zdarzeniach.
- **EndpointSecurityMessageManager**: wysyła wiadomości i powiadomienia o zdarzeniach do klientów w przestrzeni użytkownika.

Zdarzenia, które może monitorować framework Endpoint Security, są podzielone na następujące kategorie:

- Zdarzenia plikowe
- Zdarzenia procesów
- Zdarzenia gniazd sieciowych
- Zdarzenia jądra, takie jak ładowanie i rozładowywanie rozszerzenia jądra lub otwieranie urządzenia I/O Kit

### Architektura Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Komunikacja w przestrzeni użytkownika** z frameworkiem Endpoint Security odbywa się za pośrednictwem klasy IOUserClient. W zależności od typu wywołującego używane są dwie różne klasy pochodne:

- **EndpointSecurityDriverClient**: wymaga entitlementu `com.apple.private.endpoint-security.manager`, który posiada wyłącznie systemowy proces `endpointsecurityd`.
- **EndpointSecurityExternalClient**: wymaga entitlementu `com.apple.developer.endpoint-security.client`. Zwykle jest używany przez zewnętrzne oprogramowanie zabezpieczające, które musi współpracować z frameworkiem Endpoint Security.<sup>[[1]](#references)</sup>

**Rozszerzenia Endpoint Security:** **`libEndpointSecurity.dylib`** to biblioteka C, której rozszerzenia systemowe używają do komunikacji z jądrem. Biblioteka ta wykorzystuje I/O Kit (`IOKit`) do komunikacji z KEXT Endpoint Security.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** to ważny demon systemowy zaangażowany w zarządzanie i uruchamianie systemowych rozszerzeń bezpieczeństwa punktów końcowych, szczególnie podczas wczesnego procesu rozruchu. **Tylko rozszerzenia systemowe** oznaczone w pliku `Info.plist` wartością **`NSEndpointSecurityEarlyBoot`** są obsługiwane podczas wczesnego rozruchu.<sup>[[2]](#references)</sup>

Inny demon systemowy, **`sysextd`**, **weryfikuje rozszerzenia systemowe** i przenosi je do właściwych lokalizacji systemowych. Następnie prosi odpowiedni demon o załadowanie rozszerzenia. Framework **`SystemExtensions.framework`** odpowiada za aktywowanie i dezaktywowanie rozszerzeń systemowych.<sup>[[2]](#references)</sup>

## Omijanie ESF

ESF jest używany przez narzędzia bezpieczeństwa, które próbują wykryć red teamera, dlatego wszelkie informacje o tym, jak można tego uniknąć, są interesujące.

### CVE-2021-30965

Problem polega na tym, że aplikacja zabezpieczająca musi posiadać uprawnienia **Full Disk Access**. Jeśli atakujący zdołałby je usunąć, mógłby uniemożliwić działanie tego oprogramowania:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
For **więcej informacji** o tym bypassie i powiązanych z nim bypassach sprawdź talk [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Ostatecznie zostało to naprawione przez nadanie nowego uprawnienia **`kTCCServiceEndpointSecurityClient`** aplikacji zabezpieczającej zarządzanej przez **`tccd`**, dzięki czemu `tccutil` nie będzie usuwać jej uprawnień, uniemożliwiając jej uruchomienie.<sup>[[3]](#references)</sup>

## Referencje

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
