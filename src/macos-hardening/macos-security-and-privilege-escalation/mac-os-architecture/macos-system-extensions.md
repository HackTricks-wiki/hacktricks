# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

W przeciwieństwie do Kernel Extensions, **System Extensions działają w przestrzeni użytkownika** zamiast w przestrzeni jądra, co zmniejsza ryzyko awarii systemu z powodu awarii rozszerzenia.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Istnieją trzy typy rozszerzeń systemowych: **DriverKit** Extensions, **Network** Extensions i **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit jest zamiennikiem dla rozszerzeń jądra, które **zapewniają wsparcie sprzętowe**. Umożliwia to działanie sterowników urządzeń (takich jak sterowniki USB, Serial, NIC i HID) w przestrzeni użytkownika zamiast w przestrzeni jądra. Framework DriverKit zawiera **wersje w przestrzeni użytkownika niektórych klas I/O Kit**, a jądro przekazuje normalne zdarzenia I/O Kit do przestrzeni użytkownika, oferując bezpieczniejsze środowisko dla tych sterowników.

### **Network Extensions**

Network Extensions zapewniają możliwość dostosowania zachowań sieciowych. Istnieje kilka typów Network Extensions:

- **App Proxy**: Używane do tworzenia klienta VPN, który implementuje protokół VPN oparty na przepływie. Oznacza to, że obsługuje ruch sieciowy na podstawie połączeń (lub przepływów) zamiast pojedynczych pakietów.
- **Packet Tunnel**: Używane do tworzenia klienta VPN, który implementuje protokół VPN oparty na pakietach. Oznacza to, że obsługuje ruch sieciowy na podstawie pojedynczych pakietów.
- **Filter Data**: Używane do filtrowania "przepływów" sieciowych. Może monitorować lub modyfikować dane sieciowe na poziomie przepływu.
- **Filter Packet**: Używane do filtrowania pojedynczych pakietów sieciowych. Może monitorować lub modyfikować dane sieciowe na poziomie pakietu.
- **DNS Proxy**: Używane do tworzenia niestandardowego dostawcy DNS. Może być używane do monitorowania lub modyfikowania zapytań i odpowiedzi DNS.

## Endpoint Security Framework

Endpoint Security to framework dostarczany przez Apple w macOS, który zapewnia zestaw API do zabezpieczeń systemowych. Jest przeznaczony do użytku przez **dostawców zabezpieczeń i deweloperów do budowania produktów, które mogą monitorować i kontrolować aktywność systemu** w celu identyfikacji i ochrony przed złośliwą działalnością.

Framework ten zapewnia **zbiór API do monitorowania i kontrolowania aktywności systemu**, takich jak wykonywanie procesów, zdarzenia systemu plików, zdarzenia sieciowe i jądra.

Rdzeń tego frameworka jest zaimplementowany w jądrze, jako Kernel Extension (KEXT) znajdujący się w **`/System/Library/Extensions/EndpointSecurity.kext`**. Ten KEXT składa się z kilku kluczowych komponentów:

- **EndpointSecurityDriver**: Działa jako "punkt wejścia" dla rozszerzenia jądra. Jest głównym punktem interakcji między systemem operacyjnym a frameworkiem Endpoint Security.
- **EndpointSecurityEventManager**: Ten komponent jest odpowiedzialny za implementację haków jądra. Haki jądra pozwalają frameworkowi monitorować zdarzenia systemowe poprzez przechwytywanie wywołań systemowych.
- **EndpointSecurityClientManager**: Zarządza komunikacją z klientami w przestrzeni użytkownika, śledząc, którzy klienci są połączeni i muszą otrzymywać powiadomienia o zdarzeniach.
- **EndpointSecurityMessageManager**: Wysyła wiadomości i powiadomienia o zdarzeniach do klientów w przestrzeni użytkownika.

Zdarzenia, które framework Endpoint Security może monitorować, są klasyfikowane na:

- Zdarzenia plików
- Zdarzenia procesów
- Zdarzenia gniazd
- Zdarzenia jądra (takie jak ładowanie/odładowanie rozszerzenia jądra lub otwieranie urządzenia I/O Kit)

### Architektura Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Komunikacja w przestrzeni użytkownika** z frameworkiem Endpoint Security odbywa się za pośrednictwem klasy IOUserClient. Używane są dwie różne podklasy, w zależności od typu wywołującego:

- **EndpointSecurityDriverClient**: Wymaga uprawnienia `com.apple.private.endpoint-security.manager`, które posiada tylko proces systemowy `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Wymaga uprawnienia `com.apple.developer.endpoint-security.client`. Zwykle byłoby to używane przez oprogramowanie zabezpieczające firm trzecich, które musi współdziałać z frameworkiem Endpoint Security.

Rozszerzenia Endpoint Security:**`libEndpointSecurity.dylib`** to biblioteka C, której używają rozszerzenia systemowe do komunikacji z jądrem. Ta biblioteka wykorzystuje I/O Kit (`IOKit`) do komunikacji z KEXT Endpoint Security.

**`endpointsecurityd`** to kluczowy demon systemowy zaangażowany w zarządzanie i uruchamianie rozszerzeń systemowych zabezpieczeń punktów końcowych, szczególnie podczas wczesnego procesu rozruchu. **Tylko rozszerzenia systemowe** oznaczone jako **`NSEndpointSecurityEarlyBoot`** w ich pliku `Info.plist` otrzymują tę wczesną obsługę rozruchu.

Inny demon systemowy, **`sysextd`**, **waliduje rozszerzenia systemowe** i przenosi je do odpowiednich lokalizacji systemowych. Następnie prosi odpowiedni demon o załadowanie rozszerzenia. **`SystemExtensions.framework`** jest odpowiedzialny za aktywację i dezaktywację rozszerzeń systemowych.

## Obejście ESF

ESF jest używane przez narzędzia zabezpieczające, które będą próbować wykryć red teamera, więc wszelkie informacje na temat tego, jak można to obejść, są interesujące.

### CVE-2021-30965

Problem polega na tym, że aplikacja zabezpieczająca musi mieć **uprawnienia do pełnego dostępu do dysku**. Jeśli więc atakujący mógłby to usunąć, mógłby zapobiec uruchomieniu oprogramowania:
```bash
tccutil reset All
```
Aby uzyskać **więcej informacji** na temat tego obejścia i pokrewnych, sprawdź wykład [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Na koniec naprawiono to, przyznając nową uprawnienie **`kTCCServiceEndpointSecurityClient`** aplikacji zabezpieczającej zarządzanej przez **`tccd`**, dzięki czemu `tccutil` nie usunie jej uprawnień, co uniemożliwi jej działanie.

## Referencje

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
