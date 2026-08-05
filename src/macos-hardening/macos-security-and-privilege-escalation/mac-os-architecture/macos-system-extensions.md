# Rozszerzenia systemowe macOS

{{#include ../../../banners/hacktricks-training.md}}

## Rozszerzenia systemowe / Endpoint Security Framework

W przeciwieństwie do **Kernel Extensions**, **System Extensions działają w przestrzeni użytkownika**, a nie w przestrzeni kernela, zmniejszając ryzyko awarii systemu spowodowanej nieprawidłowym działaniem rozszerzenia.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Istnieją trzy typy rozszerzeń systemowych: rozszerzenia **DriverKit**, rozszerzenia **Network** oraz rozszerzenia **Endpoint Security**.

### **Rozszerzenia DriverKit**

DriverKit zastępuje rozszerzenia kernela, które **zapewniają obsługę sprzętu**. Umożliwia uruchamianie sterowników urządzeń, takich jak sterowniki USB, portów szeregowych, kart sieciowych (NIC) i HID, w przestrzeni użytkownika zamiast w przestrzeni kernela. Framework DriverKit zawiera **wersje niektórych klas I/O Kit działające w przestrzeni użytkownika**, a kernel przekazuje standardowe zdarzenia I/O Kit do przestrzeni użytkownika, zapewniając bezpieczniejsze środowisko działania tych sterowników.<sup>[2]</sup>

### **Rozszerzenia Network**

Rozszerzenia Network umożliwiają dostosowywanie zachowania sieci. Istnieje kilka typów rozszerzeń Network:

- **App Proxy**: służy do tworzenia klienta VPN implementującego niestandardowy protokół VPN zorientowany na przepływy. Oznacza to, że obsługuje ruch sieciowy na podstawie połączeń (lub przepływów), a nie pojedynczych pakietów.
- **Packet Tunnel**: służy do tworzenia klienta VPN implementującego niestandardowy protokół VPN zorientowany na pakiety. Oznacza to, że obsługuje ruch sieciowy na podstawie pojedynczych pakietów.
- **Filter Data**: służy do filtrowania sieciowych „przepływów”. Może monitorować dane sieciowe na poziomie przepływu lub je modyfikować.
- **Filter Packet**: służy do filtrowania pojedynczych pakietów sieciowych. Może monitorować dane sieciowe na poziomie pakietów lub je modyfikować.
- **DNS Proxy**: służy do tworzenia niestandardowego dostawcy DNS. Może monitorować żądania i odpowiedzi DNS lub je modyfikować.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security to framework dostarczany przez Apple w systemie macOS, który udostępnia zestaw API do zapewniania bezpieczeństwa systemu. Jest przeznaczony dla **dostawców zabezpieczeń i developerów do tworzenia produktów, które mogą monitorować i kontrolować aktywność systemu**, aby wykrywać złośliwą aktywność i chronić przed nią.

Framework ten udostępnia **zestaw API do monitorowania i kontrolowania aktywności systemu**, takich jak wykonywanie procesów, zdarzenia systemu plików oraz zdarzenia sieciowe i kernela.

Rdzeń tego frameworka jest zaimplementowany w kernelu jako Kernel Extension (KEXT) znajdujący się w **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> Ten KEXT składa się z kilku kluczowych komponentów:

- **EndpointSecurityDriver**: działa jako „punkt wejścia” dla rozszerzenia kernela. Jest głównym punktem interakcji między systemem operacyjnym a frameworkiem Endpoint Security.
- **EndpointSecurityEventManager**: komponent odpowiedzialny za implementowanie hooków kernela. Hooki kernela umożliwiają frameworkowi monitorowanie zdarzeń systemowych poprzez przechwytywanie wywołań systemowych.
- **EndpointSecurityClientManager**: zarządza komunikacją z klientami w przestrzeni użytkownika, śledząc, którzy klienci są połączeni i muszą otrzymywać powiadomienia o zdarzeniach.
- **EndpointSecurityMessageManager**: wysyła wiadomości i powiadomienia o zdarzeniach do klientów w przestrzeni użytkownika.

Zdarzenia, które może monitorować framework Endpoint Security, są podzielone na następujące kategorie:

- Zdarzenia plikowe
- Zdarzenia procesów
- Zdarzenia gniazd
- Zdarzenia kernela (takie jak ładowanie/wyładowywanie rozszerzenia kernela lub otwieranie urządzenia I/O Kit)

### Architektura Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Komunikacja z przestrzeni użytkownika** z frameworkiem Endpoint Security odbywa się za pośrednictwem klasy IOUserClient. Używane są dwie różne podklasy, zależnie od typu wywołującego:

- **EndpointSecurityDriverClient**: wymaga entitlementu `com.apple.private.endpoint-security.manager`, który posiada wyłącznie proces systemowy `endpointsecurityd`.
- **EndpointSecurityExternalClient**: wymaga entitlementu `com.apple.developer.endpoint-security.client`. Zwykle korzysta z niego oprogramowanie zabezpieczające firm trzecich, które musi współdziałać z frameworkiem Endpoint Security.<sup>[1]</sup>

Rozszerzenia Endpoint Security:**`libEndpointSecurity.dylib`** to biblioteka C, której rozszerzenia systemowe używają do komunikacji z kernelem. Biblioteka ta wykorzystuje I/O Kit (`IOKit`) do komunikacji z KEXT Endpoint Security.<sup>[2]</sup>

**`endpointsecurityd`** to kluczowy demon systemowy odpowiedzialny za zarządzanie rozszerzeniami systemowymi bezpieczeństwa endpointów i ich uruchamianie, szczególnie podczas wczesnego procesu bootowania. **Tylko rozszerzenia systemowe** oznaczone w pliku **`Info.plist`** wartością **`NSEndpointSecurityEarlyBoot`** otrzymują takie traktowanie podczas wczesnego bootowania.<sup>[2]</sup>

Inny demon systemowy, **`sysextd`**, **weryfikuje rozszerzenia systemowe** i przenosi je do właściwych lokalizacji systemowych. Następnie prosi odpowiedni demon o załadowanie rozszerzenia. Framework **`SystemExtensions.framework`** odpowiada za aktywowanie i dezaktywowanie rozszerzeń systemowych.<sup>[2]</sup>

## Omijanie ESF

ESF jest używany przez narzędzia bezpieczeństwa, które będą próbowały wykryć red teamera, więc wszelkie informacje o tym, jak można tego uniknąć, brzmią interesująco.

### CVE-2021-30965

Problem polega na tym, że aplikacja zabezpieczająca musi mieć **uprawnienia Full Disk Access**. Jeśli attacker mógłby je usunąć, mógłby uniemożliwić działanie oprogramowania:<sup>[3]</sup>
```bash
tccutil reset All
```
Aby uzyskać **więcej informacji** o tym bypassie i powiązanych z nim bypassach, zobacz prelekcję [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Ostatecznie naprawiono ten problem, nadając nowe uprawnienie **`kTCCServiceEndpointSecurityClient`** aplikacji security zarządzanej przez **`tccd`**, dzięki czemu `tccutil` nie będzie usuwać jej uprawnień i uniemożliwiać jej uruchomienia.<sup>[3]</sup>

## Referencje

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
