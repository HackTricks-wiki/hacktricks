# Rozszerzenia systemowe macOS

{{#include ../../../banners/hacktricks-training.md}}

## Rozszerzenia systemowe / Endpoint Security Framework

W przeciwieństwie do **Kernel Extensions**, **System Extensions działają w przestrzeni użytkownika**, a nie w przestrzeni kernela, zmniejszając ryzyko awarii systemu spowodowanej nieprawidłowym działaniem rozszerzenia.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Istnieją trzy typy rozszerzeń systemowych: rozszerzenia **DriverKit**, **Network** oraz **Endpoint Security**.

### **Rozszerzenia DriverKit**

DriverKit jest zamiennikiem rozszerzeń kernela, które **zapewniają obsługę sprzętu**. Umożliwia sterownikom urządzeń (takim jak sterowniki USB, Serial, NIC i HID) działanie w przestrzeni użytkownika zamiast w przestrzeni kernela. Framework DriverKit zawiera **wersje niektórych klas I/O Kit działające w przestrzeni użytkownika**, a kernel przekazuje standardowe zdarzenia I/O Kit do przestrzeni użytkownika, zapewniając bezpieczniejsze środowisko dla działania tych sterowników.<sup>[[2]](#references)</sup>

### **Rozszerzenia Network**

Network Extensions umożliwiają dostosowywanie zachowania sieci. Istnieje kilka typów Network Extensions:

- **App Proxy**: służy do tworzenia klienta VPN implementującego niestandardowy, zorientowany na przepływy protokół VPN. Oznacza to, że obsługuje ruch sieciowy na podstawie połączeń (lub przepływów), a nie pojedynczych pakietów.
- **Packet Tunnel**: służy do tworzenia klienta VPN implementującego niestandardowy, zorientowany na pakiety protokół VPN. Oznacza to, że obsługuje ruch sieciowy na podstawie pojedynczych pakietów.
- **Filter Data**: służy do filtrowania sieciowych „przepływów”. Może monitorować lub modyfikować dane sieciowe na poziomie przepływu.
- **Filter Packet**: służy do filtrowania pojedynczych pakietów sieciowych. Może monitorować lub modyfikować dane sieciowe na poziomie pakietu.
- **DNS Proxy**: służy do tworzenia niestandardowego dostawcy DNS. Może służyć do monitorowania lub modyfikowania żądań i odpowiedzi DNS.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security jest frameworkiem udostępnianym przez Apple w systemie macOS, który zapewnia zestaw API do zabezpieczeń systemu. Jest przeznaczony dla **dostawców zabezpieczeń i developerów do tworzenia produktów, które mogą monitorować i kontrolować aktywność systemu**, aby identyfikować złośliwą aktywność i chronić przed nią.

Framework ten zapewnia **zbiór API do monitorowania i kontrolowania aktywności systemu**, takich jak wykonywanie procesów, zdarzenia systemu plików oraz zdarzenia sieciowe i kernela.

Podstawowa część tego frameworka jest zaimplementowana w kernelu jako Kernel Extension (KEXT) znajdujący się w **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Ten KEXT składa się z kilku kluczowych komponentów:

- **EndpointSecurityDriver**: działa jako „punkt wejścia” dla rozszerzenia kernela. Jest głównym punktem interakcji między systemem operacyjnym a frameworkiem Endpoint Security.
- **EndpointSecurityEventManager**: ten komponent odpowiada za implementację kernel hooks. Kernel hooks umożliwiają frameworkowi monitorowanie zdarzeń systemowych poprzez przechwytywanie wywołań systemowych.
- **EndpointSecurityClientManager**: zarządza komunikacją z klientami w przestrzeni użytkownika, śledząc, którzy klienci są połączeni i muszą otrzymywać powiadomienia o zdarzeniach.
- **EndpointSecurityMessageManager**: wysyła wiadomości i powiadomienia o zdarzeniach do klientów w przestrzeni użytkownika.

Zdarzenia, które może monitorować framework Endpoint Security, są podzielone na następujące kategorie:

- Zdarzenia dotyczące plików
- Zdarzenia dotyczące procesów
- Zdarzenia dotyczące socketów
- Zdarzenia kernela (takie jak ładowanie/wyładowywanie rozszerzenia kernela lub otwieranie urządzenia I/O Kit)

### Architektura Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Komunikacja z przestrzeni użytkownika** z frameworkiem Endpoint Security odbywa się za pośrednictwem klasy IOUserClient. W zależności od typu wywołującego używane są dwie różne podklasy:

- **EndpointSecurityDriverClient**: wymaga entitlementu `com.apple.private.endpoint-security.manager`, który posiada wyłącznie proces systemowy `endpointsecurityd`.
- **EndpointSecurityExternalClient**: wymaga entitlementu `com.apple.developer.endpoint-security.client`. Zwykle używałoby go zewnętrzne oprogramowanie zabezpieczające, które musi komunikować się z frameworkiem Endpoint Security.<sup>[[1]](#references)</sup>

**Rozszerzenia Endpoint Security:** **`libEndpointSecurity.dylib`** to biblioteka C, której system extensions używają do komunikacji z kernelem. Biblioteka ta wykorzystuje I/O Kit (`IOKit`) do komunikacji z KEXT Endpoint Security.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** jest kluczowym daemonem systemowym zaangażowanym w zarządzanie i uruchamianie system extensions związanych z endpoint security, szczególnie podczas wczesnego procesu bootowania. **Tylko system extensions** oznaczone wartością **`NSEndpointSecurityEarlyBoot`** w pliku `Info.plist` otrzymują takie traktowanie podczas early boot.<sup>[[2]](#references)</sup>

Inny daemon systemowy, **`sysextd`**, **weryfikuje system extensions** i przenosi je do właściwych lokalizacji systemowych. Następnie prosi odpowiedni daemon o załadowanie rozszerzenia. Framework **`SystemExtensions.framework`** odpowiada za aktywowanie i dezaktywowanie system extensions.<sup>[[2]](#references)</sup>

## Omijanie ESF

ESF jest używany przez narzędzia zabezpieczające, które będą próbowały wykryć red teamera, dlatego wszelkie informacje o tym, jak można tego uniknąć, są interesujące.

### CVE-2021-30965

Problem polega na tym, że aplikacja zabezpieczająca musi mieć **uprawnienia Full Disk Access**. Jeśli atakujący mógłby je usunąć, mógłby uniemożliwić działanie oprogramowania:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Aby uzyskać **więcej informacji** o tym bypassie i powiązanych z nim bypassach, sprawdź wystąpienie [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup>

Ostatecznie naprawiono to, nadając nowe uprawnienie **`kTCCServiceEndpointSecurityClient`** aplikacji zabezpieczającej zarządzanej przez **`tccd`**, dzięki czemu `tccutil` nie będzie usuwać jej uprawnień, uniemożliwiając jej uruchomienie.<sup>[[3]](#references)</sup>

## References

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
