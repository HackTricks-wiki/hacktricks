# Zabezpieczenia macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper jest zwykle używany jako określenie połączenia **Quarantine + Gatekeeper + XProtect** — 3 modułów bezpieczeństwa macOS, które próbują **uniemożliwić użytkownikom uruchamianie potencjalnie złośliwego oprogramowania pobranego** z Internetu.

Więcej informacji:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Ograniczenia procesów

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

macOS Sandbox **ogranicza aplikacje** uruchomione w sandboxie do **dozwolonych działań określonych w profilu Sandbox**, z którym uruchomiona jest aplikacja. Pomaga to zapewnić, że **aplikacja będzie uzyskiwać dostęp wyłącznie do oczekiwanych zasobów**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** to framework bezpieczeństwa. Został zaprojektowany do **zarządzania uprawnieniami** aplikacji, w szczególności przez regulowanie ich dostępu do wrażliwych funkcji. Obejmuje to takie elementy jak **usługi lokalizacyjne, kontakty, zdjęcia, mikrofon, kamera, ułatwienia dostępu i pełny dostęp do dysku**. TCC zapewnia, że aplikacje mogą uzyskiwać dostęp do tych funkcji dopiero po uzyskaniu wyraźnej zgody użytkownika, wzmacniając tym samym prywatność i kontrolę nad danymi osobowymi.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints w macOS to funkcja bezpieczeństwa służąca do **regulowania uruchamiania procesów** poprzez definiowanie, **kto może uruchomić** proces, **w jaki sposób** i **z jakiego miejsca**. Wprowadzono je w macOS Ventura, gdzie kategoryzują binaria systemowe w ramach kategorii ograniczeń w **trust cache**. Każdy wykonywalny plik binarny ma określone **reguły** dotyczące swojego **uruchamiania**, w tym ograniczenia **self**, **parent** i **responsible**. W macOS Sonoma rozszerzono te funkcje na aplikacje innych firm jako ograniczenia **Environment**. Pomagają one ograniczać potencjalne exploity systemu poprzez kontrolowanie warunków uruchamiania procesów.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) to kolejna część infrastruktury bezpieczeństwa macOS. Jak sugeruje nazwa, główną funkcją MRT jest **usuwanie znanego malware z zainfekowanych systemów**.

Po wykryciu malware na komputerze Mac — przez XProtect lub w inny sposób — MRT może zostać użyty do automatycznego **usunięcia malware**. MRT działa po cichu w tle i zwykle uruchamia się przy każdej aktualizacji systemu lub po pobraniu nowej definicji malware (wygląda na to, że reguły używane przez MRT do wykrywania malware znajdują się wewnątrz pliku binarnego).

Chociaż zarówno XProtect, jak i MRT są częścią mechanizmów bezpieczeństwa macOS, pełnią różne funkcje:

- **XProtect** jest narzędziem prewencyjnym. **Sprawdza pliki podczas ich pobierania** (za pośrednictwem określonych aplikacji), a jeśli wykryje znane rodzaje malware, **uniemożliwia otwarcie pliku**, zapobiegając tym samym zainfekowaniu systemu przez malware.
- **MRT** jest natomiast **narzędziem reaktywnym**. Działa po wykryciu malware w systemie, aby usunąć szkodliwe oprogramowanie i oczyścić system.

Aplikacja MRT znajduje się w **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Zarządzanie zadaniami w tle

**macOS** wyświetla teraz **alert** za każdym razem, gdy narzędzie używa dobrze znanej **techniki utrzymywania trwałego wykonywania kodu** (takiej jak Login Items, Daemons...), dzięki czemu użytkownik lepiej wie, **które oprogramowanie utrzymuje persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Działa to za pomocą **daemona** znajdującego się w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` oraz **agenta** w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Sposób, w jaki **`backgroundtaskmanagementd`** rozpoznaje, że coś zostało zainstalowane w folderze persistence, polega na **pobieraniu FSEvents** i tworzeniu dla nich pewnych **handlerów**.<sup>[[1]](#references)</sup>

Ponadto istnieje plik plist zawierający **dobrze znane aplikacje**, które często utrzymują persistence, zarządzany przez Apple i znajdujący się w: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeracja

Możliwe jest **wyliczenie wszystkich** skonfigurowanych elementów działających w tle za pomocą narzędzia Apple CLI:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ponadto informacje te można również wyświetlić za pomocą [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Informacje te są przechowywane w **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, a Terminal wymaga FDA.<sup>[[2]](#references)</sup>

### Manipulowanie BTM

Po wykryciu nowego persistence generowany jest event typu **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Zatem każdy sposób na **uniemożliwienie** wysłania tego **eventu** lub **powstrzymanie agenta przed wyświetleniem alertu** użytkownikowi pomoże atakującemu _**ominąć**_ BTM.<sup>[[1]](#references)</sup>

- **Resetowanie bazy danych**: Uruchomienie poniższego polecenia resetuje bazę danych (która powinna zostać odbudowana od zera). Jednak po wykonaniu tej czynności **nie pojawiają się żadne nowe alerty dotyczące persistence do czasu ponownego uruchomienia systemu**.<sup>[[1]](#references)</sup>
- Wymagany jest **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Zatrzymanie agenta**: Możliwe jest wysłanie do agenta sygnału zatrzymania, dzięki czemu **nie będzie on ostrzegał użytkownika** o znalezieniu nowych detekcji.<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**: Jeśli **proces, który utworzył persistence, natychmiast potem zakończy działanie**, daemon próbuje **uzyskać informacje** na jego temat, **nie udaje mu się to** i **nie może wysłać zdarzenia** informującego, że nowy element utrzymuje persistence.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: „Demistyfikacja (i obchodzenie) zarządzania zadaniami w tle w macOS” - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Nowe narzędzie (dla deweloperów): „DumpBTM” - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Zarządzanie elementami logowania i zadaniami w tle na Macu - wdrażanie platformy Apple](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
