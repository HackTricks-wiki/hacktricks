# Zabezpieczenia macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper zwykle odnosi się do połączenia **Quarantine + Gatekeeper + XProtect** — 3 modułów bezpieczeństwa macOS, które próbują **uniemożliwić użytkownikom uruchamianie potencjalnie złośliwego oprogramowania pobranego** z Internetu.

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

Sandbox w MacOS **ogranicza aplikacje** uruchomione wewnątrz sandboxa do **dozwolonych działań określonych w profilu Sandbox**, z którym aplikacja jest uruchamiana. Pomaga to zapewnić, że **aplikacja będzie uzyskiwać dostęp wyłącznie do oczekiwanych zasobów**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** to framework bezpieczeństwa. Jest przeznaczony do **zarządzania uprawnieniami** aplikacji, w szczególności poprzez regulowanie ich dostępu do wrażliwych funkcji. Obejmuje to takie elementy jak **usługi lokalizacyjne, kontakty, zdjęcia, mikrofon, kamera, ułatwienia dostępu oraz pełny dostęp do dysku**. TCC zapewnia, że aplikacje mogą uzyskiwać dostęp do tych funkcji dopiero po uzyskaniu wyraźnej zgody użytkownika, wzmacniając tym samym prywatność i kontrolę nad danymi osobowymi.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints w macOS to funkcja bezpieczeństwa służąca do **regulowania uruchamiania procesów** poprzez określanie, **kto może uruchomić** proces, **w jaki sposób** i **z jakiego miejsca**. Wprowadzona w macOS Ventura, kategoryzuje binaria systemowe według kategorii ograniczeń w obrębie **trust cache**. Każdy wykonywalny binarny plik ma zestaw **reguł** dotyczących jego **uruchamiania**, obejmujących ograniczenia **self**, **parent** i **responsible**. Rozszerzone na aplikacje innych firm jako ograniczenia **Environment** w macOS Sonoma, funkcje te pomagają ograniczać potencjalne exploitacje systemu poprzez regulowanie warunków uruchamiania procesów.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) to kolejna część infrastruktury bezpieczeństwa macOS. Jak wskazuje nazwa, główną funkcją MRT jest **usuwanie znanego malware z zainfekowanych systemów**.

Po wykryciu malware na Macu (przez XProtect lub w inny sposób) MRT może zostać użyty do automatycznego **usunięcia malware**. MRT działa cicho w tle i zazwyczaj jest uruchamiany podczas aktualizacji systemu lub pobierania nowej definicji malware (wygląda na to, że reguły używane przez MRT do wykrywania malware znajdują się wewnątrz binarnego pliku).

Chociaż zarówno XProtect, jak i MRT są częścią zabezpieczeń macOS, pełnią różne funkcje:

- **XProtect** to narzędzie prewencyjne. **Sprawdza pliki podczas ich pobierania** (za pośrednictwem określonych aplikacji), a jeśli wykryje znane typy malware, **uniemożliwia otwarcie pliku**, zapobiegając tym samym zainfekowaniu systemu przez malware.
- **MRT** jest natomiast **narzędziem reaktywnym**. Działa po wykryciu malware w systemie, a jego celem jest usunięcie szkodliwego oprogramowania i oczyszczenie systemu.

Aplikacja MRT znajduje się w **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Zarządzanie zadaniami w tle

**macOS** wyświetla teraz **alert** za każdym razem, gdy narzędzie używa dobrze znanej **techniki utrwalania wykonywania kodu** (takiej jak Login Items, Daemons...), dzięki czemu użytkownik lepiej wie, **które oprogramowanie utrwala swoją obecność**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Działa to za pośrednictwem **daemon** znajdującego się w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` oraz **agenta** w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Sposób, w jaki **`backgroundtaskmanagementd`** wie, że coś zostało zainstalowane w folderze używanym do persistence, polega na **pobieraniu zdarzeń FSEvents** i tworzeniu dla nich pewnych **handlerów**.<sup>[[1]](#references)</sup>

Ponadto istnieje plik plist zawierający **dobrze znane aplikacje**, które często utrwalają swoją obecność; jest on utrzymywany przez Apple i znajduje się w: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Możliwe jest **wyliczenie wszystkich** skonfigurowanych elementów działających w tle za pomocą narzędzia CLI firmy Apple:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ponadto można również wyświetlić te informacje za pomocą [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Te informacje są przechowywane w **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, a Terminal wymaga FDA.<sup>[[2]](#references)</sup>

### Manipulowanie BTM

Po wykryciu nowej persistence generowane jest zdarzenie typu **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Zatem każdy sposób na **uniemożliwienie** wysłania tego **zdarzenia** lub **powstrzymanie agenta przed ostrzeżeniem** użytkownika pomoże attackerowi **_ominąć_** BTM.<sup>[[1]](#references)</sup>

- **Resetowanie bazy danych**: Uruchomienie poniższego polecenia zresetuje bazę danych (powinno odbudować ją od podstaw), jednak z jakiegoś powodu po jego wykonaniu **żadna nowa persistence nie będzie zgłaszana do momentu ponownego uruchomienia systemu**.<sup>[[1]](#references)</sup>
- Wymagany jest **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Zatrzymanie agenta**: Możliwe jest wysłanie do agenta sygnału zatrzymania, dzięki czemu **nie będzie on ostrzegał użytkownika**, gdy zostaną wykryte nowe zagrożenia.<sup>[[1]](#references)</sup>
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
- **Bug**: Jeśli **proces, który utworzył persistence, zakończy działanie natychmiast po jego utworzeniu**, daemon spróbuje uzyskać **informacje** na jego temat, **nie powiedzie się**, a następnie **nie będzie w stanie wysłać zdarzenia** informującego o tym, że nowy element uzyskał persistence.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
