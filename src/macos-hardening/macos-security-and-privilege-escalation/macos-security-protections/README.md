# Ochrony bezpieczeństwa macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper zazwyczaj odnosi się do kombinacji **Quarantine + Gatekeeper + XProtect**, 3 modułów zabezpieczeń macOS, które będą próbować **zapobiec użytkownikom w uruchamianiu potencjalnie złośliwego oprogramowania pobranego**.

Więcej informacji w:

{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Ograniczenia procesów

### MACF

### SIP - Ochrona integralności systemu

{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **ogranicza aplikacje** działające w piaskownicy do **dozwolonych działań określonych w profilu Sandbox**, z którym działa aplikacja. Pomaga to zapewnić, że **aplikacja będzie miała dostęp tylko do oczekiwanych zasobów**.

{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Przejrzystość, Zgoda i Kontrola**

**TCC (Przejrzystość, Zgoda i Kontrola)** to ramy zabezpieczeń. Zostały zaprojektowane, aby **zarządzać uprawnieniami** aplikacji, szczególnie poprzez regulowanie ich dostępu do wrażliwych funkcji. Obejmuje to elementy takie jak **usługi lokalizacji, kontakty, zdjęcia, mikrofon, kamera, dostępność i pełny dostęp do dysku**. TCC zapewnia, że aplikacje mogą uzyskać dostęp do tych funkcji tylko po uzyskaniu wyraźnej zgody użytkownika, co wzmacnia prywatność i kontrolę nad danymi osobowymi.

{{#ref}}
macos-tcc/
{{#endref}}

### Ograniczenia uruchamiania/środowiska i pamięć podręczna zaufania

Ograniczenia uruchamiania w macOS to funkcja zabezpieczeń, która **reguluje inicjację procesów** poprzez definiowanie **kto może uruchomić** proces, **jak** i **skąd**. Wprowadzona w macOS Ventura, klasyfikuje binaria systemowe w kategorie ograniczeń w **pamięci podręcznej zaufania**. Każdy wykonywalny plik binarny ma ustalone **zasady** dotyczące swojego **uruchamiania**, w tym **własne**, **rodzica** i **odpowiedzialne** ograniczenia. Rozszerzone na aplikacje innych firm jako **Ograniczenia Środowiska** w macOS Sonoma, te funkcje pomagają łagodzić potencjalne wykorzystania systemu poprzez regulowanie warunków uruchamiania procesów.

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Narzędzie do usuwania złośliwego oprogramowania

Narzędzie do usuwania złośliwego oprogramowania (MRT) jest kolejną częścią infrastruktury zabezpieczeń macOS. Jak sama nazwa wskazuje, główną funkcją MRT jest **usuwanie znanego złośliwego oprogramowania z zainfekowanych systemów**.

Gdy złośliwe oprogramowanie zostanie wykryte na Macu (czy to przez XProtect, czy w inny sposób), MRT może być używane do automatycznego **usunięcia złośliwego oprogramowania**. MRT działa cicho w tle i zazwyczaj uruchamia się, gdy system jest aktualizowany lub gdy pobierana jest nowa definicja złośliwego oprogramowania (wygląda na to, że zasady, które MRT ma do wykrywania złośliwego oprogramowania, są wewnątrz binarnego pliku).

Chociaż zarówno XProtect, jak i MRT są częścią środków zabezpieczeń macOS, pełnią różne funkcje:

- **XProtect** jest narzędziem zapobiegawczym. **Sprawdza pliki w momencie ich pobierania** (za pośrednictwem niektórych aplikacji), a jeśli wykryje jakiekolwiek znane rodzaje złośliwego oprogramowania, **zapobiega otwarciu pliku**, tym samym zapobiegając infekcji systemu przez złośliwe oprogramowanie.
- **MRT**, z drugiej strony, jest **narzędziem reaktywnym**. Działa po wykryciu złośliwego oprogramowania w systemie, mając na celu usunięcie szkodliwego oprogramowania w celu oczyszczenia systemu.

Aplikacja MRT znajduje się w **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Zarządzanie zadaniami w tle

**macOS** teraz **powiadamia** za każdym razem, gdy narzędzie używa znanej **techniki do utrzymywania wykonania kodu** (takiej jak elementy logowania, demony...), aby użytkownik lepiej wiedział **które oprogramowanie się utrzymuje**.

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Działa to z **demonem** znajdującym się w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` oraz **agentem** w `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Sposób, w jaki **`backgroundtaskmanagementd`** wie, że coś jest zainstalowane w folderze persistent, polega na **uzyskaniu FSEvents** i utworzeniu kilku **handlerów** dla nich.

Ponadto istnieje plik plist, który zawiera **znane aplikacje**, które często się utrzymują, zarządzany przez Apple, znajdujący się w: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

Możliwe jest **wyliczenie wszystkich** skonfigurowanych elementów w tle za pomocą narzędzia Apple cli:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ponadto możliwe jest również wylistowanie tych informacji za pomocą [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Te informacje są przechowywane w **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** i Terminal potrzebuje FDA.

### Manipulowanie BTM

Gdy zostanie znalezione nowe utrwalenie, występuje zdarzenie typu **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Zatem wszelkie sposoby na **zapobieżenie** wysłaniu tego **zdarzenia** lub **powiadomieniu** użytkownika przez **agenta** pomogą atakującemu w _**obejściu**_ BTM.

- **Resetowanie bazy danych**: Uruchomienie następującego polecenia zresetuje bazę danych (powinno odbudować ją od podstaw), jednak z jakiegoś powodu, po uruchomieniu tego, **żadne nowe utrwalenie nie będzie zgłaszane, dopóki system nie zostanie ponownie uruchomiony**.
- Wymagany jest **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Zatrzymaj Agenta**: Możliwe jest wysłanie sygnału zatrzymania do agenta, aby **nie informował użytkownika** o nowych wykryciach.
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
- **Błąd**: Jeśli **proces, który stworzył persistencję, istnieje szybko po nim**, demon spróbuje **uzyskać informacje** na jego temat, **nie powiedzie się** i **nie będzie w stanie wysłać zdarzenia** wskazującego, że nowa rzecz jest persistowana.

Referencje i **więcej informacji o BTM**:

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
