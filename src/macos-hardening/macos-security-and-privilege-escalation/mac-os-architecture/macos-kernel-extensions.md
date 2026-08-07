# Rozszerzenia kernela macOS i kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Kernel extensions (Kexts) to **pakiety** z rozszerzeniem **`.kext`**, które są **ładowane bezpośrednio do przestrzeni kernela macOS**, zapewniając dodatkowe funkcje głównemu systemowi operacyjnemu.

### Status deprecated oraz DriverKit / System Extensions
Począwszy od **macOS Catalina (10.15)** firma Apple oznaczyła większość starszych KPI jako *deprecated* i wprowadziła frameworki **System Extensions & DriverKit**, które działają w **user-space**. Od **macOS Big Sur (11)** system operacyjny będzie *odmawiał załadowania* zewnętrznych kexts korzystających z deprecated KPI, chyba że komputer zostanie uruchomiony w trybie **Reduced Security**. Na urządzeniach Apple Silicon włączenie kexts wymaga dodatkowo od użytkownika:

1. Uruchomienia ponownie komputera w trybie **Recovery** → *Startup Security Utility*.
2. Wybrania **Reduced Security** i zaznaczenia opcji **“Allow user management of kernel extensions from identified developers”**.
3. Ponownego uruchomienia komputera i zatwierdzenia kext w **System Settings → Privacy & Security**.

Drivery user-land napisane z użyciem DriverKit/System Extensions znacznie **zmniejszają attack surface**, ponieważ crashe lub memory corruption są ograniczone do procesu działającego w sandboxie, zamiast do przestrzeni kernela.<sup>[[1]](#references)</sup>

> 📝 Od macOS Sequoia (15) firma Apple całkowicie usunęła kilka starszych KPI dotyczących sieci i USB – jedynym rozwiązaniem zapewniającym kompatybilność w przyszłości jest migracja dostawców do System Extensions.

### Wymagania

Oczywiście jest to na tyle potężne rozwiązanie, że **załadowanie kernel extension jest skomplikowane**. Oto **wymagania**, które kernel extension musi spełniać, aby można było ją załadować:

- Podczas **uruchamiania w trybie recovery** kernel **extensions muszą mieć zezwolenie na ładowanie**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension musi być **podpisana certyfikatem kernel code signing**, który może zostać **przyznany wyłącznie przez firmę Apple**. Firma Apple szczegółowo sprawdzi firmę oraz powody, dla których certyfikat jest potrzebny.
- Kernel extension musi również być **notarized**; firma Apple będzie mogła sprawdzić ją pod kątem malware.
- Następnie użytkownik **root** jest jedynym użytkownikiem, który może **załadować kernel extension**, a pliki znajdujące się w pakiecie muszą **należeć do użytkownika root**.
- Podczas procesu upload pakiet musi zostać przygotowany w **chronionej lokalizacji non-root**: `/Library/StagedExtensions` (wymaga uprawnienia `com.apple.rootless.storage.KernelExtensionManagement`).
- Na koniec, podczas próby załadowania, użytkownik [**otrzyma żądanie potwierdzenia**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html), a po jego zaakceptowaniu komputer musi zostać **uruchomiony ponownie**, aby załadować kernel extension.

### Proces ładowania

W systemie Catalina wyglądało to następująco: Warto zauważyć, że proces **weryfikacji** odbywa się w userland. Jednak tylko aplikacje posiadające uprawnienie **`com.apple.private.security.kext-management`** mogą **zażądać od kernela załadowania extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **rozpoczyna** proces **weryfikacji** w celu załadowania extension
- Komunikuje się z **`kextd`**, wysyłając żądanie za pomocą **Mach service**.
2. **`kextd`** sprawdza kilka elementów, takich jak **podpis**
- Komunikuje się z **`syspolicyd`**, aby **sprawdzić**, czy extension może zostać **załadowana**.
3. **`syspolicyd`** wyświetli **monit** dla **użytkownika**, jeśli extension nie była wcześniej załadowana.
- **`syspolicyd`** przekaże wynik do **`kextd`**
4. **`kextd`** będzie mogło ostatecznie **przekazać kernelowi polecenie załadowania** extension

Jeśli **`kextd`** jest niedostępny, **`kextutil`** może wykonać te same kontrole.

### Enumeracja i zarządzanie (załadowane kexts)

`kextstat` było historycznym narzędziem, ale w nowszych wydaniach macOS jest **deprecated**. Nowoczesnym interfejsem jest **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Starsza składnia jest nadal dostępna jako odniesienie:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` można również wykorzystać do **zrzucenia zawartości Kernel Collection (KC)** lub sprawdzenia, czy kext rozwiązuje wszystkie zależności symboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Mimo że oczekuje się, że kernel extensions będą znajdować się w `/System/Library/Extensions/`, po przejściu do tego folderu **nie znajdziesz żadnego pliku binarnego**. Dzieje się tak z powodu **kernelcache**, a aby wykonać reverse engineering jednego pliku `.kext`, musisz znaleźć sposób na jego pozyskanie.

**kernelcache** to **wstępnie skompilowana i wstępnie połączona wersja kernela XNU**, wraz z niezbędnymi **driverami** urządzeń i **kernel extensions**. Jest przechowywany w formacie **skompresowanym** i dekompresowany w pamięci podczas procesu bootowania. Kernelcache umożliwia **szybsze bootowanie**, ponieważ gotowa do uruchomienia wersja kernela i kluczowych driverów jest dostępna od razu, co ogranicza czas i zasoby, które w przeciwnym razie zostałyby przeznaczone na dynamiczne ładowanie i łączenie tych komponentów podczas bootowania.

Główne zalety kernelcache to **szybkość ładowania** oraz to, że wszystkie moduły są prelinked (brak opóźnienia podczas ładowania). Ponadto po prelinkowaniu wszystkich modułów KXLD może zostać usunięty z pamięci, dzięki czemu **XNU nie może ładować nowych KEXT-ów.**

> [!TIP]
> Narzędzie [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) odszyfrowuje kontenery AEA (Apple Encrypted Archive / AEA asset) firmy Apple — zaszyfrowany format kontenera używany przez Apple dla assetów OTA i niektórych elementów IPSW — oraz może wygenerować znajdujące się wewnątrz archiwum `.dmg`/asset, które następnie można wypakować za pomocą dostarczonych narzędzi aastuff.


### Local Kerlnelcache

W iOS znajduje się w **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, natomiast w macOS można go znaleźć za pomocą: **`find / -name "kernelcache" 2>/dev/null`** \
W moim przypadku w macOS znalazłem go w:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Tutaj znajdziesz również [**kernelcache wersji 14 z symbolami**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### Skompresowany IMG4 / BVX2 (LZFSE)

Format pliku IMG4 to format kontenera używany przez Apple na urządzeniach iOS i macOS do bezpiecznego **przechowywania i weryfikowania komponentów firmware’u** (takich jak **kernelcache**). Format IMG4 zawiera nagłówek oraz kilka tagów, które enkapsulują różne elementy danych, w tym właściwy payload (taki jak kernel lub bootloader), sygnaturę oraz zestaw właściwości manifestu. Format obsługuje weryfikację kryptograficzną, umożliwiając urządzeniu potwierdzenie autentyczności i integralności komponentu firmware’u przed jego uruchomieniem.

Zwykle składa się z następujących komponentów:

- **Payload (IM4P)**:
- Często skompresowany (LZFSE4, LZSS, …)
- Opcjonalnie zaszyfrowany
- **Manifest (IM4M)**:
- Zawiera sygnaturę
- Dodatkowy słownik Key/Value
- **Restore Info (IM4R)**:
- Znany również jako APNonce
- Zapobiega replayowaniu niektórych aktualizacji
- OPCJONALNE: Zwykle nie jest znajdowany

Dekompresja Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Symbole `Disarm` dla kernela

**`Disarm`** pozwala symbolicate'ować funkcje z kernelcache przy użyciu matcherów. Matchery to po prostu proste reguły wzorców (wiersze tekstu), które informują disarm, jak rozpoznawać i automatycznie symbolicate'ować funkcje, argumenty oraz stringi panic/log wewnątrz binarnego pliku.

Zasadniczo wskazujesz string używany przez funkcję, a disarm go znajdzie i **symbolicate'uje**.

Niektóre `xnu.matchers` znajdziesz na stronie [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html), w sekcji **`Matchers`**. Możesz również tworzyć własne matchery.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Pobieranie

**IPSW (iPhone/iPad Software)** to format pakietu firmware firmy Apple używany do przywracania urządzeń, aktualizacji i pełnych pakietów firmware. Między innymi zawiera **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

W [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) można znaleźć wszystkie kernel debug kits. Możesz go pobrać, zamontować, otworzyć za pomocą narzędzia [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), przejść do folderu **`.kext`** i **wypakować go**.

Sprawdź symbole za pomocą:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Czasami Apple udostępnia **kernelcache** wraz z **symbols**. Możesz pobrać niektóre firmware’y z symbolami, korzystając z linków na tych stronach. Firmware’y będą zawierać między innymi **kernelcache**.

Aby **wyodrębnić** kernel cache, możesz użyć:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Inną opcją na **wyodrębnienie** plików jest rozpoczęcie od zmiany rozszerzenia z `.ipsw` na `.zip`, a następnie wykonanie **unzip**.

Po wypakowaniu firmware otrzymasz plik taki jak: **`kernelcache.release.iphone14`**. Jest on w formacie **IMG4**, a interesujące informacje możesz wyodrębnić za pomocą:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspekcja kernelcache

Sprawdź, czy kernelcache zawiera symbole za pomocą
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Dzięki temu możemy teraz **wyodrębnić wszystkie rozszerzenia** lub **to, które Cię interesuje:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Najnowsze podatności i techniki exploitation

| Rok | CVE | Podsumowanie |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Błąd logiczny w **`storagekitd`** pozwalał atakującemu z uprawnieniami *root* zarejestrować złośliwy bundle systemu plików, który ostatecznie ładował **niepodpisany kext**, **omijając System Integrity Protection (SIP)** i umożliwiając stosowanie trwałych rootkitów. Załatano w macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Daemon instalacyjny z entitlementem `com.apple.rootless.install` mógł zostać wykorzystany do wykonania dowolnych skryptów post-install, wyłączenia SIP i załadowania dowolnych kextów. <sup>[[3]](#references)</sup> |

**Wnioski dla red-teamerów**

1. **Szukaj daemonów z entitlementami (`codesign -dvv /path/bin | grep entitlements`), które współpracują z Disk Arbitration, Installer lub Kext Management.**
2. **Wykorzystanie obejść SIP niemal zawsze zapewnia możliwość załadowania kexta → wykonanie kodu w kernelu**.

**Wskazówki dotyczące obrony**

*Pozostaw SIP włączone*, monitoruj wywołania `kmutil load`/`kmutil create -n aux` pochodzące od binariów innych niż Apple i generuj alerty przy każdym zapisie do `/Library/Extensions`. Zdarzenia Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` zapewniają widoczność niemal w czasie rzeczywistym.

## Debugowanie kernela macOS i kextów

Zalecany przez Apple workflow polega na zbudowaniu **Kernel Debug Kit (KDK)** odpowiadającego uruchomionemu buildowi, a następnie podłączeniu **LLDB** przez sieciową sesję **KDP (Kernel Debugging Protocol)**.

### Jednorazowe lokalne debugowanie panicu
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Zdalne debugowanie na żywo z innego Maca

1. Pobierz i zainstaluj dokładnie tę samą wersję **KDK**, która jest używana na komputerze docelowym.
2. Połącz docelowego Maca z hostem Mac za pomocą **kabla USB-C lub Thunderbolt**.
3. Na **docelowym Macu**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Na **hoście**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Dołączanie LLDB do konkretnego załadowanego kexta
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️ KDP udostępnia wyłącznie interfejs **tylko do odczytu**. W przypadku dynamic instrumentation konieczne będzie spatchowanie pliku binarnego na dysku, wykorzystanie **kernel function hooking** (np. `mach_override`) lub przeniesienie sterownika do **hypervisora** w celu uzyskania pełnego odczytu/zapisu.

## Referencje

- [1] [Bezpieczeństwo DriverKit dla macOS - przewodnik Apple Platform Security](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analiza CVE-2024-44243, obejścia macOS System Integrity Protection przez kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft wykrywa nową lukę w macOS, Shrootless, która mogła ominąć System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
