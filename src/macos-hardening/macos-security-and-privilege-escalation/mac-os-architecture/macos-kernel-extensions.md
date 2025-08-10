# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Rozszerzenia jądra (Kexts) to **pakiety** z rozszerzeniem **`.kext`**, które są **ładowane bezpośrednio do przestrzeni jądra macOS**, zapewniając dodatkową funkcjonalność głównemu systemowi operacyjnemu.

### Status deprecacji & DriverKit / System Extensions
Począwszy od **macOS Catalina (10.15)**, Apple oznaczyło większość przestarzałych KPI jako *deprecated* i wprowadziło frameworki **System Extensions & DriverKit**, które działają w **przestrzeni użytkownika**. Od **macOS Big Sur (11)** system operacyjny *odmówi załadowania* kextów firm trzecich, które polegają na przestarzałych KPI, chyba że maszyna jest uruchomiona w trybie **Reduced Security**. Na Apple Silicon, włączenie kextów dodatkowo wymaga od użytkownika:

1. Uruchomienia ponownego w **Recovery** → *Startup Security Utility*.
2. Wybrania **Reduced Security** i zaznaczenia **„Zezwól użytkownikowi na zarządzanie rozszerzeniami jądra od zidentyfikowanych deweloperów”**.
3. Ponownego uruchomienia i zatwierdzenia kextu w **Ustawienia systemowe → Prywatność i bezpieczeństwo**.

Sterowniki w przestrzeni użytkownika napisane z użyciem DriverKit/System Extensions znacznie **zmniejszają powierzchnię ataku**, ponieważ awarie lub uszkodzenia pamięci są ograniczone do procesów w piaskownicy, a nie przestrzeni jądra.

> 📝 Od macOS Sequoia (15) Apple całkowicie usunęło kilka przestarzałych KPI dotyczących sieci i USB – jedynym rozwiązaniem zgodnym z przyszłością dla dostawców jest migracja do System Extensions.

### Wymagania

Oczywiście, jest to tak potężne, że **załadowanie rozszerzenia jądra** jest **skomplikowane**. Oto **wymagania**, które musi spełnić rozszerzenie jądra, aby mogło być załadowane:

- Podczas **wejścia w tryb odzyskiwania**, rozszerzenia jądra **muszą być dozwolone** do załadowania:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Rozszerzenie jądra musi być **podpisane certyfikatem podpisu kodu jądra**, który może być **przyznany tylko przez Apple**. Kto dokładnie przeanalizuje firmę i powody, dla których jest to potrzebne.
- Rozszerzenie jądra musi być również **notaryzowane**, Apple będzie mogło je sprawdzić pod kątem złośliwego oprogramowania.
- Następnie, użytkownik **root** jest tym, który może **załadować rozszerzenie jądra**, a pliki wewnątrz pakietu muszą **należeć do root**.
- Podczas procesu ładowania, pakiet musi być przygotowany w **chronionej lokalizacji nie-root**: `/Library/StagedExtensions` (wymaga przyznania `com.apple.rootless.storage.KernelExtensionManagement`).
- Na koniec, podczas próby załadowania, użytkownik [**otrzyma prośbę o potwierdzenie**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, jeśli zostanie zaakceptowana, komputer musi być **ponownie uruchomiony**, aby go załadować.

### Proces ładowania

W Catalina wyglądało to tak: Interesujące jest to, że proces **weryfikacji** odbywa się w **przestrzeni użytkownika**. Jednak tylko aplikacje z przyznaniem **`com.apple.private.security.kext-management`** mogą **zażądać od jądra załadowania rozszerzenia**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **rozpoczyna** proces **weryfikacji** ładowania rozszerzenia
- Będzie komunikować się z **`kextd`**, wysyłając za pomocą **usługi Mach**.
2. **`kextd`** sprawdzi kilka rzeczy, takich jak **podpis**
- Będzie komunikować się z **`syspolicyd`**, aby **sprawdzić**, czy rozszerzenie może być **załadowane**.
3. **`syspolicyd`** **poprosi** **użytkownika**, jeśli rozszerzenie nie zostało wcześniej załadowane.
- **`syspolicyd`** przekaże wynik do **`kextd`**
4. **`kextd`** w końcu będzie mógł **powiedzieć jądru, aby załadowało** rozszerzenie

Jeśli **`kextd`** nie jest dostępny, **`kextutil`** może przeprowadzić te same kontrole.

### Enumeracja i zarządzanie (załadowane kexty)

`kextstat` był historycznym narzędziem, ale jest **deprecated** w ostatnich wydaniach macOS. Nowoczesnym interfejsem jest **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Starsza składnia jest nadal dostępna do odniesienia:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` może być również wykorzystane do **zrzucenia zawartości Kolekcji Jądra (KC)** lub weryfikacji, że kext rozwiązuje wszystkie zależności symboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Mimo że rozszerzenia jądra powinny znajdować się w `/System/Library/Extensions/`, jeśli przejdziesz do tego folderu, **nie znajdziesz żadnego pliku binarnego**. Dzieje się tak z powodu **kernelcache** i aby odwrócić jeden `.kext`, musisz znaleźć sposób na jego uzyskanie.

**Kernelcache** to **wstępnie skompilowana i wstępnie połączona wersja jądra XNU**, wraz z niezbędnymi **sterownikami** i **rozszerzeniami jądra**. Jest przechowywana w formacie **skompresowanym** i dekompresowana do pamięci podczas procesu uruchamiania. Kernelcache ułatwia **szybszy czas uruchamiania**, mając gotową do uruchomienia wersję jądra i kluczowych sterowników, co zmniejsza czas i zasoby, które w przeciwnym razie byłyby wydawane na dynamiczne ładowanie i łączenie tych komponentów w czasie uruchamiania.

### Lokalny Kernelcache

W iOS znajduje się w **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, w macOS możesz go znaleźć za pomocą: **`find / -name "kernelcache" 2>/dev/null`** \
W moim przypadku w macOS znalazłem go w:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Format pliku IMG4 to format kontenera używany przez Apple w swoich urządzeniach iOS i macOS do bezpiecznego **przechowywania i weryfikowania komponentów oprogramowania układowego** (takich jak **kernelcache**). Format IMG4 zawiera nagłówek i kilka tagów, które kapsułkują różne fragmenty danych, w tym rzeczywisty ładunek (tak jak jądro lub bootloader), podpis oraz zestaw właściwości manifestu. Format wspiera weryfikację kryptograficzną, pozwalając urządzeniu potwierdzić autentyczność i integralność komponentu oprogramowania układowego przed jego wykonaniem.

Zwykle składa się z następujących komponentów:

- **Payload (IM4P)**:
- Często skompresowany (LZFSE4, LZSS, …)
- Opcjonalnie szyfrowany
- **Manifest (IM4M)**:
- Zawiera podpis
- Dodatkowy słownik klucz/wartość
- **Restore Info (IM4R)**:
- Znany również jako APNonce
- Zapobiega powtarzaniu niektórych aktualizacji
- OPCJONALNE: Zwykle to nie jest znalezione

Rozpakuj Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Pobierz

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

W [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) można znaleźć wszystkie zestawy debugowania jądra. Możesz je pobrać, zamontować, otworzyć za pomocą narzędzia [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), uzyskać dostęp do folderu **`.kext`** i **wyodrębnić go**.

Sprawdź to pod kątem symboli za pomocą:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Czasami Apple wydaje **kernelcache** z **symbolami**. Możesz pobrać niektóre firmware z symbolami, korzystając z linków na tych stronach. Firmware będzie zawierać **kernelcache** oraz inne pliki.

Aby **wyodrębnić** pliki, zacznij od zmiany rozszerzenia z `.ipsw` na `.zip` i **rozpakuj** go.

Po wyodrębnieniu firmware otrzymasz plik taki jak: **`kernelcache.release.iphone14`**. Jest w formacie **IMG4**, możesz wyodrębnić interesujące informacje za pomocą:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspekcja kernelcache

Sprawdź, czy kernelcache ma symbole z
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
## Ostatnie luki i techniki eksploatacji

| Rok | CVE | Podsumowanie |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Błąd logiczny w **`storagekitd`** pozwalał atakującemu *root* zarejestrować złośliwy pakiet systemu plików, który ostatecznie ładował **niesigned kext**, **omijając Ochronę Integralności Systemu (SIP)** i umożliwiając trwałe rootkity. Naprawione w macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Demon instalacyjny z uprawnieniem `com.apple.rootless.install` mógł być nadużyty do wykonywania dowolnych skryptów po instalacji, wyłączania SIP i ładowania dowolnych kextów.  |

**Wnioski dla zespołów red-team**

1. **Szukaj demonów z uprawnieniami (`codesign -dvv /path/bin | grep entitlements`), które współdziałają z Disk Arbitration, Installer lub Kext Management.**
2. **Nadużywanie omijania SIP prawie zawsze daje możliwość ładowania kextu → wykonanie kodu jądra**.

**Wskazówki obronne**

*Zachowaj włączone SIP*, monitoruj wywołania `kmutil load`/`kmutil create -n aux` pochodzące z nie-Apple binariów i alarmuj o jakimkolwiek zapisie do `/Library/Extensions`. Wydarzenia bezpieczeństwa punktów końcowych `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` zapewniają niemal rzeczywistą widoczność.

## Debugowanie jądra macOS i kextów

Zalecany przez Apple proces to zbudowanie **Kernel Debug Kit (KDK)**, który odpowiada działającej wersji, a następnie podłączenie **LLDB** przez sesję sieciową **KDP (Kernel Debugging Protocol)**.

### Jednorazowe lokalne debugowanie paniki
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Zdalne debugowanie na żywo z innego Maca

1. Pobierz i zainstaluj dokładną wersję **KDK** dla docelowej maszyny.
2. Podłącz docelowego Maca i Maca gospodarza za pomocą **kabelka USB-C lub Thunderbolt**.
3. Na **docelowym**:
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
### Podłączanie LLDB do konkretnego załadowanego kexta
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP udostępnia tylko interfejs **tylko do odczytu**. Aby uzyskać dynamiczną instrumentację, będziesz musiał zpatchować binarny plik na dysku, wykorzystać **hooking funkcji jądra** (np. `mach_override`) lub przenieść sterownik do **hypervisora** w celu pełnego odczytu/zapisu.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
