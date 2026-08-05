# Rozszerzenia jądra macOS i Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Rozszerzenia jądra (Kexts) to **pakiety** z rozszerzeniem **`.kext`**, które są **ładowane bezpośrednio do przestrzeni jądra macOS**, zapewniając dodatkową funkcjonalność głównemu systemowi operacyjnemu.

### Status wycofania i DriverKit / System Extensions
Począwszy od **macOS Catalina (10.15)** firma Apple oznaczyła większość starszych KPI jako *deprecated* i wprowadziła frameworki **System Extensions i DriverKit**, które działają w **przestrzeni użytkownika**. Od wersji **macOS Big Sur (11)** system operacyjny będzie *odmawiał załadowania* kexts innych firm, które korzystają z wycofanych KPI, chyba że komputer zostanie uruchomiony w trybie **Reduced Security**. Na urządzeniach z Apple Silicon włączenie kexts dodatkowo wymaga od użytkownika:

1. Ponownego uruchomienia komputera w trybie **Recovery** → *Startup Security Utility*.
2. Wybrania opcji **Reduced Security** i zaznaczenia **„Allow user management of kernel extensions from identified developers”**.
3. Ponownego uruchomienia komputera i zatwierdzenia kext w **System Settings → Privacy & Security**.

Sterowniki działające w przestrzeni użytkownika, napisane z użyciem DriverKit/System Extensions, znacznie **zmniejszają attack surface**, ponieważ awarie lub uszkodzenia pamięci są ograniczone do procesu działającego w sandboxie, a nie do przestrzeni jądra.<sup>[1]</sup>

> 📝 Od wersji macOS Sequoia (15) firma Apple całkowicie usunęła kilka starszych KPI związanych z siecią i USB — jedynym rozwiązaniem zapewniającym zgodność z przyszłymi wersjami jest migracja dostawców do System Extensions.

### Wymagania

Oczywiście jest to na tyle potężne rozwiązanie, że **załadowanie rozszerzenia jądra jest skomplikowane**. Poniżej znajdują się **wymagania**, które musi spełniać rozszerzenie jądra, aby można było je załadować:

- Podczas **wchodzenia w tryb recovery** musi być dozwolone ładowanie **rozszerzeń jądra**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Rozszerzenie jądra musi być **podpisane certyfikatem podpisywania kodu jądra**, który może zostać **przyznany wyłącznie przez Apple**. Firma Apple szczegółowo sprawdzi firmę oraz powody, dla których certyfikat jest potrzebny.
- Rozszerzenie jądra musi być również **notarized**; firma Apple będzie mogła sprawdzić je pod kątem malware.
- Następnie użytkownik **root** może **załadować rozszerzenie jądra**, a pliki wewnątrz pakietu muszą **należeć do użytkownika root**.
- Podczas procesu przesyłania pakiet musi zostać przygotowany w **chronionej lokalizacji niebędącej własnością użytkownika root**: `/Library/StagedExtensions` (wymaga uprawnienia `com.apple.rootless.storage.KernelExtensionManagement`).
- Na koniec, podczas próby załadowania rozszerzenia użytkownik [**otrzyma prośbę o potwierdzenie**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html), a po jej zaakceptowaniu komputer musi zostać **uruchomiony ponownie**, aby załadować rozszerzenie.

### Proces ładowania

W systemie Catalina wyglądało to następująco: warto zauważyć, że proces **weryfikacji** odbywa się w userland. Jednak tylko aplikacje z uprawnieniem **`com.apple.private.security.kext-management`** mogą **zażądać od jądra załadowania rozszerzenia**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **rozpoczyna** proces **weryfikacji** w celu załadowania rozszerzenia
- Komunikuje się z **`kextd`**, wysyłając żądanie za pomocą **usługi Mach**.
2. **`kextd`** sprawdza kilka elementów, takich jak **podpis**
- Komunikuje się z **`syspolicyd`**, aby **sprawdzić**, czy rozszerzenie może zostać **załadowane**.
3. **`syspolicyd`** wyświetli **użytkownikowi monit**, jeśli rozszerzenie nie było wcześniej ładowane.
- **`syspolicyd`** przekaże wynik do **`kextd`**
4. **`kextd`** będzie ostatecznie mógł **przekazać jądru polecenie załadowania** rozszerzenia

Jeśli **`kextd`** jest niedostępny, **`kextutil`** może wykonać te same kontrole.

### Enumeracja i zarządzanie (załadowanymi kexts)

`kextstat` było historycznym narzędziem, ale w nowszych wydaniach macOS jest **deprecated**. Współczesnym interfejsem jest **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Starsza składnia jest nadal dostępna do celów referencyjnych:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` można również wykorzystać do **zrzutu zawartości Kernel Collection (KC)** lub sprawdzenia, czy kext rozwiązuje wszystkie zależności symboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Mimo że oczekuje się, że rozszerzenia kernela będą znajdować się w `/System/Library/Extensions/`, po przejściu do tego folderu **nie znajdziesz żadnego pliku binarnego**. Wynika to z użycia **kernelcache** — aby dokonać reverse engineeringu jednego pliku `.kext`, musisz znaleźć sposób na jego uzyskanie.

**Kernelcache** to **wstępnie skompilowana i wstępnie połączona wersja kernela XNU**, wraz z niezbędnymi **drivers** urządzeń i **kernel extensions**. Jest przechowywany w formacie **skompresowanym** i rozpakowywany do pamięci podczas procesu uruchamiania systemu. Kernelcache umożliwia **szybsze uruchamianie systemu**, ponieważ gotowa do wykonania wersja kernela i kluczowych drivers jest dostępna od razu, co ogranicza czas i zasoby, które w przeciwnym razie byłyby potrzebne do dynamicznego ładowania i łączenia tych komponentów podczas uruchamiania.

Główne zalety kernelcache to **szybkość ładowania** oraz fakt, że wszystkie moduły są wstępnie połączone (brak opóźnienia podczas ładowania). Ponadto po wstępnym połączeniu wszystkich modułów KXLD może zostać usunięty z pamięci, dzięki czemu **XNU nie może ładować nowych KEXT-ów.**

> [!TIP]
> Narzędzie [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) odszyfrowuje kontenery AEA firmy Apple (Apple Encrypted Archive / AEA asset) — zaszyfrowany format kontenera używany przez Apple dla zasobów OTA i niektórych elementów IPSW — oraz może wygenerować znajdujące się wewnątrz archiwum .dmg/asset, które następnie można wypakować za pomocą dostarczonych narzędzi aastuff.


### Lokalny Kerlnelcache

W iOS znajduje się w **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, natomiast w macOS można go znaleźć za pomocą: **`find / -name "kernelcache" 2>/dev/null`** \
W moim przypadku w macOS znalazłem go w:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Znajdziesz go również tutaj: [**kernelcache wersji 14 z symbolami**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### Skompresowany IMG4 / BVX2 (LZFSE)

Format pliku IMG4 to format kontenera używany przez Apple w urządzeniach iOS i macOS do bezpiecznego **przechowywania i weryfikowania komponentów firmware** (takich jak **kernelcache**). Format IMG4 zawiera nagłówek oraz kilka tagów, które hermetyzują różne elementy danych, w tym właściwy payload (taki jak kernel lub bootloader), sygnaturę oraz zestaw właściwości manifestu. Format obsługuje weryfikację kryptograficzną, dzięki czemu urządzenie może potwierdzić autentyczność i integralność komponentu firmware przed jego wykonaniem.

Zwykle składa się z następujących komponentów:

- **Payload (IM4P)**:
- Często skompresowany (LZFSE4, LZSS, …)
- Opcjonalnie zaszyfrowany
- **Manifest (IM4M)**:
- Zawiera sygnaturę
- Dodatkowy słownik Key/Value
- **Restore Info (IM4R)**:
- Znany również jako APNonce
- Zapobiega ponownemu zastosowaniu niektórych aktualizacji
- OPCJONALNIE: Zwykle nie jest znajdowany

Rozpakuj Kernelcache:
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
#### Wyłączanie symboli dla kernela

**`Disarm`** pozwala symbolicate funkcje z kernelcache za pomocą matcherów. Matchery to po prostu proste reguły wzorców (wiersze tekstu), które informują disarm, jak rozpoznawać i automatycznie symbolicate funkcje, argumenty oraz ciągi panic/log znajdujące się wewnątrz pliku binarnego.

Zasadniczo wskazujesz ciąg znaków używany przez funkcję, a disarm go znajdzie i **symbolicate**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Przejdź do /tmp/extracted, gdzie disarm wypakował zestawy plików
disarm -e filesets kernelcache.release.d23 # Zawsze wypakowuj do /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Pamiętaj, że xnu.matchers to tak naprawdę plik z matcherami
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# Zainstaluj narzędzie ipsw
brew install blacktop/tap/ipsw

# Wyodrębnij tylko kernelcache z IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Powinieneś otrzymać coś takiego:
#   out/Firmware/kernelcache.release.iPhoneXX
#   lub payload IMG4: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Jeśli otrzymasz payload IMG4:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

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

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

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


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# Zidentyfikuj adres załadowania kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Dołącz
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
