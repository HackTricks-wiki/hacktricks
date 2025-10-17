# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Kernel extensions (Kexts) to pakiety z rozszerzeniem **`.kext`**, które są **ładowane bezpośrednio do przestrzeni jądra macOS**, dostarczając dodatkową funkcjonalność dla głównego systemu operacyjnego.

### Status wycofania & DriverKit / System Extensions
Począwszy od **macOS Catalina (10.15)** Apple oznaczyło większość starych KPI jako *deprecated* i wprowadziło frameworki **System Extensions & DriverKit**, które działają w **user-space**. Od **macOS Big Sur (11)** system operacyjny będzie *odmawiać ładowania* third-party kextów korzystających ze zdeprecjonowanych KPI, chyba że maszyna zostanie uruchomiona w trybie **Reduced Security**. Na Apple Silicon włączenie kextów dodatkowo wymaga od użytkownika:

1. Reboot do **Recovery** → *Startup Security Utility*.
2. Wybrania **Reduced Security** i zaznaczenia **“Allow user management of kernel extensions from identified developers”**.
3. Restartu i zatwierdzenia kexta w **System Settings → Privacy & Security**.

Sterowniki user-land napisane przy użyciu DriverKit/System Extensions znacząco **zmniejszają powierzchnię ataku**, ponieważ awarie lub uszkodzenia pamięci są ograniczone do sandboxowanego procesu zamiast przestrzeni jądra.

> 📝 From macOS Sequoia (15) Apple has removed several legacy networking and USB KPIs entirely – the only forward-compatible solution for vendors is to migrate to System Extensions.

### Wymagania

Oczywiście, to jest tak potężne, że **załadowanie kernel extension jest skomplikowane**. Oto **wymagania**, które rozszerzenie jądra musi spełnić, żeby mogło zostać załadowane:

- When **entering recovery mode**, kernel **extensions must be allowed** to be loaded:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Rozszerzenie jądra musi być **podpisane certyfikatem podpisu kodu jądra**, który może być **wydany tylko przez Apple**. Apple dokładnie sprawdzi firmę i powody, dla których jest to potrzebne.
- Rozszerzenie musi być także **notarizowane**; Apple będzie mogło je sprawdzić pod kątem malware.
- Następnie, użytkownik **root** jest tym, który może **załadować rozszerzenie jądra**, a pliki wewnątrz pakietu muszą **należeć do root**.
- Podczas procesu uploadu, pakiet musi być przygotowany w **chronionej lokalizacji niebędącej rootem**: `/Library/StagedExtensions` (wymaga nadania uprawnienia `com.apple.rootless.storage.KernelExtensionManagement`).
- W końcu, przy próbie załadowania, użytkownik [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, jeśli zaakceptuje, komputer musi zostać **zrestartowany**, aby go załadować.

### Proces ładowania

W Catalina wyglądało to tak: Warto zauważyć, że proces **weryfikacji** odbywa się w **userland**. Jednak tylko aplikacje z nadanym uprawnieniem **`com.apple.private.security.kext-management`** mogą **zażądać od jądra załadowania rozszerzenia**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **uruchamia** proces **weryfikacji** przed załadowaniem rozszerzenia
- Będzie komunikować się z **`kextd`** wysyłając za pomocą **Mach service**.
2. **`kextd`** sprawdzi kilka rzeczy, takich jak **signature**
- Będzie komunikować się z **`syspolicyd`**, aby **sprawdzić**, czy rozszerzenie może zostać **załadowane**.
3. **`syspolicyd`** poprosi **użytkownika** o potwierdzenie, jeśli rozszerzenie nie było wcześniej załadowane.
- **`syspolicyd`** przekaże wynik do **`kextd`**
4. **`kextd`** w końcu będzie mógł **polecić jądru załadowanie** rozszerzenia

Jeśli **`kextd`** nie jest dostępne, **`kextutil`** może wykonać te same kontrole.

### Enumeracja & zarządzanie (załadowane kexts)

`kextstat` był historycznym narzędziem, ale jest **przestarzały** w nowszych wydaniach macOS. Nowoczesnym interfejsem jest **`kmutil`**:
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
`kmutil inspect` może być również wykorzystany do **zrzucenia zawartości Kernel Collection (KC)** lub weryfikacji, że kext rozwiązuje wszystkie zależności symboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Chociaż rozszerzenia jądra są zwykle oczekiwane w `/System/Library/Extensions/`, jeśli wejdziesz do tego folderu **nie znajdziesz żadnego pliku binarnego**. Dzieje się tak z powodu **kernelcache** i aby poddać pojedynczy `.kext` reverse engineeringowi, musisz znaleźć sposób na jego pozyskanie.

The **kernelcache** jest **wstępnie skompilowaną i wstępnie powiązaną wersją jądra XNU**, wraz z niezbędnymi sterownikami urządzeń (**drivers**) i **kernel extensions**. Jest przechowywany w **skomprymowanym** formacie i jest dekompresowany do pamięci podczas procesu uruchamiania. Kernelcache przyspiesza czas rozruchu, mając gotową do uruchomienia wersję jądra i kluczowych sterowników, co zmniejsza czas i zasoby, które w przeciwnym razie byłyby potrzebne do dynamicznego ładowania i linkowania tych komponentów podczas startu.

Główne korzyści z kernelcache to **szybsze ładowanie** oraz to, że wszystkie moduły są wstępnie powiązane (brak opóźnień przy ładowaniu). A gdy wszystkie moduły zostały wstępnie powiązane — KXLD może zostać usunięty z pamięci, więc **XNU nie może załadować nowych KEXTów.**

> [!TIP]
> Narzędzie [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) odszyfrowuje kontenery AEA (Apple Encrypted Archive / AEA asset) używane przez Apple dla zasobów OTA i niektórych części IPSW — i może wygenerować podstawowy .dmg/asset archive, który następnie możesz rozpakować za pomocą dostarczonych narzędzi aastuff.

### Local Kerlnelcache

W iOS znajduje się w **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, w macOS możesz go znaleźć poleceniem: **`find / -name "kernelcache" 2>/dev/null`** \
W moim przypadku w macOS znalazłem go w:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Zobacz także tutaj [**kernelcache wersji 14 z symbolami**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Format pliku IMG4 jest formatem kontenera używanym przez Apple w urządzeniach iOS i macOS do bezpiecznego przechowywania i weryfikacji komponentów firmware (np. kernelcache). Format IMG4 zawiera nagłówek i kilka tagów, które enkapsulują różne fragmenty danych, w tym rzeczywisty payload (np. jądro lub bootloader), podpis oraz zestaw właściwości manifestu. Format obsługuje weryfikację kryptograficzną, pozwalając urządzeniu potwierdzić autentyczność i integralność komponentu firmware przed jego wykonaniem.

Zazwyczaj składa się z następujących komponentów:

- **Payload (IM4P)**:
  - Często skompresowany (LZFSE4, LZSS, …)
  - Opcjonalnie zaszyfrowany
- **Manifest (IM4M)**:
  - Zawiera Signature
  - Dodatowy słownik Key/Value
- **Restore Info (IM4R)**:
  - Znany również jako APNonce
  - Zapobiega ponownemu odtwarzaniu (replay) niektórych aktualizacji
  - OPTIONAL: Zwykle tego nie ma

Decompress the Kernelcache:
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
#### Symbole jądra dla Disarm

**`Disarm`** pozwala symbolikować funkcje z kernelcache przy użyciu matchers. Te matchery to po prostu proste reguły wzorców (linie tekstu), które mówią disarm, jak rozpoznawać i automatycznie symbolikować funkcje, argumenty oraz panic/log strings wewnątrz binarki.

Czyli zasadniczo wskazujesz łańcuch znaków, którego używa funkcja, a disarm go znajdzie i **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Przejdź do /tmp/extracted, gdzie disarm wyodrębnił filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
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
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

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
# Wypisz wszystkie rozszerzenia
kextex -l kernelcache.release.iphone14.e
## Wyodrębnij com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Wyodrębnij wszystko
kextex_all kernelcache.release.iphone14.e

# Sprawdź rozszerzenie pod kątem symboli
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
# Utwórz pakiet symbolikacji dla najnowszego zrzutu paniki
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
(lldb) bt  # pobierz backtrace w kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# Zidentyfikuj adres załadowania kexta
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Dołącz
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
