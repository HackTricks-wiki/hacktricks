# Rozszerzenia jądra macOS i Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Kernel extensions (Kexts) to pakiety z rozszerzeniem **`.kext`**, które są **ładowane bezpośrednio do przestrzeni jądra macOS**, dostarczając dodatkową funkcjonalność głównemu systemowi operacyjnemu.

### Status przestarzałości & DriverKit / System Extensions
Począwszy od **macOS Catalina (10.15)** Apple oznaczyło większość starych KPI jako *deprecated* i wprowadziło frameworki **System Extensions & DriverKit**, które działają w **user-space**. Od **macOS Big Sur (11)** system operacyjny będzie *odmawiał ładowania* zewnętrznych kextów, które polegają na przestarzałych KPI, chyba że maszyna jest uruchomiona w trybie **Reduced Security**. Na Apple Silicon dodatkowo wymagane jest, aby użytkownik:

1. Uruchomił ponownie do **Recovery** → *Startup Security Utility*.
2. Wybrał **Reduced Security** i zaznaczył **“Allow user management of kernel extensions from identified developers”**.
3. Uruchomił ponownie i zatwierdził kext w **System Settings → Privacy & Security**.

Sterowniki użytkownika napisane z użyciem DriverKit/System Extensions znacząco **zmniejszają powierzchnię ataku**, ponieważ awarie lub korupcja pamięci są ograniczone do sandboxowanego procesu, a nie przestrzeni jądra.

> 📝 Od macOS Sequoia (15) Apple usunęło całkowicie kilka starych KPI związanych z sieciami i USB – jedynym rozwiązaniem kompatybilnym w przyszłości dla dostawców jest migracja do System Extensions.

### Wymagania

Oczywiście, to jest tak potężne, że **ładowanie rozszerzenia jądra jest skomplikowane**. Oto **wymagania**, które rozszerzenie jądra musi spełnić, aby zostać załadowane:

- Podczas **wejścia w tryb recovery**, rozszerzenia jądra muszą być **dozwolone** do ładowania:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Rozszerzenie jądra musi być **podpisane certyfikatem podpisu kodu dla jądra (kernel code signing certificate)**, który może być **przyznany tylko przez Apple**. Apple przeprowadzi szczegółowy przegląd firmy i powodów, dla których certyfikat jest potrzebny.
- Rozszerzenie jądra musi być także **notarizowane**, Apple będzie mogło sprawdzić je pod kątem malware.
- Następnie to użytkownik **root** może **załadować rozszerzenie jądra** i pliki wewnątrz pakietu muszą **należeć do root**.
- Podczas procesu przesyłania pakiet musi być przygotowany w **chronionej lokalizacji nie-root**: `/Library/StagedExtensions` (wymaga uprawnienia `com.apple.rootless.storage.KernelExtensionManagement`).
- Wreszcie, przy próbie załadowania użytkownik [**otrzyma prośbę o potwierdzenie**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, jeśli zaakceptuje, komputer musi zostać **uruchomiony ponownie**, aby załadować rozszerzenie.

### Proces ładowania

W Catalinie wyglądało to tak: interesujące jest to, że proces **weryfikacji** odbywa się w **userland**. Jednak tylko aplikacje z uprawnieniem **`com.apple.private.security.kext-management`** mogą **zażądać od jądra załadowania rozszerzenia**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **rozpoczyna** proces **weryfikacji** przed załadowaniem rozszerzenia
- Komunikuje się z **`kextd`** wysyłając żądanie za pomocą **Mach service**.
2. **`kextd`** sprawdzi kilka rzeczy, takich jak **podpis**
- Będzie komunikować się z **`syspolicyd`**, aby **sprawdzić**, czy rozszerzenie może zostać **załadowane**.
3. **`syspolicyd`** **wyświetli monit** użytkownikowi, jeśli rozszerzenie nie było wcześniej ładowane.
- **`syspolicyd`** zgłosi wynik do **`kextd`**
4. **`kextd`** ostatecznie będzie mógł **powiedzieć jądru, aby załadowało** rozszerzenie

Jeśli **`kextd`** nie jest dostępny, **`kextutil`** może wykonać te same kontrole.

### Enumeracja i zarządzanie (załadowane kexty)

`kextstat` był historycznym narzędziem, ale jest **deprecated** w nowszych wydaniach macOS. Nowoczesnym interfejsem jest **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Starsza składnia jest nadal dostępna do wglądu:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` może być również użyty do **dump the contents of a Kernel Collection (KC)** lub do zweryfikowania, że kext rozwiązuje wszystkie zależności symboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Nawet jeśli rozszerzenia jądra oczekuje się znaleźć w `/System/Library/Extensions/`, jeśli wejdziesz do tego folderu **nie znajdziesz żadnego pliku binarnego**. Dzieje się tak z powodu **kernelcache** i aby wykonać odwrotną inżynierię jednego `.kext` musisz znaleźć sposób, by go uzyskać.

The **kernelcache** is a **pre-compiled and pre-linked version of the XNU kernel**, along with essential device **drivers** and **kernel extensions**. It's stored in a **compressed** format and gets decompressed into memory during the boot-up process. The kernelcache facilitates a **faster boot time** by having a ready-to-run version of the kernel and crucial drivers available, reducing the time and resources that would otherwise be spent on dynamically loading and linking these components at boot time.

Główne zalety kernelcache to **szybkość ładowania** oraz to, że wszystkie moduły są wstępnie połączone (brak opóźnień przy ładowaniu). A po wstępnym połączeniu wszystkich modułów KXLD może zostać usunięty z pamięci, więc **XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.

### Local Kerlnelcache

W iOS znajduje się w **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** , natomiast w macOS możesz go znaleźć poleceniem: **`find / -name "kernelcache" 2>/dev/null`** \
W moim przypadku na macOS znalazłem go w:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

The IMG4 file format is a container format used by Apple in its iOS and macOS devices for securely **storing and verifying firmware** components (like **kernelcache**). The IMG4 format includes a header and several tags which encapsulate different pieces of data including the actual payload (like a kernel or bootloader), a signature, and a set of manifest properties. The format supports cryptographic verification, allowing the device to confirm the authenticity and integrity of the firmware component before executing it.

Zwykle składa się z następujących komponentów:

- **Payload (IM4P)**:
  - Często skompresowany (LZFSE4, LZSS, …)
  - Opcjonalnie zaszyfrowany
- **Manifest (IM4M)**:
  - Zawiera Signature
  - Dodatkowy Key/Value dictionary
- **Restore Info (IM4R)**:
  - Znane także jako APNonce
  - Zapobiega replaying niektórych aktualizacji
  - OPTIONAL: Zwykle nie występuje

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
#### Disarm — symbole dla kernela

**`Disarm`** pozwala symbolicate funkcje z kernelcache przy użyciu matchers. Te matchers to po prostu proste reguły wzorców (linie tekstu), które mówią disarm, jak rozpoznać i auto-symbolicate funkcje, argumenty oraz panic/log strings wewnątrz binarki.

Czyli zasadniczo wskazujesz string, którego używa funkcja, a disarm go znajdzie i **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Przejdź do /tmp/extracted gdzie disarm rozpakował filesets
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
#   lub IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Jeśli otrzymasz IMG4 payload:
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

# Wyodrębnij wszystkie
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
# Utwórz pakiet symbolikacji dla najnowszego panic
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
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
