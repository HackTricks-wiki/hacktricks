# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Kernel extensions (Kexts) su **paketi** sa ekstenzijom **`.kext`** koji se **učitavaju direktno u prostor macOS kernela**, pružajući dodatnu funkcionalnost glavnom operativnom sistemu.

### Status zastarelosti i DriverKit / System Extensions
Počev od **macOS Catalina (10.15)**, Apple je označio većinu zastarelih KPI-jeva kao *deprecated* i uveo framework-e **System Extensions & DriverKit**, koji se izvršavaju u **user-space**. Od verzije **macOS Big Sur (11)** operativni sistem će *odbiti da učita* third-party kexts koji zavise od zastarelih KPI-jeva, osim ako je računar pokrenut u režimu **Reduced Security**. Na Apple Silicon računarima, omogućavanje kexts dodatno zahteva od korisnika da:

1. Ponovo pokrene računar u **Recovery** → *Startup Security Utility*.
2. Izabere **Reduced Security** i označi **“Allow user management of kernel extensions from identified developers”**.
3. Ponovo pokrene računar i odobri kext u **System Settings → Privacy & Security**.

User-land drivers napisani pomoću DriverKit/System Extensions značajno **smanjuju attack surface**, jer su crashes ili oštećenje memorije ograničeni na sandboxed proces, umesto na kernel space.<sup>[[1]](#references)</sup>

> 📝 Od verzije macOS Sequoia (15), Apple je u potpunosti uklonio nekoliko zastarelih networking i USB KPI-jeva – jedino rešenje kompatibilno sa budućim verzijama za vendore jeste migracija na System Extensions.

### Zahtevi

Očigledno je da je ovo toliko moćno da je **učitavanje kernel extension-a komplikovano**. Ovo su **zahtevi** koje kernel extension mora da ispuni da bi bio učitan:

- Prilikom **ulaska u recovery mode**, kernel **extensions moraju biti dozvoljeni** za učitavanje:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension mora biti **potpisan kernel code signing sertifikatom**, koji može da **dodeli samo Apple**. Apple će detaljno proveriti kompaniju i razloge zbog kojih je sertifikat potreban.
- Kernel extension takođe mora biti **notarized**; Apple će moći da proveri da li sadrži malware.
- Zatim, **root** korisnik može da **učita kernel extension**, a fajlovi unutar paketa moraju **pripadati root korisniku**.
- Tokom procesa upload-a, paket mora biti pripremljen na **zaštićenoj lokaciji koja nije u vlasništvu root korisnika**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Konačno, prilikom pokušaja učitavanja, korisnik će [**dobiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, ako ga prihvati, računar mora biti **restartovan** da bi se extension učitao.

### Proces učitavanja

U Catalina verziji proces je izgledao ovako: Zanimljivo je da se proces **verifikacije** odvija u userland-u. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** grant-om mogu **zatražiti od kernela da učita extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **pokreće** proces **verifikacije** za učitavanje extension-a
- Komunicira sa **`kextd`** slanjem zahteva putem **Mach service-a**.
2. **`kextd`** proverava nekoliko stvari, kao što je **signature**
- Komunicira sa **`syspolicyd`** da bi **proverio** da li extension može biti **učitan**.
3. **`syspolicyd`** će **prikazati upit** **korisniku** ako extension ranije nije bio učitan.
- **`syspolicyd`** će prijaviti rezultat procesu **`kextd`**
4. **`kextd`** će konačno moći da **naloži kernelu da učita** extension

Ako **`kextd`** nije dostupan, **`kextutil`** može da izvrši iste provere.

### Enumeracija i upravljanje (učitani kexts)

`kextstat` je bio istorijski alat, ali je u novijim izdanjima macOS-a **deprecated**. Savremeni interfejs je **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Starija sintaksa je i dalje dostupna kao referenca:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` se takođe može koristiti za **izbacivanje sadržaja Kernel Collection (KC)** ili proveru da li kext razrešava sve zavisnosti simbola:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Iako se očekuje da se kernel extensions nalaze u `/System/Library/Extensions/`, ako otvorite ovaj folder, **nećete pronaći nijedan binary**. Razlog tome je **kernelcache**, a da biste izvršili reverse engineering jednog `.kext` fajla, morate pronaći način da ga pribavite.

**Kernelcache** je **pre-compiled i pre-linked verzija XNU kernela**, zajedno sa osnovnim device **driverima** i **kernel extensions**. Čuva se u **compressed** formatu i decompressed se u memoriju tokom boot-up procesa. Kernelcache omogućava **brže bootovanje** tako što je spremna verzija kernela i ključnih drivera dostupna za pokretanje, čime se smanjuje vreme i resursi koji bi inače bili potrebni za dinamičko učitavanje i povezivanje ovih komponenti tokom bootovanja.

Glavne prednosti kernelcache-a su **brzina učitavanja** i činjenica da su svi moduli prelinked (nema impedimenta tokom učitavanja). Takođe, kada su svi moduli prelinked, KXLD može biti uklonjen iz memorije, pa **XNU ne može učitavati nove KEXT-ove.**

> [!TIP]
> Alat [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) dešifruje Apple-ove AEA (Apple Encrypted Archive / AEA asset) kontejnere — encrypted container format koji Apple koristi za OTA assets i neke IPSW delove — i može proizvesti osnovni .dmg/asset archive koji zatim možete extractovati pomoću priloženih aastuff alata.


### Lokalni Kerlnelcache

U iOS-u se nalazi na lokaciji **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, a u macOS-u ga možete pronaći pomoću: **`find / -name "kernelcache" 2>/dev/null`** \
U mom slučaju, u macOS-u sam ga pronašao na:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Ovde pronađite i [**kernelcache verzije 14 sa symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format je container format koji Apple koristi na svojim iOS i macOS uređajima za bezbedno **čuvanje i verifikovanje firmware** komponenti (kao što je **kernelcache**). IMG4 format uključuje header i nekoliko tagova koji enkapsuliraju različite delove podataka, uključujući stvarni payload (kao što su kernel ili bootloader), signature i skup manifest properties. Format podržava cryptographic verification, što uređaju omogućava da potvrdi autentičnost i integritet firmware komponente pre njenog izvršavanja.

Obično se sastoji od sledećih komponenti:

- **Payload (IM4P)**:
- Često compressed (LZFSE4, LZSS, …)
- Opciono encrypted
- **Manifest (IM4M)**:
- Sadrži Signature
- Dodatni Key/Value dictionary
- **Restore Info (IM4R)**:
- Takođe poznat kao APNonce
- Sprečava replayovanje nekih update-a
- OPTIONAL: Ovo se obično ne nalazi

Decompressujte Kernelcache:
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
#### Disarm symbols for the kernel

**`Disarm`** omogućava symbolicate funkcija iz kernelcache-a pomoću matcher-a. Ovi matcher-i su samo jednostavna pattern pravila (tekstualne linije) koja govore disarm-u kako da prepozna i automatski symbolicate funkcije, argumente i panic/log stringove unutar binary-ja.

Dakle, jednostavno navedete string koji funkcija koristi, a disarm će ga pronaći i **symbolicate**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Go to /tmp/extracted where disarm extracted the filesets
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
# Instalirajte ipsw alat
brew install blacktop/tap/ipsw

# Izvucite samo kernelcache iz IPSW-a
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Trebalo bi da dobijete nešto poput:
#   out/Firmware/kernelcache.release.iPhoneXX
#   ili IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Ako dobijete IMG4 payload:
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
# Izlistaj sve ekstenzije
kextex -l kernelcache.release.iphone14.e
## Izdvoji com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Izdvoji sve
kextex_all kernelcache.release.iphone14.e

# Proveri ekstenziju da li sadrži simbole
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
# Kreirajte symbolication bundle za najnoviji panic
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
# Identifikuj adresu učitavanja kext-a
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Poveži se
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
