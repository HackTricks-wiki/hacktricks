# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Kernel extensions (Kexts) su **paketi** sa **`.kext`** ekstenzijom koji se **učitavaju direktno u macOS kernel space**, pružajući dodatnu funkcionalnost glavnom operativnom sistemu.

### Status zastarevanja & DriverKit / System Extensions
Počevši od **macOS Catalina (10.15)** Apple je označio većinu legacy KPI-ova kao *deprecated* i uveo **System Extensions & DriverKit** okvire koji rade u **user-space**. Od **macOS Big Sur (11)** operativni sistem će *odbiti da učita* third-party kexts koji zavise od deprecated KPI-ova osim ako je mašina podignuta u **Reduced Security** režimu. Na Apple Silicon-u, omogućavanje kext-ova dodatno zahteva od korisnika da:

1. Reboot-uje u **Recovery** → *Startup Security Utility*.
2. Izabere **Reduced Security** i štiklira **“Allow user management of kernel extensions from identified developers”**.
3. Reboot-uje i odobri kext iz **System Settings → Privacy & Security**.

User-land drajveri napisani sa DriverKit/System Extensions dramatično **smanjuju attack surface** jer su padovi ili korupcija memorije ograničeni na sandboxovani proces umesto na kernel space.

> 📝 From macOS Sequoia (15) Apple has removed several legacy networking and USB KPIs entirely – the only forward-compatible solution for vendors is to migrate to System Extensions.

### Zahtevi

Očigledno, ovo je toliko moćno da je **komplikovano učitati kernel extension**. Ovo su **zahtevi** koje kernel extension mora ispuniti da bi bio učitan:

- Kada se **ulazi u recovery mode**, kernel **extensions moraju biti dozvoljene** za učitavanje:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension mora biti **potpisan sa kernel code signing certificate**, koji može biti dodeljen samo od strane **Apple**. Apple će detaljno pregledati kompaniju i razloge zbog kojih je potreban.
- Kernel extension takođe mora biti **notarized**, Apple će moći da ga proveri na malware.
- Zatim, korisnik **root** je taj koji može **učitati kernel extension** i fajlovi unutar paketa moraju **pripadati root-u**.
- Tokom procesa otpremanja, paket mora biti pripremljen u **zaštićenoj non-root lokaciji**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Na kraju, prilikom pokušaja učitavanja, korisnik će [**dobiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, ako ga prihvati, računar mora biti **restartovan** da bi se učitao.

### Proces učitavanja

U Catalini je to izgledalo ovako: interesantno je primetiti da se proces **verifikacije** odvija u **userland-u**. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** grant-om mogu **zahtevati od kernela da učita ekstenziju**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **pokreće** proces **verifikacije** za učitavanje ekstenzije
- Komunicira sa **`kextd`** koristeći **Mach service**.
2. **`kextd`** će proveriti nekoliko stvari, kao što je **potpis**
- Komunicira sa **`syspolicyd`** da **proveri** da li ekstenzija može biti **učitana**.
3. **`syspolicyd`** će **prompt-ovati** **korisnika** ako ekstenzija nije prethodno učitana.
- **`syspolicyd`** će izvestiti rezultat nazad **`kextd`**-u
4. **`kextd`** će konačno moći da **naredi kernelu da učita** ekstenziju

Ako **`kextd`** nije dostupan, **`kextutil`** može izvesti iste provere.

### Enumeracija & upravljanje (učitani kexts)

`kextstat` je bio istorijski alat ali je **deprecated** u novijim macOS izdanjima. Moderni interfejs je **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Starija sintaksa je i dalje dostupna za referencu:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` se takođe može iskoristiti za **dump the contents of a Kernel Collection (KC)** ili da proveri da kext razrešava sve simboličke zavisnosti:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Even though the kernel extensions are expected to be in `/System/Library/Extensions/`, if you go to this folder you **won't find any binary**. This is because of the **kernelcache** and in order to reverse one `.kext` you need to find a way to obtain it.

The **kernelcache** is a **pre-compiled and pre-linked version of the XNU kernel**, along with essential device **drivers** and **kernel extensions**. It's stored in a **compressed** format and gets decompressed into memory during the boot-up process. The kernelcache facilitates a **faster boot time** by having a ready-to-run version of the kernel and crucial drivers available, reducing the time and resources that would otherwise be spent on dynamically loading and linking these components at boot time.

The main benefits of the kernelcache is **speed of loading** and that all modules are prelinked (no load time impediment). And that once all modules have been prelinked- KXLD can be removed from memory so **XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.


### Lokalni Kernelcache

In iOS it's located in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS you can find it with: **`find / -name "kernelcache" 2>/dev/null`** \
U mom slučaju na macOS-u pronašao sam ga u:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Pronađi takođe ovde [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

The IMG4 file format is a container format used by Apple in its iOS and macOS devices for securely **storing and verifying firmware** components (like **kernelcache**). The IMG4 format includes a header and several tags which encapsulate different pieces of data including the actual payload (like a kernel or bootloader), a signature, and a set of manifest properties. The format supports cryptographic verification, allowing the device to confirm the authenticity and integrity of the firmware component before executing it.

It's usually composed of the following components:

- **Payload (IM4P)**:
- Often compressed (LZFSE4, LZSS, …)
- Optionally encrypted
- **Manifest (IM4M)**:
- Contains Signature
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- Also known as APNonce
- Prevents replaying of some updates
- OPTIONAL: Usually this isn't found

Dekompresujte Kernelcache:
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

**`Disarm`** omogućava symbolicate funkcija iz kernelcache koristeći matchere. Ti matcheri su samo jednostavna pravila obrasca (tekstualne linije) koja govore disarm kako da prepozna & auto-symbolicate funkcije, argumente i panic/log strings unutar binarnog fajla.

Dakle, u suštini označite string koji funkcija koristi i disarm će ga pronaći i **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Idi u /tmp/extracted gde je disarm izvukao filesets
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
# Lista svih ekstenzija
kextex -l kernelcache.release.iphone14.e
## Izdvoji com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Izdvoji sve
kextex_all kernelcache.release.iphone14.e

# Proveri ekstenziju za simbole
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
# Napravite paket za simbolikaciju za najnoviji kernel panic
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

# Priključi se
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
