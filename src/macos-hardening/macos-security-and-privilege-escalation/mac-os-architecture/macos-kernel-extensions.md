# macOS Kernel Uzantıları & Kernelcache'ler

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Kernel extensions (Kexts) **`.kext`** uzantısına sahip **paketlerdir** ve **macOS kernel alanına doğrudan yüklenirler**, işletim sistemine ek işlevsellik sağlarlar.

### Deprecation status & DriverKit / System Extensions
**macOS Catalina (10.15)** ile başlayarak Apple çoğu eski KPI'yi *deprecated* olarak işaretledi ve **System Extensions & DriverKit** framework'lerini tanıttı; bunlar **user-space** içinde çalışır. **macOS Big Sur (11)**'den itibaren işletim sistemi, deprecated KPI'lara dayanan üçüncü taraf kext'leri makine **Reduced Security** modunda önyüklemedikçe *yüklemeyi reddedecek*. Apple Silicon üzerinde kext'leri etkinleştirmek ayrıca kullanıcının şunları yapmasını gerektirir:

1. **Recovery** → *Startup Security Utility* ile yeniden başlatma.
2. **Reduced Security**'yi seçmek ve **“Allow user management of kernel extensions from identified developers”** kutusunu işaretlemek.
3. Yeniden başlatma ve kext'i **System Settings → Privacy & Security** üzerinden onaylama.

DriverKit/System Extensions ile yazılmış user-land sürücüler, çökmeler veya bellek bozulmalarının kernel alanına değil sandbox'lanmış bir işleme hapsedilmesi nedeniyle saldırı yüzeyini ciddi şekilde **azaltır**.

> 📝 **macOS Sequoia (15)** ile Apple, bazı eski ağ ve USB KPI'lerini tamamen kaldırdı – satıcılar için ileriye dönük uyumlu tek çözüm System Extensions'a geçiş yapmaktır.

### Gereksinimler

Açıkça görüldüğü gibi, bu çok güçlü olduğu için **kernel extension yüklemek karmaşıktır**. Bir kernel extension'ın yüklenebilmesi için karşılaması gereken **gereksinimler** şunlardır:

- **recovery mode** girildiğinde, kernel **extensions'ın yüklenmesine izin verilmelidir**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension **kernel code signing sertifikasıyla imzalanmış** olmalıdır; bu sertifika yalnızca **Apple tarafından verilebilir**. Apple, şirketi ve neden gerekli olduğunu ayrıntılı olarak inceleyecektir.
- Kernel extension ayrıca **notarized** olmalıdır; Apple bunun için kötü amaçlı yazılım kontrolü yapabilecektir.
- Ardından, kernel extension'ı **yükleyebilecek** olan kullanıcı **root**'tur ve paket içindeki dosyalar **root'a ait** olmalıdır.
- Yükleme sürecinde paket, **korumalı non-root bir konumda** hazırlanmalıdır: `/Library/StagedExtensions` (bu, `com.apple.rootless.storage.KernelExtensionManagement` izni gerektirir).
- Son olarak, yüklemeye çalışırken kullanıcı [**onay isteği alacaktır**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ve kabul edilirse, yüklemek için bilgisayar **yeniden başlatılmalıdır**.

### Yükleme süreci

Catalina'da süreç şu şekildedir: İlginç olan nokta doğrulama işleminin **userland** içinde gerçekleşmesidir. Ancak yalnızca **`com.apple.private.security.kext-management`** iznine sahip uygulamalar **kernel'e bir extension yüklemesini talep edebilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli, bir uzantının yüklenmesi için **doğrulama** sürecini **başlatır**
- **Mach service** kullanarak **`kextd`** ile iletişim kurar.
2. **`kextd`** imza gibi çeşitli şeyleri **kontrol eder**
- Uzantının **yüklenip yüklenemeyeceğini** **kontrol etmek** için **`syspolicyd`** ile konuşur.
3. **`syspolicyd`**, uzantı daha önce yüklenmemişse **kullanıcıyı** **uyarı**r
- **`syspolicyd`** sonucu **`kextd`**'ye bildirir
4. Son olarak **`kextd`**, kernel'e uzantıyı **yüklemesini söyleyebilir**

Eğer **`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri gerçekleştirebilir.

### Sıralama & yönetim (yüklü kext'ler)

`kextstat` tarihsel araçtı fakat son macOS sürümlerinde **deprecated** olmuştur. Modern arayüz **`kmutil`**'dir:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Eski sözdizimi hâlâ referans için kullanılabilir:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` ayrıca **Kernel Collection (KC) içeriğinin dökümünü almak** veya bir kext'in tüm sembol bağımlılıklarını çözüp çözmediğini doğrulamak için kullanılabilir:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Kernel uzantılarının `/System/Library/Extensions/` içinde olması beklenmesine rağmen, bu klasöre giderseniz **hiçbir ikili dosya bulamazsınız**. Bunun nedeni **kernelcache** ve bir `.kext`'i tersine mühendislik yapmak için onu elde etmenin bir yolunu bulmanız gerekir.

The **kernelcache** is a **pre-compiled and pre-linked version of the XNU kernel**, along with essential device **drivers** and **kernel extensions**. It's stored in a **compressed** format and gets decompressed into memory during the boot-up process. The kernelcache facilitates a **faster boot time** by having a ready-to-run version of the kernel and crucial drivers available, reducing the time and resources that would otherwise be spent on dynamically loading and linking these components at boot time.

The main benefits of the kernelcache is **speed of loading** and that all modules are prelinked (no load time impediment). And that once all modules have been prelinked- KXLD can be removed from memory so **XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.


### Yerel Kernelcache

iOS'ta konumu **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** olarak bulunur; macOS'ta ise şunu kullanarak bulabilirsiniz: **`find / -name "kernelcache" 2>/dev/null`** \
Benim macOS örneğimde bunu şu konumda buldum:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

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
#### Disarm çekirdek için semboller

**`Disarm`** matchers kullanarak kernelcache içindeki fonksiyonları symbolicate etmenizi sağlar. Bu matchers, bir binary içinde fonksiyonları, argümanları ve panic/log stringlerini nasıl tanıyıp auto-symbolicate edeceğini disarm'a söyleyen basit pattern kuralları (metin satırları)dır.

Kısacası bir fonksiyonun kullandığı stringi belirtirsiniz ve disarm bunu bulur ve **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# /tmp/extracted dizinine gidin — disarm'ın filesets'i çıkardığı yer
disarm -e filesets kernelcache.release.d23 # Her zaman /tmp/extracted'e çıkar
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # xnu.matchers'in aslında matchers içeren bir dosya olduğunu unutmayın
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
# ipsw aracını yükle
brew install blacktop/tap/ipsw

# IPSW'den yalnızca kernelcache'i çıkar
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Aşağıdakine benzer bir çıktı alırsınız:
#   out/Firmware/kernelcache.release.iPhoneXX
#   veya bir IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Eğer bir IMG4 payload alırsanız:
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
# Tüm uzantıları listele
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox'i çıkar
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Hepsini çıkar
kextex_all kernelcache.release.iphone14.e

# Uzantıyı semboller için kontrol et
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
# En son panic için symbolication paketi oluşturun
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
(lldb) bt  # çekirdek bağlamında backtrace al
```

### Attaching LLDB to a specific loaded kext

```bash
# kext'in yükleme adresini belirle
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Bağlan
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
