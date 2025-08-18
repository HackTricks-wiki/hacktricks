# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Kernel extensions (Kexts) are **packages** with a **`.kext`** extension that are **loaded directly into the macOS kernel space**, providing additional functionality to the main operating system.

### Deprecation status & DriverKit / System Extensions  
Starting with **macOS Catalina (10.15)** Apple marked most legacy KPIs as *deprecated* and introduced the **System Extensions & DriverKit** frameworks that run in **user-space**. From **macOS Big Sur (11)** the operating system will *refuse to load* third-party kexts that rely on deprecated KPIs unless the machine is booted in **Reduced Security** mode. On Apple Silicon, enabling kexts additionally requires the user to:

1. Reboot into **Recovery** → *Startup Security Utility*.
2. Select **Reduced Security** and tick **“Allow user management of kernel extensions from identified developers”**.
3. Reboot and approve the kext from **System Settings → Privacy & Security**.

User-land drivers written with DriverKit/System Extensions dramatically **reduce attack surface** because crashes or memory corruption are confined to a sandboxed process rather than kernel space.  

> 📝 From macOS Sequoia (15) Apple has removed several legacy networking and USB KPIs entirely – the only forward-compatible solution for vendors is to migrate to System Extensions.

### Requirements

Obviously, this is so powerful that it is **complicated to load a kernel extension**. These are the **requirements** that a kernel extension must meet to be loaded:

- When **entering recovery mode**, kernel **extensions must be allowed** to be loaded:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- The kernel extension must be **signed with a kernel code signing certificate**, which can only be **granted by Apple**. Who will review in detail the company and the reasons why it is needed.
- The kernel extension must also be **notarized**, Apple will be able to check it for malware.
- Then, the **root** user is the one who can **load the kernel extension** and the files inside the package must **belong to root**.
- During the upload process, the package must be prepared in a **protected non-root location**: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Finally, when attempting to load it, the user will [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) and, if accepted, the computer must be **restarted** to load it.

### Loading process

In Catalina it was like this: It is interesting to note that the **verification** process occurs in **userland**. However, only applications with the **`com.apple.private.security.kext-management`** grant can **request the kernel to load an extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **starts** the **verification** process for loading an extension
   - It will talk to **`kextd`** by sending using a **Mach service**.
2. **`kextd`** will check several things, such as the **signature**
   - It will talk to **`syspolicyd`** to **check** if the extension can be **loaded**.
3. **`syspolicyd`** will **prompt** the **user** if the extension has not been previously loaded.
   - **`syspolicyd`** will report the result to **`kextd`**
4. **`kextd`** will finally be able to **tell the kernel to load** the extension

If **`kextd`** is not available, **`kextutil`** can perform the same checks.

### Enumeration & management (loaded kexts)

`kextstat` was the historical tool but it is **deprecated** in recent macOS releases. The modern interface is **`kmutil`**:

```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```

Older syntax is still available for reference:

```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```

`kmutil inspect` can also be leveraged to **dump the contents of a Kernel Collection (KC)** or verify that a kext resolves all symbol dependencies:

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

### Local Kerlnelcache

In iOS it's located in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS you can find it with: **`find / -name "kernelcache" 2>/dev/null`** \
In my case in macOS I found it in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

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
```

### Download

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

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
