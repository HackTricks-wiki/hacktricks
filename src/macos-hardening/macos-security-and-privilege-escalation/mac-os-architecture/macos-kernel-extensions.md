# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Kernel extensions(Kexts)은 **`.kext`** 확장자를 가진 **packages**이며, **macOS kernel space에 직접 로드되어** main operating system에 추가 기능을 제공합니다.

### Deprecation status & DriverKit / System Extensions
**macOS Catalina (10.15)**부터 Apple은 대부분의 legacy KPI를 *deprecated*로 표시하고 **user-space에서 실행되는** **System Extensions & DriverKit** frameworks를 도입했습니다. **macOS Big Sur (11)**부터 operating system은 deprecated KPI에 의존하는 third-party kexts의 로드를 *거부*합니다. 단, machine이 **Reduced Security** mode로 boot된 경우는 예외입니다. Apple Silicon에서는 kexts를 활성화하기 위해 사용자가 추가로 다음을 수행해야 합니다.

1. **Recovery**로 재부팅 → *Startup Security Utility*로 이동합니다.
2. **Reduced Security**를 선택하고 **“Allow user management of kernel extensions from identified developers”**를 선택합니다.
3. 재부팅한 후 **System Settings → Privacy & Security**에서 kext를 승인합니다.

DriverKit/System Extensions로 작성된 User-land drivers는 crash 또는 memory corruption이 kernel space가 아닌 sandboxed process에 제한되므로 **attack surface를 크게 줄입니다**.<sup>[1]</sup>

> 📝 macOS Sequoia (15)부터 Apple은 여러 legacy networking 및 USB KPI를 완전히 제거했습니다. vendors를 위한 유일한 forward-compatible solution은 System Extensions로 migrate하는 것입니다.

### Requirements

당연히 이 기능은 매우 강력하므로 **kernel extension을 로드하는 것은** **복잡합니다**. kernel extension이 로드되려면 다음 **requirements**를 충족해야 합니다.

- **recovery mode로 진입할 때**, kernel **extensions가 로드되도록 허용되어야** 합니다:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension은 **kernel code signing certificate로 sign되어야** 하며, 이 certificate는 **Apple만** 발급할 수 있습니다. Apple은 company와 해당 certificate가 필요한 이유를 상세히 검토합니다.
- kernel extension은 **notarized**되어야 하며, Apple은 이를 malware에 대해 검사할 수 있습니다.
- 그런 다음 **root** user가 **kernel extension을 로드할 수** 있으며 package 내부의 files는 **root에 속해야** 합니다.
- upload process 중 package는 보호된 non-root location인 `/Library/StagedExtensions`에 준비되어야 합니다(`com.apple.rootless.storage.KernelExtensionManagement` grant가 필요합니다).
- 마지막으로 로드를 시도하면 사용자는 [**confirmation request를 받게 되며**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html), 이를 수락한 경우 computer를 **restart해야** 로드됩니다.

### Loading process

Catalina에서는 다음과 같았습니다. **verification** process가 **userland에서 수행된다**는 점이 흥미롭습니다. 그러나 **`com.apple.private.security.kext-management`** grant를 가진 applications만 **kernel에 extension 로드를 요청할 수** 있습니다: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli가 extension 로드를 위한 **verification** process를 **시작합니다**
- **Mach service**를 사용해 message를 전송하여 **`kextd`와 통신합니다**.
2. **`kextd`**는 **signature**와 같은 여러 항목을 **확인합니다**
- extension이 **로드될 수 있는지 확인하기 위해** **`syspolicyd`와 통신합니다**.
3. extension이 이전에 로드되지 않았다면 **`syspolicyd`**는 **user에게 prompt를 표시합니다**.
- **`syspolicyd`**는 결과를 **`kextd`에 보고합니다**
4. **`kextd`**는 최종적으로 **kernel에 extension 로드를 지시할 수 있습니다**

**`kextd`**를 사용할 수 없는 경우 **`kextutil`**이 동일한 checks를 수행할 수 있습니다.

### Enumeration & management (loaded kexts)

`kextstat`는 historical tool이었지만 최근 macOS releases에서는 **deprecated**되었습니다. modern interface는 **`kmutil`**입니다:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
이전 syntax도 여전히 reference 용도로 사용할 수 있습니다:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect`는 **Kernel Collection (KC)의 내용을 dump**하거나 kext가 모든 symbol dependencies를 resolve하는지 확인하는 데에도 활용할 수 있습니다:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Kernel extensions는 `/System/Library/Extensions/`에 있어야 하지만, 이 폴더로 이동해도 **어떤 binary도 찾을 수 없습니다**. 이는 **kernelcache** 때문이며, 하나의 `.kext`를 reverse하려면 이를 얻을 방법을 찾아야 합니다.

**kernelcache**는 필수 device **drivers** 및 **kernel extensions**와 함께 사전 컴파일되고 사전 링크된 **XNU kernel 버전**입니다. **압축된** 형식으로 저장되며 boot-up 과정에서 memory로 압축 해제됩니다. kernelcache는 실행 가능한 kernel 버전과 중요한 drivers를 미리 준비하여 **더 빠른 boot time**을 지원합니다. 이를 통해 boot 시 이러한 component를 동적으로 loading하고 linking하는 데 소요되는 time과 resources를 줄일 수 있습니다.

kernelcache의 주요 이점은 **loading speed**와 모든 module이 prelinked되어 있다는 점입니다(load time impediment 없음). 또한 모든 module이 prelinked되면 KXLD를 memory에서 제거할 수 있으므로 **XNU는 새로운 KEXT를 load할 수 없습니다.**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool은 Apple의 AEA(A​​pple Encrypted Archive / AEA asset) container를 decrypt합니다. 이는 Apple이 OTA asset 및 일부 IPSW piece에 사용하는 encrypted container format이며, 제공된 aastuff tools로 extract할 수 있는 underlying `.dmg`/asset archive를 생성할 수 있습니다.


### Local Kerlnelcache

iOS에서는 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**에 있으며, macOS에서는 다음 명령으로 찾을 수 있습니다: **`find / -name "kernelcache" 2>/dev/null`** \
제 macOS에서는 다음 위치에서 찾았습니다:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

여기에서 [**symbols가 포함된 version 14의 kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en)도 확인할 수 있습니다.

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format은 Apple이 iOS 및 macOS device에서 **firmware** component(예: **kernelcache**)를 안전하게 **storing하고 verifying**하기 위해 사용하는 container format입니다. IMG4 format에는 header와 여러 tag가 포함되어 있으며, 실제 payload(kernel 또는 bootloader 등), signature, manifest properties 집합 등 서로 다른 data piece를 encapsulate합니다. 이 format은 cryptographic verification을 지원하므로 device가 firmware component를 실행하기 전에 해당 component의 authenticity와 integrity를 확인할 수 있습니다.

일반적으로 다음 component로 구성됩니다:

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

Kernelcache를 Decompress합니다:
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
#### 커널의 Disarm symbols

**`Disarm`**를 사용하면 matcher를 통해 kernelcache의 함수를 symbolicate할 수 있습니다. 이러한 matcher는 disarm이 바이너리 내부의 함수, 인자 및 panic/log 문자열을 인식하고 자동으로 symbolicate하는 방법을 알려주는 간단한 패턴 규칙(텍스트 줄)입니다.

기본적으로 함수가 사용하는 문자열을 지정하면 disarm이 해당 문자열을 찾아 **symbolicate**합니다.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# disarm이 filesets를 추출한 /tmp/extracted로 이동
disarm -e filesets kernelcache.release.d23 # 항상 /tmp/extracted에 추출
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # xnu.matchers는 실제로 matchers가 포함된 파일임에 유의
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
# ipsw tool 설치
brew install blacktop/tap/ipsw

# IPSW에서 kernelcache만 추출
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# 다음과 같은 결과를 확인할 수 있습니다:
#   out/Firmware/kernelcache.release.iPhoneXX
#   또는 IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# IMG4 payload를 얻은 경우:
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
# 모든 extensions 나열
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox 추출
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# 모두 추출
kextex_all kernelcache.release.iphone14.e

# symbols에 대해 extension 확인
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
# 최신 panic을 위한 symbolication bundle 생성
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
# kext의 load address 식별
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
