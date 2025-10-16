# macOS 커널 확장(Kernel Extensions) & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Kernel extensions (Kexts)는 **`.kext`** 확장자를 가진 **패키지**로, **macOS 커널 공간에 직접 로드되어** 운영체제에 추가 기능을 제공합니다.

### 사용 중단 상태 & DriverKit / System Extensions
macOS Catalina (10.15)부터 Apple은 대부분의 레거시 KPI를 *deprecated*로 표시하고, **user-space**에서 동작하는 **System Extensions & DriverKit** 프레임워크를 도입했습니다. macOS Big Sur (11)부터 운영체제는 레거시 KPI에 의존하는 서드파티 kext를, 시스템이 **Reduced Security** 모드로 부팅되지 않는 한 *로딩을 거부*합니다. Apple Silicon에서는 kext를 활성화하려면 추가로 사용자가 다음을 수행해야 합니다:

1. Recovery로 재부팅 → *Startup Security Utility*를 엽니다.
2. **Reduced Security**를 선택하고 **“Allow user management of kernel extensions from identified developers”**를 체크합니다.
3. 재부팅하고 **System Settings → Privacy & Security**에서 kext를 승인합니다.

DriverKit/System Extensions로 작성된 유저랜드 드라이버는 충돌이나 메모리 손상이 커널 공간이 아닌 샌드박스된 프로세스에 국한되므로 공격 표면을 크게 줄입니다.

> 📝 From macOS Sequoia (15) Apple has removed several legacy networking and USB KPIs entirely – the only forward-compatible solution for vendors is to migrate to System Extensions.

### 요구사항

강력한 만큼 커널 확장을 로드하는 것은 **복잡합니다**. 커널 확장이 로드되기 위해 충족해야 하는 **요구사항**은 다음과 같습니다:

- 복구 모드로 진입할 때, 커널 **확장이 로드될 수 있도록 허용**되어야 합니다:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- 커널 확장은 반드시 **커널 코드 서명 인증서**로 **서명**되어야 하며, 이 인증서는 **Apple만** 발급할 수 있습니다. Apple은 회사와 해당 확장이 필요한 이유를 상세히 검토합니다.
- 커널 확장은 또한 **notarized**되어야 하며, Apple이 이를 악성코드 여부로 검사할 수 있습니다.
- 그런 다음, 커널 확장을 **로드할 수 있는 권한은 root 사용자**에게 있으며 패키지 내부의 파일들은 **root 소유**여야 합니다.
- 업로드 과정 중에는 패키지가 **비-root에 보호된 위치**로 준비되어야 합니다: `/Library/StagedExtensions` (`com.apple.rootless.storage.KernelExtensionManagement` 권한 필요).
- 마지막으로 로드 시도 시 사용자는 [**확인 요청을 받게 됩니다**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) — 승인되면 컴퓨터를 **재시동**해야 로드됩니다.

### 로딩 프로세스

Catalina에서는 다음과 같았습니다. 흥미로운 점은 **검증 과정이 userland에서 수행된다는 것**입니다. 다만, **`com.apple.private.security.kext-management`** 권한을 가진 애플리케이션만이 커널에 확장 로드를 요청할 수 있습니다: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI가 확장 로드를 위한 **검증** 프로세스를 **시작**합니다.
- 이 과정에서 **`kextd`**와 **Mach service**를 통해 통신합니다.
2. **`kextd`**는 서명 등 여러 항목을 확인합니다.
- 확장을 **로드할 수 있는지** 확인하기 위해 **`syspolicyd`**와 통신합니다.
3. 확장이 이전에 로드된 적이 없다면 **`syspolicyd`**는 **사용자에게 프롬프트**를 표시합니다.
- **`syspolicyd`**는 결과를 **`kextd`**에 보고합니다.
4. 최종적으로 **`kextd`**가 커널에 확장을 로드하도록 지시할 수 있습니다.

만약 **`kextd`**가 사용 불가능한 경우, **`kextutil`**이 동일한 검사를 수행할 수 있습니다.

### 열거 및 관리 (로딩된 kexts)

`kextstat`는 과거의 도구였지만 최근 macOS 릴리스에서는 **사용 중단(deprecated)** 되었습니다. 현대적인 인터페이스는 **`kmutil`** 입니다:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
이전 문법은 참고용으로 여전히 제공됩니다:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect`는 또한 **Kernel Collection (KC)의 내용을 덤프**하거나 kext가 모든 심볼 종속성을 해결하는지 확인하는 데 활용될 수 있습니다:
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


### Local Kerlnelcache

In iOS it's located in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS you can find it with: **`find / -name "kernelcache" 2>/dev/null`** \
In my case in macOS I found it in:

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
#### Disarm symbols for the kernel

**`Disarm`**은 matchers를 사용하여 kernelcache의 함수들을 symbolicate할 수 있게 해준다. 이 matchers들은 단순한 패턴 규칙(텍스트 라인)으로, binary 내부의 functions, arguments and panic/log strings를 disarm이 어떻게 인식하고 auto-symbolicate할지 알려준다.

간단히 말해, 함수가 사용하는 문자열을 지정하면 disarm이 그것을 찾아서 **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# disarm가 filesets를 추출한 /tmp/extracted로 이동
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
# ipsw 도구 설치
brew install blacktop/tap/ipsw

# IPSW에서 kernelcache만 추출
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# 다음과 같은 결과를 얻을 것입니다:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

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
# 모든 확장 목록
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox 추출
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# 모두 추출
kextex_all kernelcache.release.iphone14.e

# 확장의 심볼 확인
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
# 최신 panic에 대한 심볼리케이션 번들 생성
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
# kext의 로드 주소 확인
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# 연결
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
