# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Kernel extensions(Kexts)은 **`.kext`** 확장자를 가진 **패키지**이며, **macOS kernel space에 직접 로드**되어 주 운영 체제에 추가 기능을 제공합니다.

### Deprecation 상태 및 DriverKit / System Extensions
**macOS Catalina (10.15)**부터 Apple은 대부분의 레거시 KPI를 *deprecated*로 표시하고 **user-space**에서 실행되는 **System Extensions & DriverKit** framework를 도입했습니다. **macOS Big Sur (11)**부터 운영 체제는 deprecated KPI에 의존하는 third-party kexts의 로드를 거부합니다. 단, 시스템이 **Reduced Security** 모드로 부팅된 경우는 예외입니다. Apple Silicon에서 kexts를 활성화하려면 사용자가 추가로 다음을 수행해야 합니다.

1. **Recovery**로 재부팅 → *Startup Security Utility*.
2. **Reduced Security**를 선택하고 **“Allow user management of kernel extensions from identified developers”**를 체크합니다.
3. 재부팅한 후 **System Settings → Privacy & Security**에서 kext를 승인합니다.

DriverKit/System Extensions로 작성된 User-land drivers는 crash 또는 memory corruption이 kernel space가 아니라 sandbox된 process 내로 제한되므로 **attack surface를 크게 줄입니다**.<sup>[[1]](#references)</sup>

> 📝 macOS Sequoia (15)부터 Apple은 여러 레거시 networking 및 USB KPI를 완전히 제거했습니다. vendor가 사용할 수 있는 유일한 forward-compatible solution은 System Extensions로 migrate하는 것입니다.

### Requirements

당연히 이는 매우 강력한 기능이므로 **kernel extension을 로드하는 과정은 복잡**합니다. kernel extension이 로드되려면 다음 **requirements**를 충족해야 합니다.

- **recovery mode에 진입할 때**, kernel **extensions의 로드가 허용**되어 있어야 합니다.

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- kernel extension은 **kernel code signing certificate로 signed**되어야 하며, 이 certificate는 **Apple만 발급**할 수 있습니다. Apple은 해당 company와 필요한 이유를 상세히 검토합니다.
- kernel extension은 또한 **notarized**되어야 하며, Apple은 이를 malware에 대해 검사할 수 있습니다.
- 그런 다음 **root** user만 **kernel extension을 로드**할 수 있으며, package 내부의 files는 **root 소유**여야 합니다.
- upload 과정에서 package는 보호된 non-root location인 `/Library/StagedExtensions`에 준비되어야 합니다(`com.apple.rootless.storage.KernelExtensionManagement` grant 필요).
- 마지막으로 로드를 시도하면 user는 [**confirmation request를 받게 되며**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html), 이를 승인한 경우 computer를 **restart**해야 로드됩니다.

### Loading process

Catalina에서는 다음과 같았습니다. **verification** process가 userland에서 수행된다는 점이 흥미롭습니다. 그러나 **`com.apple.private.security.kext-management`** grant가 있는 applications만 **kernel에 extension 로드를 요청**할 수 있습니다: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli가 extension 로드를 위한 **verification** process를 **시작**합니다.
- **Mach service**를 사용해 전송하여 **`kextd`**와 통신합니다.
2. **`kextd`**는 **signature**와 같은 여러 항목을 확인합니다.
- extension을 **로드할 수 있는지** **확인**하기 위해 **`syspolicyd`**와 통신합니다.
3. extension이 이전에 로드된 적이 없다면 **`syspolicyd`**가 **user에게 prompt를 표시**합니다.
- **`syspolicyd`**는 결과를 **`kextd`**에 보고합니다.
4. 마지막으로 **`kextd`**가 **kernel에 extension을 로드하도록 알릴** 수 있게 됩니다.

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
이전 구문은 여전히 참고용으로 사용할 수 있습니다:
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
> Kernel extensions는 `/System/Library/Extensions/`에 있어야 하지만, 이 폴더로 이동해도 **바이너리를 찾을 수 없습니다**. 이는 **kernelcache** 때문이며, 하나의 `.kext`를 reverse하려면 이를 확보할 방법을 찾아야 합니다.

**kernelcache**는 필수 디바이스 **drivers**와 **kernel extensions**가 포함된 **XNU kernel의 사전 컴파일 및 사전 링크된 버전**입니다. **압축된** 형식으로 저장되며, boot-up 과정에서 메모리로 압축 해제됩니다. kernelcache는 즉시 실행할 수 있는 kernel 및 핵심 drivers를 미리 준비해 두어 **더 빠른 boot time**을 지원합니다. 따라서 boot time에 이러한 구성 요소를 동적으로 로드하고 링크하는 데 소요되는 시간과 리소스를 줄일 수 있습니다.

kernelcache의 주요 이점은 **loading 속도**와 모든 module이 사전 링크되어 있다는 점입니다(load time impediment 없음). 또한 모든 module이 사전 링크되면 KXLD를 메모리에서 제거할 수 있으므로 **XNU는 새로운 KEXT를 로드할 수 없습니다.**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool은 Apple의 AEA (Apple Encrypted Archive / AEA asset) container를 decrypt합니다. 이는 Apple이 OTA asset 및 일부 IPSW 구성 요소에 사용하는 encrypted container format이며, 제공된 aastuff tools로 extract할 수 있는 underlying .dmg/asset archive를 생성할 수 있습니다.


### Local Kernelcache

iOS에서는 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**에 있으며, macOS에서는 다음 명령으로 찾을 수 있습니다: **`find / -name "kernelcache" 2>/dev/null`** \
제 macOS 환경에서는 다음 위치에서 찾았습니다:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

여기에서 [**symbols가 포함된 version 14의 kernelcache**](https://x.com/tihmstar/status/1295814618242318337?lang=en)도 찾을 수 있습니다.

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format은 Apple이 iOS 및 macOS devices에서 **firmware** 구성 요소(예: **kernelcache**)를 안전하게 **저장하고 검증**하기 위해 사용하는 container format입니다. IMG4 format에는 header와 여러 tag가 포함되어 있으며, 이 tag는 실제 payload(예: kernel 또는 bootloader), signature, manifest properties 집합 등 서로 다른 data 조각을 캡슐화합니다. 이 format은 cryptographic verification을 지원하므로, device는 firmware 구성 요소를 실행하기 전에 해당 구성 요소의 authenticity와 integrity를 확인할 수 있습니다.

일반적으로 다음 구성 요소로 이루어집니다:

- **Payload (IM4P)**:
- 주로 compressed (LZFSE4, LZSS, …)
- Optionally encrypted
- **Manifest (IM4M)**:
- Signature 포함
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- APNonce라고도 함
- 일부 update의 replay 방지
- OPTIONAL: 일반적으로 찾을 수 없음

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
#### 커널용 Disarm 심볼

**`Disarm`**를 사용하면 matcher를 통해 kernelcache의 함수를 symbolicate할 수 있습니다. 이러한 matcher는 disarm이 바이너리 내부의 함수, 인자 및 panic/log 문자열을 인식하고 자동으로 symbolicate하는 방법을 알려주는 간단한 패턴 규칙(텍스트 줄)입니다.

기본적으로 함수가 사용하는 문자열을 지정하면 disarm이 해당 문자열을 찾아 **symbolicate**합니다.

[https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html)의 **`Matchers`** 섹션에서 일부 `xnu.matchers`를 확인할 수 있습니다. 직접 matcher를 만들 수도 있습니다.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### 다운로드

**IPSW (iPhone/iPad Software)**는 기기 복원, 업데이트 및 전체 firmware bundle에 사용되는 Apple의 firmware package format입니다. 여기에는 **kernelcache**가 포함되어 있습니다.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases)에서 모든 kernel debug kits를 확인할 수 있습니다. 이를 다운로드하고 mount한 다음 [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) 도구로 열어 **`.kext`** 폴더에 접근한 후 **extract**할 수 있습니다.

다음 명령으로 symbols를 확인합니다:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Apple은 때때로 **symbols**가 포함된 **kernelcache**를 release합니다. 해당 페이지의 링크를 따라가면 **symbols**가 포함된 일부 firmware를 download할 수 있습니다. firmware에는 다른 파일들과 함께 **kernelcache**가 포함되어 있습니다.

kernel cache를 **extract**하려면 다음을 실행할 수 있습니다:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
파일을 **extract**하는 또 다른 방법은 먼저 확장자를 `.ipsw`에서 `.zip`으로 변경한 후 **unzip**하는 것입니다.

firmware를 extract하면 다음과 같은 파일을 얻게 됩니다: **`kernelcache.release.iphone14`**. 이 파일은 **IMG4** 형식이며, 다음 도구를 사용해 흥미로운 정보를 extract할 수 있습니다:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
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
### kernelcache 검사

다음을 사용하여 kernelcache에 symbols가 있는지 확인합니다.
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
이를 통해 이제 **모든 확장 프로그램을 추출**하거나 **관심 있는 확장 프로그램 하나를 추출**할 수 있습니다:
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
## 최근 취약점 및 exploitation 기법

| 연도 | CVE | 요약 |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`**의 로직 결함으로 인해 *root* attacker가 악성 file-system bundle을 등록할 수 있었으며, 최종적으로 **서명되지 않은 kext**가 로드되어 **System Integrity Protection (SIP)**을 **bypass**하고 지속적인 rootkit을 구축할 수 있었습니다. macOS 14.2 / 15.2에서 패치되었습니다. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | `com.apple.rootless.install` entitlement가 있는 installation daemon을 악용하여 임의의 post-install script를 실행하고, SIP를 비활성화하며, 임의의 kext를 로드할 수 있었습니다. <sup>[[3]](#references)</sup> |

**red-teamers를 위한 핵심 사항**

1. **Disk Arbitration, Installer 또는 Kext Management와 상호작용하는 entitlement 보유 daemon (`codesign -dvv /path/bin | grep entitlements`)을 찾으십시오.**
2. **SIP bypass를 악용하면 거의 항상 kext를 로드할 수 있는 권한이 부여되며 → kernel code execution으로 이어집니다.**

**방어 팁**

*SIP를 활성화된 상태로 유지하고*, Apple이 아닌 binary에서 발생하는 `kmutil load`/`kmutil create -n aux` 호출을 모니터링하며 `/Library/Extensions`에 대한 모든 write를 alert하십시오. Endpoint Security event인 `ES_EVENT_TYPE_NOTIFY_KEXTLOAD`는 거의 실시간에 가까운 visibility를 제공합니다.

## macOS kernel 및 kext 디버깅

Apple이 권장하는 workflow는 실행 중인 build와 일치하는 **Kernel Debug Kit (KDK)**를 빌드한 다음, **KDP (Kernel Debugging Protocol)** network session을 통해 **LLDB**를 연결하는 것입니다.

### panic에 대한 일회성 로컬 debug
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### 다른 Mac에서 실시간 원격 디버깅

1. 대상 machine에 맞는 정확한 **KDK** version을 다운로드하고 설치합니다.
2. **USB-C 또는 Thunderbolt cable**로 대상 Mac과 host Mac을 연결합니다.
3. **대상**에서:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. **호스트**에서:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### 특정 로드된 kext에 LLDB 연결
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP는 **read-only** 인터페이스만 노출합니다. 동적 계측을 수행하려면 디스크상의 binary를 patch하거나, **kernel function hooking** (예: `mach_override`)을 활용하거나, 완전한 read/write를 위해 driver를 **hypervisor**로 migrate해야 합니다.

## 참고 문헌

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
