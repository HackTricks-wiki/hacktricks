# macOS 커널 확장(Kernel Extensions) & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Kernel extensions (Kexts)는 `.kext` 확장자를 가진 패키지로, macOS 커널 공간에 직접 로드되어 운영 체제에 추가 기능을 제공합니다.

### 지원 중단 상태 & DriverKit / System Extensions
macOS Catalina (10.15)부터 Apple은 대부분의 레거시 KPI를 deprecated로 표시하고 user-space에서 실행되는 System Extensions & DriverKit 프레임워크를 도입했습니다. macOS Big Sur (11)부터 운영 체제는 Reduced Security 모드로 부팅되지 않은 한 deprecated KPI에 의존하는 타사 kext의 로드를 거부합니다. Apple Silicon에서는 kext를 활성화하려면 추가로 사용자가 다음을 수행해야 합니다:

1. Reboot into **Recovery** → *Startup Security Utility*.
2. Select **Reduced Security** and tick **“Allow user management of kernel extensions from identified developers”**.
3. Reboot and approve the kext from **System Settings → Privacy & Security**.

DriverKit/System Extensions로 작성된 user-land 드라이버는 충돌이나 메모리 손상이 커널 공간이 아닌 샌드박스된 프로세스에 국한되므로 공격 표면을 크게 감소시킵니다.

> 📝 macOS Sequoia (15)부터 Apple은 몇몇 레거시 네트워킹 및 USB KPI를 완전히 제거했습니다 – 벤더가 앞으로 호환성을 유지하려면 System Extensions로 이전하는 것이 유일한 해결책입니다.

### 요구사항

이 기능은 매우 강력하기 때문에 커널 확장을 로드하는 것은 복잡합니다. 커널 확장이 로드되기 위해 충족해야 하는 요구사항은 다음과 같습니다:

- 복구 모드로 진입할 때, 커널 확장이 로드되도록 허용되어야 합니다:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- 커널 확장은 kernel code signing certificate로 서명되어야 하며, 이는 Apple만 발급할 수 있습니다. Apple은 회사와 필요한 이유를 상세히 검토합니다.
- 커널 확장은 또한 notarized되어야 하며, Apple은 이를 악성코드 여부 확인에 활용할 수 있습니다.
- 커널 확장을 로드할 수 있는 권한은 root 사용자에게 있으며, 패키지 내부의 파일들은 root 소유여야 합니다.
- 업로드 과정에서는 패키지가 보호된 non-root 위치에 준비되어야 합니다: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant).
- 마지막으로, 로드를 시도할 때 사용자는 [receive a confirmation request](https://developer.apple.com/library/archive/technotes/tn2459/_index.html)를 받고, 승인이 되면 로드하기 위해 컴퓨터를 재시동해야 합니다.

### 로딩 과정

Catalina에서는 다음과 같았습니다: 검증 과정이 userland에서 발생한다는 점이 흥미롭습니다. 하지만 `com.apple.private.security.kext-management` grant를 가진 애플리케이션만이 커널에 확장 로드를 요청할 수 있습니다: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. `kextutil` cli가 확장 로드를 위한 검증 절차를 시작합니다.
- `kextutil`은 Mach 서비스로 통신하여 `kextd`와 대화합니다.
2. `kextd`는 서명 등 여러 항목을 검사합니다.
- `kextd`는 확장을 로드할 수 있는지 확인하기 위해 `syspolicyd`와 통신합니다.
3. `syspolicyd`는 확장이 이전에 로드된 적이 없다면 사용자에게 프롬프트를 표시합니다.
- `syspolicyd`는 결과를 `kextd`에 보고합니다.
4. `kextd`는 최종적으로 커널에 확장을 로드하라고 지시할 수 있습니다.

`kextd`가 없을 경우 `kextutil`이 동일한 검사를 수행할 수 있습니다.

### 열거 및 관리 (loaded kexts)

`kextstat`는 역사적인 도구였지만 최근 macOS 릴리스에서는 deprecated되었습니다. 현대적인 인터페이스는 `kmutil`입니다:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
이전 구문은 참조용으로 여전히 사용할 수 있습니다:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect`는 **Kernel Collection (KC)의 내용을 덤프**하거나 kext가 모든 심볼 종속성을 해결하는지 확인하는 데에도 사용할 수 있다:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> `/System/Library/Extensions/`에 kernel extensions가 있어야 하지만, 이 폴더에 가도 **바이너리를 찾을 수 없습니다**. 이는 **kernelcache** 때문이며, `.kext`를 리버스하려면 이를 얻는 방법을 찾아야 합니다.

**kernelcache**는 XNU 커널의 **사전 컴파일되고 사전 링크된 버전**으로, 필수 디바이스 **drivers**와 **kernel extensions**가 함께 포함되어 있습니다. 이는 **압축된** 형태로 저장되어 부팅 과정에서 메모리로 압축이 풀립니다. kernelcache는 커널과 중요한 드라이버의 즉시 실행 가능한 버전을 제공하여 동적으로 이 컴포넌트들을 부팅 시 로드하고 링크하는 데 소요되는 시간과 자원을 줄여 **더 빠른 부팅 시간**을 가능하게 합니다.

kernelcache의 주요 장점은 **로딩 속도**와 모든 모듈이 사전 링크되어 있다는 점(로딩 시간 지연 없음)입니다. 그리고 모든 모듈이 사전 링크된 이후에는 KXLD를 메모리에서 제거할 수 있어 **XNU가 새로운 KEXTs를 로드할 수 없습니다.**

> [!TIP]
> [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) 도구는 Apple의 AEA (Apple Encrypted Archive / AEA asset) 컨테이너를 복호화합니다 — Apple이 OTA 자산 및 일부 IPSW 조각에 사용하는 암호화된 컨테이너 포맷 — 그리고 제공된 aastuff 도구로 추출할 수 있는 기본 .dmg/asset 아카이브를 생성할 수 있습니다.

### 로컬 kernelcache

iOS에서는 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**에 위치하고, macOS에서는 다음으로 찾을 수 있습니다: **`find / -name "kernelcache" 2>/dev/null`** \
제 경우 macOS에서 찾은 경로는 다음과 같습니다:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

또한 여기에서 [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en)를 확인할 수 있습니다.

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 파일 포맷은 Apple이 iOS와 macOS 장치에서 펌웨어 구성요소(예: **kernelcache**)를 안전하게 **저장하고 검증**하기 위해 사용하는 컨테이너 포맷입니다. IMG4 포맷은 헤더와 실제 페이로드(커널이나 부트로더 등), 서명, 매니페스트 속성 집합 등을 캡슐화하는 여러 태그를 포함합니다. 이 포맷은 암호화 검증을 지원하여 장치가 펌웨어 구성요소의 정당성과 무결성을 실행 전에 확인할 수 있게 합니다.

보통 다음 구성요소로 이루어져 있습니다:

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

Kernelcache 압축 해제:
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

**`Disarm`**는 matchers를 사용해 kernelcache에서 함수를 symbolicate할 수 있게 해줍니다.

이 matchers는 단순한 패턴 규칙(텍스트 라인)으로, disarm에게 binary 내부의 functions, arguments & panic/log strings을 어떻게 recognise & auto-symbolicate할지 알려줍니다.

즉, 함수가 사용하는 문자열을 지정하면 disarm이 이를 찾아 **symbolicate it**.
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

# 다음과 유사한 결과가 나와야 합니다:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# IMG4 payload를 받았다면:
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
# 모든 확장 나열
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
# kext의 로드 주소 식별
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# 연결
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
