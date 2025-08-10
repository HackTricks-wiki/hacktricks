# macOS 커널 확장 및 디버깅

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

커널 확장(Kexts)은 **`.kext`** 확장자를 가진 **패키지**로, **macOS 커널 공간에 직접 로드**되어 운영 체제에 추가 기능을 제공합니다.

### 사용 중단 상태 및 DriverKit / 시스템 확장
**macOS Catalina (10.15)**부터 Apple은 대부분의 레거시 KPI를 *사용 중단*으로 표시하고 **시스템 확장 및 DriverKit** 프레임워크를 도입하여 **사용자 공간**에서 실행됩니다. **macOS Big Sur (11)**부터 운영 체제는 사용 중단된 KPI에 의존하는 서드파티 kext를 *로드하지 않도록 거부*합니다. Apple Silicon에서는 kext를 활성화하려면 사용자가 추가로:

1. **복구**로 재부팅 → *시작 보안 유틸리티*.
2. **감소된 보안**을 선택하고 **“확인된 개발자의 커널 확장 관리 허용”**을 체크합니다.
3. 재부팅하고 **시스템 설정 → 개인 정보 보호 및 보안**에서 kext를 승인합니다.

DriverKit/시스템 확장으로 작성된 사용자 공간 드라이버는 충돌이나 메모리 손상이 커널 공간이 아닌 샌드박스화된 프로세스에 국한되므로 **공격 표면을 크게 줄입니다**.

> 📝 macOS Sequoia (15)부터 Apple은 여러 레거시 네트워킹 및 USB KPI를 완전히 제거했습니다. 공급업체를 위한 유일한 호환 가능한 솔루션은 시스템 확장으로 마이그레이션하는 것입니다.

### 요구 사항

명백히, 이것은 매우 강력하여 **커널 확장을 로드하는 것이 복잡합니다**. 커널 확장이 로드되기 위해 충족해야 하는 **요구 사항**은 다음과 같습니다:

- **복구 모드**에 **진입할 때**, 커널 **확장이 로드될 수 있도록 허용되어야** 합니다:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- 커널 확장은 **커널 코드 서명 인증서**로 **서명되어야** 하며, 이는 **Apple에 의해 부여**될 수 있습니다. 회사와 필요 이유를 자세히 검토할 것입니다.
- 커널 확장은 또한 **노타리제이션**되어야 하며, Apple은 이를 악성 소프트웨어에 대해 검사할 수 있습니다.
- 그런 다음, **루트** 사용자만이 **커널 확장을 로드할 수** 있으며 패키지 내의 파일은 **루트에 속해야** 합니다.
- 업로드 과정 중 패키지는 **보호된 비루트 위치**에 준비되어야 합니다: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant).
- 마지막으로, 로드하려고 시도할 때 사용자는 [**확인 요청을 받게**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) 되며, 수락되면 컴퓨터는 **재시작**되어야 합니다.

### 로드 프로세스

Catalina에서는 다음과 같았습니다: **검증** 프로세스가 **사용자 공간**에서 발생한다는 점이 흥미롭습니다. 그러나 **`com.apple.private.security.kext-management`** 권한이 있는 애플리케이션만이 **커널에 확장을 로드하도록 요청할 수** 있습니다: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI가 **확장을 로드하기 위한 검증** 프로세스를 **시작**합니다.
- **`kextd`**와 **Mach 서비스**를 사용하여 통신합니다.
2. **`kextd`**는 **서명**과 같은 여러 사항을 확인합니다.
- **`syspolicyd`**와 통신하여 확장이 **로드될 수 있는지 확인**합니다.
3. **`syspolicyd`**는 확장이 이전에 로드되지 않았다면 **사용자에게 요청**합니다.
- **`syspolicyd`**는 결과를 **`kextd`**에 보고합니다.
4. **`kextd`**는 마지막으로 **커널에 확장을 로드하도록 지시**할 수 있습니다.

**`kextd`**가 사용 불가능한 경우, **`kextutil`**이 동일한 검사를 수행할 수 있습니다.

### 열거 및 관리 (로드된 kexts)

`kextstat`는 역사적인 도구였지만 최근 macOS 릴리스에서 **사용 중단**되었습니다. 현대 인터페이스는 **`kmutil`**입니다:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
구식 구문은 참조용으로 여전히 사용할 수 있습니다:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect`는 **커널 컬렉션(KC)의 내용을 덤프하거나** kext가 모든 심볼 의존성을 해결하는지 확인하는 데에도 활용될 수 있습니다:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> 비록 커널 확장이 `/System/Library/Extensions/`에 있을 것으로 예상되지만, 이 폴더에 가면 **이진 파일을 찾을 수 없습니다**. 이는 **kernelcache** 때문이며, 하나의 `.kext`를 리버스 엔지니어링하기 위해서는 이를 얻는 방법을 찾아야 합니다.

**kernelcache**는 **XNU 커널의 미리 컴파일되고 미리 링크된 버전**으로, 필수 장치 **드라이버**와 **커널 확장**이 포함되어 있습니다. 이는 **압축된** 형식으로 저장되며 부팅 과정 중 메모리로 압축 해제됩니다. kernelcache는 커널과 중요한 드라이버의 실행 준비가 된 버전을 제공하여 **빠른 부팅 시간**을 촉진하며, 부팅 시 이러한 구성 요소를 동적으로 로드하고 링크하는 데 소요되는 시간과 자원을 줄입니다.

### Local Kerlnelcache

iOS에서는 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**에 위치하고, macOS에서는 다음 명령어로 찾을 수 있습니다: **`find / -name "kernelcache" 2>/dev/null`** \
제 경우 macOS에서 다음 위치에서 찾았습니다:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 파일 형식은 Apple이 iOS 및 macOS 장치에서 펌웨어 구성 요소(예: **kernelcache**)를 안전하게 **저장하고 검증하기 위해** 사용하는 컨테이너 형식입니다. IMG4 형식은 헤더와 여러 태그를 포함하여 실제 페이로드(예: 커널 또는 부트로더), 서명 및 일련의 매니페스트 속성을 캡슐화합니다. 이 형식은 암호화 검증을 지원하여 장치가 실행하기 전에 펌웨어 구성 요소의 진위와 무결성을 확인할 수 있도록 합니다.

일반적으로 다음 구성 요소로 구성됩니다:

- **Payload (IM4P)**:
- 종종 압축됨 (LZFSE4, LZSS, …)
- 선택적으로 암호화됨
- **Manifest (IM4M)**:
- 서명 포함
- 추가 키/값 사전
- **Restore Info (IM4R)**:
- APNonce로도 알려짐
- 일부 업데이트의 재생을 방지
- 선택 사항: 일반적으로 발견되지 않음

Kernelcache 압축 해제:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### 다운로드

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases)에서 모든 커널 디버그 키트를 찾을 수 있습니다. 다운로드하여 마운트하고 [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) 도구로 열어 **`.kext`** 폴더에 접근하고 **추출**할 수 있습니다.

기호를 확인하려면:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

가끔 Apple은 **kernelcache**와 **symbols**를 함께 배포합니다. 이러한 페이지의 링크를 따라가면 심볼이 포함된 일부 펌웨어를 다운로드할 수 있습니다. 펌웨어에는 다른 파일들 중에 **kernelcache**가 포함되어 있습니다.

파일을 **추출**하려면 `.ipsw` 확장자를 `.zip`으로 변경한 후 **압축을 풉니다**.

펌웨어를 추출한 후에는 **`kernelcache.release.iphone14`**와 같은 파일을 얻게 됩니다. 이 파일은 **IMG4** 형식이며, 다음을 사용하여 흥미로운 정보를 추출할 수 있습니다:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### 커널 캐시 검사

커널 캐시에 기호가 있는지 확인하십시오.
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
이제 우리는 **모든 확장자를 추출**하거나 **관심 있는 확장자를 추출**할 수 있습니다:
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
## 최근 취약점 및 악용 기술

| 연도 | CVE | 요약 |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`**의 논리 결함으로 인해 *root* 공격자가 악성 파일 시스템 번들을 등록할 수 있었고, 이는 궁극적으로 **서명되지 않은 kext**를 로드하여 **시스템 무결성 보호(SIP)**를 우회하고 지속적인 루트킷을 활성화했습니다. macOS 14.2 / 15.2에서 패치됨.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | `com.apple.rootless.install` 권한을 가진 설치 데몬이 임의의 설치 후 스크립트를 실행하고 SIP를 비활성화하며 임의의 kext를 로드하는 데 악용될 수 있었습니다.  |

**레드 팀을 위한 주요 사항**

1. **Disk Arbitration, Installer 또는 Kext Management와 상호작용하는 권한이 있는 데몬(`codesign -dvv /path/bin | grep entitlements`)을 찾으십시오.**
2. **SIP 우회 악용은 거의 항상 kext를 로드할 수 있는 능력을 부여합니다 → 커널 코드 실행**.

**방어 팁**

*SIP를 활성화 상태로 유지*하고, 비-Apple 바이너리에서 오는 `kmutil load`/`kmutil create -n aux` 호출을 모니터링하며 `/Library/Extensions`에 대한 모든 쓰기에 경고하십시오. 엔드포인트 보안 이벤트 `ES_EVENT_TYPE_NOTIFY_KEXTLOAD`는 거의 실시간 가시성을 제공합니다.

## macOS 커널 및 kext 디버깅

Apple의 권장 워크플로우는 실행 중인 빌드와 일치하는 **커널 디버그 키트(KDK)**를 빌드한 다음 **KDP(커널 디버깅 프로토콜)** 네트워크 세션을 통해 **LLDB**를 연결하는 것입니다.

### 패닉의 원샷 로컬 디버그
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### 다른 Mac에서의 실시간 원격 디버깅

1. 대상 머신에 맞는 정확한 **KDK** 버전을 다운로드 + 설치합니다.
2. **USB-C 또는 Thunderbolt 케이블**로 대상 Mac과 호스트 Mac을 연결합니다.
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
### 특정 로드된 kext에 LLDB 연결하기
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP는 **읽기 전용** 인터페이스만 노출합니다. 동적 계측을 위해서는 디스크에서 바이너리를 패치하거나, **커널 함수 후킹**(예: `mach_override`)을 활용하거나, 드라이버를 **하이퍼바이저**로 마이그레이션하여 전체 읽기/쓰기를 수행해야 합니다.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
