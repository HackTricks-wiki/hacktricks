# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **기본 정보**

**System Integrity Protection (SIP)**는 macOS에서 가장 권한이 높은 사용자조차도 주요 시스템 폴더에 대한 무단 변경을 방지하기 위해 설계된 메커니즘입니다. 이 기능은 보호된 영역에서 파일을 추가, 수정 또는 삭제하는 등의 작업을 제한함으로써 시스템의 무결성을 유지하는 데 중요한 역할을 합니다. SIP에 의해 보호되는 주요 폴더는 다음과 같습니다:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP의 동작을 규정하는 규칙은 **`/System/Library/Sandbox/rootless.conf`**에 위치한 구성 파일에 정의되어 있습니다. 이 파일 내에서 별표(\*)로 접두사가 붙은 경로는 일반적으로 엄격한 SIP 제한의 예외로 표시됩니다.

아래의 예를 고려해 보십시오:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
이 코드 조각은 SIP가 일반적으로 **`/usr`** 디렉토리를 보호하지만, 특정 하위 디렉토리(`/usr/libexec/cups`, `/usr/local`, `/usr/share/man`)에서는 수정이 허용된다는 것을 나타냅니다. 이는 해당 경로 앞에 있는 별표(\*)로 표시됩니다.

디렉토리나 파일이 SIP에 의해 보호되는지 확인하려면 **`ls -lOd`** 명령을 사용하여 **`restricted`** 또는 **`sunlnk`** 플래그의 존재를 확인할 수 있습니다. 예:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
이 경우, **`sunlnk`** 플래그는 `/usr/libexec/cups` 디렉토리 자체가 **삭제될 수 없음을** 나타내지만, 그 안의 파일은 생성, 수정 또는 삭제할 수 있습니다.

반면:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
여기서 **`restricted`** 플래그는 `/usr/libexec` 디렉토리가 SIP에 의해 보호되고 있음을 나타냅니다. SIP로 보호되는 디렉토리에서는 파일을 생성, 수정 또는 삭제할 수 없습니다.

또한, 파일에 **`com.apple.rootless`** 확장 **속성**이 포함되어 있으면 해당 파일도 **SIP에 의해 보호**됩니다.

> [!TIP]
> **Sandbox** 훅 **`hook_vnode_check_setextattr`**는 확장 속성 **`com.apple.rootless`**를 수정하려는 모든 시도를 방지합니다.

**SIP는 다른 루트 작업도 제한합니다**:

- 신뢰할 수 없는 커널 확장 로드
- Apple 서명 프로세스에 대한 작업 포트 가져오기
- NVRAM 변수 수정
- 커널 디버깅 허용

옵션은 비트 플래그로 nvram 변수에 유지됩니다 (`csr-active-config`는 Intel에서, `lp-sip0`는 ARM의 부팅된 장치 트리에서 읽습니다). 플래그는 `csr.sh`의 XNU 소스 코드에서 찾을 수 있습니다:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP 상태

다음 명령어로 시스템에서 SIP가 활성화되어 있는지 확인할 수 있습니다:
```bash
csrutil status
```
SIP를 비활성화해야 하는 경우, 컴퓨터를 복구 모드로 재시작해야 합니다(시작 중 Command+R을 누름). 그런 다음 다음 명령을 실행하십시오:
```bash
csrutil disable
```
SIP을 활성화한 상태로 유지하면서 디버깅 보호를 제거하려면 다음을 사용하면 됩니다:
```bash
csrutil enable --without debug
```
### 기타 제한 사항

- **서명되지 않은 커널 확장(kexts)의 로드를 허용하지 않음**으로써, 검증된 확장만이 시스템 커널과 상호작용하도록 보장합니다.
- **macOS 시스템 프로세스의 디버깅을 방지**하여, 핵심 시스템 구성 요소를 무단 접근 및 수정으로부터 보호합니다.
- **dtrace와 같은 도구의 사용을 억제**하여 시스템 운영의 무결성을 추가로 보호합니다.

[**이 발표에서 SIP 정보에 대해 더 알아보세요**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **SIP 관련 권한**

- `com.apple.rootless.xpc.bootstrap`: launchd 제어
- `com.apple.rootless.install[.heritable]`: 파일 시스템 접근
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT 관리
- `com.apple.rootless.xpc.bootstrap`: XPC 설정 기능
- `com.apple.rootless.xpc.effective-root`: launchd XPC를 통한 루트 접근
- `com.apple.rootless.restricted-block-devices`: 원시 블록 장치 접근
- `com.apple.rootless.internal.installer-equivalent`: 제한 없는 파일 시스템 접근
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAM에 대한 전체 접근
- `com.apple.rootless.storage.label`: 해당 레이블로 com.apple.rootless xattr에 의해 제한된 파일 수정
- `com.apple.rootless.volume.VM.label`: 볼륨에서 VM 스왑 유지

## SIP 우회

SIP를 우회하면 공격자가 다음을 수행할 수 있습니다:

- **사용자 데이터 접근**: 모든 사용자 계정에서 메일, 메시지 및 Safari 기록과 같은 민감한 사용자 데이터를 읽습니다.
- **TCC 우회**: TCC(투명성, 동의 및 제어) 데이터베이스를 직접 조작하여 웹캠, 마이크 및 기타 리소스에 대한 무단 접근을 부여합니다.
- **지속성 확립**: SIP로 보호된 위치에 악성 코드를 배치하여 루트 권한으로도 제거에 저항하도록 만듭니다. 여기에는 악성 코드 제거 도구(MRT)를 변조할 가능성도 포함됩니다.
- **커널 확장 로드**: 추가적인 보호 장치가 있지만, SIP를 우회하면 서명되지 않은 커널 확장을 로드하는 과정이 간소화됩니다.

### 설치 패키지

**Apple의 인증서로 서명된 설치 패키지**는 그 보호를 우회할 수 있습니다. 이는 표준 개발자가 서명한 패키지조차도 SIP로 보호된 디렉토리를 수정하려고 시도하면 차단된다는 것을 의미합니다.

### 존재하지 않는 SIP 파일

하나의 잠재적 허점은 **`rootless.conf`에 지정된 파일이 현재 존재하지 않는 경우** 해당 파일을 생성할 수 있다는 것입니다. 악성 코드는 이를 악용하여 시스템에서 **지속성을 확립**할 수 있습니다. 예를 들어, 악성 프로그램이 `rootless.conf`에 나열되어 있지만 존재하지 않는 경우 `/System/Library/LaunchDaemons`에 .plist 파일을 생성할 수 있습니다.

### com.apple.rootless.install.heritable

> [!CAUTION]
> 권한 **`com.apple.rootless.install.heritable`**는 SIP를 우회할 수 있게 해줍니다.

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

시스템이 코드 서명을 검증한 후 **설치 패키지를 교체하는 것이 가능하다는 것이 발견되었습니다**. 그 후 시스템은 원본 대신 악성 패키지를 설치하게 됩니다. 이러한 작업이 **`system_installd`**에 의해 수행되었기 때문에 SIP를 우회할 수 있게 됩니다.

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

마운트된 이미지나 외부 드라이브에서 패키지가 설치된 경우 **설치 프로그램**이 **해당 파일 시스템**에서 바이너리를 **실행**하게 되어 **`system_installd`**가 임의의 바이너리를 실행하게 됩니다.

#### CVE-2021-30892 - Shrootless

[**이 블로그 게시물의 연구자들**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)은 macOS의 시스템 무결성 보호(SIP) 메커니즘에서 'Shrootless' 취약점을 발견했습니다. 이 취약점은 **`system_installd`** 데몬을 중심으로 하며, 이 데몬은 **`com.apple.rootless.install.heritable`**라는 권한을 가지고 있어 자식 프로세스가 SIP의 파일 시스템 제한을 우회할 수 있게 해줍니다.

**`system_installd`** 데몬은 **Apple**에 의해 서명된 패키지를 설치합니다.

연구자들은 Apple 서명 패키지(.pkg 파일)의 설치 중에 **`system_installd`**가 패키지에 포함된 모든 **post-install** 스크립트를 **실행**한다는 것을 발견했습니다. 이러한 스크립트는 기본 셸인 **`zsh`**에 의해 실행되며, 존재하는 경우 **`/etc/zshenv`** 파일에서 명령을 자동으로 **실행**합니다. 이 동작은 공격자에 의해 악용될 수 있습니다: 악성 **`/etc/zshenv`** 파일을 생성하고 **`system_installd`가 `zsh`를 호출할 때** 임의의 작업을 수행할 수 있습니다.

게다가 **`/etc/zshenv`**는 SIP 우회뿐만 아니라 일반적인 공격 기법으로도 사용될 수 있다는 것이 발견되었습니다. 각 사용자 프로필에는 `~/.zshenv` 파일이 있으며, 이는 `/etc/zshenv`와 동일하게 동작하지만 루트 권한이 필요하지 않습니다. 이 파일은 `zsh`가 시작될 때마다 트리거되는 지속성 메커니즘으로 사용되거나 권한 상승 메커니즘으로 사용될 수 있습니다. 관리 사용자가 `sudo -s` 또는 `sudo <command>`를 사용하여 루트로 상승하면 `~/.zshenv` 파일이 트리거되어 루트로 상승하게 됩니다.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)에서 **`system_installd`** 프로세스가 여전히 악용될 수 있다는 것이 발견되었습니다. 이는 **`/tmp`** 내의 SIP로 보호된 임의의 이름의 폴더에 **post-install 스크립트**를 넣기 때문입니다. 문제는 **`/tmp` 자체는 SIP로 보호되지 않기 때문에**, **가상 이미지를 마운트**한 후 **설치 프로그램**이 **post-install 스크립트**를 그곳에 넣고, **가상 이미지를 언마운트**한 다음, 모든 **폴더를 재생성**하고 **payload**를 실행하기 위한 **post installation** 스크립트를 추가할 수 있었다는 것입니다.

#### [fsck_cs 유틸리티](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

**`fsck_cs`**가 **심볼릭 링크**를 따라가는 능력으로 인해 중요한 파일을 손상시키는 취약점이 확인되었습니다. 구체적으로, 공격자는 _`/dev/diskX`_에서 `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` 파일로의 링크를 작성했습니다. _`/dev/diskX`_에서 **`fsck_cs`**를 실행하면 `Info.plist`가 손상되었습니다. 이 파일의 무결성은 운영 체제의 SIP(시스템 무결성 보호)에 필수적이며, 이는 커널 확장의 로드를 제어합니다. 손상되면 SIP의 커널 제외 관리 기능이 손상됩니다.

이 취약점을 악용하기 위한 명령은:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
이 취약점의 악용은 심각한 영향을 미칩니다. `Info.plist` 파일은 일반적으로 커널 확장에 대한 권한을 관리하는 역할을 하지만, 비효율적이 됩니다. 여기에는 `AppleHWAccess.kext`와 같은 특정 확장을 블랙리스트에 추가할 수 없는 것이 포함됩니다. 결과적으로 SIP의 제어 메커니즘이 작동하지 않게 되면, 이 확장이 로드될 수 있어 시스템의 RAM에 대한 무단 읽기 및 쓰기 접근을 허용하게 됩니다.

#### [SIP 보호 폴더에 대한 마운트](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**보호를 우회하기 위해 SIP 보호 폴더 위에 새로운 파일 시스템을 마운트하는 것이 가능했습니다.**
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [업그레이더 우회 (2016)](https://objective-see.org/blog/blog_0x14.html)

시스템은 OS를 업그레이드하기 위해 `Install macOS Sierra.app` 내의 임베디드 설치 디스크 이미지에서 부팅하도록 설정되어 있으며, `bless` 유틸리티를 사용합니다. 사용된 명령은 다음과 같습니다:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
이 프로세스의 보안은 공격자가 부팅 전에 업그레이드 이미지(`InstallESD.dmg`)를 변경하면 손상될 수 있습니다. 이 전략은 동적 로더(dyld)를 악성 버전(`libBaseIA.dylib`)으로 대체하는 것을 포함합니다. 이 교체는 설치 프로그램이 시작될 때 공격자의 코드가 실행되도록 합니다.

공격자의 코드는 업그레이드 프로세스 중에 제어를 얻고, 설치 프로그램에 대한 시스템의 신뢰를 악용합니다. 공격은 `extractBootBits` 메서드를 특히 겨냥하여 메서드 스위즐링을 통해 `InstallESD.dmg` 이미지를 변경함으로써 진행됩니다. 이를 통해 디스크 이미지가 사용되기 전에 악성 코드를 주입할 수 있습니다.

또한, `InstallESD.dmg` 내에는 업그레이드 코드의 루트 파일 시스템 역할을 하는 `BaseSystem.dmg`가 있습니다. 여기에 동적 라이브러리를 주입하면 악성 코드가 OS 수준 파일을 변경할 수 있는 프로세스 내에서 작동할 수 있어 시스템 손상의 가능성이 크게 증가합니다.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)에서의 이 발표에서는 **`systemmigrationd`** (SIP를 우회할 수 있는)가 **bash** 및 **perl** 스크립트를 실행하는 방법이 보여지며, 이는 env 변수 **`BASH_ENV`** 및 **`PERL5OPT`**를 통해 악용될 수 있습니다.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**이 블로그 게시물에서 자세히 설명된 바와 같이**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` 패키지의 `postinstall` 스크립트가 실행되고 있었습니다:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
and it was possible to crate a symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` that would allow a user to **unrestrict any file, bypassing SIP protection**.

### **com.apple.rootless.install**

> [!CAUTION]
> The entitlement **`com.apple.rootless.install`** allows to bypass SIP

The entitlement `com.apple.rootless.install` is known to bypass System Integrity Protection (SIP) on macOS. This was notably mentioned in relation to [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

In this specific case, the system XPC service located at `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possesses this entitlement. This allows the related process to circumvent SIP constraints. Furthermore, this service notably presents a method that permits the movement of files without enforcing any security measures.

## Sealed System Snapshots

Sealed System Snapshots는 **macOS Big Sur (macOS 11)**에서 Apple이 도입한 기능으로, **System Integrity Protection (SIP)** 메커니즘의 일환으로 추가적인 보안 및 시스템 안정성을 제공합니다. 이들은 본질적으로 시스템 볼륨의 읽기 전용 버전입니다.

다음은 더 자세한 설명입니다:

1. **불변 시스템**: Sealed System Snapshots는 macOS 시스템 볼륨을 "불변"으로 만들어 수정할 수 없게 합니다. 이는 보안이나 시스템 안정성을 위협할 수 있는 무단 또는 우발적인 변경을 방지합니다.
2. **시스템 소프트웨어 업데이트**: macOS 업데이트나 업그레이드를 설치할 때, macOS는 새로운 시스템 스냅샷을 생성합니다. 그런 다음 macOS 시작 볼륨은 **APFS (Apple File System)**를 사용하여 이 새로운 스냅샷으로 전환합니다. 업데이트 적용 과정이 더 안전하고 신뢰할 수 있게 되며, 업데이트 중 문제가 발생할 경우 시스템이 항상 이전 스냅샷으로 되돌릴 수 있습니다.
3. **데이터 분리**: macOS Catalina에서 도입된 데이터와 시스템 볼륨 분리 개념과 함께, Sealed System Snapshot 기능은 모든 데이터와 설정이 별도의 "**Data**" 볼륨에 저장되도록 보장합니다. 이 분리는 데이터를 시스템과 독립적으로 만들어 시스템 업데이트 과정을 단순화하고 시스템 보안을 강화합니다.

이 스냅샷은 macOS에 의해 자동으로 관리되며, APFS의 공간 공유 기능 덕분에 디스크에 추가 공간을 차지하지 않습니다. 또한, 이러한 스냅샷은 전체 시스템의 사용자 접근 가능한 백업인 **Time Machine snapshots**와는 다르다는 점도 중요합니다.

### Check Snapshots

The command **`diskutil apfs list`** lists the **details of the APFS volumes** and their layout:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

In the previous output it's possible to see that **user-accessible locations** are mounted under `/System/Volumes/Data`.

Moreover, **macOS System volume snapshot** is mounted in `/` and it's **sealed** (cryptographically signed by the OS). So, if SIP is bypassed and modifies it, the **OS won't boot anymore**.

It's also possible to **verify that seal is enabled** by running:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
또한, 스냅샷 디스크는 **읽기 전용**으로 마운트됩니다:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{{#include ../../../banners/hacktricks-training.md}}
