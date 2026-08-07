# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **기본 정보**

macOS의 **System Integrity Protection (SIP)**은 가장 높은 권한을 가진 사용자라도 주요 시스템 폴더를 무단으로 변경하지 못하도록 설계된 메커니즘입니다. 이 기능은 보호된 영역에서 파일 추가, 수정 또는 삭제와 같은 작업을 제한하여 시스템 무결성을 유지하는 데 중요한 역할을 합니다. SIP가 보호하는 주요 폴더는 다음과 같습니다.

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP의 동작을 제어하는 규칙은 **`/System/Library/Sandbox/rootless.conf`**에 있는 configuration file에 정의되어 있습니다. 이 파일에서 별표(\*)가 접두사로 붙은 경로는 엄격한 SIP 제한의 예외로 지정됩니다.

다음 예를 살펴보겠습니다.
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
이 스니펫은 SIP가 일반적으로 **`/usr`** 디렉터리를 보호하지만, 경로 앞의 별표(\*)로 표시된 특정 하위 디렉터리(`/usr/libexec/cups`, `/usr/local`, `/usr/share/man`)에서는 수정이 허용된다는 것을 의미합니다.

디렉터리 또는 파일이 SIP로 보호되는지 확인하려면 **`ls -lOd`** 명령을 사용하여 **`restricted`** 또는 **`sunlnk`** 플래그가 있는지 확인할 수 있습니다. 예를 들면 다음과 같습니다:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
이 경우 **`sunlnk`** 플래그는 `/usr/libexec/cups` 디렉터리 자체를 **삭제할 수 없음**을 의미하지만, 해당 디렉터리 내의 파일은 생성, 수정 또는 삭제할 수 있습니다.

반면:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
여기서 **`restricted`** 플래그는 `/usr/libexec` 디렉터리가 SIP로 보호된다는 것을 나타냅니다. SIP로 보호되는 디렉터리에서는 파일을 생성, 수정 또는 삭제할 수 없습니다.

또한 파일에 **`com.apple.rootless`** 확장 **attribute**가 포함되어 있으면 해당 파일 역시 **SIP로 보호됩니다**.

> [!TIP]
> **Sandbox** hook **`hook_vnode_check_setextattr`**은 확장 attribute **`com.apple.rootless`**를 수정하려는 모든 시도를 방지합니다.

**SIP는 다음과 같은 기타 root 작업도 제한합니다**:

- 신뢰할 수 없는 kernel extension 로드
- Apple-signed process에 대한 task-port 획득
- NVRAM 변수 수정
- kernel debugging 허용

옵션은 bitflag로 nvram 변수에 유지됩니다(Intel에서는 `csr-active-config`이며 ARM에서는 부팅된 Device Tree에서 `lp-sip0`을 읽습니다). 플래그는 XNU source code의 `csr.sh`에서 확인할 수 있습니다:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP 상태

다음 명령으로 시스템에서 SIP가 활성화되어 있는지 확인할 수 있습니다:
```bash
csrutil status
```
SIP를 비활성화해야 하는 경우, 컴퓨터를 recovery mode로 재시작한 후(시작 중 Command+R을 누름) 다음 명령을 실행해야 합니다:
```bash
csrutil disable
```
SIP를 활성화된 상태로 유지하면서 debugging protections를 제거하려면 다음을 수행할 수 있습니다:
```bash
csrutil enable --without debug
```
### 기타 제한 사항

- **서명되지 않은 kernel extensions**(kexts)의 로딩을 차단하여, 검증된 extensions만 시스템 kernel과 상호 작용하도록 합니다.
- macOS 시스템 프로세스의 **debugging**을 방지하여, 핵심 시스템 구성 요소에 대한 무단 액세스 및 수정을 보호합니다.
- `dtrace`와 같은 **tools**가 시스템 프로세스를 검사하지 못하도록 하여, 시스템 작동의 무결성을 더욱 보호합니다.

[**Learn more about SIP info in this talk**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **SIP 관련 Entitlements**

- `com.apple.rootless.xpc.bootstrap`: launchd 제어
- `com.apple.rootless.install[.heritable]`: 파일 시스템 액세스
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT 관리
- `com.apple.rootless.xpc.bootstrap`: XPC 설정 capabilities
- `com.apple.rootless.xpc.effective-root`: launchd XPC를 통한 Root
- `com.apple.rootless.restricted-block-devices`: raw block devices에 대한 액세스
- `com.apple.rootless.internal.installer-equivalent`: 제한 없는 파일 시스템 액세스
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAM에 대한 전체 액세스
- `com.apple.rootless.storage.label`: 해당 label이 지정된 com.apple.rootless xattr로 제한된 파일 수정
- `com.apple.rootless.volume.VM.label`: volume에서 VM swap 유지

## SIP 우회

SIP를 우회하면 공격자는 다음을 수행할 수 있습니다.

- **사용자 데이터 액세스**: 모든 사용자 계정의 mail, messages, Safari history와 같은 민감한 사용자 데이터를 읽습니다.
- **TCC Bypass**: TCC (Transparency, Consent, and Control) database를 직접 조작하여 webcam, microphone 및 기타 리소스에 대한 무단 액세스를 허용합니다.
- **Persistence 수립**: SIP로 보호되는 위치에 malware를 배치하여 root privileges로도 제거하기 어렵게 합니다. 여기에는 Malware Removal Tool (MRT)을 변조할 가능성도 포함됩니다.
- **Kernel Extensions 로드**: 추가적인 safeguards가 존재하지만, SIP를 우회하면 서명되지 않은 kernel extensions를 더 쉽게 로드할 수 있습니다.

### Installer Packages

**Apple의 certificate로 서명된 Installer packages**는 해당 보호 기능을 우회할 수 있습니다. 즉, standard developers가 서명한 packages라도 SIP로 보호되는 directories를 수정하려고 하면 차단됩니다.

### 존재하지 않는 SIP 파일

한 가지 잠재적인 loophole은 **`rootless.conf`에 파일이 지정되어 있지만 현재 존재하지 않는 경우**, 해당 파일을 생성할 수 있다는 것입니다. Malware는 이를 악용하여 시스템에 **persistence를 수립**할 수 있습니다. 예를 들어, malicious program은 `/System/Library/LaunchDaemons`가 `rootless.conf`에 지정되어 있지만 해당 파일이 존재하지 않는 경우 그 위치에 .plist 파일을 생성할 수 있습니다.

### com.apple.rootless.install.heritable

> [!CAUTION]
> **`com.apple.rootless.install.heritable`** entitlement를 사용하면 SIP를 우회할 수 있습니다.

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

시스템이 code **signature**를 검증한 후 installer package를 **교체**할 수 있으며, 이로 인해 시스템이 원본 대신 malicious package를 설치할 수 있다는 사실이 발견되었습니다. 이러한 작업은 **`system_installd`**가 수행하므로 SIP를 우회할 수 있습니다.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Package가 mounted image 또는 external drive에서 설치되는 경우 **installer**는 SIP로 보호되는 위치가 아닌 **해당 file system에서** binary를 **execute**하므로, **`system_installd`**가 arbitrary binary를 실행하게 만들 수 있습니다.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**이 blog post의 Researchers**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)는 'Shrootless' vulnerability라고 불리는 macOS의 System Integrity Protection (SIP) mechanism vulnerability를 발견했습니다. 이 vulnerability는 **`com.apple.rootless.install.heritable`** entitlement를 가진 **`system_installd`** daemon을 중심으로 하며, 이 entitlement는 모든 child processes가 SIP의 file system restrictions를 우회하도록 허용합니다.<sup>[[4]](#references)</sup>

**`system_installd`** daemon은 **Apple**이 서명한 packages를 설치합니다.

Researchers는 Apple-signed package (.pkg file)를 설치하는 동안 **`system_installd`**가 package에 포함된 모든 **post-install** scripts를 **runs**한다는 사실을 발견했습니다. 이러한 scripts는 default shell인 **`zsh`**에 의해 실행되며, `zsh`는 non-interactive mode에서도 `/etc/zshenv` 파일이 존재하면 해당 파일의 commands를 자동으로 **runs**합니다. 공격자는 이 behaviour를 악용하여 malicious `/etc/zshenv` 파일을 생성하고 **`system_installd`가 `zsh`를 invoke하도록 대기**함으로써 device에서 arbitrary operations를 수행할 수 있습니다.<sup>[[4]](#references)</sup>

또한 **`/etc/zshenv`가 SIP bypass뿐만 아니라 general attack technique으로 사용될 수 있음**이 발견되었습니다. 각 user profile에는 `/etc/zshenv`와 동일하게 동작하지만 root permissions가 필요하지 않은 `~/.zshenv` 파일이 있습니다. 이 파일은 `zsh`가 시작될 때마다 trigger되는 persistence mechanism 또는 elevation of privilege mechanism으로 사용될 수 있습니다. admin user가 `sudo -s` 또는 `sudo <command>`를 사용하여 root로 elevation하면 `~/.zshenv` 파일이 trigger되어 사실상 root로 elevation됩니다.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)에서는 동일한 **`system_installd`** process가 여전히 abuse될 수 있다는 사실이 발견되었습니다. **`system_installd`**가 **`/tmp` 내부에서 SIP로 보호되는 무작위 이름의 folder 안에 post-install script를 배치**하고 있었기 때문입니다. 문제는 **`/tmp` 자체는 SIP로 보호되지 않는다**는 점이므로, 그 위에 **virtual image를 mount**할 수 있었습니다. 그러면 **installer**가 그 안에 **post-install script를 배치**하고, virtual image를 **unmount**한 다음, 모든 **folders를 재생성**하고 실행할 **payload가 포함된 post-installation** script를 **추가**할 수 있었습니다.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

**`fsck_cs`**가 **symbolic links**를 따라갈 수 있다는 점 때문에 중요한 파일을 손상하도록 오도될 수 있는 vulnerability가 확인되었습니다. 구체적으로 공격자는 _`/dev/diskX`_에서 `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` 파일을 가리키는 link를 생성했습니다. _`/dev/diskX`_에서 **`fsck_cs`**를 실행하면 `Info.plist`가 손상되었습니다. 이 파일의 무결성은 kernel extensions의 로딩을 제어하는 운영 체제의 SIP (System Integrity Protection)에 매우 중요합니다. 파일이 손상되면 kernel exclusions를 관리하는 SIP의 기능이 손상됩니다.<sup>[[6]](#references)</sup>

이 vulnerability를 exploit하는 commands는 다음과 같습니다.
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
이 취약점의 exploit에는 심각한 영향이 있습니다. 일반적으로 kernel extensions의 권한을 관리하는 `Info.plist` 파일이 더 이상 제대로 작동하지 않게 됩니다. 여기에는 `AppleHWAccess.kext`와 같은 특정 extension을 blacklist에 등록할 수 없는 문제도 포함됩니다. 결과적으로 SIP의 control mechanism이 작동하지 않게 되면서 이 extension을 load할 수 있고, 이를 통해 system RAM에 대한 비인가 read 및 write access가 부여됩니다.<sup>[[6]](#references)</sup>

#### [SIP protected folders 위에 Mount](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP protected folders 위에 새로운 file system을 mount하여 protection을 bypass할 수 있었습니다**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

시스템은 `bless` utility를 사용하여 `Install macOS Sierra.app` 내의 embedded installer disk image에서 boot하여 OS를 upgrade하도록 설정됩니다. 사용되는 command는 다음과 같습니다:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
공격자가 부팅 전에 업그레이드 이미지(`InstallESD.dmg`)를 변경하면 이 프로세스의 보안이 손상될 수 있습니다. 이 전략은 dynamic loader(dyld)를 악성 버전(`libBaseIA.dylib`)으로 교체하는 방식입니다. 이렇게 교체하면 installer가 시작될 때 공격자의 code가 실행됩니다.<sup>[[7]](#references)</sup>

공격자의 code는 업그레이드 프로세스 중 제어권을 확보하며, installer에 대한 시스템의 신뢰를 악용합니다. 이 공격은 특히 `extractBootBits` method를 대상으로 method swizzling을 사용해 `InstallESD.dmg` image를 변경하는 방식으로 수행됩니다. 이를 통해 disk image가 사용되기 전에 악성 code를 주입할 수 있습니다.<sup>[[7]](#references)</sup>

또한 `InstallESD.dmg` 내부에는 업그레이드 code의 root file system 역할을 하는 `BaseSystem.dmg`가 있습니다. 여기에 dynamic library를 주입하면 OS-level files를 변경할 수 있는 process 내에서 악성 code를 실행할 수 있으므로, system compromise 가능성이 크게 증가합니다.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)에서 진행된 이 발표에서는 **`systemmigrationd`**(SIP를 우회할 수 있음)가 **bash** 및 **perl** script를 실행하며, env variables **`BASH_ENV`** 및 **`PERL5OPT`**를 통해 악용될 수 있음이 소개되었습니다.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**이 blog post에 자세히 설명된 것처럼**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` packages의 `postinstall` script가 실행을 허용했습니다:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
그리고 `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`에 symlink를 생성하여 **모든 파일의 제한을 해제하고 SIP 보호를 우회할 수 있었습니다**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> entitlement **`com.apple.rootless.install`은 SIP를 우회할 수 있습니다**

entitlement `com.apple.rootless.install`은 macOS에서 System Integrity Protection (SIP)을 우회하는 것으로 알려져 있습니다. 이는 특히 [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)와 관련하여 언급되었습니다.<sup>[[10]](#references)</sup>

이 특정 사례에서 `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`에 위치한 시스템 XPC service는 이 entitlement를 보유하고 있습니다. 이를 통해 관련 process가 SIP 제약을 우회할 수 있습니다. 또한 이 service에는 어떠한 security measure도 적용하지 않고 파일을 이동할 수 있는 method가 존재합니다.<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots는 추가적인 security 및 system stability 계층을 제공하기 위해 **macOS Big Sur (macOS 11)**에서 **System Integrity Protection (SIP)** 메커니즘의 일부로 Apple이 도입한 기능입니다. 이는 본질적으로 system volume의 read-only 버전입니다.

자세히 살펴보면 다음과 같습니다.

1. **Immutable System**: Sealed System Snapshots는 macOS system volume을 "immutable"하게 만듭니다. 즉, 수정할 수 없습니다. 이를 통해 security 또는 system stability를 저해할 수 있는 system에 대한 무단 변경이나 실수로 인한 변경을 방지합니다.
2. **System Software Updates**: macOS update 또는 upgrade를 설치하면 macOS는 새로운 system snapshot을 생성합니다. 이후 macOS startup volume은 **APFS (Apple File System)**를 사용하여 이 새로운 snapshot으로 전환합니다. update 중 문제가 발생하더라도 system이 항상 이전 snapshot으로 되돌아갈 수 있으므로, update를 적용하는 전체 process가 더 안전하고 안정적입니다.
3. **Data Separation**: macOS Catalina에서 도입된 Data volume과 System volume 분리 개념과 함께 Sealed System Snapshot 기능은 모든 data와 settings가 별도의 "**Data**" volume에 저장되도록 합니다. 이러한 분리를 통해 data가 system과 독립되므로 system update process가 간소화되고 system security가 향상됩니다.

이러한 snapshot은 macOS가 자동으로 관리하며 APFS의 space sharing 기능 덕분에 disk에서 추가 공간을 차지하지 않는다는 점을 기억하세요. 또한 이러한 snapshot은 전체 system에 대해 사용자가 접근할 수 있는 backup인 **Time Machine snapshots**과는 다르다는 점도 중요합니다.

### Snapshot 확인

**`diskutil apfs list`** command는 **APFS volume의 세부 정보**와 layout을 표시합니다.

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
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
|   Encrypted:                 No
</code></pre>

이전 output에서 **user-accessible location**이 `/System/Volumes/Data` 아래에 mount되어 있음을 확인할 수 있습니다.

또한 **macOS System volume snapshot**은 `/`에 mount되어 있으며 **sealed** 상태입니다(OS가 cryptographically signed함). 따라서 SIP를 우회하여 이를 수정하면 **OS가 더 이상 boot되지 않습니다**.

다음을 실행하여 **seal이 활성화되어 있는지 확인**할 수도 있습니다.
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
또한 snapshot 디스크도 **읽기 전용**으로 마운트됩니다:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## 참고 자료

- [1] [SyScan360 - Stefan Esser - OS X El Capitan이 S\H/IP를 침몰시키다](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft가 System Integrity Protection을 우회할 수 있는 새로운 macOS 취약점 Shrootless를 발견](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple의 결실 없는 rootless 보안을 트윗 하나에 들어가는 코드로 무너뜨리다 - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Apple의 System Integrity Protection 우회 - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple이 Installer Scripts의 취약점을 완화하다 - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: SIP-Bypass용 POC는 트윗으로도 작성할 수 있다](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
