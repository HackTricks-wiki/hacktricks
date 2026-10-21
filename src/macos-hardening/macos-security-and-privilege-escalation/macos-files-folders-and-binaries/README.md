# macOS 파일, 폴더, 바이너리 및 메모리

{{#include ../../../banners/hacktricks-training.md}}

## 파일 계층 구조

Apple은 macOS 파일 시스템을 시스템, 로컬, 네트워크 및 사용자 도메인의 계층 구조로 설명합니다. 정확한 내용은 OS 릴리스에 따라 달라지며, 시스템 위치는 점점 더 강하게 보호되거나 합성되고 있습니다. <sup>[[1]](#references)</sup>

- **/Applications**: 설치된 앱이 위치합니다. 모든 사용자가 앱에 접근할 수 있습니다.
- **/bin**: 명령줄 바이너리
- **/cores**: 존재하는 경우 core dump를 저장하는 데 사용됩니다.
- **/dev**: 모든 것이 파일로 취급되므로, 하드웨어 장치가 여기에 저장된 것을 볼 수 있습니다.
- **/etc**: 설정 파일
- **/Library**: 환경설정, 캐시 및 로그와 관련된 많은 하위 디렉터리와 파일이 있습니다. Library 폴더는 루트 디렉터리와 각 사용자의 디렉터리에 존재합니다.
- **/private**: 문서화되어 있지 않지만, 앞서 언급한 폴더 중 상당수가 private 디렉터리를 가리키는 symbolic link입니다.
- **/sbin**: 필수 시스템 바이너리(관리 관련)
- **/System**: macOS에 필요한 파일이 있으며, 이 트리에는 주로 Apple이 제공하는 구성 요소가 포함됩니다.
- **/tmp**: 임시 파일(`/private/tmp`를 가리키는 symbolic link). 과거에는 오래된 임시 파일을 주기적으로 정리하는 경우가 일반적이었으며, 때로는 3일 주기로 설명되기도 했습니다. 하지만 현재 정리 시점은 시스템 및 정책에 따라 다르므로, 데이터가 계속 유지된다고 가정하지 마세요.
- **/Users**: 사용자의 홈 디렉터리
- **/usr**: 설정 및 시스템 바이너리
- **/var**: 로그 파일
- **/Volumes**: 마운트된 볼륨이 여기에 표시됩니다.
- **/.vol**: `stat a.txt`를 실행하면 `16777223 7545753 -rw-r--r-- 1 username wheel ...`과 같은 결과가 표시됩니다. 첫 번째 숫자는 파일이 있는 볼륨의 ID이고, 두 번째 숫자는 inode 번호입니다. 이 정보를 사용해 `cat /.vol/16777223/7545753`을 실행하면 `/.vol/`을 통해 파일 내용에 접근할 수 있습니다.

### Applications 폴더

- **시스템 앱**은 `/System/Applications` 아래에 있습니다.
- **설치된** 앱은 일반적으로 `/Applications` 또는 `~/Applications`에 설치됩니다.
- **애플리케이션 데이터**는 root로 실행되는 앱의 경우 `/Library/Application Support`에서, 사용자 권한으로 실행되는 앱의 경우 `~/Library/Application Support`에서 찾을 수 있습니다.
- **root로 실행해야 하는** 서드파티 앱 **daemon**은 일반적으로 `/Library/PrivilegedHelperTools/`에 있습니다.
- **Sandboxed** 앱은 `~/Library/Containers` 폴더에 매핑됩니다. 각 앱에는 애플리케이션의 bundle ID(`com.apple.Safari`)에 해당하는 이름의 폴더가 있습니다.
- **kernel**은 `/System/Library/Kernels/kernel`에 있습니다.
- **Apple의 kernel extension**은 `/System/Library/Extensions`에 있습니다.
- **서드파티 kernel extension**은 `/Library/Extensions`에 저장됩니다.

### 민감한 정보가 포함된 파일

macOS는 자격 증명을 비롯한 민감한 정보를 여러 위치에 저장합니다.


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 취약한 pkg installer


{{#ref}}
macos-installers-abuse.md
{{#endref}}

이 계층 구조에 표시된 쓰기 가능한 Data 볼륨과 봉인된 System 볼륨의 차이는 [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md)를 참조하세요.

## OS X 전용 확장자

- **`.dmg`**: Apple Disk Image 파일은 installer에 매우 흔히 사용됩니다.
- **`.kext`**: 특정 구조를 따라야 하며, OS X 버전의 driver입니다. (bundle입니다)
- **`.plist`**: property list는 구조화된 정보를 XML 또는 binary 형식으로 저장합니다.
  - XML 또는 binary 형식일 수 있습니다. Binary 형식은 다음 명령어로 읽을 수 있습니다.
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: 표준 macOS 디렉터리 구조를 따르는 애플리케이션 bundle입니다.
- **`.dylib`**: Dynamic library(Windows DLL 파일과 유사)
- **`.pkg`**: 최신 flat installer package는 XAR archive이지만, `.pkg`는 installer 형식이지 XAR의 동의어가 아닙니다. 이전의 bundle 스타일 installer package는 디렉터리입니다. package 구조와 검사 방법은 [macOS installers](macos-installers-abuse.md)를 참조하세요. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: 각 디렉터리에 있는 이 파일은 디렉터리의 속성과 사용자 지정을 저장합니다.
- **`.Spotlight-V100`**: 이 폴더는 시스템의 모든 볼륨 루트 디렉터리에 나타납니다.
- **`.metadata_never_index`**: 이 파일이 볼륨의 루트에 있으면 Spotlight가 해당 볼륨을 인덱싱하지 않습니다.
- **`.noindex`**: 이 확장자를 가진 파일과 폴더는 Spotlight가 인덱싱하지 않습니다.
- **`.sdef`**: AppleScript가 애플리케이션과 상호작용하는 방법을 설명하는 scripting definition 파일입니다.

### macOS Bundle

bundle은 표준화된 계층 구조를 가진 디렉터리로, Finder에서는 하나의 객체처럼 표시할 수 있습니다. 애플리케이션 bundle은 `.app` 확장자를 사용합니다. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS와 iOS에서는 자주 사용되는 시스템 라이브러리와 framework를 **dyld shared cache**에 미리 링크하여 애플리케이션 시작 성능을 높입니다. 이를 하나의 논리적 캐시로 취급하지만, 현재 릴리스에서는 실제로 하나의 파일이 아니라 기본 캐시와 여러 하위 캐시 파일로 저장될 수 있습니다. 형식과 위치는 OS 릴리스에 따라 달라지는 구현 세부 사항입니다. <sup>[[3]](#references)</sup>

macOS에서는 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`에 있으며, 이전 버전에서는 **shared cache**를 **`/System/Library/dyld/`**에서 찾을 수 있습니다.\
iOS에서는 **`/System/Library/Caches/com.apple.dyld/`**에서 찾을 수 있습니다.

dyld shared cache와 마찬가지로 kernel과 kernel extension도 kernel cache로 컴파일되어 부팅 시 로드됩니다.

이전 릴리스에서는 [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip)을 사용해 추출할 수 있었습니다. 이 빌드는 현재 캐시 형식을 지원하지 않을 수 있습니다. 다른 방법으로 [**dyldextractor**](https://github.com/arandomdev/dyldextractor)를 사용할 수 있습니다.

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> `dyld_shared_cache_util` 도구가 작동하지 않더라도 **shared dyld 바이너리를 Hopper에 전달**하면 Hopper가 모든 라이브러리를 식별하고 조사할 라이브러리를 **선택할 수 있게 해줍니다**:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

dylib는 하드코딩된 주소로 미리 연결되어 있어 알 수 없는 주소로 점프할 수 있으므로, 일부 추출기는 작동하지 않습니다.

> [!TIP]
> Xcode의 에뮬레이터를 사용하면 macOS에서 다른 \*OS 기기의 Shared Library Cache도 다운로드할 수 있습니다. 캐시는 다음 경로에 다운로드됩니다: `ls $HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, 예: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### SLC 매핑

**`dyld`**는 SLC가 매핑되었는지 확인하기 위해(주소를 반환함) syscall **`shared_region_check_np`**를 사용하고, SLC를 매핑하기 위해 **`shared_region_map_and_slide_np`**를 사용합니다.

처음 사용될 때 SLC에 slide가 적용되더라도 모든 **프로세스**는 **같은 복사본**을 사용합니다. 따라서 공격자가 시스템에서 프로세스를 실행할 수 있었다면 **ASLR 보호가 제거됩니다**. 이 문제는 실제로 과거에 악용되었으며 shared region pager를 통해 수정되었습니다.

Branch pools는 이미지 매핑 사이에 작은 공간을 만드는 작은 Mach-O dylib이며, 이를 통해 함수를 interpose할 수 없게 합니다.

### Shared-cache 환경 제한

`DYLD_SHARED_CACHE_DIR`는 캐시 디렉터리를 지정하고, `DYLD_SHARED_REGION`은 shared-region 모드를 선택합니다. 이전의 `DYLD_DHARED_REGION` 표기는 잘못된 것이며, `avoid`는 `DYLD_SHARED_CACHE_DIR`의 유효한 값이 아닙니다. 현재 dyld는 사용자 지정 shared cache를 사용할 수 있는 AMFI 권한이 있을 때만 `private` 모드를 허용합니다. 따라서 환경 변수만 설정한다고 해서 프로세스가 대체 캐시를 로드할 수 있는 것은 아닙니다. <sup>[[10]](#references)</sup>

## 특수 파일 권한

### 폴더 권한

디렉터리에서 **read** 권한은 항목 목록을 볼 수 있게 하고, **write** 권한은 항목을 만들거나 삭제할 수 있게 하며, **execute** 권한은 디렉터리를 탐색할 수 있게 합니다. 따라서 파일을 읽을 수 있더라도 상위 디렉터리를 탐색할 수 없는 사용자는 경로를 통해 해당 파일에 접근할 수 없습니다. <sup>[[4]](#references)</sup>

### 플래그 수정자

파일에는 동작을 변경하는 플래그가 설정될 수 있습니다. 디렉터리의 플래그는 `ls -lO /path/directory`로 확인합니다.

- **`uchg`**: **uchange** 플래그라고도 하며, 파일을 변경하거나 삭제하는 **모든 작업을 방지**합니다. 설정하려면 다음을 실행합니다: `chflags uchg file.txt`
  - 파일 소유자나 root는 `chflags nouchg file.txt`로 이 **사용자** 플래그를 해제할 수 있습니다. 따라서 이 플래그는 둘 중 어느 쪽에 대한 보호 기능도 아닙니다. 별도의 **시스템** 불변 플래그(`schg`)는 root만 설정할 수 있습니다. <sup>[[11]](#references)</sup>
- **`restricted`**: 이 플래그가 설정된 파일은 **SIP로 보호**됩니다(파일에 이 플래그를 추가할 수는 없습니다).
- **`Sticky bit`**: Sticky bit가 설정된 디렉터리에서는 파일 소유자, 디렉터리 소유자 또는 root만 항목의 이름을 바꾸거나 삭제할 수 있습니다. 사용자가 다른 사용자의 파일을 삭제하거나 이동하지 못하도록 `/tmp`에 일반적으로 설정됩니다.

모든 플래그는 `sys/stat.h` 파일에서 확인할 수 있으며(`mdfind stat.h | grep stat.h`로 찾을 수 있음), 다음과 같습니다.

- `UF_SETTABLE` 0x0000ffff: 소유자가 변경할 수 있는 플래그의 마스크.
- `UF_NODUMP` 0x00000001: 파일을 덤프하지 않음.
- `UF_IMMUTABLE` 0x00000002: 파일을 변경할 수 없음.
- `UF_APPEND` 0x00000004: 파일에 추가 작업만 가능.
- `UF_OPAQUE` 0x00000008: 디렉터리가 union에 대해 불투명함.
- `UF_COMPRESSED` 0x00000020: 파일이 압축되어 있음(일부 파일 시스템).
- `UF_TRACKED` 0x00000040: 이 플래그가 설정된 파일을 삭제하거나 이름을 바꿔도 알림이 전송되지 않음.
- `UF_DATAVAULT` 0x00000080: 읽기 및 쓰기에 entitlement가 필요함.
- `UF_HIDDEN` 0x00008000: GUI에서 이 항목을 표시하지 않도록 하는 힌트.
- `SF_SUPPORTED` 0x009f0000: superuser가 지원하는 플래그의 마스크.
- `SF_SETTABLE` 0x3fff0000: superuser가 변경할 수 있는 플래그의 마스크.
- `SF_SYNTHETIC` 0xc0000000: 시스템 읽기 전용 synthetic 플래그의 마스크.
- `SF_ARCHIVED` 0x00010000: 파일이 아카이브됨.
- `SF_IMMUTABLE` 0x00020000: 파일을 변경할 수 없음.
- `SF_APPEND` 0x00040000: 파일에 추가 작업만 가능.
- `SF_RESTRICTED` 0x00080000: 쓰기에 entitlement가 필요함.
- `SF_NOUNLINK` 0x00100000: 항목을 제거하거나 이름을 바꾸거나 마운트할 수 없음.
- `SF_FIRMLINK` 0x00800000: 파일이 firmlink임.
- `SF_DATALESS` 0x40000000: 파일이 dataless 객체임.

### **파일 ACL**

파일 **ACL**에는 **ACE**(Access Control Entries)가 포함되며, 이를 통해 서로 다른 사용자에게 더 **세분화된 권한**을 지정할 수 있습니다.

**디렉터리**에는 다음 권한을 부여할 수 있습니다: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
**파일**에는 다음 권한을 부여할 수 있습니다: `read`, `write`, `append`, `execute`.

파일에 ACL이 있으면 권한을 나열할 때 다음과 같이 **"+"가 표시됩니다**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

다음을 사용해 파일의 **ACL을 읽을 수 있습니다**:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

다음 명령을 사용하면 ACL이 설정된 **모든 파일**을 찾을 수 있습니다(매우 느립니다):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### 확장 속성

확장 속성은 파일의 일반 속성과 별도로 저장되는 이름이 지정된 메타데이터 값입니다. `ls -l@`로 목록을 확인하고 `xattr`로 검사하거나 수정할 수 있습니다. <sup>[[5]](#references)</sup> 일반적인 확장 속성은 다음과 같습니다.

- `com.apple.resourceFork`: 리소스 포크 호환성. `filename/..namedfork/rsrc`에서도 확인 가능
- `com.apple.quarantine`: macOS Gatekeeper 격리 메타데이터
- `metadata:*`: `_backup_excludeItem` 또는 `kMD*`와 같은 macOS 메타데이터
- `com.apple.lastuseddate` (#PS): 파일을 마지막으로 사용한 날짜
- `com.apple.FinderInfo`: 색상 태그와 같은 macOS Finder 정보
- `com.apple.TextEncoding`: ASCII 텍스트 파일의 텍스트 인코딩 지정
- `com.apple.logd.metadata`: `/var/db/diagnostics`의 파일에서 logd가 사용
- `com.apple.genstore.*`: 세대별 저장소(파일 시스템 루트의 `/.DocumentRevisions-V100`)
- `com.apple.rootless`: System Integrity Protection과 관련된 macOS 메타데이터
- `com.apple.uuidb.boot-uuid`: 고유 UUID를 사용해 부팅 epoch를 표시하는 logd 마커
- `com.apple.decmpfs`: macOS 투명 파일 압축 메타데이터
- `com.apple.cprotect`: \*OS: 파일별 암호화 데이터(III/11)
- `com.apple.installd.*`: \*OS: `installType`, `uniqueInstallID` 등 installd가 사용하는 메타데이터

### 리소스 포크 | macOS ADS

리소스 포크는 macOS에서 대체 데이터 스트림을 제공합니다. 콘텐츠는 `com.apple.ResourceFork` 확장 속성에 저장할 수 있으며 `file/..namedfork/rsrc`를 통해 접근할 수 있습니다.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

이 확장 속성을 포함하는 모든 파일은 다음과 같이 **찾을 수 있습니다**:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

확장 속성 `com.apple.decmpfs`에는 투명 압축을 위한 메타데이터가 저장되며, 암호화를 나타내지는 않습니다. 압축 형식에 따라 압축된 데이터는 속성 또는 리소스 포크에 저장될 수 있으며, 읽을 때 투명하게 압축 해제됩니다.

`UF_COMPRESSED` 플래그는 `ls -lO`에서 `compressed`로 표시됩니다. 이 플래그를 수동으로 지우지 마세요. 시스템이 압축된 표현을 잘못 해석할 수 있습니다.

플래그를 지우는 명령은 포렌식 검토에 유용하므로 여기에 나와 있지만, 압축된 파일에 실행하면 메타데이터를 복구할 때까지 파일이 비어 있거나 접근할 수 없는 것처럼 보일 수 있습니다:

```bash
chflags nocompressed /path/to/file
```

내장 `/usr/bin/afscexpand` 유틸리티는 투명하게 압축된 파일을 강제로 확장할 수 있습니다. 별도의 서드파티 `afsctool` 유틸리티도 Apple 파일 시스템 압축을 검사하거나 해제할 수 있지만, 내장 명령어와 혼동해서는 안 됩니다. <sup>[[8]](#references)</sup>


### 흥미로운 구성 위치 (macOS)

| 경로 / 위치 | 용도 / 구성 대상 | 보안 / 공격 가능성 |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | 시스템 데몬 / 프레임워크의 선택적 또는 실험적 동작을 제어하는 Apple 기능 플래그 plist 파일 저장 | 공격자가 SIP를 우회하거나 권한을 얻으면, 이를 변조해 숨겨진 코드 경로를 활성화하거나 보호 기능을 비활성화할 수 있음 |
| `/System/Library/CoreServices/systemVersion.plist` | 앱 / 설치 프로그램이 동작을 결정할 때 사용하는 macOS 버전 메타데이터(ProductVersion, BuildVersion) 저장 | 수정하면 앱이나 설치 프로그램이 지원되지 않는 OS 버전을 허용하거나 기능을 잠금 해제하도록 속일 수 있음 |
| `/Library/Preferences/com.apple.*.plist` 및 `~/Library/Preferences/*.plist` | 애플리케이션 / 시스템 전반의 환경설정 | 쓰기가 가능하면 공격자가 설정을 주입해 앱 동작을 유도하거나, 보호 기능을 비활성화하거나, 잘못된 구성을 유발할 수 있음 |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | 백그라운드 데몬 및 에이전트의 plist 정의 | 권한이 허용하는 경우 악성 plist를 삽입하거나 조작해 지속성 또는 권한 상승을 달성할 수 있음 |
| `/etc/hosts` | 시스템 DNS 확인자가 사용하는 호스트 이름 ↔ IP 매핑 | 도메인 이름을 리디렉션하고, 트래픽을 가로채거나, 로컬에서 제어하는 서비스를 스푸핑할 수 있음 |
| `/etc/sudoers` | `sudo`로 명령을 실행할 수 있는 사용자와 적용 조건 정의 | 손상된 sudoers 파일은 공격자 계정에 root 권한 또는 부적절한 권한을 부여할 수 있음 |
| `/private/var/db/dslocal/nodes/Default/users/` | 로컬 사용자 계정 정의 plist | 이를 변조하면 사용자 계정, 암호 해시 또는 사용자 메타데이터를 생성하거나 수정할 수 있음 |
| `/System/Library/Extensions/` / `/Library/Extensions/` | 커널 확장 / 드라이버 | kext를 설치하거나 수정하면 커널 수준의 제어권을 얻을 수 있음. SIP / 서명 정책으로 강력히 보호됨 |
| `/private/var/db/SystemPolicyConfiguration/` | 시스템 정책 적용 구성(예: Gatekeeper, 공증) 저장 | 이를 변조하면 정책 검사 또는 신뢰 규칙을 우회할 수 있음 |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH 보조 바이너리 및 구성 파일 | 잘못 구성하면 SSH 보안이 약화되고, 무단 접근이나 안전하지 않은 알고리즘 사용으로 이어질 수 있음 |
| `/System/Library/Sandbox/Profiles` | 프로세스의 동작을 제한하는 시스템 sandbox 프로파일(SBPL) | 프로파일을 교체하거나 변경하면 sandbox 탈출 경로가 생기거나 격리 수준이 약화될 수 있음 |

> **참고**: 이러한 경로 중 다수는 SIP로 보호되는 디렉터리(예: `/System`) 아래에 있으며, SIP를 비활성화하거나 우회하지 않는 한 쓰기가 차단됩니다.  


## Universal Binary와 Mach-O 형식

Mach-O는 macOS의 기본 실행 파일 형식입니다. Universal 또는 fat 바이너리는 아키텍처별 Mach-O 슬라이스 여러 개를 하나의 파일로 묶습니다. 전용 페이지에서 두 형식을 모두 설명합니다.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS 메모리 덤프

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## 파일 위험 및 핸들러 메타데이터

LaunchServices, 파일 격리(quarantine), Gatekeeper는 함께 macOS가 다운로드한 파일을 처리하고 확장자와 URL 스킴에 사용할 애플리케이션을 선택하는 방식에 영향을 줍니다. 관련 데이터베이스와 내부 리소스 파일은 릴리스마다 달라지므로, 비공개 CoreTypes 경로를 안정적인 정책 인터페이스로 간주하지 말고 전용 페이지를 참조하세요.

레거시 CoreTypes 위험 메타데이터가 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`에 노출되는 릴리스에서 흔히 접하는 범주는 다음과 같습니다.<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: 적용되는 애플리케이션 정책에 따라 자동으로 열어도 안전하다고 간주되는 콘텐츠입니다.
- **`LSRiskCategoryNeutral`**: 일반적으로 경고를 유발하지 않으며 자동으로 열리지 않는 콘텐츠입니다.
- **`LSRiskCategoryUnsafeExecutable`**: 사용자에게 애플리케이션 경고를 표시해야 하는 실행 가능한 콘텐츠입니다.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: 실행 가능한 콘텐츠를 포함할 수 있어 추가 검사가 필요한 아카이브와 같은 컨테이너입니다.

이는 구현 세부 정보이지 안정적인 공개 정책 API가 아닙니다. 테스트 대상 macOS 버전에서 실제 메타데이터와 Safari/Gatekeeper 동작을 확인하세요.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## 로그 파일

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: 다운로드한 파일의 정보(예: 파일을 다운로드한 URL)를 포함합니다.
- **통합 로그**: 최신 macOS 버전에서는 `log show`와 `log stream`으로 시스템 및 애플리케이션 이벤트를 조회합니다. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** 및 **`/private/var/log/asl/*.asl`**: 구형 시스템에서 여전히 관련이 있을 수 있는 레거시 로깅 아티팩트입니다. 해당 릴리스에서는 `/System/Library/LaunchDaemons/com.apple.syslogd.plist`가 `syslogd`를 구성합니다. `launchctl list | grep com.apple.syslogd`를 사용하면 서비스가 로드되어 있는지 확인하는 데 도움이 됩니다.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder"를 통해 최근에 접근한 파일과 애플리케이션을 저장합니다.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: 로그인 항목과 관련된 레거시 환경설정 경로입니다. 최신 macOS 버전에서는 추가 메커니즘을 사용합니다.
- **`$HOME/Library/Logs/DiskUtility.log`**: 드라이브(USB 기기 포함)에 대한 정보가 들어 있을 수 있는 레거시 Disk Utility 로그입니다.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: 무선 액세스 포인트에 관한 데이터입니다.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: 레거시 launchd 재정의 데이터입니다.



## References

- [1] [Apple - 파일 시스템 프로그래밍 가이드](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle 프로그래밍 가이드](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld 공유 캐시 개요](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - 파일 시스템 프로그래밍 가이드: macOS 파일 시스템 보안](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS 매뉴얼 페이지](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS 매뉴얼 페이지](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS 매뉴얼 페이지](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - Apple 아카이브 압축 해제](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Shell Script 보안: 특수 파일 권한 플래그](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - 코드 서명 작업: 설치 프로그램 패키지](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
