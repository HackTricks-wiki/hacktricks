# macOS 파일, 폴더, 바이너리 및 메모리

{{#include ../../../banners/hacktricks-training.md}}

## 파일 계층 구조

- **/Applications**: 설치된 앱이 위치해야 합니다. 모든 사용자가 이에 액세스할 수 있습니다.
- **/bin**: 명령줄 바이너리
- **/cores**: 존재하는 경우 core dump를 저장하는 데 사용됩니다.
- **/dev**: 모든 것이 파일로 취급되므로 하드웨어 장치가 이곳에 저장된 것을 볼 수 있습니다.
- **/etc**: 구성 파일
- **/Library**: 환경 설정, 캐시 및 로그와 관련된 많은 하위 디렉터리와 파일을 찾을 수 있습니다. root와 각 사용자의 디렉터리에 Library 폴더가 존재합니다.
- **/private**: 문서화되지 않았지만, 앞서 언급한 많은 폴더가 private 디렉터리를 가리키는 symbolic link입니다.
- **/sbin**: 필수 시스템 바이너리 (administration 관련)
- **/System**: OS X 실행에 필요한 파일입니다. 대부분 Apple 전용 파일만 이곳에서 찾을 수 있습니다 (third party 파일은 제외).
- **/tmp**: 파일은 3일 후 삭제됩니다 (/private/tmp에 대한 soft link입니다).
- **/Users**: 사용자의 Home directory입니다.
- **/usr**: 구성 및 시스템 바이너리
- **/var**: 로그 파일
- **/Volumes**: Mount된 drive가 이곳에 표시됩니다.
- **/.vol**: `stat a.txt`를 실행하면 `16777223 7545753 -rw-r--r-- 1 username wheel ...`과 같은 결과를 얻습니다. 여기서 첫 번째 숫자는 파일이 존재하는 volume의 ID 번호이고 두 번째 숫자는 inode 번호입니다. 해당 정보를 사용하여 `cat /.vol/16777223/7545753`을 실행하면 /.vol/을 통해 이 파일의 콘텐츠에 액세스할 수 있습니다.

### Applications 폴더

- **System applications**는 `/System/Applications` 아래에 있습니다.
- **Installed** applications는 일반적으로 `/Applications` 또는 `~/Applications`에 설치됩니다.
- **Application data**는 root로 실행되는 applications의 경우 `/Library/Application Support`에서, 사용자로 실행되는 applications의 경우 `~/Library/Application Support`에서 찾을 수 있습니다.
- **root로 실행해야 하는** third-party applications **daemons**는 일반적으로 `/Library/PrivilegedHelperTools/`에 있습니다.
- **Sandboxed** apps는 `~/Library/Containers` 폴더에 매핑됩니다. 각 app에는 application의 bundle ID (`com.apple.Safari`)에 따라 이름이 지정된 폴더가 있습니다.
- **kernel**은 `/System/Library/Kernels/kernel`에 있습니다.
- **Apple의 kernel extensions**는 `/System/Library/Extensions`에 있습니다.
- **Third-party kernel extensions**는 `/Library/Extensions`에 저장됩니다.

### 민감한 정보가 포함된 파일

MacOS는 다음과 같은 여러 위치에 passwords와 같은 정보를 저장합니다:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 취약한 pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X 전용 Extensions

- **`.dmg`**: Apple Disk Image 파일이며 installers에 매우 자주 사용됩니다.
- **`.kext`**: 특정 구조를 따라야 하며 OS X 버전의 driver입니다. (bundle입니다)
- **`.plist`**: property list라고도 하며 XML 또는 binary 형식으로 정보를 저장합니다.
- XML 또는 binary 형식일 수 있습니다. Binary 파일은 다음 명령으로 읽을 수 있습니다.
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: directory structure를 따르는 Apple applications입니다 (bundle입니다).
- **`.dylib`**: Dynamic libraries입니다 (Windows DLL 파일과 유사).
- **`.pkg`**: xar (eXtensible Archive format)와 동일합니다. installer command를 사용하여 이러한 파일의 콘텐츠를 설치할 수 있습니다.
- **`.DS_Store`**: 각 directory에 존재하며 directory의 attributes와 customisations를 저장합니다.
- **`.Spotlight-V100`**: 이 폴더는 시스템의 모든 volume의 root directory에 나타납니다.
- **`.metadata_never_index`**: 이 파일이 volume의 root에 있으면 Spotlight가 해당 volume을 index하지 않습니다.
- **`.noindex`**: 이 extension을 가진 files와 folders는 Spotlight에 의해 index되지 않습니다.
- **`.sdef`**: AppleScript에서 application과 상호 작용하는 방법을 지정하는 bundle 내부의 파일입니다.

### macOS Bundles

bundle은 **Finder에서 object처럼 보이는** **directory**입니다 (bundle의 예로 `*.app` 파일이 있습니다).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS (및 iOS)에서는 frameworks와 dylibs 같은 모든 시스템 shared libraries가 **dyld shared cache**라고 하는 **단일 파일로 결합**됩니다. 이를 통해 code를 더 빠르게 로드할 수 있으므로 성능이 향상되었습니다.

macOS에서는 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`에 있으며, 이전 버전에서는 **`/System/Library/dyld/`**에서 **shared cache**를 찾을 수 있을 수 있습니다.\
iOS에서는 `/System/Library/Caches/com.apple.dyld/`에서 찾을 수 있습니다.

dyld shared cache와 마찬가지로 kernel 및 kernel extensions도 kernel cache로 compile되며, boot time에 로드됩니다.

단일 파일인 dylib shared cache에서 libraries를 추출하려면 [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) binary를 사용할 수 있었지만, 현재는 작동하지 않을 수 있습니다. 대신 [**dyldextractor**](https://github.com/arandomdev/dyldextractor)를 사용할 수도 있습니다.
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> `dyld_shared_cache_util` tool이 작동하지 않더라도 **shared dyld binary를 Hopper에 전달**할 수 있습니다. 그러면 Hopper가 모든 library를 식별하고 조사하려는 library를 **선택**할 수 있습니다:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

일부 extractor는 dylib가 hard coded address로 prelink되어 있기 때문에 작동하지 않을 수 있으며, 이로 인해 알 수 없는 address로 jump할 수 있습니다.

> [!TIP]
> Xcode에서 emulator를 사용하면 macos에서 다른 \*OS device의 Shared Library Cache를 download할 수도 있습니다. 해당 파일은 다음 위치에 download됩니다: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, 예:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`**는 syscall **`shared_region_check_np`**를 사용하여 SLC가 mapping되었는지 확인하고(이 syscall은 address를 반환함), **`shared_region_map_and_slide_np`**를 사용하여 SLC를 mapping합니다.

SLC가 처음 사용될 때 slide되더라도 모든 **process**는 **동일한 copy**를 사용한다는 점에 유의해야 합니다. 따라서 attacker가 system에서 process를 실행할 수 있었다면 **ASLR** protection이 **제거**됩니다. 이는 실제로 과거에 exploit되었으며 shared region pager를 사용하여 수정되었습니다.

Branch pools는 작은 Mach-O dylib로, image mapping 사이에 작은 공간을 생성하여 function을 interpose할 수 없게 만듭니다.

### Override SLCs

다음 env variable을 사용합니다:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> 새로운 shared library cache를 load할 수 있습니다.
- **`DYLD_SHARED_CACHE_DIR=avoid`**를 사용하고 library를 shared cache의 실제 library에 대한 symlink로 수동으로 교체합니다(먼저 library를 extract해야 합니다).

## Special File Permissions

### Folder permissions

**folder**에서 **read**는 해당 folder를 **list**할 수 있음을 의미하고, **write**는 해당 folder의 file을 **delete**하고 **write**할 수 있음을 의미하며, **execute**는 directory를 **traverse**할 수 있음을 의미합니다. 따라서 예를 들어 directory 내부의 **file에 대한 read permission**은 있지만 해당 directory에 대한 **execute** permission이 없는 user는 해당 **file을 read**할 수 없습니다.

### Flag modifiers

file에는 file이 다르게 동작하도록 만드는 flag를 설정할 수 있습니다. directory 내부 file의 **flag를 확인**하려면 `ls -lO /path/directory`를 사용합니다.

- **`uchg`**: **uchange** flag로 알려져 있으며 **file을 변경하거나 delete하는 모든 action을 방지**합니다. 설정하려면 `chflags uchg file.txt`를 실행합니다.
- root user는 **flag를 제거**하고 file을 수정할 수 있습니다.
- **`restricted`**: 이 flag는 file을 **SIP로 보호**되도록 만듭니다(이 flag를 file에 추가할 수는 없습니다).
- **`Sticky bit`**: sticky bit가 설정된 directory에서는 **directory owner 또는 root만 file을 rename하거나 delete**할 수 있습니다. 일반적으로 ordinary user가 다른 user의 file을 delete하거나 move하지 못하도록 /tmp directory에 설정됩니다.

모든 flag는 `sys/stat.h` file에서 확인할 수 있으며(`mdfind stat.h | grep stat.h`를 사용하여 찾을 수 있음), 다음과 같습니다:

- `UF_SETTABLE` 0x0000ffff: owner가 변경할 수 있는 flag의 mask.
- `UF_NODUMP` 0x00000001: file을 dump하지 않음.
- `UF_IMMUTABLE` 0x00000002: file을 변경할 수 없음.
- `UF_APPEND` 0x00000004: file에 대한 write는 append만 가능함.
- `UF_OPAQUE` 0x00000008: union과 관련하여 directory가 opaque임.
- `UF_COMPRESSED` 0x00000020: file이 compressed 상태임(일부 file-system).
- `UF_TRACKED` 0x00000040: 이 flag가 설정된 file에 대해서는 delete/rename notification이 없음.
- `UF_DATAVAULT` 0x00000080: read 및 write를 위해 entitlement가 필요함.
- `UF_HIDDEN` 0x00008000: 이 item을 GUI에 표시하지 않아야 한다는 hint.
- `SF_SUPPORTED` 0x009f0000: superuser가 지원하는 flag의 mask.
- `SF_SETTABLE` 0x3fff0000: superuser가 변경할 수 있는 flag의 mask.
- `SF_SYNTHETIC` 0xc0000000: system read-only synthetic flag의 mask.
- `SF_ARCHIVED` 0x00010000: file이 archived 상태임.
- `SF_IMMUTABLE` 0x00020000: file을 변경할 수 없음.
- `SF_APPEND` 0x00040000: file에 대한 write는 append만 가능함.
- `SF_RESTRICTED` 0x00080000: write를 위해 entitlement가 필요함.
- `SF_NOUNLINK` 0x00100000: item을 remove, rename 또는 mount할 수 없음.
- `SF_FIRMLINK` 0x00800000: file이 firmlink임.
- `SF_DATALESS` 0x40000000: file이 dataless object임.

### **File ACLs**

File **ACL**에는 **ACE**(Access Control Entries)가 포함되며, 서로 다른 user에게 더욱 **세분화된 permission**을 할당할 수 있습니다.

**directory**에 다음 permission을 부여할 수 있습니다: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
그리고 **file**에는 다음 permission을 부여할 수 있습니다: `read`, `write`, `append`, `execute`.

file에 ACL이 포함되어 있으면 다음과 같이 permission을 listing할 때 **"+"가 표시**됩니다:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
다음 명령으로 파일의 ACL을 **읽을 수 있습니다**:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
**ACL이 설정된 모든 파일**은 다음 명령으로 찾을 수 있습니다(매우 느립니다):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 확장 속성

확장 속성에는 이름과 원하는 값이 있으며, `ls -@`를 사용해 확인하고 `xattr` 명령으로 조작할 수 있습니다. 일반적인 확장 속성은 다음과 같습니다.

- `com.apple.resourceFork`: Resource fork 호환성. `filename/..namedfork/rsrc`로도 확인 가능
- `com.apple.quarantine`: MacOS: Gatekeeper quarantine 메커니즘 (III/6)
- `metadata:*`: MacOS: `_backup_excludeItem` 또는 `kMD*`와 같은 다양한 metadata
- `com.apple.lastuseddate` (#PS): 파일을 마지막으로 사용한 날짜
- `com.apple.FinderInfo`: MacOS: Finder 정보(예: 색상 Tags)
- `com.apple.TextEncoding`: ASCII 텍스트 파일의 텍스트 인코딩 지정
- `com.apple.logd.metadata`: `/var/db/diagnostics`의 파일에서 logd가 사용
- `com.apple.genstore.*`: Generational storage (파일 시스템 루트의 `/.DocumentRevisions-V100`)
- `com.apple.rootless`: MacOS: System Integrity Protection이 파일에 label을 지정하는 데 사용 (III/10)
- `com.apple.uuidb.boot-uuid`: 고유 UUID를 사용한 boot epoch에 대한 logd 표시
- `com.apple.decmpfs`: MacOS: 투명한 파일 압축 (II/7)
- `com.apple.cprotect`: \*OS: 파일별 암호화 데이터 (III/11)
- `com.apple.installd.*`: \*OS: installd가 사용하는 metadata(예: `installType`, `uniqueInstallID`)

### Resource Forks | macOS ADS

이는 **MacOS** 시스템에서 **Alternate Data Streams**를 얻는 방법입니다. 파일 내부의 **com.apple.ResourceFork**라는 확장 속성에 콘텐츠를 저장할 수 있으며, 콘텐츠를 **file/..namedfork/rsrc**에 저장하면 됩니다.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
다음과 같이 **이 확장 속성을 포함하는 모든 파일을 찾을 수 있습니다**:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

확장 속성 `com.apple.decmpfs`는 파일이 암호화되어 저장되었음을 나타내며, `ls -l`은 **크기를 0으로** 보고하고 압축된 데이터는 이 속성 내부에 저장됩니다. 파일에 액세스할 때마다 메모리에서 복호화됩니다.

이 attr은 `ls -lO`를 사용하면 압축됨으로 표시되는 것을 확인할 수 있으며, 압축된 파일에는 `UF_COMPRESSED` 플래그도 지정됩니다. 압축된 파일에서 `chflags nocompressed </path/to/file>`를 사용해 이 플래그를 제거하면 시스템은 해당 파일이 압축되었다는 사실을 알 수 없게 됩니다. 따라서 데이터를 압축 해제하거나 액세스할 수 없으며, 파일이 실제로 비어 있다고 판단합니다.

afscexpand 도구를 사용하면 파일의 압축을 강제로 해제할 수 있습니다.


### Interesting configuration locations (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | 시스템 daemon / framework에서 선택적 또는 실험적 동작을 제어하는 Apple의 feature-flag plist 파일 저장 | 공격자가 SIP를 우회하거나 권한을 획득할 수 있다면 이를 변조하여 숨겨진 code path를 활성화하거나 보호 기능을 비활성화할 수 있음 |
| `/System/Library/CoreServices/systemVersion.plist` | 앱 / installer가 동작을 제한하는 데 사용하는 macOS 버전 메타데이터(ProductVersion, BuildVersion) 저장 | 수정하면 앱이나 installer가 지원되지 않는 OS 버전을 허용하거나 기능을 잠금 해제하도록 속일 수 있음 |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | 애플리케이션 / system-wide preferences | 쓰기 가능한 경우 공격자가 설정을 주입하여 앱 동작을 유도하거나 보호 기능을 비활성화하거나 잘못된 구성을 유발할 수 있음 |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | 백그라운드 daemon 및 agent에 대한 plist 정의 | 권한이 허용되면 악성 plist를 삽입하거나 조작하여 persistence 또는 privilege escalations를 수행할 수 있음 |
| `/etc/hosts` | 시스템 DNS resolver가 사용하는 hostname ↔ IP 매핑 | domain name을 redirect하고, 트래픽을 intercept하며, 로컬 제어하에 서비스를 spoofing |
| `/etc/sudoers` | `sudo`로 명령을 실행할 수 있는 사용자와 조건 정의 | 손상된 sudoers 파일은 공격자 계정에 root 또는 부적절한 권한을 부여할 수 있음 |
| `/private/var/db/dslocal/nodes/Default/users/` | 로컬 사용자 계정 정의 plist | 변조하면 사용자 계정, password hash 또는 사용자 메타데이터를 생성하거나 수정할 수 있음 |
| `/System/Library/Extensions/` / `/Library/Extensions/` | kernel extension / driver | kext를 설치하거나 수정하면 kernel-level control을 획득할 수 있으며, SIP / signature policy로 강력하게 보호됨 |
| `/private/var/db/SystemPolicyConfiguration/` | system policy enforcement(예: Gatekeeper, notarization) 관련 구성 저장 | 이를 변조하면 policy check 또는 trust rule을 우회할 수 있음 |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binary 및 config file | 잘못된 구성은 취약한 SSH 보안, unauthorized access 또는 안전하지 않은 algorithm으로 이어짐 |
| `/System/Library/Sandbox/Profiles` | process action을 제한하는 system sandbox profile(SBPL) | profile을 교체하거나 변경하면 sandbox escape vector를 열거나 containment를 약화할 수 있음 |

> **Note**: 이러한 경로 중 다수는 SIP로 보호되는 directory(예: `/System`) 아래에 있으며, SIP가 비활성화되거나 우회되지 않는 한 쓰기로부터 보호됩니다.


## **Universal binaries &** Mach-o Format

Mac OS binary는 일반적으로 **universal binary**로 compile됩니다. **universal binary**는 **하나의 파일에서 여러 architecture를 지원할 수 있습니다**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`에는 **서로 다른 file extension과 관련된 risk 정보가 저장됩니다**. 이 directory는 파일을 여러 risk level로 분류하며, 다운로드 시 Safari가 이러한 파일을 처리하는 방식에 영향을 줍니다. category는 다음과 같습니다:

- **LSRiskCategorySafe**: 이 category의 파일은 **완전히 안전한 것으로 간주됩니다**. Safari는 다운로드가 완료된 후 이러한 파일을 자동으로 엽니다.
- **LSRiskCategoryNeutral**: 이러한 파일에는 warning이 표시되지 않으며 Safari가 **자동으로 열지 않습니다**.
- **LSRiskCategoryUnsafeExecutable**: 이 category의 파일은 해당 파일이 application임을 알리는 **warning을 발생시킵니다**. 이는 사용자에게 경고하는 security measure입니다.
- **LSRiskCategoryMayContainUnsafeExecutable**: 이 category는 executable을 포함할 수 있는 archive와 같은 파일을 위한 것입니다. 모든 콘텐츠가 safe 또는 neutral인지 확인할 수 없는 경우 Safari는 **warning을 발생시킵니다**.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: 다운로드한 파일에 대한 정보(예: 다운로드된 URL)를 포함합니다.
- **`/var/log/system.log`**: OSX system의 main log입니다. com.apple.syslogd.plist가 syslogging 실행을 담당합니다(`launchctl list`에서 "com.apple.syslogd"를 찾아 비활성화되었는지 확인할 수 있습니다).
- **`/private/var/log/asl/*.asl`**: 흥미로운 정보를 포함할 수 있는 Apple System Log입니다.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder"를 통해 최근 액세스한 파일 및 application을 저장합니다.
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: system startup 시 실행할 항목을 저장합니다.
- **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility App의 log file입니다(USB를 포함한 drive 관련 정보).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: wireless access point에 대한 데이터입니다.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: 비활성화된 daemon 목록입니다.

{{#include ../../../banners/hacktricks-training.md}}
