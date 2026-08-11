# macOS 파일, 폴더, 바이너리 및 메모리

{{#include ../../../banners/hacktricks-training.md}}

## 파일 계층 구조 레이아웃

Apple은 macOS 파일시스템을 system, local, network 및 user domain의 계층 구조로 문서화합니다. 정확한 내용은 OS 릴리스에 따라 달라지며, system 위치는 점점 더 보호되거나 합성되고 있습니다. <sup>[[1]](#references)</sup>

- **/Applications**: 설치된 앱은 여기에 있어야 합니다. 모든 사용자가 액세스할 수 있습니다.
- **/bin**: 명령줄 바이너리
- **/cores**: 존재하는 경우 core dump를 저장하는 데 사용됩니다.
- **/dev**: 모든 것이 파일로 처리되므로 하드웨어 장치가 여기에 저장된 것을 볼 수 있습니다.
- **/etc**: 구성 파일
- **/Library**: preferences, caches 및 logs와 관련된 많은 하위 디렉터리와 파일을 여기에서 찾을 수 있습니다. root와 각 사용자의 디렉터리에 Library 폴더가 존재합니다.
- **/private**: 문서화되지 않았지만, 앞에서 언급한 많은 폴더가 private 디렉터리를 가리키는 symbolic link입니다.
- **/sbin**: 필수 system 바이너리 (administration 관련)
- **/System**: macOS에 필요한 파일입니다. 이 트리에는 주로 Apple이 제공하는 구성 요소가 포함됩니다.
- **/tmp**: 임시 파일 (`/private/tmp`에 대한 symbolic link). 과거 설치에서는 일반적으로 일정에 따라 오래된 임시 파일을 정리했으며, 때로는 3일로 설명되기도 했지만 현재 정리 시점은 system 및 policy에 따라 달라집니다. 데이터가 이곳에 계속 존재한다고 가정하지 마세요.
- **/Users**: 사용자의 home directory
- **/usr**: 구성 및 system 바이너리
- **/var**: Log 파일
- **/Volumes**: Mounted volume이 여기에 표시됩니다.
- **/.vol**: `stat a.txt`를 실행하면 `16777223 7545753 -rw-r--r-- 1 username wheel ...`과 같은 결과를 얻습니다. 첫 번째 숫자는 파일이 존재하는 volume의 id number이고 두 번째 숫자는 inode number입니다. 해당 정보를 사용해 `cat /.vol/16777223/7545753`을 실행하면 `/.vol/`을 통해 이 파일의 내용에 액세스할 수 있습니다.

### Applications 폴더

- **System applications**는 `/System/Applications` 아래에 있습니다.
- **Installed** applications는 일반적으로 `/Applications` 또는 `~/Applications`에 설치됩니다.
- **Application data**는 root로 실행되는 applications의 경우 `/Library/Application Support`에서, user로 실행되는 applications의 경우 `~/Library/Application Support`에서 찾을 수 있습니다.
- **root로 실행해야 하는** third-party application **daemons**는 일반적으로 `/Library/PrivilegedHelperTools/`에 있습니다.
- **Sandboxed** apps는 `~/Library/Containers` 폴더에 매핑됩니다. 각 app에는 application의 bundle ID(`com.apple.Safari`)에 따라 이름이 지정된 폴더가 있습니다.
- **kernel**은 `/System/Library/Kernels/kernel`에 있습니다.
- **Apple의 kernel extensions**는 `/System/Library/Extensions`에 있습니다.
- **Third-party kernel extensions**는 `/Library/Extensions`에 저장됩니다.

### 민감한 정보가 포함된 파일

macOS는 credentials를 포함한 민감한 정보를 여러 위치에 저장합니다:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 취약한 pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X 전용 확장자

- **`.dmg`**: Apple Disk Image 파일이며 installers에 매우 자주 사용됩니다.
- **`.kext`**: 특정 구조를 따라야 하며 driver의 OS X 버전입니다. (bundle입니다.)
- **`.plist`**: property list는 XML 또는 binary 형식으로 구조화된 정보를 저장합니다.
- XML 또는 binary일 수 있습니다. binary 파일은 다음 명령으로 읽을 수 있습니다.
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: 표준 macOS directory structure를 따르는 application bundle입니다.
- **`.dylib`**: Dynamic libraries (Windows DLL 파일과 유사)
- **`.pkg`**: xar (eXtensible Archive format)와 동일합니다. installer command를 사용해 이러한 파일의 내용을 설치할 수 있습니다.
- **`.DS_Store`**: 각 directory에 있는 파일로, 해당 directory의 attributes와 customisations를 저장합니다.
- **`.Spotlight-V100`**: 이 폴더는 system의 모든 volume의 root directory에 나타납니다.
- **`.metadata_never_index`**: 이 파일이 volume의 root에 있으면 Spotlight는 해당 volume을 index하지 않습니다.
- **`.noindex`**: 이 확장자를 가진 files와 folders는 Spotlight에 의해 index되지 않습니다.
- **`.sdef`**: AppleScript가 application과 상호 작용하는 방법을 설명하는 scripting definition file입니다.

### macOS Bundles

bundle은 Finder가 단일 object로 표시할 수 있는 표준화된 계층 구조를 가진 directory이며, application bundles는 `.app` 확장자를 사용합니다. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS와 iOS에서는 일반적으로 사용되는 system libraries와 frameworks가 **dyld shared cache**에 미리 연결되어 application startup 성능을 향상합니다. 하나의 논리적 cache로 취급되지만, 현재 릴리스에서는 실제로 하나의 파일이 아니라 main cache와 여러 subcache 파일로 저장될 수 있습니다. 형식과 위치는 OS 릴리스에 따라 변경되는 implementation detail입니다. <sup>[[3]](#references)</sup>

macOS에서는 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`에 있으며, 이전 버전에서는 **shared cache**를 **`/System/Library/dyld/`**에서 찾을 수 있을 수 있습니다.\
iOS에서는 `/System/Library/Caches/com.apple.dyld/`에서 찾을 수 있습니다.

dyld shared cache와 마찬가지로 kernel과 kernel extensions도 kernel cache로 compile되며, boot time에 load됩니다.

이전 릴리스는 [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip)을 사용해 extract할 수 있었습니다. 해당 build는 현재 cache 형식을 지원하지 않을 수 있습니다. 다른 옵션으로 [**dyldextractor**](https://github.com/arandomdev/dyldextractor)를 사용할 수 있습니다.
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> `dyld_shared_cache_util` 도구가 작동하지 않더라도 **shared dyld binary를 Hopper에 전달**할 수 있으며, Hopper는 모든 라이브러리를 식별하고 조사할 **라이브러리를 선택**할 수 있게 해줍니다:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

일부 extractor는 dylib가 하드코딩된 주소로 prelink되어 있기 때문에 작동하지 않을 수 있으며, 이로 인해 알 수 없는 주소로 jump할 수 있습니다.

> [!TIP]
> Xcode에서 emulator를 사용하면 macOS에서 다른 \*OS 기기의 Shared Library Cache를 다운로드할 수도 있습니다. 해당 파일은 다음 경로에 다운로드됩니다: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, 예:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`**는 SLC가 mapping되었는지 확인하기 위해 syscall **`shared_region_check_np`**를 사용하며(이 syscall은 주소를 반환함), SLC를 mapping하기 위해 **`shared_region_map_and_slide_np`**를 사용합니다.

SLC가 최초 사용 시 slide되더라도 모든 **process**는 **동일한 copy**를 사용합니다. 따라서 attacker가 system에서 process를 실행할 수 있었다면 **ASLR** protection이 **제거되었습니다**. 이는 실제로 과거에 exploit되었으며 shared region pager를 사용하여 수정되었습니다.

Branch pool은 작은 Mach-O dylib로, image mapping 사이에 작은 공간을 만들어 function을 interpose할 수 없게 합니다.

### Override SLCs

다음 env variable을 사용합니다:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> 새로운 shared library cache를 load할 수 있습니다.
- **`DYLD_SHARED_CACHE_DIR=avoid`**를 설정하고 library를 실제 library에 대한 shared cache symlink로 수동 교체합니다(먼저 library를 extract해야 합니다).

## Special File Permissions

### Folder permissions

directory의 경우 **read**는 entry 목록 조회를, **write**는 entry 생성 또는 제거를, **execute**는 traversal을 허용합니다. 따라서 file을 read할 수 있지만 parent directory를 traverse할 수 없는 user는 해당 file에 path를 통해 access할 수 없습니다. <sup>[[4]](#references)</sup>

### Flag modifiers

File에는 동작을 변경하는 flag를 설정할 수 있습니다. `ls -lO /path/directory`를 사용하여 directory의 flag를 확인합니다.

- **`uchg`**: **uchange** flag로 알려져 있으며 **file**을 변경하거나 삭제하는 **모든 action을 방지**합니다. 설정하려면 다음을 실행합니다: `chflags uchg file.txt`
- root user는 **flag를 제거**하고 file을 수정할 수 있습니다.
- **`restricted`**: 이 flag는 file을 **SIP로 보호**되게 합니다(이 flag를 file에 추가할 수 없습니다).
- **`Sticky bit`**: sticky bit가 설정된 directory에서는 file owner, directory owner 또는 root만 entry를 rename하거나 delete할 수 있습니다. 이는 다른 user의 file을 삭제하거나 이동하지 못하게 하기 위해 일반적으로 `/tmp`에서 활성화됩니다.

모든 flag는 `sys/stat.h` file에서 확인할 수 있으며(`mdfind stat.h | grep stat.h`를 사용하여 찾을 수 있음), 다음과 같습니다:

- `UF_SETTABLE` 0x0000ffff: owner가 변경할 수 있는 flag의 mask.
- `UF_NODUMP` 0x00000001: file을 dump하지 않음.
- `UF_IMMUTABLE` 0x00000002: file을 변경할 수 없음.
- `UF_APPEND` 0x00000004: file에 대한 write는 append만 가능함.
- `UF_OPAQUE` 0x00000008: union과 관련하여 directory가 opaque임.
- `UF_COMPRESSED` 0x00000020: file이 compressed 상태임(일부 file-system).
- `UF_TRACKED` 0x00000040: 이 flag가 설정된 file의 delete/rename에 대한 notification이 없음.
- `UF_DATAVAULT` 0x00000080: read 및 write에 entitlement가 필요함.
- `UF_HIDDEN` 0x00008000: 이 item을 GUI에 표시하지 않아야 한다는 hint.
- `SF_SUPPORTED` 0x009f0000: superuser가 지원하는 flag의 mask.
- `SF_SETTABLE` 0x3fff0000: superuser가 변경할 수 있는 flag의 mask.
- `SF_SYNTHETIC` 0xc0000000: system의 read-only synthetic flag의 mask.
- `SF_ARCHIVED` 0x00010000: file이 archived 상태임.
- `SF_IMMUTABLE` 0x00020000: file을 변경할 수 없음.
- `SF_APPEND` 0x00040000: file에 대한 write는 append만 가능함.
- `SF_RESTRICTED` 0x00080000: write에 entitlement가 필요함.
- `SF_NOUNLINK` 0x00100000: item을 remove, rename 또는 mount할 수 없음.
- `SF_FIRMLINK` 0x00800000: file이 firmlink임.
- `SF_DATALESS` 0x40000000: file이 dataless object임.

### **File ACLs**

File **ACL**에는 **ACE**(Access Control Entries)가 포함되며, 서로 다른 user에게 더 **세분화된 permissions**를 할당할 수 있습니다.

**directory**에는 다음 permissions를 부여할 수 있습니다: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`:
File에는 `read`, `write`, `append`, `execute`를 부여할 수 있습니다.

File에 ACL이 포함되어 있으면 **다음과 같이 permissions를 listing할 때 "+"가 표시됩니다**:
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
다음 명령어를 사용하면 **ACL이 설정된 모든 파일**을 찾을 수 있습니다 (매우 느립니다):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes는 파일의 일반적인 attributes와 별도로 저장되는 이름이 지정된 metadata 값입니다. `ls -l@`로 나열하고 `xattr`로 검사하거나 수정할 수 있습니다. <sup>[[5]](#references)</sup> 일반적인 extended attributes는 다음과 같습니다.

- `com.apple.resourceFork`: Resource fork 호환성. `filename/..namedfork/rsrc`로도 표시됩니다.
- `com.apple.quarantine`: macOS Gatekeeper quarantine metadata
- `metadata:*`: `_backup_excludeItem` 또는 `kMD*`와 같은 macOS metadata
- `com.apple.lastuseddate` (#PS): 마지막 파일 사용 날짜
- `com.apple.FinderInfo`: 색상 tags와 같은 macOS Finder 정보
- `com.apple.TextEncoding`: ASCII text 파일의 text encoding 지정
- `com.apple.logd.metadata`: `/var/db/diagnostics`의 파일에서 logd가 사용
- `com.apple.genstore.*`: Generational storage (파일시스템 루트의 `/.DocumentRevisions-V100`)
- `com.apple.rootless`: System Integrity Protection과 연결된 macOS metadata
- `com.apple.uuidb.boot-uuid`: 고유 UUID를 사용한 boot epoch의 logd 표시
- `com.apple.decmpfs`: macOS transparent file compression metadata
- `com.apple.cprotect`: \*OS: 파일별 encryption data (III/11)
- `com.apple.installd.*`: \*OS: `installType`, `uniqueInstallID`와 같이 installd가 사용하는 metadata

### Resource Forks | macOS ADS

Resource forks는 macOS에서 alternate data stream을 제공합니다. 콘텐츠는 `com.apple.ResourceFork` extended attribute에 저장할 수 있으며 `file/..namedfork/rsrc`를 통해 액세스할 수 있습니다.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
**다음과 같이 이 extended attribute를 포함하는 모든 파일을 찾을 수 있습니다:**
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

확장 속성 `com.apple.decmpfs`는 transparent compression을 위한 metadata를 저장하며, encryption을 나타내지 않습니다. compression format에 따라 compressed data가 속성 또는 resource fork에 저장될 수 있으며, 읽을 때 transparent하게 decompression됩니다.

`UF_COMPRESSED` flag는 `ls -lO`에서 `compressed`로 표시됩니다. 이를 수동으로 clear하지 마세요. 그렇게 하면 system이 compressed representation을 잘못 해석할 수 있습니다.

flag를 clear하는 command는 forensic review 중 유용하므로 여기에 표시했지만, compressed file에 실행하면 metadata가 복구될 때까지 해당 file이 empty이거나 접근할 수 없는 것처럼 보일 수 있습니다:
```bash
chflags nocompressed /path/to/file
```
내장된 `/usr/bin/afscexpand` utility는 transparently compressed files의 expansion을 강제로 수행할 수 있습니다. 별도의 third-party `afsctool` utility도 Apple filesystem compression을 검사하거나 decompress할 수 있지만, 내장 command와 혼동해서는 안 됩니다. <sup>[[8]](#references)</sup>


### Interesting configuration locations (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | system daemons / frameworks에서 선택적 또는 experimental behavior를 제어하는 Apple의 feature-flag plist files 저장 | attacker가 SIP를 우회하거나 privilege를 획득할 수 있다면, 이를 tampering하여 hidden code paths를 활성화하거나 safeguards를 비활성화할 수 있음 |
| `/System/Library/CoreServices/systemVersion.plist` | apps / installers가 behavior를 제한하는 데 사용하는 macOS version metadata(ProductVersion, BuildVersion) 저장 | modification을 통해 apps 또는 installers가 지원되지 않는 OS versions를 허용하거나 features를 unlock하도록 속일 수 있음 |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | writable한 경우 attackers가 settings를 inject하여 app behavior를 유도하거나 protections를 비활성화하거나 misconfiguration을 유발할 수 있음 |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | background daemons 및 agents를 위한 Plist definitions | permissions가 허용하면 malicious plist insertion 또는 manipulation을 통해 persistence나 privilege escalations가 가능함 |
| `/etc/hosts` | system DNS resolver가 사용하는 Hostname ↔ IP mappings | domain names를 redirect하거나 traffic을 intercept하거나 local control 하에서 services를 spoof할 수 있음 |
| `/etc/sudoers` | 누가 `sudo`로 commands를 실행할 수 있는지 및 해당 conditions 정의 | corrupted sudoers file은 attacker accounts에 root 또는 부적절한 privileges를 부여할 수 있음 |
| `/private/var/db/dslocal/nodes/Default/users/` | Local user account definition plists | tampering을 통해 user accounts, password hashes 또는 user metadata를 생성하거나 수정할 수 있음 |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | kexts를 설치하거나 수정하면 kernel-level control로 이어질 수 있으며, SIP / signature policies에 의해 강하게 보호됨 |
| `/private/var/db/SystemPolicyConfiguration/` | system policy enforcement(예: Gatekeeper, notarization)을 위한 configuration 저장 | 이를 tampering하면 policy checks 또는 trust rules의 우회가 가능할 수 있음 |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries 및 config files | Misconfiguration은 weak SSH security, unauthorized access 또는 insecure algorithms로 이어질 수 있음 |
| `/System/Library/Sandbox/Profiles` | process actions를 제한하는 system sandbox profiles(SBPL) | profiles를 교체하거나 변경하면 sandbox escape vectors가 열리거나 containment가 약화될 수 있음 |

> **Note**: 이러한 paths 중 다수는 SIP-protected directories(예: `/System`) 아래에 있으며, SIP가 disabled 또는 bypass되지 않는 한 writes로부터 보호됩니다.


## Universal Binaries And Mach-O Format

Mach-O는 macOS의 native executable format입니다. universal 또는 fat binary는 하나의 file 안에 여러 architecture-specific Mach-O slices를 묶습니다. 전용 page에서 두 formats를 모두 설명합니다.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk And Handler Metadata

LaunchServices, file quarantine 및 Gatekeeper는 macOS가 downloaded files를 처리하고 extensions 및 URL schemes에 사용할 applications를 선택하는 방식에 종합적으로 영향을 줍니다. 이러한 databases 및 internal resource files는 releases에 따라 변경되므로, private CoreTypes path를 안정적인 policy interface로 취급하지 말고 전용 pages를 사용하십시오.

legacy CoreTypes risk metadata를 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` 아래에 노출하는 releases에서 일반적으로 확인되는 categories는 다음과 같습니다:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: 해당 application policy에 따라 automatic opening에 충분히 안전한 것으로 간주되는 content입니다.
- **`LSRiskCategoryNeutral`**: 일반적으로 warning을 trigger하지 않으며 automatic opening되지 않는 content입니다.
- **`LSRiskCategoryUnsafeExecutable`**: user에게 application warning을 표시해야 하는 executable content입니다.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: executable content를 포함할 수 있어 추가 inspection이 필요한 archives와 같은 containers입니다.

이는 implementation details이며 안정적인 public policy API가 아닙니다. 테스트 중인 macOS version에서 실제 metadata와 Safari/Gatekeeper behavior를 확인하십시오.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: downloaded files에 대한 정보(예: download된 URL)를 포함합니다.
- **Unified log**: 현재 macOS versions에서는 `log show` 및 `log stream`을 사용하여 system 및 application events를 query합니다. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** 및 **`/private/var/log/asl/*.asl`**: older systems에서 여전히 relevant할 수 있는 legacy logging artifacts입니다. 이러한 releases에서는 `/System/Library/LaunchDaemons/com.apple.syslogd.plist`가 `syslogd`를 configure하며, `launchctl list | grep com.apple.syslogd`를 사용하면 service가 loaded되어 있는지 확인하는 데 도움이 됩니다.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder"를 통해 recently accessed files 및 applications를 저장합니다.
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: login items와 관련된 legacy preference path입니다. modern macOS versions에서는 추가 mechanisms를 사용합니다.
- **`$HOME/Library/Logs/DiskUtility.log`**: drives에 대한 정보(USB devices 포함)를 포함할 수 있는 legacy Disk Utility log입니다.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: wireless access points에 대한 data입니다.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: legacy launchd override data입니다.

## References

- [1] [Apple - File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programming Guide](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache overview](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - File System Programming Guide: macOS File System Security](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS manual page](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS manual page](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS manual page](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
