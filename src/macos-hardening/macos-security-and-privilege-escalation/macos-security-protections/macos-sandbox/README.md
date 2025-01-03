# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MacOS Sandbox (초기 이름: Seatbelt) **는 샌드박스 내에서 실행되는 애플리케이션의** **허용된 작업**을 **샌드박스 프로필에 지정된 대로 제한**합니다. 이는 **애플리케이션이 예상된 리소스만 접근하도록 보장하는 데 도움**을 줍니다.

**`com.apple.security.app-sandbox`** 권한을 가진 모든 애플리케이션은 샌드박스 내에서 실행됩니다. **Apple 바이너리**는 일반적으로 샌드박스 내에서 실행되며, **App Store의 모든 애플리케이션은 해당 권한을 가집니다**. 따라서 여러 애플리케이션이 샌드박스 내에서 실행됩니다.

프로세스가 할 수 있는 것과 할 수 없는 것을 제어하기 위해 **샌드박스는** 프로세스가 시도할 수 있는 거의 모든 작업(대부분의 시스템 호출 포함)에 **후크**를 가지고 있습니다. 그러나 애플리케이션의 **권한**에 따라 샌드박스는 프로세스에 대해 더 관대할 수 있습니다.

샌드박스의 몇 가지 중요한 구성 요소는 다음과 같습니다:

- **커널 확장** `/System/Library/Extensions/Sandbox.kext`
- **프라이빗 프레임워크** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- 사용자 공간에서 실행되는 **데몬** `/usr/libexec/sandboxd`
- **컨테이너** `~/Library/Containers`

### Containers

모든 샌드박스 애플리케이션은 `~/Library/Containers/{CFBundleIdentifier}`에 고유한 컨테이너를 가집니다:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
각 번들 ID 폴더 안에는 **plist**와 홈 폴더를 모방한 구조의 앱 **Data 디렉토리**를 찾을 수 있습니다:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> 심볼릭 링크가 Sandbox에서 "탈출"하여 다른 폴더에 접근하기 위해 존재하더라도, 앱은 여전히 **접근 권한**을 가져야 합니다. 이러한 권한은 `RedirectablePaths`의 **`.plist`** 안에 있습니다.

**`SandboxProfileData`**는 B64로 이스케이프된 컴파일된 샌드박스 프로필 CFData입니다.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> Sandbox 애플리케이션에 의해 생성/수정된 모든 것은 **격리 속성**을 갖게 됩니다. 이는 샌드박스 앱이 **`open`**으로 무언가를 실행하려고 할 때 Gatekeeper를 트리거하여 샌드박스 공간을 방지합니다.

## 샌드박스 프로필

샌드박스 프로필은 해당 **샌드박스**에서 **허용/금지**될 사항을 나타내는 구성 파일입니다. 이는 [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) 프로그래밍 언어를 사용하는 **샌드박스 프로필 언어(SBPL)**를 사용합니다.

여기 예시를 찾을 수 있습니다:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> 이 [**연구**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)를 확인하여 허용되거나 거부될 수 있는 추가 작업을 확인하세요.
>
> 프로파일의 컴파일된 버전에서는 작업의 이름이 dylib와 kext에 의해 알려진 배열의 항목으로 대체되어 컴파일된 버전이 더 짧고 읽기 어렵게 만듭니다.

중요한 **시스템 서비스**는 `mdnsresponder` 서비스와 같은 자체 맞춤 **샌드박스** 내에서 실행됩니다. 이러한 맞춤 **샌드박스 프로파일**은 다음에서 확인할 수 있습니다:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- 다른 샌드박스 프로파일은 [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)에서 확인할 수 있습니다.

**App Store** 앱은 **프로파일** **`/System/Library/Sandbox/Profiles/application.sb`**를 사용합니다. 이 프로파일에서 **`com.apple.security.network.server`**와 같은 권한이 프로세스가 네트워크를 사용할 수 있도록 허용하는 방법을 확인할 수 있습니다.

그런 다음, 일부 **Apple 데몬 서비스**는 `/System/Library/Sandbox/Profiles/*.sb` 또는 `/usr/share/sandbox/*.sb`에 위치한 다른 프로파일을 사용합니다. 이러한 샌드박스는 API `sandbox_init_XXX`를 호출하는 주요 기능에 적용됩니다.

**SIP**는 `/System/Library/Sandbox/rootless.conf`에 있는 platform_profile이라는 샌드박스 프로파일입니다.

### 샌드박스 프로파일 예시

**특정 샌드박스 프로파일**로 애플리케이션을 시작하려면 다음을 사용할 수 있습니다:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!NOTE]
> **Apple이 작성한** **소프트웨어**는 **Windows**에서 **추가적인 보안 조치**가 없으며, 애플리케이션 샌드박싱과 같은 기능이 없습니다.

우회 예시:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (그들은 `~$`로 시작하는 이름의 파일을 샌드박스 외부에 쓸 수 있습니다).

### 샌드박스 추적

#### 프로필을 통한

작업이 확인될 때마다 샌드박스가 수행하는 모든 검사를 추적할 수 있습니다. 이를 위해 다음 프로필을 생성하십시오:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
그런 다음 해당 프로필을 사용하여 무언가를 실행하십시오:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out`에서 호출될 때마다 수행된 각 샌드박스 검사를 볼 수 있습니다(즉, 많은 중복이 발생합니다).

**`-t`** 매개변수를 사용하여 샌드박스를 추적할 수도 있습니다: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API를 통한 방법

`libsystem_sandbox.dylib`에서 내보낸 `sandbox_set_trace_path` 함수는 샌드박스 검사가 기록될 추적 파일 이름을 지정할 수 있게 해줍니다.\
`sandbox_vtrace_enable()`을 호출하고, 그 후 `sandbox_vtrace_report()`를 호출하여 버퍼에서 로그 오류를 가져오는 유사한 작업도 가능합니다.

### 샌드박스 검사

`libsandbox.dylib`는 프로세스의 샌드박스 상태 목록(확장 포함)을 제공하는 `sandbox_inspect_pid`라는 함수를 내보냅니다. 그러나 이 함수는 플랫폼 바이너리만 사용할 수 있습니다.

### MacOS 및 iOS 샌드박스 프로파일

MacOS는 시스템 샌드박스 프로파일을 두 위치에 저장합니다: **/usr/share/sandbox/** 및 **/System/Library/Sandbox/Profiles**.

그리고 서드파티 애플리케이션이 _**com.apple.security.app-sandbox**_ 권한을 가지고 있다면, 시스템은 해당 프로세스에 **/System/Library/Sandbox/Profiles/application.sb** 프로파일을 적용합니다.

iOS에서는 기본 프로파일이 **container**라고 하며, SBPL 텍스트 표현이 없습니다. 메모리에서 이 샌드박스는 샌드박스의 각 권한에 대해 허용/거부 이진 트리로 표현됩니다.

### App Store 앱의 사용자 정의 SBPL

회사가 **사용자 정의 샌드박스 프로파일**로 앱을 실행할 수 있는 가능성이 있습니다(기본 프로파일 대신). 그들은 Apple의 승인이 필요한 **`com.apple.security.temporary-exception.sbpl`** 권한을 사용해야 합니다.

이 권한의 정의는 **`/System/Library/Sandbox/Profiles/application.sb:`**에서 확인할 수 있습니다.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
이것은 **이 권한 이후의 문자열을** Sandbox 프로필로 **eval**합니다.

### Sandbox 프로필 컴파일 및 디컴파일

**`sandbox-exec`** 도구는 `libsandbox.dylib`의 `sandbox_compile_*` 함수를 사용합니다. 내보내는 주요 함수는 다음과 같습니다: `sandbox_compile_file` (파일 경로를 기대하며, 매개변수 `-f`), `sandbox_compile_string` (문자열을 기대하며, 매개변수 `-p`), `sandbox_compile_name` (컨테이너의 이름을 기대하며, 매개변수 `-n`), `sandbox_compile_entitlements` (권한 plist를 기대합니다).

이 도구의 리버스 및 [**오픈 소스 버전인 sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c)는 **`sandbox-exec`**가 컴파일된 Sandbox 프로필을 파일에 기록할 수 있게 합니다.

또한, 프로세스를 컨테이너 내에 제한하려면 `sandbox_spawnattrs_set[container/profilename]`를 호출하고 컨테이너 또는 기존 프로필을 전달할 수 있습니다.

## Sandbox 디버그 및 우회

macOS에서는 프로세스가 커널에 의해 처음부터 Sandbox에 격리되는 iOS와 달리, **프로세스가 스스로 Sandbox에 참여해야 합니다**. 이는 macOS에서 프로세스가 적극적으로 Sandbox에 들어가기로 결정할 때까지 Sandbox에 의해 제한되지 않음을 의미하며, App Store 앱은 항상 Sandbox에 격리됩니다.

프로세스는 `com.apple.security.app-sandbox` 권한이 있을 경우 사용자 공간에서 시작할 때 자동으로 Sandbox에 격리됩니다. 이 프로세스에 대한 자세한 설명은 다음을 확인하십시오:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox 확장**

확장은 객체에 추가 권한을 부여할 수 있으며, 다음 함수 중 하나를 호출하여 부여됩니다:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

확장은 프로세스 자격 증명에서 접근할 수 있는 두 번째 MACF 레이블 슬롯에 저장됩니다. 다음 **`sbtool`**이 이 정보를 접근할 수 있습니다.

확장은 일반적으로 허용된 프로세스에 의해 부여되며, 예를 들어, `tccd`는 프로세스가 사진에 접근하려고 시도하고 XPC 메시지에서 허용되었을 때 `com.apple.tcc.kTCCServicePhotos`의 확장 토큰을 부여합니다. 그런 다음 프로세스는 확장 토큰을 소비해야 추가됩니다.\
확장 토큰은 부여된 권한을 인코딩하는 긴 16진수입니다. 그러나 허용된 PID가 하드코딩되어 있지 않으므로, 토큰에 접근할 수 있는 모든 프로세스가 **여러 프로세스에 의해 소비될 수 있습니다**.

확장은 권한과 매우 관련이 있으므로 특정 권한을 가지면 특정 확장이 자동으로 부여될 수 있습니다.

### **PID 권한 확인**

[**이것에 따르면**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), **`sandbox_check`** 함수(이는 `__mac_syscall`입니다)는 특정 PID, 감사 토큰 또는 고유 ID에 대해 **작업이 허용되는지 여부를** 확인할 수 있습니다.

[**도구 sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (여기 [컴파일된 버전 찾기](https://newosxbook.com/articles/hitsb.html))는 PID가 특정 작업을 수행할 수 있는지 확인할 수 있습니다:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

샌드박스를 일시 중지하고 다시 시작하는 것도 가능합니다. `libsystem_sandbox.dylib`의 `sandbox_suspend` 및 `sandbox_unsuspend` 함수를 사용합니다.

일시 중지 함수를 호출하려면 호출자가 이를 호출할 수 있도록 몇 가지 권한이 확인됩니다:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

이 시스템 호출 (#381)은 첫 번째 인수로 실행할 모듈을 나타내는 문자열을 기대하며, 두 번째 인수로 실행할 함수를 나타내는 코드를 기대합니다. 세 번째 인수는 실행된 함수에 따라 달라집니다.

함수 `___sandbox_ms` 호출은 `mac_syscall`을 래핑하며 첫 번째 인수로 `"Sandbox"`를 나타냅니다. `___sandbox_msp`는 `mac_set_proc` (#387)의 래퍼입니다. 그런 다음 `___sandbox_ms`에서 지원되는 일부 코드는 다음 표에서 확인할 수 있습니다:

- **set_profile (#0)**: 프로세스에 컴파일된 또는 명명된 프로파일을 적용합니다.
- **platform_policy (#1)**: 플랫폼별 정책 검사를 시행합니다 (macOS와 iOS 간에 다름).
- **check_sandbox (#2)**: 특정 샌드박스 작업의 수동 검사를 수행합니다.
- **note (#3)**: 샌드박스에 주석을 추가합니다.
- **container (#4)**: 일반적으로 디버깅 또는 식별을 위해 샌드박스에 주석을 첨부합니다.
- **extension_issue (#5)**: 프로세스에 대한 새로운 확장을 생성합니다.
- **extension_consume (#6)**: 주어진 확장을 소비합니다.
- **extension_release (#7)**: 소비된 확장에 연결된 메모리를 해제합니다.
- **extension_update_file (#8)**: 샌드박스 내의 기존 파일 확장의 매개변수를 수정합니다.
- **extension_twiddle (#9)**: 기존 파일 확장을 조정하거나 수정합니다 (예: TextEdit, rtf, rtfd).
- **suspend (#10)**: 모든 샌드박스 검사를 일시적으로 중지합니다 (적절한 권한 필요).
- **unsuspend (#11)**: 이전에 일시 중지된 모든 샌드박스 검사를 재개합니다.
- **passthrough_access (#12)**: 샌드박스 검사를 우회하여 리소스에 대한 직접적인 패스스루 액세스를 허용합니다.
- **set_container_path (#13)**: (iOS 전용) 앱 그룹 또는 서명 ID에 대한 컨테이너 경로를 설정합니다.
- **container_map (#14)**: (iOS 전용) `containermanagerd`에서 컨테이너 경로를 검색합니다.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) 샌드박스에서 사용자 모드 메타데이터를 설정합니다.
- **inspect (#16)**: 샌드박스화된 프로세스에 대한 디버그 정보를 제공합니다.
- **dump (#18)**: (macOS 11) 분석을 위해 샌드박스의 현재 프로파일을 덤프합니다.
- **vtrace (#19)**: 모니터링 또는 디버깅을 위해 샌드박스 작업을 추적합니다.
- **builtin_profile_deactivate (#20)**: (macOS < 11) 명명된 프로파일을 비활성화합니다 (예: `pe_i_can_has_debugger`).
- **check_bulk (#21)**: 단일 호출에서 여러 `sandbox_check` 작업을 수행합니다.
- **reference_retain_by_audit_token (#28)**: 샌드박스 검사에 사용할 감사 토큰에 대한 참조를 생성합니다.
- **reference_release (#29)**: 이전에 유지된 감사 토큰 참조를 해제합니다.
- **rootless_allows_task_for_pid (#30)**: `task_for_pid`가 허용되는지 확인합니다 (유사한 `csr` 검사).
- **rootless_whitelist_push (#31)**: (macOS) 시스템 무결성 보호(SIP) 매니페스트 파일을 적용합니다.
- **rootless_whitelist_check (preflight) (#32)**: 실행 전에 SIP 매니페스트 파일을 검사합니다.
- **rootless_protected_volume (#33)**: (macOS) 디스크 또는 파티션에 SIP 보호를 적용합니다.
- **rootless_mkdir_protected (#34)**: 디렉토리 생성 프로세스에 SIP/DataVault 보호를 적용합니다.

## Sandbox.kext

iOS에서는 커널 확장이 **모든 프로파일을 하드코딩**하여 `__TEXT.__const` 세그먼트 내에 포함되어 수정되지 않도록 합니다. 다음은 커널 확장에서 흥미로운 몇 가지 함수입니다:

- **`hook_policy_init`**: `mpo_policy_init`을 후킹하며 `mac_policy_register` 이후에 호출됩니다. 샌드박스의 대부분 초기화를 수행합니다. SIP도 초기화합니다.
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` 및 `security.mac.sandbox.debug_mode`를 등록하여 sysctl 인터페이스를 설정합니다 (PE_i_can_has_debugger로 부팅된 경우).
- **`hook_policy_syscall`**: "Sandbox"를 첫 번째 인수로 하고 두 번째 인수로 작업을 나타내는 코드와 함께 `mac_syscall`에 의해 호출됩니다. 요청된 코드에 따라 실행할 코드를 찾기 위해 switch가 사용됩니다.

### MACF Hooks

**`Sandbox.kext`**는 MACF를 통해 백 개 이상의 후킹을 사용합니다. 대부분의 후킹은 작업을 수행할 수 있는 사소한 경우를 확인하며, 그렇지 않은 경우 **`cred_sb_evalutate`**를 호출하여 MACF의 **credentials**와 수행할 **operation**에 해당하는 숫자 및 출력용 **buffer**를 전달합니다.

그 좋은 예는 **`_mpo_file_check_mmap`** 함수로, **`mmap`**을 후킹하며 새로운 메모리가 쓰기 가능할지 확인한 후 (그렇지 않으면 실행을 허용하지 않음), dyld 공유 캐시에서 사용되는지 확인하고, 그렇다면 실행을 허용하며, 마지막으로 **`sb_evaluate_internal`** (또는 그 래퍼 중 하나)을 호출하여 추가 허용 검사를 수행합니다.

게다가, 샌드박스가 사용하는 수백 개의 후킹 중에서 특히 흥미로운 세 가지가 있습니다:

- `mpo_proc_check_for`: 필요할 경우 프로파일을 적용하며, 이전에 적용되지 않은 경우에만 적용합니다.
- `mpo_vnode_check_exec`: 프로세스가 관련 이진 파일을 로드할 때 호출되며, 프로파일 검사가 수행되고 SUID/SGID 실행을 금지하는 검사도 수행됩니다.
- `mpo_cred_label_update_execve`: 레이블이 할당될 때 호출됩니다. 이 함수는 이진 파일이 완전히 로드되었지만 아직 실행되지 않았을 때 호출되므로 가장 긴 함수입니다. 샌드박스 객체를 생성하고, kauth 자격 증명에 샌드박스 구조체를 첨부하고, mach 포트에 대한 액세스를 제거하는 등의 작업을 수행합니다.

**`_cred_sb_evalutate`**는 **`sb_evaluate_internal`**의 래퍼이며, 이 함수는 전달된 자격 증명을 가져온 후 **`eval`** 함수를 사용하여 평가를 수행합니다. 이 함수는 일반적으로 모든 프로세스에 기본적으로 적용되는 **platform profile**을 평가한 다음 **specific process profile**을 평가합니다. 플랫폼 프로파일은 macOS의 **SIP**의 주요 구성 요소 중 하나입니다.

## Sandboxd

샌드박스는 XPC Mach 서비스 `com.apple.sandboxd`를 노출하는 사용자 데몬도 실행하며, 커널 확장이 통신하는 데 사용하는 특별한 포트 14 (`HOST_SEATBELT_PORT`)에 바인딩됩니다. MIG를 사용하여 일부 기능을 노출합니다.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
