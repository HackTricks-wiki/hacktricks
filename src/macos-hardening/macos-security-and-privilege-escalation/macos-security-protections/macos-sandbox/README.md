# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

MacOS Sandbox(처음에는 Seatbelt이라고 불림)는 sandbox profile에서 지정한 **허용된 작업**으로 sandbox 내부에서 실행되는 **애플리케이션을 제한**합니다. 이를 통해 **애플리케이션이 예상된 리소스에만 액세스하도록** 할 수 있습니다.

**entitlement** **`com.apple.security.app-sandbox`**를 가진 모든 앱은 sandbox 내부에서 실행됩니다. **Apple 바이너리**는 일반적으로 Sandbox 내부에서 실행되며, **App Store의 모든 애플리케이션에는 해당 entitlement가 있습니다**. 따라서 여러 애플리케이션이 sandbox 내부에서 실행됩니다.<sup>[[4]](#references)</sup>

프로세스가 수행할 수 있는 작업과 수행할 수 없는 작업을 제어하기 위해 **Sandbox에는 hooks가 있으며**, **MACF**를 사용해 프로세스가 시도할 수 있는 거의 모든 작업(대부분의 syscall 포함)에 적용됩니다. 그러나 앱의 **entitlement**에 **따라** Sandbox는 프로세스에 대해 더 permissive할 수 있습니다.

Sandbox의 주요 구성 요소는 다음과 같습니다.

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- userland에서 실행되는 **daemon** `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

모든 sandboxed application에는 `~/Library/Containers/{CFBundleIdentifier}`에 자체 container가 있습니다:
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
각 bundle id 폴더 안에서는 Home 폴더와 유사한 구조로 된 해당 App의 **plist**와 **Data directory**를 찾을 수 있습니다:
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
> symlinks가 Sandbox에서 "escape"하여 다른 폴더에 접근할 수 있도록 존재하더라도, App에는 해당 폴더에 접근할 **permissions**가 여전히 필요합니다. 이러한 permissions는 **`RedirectablePaths`**의 **`.plist`** 내부에 있습니다.

**`SandboxProfileData`**는 B64로 escape된 compiled sandbox profile CFData입니다.
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
> Sandboxed 애플리케이션이 생성하거나 수정하는 모든 항목에는 **quarantine attribute**가 지정됩니다. 이로 인해 Sandbox 앱이 **`open`**을 사용하여 무언가를 실행하려고 하면 Gatekeeper가 트리거되어 Sandbox 공간에서 실행되지 않습니다.

## Sandbox Profiles

Sandbox 프로필은 해당 **Sandbox**에서 무엇이 **허용/금지**되는지를 나타내는 구성 파일입니다. 이 프로필은 [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) 프로그래밍 언어를 사용하는 **Sandbox Profile Language (SBPL)**를 사용합니다.

여기에서 예시를 확인할 수 있습니다:
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
> 더 많은 허용 또는 거부 가능한 동작을 확인하려면 이 [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)를 **확인하세요.**<sup>[[5]](#references)</sup>
>
> 컴파일된 버전의 profile에서는 작업 이름이 dylib와 kext가 알고 있는 배열의 항목으로 대체되므로, 컴파일된 버전은 더 짧고 읽기 어렵습니다.

중요한 **system services**도 `mdnsresponder` service와 같이 자체 custom **sandbox** 내부에서 실행됩니다. 다음 위치에서 이러한 custom **sandbox profiles**을 확인할 수 있습니다.

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- 다른 sandbox profiles은 [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)에서 확인할 수 있습니다.
- iOS에서 platform profile은 binary 내부의 `_platform_profile_data`에 있는 sandbox `.kext` 내부에 존재합니다.

**App Store** apps은 **profile** **`/System/Library/Sandbox/Profiles/application.sb`**를 사용합니다. 이 profile에서 **`com.apple.security.network.server`**와 같은 entitlements가 process의 network 사용을 허용하는 방식을 확인할 수 있습니다.

그런 다음 일부 **Apple daemon services**은 `/System/Library/Sandbox/Profiles/*.sb` 또는 `/usr/share/sandbox/*.sb`에 있는 서로 다른 profiles을 사용합니다. 이러한 sandboxes은 API `sandbox_init_XXX`를 호출하는 main function에서 적용됩니다.<sup>[[3]](#references)</sup>

**SIP**는 `/System/Library/Sandbox/rootless.conf`에 있는 platform_profile이라는 Sandbox profile입니다.

### Sandbox Profile Examples

**specific sandbox profile**로 application을 시작하려면 다음을 사용할 수 있습니다.
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
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

> [!TIP]
> **Windows**에서 실행되는 **Apple-authored** **software**에는 application sandboxing과 같은 **추가 보안 예방 조치가 적용되지 않는다는 점에 유의하세요**.

Bypasses examples:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (이들은 이름이 `~$`로 시작하는 파일을 sandbox 외부에 작성할 수 있습니다).<sup>[[7]](#references)</sup>

### Sandbox 추적

#### 프로필 사용

sandbox가 작업을 확인할 때마다 수행하는 모든 검사를 추적할 수 있습니다. 이를 위해 다음 프로필을 생성하세요:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
그런 다음 해당 프로필을 사용하여 무언가를 실행하면 됩니다:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
`/tmp/trace.out`에서 호출될 때마다 수행된 각 sandbox check를 확인할 수 있습니다(따라서 중복 항목이 많이 표시됩니다).

**`-t`** parameter를 사용해 sandbox를 trace하는 것도 가능합니다: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API를 통한 방법

`libsystem_sandbox.dylib`가 export하는 `sandbox_set_trace_path` function을 사용하면 sandbox checks가 기록될 trace filename을 지정할 수 있습니다.\
`sandbox_vtrace_enable()`을 호출한 다음, buffer에서 `sandbox_vtrace_report()`를 호출해 logs error를 가져오는 방식도 가능합니다.

### Sandbox Inspection

`libsandbox.dylib`는 프로세스의 sandbox state(extensions 포함) 목록을 반환하는 `sandbox_inspect_pid` function을 export합니다. 그러나 platform binaries만 이 function을 사용할 수 있습니다.

### MacOS & iOS Sandbox Profiles

MacOS는 system sandbox profiles을 **/usr/share/sandbox/** 및 **/System/Library/Sandbox/Profiles** 두 위치에 저장합니다.

그리고 third-party application이 _**com.apple.security.app-sandbox**_ entitlement를 가지고 있으면, system은 해당 프로세스에 **/System/Library/Sandbox/Profiles/application.sb** profile을 적용합니다.

iOS에서 default profile의 이름은 **container**이며, SBPL text representation은 제공되지 않습니다. Memory에서 이 sandbox는 sandbox의 각 permission에 대한 Allow/Deny binary tree로 표현됩니다.

### App Store apps의 Custom SBPL

회사가 자신의 apps를 default profile 대신 **custom Sandbox profiles**로 실행하도록 만드는 것이 가능할 수 있습니다. 이를 위해서는 Apple의 authorization이 필요한 **`com.apple.security.temporary-exception.sbpl`** entitlement를 사용해야 합니다.

이 entitlement의 definition은 **`/System/Library/Sandbox/Profiles/application.sb:`**에서 확인할 수 있습니다.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
이렇게 하면 **이 entitlement 뒤의 문자열을 Sandbox profile로 eval**합니다.

### Sandbox Profile 컴파일 및 decompiling

**`sandbox-exec`** tool은 `libsandbox.dylib`의 `sandbox_compile_*` functions를 사용합니다. Export되는 주요 functions는 다음과 같습니다: `sandbox_compile_file` (file path를 예상하며, param `-f`), `sandbox_compile_string` (string을 예상하며, param `-p`), `sandbox_compile_name` (container의 name을 예상하며, param `-n`), `sandbox_compile_entitlements` (entitlements plist를 예상).

이 reversed 및 [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c)을 사용하면 **`sandbox-exec`**가 compiled sandbox profile을 file에 작성하도록 할 수 있습니다.

또한 process를 container 내부에 confine하려면 `sandbox_spawnattrs_set[container/profilename]`을 호출하고 container 또는 pre-existing profile을 전달할 수 있습니다.

## Debug & Bypass Sandbox

iOS에서는 process가 처음부터 kernel에 의해 sandboxed되는 것과 달리, macOS에서는 **process가 직접 sandbox에 opt-in해야 합니다**. 즉, macOS에서는 process가 적극적으로 sandbox에 진입하기 전까지 sandbox의 제한을 받지 않지만, App Store apps는 항상 sandboxed됩니다.

Process에 `com.apple.security.app-sandbox` entitlement가 있으면 userland에서 시작할 때 자동으로 Sandboxed됩니다. 이 process에 대한 자세한 설명은 다음을 확인하세요:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions는 object에 추가 privileges를 부여하며, 다음 functions 중 하나를 호출하여 부여됩니다:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions는 process credentials에서 접근할 수 있는 두 번째 MACF label slot에 저장됩니다. 다음 **`sbtool`**을 사용하면 이 정보에 접근할 수 있습니다.

Extensions는 일반적으로 allowed processes에 의해 부여됩니다. 예를 들어 process가 photos에 접근하려 했고 XPC message에서 허용된 경우, `tccd`는 `com.apple.tcc.kTCCServicePhotos`의 extension token을 부여합니다. 그런 다음 process는 extension token을 consume해야 해당 token이 process에 추가됩니다.\
Extension token은 부여된 permissions를 encode하는 긴 hexadecimal 값이라는 점에 유의하세요. 그러나 allowed PID가 hardcoded되어 있지 않으므로 token에 접근할 수 있는 모든 process에 의해 **여러 process가 consume할 수 있습니다**.

또한 extensions는 entitlements와도 밀접한 관련이 있으므로, 특정 entitlements를 보유하면 특정 extensions가 자동으로 부여될 수 있습니다.

### **PID Privileges 확인**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), **`sandbox_check`** functions (`__mac_syscall`임)은 특정 PID, audit token 또는 unique ID에서 operation이 sandbox에 의해 허용되는지 여부를 확인할 수 있습니다.<sup>[[8]](#references)</sup>

[**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c)은 PID가 특정 actions를 수행할 수 있는지 확인할 수 있습니다([여기에서 compiled version을 찾을 수 있습니다](https://newosxbook.com/articles/hitsb.html)):
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

`libsystem_sandbox.dylib`의 `sandbox_suspend` 및 `sandbox_unsuspend` 함수를 사용하여 sandbox를 suspend 및 unsuspend하는 것도 가능합니다.

suspend 함수를 호출하려면 호출자가 해당 함수를 호출할 수 있도록 일부 entitlements가 확인된다는 점에 유의해야 합니다. 예시는 다음과 같습니다.

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

이 system call(#381)은 먼저 실행할 module을 나타내는 하나의 문자열 인수를 받고, 두 번째 인수로 실행할 function을 나타내는 code를 받습니다. 세 번째 인수는 실행된 function에 따라 달라집니다.<sup>[[2]](#references)</sup>

`___sandbox_ms` 함수는 첫 번째 인수로 `"Sandbox"`를 지정하여 `mac_syscall` 호출을 wrapping하며, `___sandbox_msp`가 `mac_set_proc`(#387)의 wrapper인 것과 같습니다. 그런 다음 `___sandbox_ms`가 지원하는 일부 code는 다음 표에서 확인할 수 있습니다.

- **set_profile (#0)**: compiled 또는 named profile을 process에 적용합니다.
- **platform_policy (#1)**: platform별 policy check를 적용합니다(macOS와 iOS에 따라 다름).
- **check_sandbox (#2)**: 특정 sandbox operation을 수동으로 확인합니다.
- **note (#3)**: Sandbox에 annotation을 추가합니다.
- **container (#4)**: 일반적으로 debugging 또는 identification을 위해 sandbox에 annotation을 연결합니다.
- **extension_issue (#5)**: process에 사용할 새로운 extension을 생성합니다.
- **extension_consume (#6)**: 지정된 extension을 consume합니다.
- **extension_release (#7)**: consume된 extension에 연결된 memory를 release합니다.
- **extension_update_file (#8)**: sandbox 내 기존 file extension의 parameter를 수정합니다.
- **extension_twiddle (#9)**: 기존 file extension(예: TextEdit, rtf, rtfd)을 조정하거나 수정합니다.
- **suspend (#10)**: 모든 sandbox check를 일시적으로 suspend합니다(적절한 entitlements 필요).
- **unsuspend (#11)**: 이전에 suspend된 모든 sandbox check를 resume합니다.
- **passthrough_access (#12)**: sandbox check를 우회하여 resource에 직접 passthrough access를 허용합니다.
- **set_container_path (#13)**: (iOS 전용) app group 또는 signing ID의 container path를 설정합니다.
- **container_map (#14)**: `containermanagerd`에서 container path를 가져옵니다.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) sandbox에 user mode metadata를 설정합니다.
- **inspect (#16)**: sandboxed process에 대한 debug 정보를 제공합니다.
- **dump (#18)**: (macOS 11) 분석을 위해 sandbox의 현재 profile을 dump합니다.
- **vtrace (#19)**: monitoring 또는 debugging을 위해 sandbox operation을 trace합니다.
- **builtin_profile_deactivate (#20)**: (macOS < 11) named profile(예: `pe_i_can_has_debugger`)을 deactivate합니다.
- **check_bulk (#21)**: 단일 호출에서 여러 `sandbox_check` operation을 수행합니다.
- **reference_retain_by_audit_token (#28)**: sandbox check에 사용할 audit token의 reference를 생성합니다.
- **reference_release (#29)**: 이전에 retain된 audit token reference를 release합니다.
- **rootless_allows_task_for_pid (#30)**: `task_for_pid`가 허용되는지 확인합니다(`csr` check와 유사).
- **rootless_whitelist_push (#31)**: (macOS) System Integrity Protection(SIP) manifest file을 적용합니다.
- **rootless_whitelist_check (preflight) (#32)**: 실행 전에 SIP manifest file을 확인합니다.
- **rootless_protected_volume (#33)**: (macOS) disk 또는 partition에 SIP protection을 적용합니다.
- **rootless_mkdir_protected (#34)**: directory creation process에 SIP/DataVault protection을 적용합니다.

## Sandbox.kext

iOS에서는 kernel extension에 **모든 profile이 hardcoded**되어 있으며, profile이 수정되는 것을 방지하기 위해 `__TEXT.__const` segment 안에 저장됩니다. 다음은 kernel extension의 흥미로운 function 일부입니다.

- **`hook_policy_init`**: `mpo_policy_init`을 hook하며 `mac_policy_register` 이후 호출됩니다. Sandbox 초기화 대부분을 수행합니다. 또한 SIP를 초기화합니다.
- **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` 및 `security.mac.sandbox.debug_mode`(`PE_i_can_has_debugger`로 boot된 경우)를 등록하여 sysctl interface를 설정합니다.
- **`hook_policy_syscall`**: 첫 번째 인수로 `"Sandbox"`를, 두 번째 인수로 operation을 나타내는 code를 전달하여 `mac_syscall`에서 호출됩니다. 요청된 code에 따라 실행할 code를 찾기 위해 switch가 사용됩니다.

### MACF Hooks

**`Sandbox.kext`**는 MACF를 통해 100개가 넘는 hook을 사용합니다. 대부분의 hook은 action을 수행할 수 있도록 몇 가지 간단한 case만 확인하며, 그렇지 않은 경우 MACF의 **credentials**, 수행할 **operation**에 해당하는 number, 그리고 output을 위한 **buffer**를 사용하여 **`cred_sb_evalutate`**를 호출합니다.<sup>[[1]](#references)</sup>

이에 대한 좋은 예는 `mmap`을 hook하는 **`_mpo_file_check_mmap`** function입니다. 이 function은 먼저 새 memory가 writable인지 확인하고(writable하지 않으면 execution을 허용함), 그 다음 dyld shared cache에 사용되는지 확인하여 그렇다면 execution을 허용합니다. 마지막으로 추가적인 allowance check를 수행하기 위해 **`sb_evaluate_internal`**(또는 그 wrapper 중 하나)를 호출합니다.

또한 Sandbox가 사용하는 수백 개의 hook 중 특히 흥미로운 것은 다음 3개입니다.

- `mpo_proc_check_for`: 필요한 경우, 그리고 이전에 적용되지 않은 경우 profile을 적용합니다.
- `mpo_vnode_check_exec`: process가 연결된 binary를 load할 때 호출되며, profile check와 SUID/SGID execution을 금지하는 check를 수행합니다.
- `mpo_cred_label_update_execve`: label이 할당될 때 호출됩니다. binary가 완전히 load되었지만 아직 execute되지 않은 시점에 호출되므로 가장 긴 function입니다. sandbox object 생성, sandbox struct를 kauth credentials에 연결, mach port에 대한 access 제거 등의 action을 수행합니다.

**`_cred_sb_evalutate`**는 **`sb_evaluate_internal`**의 wrapper이며, 이 function은 전달받은 credentials를 가져온 다음 **`eval`** function을 사용하여 evaluation을 수행합니다. **`eval`**은 일반적으로 모든 process에 기본적으로 적용되는 **platform profile**과 이후 **specific process profile**을 평가합니다. platform profile은 macOS에서 **SIP**의 주요 component 중 하나라는 점에 유의해야 합니다.

## Sandboxd

Sandbox에는 user daemon도 실행되고 있으며, XPC Mach service `com.apple.sandboxd`를 expose하고 special port 14(`HOST_SEATBELT_PORT`)에 bind합니다. kernel extension은 이 port를 사용하여 daemon과 communicate합니다. 또한 MIG를 사용하여 일부 function을 expose합니다.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
