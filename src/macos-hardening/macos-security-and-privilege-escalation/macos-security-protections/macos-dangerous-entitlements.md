# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`**로 시작하는 entitlements는 서드파티에서 사용할 수 없으며, Apple만 이를 부여할 수 있습니다... 또는 enterprise certificate를 사용하는 경우 실제로 **`com.apple`**로 시작하는 자체 entitlements를 생성하여 이를 기반으로 한 보호 기능을 우회할 수 있습니다.

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement를 사용하면 **SIP를 우회**할 수 있습니다. 자세한 내용은 [여기](macos-sip.md#com.apple.rootless.install.heritable)를 확인하세요.

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement를 사용하면 **SIP를 우회**할 수 있습니다. 자세한 내용은[ 여기](macos-sip.md#com.apple.rootless.install)를 확인하세요.

### **`com.apple.system-task-ports` (이전에는 `task_for_pid-allow`라고 불림)**

이 entitlement를 사용하면 kernel을 제외한 **모든** process의 **task port를 가져올** 수 있습니다. 자세한 내용은 [**여기**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)를 확인하세요.

### `com.apple.security.get-task-allow`

이 entitlement를 가진 binary가 실행한 process의 task port를 **`com.apple.security.cs.debugger`** entitlement를 가진 다른 process가 가져와 **해당 process에 code를 inject**할 수 있습니다. 자세한 내용은 [**여기**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)를 확인하세요.

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement가 있는 apps는 `task_for_pid()`를 호출하여 `Get Task Allow` entitlement가 `true`로 설정된 unsigned 및 서드파티 apps의 유효한 task port를 가져올 수 있습니다. 그러나 debugging tool entitlement가 있어도 debugger는 **`Get Task Allow` entitlement가 없는** process의 **task ports를 가져올 수 없으며**, 따라서 해당 process는 System Integrity Protection의 보호를 받습니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)를 확인하세요.

### `com.apple.security.cs.disable-library-validation`

이 entitlement를 사용하면 main executable과 **동일한 Team ID로 서명되었거나 Apple이 서명한 경우가 아닌** frameworks, plug-ins 또는 libraries를 **load**할 수 있으므로, attacker는 임의의 library load를 악용하여 code를 inject할 수 있습니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)를 확인하세요.

### `com.apple.private.security.clear-library-validation`

이 entitlement는 **`com.apple.security.cs.disable-library-validation`**과 매우 유사하지만, library validation을 **직접 disable**하는 대신 process가 runtime에 **`csops` system call을 호출하여 이를 disable**할 수 있도록 합니다.

이 entitlement 이름은 이를 사용하는 `csops` operation 옆의 XNU에 hardcoded되어 있습니다:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`의 kernel handler(`bsd/kern/kern_proc.c`)는 이 primitive가 정확히 얼마나 제한적인지 보여준다:<sup>[3]</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
따라서 이 작업은 다음과 같습니다.

- **macOS-only**입니다(다른 모든 플랫폼에서는 `ENOTSUP`).
- **자기 자신에게만** 작동합니다(`forself == 1`) — 이를 사용해 다른 프로세스에서 library validation을 제거할 수 없습니다.
- 프로세스가 실제로 해당 entitlement를 **보유하고 있어야** 하며, 프로세스가 `CS_INSTALLER`로 플래그되었거나 subsystem root path에서 실행 중인 경우 거부합니다.
- 프로세스의 code-signing flags에서 **`CS_REQUIRE_LV | CS_FORCED_LV`**를 제거합니다.

XNU 주석은 의도된 사용 사례와 이것이 attacker에게 흥미로운 이유를 설명합니다.

> 이 옵션은 실행 중인 프로세스에서 library validation을 제거하는 데 사용됩니다. 프로그램이 신뢰할 수 없는 library를 load해야 하는 plugin architecture에서 사용됩니다. [...] 프로세스가 신뢰할 수 없는 library를 load한 후에는 향후 library validation에 의존하는 것이 효과적이지 않습니다.

즉, **이 entitlement를 포함하는 모든 binary는 dylib-injection target입니다**. `CS_REQUIRE_LV`를 제거한 후 해당 binary 내부에서 code를 실행하거나(또는 자체 plug-in을 load하도록 설득하면), host process가 수행하도록 허용된 작업을 그대로 상속받습니다.

### `com.apple.security.cs.allow-dyld-environment-variables`

이 entitlement는 library와 code를 inject하는 데 사용될 수 있는 **DYLD environment variables를 사용할 수 있도록** 합니다. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)를 확인하세요.

### `com.apple.private.tcc.manager` 또는 `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) 및 [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)에 따르면, 이러한 entitlements를 사용하면 **TCC** database를 **modify**할 수 있습니다.

### **`system.install.apple-software`** 및 **`system.install.apple-software.standar-user`**

이러한 entitlements를 사용하면 사용자에게 **permission을 요청하지 않고 software를 install**할 수 있으며, 이는 **privilege escalation**에 유용할 수 있습니다.

### `com.apple.private.security.kext-management`

**kernel에 kernel extension을 load하도록 요청하는 데** 필요한 entitlement입니다.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement가 있으면 **iCloud tokens를 제공하는** **`com.apple.iCloudHelper`** XPC service와 통신할 수 있습니다.

**iMovie**와 **Garageband**에 이 entitlement가 있었습니다.

해당 entitlement를 통해 **iCloud tokens를 획득하는** exploit에 대한 자세한 **information**은 다음 talk를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 이것으로 무엇을 할 수 있는지 모르겠습니다.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 이를 사용해 reboot 후 SSV-protected contents를 **update할 수 있다**고 언급합니다. 어떻게 사용하는지 알고 있다면 PR을 보내주세요!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 이를 사용해 reboot 후 SSV-protected contents를 **update할 수 있다**고 언급합니다. 어떻게 사용하는지 알고 있다면 PR을 보내주세요!

### `keychain-access-groups`

이 entitlement는 application이 access할 수 있는 **keychain** groups를 나열합니다:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

**Full Disk Access** 권한을 부여하며, TCC에서 부여할 수 있는 가장 높은 권한 중 하나입니다.

### **`kTCCServiceAppleEvents`**

**automating tasks**에 일반적으로 사용되는 다른 애플리케이션으로 이벤트를 보낼 수 있도록 합니다. 다른 앱을 제어하여 해당 앱에 부여된 권한을 악용할 수 있습니다.

예를 들어 해당 앱이 사용자에게 비밀번호를 묻게 만들 수 있습니다:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
또는 이들이 **임의의 작업**을 수행하도록 만들 수 있습니다.

### **`kTCCServiceEndpointSecurityClient`**

무엇보다도 **사용자의 TCC 데이터베이스에 쓰기**를 허용합니다.

### **`kTCCServiceSystemPolicySysAdminFiles`**

사용자의 **`NFSHomeDirectory`** 속성을 **변경**하여 홈 폴더 경로를 바꿀 수 있도록 하며, 따라서 **TCC를 우회**할 수 있습니다.

### **`kTCCServiceSystemPolicyAppBundles`**

앱 번들 내부(app.app)의 파일을 수정할 수 있도록 합니다. 이는 기본적으로 **허용되지 않습니다**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

_System Settings_ > _Privacy & Security_ > _App Management_에서 이 접근 권한을 가진 사용자를 확인할 수 있습니다.

### `kTCCServiceAccessibility`

프로세스가 **macOS 접근성 기능을 악용**할 수 있게 됩니다. 예를 들어 키 입력을 전송할 수 있습니다. 따라서 이 권한을 사용하면 Finder와 같은 앱을 제어할 수 있는 접근 권한을 요청하고 해당 권한으로 대화 상자를 승인할 수 있습니다.

## Trustcache/CDhash 관련 entitlements

Apple 바이너리의 downgrade된 버전 실행을 방지하는 Trustcache/CDhash 보호를 우회하는 데 사용될 수 있는 entitlements가 있습니다.

## 중간

### `com.apple.security.cs.allow-jit`

이 entitlement는 `mmap()` system function에 `MAP_JIT` flag를 전달하여 **쓰기 가능하고 실행 가능한 메모리를 생성**할 수 있도록 합니다. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)를 확인하세요.

### `com.apple.security.cs.allow-unsigned-executable-memory`

이 entitlement는 **C code를 override하거나 patch**하거나, 오래전에 deprecated된 **`NSCreateObjectFileImageFromMemory`**를 사용하거나(이는 근본적으로 안전하지 않음), **DVDPlayback** framework를 사용할 수 있도록 합니다. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)를 확인하세요.

> [!CAUTION]
> 이 entitlement를 포함하면 memory-unsafe code languages의 일반적인 취약점에 앱이 노출됩니다. 앱에 이 예외가 필요한지 신중하게 고려하세요.

### `com.apple.security.cs.disable-executable-page-protection`

이 entitlement는 강제로 종료하기 위해 디스크에 있는 자체 executable files의 **섹션을 수정**할 수 있도록 합니다. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)를 확인하세요.

> [!CAUTION]
> Disable Executable Memory Protection Entitlement는 앱에서 근본적인 보안 보호 기능을 제거하는 극단적인 entitlement입니다. 이로 인해 attacker가 탐지되지 않은 상태로 앱의 executable code를 다시 작성할 수 있습니다. 가능하다면 더 범위가 좁은 entitlements를 사용하세요.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

이 entitlement는 nullfs file system을 mount할 수 있도록 합니다(기본적으로 금지됨). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

이 blogpost에 따르면, 이 TCC permission은 일반적으로 다음과 같은 형태로 발견됩니다:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
프로세스가 **모든 TCC permissions를 요청할 수 있도록 허용**합니다.

### **`kTCCServicePostEvent`**

`CGEventPost()`를 통해 시스템 전체에 **synthetic keyboard and mouse events를 주입**할 수 있습니다. 이 permission이 있는 프로세스는 모든 애플리케이션에서 keystroke, mouse click, scroll event를 시뮬레이션할 수 있어 사실상 데스크톱을 **remote control**할 수 있습니다.

이는 `kTCCServiceAccessibility` 또는 `kTCCServiceListenEvent`와 결합될 때 특히 위험합니다. input을 읽는 동시에 **주입**할 수 있기 때문입니다.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

시스템 전반에서 **모든 키보드 및 마우스 이벤트를 intercept**할 수 있도록 허용합니다(input monitoring / keylogging). 프로세스는 `CGEventTap`을 등록하여 모든 애플리케이션에서 입력되는 모든 키 입력을 캡처할 수 있으며, 여기에는 비밀번호, 신용카드 번호, private message가 포함됩니다.

자세한 exploitation techniques는 다음을 참조하세요:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**디스플레이 버퍼를 읽어** 모든 애플리케이션의 스크린샷을 촬영하고 화면 영상을 녹화할 수 있도록 허용합니다. 여기에는 secure text field도 포함됩니다. OCR과 결합하면 화면에서 비밀번호와 민감한 데이터를 자동으로 추출할 수 있습니다.

> [!WARNING]
> macOS Sonoma부터 screen capture에는 지속적인 메뉴 바 indicator가 표시됩니다. 이전 버전에서는 screen recording이 완전히 silent하게 수행될 수 있습니다.

### **`kTCCServiceCamera`**

내장 카메라 또는 연결된 USB 카메라로 사진과 영상을 **capturing**할 수 있도록 허용합니다. camera-entitled binary에 code injection을 수행하면 silent visual surveillance가 가능합니다.

### **`kTCCServiceMicrophone`**

모든 입력 장치에서 오디오를 **recording**할 수 있도록 허용합니다. mic access 권한이 있는 background daemon은 애플리케이션 창을 표시하지 않고도 지속적인 주변 오디오 surveillance를 수행할 수 있습니다.

### **`kTCCServiceLocation`**

Wi-Fi triangulation 또는 Bluetooth beacon을 통해 장치의 **physical location**을 조회할 수 있도록 허용합니다. 지속적인 monitoring을 통해 집과 직장 주소, 이동 패턴, 일상적인 생활 패턴을 파악할 수 있습니다.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**(이름, 이메일, 전화번호 — spear-phishing에 유용), **Calendar**(회의 일정, 참석자 목록), **Photos**(개인 사진, credential이 포함될 수 있는 스크린샷, 위치 metadata)에 액세스할 수 있습니다.

TCC permissions를 통한 complete credential theft exploitation techniques는 다음을 참조하세요:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox 및 Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**는 sandbox가 일반적으로 차단하는 system-wide Mach/XPC service와의 통신을 허용하여 App Sandbox를 약화합니다. 이는 **primary sandbox escape primitive**입니다. compromised sandboxed app은 mach-lookup exceptions를 사용하여 privileged daemon에 접근하고 해당 XPC interface를 exploit할 수 있습니다.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
자세한 exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape는 다음을 참조하세요:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements**를 사용하면 user-space driver 바이너리가 IOKit 인터페이스를 통해 kernel과 직접 통신할 수 있습니다. DriverKit 바이너리는 USB, Thunderbolt, PCIe, HID devices, audio 및 networking hardware를 관리합니다.

DriverKit 바이너리를 compromise하면 다음이 가능합니다:
- 잘못 구성된 `IOConnectCallMethod` 호출을 통한 **kernel attack surface** 악용
- **USB device spoofing** (HID injection을 위한 keyboard 에뮬레이션)
- PCIe/Thunderbolt 인터페이스를 통한 **DMA attacks**
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
자세한 IOKit/DriverKit exploitation 내용은 다음을 참조하세요:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## 참고 자료

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` 작업 및 `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` 핸들러)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
