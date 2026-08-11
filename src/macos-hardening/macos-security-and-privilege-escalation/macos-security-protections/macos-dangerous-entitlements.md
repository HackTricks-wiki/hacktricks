# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements는 운영 체제가 서명된 코드에 부여하는 capability와 security exception을 선언합니다. 아래 항목은 offensive review 중 특히 유용한 항목에 초점을 둡니다.<sup>[[13]](#references)</sup>

> [!WARNING]
> **`com.apple`**로 시작하는 entitlements는 third-party에서 사용할 수 없으며, Apple만 이를 부여할 수 있습니다... 또는 enterprise certificate를 사용한다면 실제로 **`com.apple`**로 시작하는 자체 entitlements를 생성하여 이를 기반으로 한 protections를 우회할 수 있습니다.

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement는 프로세스가 **SIP를 우회**할 수 있도록 합니다. 자세한 내용은 [this for more info](macos-sip.md#com.apple.rootless.install.heritable)를 참고하세요.

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement는 프로세스가 **SIP를 우회**할 수 있도록 합니다. 자세한 내용은 [this for more info](macos-sip.md#com.apple.rootless.install)를 참고하세요.

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

이 entitlement를 사용하면 프로세스가 kernel을 제외한 **모든** 프로세스의 **task port**를 가져올 수 있습니다. 자세한 내용은 [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)를 참고하세요.

### `com.apple.security.get-task-allow`

이 entitlement를 사용하면 **`com.apple.security.cs.debugger`** entitlement를 가진 다른 프로세스가 이 entitlement를 가진 binary가 실행한 프로세스의 task port를 가져와 해당 프로세스에 **code를 inject**할 수 있습니다. 자세한 내용은 [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)를 참고하세요.

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement가 있는 App은 `task_for_pid()`를 호출하여 `Get Task Allow` entitlement가 `true`로 설정된 unsigned 및 third-party App의 유효한 task port를 가져올 수 있습니다. 그러나 debugging tool entitlement가 있더라도 debugger는 **`Get Task Allow entitlement`가 없는** 프로세스의 **task ports를 가져올 수 없으며**, 따라서 해당 프로세스는 System Integrity Protection으로 보호됩니다. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)를 참고하세요.<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

이 entitlement를 사용하면 애플리케이션이 **Apple이 서명했거나 main executable과 동일한 Team ID로 서명된 것**을 요구하지 않고 **frameworks, plug-ins 또는 libraries를 load**할 수 있으므로, attacker는 임의의 library load를 악용하여 code를 inject할 수 있습니다. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)를 참고하세요.<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

이 entitlement는 **`com.apple.security.cs.disable-library-validation`**과 매우 유사하지만, library validation을 **직접 disable하는 대신**, 프로세스가 runtime에 이를 **disable하기 위한 `csops` system call을 호출**할 수 있도록 합니다.

이 entitlement 이름은 이를 사용하는 `csops` operation 옆의 XNU에 hardcoded되어 있습니다:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`(`bsd/kern/kern_proc.c`)의 kernel handler는 이 primitive가 정확히 얼마나 제한적인지 보여준다:<sup>[[2]](#references)</sup>
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

- **macOS 전용**입니다(다른 모든 플랫폼에서는 `ENOTSUP`).
- **자기 자신에 대해서만** 작동합니다(`forself == 1`). 이를 사용해 다른 프로세스에서 library validation을 제거할 수는 없습니다.
- 프로세스가 실제로 해당 entitlement를 **보유하고 있어야** 하며, 프로세스에 `CS_INSTALLER` 플래그가 설정되어 있거나 subsystem root path에서 실행 중이면 거부합니다.
- 프로세스의 code-signing flags에서 **`CS_REQUIRE_LV | CS_FORCED_LV`**를 제거합니다.

XNU 주석은 의도된 사용 사례와 이것이 attacker에게 흥미로운 이유를 설명합니다.

> 이 옵션은 실행 중인 프로세스에서 library validation을 제거하는 데 사용됩니다. 프로그램이 신뢰할 수 없는 library를 로드해야 하는 plugin architecture에서 사용됩니다. [...] 프로세스가 신뢰할 수 없는 library를 로드한 후에는 향후 library validation에 의존하는 것이 효과적이지 않습니다.

즉, **이 entitlement를 포함하는 모든 binary는 dylib-injection target입니다**. `CS_REQUIRE_LV`를 제거한 후 해당 binary 내부에서 code를 실행하거나(또는 해당 binary가 사용자의 plug-in을 로드하도록 유도하면), host process가 신뢰된 상태로 수행할 수 있는 작업을 그대로 이어받게 됩니다.

### `com.apple.security.cs.allow-dyld-environment-variables`

이 entitlement를 사용하면 library와 code를 inject하는 데 사용될 수 있는 **DYLD environment variables를 사용할 수 있습니다**. 자세한 내용은 [**여기를 확인하세요**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` 또는 `com.apple.rootless.storage`.`TCC`

[**이 blog에 따르면**](https://objective-see.org/blog/blog_0x4C.html) 그리고 [**이 blog에 따르면**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), 이러한 entitlements를 사용하면 프로세스가 **TCC** database를 **수정할 수 있습니다**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** 및 **`system.install.apple-software.standar-user`**

이러한 entitlements를 사용하면 프로세스가 **사용자에게 권한을 요청하지 않고 software를 설치할 수 있으며**, 이는 **privilege escalation**에 유용할 수 있습니다.

### `com.apple.private.security.kext-management`

**kernel에 kernel extension을 로드하도록 요청하는 데 필요한 entitlement**입니다.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement를 사용하면 **iCloud tokens를 제공하는** **`com.apple.iCloudHelper`** XPC service와 통신할 수 있습니다.

**iMovie**와 **Garageband**에 이 entitlement가 있었습니다.

해당 entitlement를 통해 **icloud tokens를 획득하는** exploit에 대한 자세한 **정보**는 다음 발표를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 이것으로 무엇을 할 수 있는지 모르겠습니다.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**이 report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 이 entitlement를 reboot 후 SSV-protected contents를 update하는 데 사용할 수 있다고 언급합니다. 방법을 알고 있다면 PR을 보내 주세요!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**동일한 report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 sealed snapshot을 생성하면 reboot 후 SSV-protected contents를 update하는 데 사용할 수 있다고 언급합니다. 방법을 알고 있다면 PR을 보내 주세요!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

이 entitlement는 application이 액세스할 수 있는 **keychain** groups를 나열합니다:
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

가질 수 있는 TCC 권한 중 가장 높은 권한 중 하나인 **전체 디스크 접근** 권한을 부여합니다.

### **`kTCCServiceAppleEvents`**

**작업 자동화**에 일반적으로 사용되는 다른 애플리케이션으로 이벤트를 전송할 수 있도록 앱에 허용합니다. 다른 앱을 제어하여 해당 앱에 부여된 권한을 악용할 수 있습니다.

예를 들어 해당 앱이 사용자에게 비밀번호를 묻도록 만들 수 있습니다:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
또는 **임의의 작업**을 수행하도록 만들 수 있습니다.

### **`kTCCServiceEndpointSecurityClient`**

여러 권한 중에서도 **사용자의 TCC 데이터베이스에 쓸 수 있습니다**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

사용자의 **`NFSHomeDirectory`** 속성을 **변경**하여 홈 폴더 경로를 바꿀 수 있으며, 따라서 **TCC를 우회할 수 있습니다**.

### **`kTCCServiceSystemPolicyAppBundles`**

앱 번들 내부(app.app 내부)의 파일을 수정할 수 있습니다. 이는 기본적으로 **허용되지 않습니다**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

_System Settings_ > _Privacy & Security_ > _App Management_에서 이 접근 권한을 가진 사용자를 확인할 수 있습니다.

### `kTCCServiceAccessibility`

이 프로세스는 **macOS 접근성 기능을 악용할 수 있습니다**. 예를 들어 키 입력을 전송할 수 있습니다. 따라서 Finder와 같은 앱을 제어할 수 있는 접근 권한을 요청한 다음, 이 권한을 사용해 대화 상자를 승인할 수 있습니다.

## Trustcache/CDhash 관련 entitlements

다운그레이드된 Apple 바이너리의 실행을 방지하는 Trustcache/CDhash 보호를 우회하는 데 사용할 수 있는 entitlements가 있습니다.

## Medium

### `com.apple.security.cs.allow-jit`

이 entitlement를 사용하면 `mmap()` 시스템 함수에 `MAP_JIT` 플래그를 전달하여 **쓰기 가능하고 실행 가능한 메모리를 생성**할 수 있습니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)를 확인하세요.<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

이 entitlement를 사용하면 **C 코드를 재정의하거나 patch**하거나, 오래전에 deprecated된 **`NSCreateObjectFileImageFromMemory`**(근본적으로 안전하지 않음)를 사용하거나, **DVDPlayback** framework를 사용할 수 있습니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)를 확인하세요.<sup>[[11]](#references)</sup>

> [!CAUTION]
> 이 entitlement를 포함하면 memory-unsafe code language에서 발생하는 일반적인 취약점에 앱이 노출됩니다. 앱에 이 예외가 필요한지 신중하게 검토하세요.

### `com.apple.security.cs.disable-executable-page-protection`

이 entitlement를 사용하면 자체 executable 파일의 디스크상 **섹션을 수정**하여 강제로 종료할 수 있습니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)를 확인하세요.<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement는 앱에서 기본적인 보안 보호 기능을 제거하는 극단적인 entitlement이며, 공격자가 탐지되지 않고 앱의 executable code를 다시 작성할 수 있게 합니다. 가능한 경우 더 제한적인 entitlements를 우선 사용하세요.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

이 entitlement를 사용하면 nullfs file system을 mount할 수 있습니다(기본적으로 금지됨). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

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

`CGEventPost()`를 통해 시스템 전체에 **synthetic keyboard and mouse events를 주입**할 수 있도록 허용합니다. 이 permission을 가진 프로세스는 모든 애플리케이션에서 keystrokes, mouse clicks, scroll events를 시뮬레이션할 수 있으며, 사실상 데스크톱에 대한 **remote control**을 제공합니다.

이는 `kTCCServiceAccessibility` 또는 `kTCCServiceListenEvent`와 결합될 때 특히 위험합니다. 입력을 읽고 주입하는 것이 모두 가능해지기 때문입니다.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

시스템 전반에서 **모든 키보드 및 마우스 이벤트를 가로채는 것**(입력 모니터링 / keylogging)을 허용합니다. 프로세스는 `CGEventTap`을 등록하여 모든 애플리케이션에서 입력되는 모든 키 입력을 캡처할 수 있으며, 여기에는 비밀번호, 신용카드 번호, 개인 메시지가 포함됩니다.

자세한 exploitation techniques는 다음을 참조하세요:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**디스플레이 버퍼를 읽는 것**을 허용합니다. 즉, 보안 텍스트 필드를 포함한 모든 애플리케이션의 스크린샷을 촬영하고 화면 동영상을 녹화할 수 있습니다. OCR과 결합하면 화면에서 비밀번호와 민감한 데이터를 자동으로 추출할 수 있습니다.

> [!WARNING]
> macOS Sonoma부터 화면 캡처 시 메뉴 막대에 지속적인 표시기가 나타납니다. 이전 버전에서는 화면 녹화가 완전히 표시되지 않을 수 있습니다.

### **`kTCCServiceCamera`**

내장 카메라 또는 연결된 USB 카메라에서 **사진과 동영상을 캡처하는 것**을 허용합니다. 카메라 entitlement가 있는 바이너리에 code injection을 수행하면 감지되지 않는 시각 감시가 가능합니다.

### **`kTCCServiceMicrophone`**

모든 입력 장치에서 **오디오를 녹음하는 것**을 허용합니다. 마이크 액세스 권한이 있는 백그라운드 daemon은 표시되는 애플리케이션 창 없이 지속적인 주변 오디오 감시를 수행할 수 있습니다.

### **`kTCCServiceLocation`**

Wi-Fi 삼각측량 또는 Bluetooth beacon을 통해 기기의 **물리적 위치를 조회하는 것**을 허용합니다. 지속적인 모니터링을 통해 집과 직장 주소, 이동 패턴, 일상 생활을 파악할 수 있습니다.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**(이름, 이메일, 전화번호 — spear-phishing에 유용), **Calendar**(회의 일정, 참석자 목록), **Photos**(개인 사진, 자격 증명이 포함될 수 있는 스크린샷, 위치 metadata)에 액세스할 수 있습니다.

TCC permissions를 통한 완전한 credential theft exploitation techniques는 다음을 참조하세요:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**는 sandbox가 일반적으로 차단하는 시스템 전역 Mach/XPC services와의 통신을 허용하여 App Sandbox를 약화합니다. 이는 **primary sandbox escape primitive**입니다. 침해된 sandboxed app은 mach-lookup exceptions를 사용하여 privileged daemons에 접근하고 해당 XPC interfaces를 exploit할 수 있습니다.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For detailed exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, see:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements**를 사용하면 user-space driver binary가 IOKit 인터페이스를 통해 kernel과 직접 통신할 수 있습니다. DriverKit binary는 USB, Thunderbolt, PCIe, HID devices, audio 및 networking hardware를 관리합니다.

DriverKit binary를 compromise하면 다음이 가능합니다.
- **Kernel attack surface**: 변조된 `IOConnectCallMethod` 호출을 통한 공격
- **USB device spoofing**: HID injection을 위한 keyboard 에뮬레이션
- **DMA attacks**: PCIe/Thunderbolt 인터페이스를 통한 공격
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
자세한 IOKit/DriverKit exploitation 내용은 다음을 참조하세요:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` 작업 및 `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` 핸들러)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: TCC 우회](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — 음악을 재생하고 TCC를 우회하기, 일명 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "Mac에서 일어난 일은 Apple의 iCloud에 남는다?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple의 OTA Update의 악몽: Signature Verification을 우회하고 Kernel을 장악하기](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
