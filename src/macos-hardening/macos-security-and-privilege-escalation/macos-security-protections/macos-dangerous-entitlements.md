# macOS Dangerous Entitlements & TCC 권한

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`**로 시작하는 entitlements는 서드 파티에서 사용할 수 없으며, Apple만 이를 부여할 수 있습니다... 또는 enterprise certificate를 사용하면 실제로 **`com.apple`**로 시작하는 자체 entitlements를 생성하여 이를 기반으로 한 보호 기능을 우회할 수 있습니다.

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement를 사용하면 **SIP를 우회**할 수 있습니다. 자세한 내용은 [여기](macos-sip.md#com.apple.rootless.install.heritable)를 확인하세요.

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement를 사용하면 **SIP를 우회**할 수 있습니다. 자세한 내용은 [여기](macos-sip.md#com.apple.rootless.install)를 확인하세요.

### **`com.apple.system-task-ports` (이전에는 `task_for_pid-allow`라고 불림)**

이 entitlement를 사용하면 kernel을 제외한 **모든** process의 **task port를 가져올** 수 있습니다. 자세한 내용은 [**여기**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)를 확인하세요.

### `com.apple.security.get-task-allow`

이 entitlement를 가진 binary가 실행한 process의 task port를 **`com.apple.security.cs.debugger`** entitlement를 가진 다른 process가 가져와 해당 process에 **code를 inject**할 수 있습니다. 자세한 내용은 [**여기**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)를 확인하세요.

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement가 있는 Apps는 `task_for_pid()`를 호출하여 `Get Task Allow` entitlement가 `true`로 설정된 unsigned 및 third-party Apps의 유효한 task port를 가져올 수 있습니다. 그러나 debugging tool entitlement가 있더라도 debugger는 **`Get Task Allow` entitlement가 없는** process의 **task port를 가져올 수 없으며**, 이러한 process는 System Integrity Protection으로 보호됩니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)를 확인하세요.<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

이 entitlement를 사용하면 **Apple이 sign했거나 main executable과 동일한 Team ID로 sign된 것이 아닌** frameworks, plug-ins 또는 libraries도 **load**할 수 있으므로, attacker가 임의의 library load를 악용하여 code를 inject할 수 있습니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)를 확인하세요.<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

이 entitlement는 **`com.apple.security.cs.disable-library-validation`**과 매우 유사하지만, library validation을 **직접 비활성화하는 대신**, process가 runtime에 **`csops` system call을 호출하여 이를 비활성화**할 수 있도록 합니다.

entitlement 이름은 이를 사용하는 `csops` operation 옆의 XNU에 hardcoded되어 있습니다:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`의 kernel handler(`bsd/kern/kern_proc.c`)는 이 primitive가 얼마나 제한적인지 정확히 보여준다:<sup>[[2]](#references)</sup>
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
따라서 이 작업은 다음과 같습니다:

- **macOS 전용**입니다(그 외 모든 플랫폼에서는 `ENOTSUP`).
- **자기 자신에게만** 작동합니다(`forself == 1`). 이를 사용해 다른 process에서 library validation을 제거할 수는 없습니다.
- process가 실제로 해당 entitlement를 **보유하고 있어야** 하며, process에 `CS_INSTALLER` 플래그가 지정되어 있거나 subsystem root path에서 실행 중인 경우 거부됩니다.
- process의 code-signing flags에서 **`CS_REQUIRE_LV | CS_FORCED_LV`**를 제거합니다.

XNU comment는 의도된 사용 사례와 이것이 attacker에게 흥미로운 이유를 설명합니다:

> 이 option은 실행 중인 process에서 library validation을 제거하는 데 사용됩니다. 프로그램이 신뢰할 수 없는 libraries를 load해야 하는 plugin architectures에서 사용됩니다. [...] process가 신뢰할 수 없는 library를 load한 후에는 향후 library validation에 의존하는 것이 효과적이지 않습니다.

즉, **이 entitlement를 가진 모든 binary는 dylib-injection target**입니다. 해당 binary 내부에서 code를 실행하거나(또는 자체 plug-in을 load하도록 유도하여) `CS_REQUIRE_LV`를 제거한 후, host process가 수행하도록 허용된 모든 작업을 상속할 수 있습니다.

### `com.apple.security.cs.allow-dyld-environment-variables`

이 entitlement는 libraries와 code를 inject하는 데 사용될 수 있는 **DYLD environment variables를 사용할 수 있도록** 합니다. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)를 확인하세요.<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` 또는 `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **및** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)에 따르면, 이러한 entitlements를 사용하면 **TCC** database를 **수정**할 수 있습니다.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** 및 **`system.install.apple-software.standar-user`**

이러한 entitlements를 사용하면 사용자에게 **권한을 요청하지 않고 software를 install**할 수 있으며, 이는 **privilege escalation**에 유용할 수 있습니다.

### `com.apple.private.security.kext-management`

**kernel에 kernel extension을 load하도록 요청**하는 데 필요한 entitlement입니다.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement를 사용하면 **iCloud tokens를 제공하는** **`com.apple.iCloudHelper`** XPC service와 통신할 수 있습니다.

**iMovie**와 **Garageband**에 이 entitlement가 있었습니다.

해당 entitlement를 통해 **iCloud tokens를 획득하는** exploit에 대한 자세한 **information**은 다음 talk를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 이것이 무엇을 허용하는지는 모릅니다.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 이것을 사용해 reboot 후 SSV-protected contents를 update할 수 있다고 **언급합니다**. 어떻게 사용하는지 알고 있다면 PR을 보내주세요!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 이것을 사용해 reboot 후 SSV-protected contents를 update할 수 있다고 **언급합니다**. 어떻게 사용하는지 알고 있다면 PR을 보내주세요!<sup>[[9]](#references)</sup>

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

보유할 수 있는 TCC 최고 권한 중 하나인 **Full Disk Access** 권한을 부여합니다.

### **`kTCCServiceAppleEvents`**

**automating tasks**에 흔히 사용되는 다른 애플리케이션으로 이벤트를 보낼 수 있도록 앱에 권한을 부여합니다. 다른 앱을 제어하여 해당 앱에 부여된 권한을 악용할 수 있습니다.

예를 들어 다른 앱이 사용자에게 비밀번호를 요청하도록 만들 수 있습니다:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
또는 **임의의 작업을 수행하도록 만들 수 있습니다**.

### **`kTCCServiceEndpointSecurityClient`**

여러 권한 중에서도 **사용자의 TCC database에 쓸 수 있도록 허용합니다**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

사용자의 홈 folder path를 변경하는 **`NFSHomeDirectory`** attribute를 **변경할 수 있도록 허용하며**, 따라서 **TCC를 우회할 수 있습니다**.

### **`kTCCServiceSystemPolicyAppBundles`**

기본적으로 **허용되지 않는** app bundle(app.app 내부)의 파일을 수정할 수 있도록 허용합니다.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

이 access 권한을 가진 사용자는 _System Settings_ > _Privacy & Security_ > _App Management_에서 확인할 수 있습니다.

### `kTCCServiceAccessibility`

해당 process는 **macOS accessibility 기능을 abuse할 수 있습니다**. 예를 들어 keystroke를 입력할 수 있습니다. 따라서 이 권한으로 Finder와 같은 app을 제어할 access를 요청하고 해당 권한으로 dialog를 승인할 수 있습니다.

## Trustcache/CDhash 관련 entitlements

downgrade된 Apple binary의 실행을 방지하는 Trustcache/CDhash protections를 우회하는 데 사용할 수 있는 entitlements가 있습니다.

## Medium

### `com.apple.security.cs.allow-jit`

이 entitlement를 사용하면 `mmap()` system function에 `MAP_JIT` flag를 전달하여 **writable하면서 executable인 memory를 생성할 수 있습니다**. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)를 확인하세요.<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

이 entitlement를 사용하면 **C code를 override하거나 patch**하거나, 오랫동안 deprecated된 **`NSCreateObjectFileImageFromMemory`**(근본적으로 insecure함)를 사용하거나, **DVDPlayback** framework를 사용할 수 있습니다. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)를 확인하세요.<sup>[[11]](#references)</sup>

> [!CAUTION]
> 이 entitlement를 포함하면 memory-unsafe code language에서 발생하는 일반적인 vulnerability에 app이 노출됩니다. app에 이 exception이 필요한지 신중하게 검토하세요.

### `com.apple.security.cs.disable-executable-page-protection`

이 entitlement를 사용하면 자체 executable file의 disk상 **section을 수정하여 강제로 종료할 수 있습니다**. 자세한 내용은 [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)를 확인하세요.<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement는 app에서 근본적인 security protection을 제거하는 extreme entitlement이므로, attacker가 detection 없이 app의 executable code를 다시 작성할 수 있습니다. 가능한 경우 더 제한적인 entitlement를 우선 사용하세요.

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
프로세스가 **모든 TCC permissions를 요청할 수 있도록 허용합니다**.

### **`kTCCServicePostEvent`**

`CGEventPost()`를 통해 시스템 전체에 **synthetic keyboard 및 mouse events를 주입**할 수 있도록 허용합니다. 이 permission이 있는 프로세스는 모든 application에서 keystrokes, mouse clicks, scroll events를 simulate할 수 있으며, 사실상 desktop에 대한 **remote control**을 제공합니다.

이는 `kTCCServiceAccessibility` 또는 `kTCCServiceListenEvent`와 함께 사용될 때 특히 위험합니다. input을 읽는 동시에 **주입**할 수 있기 때문입니다.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

시스템 전역에서 **모든 키보드 및 마우스 이벤트를 가로채는 것**(input monitoring / keylogging)을 허용합니다. 프로세스는 `CGEventTap`을 등록하여 비밀번호, 신용카드 번호, 비공개 메시지를 포함해 모든 애플리케이션에서 입력되는 모든 키 입력을 캡처할 수 있습니다.

자세한 exploitation techniques는 다음을 참조하세요:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**디스플레이 버퍼를 읽는 것**을 허용합니다. 즉, 보안 텍스트 필드를 포함한 모든 애플리케이션의 스크린샷을 촬영하고 화면 영상을 녹화할 수 있습니다. OCR과 결합하면 화면에서 비밀번호와 민감한 데이터를 자동으로 추출할 수 있습니다.

> [!WARNING]
> macOS Sonoma부터 화면 캡처에는 지속적인 메뉴 막대 표시기가 나타납니다. 이전 버전에서는 화면 녹화가 완전히 흔적 없이 수행될 수 있습니다.

### **`kTCCServiceCamera`**

내장 카메라 또는 연결된 USB 카메라에서 **사진과 동영상을 캡처하는 것**을 허용합니다. camera-entitled binary에 code injection을 수행하면 흔적 없이 시각적 감시를 할 수 있습니다.

### **`kTCCServiceMicrophone`**

모든 입력 장치에서 **오디오를 녹음하는 것**을 허용합니다. microphone access 권한이 있는 백그라운드 daemon은 표시되는 애플리케이션 창 없이 지속적인 주변 오디오 감시를 수행할 수 있습니다.

### **`kTCCServiceLocation`**

Wi-Fi 삼각 측량 또는 Bluetooth beacon을 통해 장치의 **물리적 위치**를 조회할 수 있습니다. 지속적인 모니터링을 통해 집과 직장 주소, 이동 패턴, 일상적인 생활 패턴을 파악할 수 있습니다.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**(이름, 이메일, 전화번호 — spear-phishing에 유용), **Calendar**(회의 일정, 참석자 목록), **Photos**(개인 사진, credential이 포함될 수 있는 스크린샷, 위치 metadata)에 접근할 수 있습니다.

TCC permissions를 통한 완전한 credential theft exploitation techniques는 다음을 참조하세요:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**는 sandbox가 일반적으로 차단하는 시스템 전역 Mach/XPC service와의 통신을 허용하여 App Sandbox를 약화합니다. 이는 **primary sandbox escape primitive**입니다. 침해된 sandboxed app은 mach-lookup exceptions를 사용하여 권한이 높은 daemon에 접근하고 해당 daemon의 XPC interface를 exploit할 수 있습니다.
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

**DriverKit entitlements**를 사용하면 user-space driver binary가 IOKit 인터페이스를 통해 kernel과 직접 통신할 수 있습니다. DriverKit binary는 USB, Thunderbolt, PCIe, HID devices, audio 및 networking과 같은 hardware를 관리합니다.

DriverKit binary가 compromise되면 다음이 가능합니다:
- **Kernel attack surface**: malformed `IOConnectCallMethod` 호출을 통한 공격
- **USB device spoofing**: HID injection을 위한 keyboard 에뮬레이션
- **DMA attacks**: PCIe/Thunderbolt 인터페이스를 통한 공격
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
자세한 IOKit/DriverKit exploitation 내용은 다음을 참고하세요:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## 참고 문헌

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations 및 `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: TCC 우회](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — 음악을 재생하고 TCC를 우회하기, 일명 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "Mac에서 발생한 일은 Apple의 iCloud에 남는다?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple OTA Update의 악몽: Signature Verification 우회 및 Kernel 장악](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — JIT-compiled Code 실행 허용 Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Unsigned Executable Memory 허용 Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Executable Memory Protection 비활성화 Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
