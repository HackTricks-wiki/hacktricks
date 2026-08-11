# macOS 위험한 Entitlements 및 TCC 권한

{{#include ../../../banners/hacktricks-training.md}}

Entitlements는 운영 체제가 서명된 코드에 부여하는 기능과 보안 예외를 선언합니다. 아래 항목은 offensive review 중 특히 유용한 항목에 초점을 맞춥니다.<sup>[[13]](#references)</sup>

> [!WARNING]
> **`com.apple`**로 시작하는 entitlements는 서드파티에서 사용할 수 없으며, Apple만 이를 부여할 수 있습니다... 또는 enterprise certificate를 사용하는 경우 실제로 **`com.apple`**로 시작하는 자체 entitlements를 생성하여 이를 기반으로 한 보호 기능을 우회할 수 있습니다.

## 높음

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement를 사용하면 프로세스가 **SIP를 우회**할 수 있습니다. 자세한 내용은 [여기](macos-sip.md#com.apple.rootless.install.heritable)를 확인하세요.

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement를 사용하면 프로세스가 **SIP를 우회**할 수 있습니다. 자세한 내용은 [여기](macos-sip.md#com.apple.rootless.install)를 확인하세요.

### **`com.apple.system-task-ports` (이전 명칭 `task_for_pid-allow`)**

이 entitlement를 사용하면 프로세스가 kernel을 제외한 **모든** 프로세스의 **task port**를 가져올 수 있습니다. [**자세한 내용**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)을 확인하세요.

### `com.apple.security.get-task-allow`

이 entitlement를 가진 바이너리가 실행한 프로세스의 task port를 **`com.apple.security.cs.debugger`** entitlement를 가진 다른 프로세스가 가져와 해당 프로세스에 **code를 inject**할 수 있습니다. [**자세한 내용**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)을 확인하세요.

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement가 있는 앱은 `task_for_pid()`를 호출하여 `Get Task Allow` entitlement가 `true`로 설정된 unsigned 및 서드파티 앱에 대한 유효한 task port를 가져올 수 있습니다. 하지만 debugging tool entitlement가 있더라도 debugger는 **`Get Task Allow` entitlement가 없는** 프로세스의 **task port를 가져올 수 없으며**, 이러한 프로세스는 System Integrity Protection으로 보호됩니다. [**자세한 내용**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)을 확인하세요.<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

이 entitlement를 사용하면 애플리케이션이 Apple에서 서명했거나 주 실행 파일과 동일한 Team ID로 서명되었는지 확인하지 않고 **frameworks, plug-ins 또는 libraries를 load**할 수 있으므로, attacker가 arbitrary library load를 악용하여 code를 inject할 수 있습니다. [**자세한 내용**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)을 확인하세요.<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

이 entitlement는 **`com.apple.security.cs.disable-library-validation`**과 매우 유사하지만, library validation을 **직접 disable**하는 대신 프로세스가 runtime에 이를 disable하기 위해 **`csops` system call을 호출**할 수 있도록 합니다.

entitlement 이름은 이를 사용하는 `csops` operation 옆의 XNU에 hardcoded되어 있습니다:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`의 kernel handler(`bsd/kern/kern_proc.c`)는 이 primitive가 정확히 얼마나 제한적인지 보여 줍니다:<sup>[[2]](#references)</sup>
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
따라서 이 operation은 다음과 같습니다:

- **macOS 전용**입니다(그 외 모든 platform에서는 `ENOTSUP`).
- **자기 자신에게만** 작동합니다(`forself == 1`) — 이를 사용해 다른 process의 library validation을 제거할 수 없습니다.
- process가 실제로 해당 entitlement를 **보유**해야 하며, process에 `CS_INSTALLER` flag가 설정되어 있거나 subsystem root path에서 실행 중이면 거부합니다.
- process의 code-signing flags에서 **`CS_REQUIRE_LV | CS_FORCED_LV`**를 제거합니다.

XNU comment는 의도된 사용 사례와 이것이 attacker에게 흥미로운 이유를 설명합니다:

> 이 option은 실행 중인 process에서 library validation을 제거하는 데 사용됩니다. 프로그램이 untrusted library를 load해야 하는 plugin architecture에서 사용됩니다. [...] process가 untrusted library를 load한 후에는 향후 library validation에 의존해도 효과가 없습니다.

다시 말해, **이 entitlement를 가진 모든 binary는 dylib-injection target입니다**: 해당 binary 안에서 code를 실행하거나(또는 해당 binary가 여러분의 plug-in을 load하도록 유도한 후) `CS_REQUIRE_LV`를 제거하면, host process가 수행하도록 trust된 모든 작업을 상속받습니다.

### `com.apple.security.cs.allow-dyld-environment-variables`

이 entitlement를 사용하면 library와 code를 inject하는 데 사용될 수 있는 **DYLD environment variables를 사용할 수 있습니다**. 자세한 내용은 [**이 문서**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)를 확인하세요.<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` 또는 `com.apple.rootless.storage`.`TCC`

[**이 blog에 따르면**](https://objective-see.org/blog/blog_0x4C.html) **그리고** [**이 blog에 따르면**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), 이러한 entitlement는 process가 **TCC** database를 **modify**할 수 있도록 합니다.<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** 및 **`system.install.apple-software.standard-user`**

이 Authorization Services rights는 Apple-provided software의 installation을 제어합니다. 이를 획득할 수 있는 entitlement를 가진 process는 일반적인 authorization flow를 우회할 수 있으며, 이는 **privilege escalation**에 유용할 수 있습니다.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

**kernel에 kernel extension을 load하도록 요청하는 데** 필요한 entitlement입니다.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement를 사용하면 **iCloud tokens를 제공하는** **`com.apple.iCloudHelper`** XPC service와 communicate할 수 있습니다.

**iMovie**와 **Garageband**에 이 entitlement가 있었습니다.

해당 entitlement를 사용해 **icloud tokens를 획득하는** exploit에 대한 자세한 **information**은 다음 talk를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 이것으로 무엇을 할 수 있는지 모릅니다

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**이 report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 이 entitlement를 사용해 reboot 후 SSV-protected contents를 update할 수 있다고 언급합니다. 방법을 알고 있다면 PR을 보내주세요!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**동일한 report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 sealed snapshot을 생성하면 reboot 후 SSV-protected contents를 update하는 데 사용할 수 있다고 언급합니다. 방법을 알고 있다면 PR을 보내주세요!<sup>[[9]](#references)</sup>

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

**Full Disk Access** 권한을 부여합니다. 이는 사용자가 가질 수 있는 TCC 권한 중 가장 높은 수준의 권한 중 하나입니다.

### **`kTCCServiceAppleEvents`**

**automating tasks**에 일반적으로 사용되는 다른 애플리케이션으로 이벤트를 보낼 수 있도록 앱에 허용합니다. 다른 앱을 제어하여 해당 앱에 부여된 권한을 악용할 수 있습니다.

예를 들어 다른 앱이 사용자에게 비밀번호를 요청하도록 만들 수 있습니다:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
또는 **임의의 작업**을 수행하도록 만들 수 있습니다.

### **`kTCCServiceEndpointSecurityClient`**

여러 권한 중에서도 **사용자의 TCC 데이터베이스에 쓸 수 있도록** 허용합니다.

### **`kTCCServiceSystemPolicySysAdminFiles`**

사용자의 **`NFSHomeDirectory`** 속성을 **변경**하여 사용자의 홈 폴더 경로를 바꿀 수 있도록 허용하며, 따라서 **TCC를 우회**할 수 있습니다.

### **`kTCCServiceSystemPolicyAppBundles`**

앱 번들(app.app) 내부의 파일을 수정할 수 있도록 허용합니다. 이는 기본적으로 **허용되지 않습니다**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

_시스템 설정_ > _개인정보 보호 및 보안_ > _앱 관리_에서 이 접근 권한을 가진 대상을 확인할 수 있습니다.

### `kTCCServiceAccessibility`

프로세스가 **macOS 접근성 기능을 악용**할 수 있게 됩니다. 예를 들어 키 입력을 전송할 수 있습니다. 따라서 Finder와 같은 앱을 제어할 수 있는 권한을 요청한 다음, 이 권한으로 해당 대화 상자를 승인할 수 있습니다.

## Trustcache/CDhash 관련 entitlements

다운그레이드된 Apple 바이너리 버전의 실행을 차단하는 Trustcache/CDhash 보호를 우회하는 데 사용할 수 있는 entitlements가 있습니다.

## 중간

### `com.apple.security.cs.allow-jit`

이 entitlement는 `mmap()` 시스템 함수에 `MAP_JIT` 플래그를 전달하여 프로세스가 **쓰기 가능하면서 실행 가능한 메모리를 생성**할 수 있도록 합니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)를 확인하세요.<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

이 entitlement는 **C 코드를 재정의하거나 patch**하거나, 오랫동안 deprecated된 **`NSCreateObjectFileImageFromMemory`**(근본적으로 안전하지 않음)를 사용하거나, **DVDPlayback** framework를 사용할 수 있도록 합니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)를 확인하세요.<sup>[[11]](#references)</sup>

> [!CAUTION]
> 이 entitlement를 포함하면 메모리 안전성이 보장되지 않는 code language에서 발생하는 일반적인 취약점에 앱이 노출됩니다. 앱에 이 예외가 필요한지 신중하게 검토하세요.

### `com.apple.security.cs.disable-executable-page-protection`

이 entitlement는 강제로 종료하기 위해 디스크에 있는 자체 executable file의 **섹션을 수정**할 수 있도록 합니다. 자세한 내용은 [**여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)를 확인하세요.<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement는 앱에서 근본적인 보안 보호 기능을 제거하는 매우 강력한 entitlement입니다. 따라서 attacker가 탐지되지 않고 앱의 executable code를 다시 작성할 수 있습니다. 가능한 경우 더 제한적인 entitlements를 우선 사용하세요.

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
프로세스가 **모든 TCC 권한을 요청**할 수 있도록 허용합니다.

### **`kTCCServicePostEvent`**

`CGEventPost()`를 통해 시스템 전체에 **합성 키보드 및 마우스 이벤트를 주입**할 수 있도록 허용합니다. 이 권한이 있는 프로세스는 모든 애플리케이션에서 키 입력, 마우스 클릭 및 스크롤 이벤트를 시뮬레이션할 수 있으며, 사실상 데스크톱을 **원격 제어**할 수 있습니다.

이는 `kTCCServiceAccessibility` 또는 `kTCCServiceListenEvent`와 결합될 때 특히 위험합니다. 입력을 읽는 동시에 주입할 수 있기 때문입니다.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

시스템 전체에서 **모든 키보드 및 마우스 이벤트를 가로채는 것**(input monitoring / keylogging)을 허용합니다. 프로세스는 `CGEventTap`을 등록하여 모든 애플리케이션에서 입력되는 모든 키 입력을 캡처할 수 있으며, 여기에는 비밀번호, 신용카드 번호, 비공개 메시지도 포함됩니다.

자세한 exploitation techniques는 다음을 참조하세요.

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**디스플레이 버퍼를 읽는 것**을 허용합니다. 즉, 보안 텍스트 필드를 포함한 모든 애플리케이션의 스크린샷을 촬영하고 화면 영상을 녹화할 수 있습니다. OCR과 결합하면 화면에서 비밀번호와 민감한 데이터를 자동으로 추출할 수 있습니다.

> [!WARNING]
> macOS Sonoma부터 화면 캡처에는 메뉴 막대에 지속적인 표시기가 나타납니다. 이전 버전에서는 화면 녹화가 완전히 조용하게 수행될 수 있습니다.

### **`kTCCServiceCamera`**

내장 카메라 또는 연결된 USB 카메라로 사진과 영상을 **캡처하는 것**을 허용합니다. 카메라 entitlement가 있는 바이너리에 code injection을 수행하면 조용한 시각 감시가 가능합니다.

### **`kTCCServiceMicrophone`**

모든 입력 장치에서 오디오를 **녹음하는 것**을 허용합니다. 마이크 접근 권한이 있는 백그라운드 daemon은 눈에 보이는 애플리케이션 창 없이 지속적인 주변 오디오 감시를 제공할 수 있습니다.

### **`kTCCServiceLocation`**

Wi-Fi 삼각 측량 또는 Bluetooth beacon을 통해 장치의 **물리적 위치**를 조회할 수 있습니다. 지속적인 모니터링을 통해 집과 직장 주소, 이동 패턴, 일상적인 생활 패턴을 파악할 수 있습니다.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**(이름, 이메일, 전화번호 — spear-phishing에 유용), **Calendar**(회의 일정, 참석자 목록), **Photos**(개인 사진, 자격 증명이 포함될 수 있는 스크린샷, 위치 metadata)에 접근할 수 있습니다.

TCC permissions를 통한 완전한 credential theft exploitation techniques는 다음을 참조하세요.

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox 및 Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**는 sandbox가 일반적으로 차단하는 시스템 전체 Mach/XPC service와의 통신을 허용하여 App Sandbox를 약화합니다. 이는 **primary sandbox escape primitive**입니다. 손상된 sandboxed app은 mach-lookup exceptions를 사용하여 권한이 높은 daemon에 접근하고 해당 XPC interface를 exploit할 수 있습니다.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
상세한 exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape는 다음을 참조하세요:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements**를 사용하면 user-space driver 바이너리가 IOKit 인터페이스를 통해 kernel과 직접 통신할 수 있습니다. DriverKit 바이너리는 USB, Thunderbolt, PCIe, HID devices, audio 및 networking과 같은 하드웨어를 관리합니다.

DriverKit 바이너리를 compromise하면 다음이 가능합니다:
- 잘못 구성된 `IOConnectCallMethod` 호출을 통한 **kernel attack surface**
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

## References

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations 및 `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple OTA Update의 악몽: Signature Verification 우회 및 Kernel Pwning](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Authorization Services Programming Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
