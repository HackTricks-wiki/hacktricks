# macOS 위험한 Entitlements 및 TCC 권한

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> 접두사가 **`com.apple`** 인 entitlements는 서드파티에 제공되지 않으며 오직 Apple만 부여할 수 있다는 점에 유의하세요... 또는 enterprise certificate를 사용하는 경우 실제로 **`com.apple`** 로 시작하는 자체 entitlements를 만들어 이러한 보호를 우회할 수도 있습니다.

## 높음

### `com.apple.rootless.install.heritable`

The entitlement **`com.apple.rootless.install.heritable`** allows to **bypass SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

The entitlement **`com.apple.rootless.install`** allows to **bypass SIP**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

이 entitlement는 커널을 제외한 모든 프로세스의 **task port를 얻을 수 있도록 허용**합니다. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

이 entitlement는 **`com.apple.security.cs.debugger`** entitlement를 가진 다른 프로세스들이 이 entitlement를 가진 바이너리가 실행하는 프로세스의 task port를 얻고 그 안에 **코드를 주입**할 수 있게 합니다. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement을 가진 앱은 `task_for_pid()`를 호출해 `Get Task Allow` entitlement가 `true`로 설정된 서명되지 않았거나 서드파티 앱의 유효한 task port를 검색할 수 있습니다. 그러나 debugging tool entitlement가 있더라도 디버거는 `Get Task Allow` entitlement가 없는 프로세스들의 task port를 얻을 수 없으며, 따라서 System Integrity Protection으로 보호됩니다. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

이 entitlement는 메인 실행파일과 동일한 Team ID로 서명되었거나 Apple에 의해 서명되지 않아도 **frameworks, plug-ins, 또는 libraries를 로드**할 수 있게 허용하므로, 공격자가 임의의 라이브러리 로드를 악용해 코드를 주입할 수 있습니다. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

이 entitlement는 **`com.apple.security.cs.disable-library-validation`** 와 매우 유사하지만, 라이브러리 검증을 **직접 비활성화하는 대신**, 프로세스가 이를 비활성화하기 위해 `csops` 시스템 콜을 **호출할 수 있도록 허용**합니다.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

이 entitlement는 라이브러리와 코드를 주입하는 데 사용될 수 있는 **DYLD 환경 변수 사용**을 허용합니다. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), these entitlements allows to **modify** the **TCC** database.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

These entitlements allows to **install software without asking for permissions** to the user, which can be helpful for a **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement needed to ask the **kernel to load a kernel extension**.

### **`com.apple.private.icloud-account-access`**

The entitlement **`com.apple.private.icloud-account-access`** it's possible to communicate with **`com.apple.iCloudHelper`** XPC service which will **provide iCloud tokens**.

**iMovie** and **Garageband** had this entitlement.

For more **information** about the exploit to **get icloud tokens** from that entitlement check the talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 무엇을 허용하는지 모릅니다

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **is mentioned that this could be used to** update the SSV-protected contents after a reboot. If you know how it send a PR please!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **is mentioned that this could be used to** update the SSV-protected contents after a reboot. If you know how it send a PR please!

### `keychain-access-groups`

This entitlement list **keychain** groups the application has access to:
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

앱에 **Full Disk Access** 권한을 부여합니다. 이는 TCC에서 얻을 수 있는 가장 높은 권한 중 하나입니다.

### **`kTCCServiceAppleEvents`**

앱이 다른 애플리케이션으로 이벤트를 보낼 수 있게 하며, 이는 **자동화 작업**에 일반적으로 사용됩니다. 다른 앱을 제어하면 그 앱들에 부여된 권한을 악용할 수 있습니다.

예를 들어, 해당 앱들로 하여금 사용자에게 비밀번호를 묻도록 만들 수 있습니다:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
또는 그들을 **임의의 동작**을 수행하게 만들 수도 있습니다.

### **`kTCCServiceEndpointSecurityClient`**

다른 권한들과 함께 사용자의 TCC 데이터베이스를 **쓰기**할 수 있게 합니다.

### **`kTCCServiceSystemPolicySysAdminFiles`**

사용자의 `NFSHomeDirectory` 속성을 **변경**할 수 있게 하여 홈 폴더 경로를 바꾸고, 따라서 **bypass TCC**를 허용합니다.

### **`kTCCServiceSystemPolicyAppBundles`**

앱 번들(app.app 내부) 내의 파일을 수정할 수 있게 하며, 이는 **기본적으로 허용되지 않습니다**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

누가 이 접근 권한을 가지고 있는지는 _System Settings_ > _Privacy & Security_ > _App Management._에서 확인할 수 있습니다.

### `kTCCServiceAccessibility`

프로세스는 macOS의 접근성 기능을 **악용**할 수 있으며, 예를 들어 키 입력을 누를 수 있습니다. 따라서 Finder와 같은 앱을 제어하기 위한 접근을 요청하고 이 권한으로 대화상자를 승인할 수 있습니다.

## Trustcache/CDhash 관련 entitlements

Trustcache/CDhash 보호를 우회하는 데 사용될 수 있는 entitlements가 있으며, 이러한 보호는 Apple 바이너리의 다운그레이드된 버전 실행을 방지합니다.

## Medium

### `com.apple.security.cs.allow-jit`

이 entitlement는 `MAP_JIT` 플래그를 `mmap()` 시스템 함수에 전달하여 **쓰기 가능하고 실행 가능한 메모리**를 생성할 수 있게 합니다. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

이 entitlement는 **C 코드를 덮어쓰거나 패치**하거나, 오래전에 사용 중단된 **`NSCreateObjectFileImageFromMemory`**(근본적으로 안전하지 않음)를 사용하거나, **DVDPlayback** 프레임워크를 사용할 수 있게 합니다. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> 이 entitlement를 포함하면 메모리-안전하지 않은 코드 언어에서 흔히 발생하는 취약점에 앱이 노출됩니다. 앱에 이 예외가 정말 필요한지 신중히 고려하세요.

### `com.apple.security.cs.disable-executable-page-protection`

이 entitlement는 디스크에 있는 자신의 실행 파일 섹션을 **수정**할 수 있게 하며, 이를 통해 강제로 종료하는 등의 동작이 가능해집니다. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> The Disable Executable Memory Protection Entitlement은 앱의 기본적인 보안 보호 장치를 제거하는 극단적인 entitlement로, 공격자가 앱의 실행 코드를 탐지 없이 재작성할 수 있게 만듭니다. 가능하면 더 좁은 범위의 entitlements를 선호하세요.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

이 entitlement는 nullfs 파일 시스템을 마운트할 수 있게 합니다(기본적으로 금지됨). 도구: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

이 블로그 게시물에 따르면, 이 TCC 권한은 일반적으로 다음 형태로 발견됩니다:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
프로세스가 **모든 TCC 권한을 요청하도록 허용합니다**.

### **`kTCCServicePostEvent`**

시스템 전반에서 `CGEventPost()`를 통해 **합성 키보드 및 마우스 이벤트를 주입할 수 있습니다**. 이 권한을 가진 프로세스는 모든 애플리케이션에서 키 입력, 마우스 클릭 및 스크롤 이벤트를 시뮬레이션할 수 있으며 — 사실상 데스크탑을 **원격 제어**할 수 있습니다.

이 권한은 `kTCCServiceAccessibility` 또는 `kTCCServiceListenEvent`와 결합될 경우 특히 위험합니다. 읽기와 입력 주입을 모두 허용하기 때문입니다.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

시스템 전역에서 **모든 키보드 및 마우스 이벤트를 가로채는 것**을 허용합니다 (input monitoring / keylogging). 프로세스는 `CGEventTap`을 등록하여 모든 애플리케이션에서 입력된 키스트로크(비밀번호, 신용카드 번호, 개인 메시지 포함)를 캡처할 수 있습니다.

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

화면 버퍼를 읽는 것을 **허용합니다** — 모든 애플리케이션(보안 텍스트 필드 포함)의 스크린샷을 찍고 화면 동영상을 녹화할 수 있습니다. OCR과 결합하면 화면에서 비밀번호 및 민감한 데이터를 자동으로 추출할 수 있습니다.

> [!WARNING]
> macOS Sonoma부터는 화면 캡처 시 지속적인 메뉴 바 표시기가 나타납니다. 구버전에서는 화면 녹화가 완전히 무음일 수 있습니다.

### **`kTCCServiceCamera`**

내장 카메라 또는 연결된 USB 카메라에서 **사진 및 비디오를 캡처**할 수 있습니다. Code injection을 camera-entitled binary에 수행하면 은밀한 영상 감시가 가능합니다.

### **`kTCCServiceMicrophone`**

모든 입력 장치에서 **오디오 녹음**을 허용합니다. mic 접근 권한을 가진 백그라운드 daemons는 애플리케이션 창 없이 지속적인 주변 오디오 감시를 제공합니다.

### **`kTCCServiceLocation`**

Wi‑Fi 삼각측량 또는 Bluetooth 비콘을 통해 기기의 **물리적 위치**를 조회할 수 있습니다. 지속적인 모니터링은 집/직장 주소, 이동 패턴, 일상 루틴을 드러냅니다.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Contacts(이름, 이메일, 전화번호 — spear-phishing에 유용함), Calendar(회의 일정, 참석자 목록), Photos(개인 사진, 자격 증명이 포함될 수 있는 스크린샷, 위치 메타데이터)에 대한 접근을 허용합니다.

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**는 App Sandbox를 약화시켜 샌드박스가 일반적으로 차단하는 시스템 전역의 Mach/XPC 서비스와의 통신을 허용합니다. 이는 **primary sandbox escape primitive**로 — 손상된 sandboxed 앱은 mach-lookup 예외를 사용하여 권한 있는 daemons에 접근하고 그들의 XPC 인터페이스를 악용할 수 있습니다.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
자세한 exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape을 보려면 다음을 참조하세요:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements**는 유저 공간 드라이버 바이너리들이 IOKit 인터페이스를 통해 커널과 직접 통신할 수 있도록 허용합니다. DriverKit 바이너리는 하드웨어를 관리합니다: USB, Thunderbolt, PCIe, HID 장치, 오디오 및 네트워킹.

DriverKit 바이너리를 손상시키면 다음을 가능하게 합니다:
- **Kernel attack surface** — 잘못된 `IOConnectCallMethod` 호출을 통해 커널 공격 표면이 확대될 수 있습니다
- **USB device spoofing** (HID injection을 위한 키보드 에뮬레이션)
- **DMA attacks** — PCIe/Thunderbolt 인터페이스를 통한 공격
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
자세한 IOKit/DriverKit exploitation에 대해서는 다음을 참조하세요:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
