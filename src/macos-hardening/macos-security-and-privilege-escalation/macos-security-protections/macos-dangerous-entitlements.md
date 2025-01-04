# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`**로 시작하는 권한은 제3자에게 제공되지 않으며, 오직 Apple만 부여할 수 있습니다.

## High

### `com.apple.rootless.install.heritable`

권한 **`com.apple.rootless.install.heritable`**는 **SIP를 우회**할 수 있게 해줍니다. [자세한 정보는 여기](macos-sip.md#com.apple.rootless.install.heritable)를 확인하세요.

### **`com.apple.rootless.install`**

권한 **`com.apple.rootless.install`**는 **SIP를 우회**할 수 있게 해줍니다. [자세한 정보는 여기](macos-sip.md#com.apple.rootless.install)를 확인하세요.

### **`com.apple.system-task-ports` (이전 이름: `task_for_pid-allow`)**

이 권한은 **커널을 제외한 모든** 프로세스의 **작업 포트**를 가져올 수 있게 해줍니다. [**자세한 정보는 여기**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)를 확인하세요.

### `com.apple.security.get-task-allow`

이 권한은 **`com.apple.security.cs.debugger`** 권한을 가진 다른 프로세스가 이 권한을 가진 바이너리에서 실행되는 프로세스의 작업 포트를 가져오고 **코드를 주입**할 수 있게 해줍니다. [**자세한 정보는 여기**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)를 확인하세요.

### `com.apple.security.cs.debugger`

디버깅 도구 권한을 가진 앱은 `task_for_pid()`를 호출하여 서명되지 않은 제3자 앱의 유효한 작업 포트를 검색할 수 있습니다. 그러나 디버깅 도구 권한이 있어도, 디버거는 **`Get Task Allow` 권한이 없는** 프로세스의 작업 포트를 **가져올 수 없습니다**, 따라서 시스템 무결성 보호에 의해 보호됩니다. [**자세한 정보는 여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)를 확인하세요.

### `com.apple.security.cs.disable-library-validation`

이 권한은 **Apple에 의해 서명되지 않거나 메인 실행 파일과 동일한 팀 ID로 서명되지 않은 프레임워크, 플러그인 또는 라이브러리를 로드**할 수 있게 해줍니다. 따라서 공격자는 임의의 라이브러리 로드를 악용하여 코드를 주입할 수 있습니다. [**자세한 정보는 여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)를 확인하세요.

### `com.apple.private.security.clear-library-validation`

이 권한은 **`com.apple.security.cs.disable-library-validation`**와 매우 유사하지만, **직접적으로** 라이브러리 검증을 **비활성화하는 대신**, 프로세스가 **`csops` 시스템 호출을 통해 이를 비활성화**할 수 있게 해줍니다.\
[**자세한 정보는 여기**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)를 확인하세요.

### `com.apple.security.cs.allow-dyld-environment-variables`

이 권한은 **DYLD 환경 변수를 사용**할 수 있게 해주며, 이는 라이브러리와 코드를 주입하는 데 사용될 수 있습니다. [**자세한 정보는 여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)를 확인하세요.

### `com.apple.private.tcc.manager` 또는 `com.apple.rootless.storage`.`TCC`

[**이 블로그에 따르면**](https://objective-see.org/blog/blog_0x4C.html) **및** [**이 블로그에 따르면**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), 이 권한은 **TCC** 데이터베이스를 **수정**할 수 있게 해줍니다.

### **`system.install.apple-software`** 및 **`system.install.apple-software.standar-user`**

이 권한은 **사용자에게 권한 요청 없이 소프트웨어를 설치**할 수 있게 해주며, 이는 **권한 상승**에 유용할 수 있습니다.

### `com.apple.private.security.kext-management`

커널에 **커널 확장을 로드**하도록 요청하는 데 필요한 권한입니다.

### **`com.apple.private.icloud-account-access`**

권한 **`com.apple.private.icloud-account-access`**를 통해 **`com.apple.iCloudHelper`** XPC 서비스와 통신할 수 있으며, 이는 **iCloud 토큰**을 **제공**합니다.

**iMovie**와 **Garageband**는 이 권한을 가지고 있었습니다.

이 권한으로부터 **iCloud 토큰을 얻는** exploit에 대한 더 많은 **정보**는 다음 강연을 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 이 권한이 무엇을 허용하는지 모르겠습니다.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**이 보고서**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서 **재부팅 후 SSV 보호 콘텐츠를 업데이트하는 데 사용될 수 있다고 언급되었습니다**. 방법을 아신다면 PR을 보내주세요!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**이 보고서**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서 **재부팅 후 SSV 보호 콘텐츠를 업데이트하는 데 사용될 수 있다고 언급되었습니다**. 방법을 아신다면 PR을 보내주세요!

### `keychain-access-groups`

이 권한 목록은 애플리케이션이 접근할 수 있는 **키체인** 그룹을 나타냅니다:
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

**전체 디스크 접근** 권한을 부여하며, TCC에서 가질 수 있는 가장 높은 권한 중 하나입니다.

### **`kTCCServiceAppleEvents`**

앱이 일반적으로 **작업 자동화**에 사용되는 다른 애플리케이션에 이벤트를 보낼 수 있도록 허용합니다. 다른 앱을 제어함으로써, 이러한 다른 앱에 부여된 권한을 악용할 수 있습니다.

예를 들어, 사용자에게 비밀번호를 요청하도록 만들 수 있습니다:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Or making them perform **임의의 작업**.

### **`kTCCServiceEndpointSecurityClient`**

사용자의 TCC 데이터베이스를 **쓰기**를 포함한 여러 권한을 허용합니다.

### **`kTCCServiceSystemPolicySysAdminFiles`**

사용자의 **`NFSHomeDirectory`** 속성을 **변경**할 수 있게 하여 홈 폴더 경로를 변경하고 따라서 TCC를 **우회**할 수 있게 합니다.

### **`kTCCServiceSystemPolicyAppBundles`**

앱 번들 내의 파일을 수정할 수 있게 하며(앱.app 내부), 이는 **기본적으로 금지되어** 있습니다.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

이 접근 권한을 가진 사용자를 확인할 수 있는 방법은 _시스템 설정_ > _개인정보 보호 및 보안_ > _앱 관리_입니다.

### `kTCCServiceAccessibility`

프로세스는 **macOS 접근성 기능을 악용**할 수 있으며, 예를 들어 키 입력을 누를 수 있습니다. 따라서 Finder와 같은 앱을 제어할 수 있는 접근 권한을 요청하고 이 권한으로 대화 상자를 승인할 수 있습니다.

## 중간

### `com.apple.security.cs.allow-jit`

이 권한은 `mmap()` 시스템 함수에 `MAP_JIT` 플래그를 전달하여 **쓰기 가능하고 실행 가능한 메모리**를 **생성**할 수 있게 합니다. [**자세한 정보는 여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)를 확인하세요.

### `com.apple.security.cs.allow-unsigned-executable-memory`

이 권한은 **C 코드를 오버라이드하거나 패치**할 수 있게 하며, 오래된 **`NSCreateObjectFileImageFromMemory`** (근본적으로 안전하지 않음)를 사용하거나 **DVDPlayback** 프레임워크를 사용할 수 있게 합니다. [**자세한 정보는 여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)를 확인하세요.

> [!CAUTION]
> 이 권한을 포함하면 메모리 안전하지 않은 코드 언어에서 일반적인 취약점에 노출됩니다. 귀하의 앱이 이 예외가 필요한지 신중하게 고려하세요.

### `com.apple.security.cs.disable-executable-page-protection`

이 권한은 **디스크에 있는 자신의 실행 파일의 섹션을 수정**하여 강제로 종료할 수 있게 합니다. [**자세한 정보는 여기**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)를 확인하세요.

> [!CAUTION]
> Disable Executable Memory Protection Entitlement는 귀하의 앱에서 기본 보안 보호를 제거하는 극단적인 권한으로, 공격자가 귀하의 앱의 실행 코드를 탐지 없이 재작성할 수 있게 합니다. 가능하다면 더 좁은 권한을 선호하세요.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

이 권한은 nullfs 파일 시스템을 마운트할 수 있게 하며(기본적으로 금지됨). 도구: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

이 블로그 게시물에 따르면, 이 TCC 권한은 일반적으로 다음 형식으로 발견됩니다:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
프로세스가 **모든 TCC 권한을 요청하도록 허용**합니다.

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}

</details>
