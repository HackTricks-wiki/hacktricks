# 무결성 수준

{{#include ../../banners/hacktricks-training.md}}

## 무결성 수준

Windows Vista 및 이후 버전에서는 보안 설정이 가능한 객체에 **무결성 수준** 레이블을 지정할 수 있습니다. 대부분의 객체는 중간 무결성으로 처리되며, 낮은 무결성 애플리케이션을 위해 지정된 특정 위치에는 낮은 무결성 레이블을 지정할 수 있습니다. 표준 사용자가 시작한 프로세스는 일반적으로 중간 무결성으로 실행되고, 권한이 상승된 애플리케이션은 높은 무결성으로 실행되며, 많은 서비스는 시스템 무결성으로 실행됩니다.<sup>[[1]](#references)</sup>

핵심 규칙은 객체의 무결성 수준보다 낮은 무결성 수준의 프로세스는 해당 객체를 수정할 수 없다는 것입니다. Windows는 객체의 임의 접근 제어 목록(DACL)을 평가하기 전에 이 필수 무결성 제어(MIC) 검사를 적용합니다. 일반적으로 사용되는 수준은 다음과 같습니다.<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: 가장 낮은 수준이며 `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`)로 표시됩니다. 이 무결성 레이블을 **Anonymous Logon** identity (`S-1-5-7`)와 혼동하지 마세요. 인증 identity와 MIC 레이블은 서로 다른 SID namespace입니다. 실제 사례로 Chromium의 Windows sandbox는 처음에 sandboxed target에 Low 무결성을 할당한 다음, 시작 후 renderer target을 Untrusted 무결성으로 낮춥니다.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: 주로 인터넷 상호작용에 사용되며, 특히 Internet Explorer의 Protected Mode에서 관련 파일과 프로세스, 그리고 **Temporary Internet Folder**와 같은 특정 폴더에 적용됩니다. Low 무결성 프로세스에는 상당한 제한이 적용되며, 여기에는 registry 쓰기 권한 없음과 제한된 user profile 쓰기 권한이 포함됩니다.
- **Medium**: 대부분의 활동에 대한 기본 수준으로, 표준 사용자와 특정 무결성 수준이 지정되지 않은 객체에 할당됩니다. Administrators group의 구성원도 기본적으로 이 수준에서 동작합니다.
- **High**: administrators용으로 예약된 수준이며, 더 낮은 무결성 수준의 객체와 High 수준 자체의 객체를 수정할 수 있습니다.
- **System**: Windows kernel과 핵심 서비스에 사용되는 가장 높은 운영 수준으로, administrators도 접근할 수 없습니다. 이를 통해 중요한 system 기능을 보호합니다.

Windows는 System보다 높은 protected-process 무결성 값도 정의합니다. 그러나 **TrustedInstaller**는 별도의 MIC 수준이 아니라 Windows service identity입니다. 보호된 operating-system resource를 수정할 수 있는 권한은 해당 identity에 부여된 permissions에서 비롯됩니다.

system drive의 root와 같은 위치가 항상 고정된 High 무결성 레이블을 가진다고 가정하지 마세요. `icacls`를 사용하여 유효한 DACL과 명시적인 mandatory label을 확인하세요. 레이블이 없는 객체는 MIC에서 Medium으로 처리되지만, 해당 객체의 DACL과 ownership은 여전히 독립적으로 access를 제한할 수 있습니다.<sup>[[1]](#references)[[4]](#references)</sup>

**Sysinternals**의 **Process Explorer**를 사용하여 프로세스의 무결성 수준을 확인할 수 있습니다. 프로세스 속성을 열고 **Security** 탭을 확인하세요.<sup>[[3]](#references)</sup>

![무결성 수준 - 무결성 수준: Sysinternals의 Process Explorer에서 프로세스 속성을 열고 확인하여 프로세스의 무결성 수준을 확인할 수 있습니다.](<../../images/image (824).png>)

`whoami /groups`를 사용하여 **현재 무결성 수준**을 확인할 수도 있습니다.

![무결성 수준 - 무결성 수준: whoami /groups를 사용하여 현재 무결성 수준도 확인할 수 있습니다.](<../../images/image (325).png>)

### 파일 시스템의 무결성 수준

파일 시스템의 객체에는 **최소 무결성 수준 요구 사항**이 있을 수 있습니다. 해당 수준보다 낮은 프로세스에는 DACL이 다른 방식으로 access를 허용하더라도 객체의 mandatory policy가 적용됩니다. 예를 들어, standard-user console에서 일반 파일을 생성한 후 permissions를 확인할 수 있습니다.<sup>[[1]](#references)[[4]](#references)</sup>
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
이제 파일에 **High** 최소 무결성 수준을 할당합니다. 일반 콘솔은 Medium 무결성 수준으로 실행되며 객체에 High 무결성 수준을 할당할 수 없으므로, 이 작업은 **administrator**로 실행 중인 **콘솔**에서 수행해야 합니다:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
사용자 `DESKTOP-IDJHTKP\user`는 해당 파일을 생성했기 때문에 파일에 대한 **FULL privileges**를 보유합니다. 그러나 mandatory label 때문에 프로세스가 High integrity에서 실행되지 않는 한 사용자는 파일을 수정할 수 없습니다. 표시된 mandatory policy가 `(NW)`, 즉 no-write-up이므로 사용자는 여전히 파일을 읽을 수 있습니다:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **따라서 파일에 최소 무결성 수준이 설정되어 있는 경우, 해당 파일을 수정하려면 최소한 그 무결성 수준에서 실행 중이어야 합니다.**

### 바이너리의 무결성 수준

다음 예제에서는 `C:\Windows\System32\cmd-low.exe`에 있는 `cmd.exe`의 복사본을 사용하고, **administrator console에서 Low integrity level을 할당**합니다:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
이제 `cmd-low.exe`를 실행하면 medium이 아닌 **low-integrity level에서 실행됩니다**:

![파일 시스템의 Integrity Levels - 바이너리의 Integrity Levels: 이제 cmd-low.exe를 실행하면 medium이 아닌 low-integrity level에서 실행됩니다](<../../images/image (313).png>)

바이너리에 High integrity label을 할당해도 (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) 해당 바이너리가 자동으로 High integrity에서 실행되지는 않습니다. Medium-integrity process에서 호출하면 새 process는 실행 파일과 호출자의 integrity level 중 더 낮은 수준을 받기 때문에 Medium integrity에서 실행됩니다.<sup>[[1]](#references)</sup>

### Process의 Integrity Levels

모든 파일과 폴더에 명시적인 최소 integrity label이 있는 것은 **아니지만, 모든 process는 integrity level에서 실행됩니다**. 파일 시스템 객체와 마찬가지로, **다른 process에 대한 write access를 얻으려는 process는 최소한 동일한 integrity level을 가져야 합니다**. 따라서 Low-integrity process는 Medium-integrity process를 full access로 열 수 없습니다.<sup>[[1]](#references)</sup>

이러한 제한 때문에 가장 안전한 방법은 **각 process를 의도한 작업을 수행할 수 있는 가장 낮은 integrity level에서 실행하는 것**입니다.

## References

- [1] [Microsoft Learn – 필수 무결성 제어](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL 열거형](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Windows 기본 sandbox 무결성 정책](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – 잘 알려진 SID](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
