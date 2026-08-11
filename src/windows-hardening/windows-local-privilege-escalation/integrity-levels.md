# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista 및 이후 버전에서는 보안 객체에 **integrity level** 레이블을 지정할 수 있습니다. 대부분의 객체는 medium integrity로 처리되며, low-integrity 애플리케이션용으로 지정된 특정 위치에는 low 레이블을 지정할 수 있습니다. 표준 사용자가 시작한 프로세스는 일반적으로 medium integrity로 실행되고, 권한이 상승된 애플리케이션은 high integrity로 실행되며, 많은 서비스는 system integrity로 실행됩니다.<sup>[[1]](#references)</sup>

핵심 규칙은 객체의 integrity level보다 낮은 integrity level을 가진 프로세스는 해당 객체를 수정할 수 없다는 것입니다. Windows는 객체의 discretionary access control list (DACL)를 평가하기 전에 Mandatory Integrity Control (MIC) 검사를 적용합니다. 일반적으로 사용되는 level은 다음과 같습니다.<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: 가장 낮은 level이며, `SECURITY_MANDATORY_UNTRUSTED_RID`로 표시됩니다. 실제 사례로 Chromium의 Windows sandbox는 처음에 sandbox된 대상을 Low integrity로 지정한 다음, 시작 후 renderer 대상을 Untrusted integrity로 낮춥니다.<sup>[[5]](#references)</sup>
- **Low**: 주로 인터넷 상호작용을 위한 level이며, 특히 Internet Explorer의 Protected Mode에서 연결된 파일과 프로세스 및 **Temporary Internet Folder**와 같은 특정 폴더에 영향을 줍니다. Low integrity 프로세스에는 레지스트리 쓰기 권한이 없고 사용자 프로필에 대한 쓰기 권한이 제한되는 등 상당한 제약이 적용됩니다.
- **Medium**: 대부분의 작업에 대한 기본 level로, 표준 사용자와 특정 integrity level이 없는 객체에 할당됩니다. Administrators 그룹의 구성원도 기본적으로 이 level에서 실행됩니다.
- **High**: 관리자용으로 예약된 level이며, 관리자가 high level 자체를 포함하여 더 낮은 integrity level의 객체를 수정할 수 있도록 합니다.
- **System**: Windows kernel 및 핵심 서비스에 사용되는 가장 높은 운영 level입니다. 관리자도 접근할 수 없으며 중요한 시스템 기능을 보호합니다.

Windows는 System보다 높은 protected-process integrity 값을 정의합니다. 그러나 **TrustedInstaller**는 별도의 MIC level이 아니라 Windows service identity입니다. 보호된 운영 체제 리소스를 수정할 수 있는 권한은 해당 identity에 부여된 permissions에서 비롯됩니다.

**Sysinternals**의 **Process Explorer**를 사용하여 프로세스의 integrity level을 확인할 수 있습니다. 프로세스 속성을 열고 **Security** 탭을 확인하면 됩니다.<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: Sysinternals의 Process Explorer에서 프로세스 속성에 접근하고 "Security" 탭을 확인하여 프로세스의 integrity level을 확인할 수 있습니다.](<../../images/image (824).png>)

`whoami /groups`를 사용하여 **현재 integrity level**도 확인할 수 있습니다.

![Integrity Levels - Integrity Levels: whoami /groups를 사용하여 현재 integrity level도 확인할 수 있습니다.](<../../images/image (325).png>)

### 파일 시스템의 Integrity Levels

파일 시스템의 객체에는 **minimum integrity-level requirement**가 있을 수 있습니다. 해당 level보다 낮은 프로세스에는 DACL이 다른 방식으로 접근 권한을 부여하더라도 객체의 mandatory policy가 적용됩니다. 예를 들어 표준 사용자 console에서 일반 파일을 생성한 다음 permissions를 확인할 수 있습니다.<sup>[[1]](#references)[[4]](#references)</sup>
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
이제 파일에 **High** integrity level을 할당합니다. 일반 콘솔은 Medium integrity에서 실행되며 객체에 High integrity를 할당할 수 없으므로, 이 작업은 **administrator** 권한으로 실행 중인 **콘솔**에서 수행해야 합니다:
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
사용자 `DESKTOP-IDJHTKP\user`는 해당 파일을 생성했기 때문에 파일에 대한 **FULL privileges**를 가집니다. 그러나 mandatory label 때문에 프로세스가 High integrity로 실행되지 않는 한 사용자는 파일을 수정할 수 없습니다. 표시된 mandatory policy가 `(NW)`, 즉 no-write-up이므로 사용자는 여전히 파일을 읽을 수 있습니다:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **따라서 파일에 최소 무결성 수준이 설정되어 있는 경우, 해당 파일을 수정하려면 최소한 그 무결성 수준으로 실행 중이어야 합니다.**

### 바이너리의 무결성 수준

다음 예제에서는 `C:\Windows\System32\cmd-low.exe`에 있는 `cmd.exe` 사본을 사용하고, **관리자 콘솔에서 Low 무결성 수준을 할당**합니다:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
이제 `cmd-low.exe`를 실행하면 medium이 아닌 **Low-integrity level에서 실행**됩니다:

![파일 시스템의 Integrity Levels - 바이너리의 Integrity Levels: 이제 cmd-low.exe를 실행하면 medium이 아닌 Low-integrity level에서 실행됩니다](<../../images/image (313).png>)

바이너리에 High integrity label을 할당해도 (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) 해당 바이너리가 자동으로 High integrity에서 실행되지는 않습니다. Medium-integrity process에서 호출하면 새 process는 실행 파일과 호출자의 integrity level 중 더 낮은 수준을 받기 때문에 Medium integrity에서 실행됩니다.<sup>[[1]](#references)</sup>

### Process의 Integrity Levels

모든 파일과 폴더에 명시적인 최소 integrity label이 지정되어 있는 것은 **아니지만, 모든 process는 integrity level에서 실행됩니다**. 파일 시스템 객체와 마찬가지로 **다른 process에 대한 write access를 원하는 process는 최소한 동일한 integrity level을 가져야 합니다**. 따라서 Low-integrity process는 Medium-integrity process를 full access로 열 수 없습니다.<sup>[[1]](#references)</sup>

이러한 제한 때문에 가장 안전한 방법은 **각 process가 의도한 작업을 수행할 수 있는 가장 낮은 integrity level에서 실행되도록 하는 것**입니다.

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL 열거형](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium 소스 – Default Windows sandbox integrity policy](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
