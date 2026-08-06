# 무결성 수준

{{#include ../../banners/hacktricks-training.md}}

## 무결성 수준

Windows Vista 및 이후 버전에서는 모든 보호된 항목에 **무결성 수준** 태그가 부여됩니다. 이 설정은 일반적으로 파일과 레지스트리 키에 "medium" 무결성 수준을 할당하지만, Internet Explorer 7이 낮은 무결성 수준에서 쓸 수 있는 특정 폴더와 파일은 예외입니다. 기본적으로 일반 사용자가 시작한 프로세스는 medium 무결성 수준을 가지며, 서비스는 일반적으로 system 무결성 수준에서 동작합니다. 높은 무결성 레이블은 루트 디렉터리를 보호합니다.

핵심 규칙은 객체의 무결성 수준보다 낮은 무결성 수준을 가진 프로세스는 해당 객체를 수정할 수 없다는 것입니다. 무결성 수준은 다음과 같습니다.

- **Untrusted**: 익명 로그인으로 실행되는 프로세스에 사용되는 수준입니다. 예: Chrome
- **Low**: 주로 인터넷 상호작용에 사용되며, 특히 Internet Explorer의 Protected Mode에서 연결된 파일과 프로세스, 그리고 **Temporary Internet Folder**와 같은 특정 폴더에 적용됩니다. Low 무결성 프로세스는 레지스트리 쓰기 권한이 없고 사용자 프로필에 대한 쓰기 권한도 제한되는 등 상당한 제약을 받습니다.
- **Medium**: 대부분의 활동에 대한 기본 수준으로, 일반 사용자와 특정 무결성 수준이 없는 객체에 할당됩니다. Administrators 그룹의 구성원도 기본적으로 이 수준에서 동작합니다.
- **High**: 관리자용으로 예약된 수준이며, 관리자는 더 낮은 무결성 수준의 객체와 동일한 high 수준의 객체까지 수정할 수 있습니다.
- **System**: Windows 커널과 핵심 서비스에 사용되는 가장 높은 운영 수준으로, 관리자조차 접근할 수 없습니다. 이를 통해 중요한 시스템 기능을 보호합니다.
- **Installer**: 다른 모든 수준보다 높은 고유한 수준으로, 이 수준의 객체는 다른 모든 객체를 uninstall할 수 있습니다.

**Sysinternals**의 **Process Explorer**를 사용하고 프로세스의 **properties**에 접근한 다음 "**Security**" 탭을 확인하면 프로세스의 무결성 수준을 확인할 수 있습니다.

![무결성 수준 - 무결성 수준: Sysinternals의 Process Explorer를 사용하고 프로세스의 properties에 접근한 다음 "..." 탭을 확인하면 프로세스의 무결성 수준을 확인할 수 있습니다.](<../../images/image (824).png>)

`whoami /groups`를 사용하여 **현재 무결성 수준**도 확인할 수 있습니다.

![무결성 수준 - 무결성 수준: whoami /groups를 사용하여 현재 무결성 수준도 확인할 수 있습니다.](<../../images/image (325).png>)

### 파일 시스템의 무결성 수준

파일 시스템 내부의 객체에는 **최소 무결성 수준 요구 사항**이 있을 수 있으며, 프로세스가 해당 무결성 수준을 갖고 있지 않으면 해당 객체와 상호작용할 수 없습니다.\
예를 들어, **일반 사용자 콘솔에서 일반 파일을 생성하고 권한을 확인**해 보겠습니다:
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
이제 파일에 최소 integrity level을 **High**로 할당해 보겠습니다. 이는 **administrator** 권한으로 실행되는 **console**에서 수행해야 합니다. 일반 **console**은 Medium Integrity level에서 실행되므로 객체에 High Integrity level을 할당할 **권한이 없습니다**:
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
여기서부터 흥미로워집니다. 사용자 `DESKTOP-IDJHTKP\user`가 해당 파일에 대해 **FULL privileges**를 가지고 있음(실제로 이 사용자가 파일을 생성함)을 확인할 수 있습니다. 그러나 구현된 최소 integrity level로 인해 High Integrity Level 내에서 실행 중이지 않은 한 더 이상 파일을 수정할 수 없습니다(단, 파일을 읽을 수는 있음):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **따라서 파일에 최소 무결성 수준이 설정되어 있는 경우, 해당 파일을 수정하려면 최소한 해당 무결성 수준에서 실행 중이어야 합니다.**

### Binaries의 무결성 수준

`cmd.exe`를 `C:\Windows\System32\cmd-low.exe`에 복사한 후 **administrator console에서 무결성 수준을 low로 설정했습니다:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
이제 `cmd-low.exe`를 실행하면 medium 무결성 수준이 아닌 **low 무결성 수준에서 실행**됩니다:

![파일 시스템의 무결성 수준 - 바이너리의 무결성 수준: 이제 cmd-low.exe를 실행하면 medium 무결성 수준이 아닌 low 무결성 수준에서 실행됩니다](<../../images/image (313).png>)

궁금한 분들을 위해 설명하자면, 바이너리에 high 무결성 수준을 할당하더라도 (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) 자동으로 high 무결성 수준으로 실행되지는 않습니다 (medium 무결성 수준에서 호출하면 --기본적으로-- medium 무결성 수준에서 실행됩니다).

### 프로세스의 무결성 수준

모든 파일과 폴더에 최소 무결성 수준이 지정되어 있는 것은 **아니지만, 모든 프로세스는 무결성 수준에서 실행됩니다**. 파일 시스템에서 발생한 것과 마찬가지로, **프로세스가 다른 프로세스 내부에 쓰기를 수행하려면 최소한 동일한 무결성 수준을 가져야 합니다**. 즉, low 무결성 수준의 프로세스는 medium 무결성 수준의 프로세스에 대해 full access 권한을 가진 핸들을 열 수 없습니다.

이 섹션과 이전 섹션에서 설명한 제한 사항으로 인해, 보안 관점에서는 항상 **가능한 한 낮은 무결성 수준에서 프로세스를 실행하는 것이 권장됩니다**.

{{#include ../../banners/hacktricks-training.md}}
