# 무결성 수준

{{#include ../../banners/hacktricks-training.md}}

## 무결성 수준

Windows Vista 및 이후 버전에서는 모든 보호된 항목에 **무결성 수준** 태그가 있습니다. 이 설정은 대부분의 파일과 레지스트리 키에 "중간" 무결성 수준을 할당하며, Internet Explorer 7이 낮은 무결성 수준에서 쓸 수 있는 특정 폴더와 파일을 제외합니다. 기본 동작은 표준 사용자가 시작한 프로세스가 중간 무결성 수준을 가지며, 서비스는 일반적으로 시스템 무결성 수준에서 작동합니다. 높은 무결성 레이블은 루트 디렉터리를 보호합니다.

주요 규칙은 객체의 무결성 수준보다 낮은 무결성 수준을 가진 프로세스가 객체를 수정할 수 없다는 것입니다. 무결성 수준은 다음과 같습니다:

- **신뢰할 수 없음**: 이 수준은 익명 로그인이 있는 프로세스를 위한 것입니다. %%%예: Chrome%%%
- **낮음**: 주로 인터넷 상호작용을 위해, 특히 Internet Explorer의 보호 모드에서 관련 파일 및 프로세스와 **임시 인터넷 폴더**와 같은 특정 폴더에 영향을 미칩니다. 낮은 무결성 프로세스는 레지스트리 쓰기 접근 및 제한된 사용자 프로필 쓰기 접근을 포함하여 상당한 제한을 받습니다.
- **중간**: 대부분의 활동에 대한 기본 수준으로, 표준 사용자 및 특정 무결성 수준이 없는 객체에 할당됩니다. 관리자의 그룹 구성원조차 기본적으로 이 수준에서 작동합니다.
- **높음**: 관리자를 위해 예약되어 있으며, 이 수준의 객체를 포함하여 낮은 무결성 수준의 객체를 수정할 수 있습니다.
- **시스템**: Windows 커널 및 핵심 서비스의 가장 높은 운영 수준으로, 관리자조차 접근할 수 없으며, 중요한 시스템 기능을 보호합니다.
- **설치 프로그램**: 모든 다른 수준 위에 있는 고유한 수준으로, 이 수준의 객체가 다른 모든 객체를 제거할 수 있게 합니다.

**Process Explorer**를 사용하여 프로세스의 무결성 수준을 확인할 수 있으며, 프로세스의 **속성**에 접근하고 "**보안**" 탭을 볼 수 있습니다:

![](<../../images/image (824).png>)

`whoami /groups`를 사용하여 **현재 무결성 수준**을 확인할 수도 있습니다.

![](<../../images/image (325).png>)

### 파일 시스템의 무결성 수준

파일 시스템 내의 객체는 **최소 무결성 수준 요구 사항**이 필요할 수 있으며, 프로세스가 이 무결성 수준을 가지지 않으면 상호작용할 수 없습니다.\
예를 들어, **일반 사용자 콘솔에서 일반 파일을 생성하고 권한을 확인해 보겠습니다**:
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
이제 파일에 최소 무결성 수준을 **높음**으로 설정합시다. 이는 **관리자로 실행되는 콘솔**에서 **반드시 수행해야** 하며, **일반 콘솔**은 중간 무결성 수준에서 실행되므로 객체에 높은 무결성 수준을 할당할 수 없습니다:
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
여기서 흥미로운 점이 발생합니다. 사용자 `DESKTOP-IDJHTKP\user`가 파일에 대해 **전체 권한**을 가지고 있는 것을 볼 수 있습니다(실제로 이 사용자가 파일을 생성한 사용자입니다). 그러나 구현된 최소 무결성 수준으로 인해 그는 더 이상 파일을 수정할 수 없으며, High Integrity Level 내에서 실행하지 않는 한 수정할 수 없습니다(읽는 것은 가능하다는 점에 유의하십시오):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!NOTE]
> **따라서 파일에 최소 무결성 수준이 있을 때, 이를 수정하려면 최소한 해당 무결성 수준에서 실행해야 합니다.**

### 이진 파일의 무결성 수준

나는 `C:\Windows\System32\cmd-low.exe`에 `cmd.exe`의 복사본을 만들고 **관리자 콘솔에서 낮은 무결성 수준으로 설정했다:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
이제 `cmd-low.exe`를 실행하면 **낮은 무결성 수준**에서 실행됩니다. 대신 중간 수준에서 실행되지 않습니다:

![](<../../images/image (313).png>)

호기심이 많은 사람들을 위해, 이진 파일에 높은 무결성 수준을 할당하면(`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) 자동으로 높은 무결성 수준으로 실행되지 않습니다(중간 무결성 수준에서 호출하면 --기본적으로-- 중간 무결성 수준에서 실행됩니다).

### 프로세스의 무결성 수준

모든 파일과 폴더가 최소 무결성 수준을 가지는 것은 아니지만, **모든 프로세스는 무결성 수준에서 실행됩니다**. 파일 시스템에서 발생한 것과 유사하게, **프로세스가 다른 프로세스 내부에 쓰기를 원할 경우 최소한 동일한 무결성 수준을 가져야 합니다**. 이는 낮은 무결성 수준을 가진 프로세스가 중간 무결성 수준을 가진 프로세스에 대한 전체 액세스 핸들을 열 수 없음을 의미합니다.

이 섹션과 이전 섹션에서 언급된 제한 사항으로 인해, 보안 관점에서 볼 때, 항상 **가능한 낮은 무결성 수준에서 프로세스를 실행하는 것이 권장됩니다**.

{{#include ../../banners/hacktricks-training.md}}
