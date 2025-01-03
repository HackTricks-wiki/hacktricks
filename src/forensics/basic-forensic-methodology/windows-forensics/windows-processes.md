{{#include ../../../banners/hacktricks-training.md}}

## smss.exe

**세션 관리자**.\
세션 0은 **csrss.exe**와 **wininit.exe** (**OS** **서비스**)를 시작하고, 세션 1은 **csrss.exe**와 **winlogon.exe** (**사용자** **세션**)을 시작합니다. 그러나 프로세스 트리에서 **자식이 없는 해당 이진 파일의 프로세스는 하나만** 보여야 합니다.

또한, 0과 1을 제외한 세션은 RDP 세션이 발생하고 있음을 의미할 수 있습니다.

## csrss.exe

**클라이언트/서버 실행 하위 시스템 프로세스**.\
**프로세스**와 **스레드**를 관리하고, 다른 프로세스에 **Windows** **API**를 제공하며, **드라이브 문자**를 매핑하고, **임시 파일**을 생성하며, **종료** **프로세스**를 처리합니다.

세션 0에서 하나가 실행되고 세션 1에서 또 하나가 실행됩니다 (따라서 프로세스 트리에 **2개의 프로세스**가 있습니다). 새로운 세션마다 또 하나가 생성됩니다.

## winlogon.exe

**Windows 로그온 프로세스**.\
사용자 **로그온**/**로그오프**를 담당합니다. 사용자 이름과 비밀번호를 요청하기 위해 **logonui.exe**를 실행한 다음, 이를 확인하기 위해 **lsass.exe**를 호출합니다.

그 후, **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**에 지정된 **Userinit** 키로 **userinit.exe**를 실행합니다.

또한, 이전 레지스트리에는 **Shell 키**에 **explorer.exe**가 있어야 하며, 그렇지 않으면 **악성코드 지속성 방법**으로 악용될 수 있습니다.

## wininit.exe

**Windows 초기화 프로세스**. \
세션 0에서 **services.exe**, **lsass.exe**, **lsm.exe**를 실행합니다. 프로세스는 하나만 있어야 합니다.

## userinit.exe

**Userinit 로그온 애플리케이션**.\
**HKCU**의 **ntduser.dat**를 로드하고 **사용자** **환경**을 초기화하며 **로그온** **스크립트**와 **GPO**를 실행합니다.

**explorer.exe**를 실행합니다.

## lsm.exe

**로컬 세션 관리자**.\
사용자 세션을 조작하기 위해 smss.exe와 함께 작동합니다: 로그온/로그오프, 셸 시작, 데스크탑 잠금/잠금 해제 등.

W7 이후 lsm.exe는 서비스(lsm.dll)로 변환되었습니다.

W7에서는 프로세스가 하나만 있어야 하며, 그 중 하나는 DLL을 실행하는 서비스입니다.

## services.exe

**서비스 제어 관리자**.\
**자동 시작**으로 구성된 **서비스**와 **드라이버**를 **로드**합니다.

**svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** 등 여러 프로세스의 부모 프로세스입니다.

서비스는 `HKLM\SYSTEM\CurrentControlSet\Services`에 정의되어 있으며, 이 프로세스는 sc.exe로 쿼리할 수 있는 서비스 정보의 DB를 메모리에 유지합니다.

**일부** **서비스**는 **자신의 프로세스에서 실행**되고, 다른 서비스는 **svchost.exe 프로세스를 공유**하게 됩니다.

프로세스는 하나만 있어야 합니다.

## lsass.exe

**로컬 보안 권한 하위 시스템**.\
사용자 **인증**을 담당하며 **보안** **토큰**을 생성합니다. `HKLM\System\CurrentControlSet\Control\Lsa`에 위치한 인증 패키지를 사용합니다.

**보안** **이벤트** **로그**에 기록하며, 프로세스는 하나만 있어야 합니다.

이 프로세스는 비밀번호 덤프 공격에 매우 취약하다는 점을 염두에 두십시오.

## svchost.exe

**일반 서비스 호스트 프로세스**.\
하나의 공유 프로세스에서 여러 DLL 서비스를 호스팅합니다.

보통 **svchost.exe**는 `-k` 플래그와 함께 실행됩니다. 이는 레지스트리 **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**에 쿼리를 실행하여 -k에 언급된 인수를 포함하는 키가 있으며, 동일한 프로세스에서 실행할 서비스를 포함합니다.

예를 들어: `-k UnistackSvcGroup`는 다음을 실행합니다: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

**플래그 `-s`**가 인수와 함께 사용되면, svchost는 이 인수에서 **지정된 서비스만 실행**하도록 요청받습니다.

여러 개의 `svchost.exe` 프로세스가 있을 것입니다. 만약 그 중 어떤 것이 **`-k` 플래그를 사용하지 않는다면**, 이는 매우 의심스럽습니다. **services.exe가 부모가 아닌 경우**도 매우 의심스럽습니다.

## taskhost.exe

이 프로세스는 DLL에서 실행되는 프로세스의 호스트 역할을 합니다. 또한 DLL에서 실행되는 서비스를 로드합니다.

W8에서는 taskhostex.exe로, W10에서는 taskhostw.exe로 불립니다.

## explorer.exe

이 프로세스는 **사용자의 데스크탑**과 파일 확장을 통해 파일을 실행하는 역할을 합니다.

**로그온한 사용자당** **오직 1개의** 프로세스만 생성되어야 합니다.

이는 **userinit.exe**에서 실행되며, 종료되어야 하므로 이 프로세스의 **부모**는 나타나지 않아야 합니다.

# 악성 프로세스 탐지

- 예상 경로에서 실행되고 있습니까? (Windows 이진 파일은 임시 위치에서 실행되지 않음)
- 이상한 IP와 통신하고 있습니까?
- 디지털 서명을 확인하십시오 (Microsoft 아티팩트는 서명되어야 함)
- 철자가 정확합니까?
- 예상 SID 아래에서 실행되고 있습니까?
- 부모 프로세스가 예상한 것입니까 (있는 경우)?
- 자식 프로세스가 예상한 것입니까? (cmd.exe, wscript.exe, powershell.exe 등이 아닌가요..?)

{{#include ../../../banners/hacktricks-training.md}}
