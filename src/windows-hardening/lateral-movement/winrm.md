# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM은 Windows 환경에서 가장 편리한 **lateral movement** 전송 방식 중 하나인데, SMB service creation 트릭 없이 **WS-Man/HTTP(S)** 위로 원격 shell을 제공하기 때문이다. 대상이 **5985/5986**을 노출하고 있고, 당신의 principal이 remoting 사용이 허용된다면, 종종 "valid creds"에서 "interactive shell"까지 매우 빠르게 이동할 수 있다.

**protocol/service enumeration**, listeners, WinRM 활성화, `Invoke-Command`, 일반적인 client 사용법은 아래를 확인하라:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- **HTTP/HTTPS**를 SMB/RPC 대신 사용하므로, PsExec-style execution이 차단된 곳에서도 자주 동작한다.
- **Kerberos**를 사용하면 재사용 가능한 credentials를 대상에 보내지 않는다.
- **Windows**, **Linux**, 그리고 **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`)에서 깔끔하게 동작한다.
- interactive PowerShell remoting 경로는 대상에서 인증된 사용자 context 아래 **`wsmprovhost.exe`**를 spawn하며, 이는 service-based exec과 운영상 다르다.

## Access model and prerequisites

실제로 WinRM lateral movement가 성공하려면 **세 가지**가 필요하다:

1. 대상에 **WinRM listener** (`5985`/`5986`)와 접근을 허용하는 firewall rules가 있다.
2. 계정이 endpoint에 **authenticate**할 수 있다.
3. 계정이 remoting session을 **open**할 수 있다.

이 접근 권한을 얻는 일반적인 방법:

- 대상에서 **Local Administrator**.
- 최신 시스템에서는 **Remote Management Users**, 또는 아직 그 그룹을 존중하는 시스템/컴포넌트에서는 **WinRMRemoteWMIUsers__** 멤버십.
- local security descriptors / PowerShell remoting ACL 변경을 통해 위임된 명시적 remoting 권한.

이미 admin 권한으로 box를 제어하고 있다면, 여기 설명된 기법을 사용해 **전체 admin group membership 없이도 WinRM access를 위임할 수 있음**을 기억하라:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos는 hostname/FQDN이 필요하다**. IP로 연결하면 client는 보통 **NTLM/Negotiate**로 fallback한다.
- **workgroup** 또는 cross-trust edge case에서는, NTLM이 일반적으로 **HTTPS** 또는 client의 **TrustedHosts**에 target 추가를 요구한다.
- workgroup에서 **local accounts**로 Negotiate를 사용할 때, UAC remote restrictions 때문에 built-in Administrator account를 사용하지 않거나 `LocalAccountTokenFilterPolicy=1`이 아니면 access가 막힐 수 있다.
- PowerShell remoting은 기본적으로 **`HTTP/<host>` SPN**을 사용한다. 환경에서 **`HTTP/<host>`**가 이미 다른 service account에 등록되어 있으면 WinRM Kerberos가 `0x80090322`로 실패할 수 있다; port-qualified SPN을 사용하거나 해당 SPN이 존재하는 **`WSMAN/<host>`**로 전환하라.

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
### Evil-WinRM for interactive shells

`evil-winrm`은 Linux에서 가장 편리한 interactive 옵션으로 남아 있으며, **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer, 그리고 in-memory PowerShell/.NET loading을 지원한다.
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

기본 **`HTTP/<host>`** SPN이 Kerberos 실패를 일으킬 때는 대신 **`WSMAN/<host>`** 티켓을 요청/사용해 보세요. 이는 **`HTTP/<host>`**가 이미 다른 서비스 계정에 연결된, 강화되었거나 특이한 엔터프라이즈 설정에서 나타날 수 있습니다.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
이것은 특히 **RBCD / S4U** abuse 이후, 일반적인 `HTTP` 티켓이 아니라 **WSMAN** 서비스 티켓을 특정해서 forged 하거나 요청했을 때도 유용합니다.

### Certificate-based authentication

WinRM은 **client certificate authentication**도 지원하지만, certificate는 대상 시스템에서 반드시 **local account**에 mapped 되어 있어야 합니다. 공격 관점에서 이는 다음과 같은 경우 중요합니다:

- 이미 WinRM에 대해 mapped 된 유효한 client certificate와 private key를 stole/exported 했을 때;
- **AD CS / Pass-the-Certificate**를 악용해 principal에 대한 certificate를 얻은 뒤 다른 authentication path로 pivot할 때;
- password-based remoting을 의도적으로 피하는 환경에서 작업할 때.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM은 password/hash/Kerberos 인증보다 훨씬 덜 일반적이지만, 존재할 경우 password rotation을 견디는 **passwordless lateral movement** 경로를 제공할 수 있습니다.

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
## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe`는 기본 제공되며, 대화형 PowerShell remoting session을 열지 않고 **native WinRM command execution**을 원할 때 유용합니다:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
운영적으로 `winrs.exe`는 일반적으로 다음과 유사한 원격 프로세스 체인을 생성합니다:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
이것은 서비스 기반 exec 및 대화형 PSRP 세션과 다르기 때문에 기억해둘 가치가 있습니다.

### `winrm.cmd` / PowerShell remoting 대신 WS-Man COM

`Enter-PSSession` 없이도 WS-Man을 통해 WMI 클래스를 호출하여 **WinRM transport**로 실행할 수 있습니다. 이렇게 하면 transport는 여전히 WinRM이지만, 원격 실행 primitive는 **WMI `Win32_Process.Create`**가 됩니다:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
그 접근 방식은 다음과 같은 경우 유용합니다:

- PowerShell logging이 강하게 모니터링될 때.
- classic PS remoting workflow가 아니라 **WinRM transport**를 원할 때.
- **`WSMan.Automation`** COM object를 중심으로 custom tooling을 만들거나 사용할 때.

## NTLM relay to WinRM (WS-Man)

SMB relay가 signing 때문에 차단되고 LDAP relay가 제한적일 때, **WS-Man/WinRM**은 여전히 매력적인 relay 대상이 될 수 있습니다. 최신 `ntlmrelayx.py`에는 **WinRM relay servers**가 포함되어 있으며 **`wsman://`** 또는 **`winrms://`** targets로 relay할 수 있습니다.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
두 가지 실용적인 메모:

- Relay는 대상이 **NTLM**을 수락하고 relayed principal이 WinRM을 사용할 수 있을 때 가장 유용합니다.
- 최근 Impacket 코드는 **`WSMANIDENTIFY: unauthenticated`** 요청을 특별히 처리하므로, `Test-WSMan` 스타일의 probe가 relay 흐름을 깨지 않습니다.

첫 번째 WinRM session에 들어간 뒤의 multi-hop 제약은 다음을 확인하세요:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC and detection notes

- **Interactive PowerShell remoting**은 일반적으로 대상에서 **`wsmprovhost.exe`**를 생성합니다.
- **`winrs.exe`**는 보통 **`winrshost.exe`**를 생성한 다음 요청된 child process를 생성합니다.
- raw `cmd.exe` 대신 PSRP를 사용하면 **network logon** telemetry, WinRM service events, 그리고 PowerShell operational/script-block logging이 발생할 수 있습니다.
- 단일 command만 필요하다면, `winrs.exe`나 one-shot WinRM execution이 오래 유지되는 interactive remoting session보다 더 조용할 수 있습니다.
- Kerberos를 사용할 수 있다면, IP + NTLM 대신 **FQDN + Kerberos**를 우선해 trust issues와 클라이언트 측 `TrustedHosts` 변경의 번거로움을 줄이세요.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
