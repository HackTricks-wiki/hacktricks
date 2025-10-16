# Tokens का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

## Tokens

अगर आप नहीं जानते कि Windows Access Tokens क्या हैं तो आगे बढ़ने से पहले यह पृष्ठ पढ़ें:


{{#ref}}
access-tokens.md
{{#endref}}

**हो सकता है कि आप अपने पास मौजूद टोकन्स का दुरुपयोग करके privileges बढ़ा सकें**

### SeImpersonatePrivilege

यह वह privilege है जो किसी भी process के पास हो सकती है और यह किसी भी token का impersonation (परंतु creation नहीं) करने की अनुमति देती है, बशर्ते कि उसका handle उपलब्ध हो। किसी Windows service (DCOM) से एक privileged token प्राप्त किया जा सकता है अगर उसे किसी exploit के खिलाफ NTLM authentication करने के लिए प्रेरित किया जाए, जिससे बाद में SYSTEM privileges के साथ एक process चलाया जा सके। इस कमजोरी का उपयोग कई tools से किया जा सकता है, जैसे [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (जिसके लिए winrm disabled होना चाहिए), [SweetPotato](https://github.com/CCob/SweetPotato), और [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)।

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

यह बहुत हद तक **SeImpersonatePrivilege** के समान है, यह privileged token प्राप्त करने के लिए **उसी विधि** का उपयोग करेगा.\
इसके बाद, यह privilege आपको एक नए/सस्पेंड किए गए process को **primary token असाइन** करने की अनुमति देता है। Privileged impersonation token के साथ आप एक primary token (DuplicateTokenEx) derive कर सकते हैं।\
उस token के साथ, आप 'CreateProcessAsUser' से **नया process** बना सकते हैं या एक process को सस्पेंड करके **token सेट** कर सकते हैं (आम तौर पर, आप किसी चल रहे process के primary token को modify नहीं कर सकते)।

### SeTcbPrivilege

यदि आपके पास यह token सक्षम है तो आप **KERB_S4U_LOGON** का उपयोग करके किसी भी अन्य user के लिए credentials जाने बिना एक **impersonation token** प्राप्त कर सकते हैं, token में एक मनमाना group (जैसे admins) जोड़ सकते हैं, token का **integrity level** "**medium**" पर सेट कर सकते हैं, और इस token को वर्तमान thread पर असाइन कर सकते हैं (SetThreadToken)।

### SeBackupPrivilege

यह privilege सिस्टम को किसी भी फ़ाइल के लिए सभी read access control देने का कारण बनता है (केवल पढ़ने के ऑपरेशनों तक सीमित)। इसका उपयोग स्थानीय Administrator के password hashes को registry से पढ़ने के लिए किया जाता है, जिसके बाद psexec या wmiexec जैसे tools hash के साथ उपयोग किए जा सकते हैं (Pass-the-Hash technique)। हालाँकि, यह तरीका तब विफल होता है जब Local Administrator account disabled हो, या जब कोई policy लागू हो जो remote कनेक्ट करने वाले Local Administrators से administrative rights हटा दे।\
आप इस privilege का दुरुपयोग निम्न तरीकों से कर सकते हैं:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- IppSec की इस वीडियो में बताए अनुसार: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- या जैसा कि **escalating privileges with Backup Operators** सेक्शन में समझाया गया है:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

यह privilege किसी भी system फ़ाइल के लिए write access की अनुमति देता है, भले ही फ़ाइल की Access Control List (ACL) कुछ भी कहे। यह कई escalation के अवसर खोलता है, जिनमें services को modify करना, DLL Hijacking करना, और Image File Execution Options के जरिए debuggers सेट करना शामिल है, तथा बहुत सी अन्य तकनीकें।

### SeCreateTokenPrivilege

SeCreateTokenPrivilege एक शक्तिशाली permission है, विशेष रूप से तब उपयोगी जब किसी user के पास tokens impersonate करने की क्षमता हो, पर यह SeImpersonatePrivilege की अनुपस्थिति में भी उपयोगी हो सकती है। यह क्षमता उस आधार पर निर्भर करती है कि क्या impersonate किया जा सकने वाला token उसी user का है और उसकी integrity level current process की तुलना में अधिक नहीं है।

मुख्य बिंदु:

- **SeImpersonatePrivilege के बिना impersonation:** विशेष परिस्थितियों में SeCreateTokenPrivilege का उपयोग कर EoP किया जा सकता है।
- **Token impersonation के लिए शर्तें:** सफल impersonation के लिए लक्ष्य token उसी user का होना चाहिए और उसकी integrity level उस process की integrity level से कम या बराबर होनी चाहिए जो impersonation कर रहा है।
- **Impersonation tokens बनाना और संशोधित करना:** उपयोगकर्ता एक impersonation token बना सकते हैं और उसमें किसी privileged group की SID जोड़कर उसे बढ़ा सकते हैं।

### SeLoadDriverPrivilege

यह privilege device drivers को **load और unload** करने की अनुमति देता है, जिसके लिए registry में एक entry बनानी होती है जिसमें `ImagePath` और `Type` के specific values सेट हों। चूंकि सीधे `HKLM` (HKEY_LOCAL_MACHINE) में write access प्रतिबंधित है, इसलिए `HKCU` (HKEY_CURRENT_USER) का उपयोग करना होगा। हालाँकि, kernel द्वारा driver configuration के लिए `HKCU` को पहचानने के लिए एक विशिष्ट path का पालन करना आवश्यक है।

यह path है `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, जहाँ `<RID>` current user का Relative Identifier है। `HKCU` के अंदर यह पूरा path बनाया जाना चाहिए, और दो values सेट करनी होंगी:

- `ImagePath`, जो execute होने वाले binary का path है
- `Type`, जिसका मान `SERVICE_KERNEL_DRIVER` (`0x00000001`) होना चाहिए।

Steps to Follow:

1. write access प्रतिबंध के कारण `HKLM` की बजाय `HKCU` का उपयोग करें।
2. `HKCU` में `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path बनाएं, जहाँ `<RID>` current user का Relative Identifier है।
3. `ImagePath` को binary के execution path पर सेट करें।
4. `Type` को `SERVICE_KERNEL_DRIVER` (`0x00000001`) के रूप में असाइन करें।
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
More ways to abuse this privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

यह **SeRestorePrivilege** के समान है। इसका मुख्य कार्य एक process को **assume ownership of an object** की अनुमति देना है, जिससे WRITE_OWNER access rights प्रदान करके explicit discretionary access की आवश्यकता दरकिनार हो जाती है। इस प्रक्रिया में पहले लिखने के उद्देश्य से लक्षित registry key का ownership हासिल करना शामिल है, और फिर write operations सक्षम करने के लिए DACL को संशोधित करना होता है।
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

यह privilege आपको **debug other processes** की अनुमति देता है, जिसमें मेमोरी को पढ़ना और लिखना शामिल है। इस privilege का उपयोग करके कई memory injection रणनीतियाँ लागू की जा सकती हैं, जो अधिकांश antivirus और host intrusion prevention solutions से बच सकती हैं।

#### Dump memory

आप [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) का उपयोग [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) से करके किसी प्रक्रिया की मेमोरी को **capture the memory of a process** कर सकते हैं। विशेष रूप से, यह **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process पर लागू हो सकता है, जो सिस्टम में सफलतापूर्वक लॉगिन करने के बाद user credentials को संग्रहीत करने के लिए जिम्मेदार है।

आप फिर इस डम्प को mimikatz में लोड करके पासवर्ड प्राप्त कर सकते हैं:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

यदि आप `NT SYSTEM` शेल प्राप्त करना चाहते हैं तो आप इनका उपयोग कर सकते हैं:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

यह अधिकार (Perform volume maintenance tasks) रॉ वॉल्यूम डिवाइस हैंडल (उदा., \\.\C:) खोलने की अनुमति देता है ताकि NTFS ACLs को बायपास करते हुए direct disk I/O किया जा सके। इसके माध्यम से आप वॉल्यूम पर किसी भी फ़ाइल के अंतर्निहित ब्लॉक्स को पढ़कर उसके बाइट्स कॉपी कर सकते हैं, जिससे संवेदनशील सामग्री की arbitrary file read संभव हो जाती है (उदा., machine private keys in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS)। यह विशेष रूप से CA servers पर प्रभावशाली है जहाँ exfiltrating the CA private key करके Golden Certificate फोर्ज कर किसी भी principal का impersonate किया जा सकता है।

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## विशेषाधिकार जाँचें
```
whoami /priv
```
वे **tokens जो Disabled के रूप में दिखाई देते हैं** सक्षम किए जा सकते हैं; आप वास्तव में _Enabled_ और _Disabled_ tokens का दुरुपयोग कर सकते हैं।

### सभी tokens को सक्षम करें

यदि आपके पास tokens disabled हैं, तो आप इस script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) का उपयोग करके सभी tokens को सक्षम कर सकते हैं:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## तालिका

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), नीचे का सारांश केवल सीधे तरीकों को सूचीबद्ध करेगा जिनसे privilege का दुरुपयोग कर admin session प्राप्त किया जा सके या संवेदनशील फाइलें पढ़ी जा सकें।

| Privilege                  | प्रभाव      | उपकरण                    | Execution path                                                                                                                                                                                                                                                                                                                                     | टिप्पणियाँ                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. मैं इसे जल्द ही किसी अधिक नुस्खा-जैसे अंदाज में फिर से लिखने की कोशिश करूँगा।                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` के साथ संवेदनशील फाइलें पढ़ें।                                                                                                                                                                                                                                                                                                      | <p>- यह और अधिक रोचक हो सकता है यदि आप %WINDIR%\MEMORY.DMP पढ़ सकें।<br><br>- <code>SeBackupPrivilege</code> (और robocopy) खुले फाइलों के मामले में मददगार नहीं है।<br><br>- Robocopy को /b पैरामीटर के साथ काम करने के लिए दोनों SeBackup और SeRestore की आवश्यकता होती है।</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` के साथ local admin rights सहित arbitrary token बनाएं।                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe` token की नकल करें।                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. szkg64.sys जैसे buggy kernel driver लोड करें<br>2. ड्राइवर vulnerability का exploit करें<br><br>वैकल्पिक रूप से, यह privilege security-related drivers को unload करने के लिए <code>ftlMC</code> builtin command के साथ उपयोग किया जा सकता है। यथा: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code> vulnerability को <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> के रूप में सूचीबद्ध किया गया है।<br>2. <code>szkg64</code> का <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> <a href="https://twitter.com/parvezghh">Parvez Anwar</a> द्वारा बनाया गया था।</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege के साथ PowerShell/ISE लॉन्च करें।<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> से privilege सक्षम करें।<br>3. utilman.exe को utilman.old में नाम बदलें<br>4. cmd.exe को utilman.exe नाम दें<br>5. कंसोल लॉक करें और Win+U दबाएँ</p> | <p>कुछ AV सॉफ़्टवेयर इस हमले का पता लगा सकते हैं।</p><p>वैकल्पिक तरीका समान privilege का उपयोग करके "Program Files" में स्थित service binaries को प्रतिस्थापित करने पर निर्भर करता है</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe का नाम बदलकर utilman.exe करें<br>4. कंसोल लॉक करें और Win+U दबाएँ</p>                                                                                                                                       | <p>कुछ AV सॉफ़्टवेयर इस हमले का पता लगा सकते हैं।</p><p>वैकल्पिक तरीका समान privilege का उपयोग करके "Program Files" में स्थित service binaries को प्रतिस्थापित करने पर निर्भर करता है।</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>tokens को manipulate करके local admin rights शामिल करें। May require SeImpersonate.</p><p>सत्यापित किया जाना बाकी है।</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## संदर्भ

- Windows tokens को परिभाषित करने वाली इस तालिका को देखें: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- privesc with tokens के बारे में जानकारी के लिए [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) देखें।
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
