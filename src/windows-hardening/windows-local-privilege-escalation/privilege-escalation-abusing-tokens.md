# टोकन का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

## टोकन

यदि आप **नहीं जानते कि Windows Access Tokens क्या हैं** तो आगे बढ़ने से पहले इस पृष्ठ को पढ़ें:


{{#ref}}
access-tokens.md
{{#endref}}

**शायद आप जिन टोकनों के मालिक हैं उनका दुरुपयोग करके escalate privileges कर सकते हैं**

### SeImpersonatePrivilege

यह वह privilege है जो किसी भी process के पास हो सकता है और यह किसी भी token का impersonation (लेकिन creation नहीं) करने की अनुमति देता है, बशर्ते उस token का handle प्राप्त किया जा सके। एक privileged token को Windows service (DCOM) से प्राप्त किया जा सकता है, उसे किसी exploit के खिलाफ NTLM authentication करने के लिए प्रेरित करके, जिससे SYSTEM privileges के साथ किसी process का execution संभव हो जाता है। इस vulnerability का उपयोग कई tools से किया जा सकता है, जैसे [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (जिसके लिए winrm को disabled होना चाहिए), [SweetPotato](https://github.com/CCob/SweetPotato), और [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

यह **SeImpersonatePrivilege** के बहुत समान है, यह privileged token पाने के लिए **वही method** उपयोग करेगा।\
फिर, यह privilege एक नए/सस्पेंड किए गए process को **primary token असाइन** करने की अनुमति देता है। privileged impersonation token से आप एक primary token derive कर सकते हैं (DuplicateTokenEx).\
इस token के साथ, आप 'CreateProcessAsUser' से एक **new process** बना सकते हैं या किसी process को suspended बनाकर **set the token** कर सकते हैं (आम तौर पर आप चल रहे process के primary token को संशोधित नहीं कर सकते)।

### SeTcbPrivilege

यदि आपके पास यह privilege enabled है तो आप **KERB_S4U_LOGON** का उपयोग करके किसी भी अन्य user के लिए credentials जाने बिना एक **impersonation token** प्राप्त कर सकते हैं, token में कोई भी group (admins) जोड़ सकते हैं, token का **integrity level** "**medium**" सेट कर सकते हैं, और इस token को **current thread** को असाइन कर सकते हैं (SetThreadToken)।

### SeBackupPrivilege

यह privilege किसी भी फ़ाइल के लिए (केवल read operations तक सीमित) सिस्टम को **सभी read access** प्रदान करने का कारण बनता है। इसका उपयोग registry से स्थानीय Administrator खातों के password hashes पढ़ने के लिए किया जाता है, जिसके बाद hash के साथ "psexec" या "wmiexec" जैसे tools का उपयोग किया जा सकता है (Pass-the-Hash technique)। हालांकि, यह तरीका दो स्थितियों में विफल होता है: जब Local Administrator account disabled हो, या जब कोई policy लागू हो जो remote कनेक्शन पर Local Administrators से administrative rights हटा देती हो।\
आप इस privilege का **दुरुपयोग (abuse)** निम्नलिखित से कर सकते हैं:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

यह privilege किसी भी system फ़ाइल में उसके Access Control List (ACL) की परवाह किए बिना **write access** की अनुमति देता है। यह escalation के कई अवसर खोलता है, जैसे कि **services को modify करना**, DLL Hijacking करना, और Image File Execution Options के माध्यम से **debuggers** सेट करना, आदि।

### SeCreateTokenPrivilege

SeCreateTokenPrivilege एक शक्तिशाली permission है, खासकर तब उपयोगी जब किसी user के पास tokens impersonate करने की क्षमता हो, लेकिन यह SeImpersonatePrivilege के बिना भी उपयोगी हो सकता है। यह क्षमता इस बात पर निर्भर करती है कि आप उस token का impersonate कर सकें जो उसी user का हो और जिसका integrity level वर्तमान process के integrity level से अधिक न हो।

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** कुछ विशिष्ट शर्तों के तहत tokens को impersonate करके SeCreateTokenPrivilege का उपयोग EoP (Elevation of Privilege) के लिए किया जा सकता है।
- **Conditions for Token Impersonation:** सफल impersonation के लिए लक्ष्य token उसी user का होना चाहिए और उसका integrity level impersonation करने वाले process के integrity level से कम या बराबर होना चाहिए।
- **Creation and Modification of Impersonation Tokens:** उपयोगकर्ता एक impersonation token बना सकते हैं और उसमें privileged group's SID (Security Identifier) जोड़कर उसे उन्नत कर सकते हैं।

### SeLoadDriverPrivilege

यह privilege `ImagePath` और `Type` के विशेष मानों के साथ एक registry entry बनाकर device drivers को **load और unload** करने की अनुमति देता है। चूँकि `HKLM` (HKEY_LOCAL_MACHINE) में सीधे लिखने की अनुमति सीमित है, इसलिए इसके स्थान पर `HKCU` (HKEY_CURRENT_USER) का उपयोग करना होगा। हालाँकि, kernel को ड्राइवर कॉन्फ़िगरेशन के लिए `HKCU` पहचानने योग्य बनाने के लिए एक विशिष्ट path का पालन करना ज़रूरी है।

यह path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` है, जहाँ `<RID>` वर्तमान user का Relative Identifier है। `HKCU` के अंदर यह पूरा path बनाना होगा, और दो मान सेट करने होंगे:

- `ImagePath`, जो उस binary का path है जिसे execute किया जाएगा
- `Type`, जिसका मान `SERVICE_KERNEL_DRIVER` (`0x00000001`) होना चाहिए।

**Steps to Follow:**

1. write access सीमित होने के कारण `HKCU` का उपयोग करें, `HKLM` की जगह।
2. `HKCU` के भीतर `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path बनाएं, जहाँ `<RID>` वर्तमान user का Relative Identifier है।
3. `ImagePath` को उस binary के execution path पर सेट करें।
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

यह **SeRestorePrivilege** के समान है। इसका प्राथमिक कार्य किसी process को **ऑब्जेक्ट का मालिकाना हक़ संभालना** अनुमति देना है, जिससे WRITE_OWNER access rights प्रदान करके explicit discretionary access की आवश्यकता को दरकिनार किया जा सकता है। इस प्रक्रिया में पहले लेखन के उद्देश्य से लक्षित रजिस्ट्री कुंजी की ownership सुरक्षित करना और फिर write operations सक्षम करने के लिए DACL को संशोधित करना शामिल है।
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

यह विशेषाधिकार **debug other processes** की अनुमति देता है, जिसमें मेमोरी में पढ़ना और लिखना शामिल है। इस विशेषाधिकार के साथ विभिन्न memory injection रणनीतियाँ लागू की जा सकती हैं, जो अधिकांश antivirus और host intrusion prevention solutions से बच सकती हैं।

#### मेमोरी डंप

आप [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) का उपयोग [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) से किसी प्रोसेस की मेमोरी **capture the memory of a process** करने के लिए कर सकते हैं। विशेष रूप से, यह **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** प्रोसेस पर लागू हो सकता है, जो किसी उपयोगकर्ता के सफलतापूर्वक सिस्टम में लॉग इन करने के बाद उपयोगकर्ता क्रेडेंशियल्स को स्टोर करने के लिए जिम्मेदार है।

फिर आप इस डंप को mimikatz में लोड करके पासवर्ड प्राप्त कर सकते हैं:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

यदि आप `NT SYSTEM` shell प्राप्त करना चाहते हैं तो आप उपयोग कर सकते हैं:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

यह अधिकार (Perform volume maintenance tasks) कच्चे वॉल्यूम डिवाइस हैंडल्स (e.g., \\.\C:) खोलने की अनुमति देता है ताकि direct disk I/O किया जा सके जो NTFS ACLs को बायपास करता है। इसके माध्यम से आप underlying blocks पढ़कर वॉल्यूम पर किसी भी फ़ाइल के बाइट कॉपी कर सकते हैं, जिससे संवेदनशील सामग्री की arbitrary file read संभव हो जाती है (e.g., machine private keys in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS)। यह CA सर्वरों पर विशेष रूप से प्रभावशाली है, जहाँ exfiltrating the CA private key करके Golden Certificate बनाकर किसी भी principal का impersonate करना संभव हो जाता है।

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## अनुमतियाँ जाँचें
```
whoami /priv
```
वे **tokens जो Disabled के रूप में दिखाई देते हैं** सक्षम किए जा सकते हैं; आप वास्तव में _Enabled_ और _Disabled_ tokens का दुरुपयोग कर सकते हैं।

### सभी tokens सक्षम करें

यदि आपके पास कुछ tokens Disabled हैं, तो आप स्क्रिप्ट [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) का उपयोग करके सभी tokens सक्षम कर सकते हैं:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
या इस [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) में एम्बेड किया गया **script**।

## तालिका

पूर्ण टोकन विशेषाधिकार चीटशीट: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)। नीचे का सारांश केवल उन सीधे तरीकों को सूचीबद्ध करेगा जिनसे विशेषाधिकार का दुरुपयोग करके admin session प्राप्त किया जा सकता है या संवेदनशील फ़ाइलें पढ़ी जा सकती हैं।

| Privilege                  | प्रभाव      | उपकरण                    | कार्यान्वयन मार्ग                                                                                                                                                                                                                                                                                                                                     | टिप्पणियाँ                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"यह उपयोगकर्ता को tokens की नक्कल करने और potato.exe, rottenpotato.exe और juicypotato.exe जैसे टूल्स का उपयोग करके nt system पर privesc करने की अनुमति देगा"_                                                                                                                                                                                                      | धन्यवाद [Aurélien Chalot](https://twitter.com/Defte_) अपडेट के लिए। मैं इसे जल्द ही थोड़े अधिक नुस्खे-जैसा रूप देने की कोशिश करूंगा।                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | संवेदनशील फ़ाइलें पढ़ने के लिए `robocopy /b` का उपयोग करें।                                                                                                                                                                                                                                                                                                             | <p>- यदि आप %WINDIR%\MEMORY.DMP पढ़ सकते हैं तो यह और भी अधिक उपयोगी हो सकता है।<br><br>- <code>SeBackupPrivilege</code> (और robocopy) खुले फ़ाइलों के मामले में मददगार नहीं है।<br><br>- Robocopy को /b पैरामीटर के साथ काम करने के लिए दोनों SeBackup और SeRestore की आवश्यकता होती है।</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` के साथ लोकल admin अधिकारों सहित मनमाना टोकन बनाएं।                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe` टोकन की नकल करें।                                                                                                                                                                                                                                                                                                                   | स्क्रिप्ट [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) पर मिल सकती है।                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. `szkg64.sys` जैसे buggy kernel driver को लोड करें।<br>2. ड्राइवर की vulnerability का उपयोग करके exploit करें।<br><br>वैकल्पिक रूप से, यह विशेषाधिकार security-related ड्राइवर्स को unload करने के लिए <code>ftlMC</code> builtin कमांड के साथ भी इस्तेमाल किया जा सकता है। उदाहरण: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. `szkg64` vulnerability को <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> में सूचीबद्ध किया गया है।<br>2. `szkg64` <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> को <a href="https://twitter.com/parvezghh">Parvez Anwar</a> ने बनाया था।</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege मौजूद रहते हुए PowerShell/ISE लॉन्च करें।<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> के साथ विशेषाधिकार सक्षम करें।<br>3. utilman.exe का नाम बदलकर utilman.old रखें।<br>4. cmd.exe का नाम बदलकर utilman.exe रखें।<br>5. कंसोल लॉक करें और Win+U दबाएँ।</p> | <p>कभी-कभी यह हमला कुछ AV सॉफ़्टवेयर द्वारा पकड़ा जा सकता है।</p><p>वैकल्पिक तरीका वही विशेषाधिकार प्रयोग करके "Program Files" में संग्रहीत service binaries को बदलने पर निर्भर करता है।</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe का नाम बदलकर utilman.exe रखें।<br>4. कंसोल लॉक करें और Win+U दबाएँ।</p>                                                                                                                                       | <p>कभी-कभी यह हमला कुछ AV सॉफ़्टवेयर द्वारा पकड़ा जा सकता है।</p><p>वैकल्पिक तरीका उसी विशेषाधिकार का उपयोग करके "Program Files" में संग्रहीत service binaries को बदलने पर निर्भर करता है।</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>टोकन्स को इस तरह संशोधित करें कि उनमें लोकल admin अधिकार शामिल हों। इसके लिए SeImpersonate की आवश्यकता पड़ सकती है।</p><p>जांच बाकी है।</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## संदर्भ

- Windows tokens को परिभाषित करने वाली इस तालिका को देखें: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- टोकन के साथ privesc के बारे में [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) देखें।
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
