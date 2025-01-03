# Tokens का दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

## Tokens

यदि आप **Windows Access Tokens क्या हैं** नहीं जानते हैं, तो आगे बढ़ने से पहले इस पृष्ठ को पढ़ें:

{{#ref}}
../access-tokens.md
{{#endref}}

**शायद आप पहले से मौजूद टोकनों का दुरुपयोग करके विशेषाधिकार बढ़ाने में सक्षम हो सकते हैं**

### SeImpersonatePrivilege

यह विशेषाधिकार किसी भी प्रक्रिया द्वारा धारण किया जाता है जो किसी भी टोकन का अनुकरण (लेकिन निर्माण नहीं) करने की अनुमति देता है, बशर्ते कि इसके लिए एक हैंडल प्राप्त किया जा सके। एक विशेषाधिकार प्राप्त टोकन को Windows सेवा (DCOM) से NTLM प्रमाणीकरण को एक शोषण के खिलाफ प्रेरित करके प्राप्त किया जा सकता है, जिससे SYSTEM विशेषाधिकार के साथ एक प्रक्रिया के निष्पादन की अनुमति मिलती है। इस भेद्यता का शोषण विभिन्न उपकरणों का उपयोग करके किया जा सकता है, जैसे [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (जिसके लिए winrm को निष्क्रिय करना आवश्यक है), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) और [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
../roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
../juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

यह **SeImpersonatePrivilege** के समान है, यह एक विशेषाधिकार प्राप्त टोकन प्राप्त करने के लिए **समान विधि** का उपयोग करेगा।\
फिर, यह विशेषाधिकार **एक नए/निलंबित प्रक्रिया** को एक प्राथमिक टोकन असाइन करने की अनुमति देता है। विशेषाधिकार प्राप्त अनुकरण टोकन के साथ आप एक प्राथमिक टोकन (DuplicateTokenEx) उत्पन्न कर सकते हैं।\
इस टोकन के साथ, आप 'CreateProcessAsUser' के साथ एक **नई प्रक्रिया** बना सकते हैं या एक प्रक्रिया को निलंबित कर सकते हैं और **टोकन सेट कर सकते हैं** (सामान्यतः, आप एक चल रही प्रक्रिया के प्राथमिक टोकन को संशोधित नहीं कर सकते)।

### SeTcbPrivilege

यदि आपने इस टोकन को सक्षम किया है, तो आप **KERB_S4U_LOGON** का उपयोग करके किसी अन्य उपयोगकर्ता के लिए **अनुकरण टोकन** प्राप्त कर सकते हैं बिना क्रेडेंशियल्स को जाने, **टोकन में एक मनमाना समूह** (admins) जोड़ सकते हैं, टोकन के **अखंडता स्तर** को "**मध्यम**" पर सेट कर सकते हैं, और इस टोकन को **वर्तमान थ्रेड** पर असाइन कर सकते हैं (SetThreadToken)।

### SeBackupPrivilege

यह विशेषाधिकार किसी भी फ़ाइल (पढ़ने के संचालन तक सीमित) के लिए **सभी पढ़ने की पहुंच** नियंत्रण प्रदान करता है। इसका उपयोग **स्थानीय व्यवस्थापक** खातों के पासवर्ड हैश को रजिस्ट्री से पढ़ने के लिए किया जाता है, जिसके बाद, "**psexec**" या "**wmiexec**" जैसे उपकरणों का उपयोग हैश के साथ किया जा सकता है (Pass-the-Hash तकनीक)। हालाँकि, यह तकनीक दो स्थितियों में विफल होती है: जब स्थानीय व्यवस्थापक खाता निष्क्रिय होता है, या जब एक नीति लागू होती है जो दूरस्थ रूप से कनेक्ट करने वाले स्थानीय व्यवस्थापकों से प्रशासनिक अधिकार हटा देती है।\
आप इस विशेषाधिकार का **दुरुपयोग** कर सकते हैं:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- **IppSec** का पालन करते हुए [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- या जैसा कि समझाया गया है **बैकअप ऑपरेटरों के साथ विशेषाधिकार बढ़ाने** के अनुभाग में:

{{#ref}}
../../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

किसी भी सिस्टम फ़ाइल के लिए **लेखन पहुंच** की अनुमति इस विशेषाधिकार द्वारा प्रदान की जाती है, चाहे फ़ाइल की एक्सेस कंट्रोल लिस्ट (ACL) कुछ भी हो। यह कई संभावनाओं को खोलता है, जिसमें **सेवाओं को संशोधित करना**, DLL Hijacking करना, और विभिन्न अन्य तकनीकों के बीच इमेज फ़ाइल निष्पादन विकल्पों के माध्यम से **डीबगर्स** सेट करना शामिल है।

### SeCreateTokenPrivilege

SeCreateTokenPrivilege एक शक्तिशाली अनुमति है, विशेष रूप से तब उपयोगी होती है जब एक उपयोगकर्ता के पास टोकनों का अनुकरण करने की क्षमता होती है, लेकिन SeImpersonatePrivilege की अनुपस्थिति में भी। यह क्षमता उस टोकन के अनुकरण की क्षमता पर निर्भर करती है जो उसी उपयोगकर्ता का प्रतिनिधित्व करता है और जिसका अखंडता स्तर वर्तमान प्रक्रिया के स्तर से अधिक नहीं होता है।

**मुख्य बिंदु:**

- **SeImpersonatePrivilege के बिना अनुकरण:** विशेष परिस्थितियों में टोकनों का अनुकरण करने के लिए SeCreateTokenPrivilege का उपयोग करके EoP प्राप्त करना संभव है।
- **टोकन अनुकरण के लिए शर्तें:** सफल अनुकरण के लिए लक्षित टोकन को उसी उपयोगकर्ता का होना चाहिए और इसका अखंडता स्तर उस प्रक्रिया के अखंडता स्तर के बराबर या कम होना चाहिए जो अनुकरण करने का प्रयास कर रही है।
- **अनुकरण टोकनों का निर्माण और संशोधन:** उपयोगकर्ता एक अनुकरण टोकन बना सकते हैं और इसे एक विशेषाधिकार प्राप्त समूह के SID (सुरक्षा पहचानकर्ता) को जोड़कर बढ़ा सकते हैं।

### SeLoadDriverPrivilege

यह विशेषाधिकार **डिवाइस ड्राइवरों को लोड और अनलोड** करने की अनुमति देता है, जिसमें `ImagePath` और `Type` के लिए विशिष्ट मानों के साथ एक रजिस्ट्री प्रविष्टि का निर्माण शामिल है। चूंकि `HKLM` (HKEY_LOCAL_MACHINE) पर सीधे लिखने की पहुंच प्रतिबंधित है, इसलिए `HKCU` (HKEY_CURRENT_USER) का उपयोग किया जाना चाहिए। हालाँकि, ड्राइवर कॉन्फ़िगरेशन के लिए `HKCU` को कर्नेल के लिए पहचानने योग्य बनाने के लिए एक विशिष्ट पथ का पालन करना आवश्यक है।

यह पथ `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` है, जहाँ `<RID>` वर्तमान उपयोगकर्ता का सापेक्ष पहचानकर्ता है। `HKCU` के भीतर, इस पूरे पथ का निर्माण किया जाना चाहिए, और दो मान सेट करने की आवश्यकता है:

- `ImagePath`, जो निष्पादित होने वाले बाइनरी का पथ है
- `Type`, जिसका मान `SERVICE_KERNEL_DRIVER` (`0x00000001`) है।

**अनुसरण करने के चरण:**

1. प्रतिबंधित लेखन पहुंच के कारण `HKLM` के बजाय `HKCU` तक पहुंचें।
2. `HKCU` के भीतर `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` पथ बनाएं, जहाँ `<RID>` वर्तमान उपयोगकर्ता का सापेक्ष पहचानकर्ता है।
3. `ImagePath` को बाइनरी के निष्पादन पथ पर सेट करें।
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
अधिक तरीके इस विशेषाधिकार का दुरुपयोग करने के लिए [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

यह **SeRestorePrivilege** के समान है। इसका मुख्य कार्य एक प्रक्रिया को **एक वस्तु का स्वामित्व ग्रहण करने** की अनुमति देना है, जो WRITE_OWNER पहुँच अधिकारों के प्रावधान के माध्यम से स्पष्ट विवेकाधीन पहुँच की आवश्यकता को दरकिनार करता है। प्रक्रिया में पहले लिखने के उद्देश्यों के लिए इच्छित रजिस्ट्री कुंजी का स्वामित्व सुरक्षित करना शामिल है, फिर लिखने के संचालन को सक्षम करने के लिए DACL को बदलना शामिल है।
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

यह विशेषाधिकार **अन्य प्रक्रियाओं को डिबग करने** की अनुमति देता है, जिसमें मेमोरी में पढ़ने और लिखने की क्षमता शामिल है। मेमोरी इंजेक्शन के लिए विभिन्न रणनीतियाँ, जो अधिकांश एंटीवायरस और होस्ट घुसपैठ रोकथाम समाधानों को चकमा देने में सक्षम हैं, इस विशेषाधिकार के साथ लागू की जा सकती हैं।

#### Dump memory

आप [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) का उपयोग कर सकते हैं [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) से **एक प्रक्रिया की मेमोरी कैप्चर करने** के लिए। विशेष रूप से, यह **स्थानीय सुरक्षा प्राधिकरण उपप्रणाली सेवा ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** प्रक्रिया पर लागू हो सकता है, जो एक उपयोगकर्ता के सफलतापूर्वक सिस्टम में लॉग इन करने के बाद उपयोगकर्ता क्रेडेंशियल्स को संग्रहीत करने के लिए जिम्मेदार है।

आप फिर इस डंप को mimikatz में लोड कर सकते हैं ताकि पासवर्ड प्राप्त कर सकें:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

यदि आप `NT SYSTEM` शेल प्राप्त करना चाहते हैं, तो आप उपयोग कर सकते हैं:

- \***\*[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)\*\***
- \***\*[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)\*\***
- \***\*[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)\*\***
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

`SeManageVolumePrivilege` एक Windows उपयोगकर्ता अधिकार है जो उपयोगकर्ताओं को डिस्क वॉल्यूम प्रबंधित करने की अनुमति देता है, जिसमें उन्हें बनाना और हटाना शामिल है। जबकि यह प्रशासकों के लिए निर्धारित है, यदि इसे गैर-प्रशासक उपयोगकर्ताओं को दिया जाता है, तो इसका उपयोग विशेषाधिकार वृद्धि के लिए किया जा सकता है।

इस विशेषाधिकार का उपयोग वॉल्यूम को हेरफेर करने के लिए किया जा सकता है, जिससे पूर्ण वॉल्यूम पहुंच प्राप्त होती है। [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) का उपयोग सभी उपयोगकर्ताओं को C:\ के लिए पूर्ण पहुंच देने के लिए किया जा सकता है।

इसके अतिरिक्त, [इस Medium लेख](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) में वर्णित प्रक्रिया `SeManageVolumePrivilege` के साथ DLL हाइजैकिंग का उपयोग करके विशेषाधिकार बढ़ाने का वर्णन करती है। एक पेलोड DLL `C:\Windows\System32\wbem\tzres.dll` रखकर और `systeminfo` को कॉल करके DLL निष्पादित होती है।

## Check privileges
```
whoami /priv
```
**जो टोकन Disabled के रूप में दिखाई देते हैं** उन्हें सक्षम किया जा सकता है, आप वास्तव में _Enabled_ और _Disabled_ टोकनों का दुरुपयोग कर सकते हैं।

### सभी टोकनों को सक्षम करें

यदि आपके पास टोकन निष्क्रिय हैं, तो आप सभी टोकनों को सक्षम करने के लिए स्क्रिप्ट [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) का उपयोग कर सकते हैं:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
या **स्क्रिप्ट** को इस [**पोस्ट**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) में एम्बेड किया गया है।

## तालिका

पूर्ण टोकन विशेषाधिकार चीटशीट [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) पर है, नीचे का सारांश केवल सीधे तरीकों को सूचीबद्ध करेगा जो विशेषाधिकार का शोषण करके एक व्यवस्थापक सत्र प्राप्त करने या संवेदनशील फ़ाइलों को पढ़ने के लिए हैं।

| विशेषाधिकार                  | प्रभाव      | उपकरण                    | निष्पादन पथ                                                                                                                                                                                                                                                                                                                                     | टिप्पणियाँ                                                                                                                                                                                                                                                                                                                        |
| ---------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`**   | _**व्यवस्थापक**_ | 3rd party tool          | _"यह एक उपयोगकर्ता को टोकन का अनुकरण करने और potato.exe, rottenpotato.exe और juicypotato.exe जैसे उपकरणों का उपयोग करके nt सिस्टम में प्रिवेस्क करने की अनुमति देगा"_                                                                                                                                                                      | धन्यवाद [Aurélien Chalot](https://twitter.com/Defte_) के लिए अपडेट के लिए। मैं इसे जल्द ही कुछ अधिक नुस्खा जैसा पुनः शब्दबद्ध करने की कोशिश करूंगा।                                                                                                                                                                         |
| **`SeBackup`**               | **खतरा**  | _**निर्मित आदेश**_      | `robocopy /b` के साथ संवेदनशील फ़ाइलें पढ़ें                                                                                                                                                                                                                                                                                                             | <p>- यदि आप %WINDIR%\MEMORY.DMP पढ़ सकते हैं तो यह अधिक दिलचस्प हो सकता है<br><br>- <code>SeBackupPrivilege</code> (और robocopy) खुली फ़ाइलों के मामले में सहायक नहीं है।<br><br>- Robocopy को /b पैरामीटर के साथ काम करने के लिए SeBackup और SeRestore दोनों की आवश्यकता होती है।</p>                                                                      |
| **`SeCreateToken`**          | _**व्यवस्थापक**_ | 3rd party tool          | `NtCreateToken` के साथ स्थानीय व्यवस्थापक अधिकारों सहित मनमाने टोकन बनाएं।                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**                | _**व्यवस्थापक**_ | **PowerShell**          | `lsass.exe` टोकन को डुप्लिकेट करें।                                                                                                                                                                                                                                                                                                                   | स्क्रिप्ट [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) पर मिलेगी                                                                                                                                                                                                         |
| **`SeLoadDriver`**           | _**व्यवस्थापक**_ | 3rd party tool          | <p>1. <code>szkg64.sys</code> जैसे बग्गी कर्नेल ड्राइवर को लोड करें<br>2. ड्राइवर की भेद्यता का शोषण करें<br><br>वैकल्पिक रूप से, विशेषाधिकार का उपयोग सुरक्षा से संबंधित ड्राइवरों को अनलोड करने के लिए <code>ftlMC</code> निर्मित आदेश का उपयोग कर सकते हैं। जैसे: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code> भेद्यता को <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> के रूप में सूचीबद्ध किया गया है<br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">शोषण कोड</a> को <a href="https://twitter.com/parvezghh">Parvez Anwar</a> द्वारा बनाया गया था</p> |
| **`SeRestore`**              | _**व्यवस्थापक**_ | **PowerShell**          | <p>1. SeRestore विशेषाधिकार के साथ PowerShell/ISE लॉन्च करें।<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> के साथ विशेषाधिकार सक्षम करें।<br>3. utilman.exe का नाम बदलकर utilman.old करें<br>4. cmd.exe का नाम बदलकर utilman.exe करें<br>5. कंसोल को लॉक करें और Win+U दबाएं</p> | <p>हमला कुछ AV सॉफ़्टवेयर द्वारा पता लगाया जा सकता है।</p><p>वैकल्पिक विधि उसी विशेषाधिकार का उपयोग करके "Program Files" में संग्रहीत सेवा बाइनरी को प्रतिस्थापित करने पर निर्भर करती है</p>                                                                                                                                                            |
| **`SeTakeOwnership`**        | _**व्यवस्थापक**_ | _**निर्मित आदेश**_      | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe का नाम बदलकर utilman.exe करें<br>4. कंसोल को लॉक करें और Win+U दबाएं</p>                                                                                                                                       | <p>हमला कुछ AV सॉफ़्टवेयर द्वारा पता लगाया जा सकता है।</p><p>वैकल्पिक विधि उसी विशेषाधिकार का उपयोग करके "Program Files" में संग्रहीत सेवा बाइनरी को प्रतिस्थापित करने पर निर्भर करती है।</p>                                                                                                                                                           |
| **`SeTcb`**                  | _**व्यवस्थापक**_ | 3rd party tool          | <p>टोकनों को इस तरह से हेरफेर करें कि स्थानीय व्यवस्थापक अधिकार शामिल हों। SeImpersonate की आवश्यकता हो सकती है।<br><p>पुष्टि की जानी है।</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## संदर्भ

- Windows टोकनों को परिभाषित करने वाली इस तालिका पर एक नज़र डालें: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- टोकनों के साथ प्रिवेस्क के बारे में [**इस पेपर**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) पर एक नज़र डालें।

{{#include ../../../banners/hacktricks-training.md}}
