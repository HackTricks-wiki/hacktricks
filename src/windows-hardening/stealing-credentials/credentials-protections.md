# Windows क्रेडेंशियल सुरक्षा

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) प्रोटोकॉल, जो Windows XP में पेश किया गया था, HTTP Protocol के माध्यम से प्रमाणीकरण के लिए डिज़ाइन किया गया है और **Windows XP से लेकर Windows 8.0 तथा Windows Server 2003 से Windows Server 2012 तक डिफ़ॉल्ट रूप से सक्षम** है। यह डिफ़ॉल्ट सेटिंग **LSASS में plain-text पासवर्ड संग्रहीत** होने का परिणाम देती है (Local Security Authority Subsystem Service)। एक हमलावर Mimikatz का उपयोग करके **इन क्रेडेंशियल्स को निकाल** सकता है, निम्नलिखित कमांड चलाकर:
```bash
sekurlsa::wdigest
```
इस सुविधा को बंद या चालू करने के लिए, _**UseLogonCredential**_ और _**Negotiate**_ रजिस्ट्री कुंजियाँ _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ के भीतर "1" पर सेट होनी चाहिए। यदि ये कुंजियाँ **अनुपस्थित या "0" पर सेट** हैं, तो WDigest **अक्षम** है:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA सुरक्षा (PP & PPL संरक्षित प्रक्रियाएँ)

**Protected Process (PP)** और **Protected Process Light (PPL)** वे **Windows kernel-level protections** हैं जो **LSASS** जैसे संवेदनशील प्रक्रियाओं तक अनधिकृत पहुँच को रोकने के लिए बनाए गए हैं। इन्हें **Windows Vista** में पेश किया गया था; मूलतः **DRM** लागू करने के लिए बनाया गया था और केवल उन बाइनरीज़ को संरक्षित करने की अनुमति देता था जो एक **विशेष मीडिया प्रमाणपत्र (special media certificate)** से साइन किए गए हों। जिस प्रक्रिया पर **PP** चिह्नित होता है, उसे केवल अन्य ऐसी प्रक्रियाएँ एक्सेस कर सकती हैं जो **भी PP** हों और जिनका संरक्षण स्तर समान या उच्च हो, और तब भी **केवल सीमित एक्सेस अधिकारों** के साथ जब तक खास अनुमति न दी गई हो।

**PPL**, जिसे **Windows 8.1** में पेश किया गया था, PP का अधिक लचीला संस्करण है। यह **विस्तृत उपयोग मामलों** (उदा., LSASS, Defender) की अनुमति देता है, क्योंकि यह डिजिटल सिग्नेचर के **EKU (Enhanced Key Usage)** फ़ील्ड पर आधारित **"protection levels"** प्रस्तुत करता है। प्रोटेक्शन स्तर `EPROCESS.Protection` फ़ील्ड में संग्रहीत होता है, जो एक `PS_PROTECTION` संरचना है जिसमें:
- **Type** (`Protected` or `ProtectedLight`)
- **Signer** (उदा., `WinTcb`, `Lsa`, `Antimalware`, आदि)

यह संरचना एक ही बाइट में पैक होती है और यह निर्धारित करती है **कौन किसे एक्सेस कर सकता है**:
- **ऊँचे signer मान निचले signer को एक्सेस कर सकते हैं**
- **PPLs PPs को एक्सेस नहीं कर सकते**
- **Unprotected प्रक्रियाएँ किसी भी PPL/PP को एक्सेस नहीं कर सकतीं**

### Offensive दृष्टिकोण से आपको क्या जानना चाहिए

- जब **LSASS PPL** के रूप में चलता है, तो एक सामान्य admin context से `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` का उपयोग करके इसे खोलने का प्रयास `0x5 (Access Denied)` के साथ विफल हो जाता है, भले ही `SeDebugPrivilege` सक्षम हो।
- आप Process Hacker जैसे टूल्स का उपयोग करके या प्रोग्रामैटिकली `EPROCESS.Protection` मान पढ़कर LSASS का protection स्तर जांच सकते हैं।
- LSASS में आमतौर पर `PsProtectedSignerLsa-Light` (`0x41`) होता है, जिसे केवल उन प्रक्रियाओं द्वारा एक्सेस किया जा सकता है जो उच्च-स्तरीय signer, जैसे `WinTcb` (`0x61` या `0x62`), द्वारा साइन की गई हों।
- PPL केवल Userland-स्तर का प्रतिबंध है; kernel-level कोड इसे पूरी तरह बायपास कर सकता है।
- यदि आप kernel shellcode execute कर सकते हैं या उपयुक्त एक्सेस के साथ किसी high-privileged प्रक्रिया का उपयोग कर सकते हैं, तो LSASS का PPL होना credential dumping को रोक नहींता।
- PPL सेट/हटाने के लिए reboot या Secure Boot/UEFI सेटिंग्स की आवश्यकता होती है, जो रजिस्ट्री परिवर्तन उलट दिए जाने के बाद भी PPL सेटिंग को कायम रख सकती हैं।

### Create a PPL process at launch (documented API)

Windows documented तरीका प्रदान करता है जिससे आप child process के निर्माण के दौरान extended startup attribute list का उपयोग करके Protected Process Light स्तर का अनुरोध कर सकते हैं। यह signing requirements को बायपास नहीं करता — लक्ष्य image को requested signer class के लिए साइन किया गया होना चाहिए।

Minimal flow in C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
नोट्स और सीमाएँ:
- `STARTUPINFOEX` का उपयोग करें `InitializeProcThreadAttributeList` और `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)` के साथ, फिर `EXTENDED_STARTUPINFO_PRESENT` को `CreateProcess*` को पास करें।
- प्रोटेक्शन `DWORD` को उन कॉन्स्टेंट्स पर सेट किया जा सकता है जैसे `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, या `PROTECTION_LEVEL_LSA_LIGHT`।
- चाइल्ड केवल तभी PPL के रूप में शुरू होता है जब उसकी इमेज उस signer क्लास के लिए साइन की गई हो; अन्यथा process creation विफल हो जाती है, आम तौर पर `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)` के साथ।
- यह कोई bypass नहीं है — यह एक समर्थित API है जो उपयुक्त रूप से साइन किए गए इमेज के लिए है। यह टूल्स को harden करने या PPL-प्रोटेक्टेड कॉन्फ़िगरेशन को वैध करने के लिए उपयोगी है।

Example CLI using a minimal loader:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Bypass PPL protections options:**

यदि आप PPL के बावजूद LSASS को dump करना चाहते हैं, तो आपके पास मुख्य रूप से ये विकल्प हैं:
1. **साइन किए हुए कर्नेल ड्राइवर का उपयोग करें (उदा., Mimikatz + mimidrv.sys)** ताकि **LSASS का protection flag हटाया जा सके**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** लाकर कस्टम कर्नेल कोड चलाएँ और प्रोटेक्शन को निष्क्रिय करें। टूल्स जैसे **PPLKiller**, **gdrv-loader**, या **kdmapper** यह संभव बनाते हैं।
3. किसी ऐसे प्रोसेस से जो उसे ओपन किए हुए है (उदा., एक AV प्रोसेस), मौजूदा LSASS हैंडल को चुरा लें, फिर उसे अपने प्रोसेस में duplicate करें। यह `pypykatz live lsa --method handledup` तकनीक का आधार है।
4. किसी प्रिविलेज्ड प्रोसेस का दुरुपयोग करें जो आपको उसके address space में या किसी अन्य प्रिविलेज्ड प्रोसेस के अंदर arbitrary code लोड करने की अनुमति दे, जिससे प्रभावी रूप से PPL प्रतिबंधों को बाईपास किया जा सके। आप इसका उदाहरण [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) या [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) में देख सकते हैं।

**Check current status of LSA protection (PPL/PP) for LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- इस जांच के बारे में अधिक जानकारी के लिए [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, a feature exclusive to **Windows 10 (Enterprise and Education editions)**, मशीन क्रेडेंशियल्स की सुरक्षा को बढ़ाता है Virtual Secure Mode (VSM) और Virtualization Based Security (VBS) का उपयोग करके। यह CPU virtualization extensions का लाभ उठाकर मुख्य ऑपरेटिंग सिस्टम की पहुँच से दूर एक सुरक्षित मेमोरी स्पेस में महत्वपूर्ण प्रक्रियाओं को अलग करता है। यह अलगाव यह सुनिश्चित करता है कि kernel भी VSM में मेमोरी तक पहुँच नहीं पा सके, जिससे pass-the-hash जैसे हमलों से क्रेडेंशियल्स का प्रभावी रूप से संरक्षण होता है। Local Security Authority (LSA) इस सुरक्षित वातावरण के भीतर एक trustlet के रूप में चलती है, जबकि मुख्य OS में LSASS प्रक्रिया केवल VSM की LSA के साथ संवादकर्ता के रूप में कार्य करती है।

डिफ़ॉल्ट रूप से, **Credential Guard** सक्रिय नहीं होता और इसे संगठन के भीतर मैन्युअल रूप से सक्षम करना पड़ता है। यह Mimikatz जैसे टूल्स के खिलाफ सुरक्षा बढ़ाने के लिए महत्वपूर्ण है, क्योंकि ये क्रेडेंशियल्स निकालने में बाधित होते हैं। हालांकि, कस्टम Security Support Providers (SSP) जोड़कर लॉगिन प्रयासों के दौरान क्रेडेंशियल्स को clear text में कैप्चर करने के लिए कमजोरियों का अभी भी फायदा उठाया जा सकता है।

Credential Guard की सक्रियता स्थिति की जाँच के लिए रजिस्ट्री कुंजी _**LsaCfgFlags**_ _**HKLM\System\CurrentControlSet\Control\LSA**_ के अंतर्गत निरीक्षण की जा सकती है। यदि मान "**1**" है तो यह UEFI lock के साथ सक्रिय होने को दर्शाता है, "**2**" lock के बिना सक्रियता को दर्शाता है, और "**0**" दर्शाता है कि यह सक्षम नहीं है। यह रजिस्ट्री जाँच एक मजबूत संकेतक होते हुए भी Credential Guard सक्षम करने का एकमात्र कदम नहीं है। इस फीचर को सक्षम करने के लिए विस्तृत मार्गदर्शन और एक PowerShell स्क्रिप्ट ऑनलाइन उपलब्ध हैं।
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
For a comprehensive understanding and instructions on enabling **Credential Guard** in Windows 10 and its automatic activation in compatible systems of **Windows 11 Enterprise and Education (version 22H2)**, visit [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Further details on implementing custom SSPs for credential capture are provided in [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** ने कई नई सुरक्षा सुविधाएँ पेश कीं, जिनमें _**Restricted Admin mode for RDP**_ शामिल है। यह मोड [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) हमलों से संबंधित जोखिमों को कम करने के लिए डिज़ाइन किया गया था।

परंपरागत रूप से, RDP के माध्यम से किसी रिमोट कंप्यूटर से कनेक्ट करते समय आपकी credentials लक्ष्य मशीन पर संग्रहीत हो जाती हैं। यह विशेष रूप से उच्च privileges वाले खातों के उपयोग के समय एक महत्वपूर्ण सुरक्षा जोखिम पैदा करता है। हालांकि, _**Restricted Admin mode**_ के परिचय के साथ, यह जोखिम काफी हद तक कम हो जाता है।

जब आप कमांड **mstsc.exe /RestrictedAdmin** का उपयोग करके RDP कनेक्शन प्रारंभ करते हैं, तो remote computer पर authentication आपकी credentials को वहां संग्रहीत किए बिना किया जाता है। इस तरीके से यह सुनिश्चित होता है कि किसी malware संक्रमण या किसी malicious user के रिमोट सर्वर तक पहुँचने की स्थिति में आपकी credentials सुरक्षित रहती हैं, क्योंकि वे सर्वर पर संग्रहीत नहीं होतीं।

यह ध्यान रखना महत्वपूर्ण है कि **Restricted Admin mode** में RDP सेशन से नेटवर्क संसाधनों तक पहुँचने के प्रयास आपके व्यक्तिगत credentials का उपयोग नहीं करेंगे; इसके बजाय **machine's identity** का उपयोग किया जाएगा।

यह फीचर रिमोट डेस्कटॉप कनेक्शनों को सुरक्षित करने और सुरक्षा उल्लंघन की स्थिति में संवेदनशील जानकारी के उजागर होने से बचाने में एक महत्वपूर्ण कदम है।

![](../../images/RAM.png)

For more detailed information on visit [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows अपने **domain credentials** को **Local Security Authority (LSA)** के माध्यम से सुरक्षित रखता है, और logon प्रक्रियाओं के लिए **Kerberos** और **NTLM** जैसे security protocols का समर्थन करता है। Windows की एक प्रमुख विशेषता यह है कि यह **last ten domain logins** को cache कर सकता है ताकि यूज़र अपने कंप्यूटरों तक तब भी पहुँच सकें जब **domain controller** offline हो—यह खासकर उन laptop उपयोगकर्ताओं के लिए लाभकारी है जो अक्सर अपने कंपनी के नेटवर्क से दूर रहते हैं।

Cached logins की संख्या को एक विशिष्ट **registry key or group policy** के माध्यम से समायोजित किया जा सकता है। इस सेटिंग को देखने या बदलने के लिए निम्नलिखित command का उपयोग किया जाता है:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.

## Protected Users

Membership in the **Protected Users group** introduces several security enhancements for users, ensuring higher levels of protection against credential theft and misuse:

- **Credential Delegation (CredSSP)**: भले ही Group Policy setting **Allow delegating default credentials** सक्षम हो, Protected Users के plain text credentials कैश नहीं होंगे।
- **Windows Digest**: **Windows 8.1 and Windows Server 2012 R2** से शुरू होकर, सिस्टम Protected Users के plain text credentials को कैश नहीं करेगा, चाहे Windows Digest की स्थिति कुछ भी हो।
- **NTLM**: सिस्टम Protected Users के plain text credentials या NT one-way functions (NTOWF) को कैश नहीं करेगा।
- **Kerberos**: Protected Users के लिए, Kerberos authentication **DES** या **RC4 keys** जेनरेट नहीं करेगा, न ही initial Ticket-Granting Ticket (TGT) प्राप्ति के बाद plain text credentials या long-term keys को कैश करेगा।
- **Offline Sign-In**: Protected Users के लिए sign-in या unlock के समय cached verifier नहीं बनाया जाएगा, जिसका अर्थ है कि इन accounts के लिए offline sign-in समर्थित नहीं है।

ये protections उस समय सक्रिय हो जाती हैं जब कोई user, जो **Protected Users group** का सदस्य होता है, डिवाइस में साइन-इन करता है। यह सुनिश्चित करता है कि credential compromise के विभिन्न तरीकों के खिलाफ महत्वपूर्ण सुरक्षा उपाय लागू हों।

For more detailed information, consult the official [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## References

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
