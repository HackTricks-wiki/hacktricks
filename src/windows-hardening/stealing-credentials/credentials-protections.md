# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, जिसे Windows XP के साथ पेश किया गया था, HTTP Protocol के माध्यम से authentication के लिए बनाया गया है और यह **Windows XP से Windows 8.0 तक तथा Windows Server 2003 से Windows Server 2012 तक डिफ़ॉल्ट रूप से enabled** है। इस default setting के कारण **LSASS** (Local Security Authority Subsystem Service) में **plain-text password storage** होता है। कोई attacker Mimikatz का उपयोग करके निम्नलिखित command चलाकर **इन credentials को extract** कर सकता है:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
इस feature को **बंद या चालू करने के लिए**, _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ के अंतर्गत _**UseLogonCredential**_ और _**Negotiate**_ registry keys को "1" पर सेट करना होगा। यदि ये keys **अनुपस्थित हों या "0" पर सेट हों**, तो WDigest **disabled** है:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP और PPL protected processes)

**Protected Process (PP)** और **Protected Process Light (PPL)**, **LSASS** जैसी संवेदनशील processes को unauthorized access से बचाने के लिए बनाई गई **Windows kernel-level protections** हैं। **Windows Vista** में प्रस्तुत किया गया **PP model** मूल रूप से **DRM** enforcement के लिए बनाया गया था और केवल **special media certificate** से signed binaries को ही protected होने की अनुमति देता था। **PP** के रूप में चिह्नित process को केवल अन्य **PP** processes द्वारा access किया जा सकता है, जिनका **protection level** समान या अधिक हो, और तब भी **केवल limited access rights** के साथ, जब तक कि विशेष रूप से अनुमति न दी गई हो।

**Windows 8.1** में प्रस्तुत किया गया **PPL**, PP का अधिक flexible version है। यह **"protection levels"** शुरू करके **broader use cases** (जैसे LSASS, Defender) की अनुमति देता है, जो **digital signature** के **EKU (Enhanced Key Usage)** field पर आधारित होते हैं। Protection level को `EPROCESS.Protection` field में store किया जाता है, जो एक `PS_PROTECTION` structure है, जिसमें:
- **Type** (`Protected` या `ProtectedLight`)
- **Signer** (जैसे `WinTcb`, `Lsa`, `Antimalware`, आदि)

यह structure एक single byte में packed होता है और निर्धारित करता है कि **कौन किसे access कर सकता है**:
- **Higher signer values**, lower values को access कर सकते हैं
- **PPLs**, **PPs** को access नहीं कर सकते
- **Unprotected processes**, किसी भी PPL/PP को access नहीं कर सकते

### Offensive perspective से आपको क्या जानना चाहिए

- जब **LSASS, PPL के रूप में चलता है**, तो normal admin context से `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` का उपयोग करके उसे open करने के attempts **`0x5 (Access Denied)`** के साथ fail होते हैं, भले ही `SeDebugPrivilege` enabled हो।
- आप Process Hacker जैसे tools का उपयोग करके या programmatically `EPROCESS.Protection` value को read करके **LSASS protection level** check कर सकते हैं।
- LSASS में आमतौर पर `PsProtectedSignerLsa-Light` (`0x41`) होता है, जिसे केवल higher-level signer से signed processes, जैसे `WinTcb` (`0x61` या `0x62`), access कर सकते हैं।
- PPL केवल **Userland-only restriction** है; **kernel-level code** इसे पूरी तरह bypass कर सकता है।
- LSASS का PPL होना credential dumping को नहीं रोकता, यदि आप **kernel shellcode execute** कर सकते हैं या **proper access** वाले high-privileged process का **leverage** कर सकते हैं।
- **PPL को set या remove करने** के लिए reboot या **Secure Boot/UEFI settings** की आवश्यकता होती है, जो registry changes को reverse करने के बाद भी PPL setting को persist कर सकती हैं।

### Launch के समय PPL process बनाना (documented API)

Windows, extended startup attribute list का उपयोग करके child process creation के दौरान **Protected Process Light level** request करने का एक documented तरीका उपलब्ध कराता है। यह signing requirements को bypass नहीं करता — target image का requested signer class के लिए signed होना आवश्यक है।

C/C++ में minimal flow:
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
- `STARTUPINFOEX` का उपयोग `InitializeProcThreadAttributeList` और `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)` के साथ करें, फिर `CreateProcess*` को `EXTENDED_STARTUPINFO_PRESENT` पास करें।<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Protection `DWORD` को `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` या `PROTECTION_LEVEL_LSA_LIGHT` जैसे constants पर सेट किया जा सकता है।
- Child केवल तभी PPL के रूप में शुरू होता है जब उसकी image उस signer class के लिए signed हो; अन्यथा process creation विफल हो जाता है, आम तौर पर `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)` के साथ।
- यह bypass नहीं है — यह उचित रूप से signed images के लिए बनाया गया एक supported API है। यह tools को harden करने या PPL-protected configurations को validate करने के लिए उपयोगी है।

Minimal loader का उपयोग करने वाला Example CLI:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**PPL protections को bypass करने के विकल्प:**

यदि आप PPL के बावजूद LSASS को dump करना चाहते हैं, तो आपके पास 4 मुख्य विकल्प हैं:
1. **एक signed kernel driver (जैसे, Mimikatz + mimidrv.sys) का उपयोग करके** **LSASS का protection flag हटाएँ**:

![Credential protection interaction दिखाने वाला Mimikatz mimidrv driver output](../../images/mimidrv.png)

2. **अपना Vulnerable Driver लाएँ (BYOVD)** ताकि custom kernel code चलाया जा सके और protection को disable किया जा सके। **PPLKiller**, **gdrv-loader** या **kdmapper** जैसे tools इसे संभव बनाते हैं।
3. किसी अन्य process, जिसके पास LSASS handle खुला है (जैसे, कोई AV process), से **मौजूदा LSASS handle चुराएँ**, फिर उसे अपने process में **duplicate करें**। यही `pypykatz live lsa --method handledup` technique का आधार है।
4. किसी **privileged process** का दुरुपयोग करें, जो आपको उसके address space में या किसी अन्य privileged process के अंदर arbitrary code load करने की अनुमति देता हो; इससे प्रभावी रूप से PPL restrictions bypass हो जाती हैं। इसका एक example [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) या [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) में देखा जा सकता है।

**LSASS के लिए LSA protection (PPL/PP) की current status जाँचें:**
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
**`mimikatz privilege::debug sekurlsa::logonpasswords`** चलाने पर, इस protection के कारण संभवतः `0x00000005` error code के साथ यह विफल हो जाएगा।

- इस check के बारे में अधिक जानकारी के लिए [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, जो केवल **Windows 10 (Enterprise और Education editions)** के लिए उपलब्ध feature है, **Virtual Secure Mode (VSM)** और **Virtualization Based Security (VBS)** का उपयोग करके machine credentials की security को बेहतर बनाता है। यह CPU virtualization extensions का उपयोग करके key processes को एक protected memory space में isolate करता है, जो मुख्य operating system की पहुंच से बाहर होता है। यह isolation सुनिश्चित करता है कि kernel भी VSM की memory तक पहुंच न सके, जिससे credentials को **pass-the-hash** जैसे attacks से प्रभावी रूप से सुरक्षित रखा जा सके। **Local Security Authority (LSA)** इस secure environment में trustlet के रूप में काम करता है, जबकि मुख्य OS में मौजूद **LSASS** process केवल VSM के LSA के साथ communication करता है।

By default, **Credential Guard** active नहीं होता और organization के भीतर इसे manually activate करना आवश्यक होता है। **Mimikatz** जैसे tools के विरुद्ध security बढ़ाने के लिए यह महत्वपूर्ण है, क्योंकि इससे credentials extract करने की उनकी क्षमता बाधित होती है। हालांकि, login attempts के दौरान credentials को clear text में capture करने के लिए custom **Security Support Providers (SSP)** जोड़कर vulnerabilities का अभी भी exploitation किया जा सकता है।

**Credential Guard** के activation status की पुष्टि करने के लिए, _**HKLM\System\CurrentControlSet\Control\LSA**_ के अंतर्गत registry key _**LsaCfgFlags**_ का निरीक्षण किया जा सकता है। "**1**" का value **UEFI lock** के साथ activation, "**2**" बिना lock के activation, और "**0**" इसके enabled न होने को दर्शाता है। यह registry check एक strong indicator है, लेकिन Credential Guard को enable करने के लिए यह अकेला step नहीं है। इस feature को enable करने के लिए detailed guidance और एक PowerShell script online उपलब्ध हैं।
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10 में **Credential Guard** को सक्षम करने और **Windows 11 Enterprise and Education (version 22H2)** के compatible systems में इसके automatic activation को समझने और इसके instructions के लिए [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) देखें।<sup>[[9]](#references)</sup>

Credential capture के लिए custom SSPs लागू करने के बारे में अधिक जानकारी [इस guide](../active-directory-methodology/custom-ssp.md) में दी गई है।

## RDP RestrictedAdmin Mode

**Windows 8.1 और Windows Server 2012 R2** ने कई नई security features पेश कीं, जिनमें _**Restricted Admin mode for RDP**_ भी शामिल है। यह mode [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) attacks से जुड़े risks को कम करके security बढ़ाने के लिए बनाया गया था।

परंपरागत रूप से, RDP के माध्यम से किसी remote computer से connect करते समय आपके credentials target machine पर store होते हैं। यह एक महत्वपूर्ण security risk पैदा करता है, खासकर elevated privileges वाले accounts का उपयोग करते समय। हालांकि, _**Restricted Admin mode**_ की शुरुआत के साथ यह risk काफी कम हो जाता है।

**mstsc.exe /RestrictedAdmin** command का उपयोग करके RDP connection शुरू करने पर remote computer पर authentication आपके credentials को store किए बिना किया जाता है। यह approach सुनिश्चित करता है कि malware infection की स्थिति में या किसी malicious user द्वारा remote server तक access प्राप्त करने पर आपके credentials compromise न हों, क्योंकि वे server पर store नहीं होते।

यह ध्यान रखना महत्वपूर्ण है कि **Restricted Admin mode** में RDP session से network resources access करने के attempts में आपके personal credentials का उपयोग नहीं किया जाएगा; इसके बजाय, **machine's identity** का उपयोग किया जाता है।

यह feature remote desktop connections को secure करने और security breach की स्थिति में sensitive information को expose होने से बचाने की दिशा में एक महत्वपूर्ण कदम है।

![Credential extraction context के लिए Windows RAM memory diagram](../../images/RAM.png)

अधिक विस्तृत जानकारी के लिए [इस resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) पर जाएं।<sup>[[6]](#references)</sup>

## Cached Credentials

Windows **domain credentials** को **Local Security Authority (LSA)** के माध्यम से secure करता है और **Kerberos** तथा **NTLM** जैसे security protocols के साथ logon processes को support करता है। Windows की एक प्रमुख feature **last ten domain logins** को cache करने की क्षमता है, ताकि **domain controller offline** होने पर भी users अपने computers को access कर सकें—यह उन laptop users के लिए विशेष रूप से उपयोगी है जो अक्सर अपनी company के network से दूर रहते हैं।

Cached logins की संख्या को एक specific **registry key or group policy** के माध्यम से adjust किया जा सकता है। इस setting को देखने या बदलने के लिए निम्न command का उपयोग किया जाता है:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
इन cached credentials तक access कड़े नियंत्रण में होता है, और केवल **SYSTEM** account के पास इन्हें देखने के लिए आवश्यक permissions होती हैं। इस information को access करने वाले Administrators को SYSTEM user privileges के साथ ऐसा करना आवश्यक है। Credentials यहां store होते हैं: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** का उपयोग command `lsadump::cache` के जरिए इन cached credentials को extract करने के लिए किया जा सकता है।

अधिक details के लिए, मूल [source](http://juggernaut.wikidot.com/cached-credentials) में व्यापक information दी गई है।<sup>[[7]](#references)</sup>

## Protected Users

**Protected Users group** की membership users के लिए कई security enhancements लागू करती है, जिससे credential theft और misuse के विरुद्ध higher levels of protection सुनिश्चित होते हैं:

- **Credential Delegation (CredSSP)**: यदि **Allow delegating default credentials** के लिए Group Policy setting enabled भी हो, तब भी Protected Users के plain text credentials cache नहीं किए जाएंगे।
- **Windows Digest**: **Windows 8.1 और Windows Server 2012 R2** से शुरू होकर, Windows Digest status की परवाह किए बिना system Protected Users के plain text credentials cache नहीं करेगा।
- **NTLM**: system Protected Users के plain text credentials या NT one-way functions (NTOWF) cache नहीं करेगा।
- **Kerberos**: Protected Users के लिए, Kerberos authentication **DES** या **RC4 keys** generate नहीं करेगा और initial Ticket-Granting Ticket (TGT) acquisition के बाद plain text credentials या long-term keys cache नहीं करेगा।
- **Offline Sign-In**: Protected Users के लिए sign-in या unlock के समय cached verifier create नहीं किया जाएगा, जिसका अर्थ है कि इन accounts के लिए offline sign-in supported नहीं है।

ये protections उसी क्षण activate हो जाती हैं जब **Protected Users group** का member कोई user device में sign in करता है। इससे यह सुनिश्चित होता है कि credential compromise के विभिन्न तरीकों से सुरक्षा के लिए critical security measures लागू हों।

अधिक detailed information के लिए, official [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) देखें।<sup>[[10]](#references)</sup>

**[docs से table](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**।<sup>[[11]](#references)</sup>

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
| Server Operators        | Server Operators        | Server Operators                                                              | Server Operators             |

## References

- [1] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode for RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
