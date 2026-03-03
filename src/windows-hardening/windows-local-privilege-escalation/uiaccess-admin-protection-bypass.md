# UIAccess के माध्यम से Admin Protection बाईपास

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन
- Windows AppInfo `RAiLaunchAdminProcess` को UIAccess प्रक्रियाएँ spawn करने के लिए एक्सपोज़ करता है (accessibility के लिए अभिकल्पित)। UIAccess अधिकांश User Interface Privilege Isolation (UIPI) संदेश फ़िल्टरिंग को बाईपास करता है ताकि accessibility सॉफ्टवेयर higher-IL UI को drive कर सके।
- UIAccess को सीधे सक्षम करने के लिए `NtSetInformationToken(TokenUIAccess)` के साथ **SeTcbPrivilege** की आवश्यकता होती है, इसलिए low-priv कॉलर सेवा पर भरोसा करते हैं। सेवा target binary पर UIAccess सेट करने से पहले तीन जाँचें करती है:
  - Embedded manifest में `uiAccess="true"` मौजूद हो।
  - Local Machine root store द्वारा भरोसेमंद किसी भी सर्टिफिकेट से signed हो (कोई EKU/Microsoft आवश्यकता नहीं)।
  - System drive पर administrator-only path में स्थित हो (उदा., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, कुछ writable सबपाथ्स को छोड़कर)।
- `RAiLaunchAdminProcess` UIAccess लॉन्च के लिए कोई consent prompt नहीं दिखाता (अन्यथा accessibility tooling prompt को drive नहीं कर पाती)।

## Token shaping और integrity levels
- अगर जाँचें सफल रहती हैं, तो AppInfo **caller token की कॉपी** बनाता है, UIAccess सक्षम करता है, और Integrity Level (IL) बढ़ाता है:
  - Limited admin user (user Administrators में है पर filtered चल रहा है) ➜ **High IL**।
  - Non-admin user ➜ IL को **+16 levels** से बढ़ाया जाता है, अधिकतम **High** तक (System IL कभी असाइन नहीं होता)।
- अगर caller token में पहले से UIAccess है, तो IL अपरिवर्तित रहती है।
- “Ratchet” ट्रिक: एक UIAccess प्रक्रिया अपने आप पर UIAccess डिसेबल कर सकती है, `RAiLaunchAdminProcess` के माध्यम से फिर से relaunch कर सकती है, और एक और +16 IL increment हासिल कर सकती है। Medium➜High के लिए 255 relaunches लगते हैं (शोरगुल होने के बावजूद काम करता है)।

## क्यों UIAccess Admin Protection escape को सक्षम करता है
- UIAccess कम-IL प्रक्रिया को higher-IL विंडोज़ को विंडो संदेश भेजने की अनुमति देता है (UIPI फ़िल्टर बाईपास करके)। समान IL पर, पारंपरिक UI primitives जैसे `SetWindowsHookEx` किसी भी process में code injection/DLL loading की अनुमति दे सकते हैं जो विंडो का मालिक है (message-only विंडोज़ सहित जो COM द्वारा प्रयोग होते हैं)।
- Admin Protection UIAccess प्रक्रिया को **limited user की identity** पर लेकिन **High IL** में लॉन्च करती है, बिना किसी संकेत के। एक बार arbitrary code उस High-IL UIAccess प्रक्रिया के अंदर चलने लगे, attacker अन्य High-IL प्रक्रियाओं में injection कर सकता है (desktop पर, यहां तक कि अलग users के भी), जिससे इच्छित隔離 टूट जाती है।

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ पर API Win32k (`NtUserGetWindowProcessHandle`) में चली गई और यह caller-supplied `DesiredAccess` का उपयोग करके process handle खोल सकती है। kernel path `ObOpenObjectByPointer(..., KernelMode, ...)` का उपयोग करता है, जो सामान्य user-mode access checks को बाईपास करता है।
- व्यावहारिक पूर्व-शर्तें: target विंडो उसी desktop पर होनी चाहिए, और UIPI checks पास होने चाहिए। ऐतिहासिक रूप से, UIAccess वाला कॉलर UIPI विफलता को बाईपास कर सकता था और फिर भी kernel-mode handle प्राप्त कर सकता था (fixed as CVE-2023-41772)।
- प्रभाव: एक विंडो हैंडल एक ऐसी capability बन जाता है जिससे शक्तिशाली process handle (सामान्यतः `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) प्राप्त किया जा सकता है जिसे caller सामान्यतः नहीं खोल सकता था। यह cross-sandbox access को सक्षम बनाता है और Protected Process / PPL boundaries को तोड़ सकता है यदि target कोई भी विंडो expose करता है (message-only विंडोज़ सहित)।
- व्यावहारिक दुरुपयोग फ्लो: HWNDs enumerate या locate करें (उदा., `EnumWindows`/`FindWindowEx`), owning PID resolve करें (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` कॉल करें, फिर returned handle का उपयोग memory read/write या code-hijack primitives के लिए करें।
- फिक्स के बाद व्यवहार: UIAccess अब UIPI विफलता पर kernel-mode opens नहीं देता और allowed access rights legacy hook set तक सीमित कर दिए गए हैं; Windows 11 24H2 process-protection checks और feature-flagged सुरक्षित paths जोड़ता है। UIPI को system-wide disable करना (`EnforceUIPI=0`) इन सुरक्षा उपायों को कमजोर कर देता है।

## Secure-directory validation कमजोरियां (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo प्रदत्त path को `GetFinalPathNameByHandle` के माध्यम से resolve करता है और फिर hardcoded roots/exclusions के खिलाफ **string allow/deny checks** लागू करता है। उस सरल validation से कई bypass क्लास उत्पन्न होते हैं:
- **Directory named streams**: Excluded writable directories (उदा., `C:\Windows\tracing`) को directory पर ही named stream के साथ बाईपास किया जा सकता है, जैसे `C:\Windows\tracing:file.exe`। string checks `C:\Windows\` देखते हैं और excluded subpath को मिस कर देते हैं।
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` को **`.exe` extension की आवश्यकता नहीं** होती। किसी भी writable file को किसी allowed root के अंतर्गत executable payload से overwrite करना काम करता है, या किसी writable subdirectory में signed `uiAccess="true"` EXE को कॉपी करना (उदा., अपडेट leftovers जैसे `Tasks_Migrated` जब मौजूद हों) secure-path check पास करवा देता है।
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins signed MSIX packages install कर सकते थे जो `WindowsApps` में आते थे, जो excluded नहीं था। MSIX के अंदर UIAccess बाइनरी पैकेज करके और उसे `RAiLaunchAdminProcess` के माध्यम से लॉन्च करके एक **promptless High-IL UIAccess process** बनाया जा सकता था। Microsoft ने इस path को exclude करके mitigated किया; `uiAccess` restricted MSIX capability खुद भी admin install की आवश्यकता रखती है।

## Attack workflow (High IL बिना prompt के)
1. एक **signed UIAccess binary** प्राप्त/बनाएँ (manifest में `uiAccess="true"`).
2. इसे ऐसे स्थान पर रखें जहाँ AppInfo की allowlist इसे स्वीकार करे (या ऊपर बताये path-validation edge case/writable artifact का दुरुपयोग करें)।
3. इसे **चुपचाप** UIAccess + elevated IL के साथ spawn करने के लिए `RAiLaunchAdminProcess` कॉल करें।
4. उस High-IL foothold से, desktop पर किसी अन्य High-IL प्रक्रिया को target करें `window hooks/DLL injection` या अन्य same-IL primitives का उपयोग करके और admin context को पूरी तरह से compromise करें।

## Candidate writable paths की enumeration
चयनित token की दृष्टि से nominally secure roots के अंदर writable/overwritable objects खोजने के लिए PowerShell helper चलाएँ:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- व्यापक दृश्यता के लिए Administrator के रूप में चलाएँ; उस token की access को समान करने के लिए `-ProcessId` को किसी low-priv process पर सेट करें।
- `RAiLaunchAdminProcess` के साथ candidates का उपयोग करने से पहले ज्ञात निषिद्ध उप-निर्देशिकाओं को बाहर करने के लिए मैन्युअली फ़िल्टर करें।

## संदर्भ
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
