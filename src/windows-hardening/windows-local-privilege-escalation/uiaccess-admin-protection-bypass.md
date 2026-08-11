# UIAccess के माध्यम से Admin Protection Bypasses

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo accessibility के लिए UIAccess applications शुरू करने हेतु उपयोग किए जाने वाले internal `RAiLaunchAdminProcess` path को expose करता है। UIAccess, User Interface Privilege Isolation (UIPI) boundaries के पार selected interaction की अनुमति देता है; यह हर process-security boundary का general bypass नहीं है।<sup>[[1]](#references)[[3]](#references)</sup>
- UIAccess को सीधे enable करने के लिए **SeTcbPrivilege** के साथ `NtSetInformationToken(TokenUIAccess)` आवश्यक है, इसलिए low-priv callers service पर निर्भर रहते हैं। UIAccess set करने से पहले service target binary पर ये तीन checks करती है:
- Embedded manifest में `uiAccess="true"` मौजूद हो।
- Local Machine root store द्वारा trusted किसी भी certificate से signed हो (किसी EKU/Microsoft requirement के बिना)।
- System drive पर administrator-only path में स्थित हो (जैसे `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), जिसमें कुछ specific writable subpaths शामिल नहीं हैं।
- `RAiLaunchAdminProcess` UIAccess launches के लिए consent prompt नहीं दिखाता (अन्यथा accessibility tooling prompt को control नहीं कर पाती)।<sup>[[1]](#references)</sup>

## Token shaping और integrity levels
- यदि checks सफल होते हैं, तो AppInfo **caller token की copy बनाता है**, UIAccess enable करता है और Integrity Level (IL) बढ़ाता है:
- Limited admin user (user Administrators में है, लेकिन filtered रूप में चल रहा है) ➜ **High IL**।
- Non-admin user ➜ IL को **+16 levels** तक बढ़ाया जाता है, अधिकतम **High** cap तक (System IL कभी assign नहीं किया जाता)।
- यदि caller token में पहले से UIAccess है, तो IL अपरिवर्तित रहता है।
- “Ratchet” trick: UIAccess process स्वयं पर UIAccess disable कर सकता है, `RAiLaunchAdminProcess` के माध्यम से relaunch कर सकता है और एक और +16 IL increment प्राप्त कर सकता है। Medium➜High के लिए 255 relaunches लगते हैं (noisy, लेकिन काम करता है)।<sup>[[1]](#references)</sup>

## UIAccess Admin Protection escape को कैसे enable करता है
- UIAccess lower-IL process को higher-IL windows पर window messages भेजने देता है (UIPI filters को bypass करके)। **Equal IL** पर, `SetWindowsHookEx` जैसे classic UI primitives किसी भी ऐसे process में **code injection/DLL loading** की अनुमति देते हैं जिसके पास कोई window हो (जिसमें COM द्वारा उपयोग की जाने वाली **message-only windows** भी शामिल हैं)।
- Admin Protection UIAccess process को **limited user की identity** के अंतर्गत, लेकिन **High IL** पर, silently launch करता है। एक बार उस High-IL UIAccess process के अंदर arbitrary code चलने लगे, तो attacker desktop पर मौजूद अन्य High-IL processes में inject कर सकता है (भले ही वे अलग users से संबंधित हों), जिससे intended separation टूट जाता है।<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ पर API Win32k में move हो गई (`NtUserGetWindowProcessHandle`) और caller-supplied `DesiredAccess` का उपयोग करके process handle open कर सकती है। Kernel path `ObOpenObjectByPointer(..., KernelMode, ...)` का उपयोग करता है, जो सामान्य user-mode access checks को bypass करता है।<sup>[[2]](#references)</sup>
- व्यवहार में preconditions: target window उसी desktop पर होनी चाहिए और UIPI checks pass होने चाहिए। ऐतिहासिक रूप से, UIAccess वाले caller UIPI failure को bypass करके फिर भी kernel-mode handle प्राप्त कर सकते थे (CVE-2023-41772 में fixed)।
- Historical impact: window handle process access के लिए एक **capability** बन गया, जैसे `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` या `PROCESS_VM_OPERATION`, जिसे caller सामान्य रूप से प्राप्त नहीं कर सकता था। Documented fixes से पहले, जब target कोई window expose करता था, तब यह sandbox और protected-process boundaries को cross कर सकता था; इसमें message-only window भी शामिल थी।<sup>[[2]](#references)</sup>
- Practical abuse flow: HWNDs enumerate या locate करें (जैसे `EnumWindows`/`FindWindowEx`), owning PID resolve करें (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` call करें, फिर returned handle का उपयोग memory read/write या code-hijack primitives के लिए करें।
- Post-fix behavior: UIPI failure पर UIAccess अब kernel-mode opens grant नहीं करता और allowed access rights legacy hook set तक restricted हैं; Windows 11 24H2 process-protection checks और feature-flagged safer paths जोड़ता है। System-wide UIPI disable करना (`EnforceUIPI=0`) इन protections को कमजोर करता है।<sup>[[2]](#references)</sup>

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo supplied path को `GetFinalPathNameByHandle` के माध्यम से resolve करता है और फिर hardcoded roots/exclusions के विरुद्ध **string allow/deny checks** लागू करता है। इस simplistic validation से कई bypass classes उत्पन्न होती हैं:
- **Directory named streams**: Excluded writable directories (जैसे `C:\Windows\tracing`) को directory पर ही named stream के साथ bypass किया जा सकता है, जैसे `C:\Windows\tracing:file.exe`। String checks `C:\Windows\` देखते हैं और excluded subpath को miss कर देते हैं।
- **Allowed root के अंदर writable file/directory**: `CreateProcessAsUser` को `.exe` extension की आवश्यकता **नहीं** होती। Allowed root के अंदर किसी भी writable file को executable payload से overwrite करना काम करता है, या signed `uiAccess="true"` EXE को किसी भी writable subdirectory में copy करना (जैसे मौजूद होने पर update leftovers जैसे `Tasks_Migrated`) उसे secure-path check pass करने देता है।
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins signed MSIX packages install कर सकते थे जो `WindowsApps` में land होते थे, जिसे exclude नहीं किया गया था। MSIX के अंदर UIAccess binary package करके उसे `RAiLaunchAdminProcess` के माध्यम से launch करने पर **promptless High-IL UIAccess process** प्राप्त होता था। Microsoft ने इस path को exclude करके mitigation किया; `uiAccess` restricted MSIX capability के लिए स्वयं पहले से admin install आवश्यक है।<sup>[[1]](#references)</sup>

## Attack workflow (बिना prompt के High IL)
1. एक **signed UIAccess binary** प्राप्त/build करें (manifest में `uiAccess="true"`)। Realistic assessment के लिए trust material और paths के साथ explicitly lab-authorized तरीके से test करें; production machine के Local Machine root store में attacker certificate न जोड़ें।
2. इसे उस स्थान पर रखें जहाँ AppInfo की allowlist इसे accept करती हो (या ऊपर बताए गए path-validation edge case/writable artifact का abuse करें)।
3. `RAiLaunchAdminProcess` call करके इसे UIAccess + elevated IL के साथ **silently** spawn करें।
4. इस High-IL foothold से desktop पर मौजूद किसी अन्य High-IL process को **window hooks/DLL injection** या अन्य same-IL primitives का उपयोग करके target करें और admin context को पूरी तरह compromise करें।<sup>[[1]](#references)</sup>

## Enumerating candidate writable paths
चुने गए token के perspective से nominally secure roots के अंदर writable/overwritable objects discover करने के लिए PowerShell helper चलाएँ:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- व्यापक visibility के लिए Administrator के रूप में चलाएँ; उस token की access को mirror करने के लिए `-ProcessId` को किसी low-priv process पर सेट करें।
- `RAiLaunchAdminProcess` के साथ candidates का उपयोग करने से पहले ज्ञात disallowed subdirectories को बाहर करने के लिए manually filter करें।

## संबंधित

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [UI Access का दुरुपयोग करके Administrator Protection को bypass करना](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) की गहन जानकारी](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccess applications](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
