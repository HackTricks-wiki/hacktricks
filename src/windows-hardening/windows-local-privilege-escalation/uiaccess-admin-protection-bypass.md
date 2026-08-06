# UIAccess के माध्यम से Admin Protection Bypasses

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo accessibility के लिए UIAccess processes को spawn करने हेतु `RAiLaunchAdminProcess` expose करता है। UIAccess अधिकांश User Interface Privilege Isolation (UIPI) message filtering को bypass करता है, ताकि accessibility software higher-IL UI को नियंत्रित कर सके।
- UIAccess को सीधे enable करने के लिए **SeTcbPrivilege** के साथ `NtSetInformationToken(TokenUIAccess)` आवश्यक है, इसलिए low-priv callers service पर निर्भर रहते हैं। UIAccess सेट करने से पहले service target binary पर ये तीन checks करती है:
- Embedded manifest में `uiAccess="true"` मौजूद हो।
- Local Machine root store द्वारा trusted किसी भी certificate से signed हो (किसी EKU/Microsoft requirement के बिना)।
- System drive पर administrator-only path में स्थित हो (जैसे `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), और कुछ specific writable subpaths को छोड़कर।
- `RAiLaunchAdminProcess` UIAccess launches के लिए consent prompt नहीं दिखाता (अन्यथा accessibility tooling prompt को नियंत्रित नहीं कर पाती)।<sup>[[1]](#references)</sup>

## Token shaping और integrity levels
- यदि checks सफल होते हैं, तो AppInfo **caller token की copy बनाता है**, UIAccess enable करता है और Integrity Level (IL) बढ़ाता है:
- Limited admin user (user Administrators में है, लेकिन filtered mode में चल रहा है) ➜ **High IL**।
- Non-admin user ➜ IL को **+16 levels** तक बढ़ाया जाता है, अधिकतम **High** cap तक (System IL कभी assign नहीं किया जाता)।
- यदि caller token में पहले से UIAccess है, तो IL अपरिवर्तित रहता है।
- “Ratchet” trick: UIAccess process स्वयं पर UIAccess disable कर सकता है, `RAiLaunchAdminProcess` के माध्यम से relaunch कर सकता है और फिर +16 IL increment प्राप्त कर सकता है। Medium➜High के लिए 255 relaunches आवश्यक हैं (noisy, लेकिन काम करता है)।<sup>[[1]](#references)</sup>

## UIAccess Admin Protection escape कैसे enable करता है
- UIAccess lower-IL process को higher-IL windows पर window messages भेजने देता है (UIPI filters को bypass करके)। **समान IL** पर, `SetWindowsHookEx` जैसे classic UI primitives किसी भी ऐसे process में **code injection/DLL loading** की अनुमति देते हैं जिसके पास कोई window हो (जिसमें COM द्वारा उपयोग की जाने वाली **message-only windows** भी शामिल हैं)।
- Admin Protection UIAccess process को **limited user की identity** के तहत, लेकिन चुपचाप **High IL** पर launch करता है। एक बार उस High-IL UIAccess process के अंदर arbitrary code चलने लगे, तो attacker desktop पर मौजूद अन्य High-IL processes में inject कर सकता है (भले ही वे अलग users से संबंधित हों), जिससे intended separation टूट जाता है।<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ पर API Win32k में चला गया (`NtUserGetWindowProcessHandle`) और caller-supplied `DesiredAccess` का उपयोग करके process handle खोल सकता है। Kernel path `ObOpenObjectByPointer(..., KernelMode, ...)` का उपयोग करता है, जो सामान्य user-mode access checks को bypass करता है।<sup>[[2]](#references)</sup>
- व्यवहार में Preconditions: target window उसी desktop पर होना चाहिए और UIPI checks पास होने चाहिए। ऐतिहासिक रूप से, UIAccess वाला caller UIPI failure को bypass करके kernel-mode handle प्राप्त कर सकता था (CVE-2023-41772 द्वारा fixed)।
- Impact: window handle एक **capability** बन जाता है, जिससे powerful process handle प्राप्त किया जा सकता है (आमतौर पर `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) जिसे caller सामान्य रूप से open नहीं कर सकता था। इससे cross-sandbox access संभव होता है और यदि target कोई window expose करता है (message-only windows सहित), तो Protected Process / PPL boundaries टूट सकती हैं।
- Practical abuse flow: HWNDs enumerate या locate करें (जैसे `EnumWindows`/`FindWindowEx`), owning PID resolve करें (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` call करें, फिर returned handle का उपयोग memory read/write या code-hijack primitives के लिए करें।
- Post-fix behavior: UIPI failure पर UIAccess अब kernel-mode opens प्रदान नहीं करता और allowed access rights legacy hook set तक सीमित हैं; Windows 11 24H2 process-protection checks और feature-flagged safer paths जोड़ता है। System-wide UIPI disable करने (`EnforceUIPI=0`) से ये protections कमजोर हो जाती हैं।<sup>[[2]](#references)</sup>

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo supplied path को `GetFinalPathNameByHandle` के माध्यम से resolve करता है और फिर hardcoded roots/exclusions के विरुद्ध **string allow/deny checks** लागू करता है। इस सरल validation से कई bypass classes उत्पन्न होती हैं:
- **Directory named streams**: Excluded writable directories (जैसे `C:\Windows\tracing`) को directory पर ही named stream के माध्यम से bypass किया जा सकता है, जैसे `C:\Windows\tracing:file.exe`। String checks `C:\Windows\` देखते हैं और excluded subpath को miss कर देते हैं।
- **Allowed root के अंदर writable file/directory**: `CreateProcessAsUser` को `.exe` extension की आवश्यकता **नहीं** होती। Allowed root के अंदर किसी भी writable file को executable payload से overwrite करना काम करता है, या signed `uiAccess="true"` EXE को किसी भी writable subdirectory में copy करना (जैसे मौजूद होने पर update leftovers जैसे `Tasks_Migrated`) उसे secure-path check पास करा देता है।
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins signed MSIX packages install कर सकते थे, जो `WindowsApps` में पहुंचते थे और यह path excluded नहीं था। MSIX के अंदर UIAccess binary package करके उसे `RAiLaunchAdminProcess` के माध्यम से launch करने पर **promptless High-IL UIAccess process** प्राप्त होता था। Microsoft ने इस path को exclude करके mitigation किया; `uiAccess` restricted MSIX capability के लिए स्वयं पहले से admin install आवश्यक है।<sup>[[1]](#references)</sup>

## Attack workflow (बिना prompt के High IL)
1. एक **signed UIAccess binary** प्राप्त/निर्मित करें (manifest में `uiAccess="true"` हो)।
2. इसे ऐसी जगह रखें जिसे AppInfo की allowlist स्वीकार करती हो (या ऊपर बताए गए path-validation edge case/writable artifact का दुरुपयोग करें)।
3. UIAccess + elevated IL के साथ इसे **silently** spawn करने के लिए `RAiLaunchAdminProcess` call करें।
4. इस High-IL foothold से desktop पर मौजूद किसी अन्य High-IL process को **window hooks/DLL injection** या अन्य same-IL primitives के माध्यम से target करके admin context पर पूर्ण compromise प्राप्त करें।<sup>[[1]](#references)</sup>

## Candidate writable paths enumerate करना
चुने गए token के perspective से nominally secure roots के अंदर writable/overwritable objects खोजने के लिए PowerShell helper चलाएँ:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- व्यापक visibility के लिए Administrator के रूप में चलाएँ; उस token के access को mirror करने के लिए `-ProcessId` को किसी low-priv process पर सेट करें।
- `RAiLaunchAdminProcess` के साथ candidates का उपयोग करने से पहले ज्ञात disallowed subdirectories को manually exclude करने के लिए filter करें।

## संबंधित

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## संदर्भ

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
