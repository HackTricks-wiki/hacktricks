# UIAccess के माध्यम से Admin Protection बाईपास

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन
- Windows AppInfo `RAiLaunchAdminProcess` को UIAccess प्रक्रियाएँ spawn करने के लिए एक्सपोज़ करता है (accessibility के लिए)। UIAccess अधिकांश User Interface Privilege Isolation (UIPI) message filtering को बाइपास करता है ताकि accessibility software higher-IL UI को drive कर सके।
- UIAccess को सीधे सक्षम करने के लिए `NtSetInformationToken(TokenUIAccess)` और **SeTcbPrivilege** की आवश्यकता होती है, इसलिए low-priv कॉलर सर्विस पर निर्भर रहते हैं। सर्विस लक्ष्य बाइनरी पर UIAccess सेट करने से पहले तीन चेक करती है:
  - Embedded manifest में `uiAccess="true"` होना चाहिए।
  - Local Machine root store द्वारा ट्रस्ट किए गए किसी भी certificate से साइन किया हुआ होना चाहिए (कोई EKU/Microsoft requirement नहीं)।
  - सिस्टम ड्राइव पर administrator-only path में स्थित होना चाहिए (उदा., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, विशिष्ट writable subpaths को छोड़कर)।
- `RAiLaunchAdminProcess` UIAccess लॉन्च के लिए कोई consent prompt नहीं दिखाता (अन्यथा accessibility tooling prompt को drive नहीं कर पाती)।

## Token shaping और integrity levels
- यदि चेक सफल होते हैं, तो AppInfo **caller token की copy बनाता है**, UIAccess सक्षम करता है, और Integrity Level (IL) बढ़ाता है:
  - Limited admin user (user Administrators में है पर filtered चल रहा है) ➜ **High IL**।
  - Non-admin user ➜ IL को **+16 levels** से बढ़ाया जाता है, अधिकतम **High** कैप तक (System IL कभी असाइन नहीं होता)।
- यदि caller token पहले से ही UIAccess रखता है, तो IL अपरिवर्तित रहती है।
- “Ratchet” ट्रिक: एक UIAccess प्रक्रिया अपने आप पर UIAccess डिसेबल कर सकती है, `RAiLaunchAdminProcess` के जरिए फिर से relaunch कर सकती है, और एक और +16 IL increment प्राप्त कर सकती है। Medium➜High के लिए 255 relaunches की आवश्यकता होती है (शोरगुल होगा, पर काम करता है)।

## क्यों UIAccess एक Admin Protection escape सक्षम बनाता है
- UIAccess एक lower-IL प्रक्रिया को higher-IL विंडोज़ को window messages भेजने देता है (UIPI filters को बाइपास करते हुए)। समान IL पर, क्लासिक UI primitives जैसे `SetWindowsHookEx` किसी भी प्रक्रिया में code injection/DLL loading की अनुमति देते हैं जो किसी विंडो की owner है (including **message-only windows** जो COM द्वारा उपयोग होते हैं)।
- Admin Protection UIAccess प्रक्रिया को **limited user की identity** पर परन्तु **High IL** में लॉन्च करता है, बिना दिखाए। एक बार arbitrary code उस High-IL UIAccess प्रक्रिया के अंदर चलने लगे, attacker उस desktop पर अन्य High-IL प्रक्रियाओं में inject कर सकता है (यहाँ तक कि अलग users की प्रक्रियाएँ भी), जिससे intended separation टूट जाती है।

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ पर API Win32k में मूव हुई (`NtUserGetWindowProcessHandle`) और यह caller-supplied `DesiredAccess` का उपयोग करके process handle खोल सकती है। kernel path `ObOpenObjectByPointer(..., KernelMode, ...)` का उपयोग करती है, जो सामान्य user-mode access checks को बाइपास करती है।
- व्यवहारिक preconditions: target window उसी desktop पर होना चाहिए, और UIPI चेक्स पास होने चाहिए। ऐतिहासिक रूप से, UIAccess वाला caller UIPI failure को बाइपास कर सकता था और फिर भी kernel-mode handle प्राप्त कर लेता था (fixed as CVE-2023-41772)।
- प्रभाव: एक window handle एक ऐसी **capability** बन जाता है जो एक शक्तिशाली process handle प्राप्त करने देती है (आम तौर पर `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) जिन्हें caller सामान्यतः खोल नहीं सकता था। यह cross-sandbox access सक्षम करता है और Protected Process / PPL boundaries को तोड़ सकता है अगर target कोई विंडो expose करता है (message-only windows सहित)।
- व्यावहारिक दुर्व्यवहार फ़्लो: HWNDs का enumeration या पता लगाना (उदा., `EnumWindows`/`FindWindowEx`), owning PID का resolution (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` कॉल करना, फिर returned handle का उपयोग memory read/write या code-hijack primitives के लिए करना।
- fix के बाद व्यवहार: UIAccess अब UIPI failure पर kernel-mode opens नहीं देता और allowed access rights legacy hook set तक सीमित हैं; Windows 11 24H2 process-protection checks और feature-flagged safer paths जोड़ता है। UIPI system-wide को disable करना (`EnforceUIPI=0`) इन सुरक्षा उपायों को कमजोर करता है।

## Secure-directory validation कमजोरियाँ (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo सप्लाई किए गए path को `GetFinalPathNameByHandle` के जरिए resolve करता है और फिर हार्कोर्ड किये गए roots/exclusions के खिलाफ **string allow/deny checks** लागू करता है। उस सरल validation से कई bypass क्लासेस उत्पन्न होती हैं:
- **Directory named streams**: Excluded writable directories (उदा., `C:\Windows\tracing`) को directory पर ही named stream के साथ बाइपास किया जा सकता है, जैसे `C:\Windows\tracing:file.exe`। string checks `C:\Windows\` देखते हैं और excluded subpath को मिस कर देते हैं।
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` को **`.exe` extension की आवश्यकता नहीं** होती। किसी भी writable file को allowed root के अंदर executable payload से overwrite करना काम करता है, या किसी signed `uiAccess="true"` EXE को किसी writable subdirectory (उदा., मौजूद होने पर update leftovers जैसे `Tasks_Migrated`) में copy करना secure-path चेक को पास करवा देता है।
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins signed MSIX packages install कर सकते थे जो `WindowsApps` में जाते थे, जिसे exclude नहीं किया गया था। MSIX में UIAccess बाइनरी पैकेज कर के और उसे `RAiLaunchAdminProcess` से लॉन्च कर के एक **promptless High-IL UIAccess process** मिल जाता था। Microsoft ने इस path को exclude करके mitigate किया; `uiAccess` restricted MSIX capability खुद भी admin install की मांग करती है।

## Attack workflow (High IL बिना prompt के)
1. एक **signed UIAccess binary** प्राप्त/बनाएँ (manifest `uiAccess="true"`).
2. इसे AppInfo की allowlist द्वारा स्वीकार किए जाने वाले स्थान पर रखें (या path-validation edge case/writable artifact का दुरुपयोग करें जैसा ऊपर बताया गया)।
3. `RAiLaunchAdminProcess` कॉल करें ताकि इसे **silently** UIAccess + बढ़ी हुई IL के साथ spawn किया जा सके।
4. उस High-IL foothold से, desktop पर किसी अन्य High-IL प्रक्रिया को target करें, `window hooks/DLL injection` या अन्य same-IL primitives का उपयोग करके admin context को पूरी तरह compromise करें।

## candidate writable paths की enumeration
चुने गए token के परिप्रेक्ष्य से nominally secure roots के अंदर writable/overwritable objects खोजने के लिए PowerShell helper चलाएँ:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- व्यापक दृश्यता के लिए Administrator के रूप में चलाएँ; `-ProcessId` को एक low-priv प्रक्रिया पर सेट करें ताकि उस token के एक्सेस का mirror हो सके।
- `RAiLaunchAdminProcess` के साथ candidates का उपयोग करने से पहले ज्ञात disallowed उपनिर्देशिकाओं को बाहर करने के लिए मैन्युअली filter करें।

## Related

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## संदर्भ
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
