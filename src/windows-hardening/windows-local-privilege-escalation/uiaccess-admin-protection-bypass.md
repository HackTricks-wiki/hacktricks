# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन
- Windows AppInfo `RAiLaunchAdminProcess` को UIAccess प्रक्रियाएँ स्पॉन करने के लिए एक्सपोज़ करता है (accessibility के लिए इरादा)। UIAccess अधिकांश User Interface Privilege Isolation (UIPI) संदेश फ़िल्टरिंग को बाइपास करता है ताकि accessibility सॉफ़्टवेयर higher-IL UI को ड्राइव कर सके।
- सीधे UIAccess को सक्षम करने के लिए `NtSetInformationToken(TokenUIAccess)` के साथ **SeTcbPrivilege** की आवश्यकता होती है, इसलिए कम-प्रिविलेज़ कॉलर सर्विस पर निर्भर करते हैं। सर्विस लक्ष्य बाइनरी पर UIAccess सेट करने से पहले तीन जाँचें करता है:
  - Embedded manifest में `uiAccess="true"` मौजूद होना चाहिए।
  - Local Machine root store द्वारा ट्रस्ट किए गए किसी भी सर्टिफिकेट से साइन किया गया होना चाहिए (कोई EKU/Microsoft आवश्यकता नहीं)।
  - सिस्टम ड्राइव पर administrator-only path में स्थित होना चाहिए (उदा., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, विशिष्ट writable subpaths को छोड़कर)।
- `RAiLaunchAdminProcess` UIAccess लॉन्च के लिए कोई consent prompt नहीं दर्शाता (अन्यथा accessibility tooling prompt को ड्राइव नहीं कर पाती)।

## Token shaping और integrity levels
- यदि जाँचें सफल रहती हैं, तो AppInfo **caller token की कॉपी** बनाता है, UIAccess को सक्षम करता है, और Integrity Level (IL) बढ़ाता है:
  - Limited admin user (user Administrators में है पर filtered चल रहा है) ➜ **High IL**।
  - Non-admin user ➜ IL को **+16 levels** से बढ़ाया जाता है, अधिकतम **High** कैप तक (System IL कभी आवंटित नहीं होता)।
- यदि caller token में पहले से ही UIAccess मौजूद है, तो IL अपरिवर्तित रहती है।
- “Ratchet” trick: एक UIAccess प्रक्रिया खुद पर UIAccess को डिसेबल कर सकती है, `RAiLaunchAdminProcess` के जरिए फिर से लॉन्च कर सकती है, और हर बार +16 IL बढ़ोतरी प्राप्त कर सकती है। Medium➜High पहुँचने के लिए 255 relaunches चाहिए (शोरगार, पर काम करता है)।

## क्यों UIAccess एक Admin Protection एस्केप सक्षम करता है
- UIAccess एक lower-IL प्रक्रिया को higher-IL विंडोज़ को विंडो संदेश भेजने की अनुमति देता है (UIPI फ़िल्टरिंग को बाइपास करते हुए)। समान IL पर, क्लासिक UI प्रिमिटिव्स जैसे `SetWindowsHookEx` किसी भी प्रोसेस में कोड इंजेक्शन/DLL लोडिंग की अनुमति दे सकते हैं जो विंडो का मालिक होता है (message-only windows सहित, जिनका उपयोग COM करता है)।
- Admin Protection UIAccess प्रक्रिया को **limited user की identity** के तहत लेकिन **High IL** पर चुपचाप लॉन्च करता है। एक बार जब arbitrary code उस High-IL UIAccess प्रक्रिया के अंदर चलता है, तो attacker उस desktop पर मौजूद अन्य High-IL प्रक्रियाओं में इंजेक्ट कर सकता है (यहाँ तक कि अलग users की प्रक्रियाएँ भी), जिससे इच्छित अलगाव टूट जाता है।

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ पर API Win32k (`NtUserGetWindowProcessHandle`) में चला गया और यह caller-supplied `DesiredAccess` का उपयोग करके एक process handle खोल सकता है। kernel path `ObOpenObjectByPointer(..., KernelMode, ...)` का उपयोग करता है, जो सामान्य user-mode access चेक्स को बाइपास करता है।
- व्यवहार में preconditions: लक्ष्य विंडो उसी desktop पर होनी चाहिए, और UIPI चेक्स पास होने चाहिए। ऐतिहासिक रूप से, UIAccess वाला कॉलर UIPI फेल होने पर भी बाइपास कर के kernel-mode handle पा सकता था (fixed as CVE-2023-41772)।
- प्रभाव: एक विंडो हैंडल एक सक्षमता बन जाता है शक्तिशाली process handle (आम तौर पर `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) प्राप्त करने के लिए जिसे कॉलर सामान्यतः खोल नहीं सकता। इससे cross-sandbox access संभव होता है और यदि लक्ष्य किसी भी विंडो (message-only windows सहित) को एक्सपोज़ करता है तो Protected Process / PPL सीमाएँ टूट सकती हैं।
- व्यावहारिक दुर्व्यवहार फ्लो: HWNDs को enumerate या locate करें (उदा., `EnumWindows`/`FindWindowEx`), owning PID resolve करें (`GetWindowThreadProcessId`), `GetProcessHandleFromHwnd` कॉल करें, फिर प्राप्त हैंडल का उपयोग memory read/write या code-hijack प्रिमिटिव्स के लिए करें।
- फिक्स के बाद व्यवहार: UIAccess अब UIPI फेल होने पर kernel-mode opens नहीं देता और अनुमत access rights legacy hook सेट तक सिमित कर दिए गए हैं; Windows 11 24H2 process-protection चेक्स और feature-flagged सुरक्षित paths जोड़ता है। UIPI को system-wide डिसेबल करना (`EnforceUIPI=0`) इन सुरक्षा उपायों को कमजोर करता है।

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo दिए गए path को `GetFinalPathNameByHandle` के जरिए resolve करता है और फिर हार्डकोडेड roots/exclusions के खिलाफ **string allow/deny checks** लगाता है। उस सरल validation से कई bypass क्लासेस निकलते हैं:
- **Directory named streams**: Excluded writable directories (उदा., `C:\Windows\tracing`) को directory पर ही named stream से बाइपास किया जा सकता है, जैसे `C:\Windows\tracing:file.exe`। string checks `C:\Windows\` देखते हैं और excluded subpath को मिस कर देते हैं।
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` को **`.exe` extension की आवश्यकता नहीं** होती। किसी भी writable file को allowed root के अंतर्गत executable payload से overwrite करना काम करता है, या signed `uiAccess="true"` EXE को किसी writable subdirectory (उदा., जब मौजूद हों तो update leftovers जैसे `Tasks_Migrated`) में कॉपी करना secure-path जाँच को पास करवा देता है।
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins signed MSIX packages इंस्टॉल कर सकते थे जो `WindowsApps` में आते थे, जो excluded नहीं था। MSIX के अंदर UIAccess बाइनरी पैकेज करके और उसे `RAiLaunchAdminProcess` से लॉन्च करके एक **promptless High-IL UIAccess process** प्राप्त किया जा सकता था। Microsoft ने इस path को exclude करके इसे mitigate किया; `uiAccess` restricted MSIX capability खुद ही admin install की आवश्यकता रखती है।

## Attack workflow (High IL without a prompt)
1. एक **signed UIAccess binary** प्राप्त/बनाएँ (manifest `uiAccess="true"`).
2. इसे AppInfo की allowlist द्वारा स्वीकार किए जाने वाले स्थान पर रखें (या ऊपर बताए गए path-validation edge case/writable artifact का फायदा उठाएँ)।
3. `RAiLaunchAdminProcess` कॉल करके इसे UIAccess + elevated IL के साथ **silent** रूप से स्पॉन करें।
4. उस High-IL foothold से, desktop पर किसी अन्य High-IL प्रक्रिया को target करें `SetWindowsHookEx`/DLL injection या अन्य same-IL प्रिमिटिव्स का उपयोग करके और admin context को पूरी तरह से compromise करें।

## Enumerating candidate writable paths
Run the PowerShell helper to discover writable/overwritable objects inside nominally secure roots from the perspective of a chosen token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator विस्तृत दृश्यता के लिए; `-ProcessId` को किसी low-priv process पर सेट करें ताकि उस token के access का प्रतिबिंब मिल सके।
- RAiLaunchAdminProcess के साथ candidates का उपयोग करने से पहले ज्ञात निषिद्ध उप-निर्देशिकाओं को बाहर करने के लिए मैन्युअल रूप से फ़िल्टर करें।

## संदर्भ
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
